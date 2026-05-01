use std::{collections::HashSet, net::Ipv4Addr};

use crate::{ed2k_server::Ed2kFoundSource, ed2k_transfer::Ed2kResumeManifest};

use super::ED2K_SOURCE_OBFUSCATION_REQUIRES_CRYPT;

pub(super) type Ed2kSourceAttemptKey = (Ipv4Addr, u16, Option<[u8; 16]>, Option<u8>);
pub(super) type Ed2kSourceEndpointKey = (Ipv4Addr, u16);

/// Callback-driven ED2K downloads can continue after the initial server-side
/// callback request completes. Treat persisted piece/hashset progress as proof
/// that a real transfer is in flight instead of reporting a terminal failure
/// immediately after the first callback grace window.
pub(super) fn manifest_has_ed2k_transfer_progress(manifest: &Ed2kResumeManifest) -> bool {
    manifest.completed
        || manifest.md4_hashset_acquired
        || !manifest.verified_ranges.is_empty()
        || manifest.pieces.iter().any(|piece| piece.bytes_written != 0)
}

pub(super) fn is_retryable_direct_download_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|inner| inner.kind() == std::io::ErrorKind::ConnectionRefused)
    })
}

pub(super) fn ed2k_source_attempt_key(source: &Ed2kFoundSource) -> Ed2kSourceAttemptKey {
    (
        source.ip,
        source.tcp_port,
        source.user_hash,
        source.obfuscation_options,
    )
}

pub(super) fn ed2k_source_endpoint_key(source: &Ed2kFoundSource) -> Ed2kSourceEndpointKey {
    (source.ip, source.tcp_port)
}

pub(super) fn sort_native_ed2k_download_sources(sources: &mut [Ed2kFoundSource]) {
    // Prefer direct, obfuscation-ready sources first, matching eMule's bias
    // toward peers that can complete the initial secure handshake.
    sources.sort_by_key(|source| {
        (
            !source.is_direct_dialable(),
            source.user_hash.is_none(),
            source.obfuscation_options.is_none(),
        )
    });
}

pub(super) fn direct_download_candidate_sources(
    sources: &[Ed2kFoundSource],
    attempted_direct_endpoints: &HashSet<Ed2kSourceEndpointKey>,
) -> Vec<Ed2kFoundSource> {
    let mut seen_endpoints = HashSet::new();
    sources
        .iter()
        .filter(|source| {
            if !source.is_direct_dialable() {
                return false;
            }
            let endpoint = ed2k_source_endpoint_key(source);
            !attempted_direct_endpoints.contains(&endpoint) && seen_endpoints.insert(endpoint)
        })
        .cloned()
        .collect()
}

pub(super) fn new_direct_ed2k_source_count(
    sources: &[Ed2kFoundSource],
    attempted_direct_endpoints: &HashSet<Ed2kSourceEndpointKey>,
) -> usize {
    direct_download_candidate_sources(sources, attempted_direct_endpoints).len()
}

pub(super) fn should_skip_no_progress_source_requery(
    had_direct_sources: bool,
    manifest_has_progress: bool,
    new_direct_source_count: usize,
) -> bool {
    had_direct_sources && !manifest_has_progress && new_direct_source_count == 0
}

pub(super) fn plaintext_fallback_for_obfuscated_source(
    source: &Ed2kFoundSource,
) -> Option<Ed2kFoundSource> {
    let options = source.obfuscation_options?;
    if options & ED2K_SOURCE_OBFUSCATION_REQUIRES_CRYPT != 0 {
        return None;
    }
    let mut fallback = source.clone();
    fallback.obfuscated = false;
    fallback.obfuscation_options = None;
    fallback.user_hash = None;
    Some(fallback)
}
