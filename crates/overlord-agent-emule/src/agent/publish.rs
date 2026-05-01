use std::{fs, net::SocketAddr, path::Path, sync::Arc};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use overlord_agent_common::{
    KadPublishObservability, PublishBatchSummary, PublishCounters, PublishSeedSource,
};
use overlord_kad_dht::PublishAttemptStats;
use overlord_kad_proto::{NodeId, Tag, TagValue, tag_name};
use rand::RngCore;
use tokio::sync::Mutex;
use tracing::info;

use super::{EMULE_LARGE_FILE_SIZE_THRESHOLD, SourcePublishSettings};
use crate::ed2k_tcp::emule_connect_options;

pub(super) fn build_publish_batch_summary(
    seed_source: PublishSeedSource,
    published_items: usize,
    stats: PublishAttemptStats,
    completed_at: DateTime<Utc>,
) -> PublishBatchSummary {
    PublishBatchSummary {
        seed_source,
        published_items: published_items as u32,
        closest_contacts_considered: stats.closest_contacts_considered,
        attempted_contacts: stats.attempted_contacts,
        acked_contacts: stats.acked_contacts,
        failed_contacts: stats.failed_contacts(),
        timed_out_contacts: stats.timed_out_contacts,
        completed_at,
        last_success_at: (stats.acked_contacts > 0).then_some(completed_at),
    }
}

pub(super) fn apply_publish_summary(counters: &mut PublishCounters, summary: &PublishBatchSummary) {
    counters.batches += 1;
    counters.published_items += u64::from(summary.published_items);
    counters.closest_contacts_considered += u64::from(summary.closest_contacts_considered);
    counters.attempted_contacts += u64::from(summary.attempted_contacts);
    counters.acked_contacts += u64::from(summary.acked_contacts);
    counters.failed_contacts += u64::from(summary.failed_contacts);
    counters.timed_out_contacts += u64::from(summary.timed_out_contacts);
    counters.last_batch_at = Some(summary.completed_at);
    if summary.last_success_at.is_some() {
        counters.last_success_at = summary.last_success_at;
    }
}

/// Returns whether the current batch snapshot reflects any observable seeding progress yet.
fn publish_summary_has_progress(summary: &PublishBatchSummary) -> bool {
    summary.published_items > 0
        || summary.closest_contacts_considered > 0
        || summary.attempted_contacts > 0
        || summary.acked_contacts > 0
        || summary.failed_contacts > 0
        || summary.timed_out_contacts > 0
}

/// Projects the counters that operators should see right now.
///
/// The stored counters only advance once a batch has fully finished. During long live
/// runs, however, `/api/internal/stats` should still reflect the current in-flight batch
/// so the roll-up totals stay aligned with the latest per-batch snapshot.
pub(super) fn effective_publish_counters(
    counters: &PublishCounters,
    latest_batch: Option<&PublishBatchSummary>,
    last_seed_at: Option<DateTime<Utc>>,
) -> PublishCounters {
    let mut effective = counters.clone();
    let Some(summary) = latest_batch else {
        return effective;
    };

    let batch_committed = counters.last_batch_at == Some(summary.completed_at);
    let batch_in_flight = match (last_seed_at, counters.last_batch_at) {
        (Some(observed_at), Some(committed_at)) => observed_at > committed_at,
        (Some(_), None) => true,
        (None, _) => false,
    };

    if batch_in_flight && !batch_committed && publish_summary_has_progress(summary) {
        apply_publish_summary(&mut effective, summary);
    }

    effective
}

fn log_publish_summary(family: &str, summary: &PublishBatchSummary) {
    let other_failures = summary
        .failed_contacts
        .saturating_sub(summary.timed_out_contacts);
    info!(
        "kad publish family={} seed_source={} items={} closest={} attempted={} acked={} failed={} timed_out={} other_failures={}",
        family,
        summary.seed_source.label(),
        summary.published_items,
        summary.closest_contacts_considered,
        summary.attempted_contacts,
        summary.acked_contacts,
        summary.failed_contacts,
        summary.timed_out_contacts,
        other_failures
    );
}

pub(super) async fn record_publish_summaries(
    publish_observability: &Arc<Mutex<KadPublishObservability>>,
    seed_source: PublishSeedSource,
    published_items: usize,
    keyword_stats: PublishAttemptStats,
    source_stats: PublishAttemptStats,
    notes_stats: Option<PublishAttemptStats>,
    completed_at: DateTime<Utc>,
) {
    let keyword_summary =
        build_publish_batch_summary(seed_source, published_items, keyword_stats, completed_at);
    let source_summary =
        build_publish_batch_summary(seed_source, published_items, source_stats, completed_at);
    let notes_summary = notes_stats.map(|stats| {
        build_publish_batch_summary(seed_source, published_items, stats, completed_at)
    });

    log_publish_summary("keyword", &keyword_summary);
    log_publish_summary("source", &source_summary);
    if let Some(summary) = notes_summary.as_ref() {
        log_publish_summary("notes", summary);
    }

    let mut observability = publish_observability.lock().await;
    observability.last_seed_source = Some(seed_source);
    observability.last_seed_at = Some(completed_at);
    observability.latest_keyword_batch = Some(keyword_summary.clone());
    observability.latest_source_batch = Some(source_summary.clone());
    observability.latest_notes_batch = notes_summary.clone();
    apply_publish_summary(&mut observability.keyword_counters, &keyword_summary);
    apply_publish_summary(&mut observability.source_counters, &source_summary);
    if let Some(summary) = notes_summary.as_ref() {
        apply_publish_summary(&mut observability.notes_counters, summary);
    }
}

/// Refreshes the live publish snapshot while a long seed batch is still running.
///
/// The cumulative counters are only committed once the whole batch completes, but
/// the latest batch snapshots are updated continuously so operators can tell that
/// startup seeding is still making progress.
pub(super) async fn update_publish_progress(
    publish_observability: &Arc<Mutex<KadPublishObservability>>,
    seed_source: PublishSeedSource,
    processed_items: usize,
    keyword_stats: PublishAttemptStats,
    source_stats: PublishAttemptStats,
    notes_stats: Option<PublishAttemptStats>,
    observed_at: DateTime<Utc>,
) {
    let mut observability = publish_observability.lock().await;
    observability.last_seed_source = Some(seed_source);
    observability.last_seed_at = Some(observed_at);
    observability.latest_keyword_batch = Some(build_publish_batch_summary(
        seed_source,
        processed_items,
        keyword_stats,
        observed_at,
    ));
    observability.latest_source_batch = Some(build_publish_batch_summary(
        seed_source,
        processed_items,
        source_stats,
        observed_at,
    ));
    if let Some(stats) = notes_stats {
        observability.latest_notes_batch = Some(build_publish_batch_summary(
            seed_source,
            processed_items,
            stats,
            observed_at,
        ));
    }
}

pub(super) async fn set_synthetic_publish_queue_depth(
    publish_observability: &Arc<Mutex<KadPublishObservability>>,
    remaining_items: usize,
) {
    let mut observability = publish_observability.lock().await;
    observability.synthetic_drip_queue_depth = Some(remaining_items as u32);
}

/// Returns the eMule high-ID source type used for source publishes in the non-firewalled case.
pub(super) fn emule_high_id_source_type(file_size: u64) -> u32 {
    if file_size > EMULE_LARGE_FILE_SIZE_THRESHOLD {
        4
    } else {
        1
    }
}

/// eMule Kad carries 128-bit search/source entry IDs in 32-bit little-endian
/// chunk order rather than raw MD4 byte order.
fn emule_kad_chunk_order(bytes: [u8; 16]) -> [u8; 16] {
    let mut ordered = [0u8; 16];
    for (dst, src) in ordered.chunks_exact_mut(4).zip(bytes.chunks_exact(4)) {
        dst.copy_from_slice(&[src[3], src[2], src[1], src[0]]);
    }
    ordered
}

/// Reuse the persisted eD2k user hash as the Kad source-publish identity.
///
/// The oracle source-publish path sends the eMule client hash rather than the
/// Kad node ID in the second `KADEMLIA2_PUBLISH_SOURCE_REQ` field.
pub(super) fn source_publish_client_hash(ed2k_user_hash: [u8; 16]) -> NodeId {
    NodeId::from_bytes(emule_kad_chunk_order(ed2k_user_hash))
}

/// Applies the classic eMule client marker bytes to an ED2K user hash.
pub(super) fn normalize_ed2k_user_hash_markers(mut user_hash: [u8; 16]) -> [u8; 16] {
    user_hash[5] = 0x0E;
    user_hash[14] = 0x6F;
    user_hash
}

/// Mirrors the oracle `isbadhash` check for persisted ED2K user hashes.
fn ed2k_user_hash_is_bad(user_hash: &[u8; 16]) -> bool {
    let lo = u64::from_le_bytes(user_hash[..8].try_into().expect("slice has 8 bytes"));
    let hi = u64::from_le_bytes(user_hash[8..].try_into().expect("slice has 8 bytes"));
    (lo & 0xffff_00ff_ffff_ffff) == 0 && (hi & 0xff00_ffff_ffff_ffff) == 0
}

/// Creates a fresh eMule-style ED2K user hash.
fn create_ed2k_user_hash() -> [u8; 16] {
    loop {
        let mut user_hash = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut user_hash);
        let user_hash = normalize_ed2k_user_hash_markers(user_hash);
        if !ed2k_user_hash_is_bad(&user_hash) {
            return user_hash;
        }
    }
}

/// Loads the persisted ED2K user hash, or creates one that mirrors eMule semantics.
pub(super) fn load_or_create_ed2k_user_hash(path: &Path) -> Result<[u8; 16]> {
    if path.exists() {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read ED2K user hash from {}", path.display()))?;
        if bytes.len() == 16 {
            let mut user_hash = [0u8; 16];
            user_hash.copy_from_slice(&bytes);
            let normalized = normalize_ed2k_user_hash_markers(user_hash);
            if !ed2k_user_hash_is_bad(&normalized) {
                if normalized != user_hash {
                    fs::write(path, normalized).with_context(|| {
                        format!("failed to normalize ED2K user hash at {}", path.display())
                    })?;
                }
                return Ok(normalized);
            }
        }
    }

    let user_hash = create_ed2k_user_hash();
    fs::write(path, user_hash)
        .with_context(|| format!("failed to persist ED2K user hash to {}", path.display()))?;
    Ok(user_hash)
}

/// Return the eMule-style `TAG_ENCRYPTION` bits for the current non-firewalled agent.
///
/// This mirrors the oracle `GetMyConnectOptions(true, false)` shape we also expose over TCP hello.
fn emule_source_encryption_options(obfuscation_enabled: bool) -> u8 {
    emule_connect_options(obfuscation_enabled)
}

/// Builds the oracle-style source publish tag set for one file announcement.
pub(super) fn build_source_publish_tags(
    bind_addr: SocketAddr,
    source_publish_settings: SourcePublishSettings,
    file_size: u64,
) -> Vec<Tag> {
    let mut tags = vec![
        Tag::new_short(
            tag_name::SOURCETYPE,
            TagValue::UInt(u64::from(emule_high_id_source_type(file_size))),
        ),
        // Mirror the oracle: SOURCEPORT carries the ED2K TCP listener while
        // SOURCEUPORT carries the Kad UDP listener.
        Tag::new_short(
            tag_name::SOURCEPORT,
            TagValue::UInt(u64::from(source_publish_settings.tcp_port)),
        ),
    ];
    if let SocketAddr::V4(addr) = bind_addr {
        tags.push(Tag::new_short(
            tag_name::SOURCEIP,
            TagValue::U32(u32::from_be_bytes(addr.ip().octets())),
        ));
    }
    tags.push(Tag::new_short(
        tag_name::SOURCEUPORT,
        TagValue::U16(bind_addr.port()),
    ));
    tags.push(Tag::filesize(file_size));
    tags.push(Tag::new_short(
        tag_name::ENCRYPTION,
        TagValue::U8(emule_source_encryption_options(
            source_publish_settings.obfuscation_enabled,
        )),
    ));
    tags
}

/// Builds a deterministic notes-publish payload for controlled live validation.
///
/// The notes-seeding path remains opt-in so the runtime can exercise notes
/// publish parity without making synthetic notes part of the default behavior.
pub(super) fn build_notes_publish_tags(canonical_name: &str, file_size: u64) -> Vec<Tag> {
    vec![
        Tag::filename(canonical_name.to_string()),
        Tag::filesize(file_size),
        Tag::new_short(tag_name::FILERATING, TagValue::U8(4)),
        Tag::new_short(
            tag_name::DESCRIPTION,
            TagValue::String(format!("overlord validation note for {canonical_name}")),
        ),
    ]
}
