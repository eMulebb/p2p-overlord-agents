use std::{
    collections::VecDeque,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::{
    ed2k_server::Ed2kFoundSource,
    ed2k_tcp::{
        Ed2kHelloIdentity, Ed2kPeerDownloadOutcome, Ed2kSecureIdent, dump_ed2k_tcp_download_meta,
    },
    ed2k_transfer::Ed2kTransferRuntime,
};

use super::super::ed2k_runtime::{
    is_retryable_direct_download_error, plaintext_fallback_for_obfuscated_source,
};
pub(in crate::agent) struct NativeDirectDownloadOutcome {
    pub(in crate::agent) completed: bool,
    pub(in crate::agent) accepted_incomplete_peers: u32,
    pub(in crate::agent) last_error: Option<anyhow::Error>,
}

pub(in crate::agent) struct NativeDirectDownloadOptions {
    pub(in crate::agent) bind_ip: Ipv4Addr,
    pub(in crate::agent) hello_identity: Ed2kHelloIdentity,
    pub(in crate::agent) secure_ident: Arc<Ed2kSecureIdent>,
    pub(in crate::agent) transfer_runtime: Arc<Ed2kTransferRuntime>,
    pub(in crate::agent) file_hash_hex: String,
    pub(in crate::agent) file_name: String,
    pub(in crate::agent) file_size: u64,
    pub(in crate::agent) sources: Vec<Ed2kFoundSource>,
    pub(in crate::agent) connect_timeout: Duration,
    pub(in crate::agent) max_parallel_download_peers: usize,
}

/// Attempts direct-dial ED2K peer downloads until the transfer manifest
/// completes or all discovered direct peers fail.
///
/// The native download path keeps several peers in flight concurrently so a
/// single dead or non-serving source does not block completion when another
/// discovered peer can provide the file.
pub(in crate::agent) async fn run_native_ed2k_direct_downloads<DownloadFn, DownloadFuture>(
    options: NativeDirectDownloadOptions,
    download_peer: DownloadFn,
) -> Result<NativeDirectDownloadOutcome>
where
    DownloadFn: Fn(
            Ipv4Addr,
            Ed2kFoundSource,
            Ed2kHelloIdentity,
            Arc<Ed2kSecureIdent>,
            Arc<Ed2kTransferRuntime>,
            String,
            u64,
            Duration,
        ) -> DownloadFuture
        + Clone
        + Send
        + Sync
        + 'static,
    DownloadFuture: Future<Output = Result<Ed2kPeerDownloadOutcome>> + Send + 'static,
{
    let NativeDirectDownloadOptions {
        bind_ip,
        hello_identity,
        secure_ident,
        transfer_runtime,
        file_hash_hex,
        file_name,
        file_size,
        sources,
        connect_timeout,
        max_parallel_download_peers,
    } = options;
    let max_parallel_download_peers = max_parallel_download_peers.max(1);
    let retry_deadline =
        if !sources.is_empty() && sources.iter().all(|source| source.ip.is_loopback()) {
            Some(tokio::time::Instant::now() + Duration::from_secs(360))
        } else {
            None
        };
    let retry_sources = sources;
    let mut retry_round = 0u32;
    let mut last_error: Option<anyhow::Error> = None;

    loop {
        let mut accepted_incomplete_peers = 0u32;
        let mut retryable_error_seen = false;
        let mut pending_sources = VecDeque::from(retry_sources.clone());
        let mut active_downloads = JoinSet::new();

        while active_downloads.len() < max_parallel_download_peers {
            let Some(source) = pending_sources.pop_front() else {
                break;
            };
            let transfer_runtime = Arc::clone(&transfer_runtime);
            let secure_ident = Arc::clone(&secure_ident);
            let download_peer = download_peer.clone();
            let file_name = file_name.clone();
            let file_hash_hex = file_hash_hex.clone();
            let peer_addr = SocketAddr::new(IpAddr::V4(source.ip), source.tcp_port);
            info!(
                "native ED2K download attempt file_hash={} peer={}:{} client_id={} obfuscated={} has_user_hash={}",
                file_hash_hex,
                source.ip,
                source.tcp_port,
                source.client_id,
                source.obfuscated,
                source.user_hash.is_some()
            );
            dump_ed2k_tcp_download_meta(
                peer_addr,
                None,
                "attempt_start",
                format!(
                    "file_hash={} client_id={} obfuscated={} has_user_hash={} retry_round={}",
                    file_hash_hex,
                    source.client_id,
                    source.obfuscated,
                    source.user_hash.is_some(),
                    retry_round
                ),
            );
            active_downloads.spawn(async move {
                let result = download_peer(
                    bind_ip,
                    source.clone(),
                    hello_identity,
                    secure_ident,
                    transfer_runtime,
                    file_name,
                    file_size,
                    connect_timeout,
                )
                .await;
                (peer_addr, source, result)
            });
        }

        while let Some(joined) = active_downloads.join_next().await {
            let (peer_addr, source, result) =
                joined.context("native ED2K download worker panicked")?;
            match result {
                Ok(Ed2kPeerDownloadOutcome::Completed) => {
                    let manifest = transfer_runtime.manifest(&file_hash_hex).await?;
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        None,
                        "attempt_success",
                        format!(
                            "file_hash={} manifest_completed={} verified_ranges={} file_size={}",
                            file_hash_hex,
                            manifest.completed,
                            manifest.verified_ranges.len(),
                            manifest.file_size
                        ),
                    );
                    if manifest.completed {
                        active_downloads.abort_all();
                        while active_downloads.join_next().await.is_some() {}
                        return Ok(NativeDirectDownloadOutcome {
                            completed: true,
                            accepted_incomplete_peers,
                            last_error: last_error
                                .as_ref()
                                .map(|error| anyhow::anyhow!(error.to_string())),
                        });
                    }
                }
                Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete) => {
                    accepted_incomplete_peers += 1;
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        None,
                        "attempt_accepted_incomplete",
                        format!("file_hash={file_hash_hex}"),
                    );
                    info!(
                        "native ED2K download peer accepted session but did not complete file_hash={} peer={}",
                        file_hash_hex, peer_addr
                    );
                }
                Err(error) => {
                    retryable_error_seen |= is_retryable_direct_download_error(&error);
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        None,
                        "attempt_failure",
                        format!("file_hash={} error={error}", file_hash_hex),
                    );
                    warn!(
                        "native ED2K download peer failed file_hash={} peer={}: {error}",
                        file_hash_hex, peer_addr
                    );
                    last_error = Some(error);
                    if let Some(fallback_source) = plaintext_fallback_for_obfuscated_source(&source)
                    {
                        info!(
                            "native ED2K download scheduling plaintext fallback file_hash={} peer={}:{}",
                            file_hash_hex, source.ip, source.tcp_port
                        );
                        pending_sources.push_front(fallback_source);
                    }
                }
            }

            while active_downloads.len() < max_parallel_download_peers {
                let Some(source) = pending_sources.pop_front() else {
                    break;
                };
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let secure_ident = Arc::clone(&secure_ident);
                let download_peer = download_peer.clone();
                let file_name = file_name.clone();
                let file_hash_hex = file_hash_hex.clone();
                let peer_addr = SocketAddr::new(IpAddr::V4(source.ip), source.tcp_port);
                info!(
                    "native ED2K download attempt file_hash={} peer={}:{} client_id={} obfuscated={} has_user_hash={}",
                    file_hash_hex,
                    source.ip,
                    source.tcp_port,
                    source.client_id,
                    source.obfuscated,
                    source.user_hash.is_some()
                );
                dump_ed2k_tcp_download_meta(
                    peer_addr,
                    None,
                    "attempt_start",
                    format!(
                        "file_hash={} client_id={} obfuscated={} has_user_hash={} retry_round={}",
                        file_hash_hex,
                        source.client_id,
                        source.obfuscated,
                        source.user_hash.is_some(),
                        retry_round
                    ),
                );
                active_downloads.spawn(async move {
                    let result = download_peer(
                        bind_ip,
                        source.clone(),
                        hello_identity,
                        secure_ident,
                        transfer_runtime,
                        file_name,
                        file_size,
                        connect_timeout,
                    )
                    .await;
                    (peer_addr, source, result)
                });
            }
        }

        let outcome = NativeDirectDownloadOutcome {
            completed: transfer_runtime.manifest(&file_hash_hex).await?.completed,
            accepted_incomplete_peers,
            last_error: last_error
                .as_ref()
                .map(|error| anyhow::anyhow!(error.to_string())),
        };
        if outcome.completed || outcome.accepted_incomplete_peers != 0 {
            return Ok(outcome);
        }

        let Some(deadline) = retry_deadline else {
            return Ok(outcome);
        };
        if !retryable_error_seen || tokio::time::Instant::now() >= deadline {
            return Ok(outcome);
        }

        let last_error_summary = outcome
            .last_error
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "connection refused".to_string());
        retry_round += 1;
        info!(
            "native ED2K download retrying loopback sources file_hash={} retry_round={} reason={}",
            file_hash_hex, retry_round, last_error_summary
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
