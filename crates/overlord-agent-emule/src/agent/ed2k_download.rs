use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::{
    AgentNetworkRuntime, ED2K_DOWNLOAD_SOURCE_REQUERY_DELAY_SECS,
    ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS,
    ed2k_enrich::{EnrichEd2kDownloadRequest, is_hash_only_ed2k_placeholder_name},
    ed2k_runtime::{
        Ed2kSourceEndpointKey, direct_download_candidate_sources, ed2k_source_attempt_key,
        ed2k_source_endpoint_key, manifest_has_ed2k_transfer_progress,
        new_direct_ed2k_source_count, should_skip_no_progress_source_requery,
        sort_native_ed2k_download_sources,
    },
    ed2k_search::resolve_hash_only_ed2k_metadata,
    merge_download_sources,
};
use crate::{
    config::EmuleAgentConfig,
    ed2k_server::{
        Ed2kCallbackRequestOptions, request_callback_on_server,
        request_callback_via_background_session,
    },
    ed2k_tcp::{
        Ed2kHelloIdentity, Ed2kPeerDownloadOptions, download_file_from_peer,
        dump_ed2k_tcp_download_meta, emule_connect_options,
    },
    ed2k_transfer::{
        Ed2kCallbackIntent, Ed2kResumeManifest, Ed2kSourceHint, Ed2kTransferRuntime,
        new_transfer_job,
    },
};
use overlord_kad_proto::Ed2kHash;

mod direct;
mod sources;

#[cfg(test)]
pub(super) use direct::NativeDirectDownloadOutcome;
pub(super) use direct::{NativeDirectDownloadOptions, run_native_ed2k_direct_downloads};
use sources::native_ed2k_download_sources;

pub(super) async fn start_native_ed2k_download(
    runtime_handle: Arc<Mutex<Option<AgentNetworkRuntime>>>,
    config_handle: Arc<RwLock<EmuleAgentConfig>>,
    ed2k_user_hash: [u8; 16],
    request: EnrichEd2kDownloadRequest,
) -> Result<()> {
    if request.kind != "ed2k_download" {
        anyhow::bail!("unsupported enrich kind {}", request.kind);
    }

    let file_hash = Ed2kHash::from_str(&request.file_hash)
        .with_context(|| format!("invalid ED2K file hash {}", request.file_hash))?;
    let runtime = runtime_handle.lock().await.clone();
    let Some(runtime) = runtime else {
        anyhow::bail!("agent networking is waiting for interface selection");
    };
    let config = config_handle.read().await.clone();
    let mut canonical_name = request.canonical_name();
    let mut file_size = request.file_size_or_unknown();
    let adopt_learned_name =
        is_hash_only_ed2k_placeholder_name(&canonical_name, &request.file_hash);
    let shared_catalog = runtime.ed2k_shared_catalog.read().await.clone();
    runtime
        .ed2k_transfer
        .ensure_job(&new_transfer_job(
            file_hash,
            canonical_name.clone(),
            file_size,
        ))
        .await?;
    runtime
        .ed2k_transfer
        .reclaim_stale_piece_requests(&request.file_hash)
        .await?;
    if request.sources.is_empty()
        && (file_size == 0 || adopt_learned_name)
        && let Some(learned_metadata) =
            resolve_hash_only_ed2k_metadata(&runtime, &config, file_hash, ed2k_user_hash).await?
    {
        let manifest = runtime
            .ed2k_transfer
            .reconcile_job_metadata(
                &request.file_hash,
                adopt_learned_name
                    .then_some(learned_metadata.canonical_name.as_deref())
                    .flatten(),
                learned_metadata.file_size,
            )
            .await?;
        canonical_name = manifest.canonical_name.clone();
        file_size = manifest.file_size;
        info!(
            "native ED2K download reconciled hash-only metadata file_hash={} file_name={} file_size={}",
            request.file_hash, canonical_name, file_size
        );
    }
    let hello_identity = Ed2kHelloIdentity {
        user_hash: ed2k_user_hash,
        client_id: 0,
        tcp_port: config.p2p.ed2k.listen_port,
        udp_port: config.p2p.kad.listen_port,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(config.p2p.ed2k.obfuscation_enabled),
        direct_udp_callback: false,
    };
    let auto_acquire_sources = request.sources.is_empty();
    let mut sources = if auto_acquire_sources {
        native_ed2k_download_sources(&runtime, &config, file_hash, file_size, ed2k_user_hash)
            .await?
    } else {
        request
            .sources
            .into_iter()
            .map(|source| source.into_found_source(file_hash))
            .collect::<Result<Vec<_>>>()?
    };
    if sources.is_empty() {
        anyhow::bail!("no ED2K sources available for {}", request.file_hash);
    }

    sort_native_ed2k_download_sources(&mut sources);

    // Low-ID peers often arrive noticeably later than direct ED2K connects
    // because the server-mediated callback has to propagate first.
    let callback_timeout = Duration::from_secs(config.p2p.ed2k.connect_timeout_secs.max(30));
    let mut attempted_direct_endpoints: HashSet<Ed2kSourceEndpointKey> = HashSet::new();
    let mut requested_callback_sources = HashSet::new();
    let mut had_direct_sources = false;
    let mut accepted_incomplete_peers = 0u32;
    let mut last_direct_error: Option<anyhow::Error> = None;
    let mut source_requery_round = 0usize;

    loop {
        sort_native_ed2k_download_sources(&mut sources);
        let pre_filter_source_count = sources.len();
        let post_filter_source_count = sources
            .iter()
            .filter(|source| source.is_direct_dialable())
            .count();
        let callback_only_sources: Vec<_> = sources
            .iter()
            .filter(|source| source.low_id)
            .cloned()
            .collect();
        let skipped_low_id_sources = callback_only_sources.len();
        info!(
            "native ED2K download source filtering file_hash={} pre_filter_source_count={} callback_only_source_count={} post_filter_source_count={} requery_round={}",
            request.file_hash,
            pre_filter_source_count,
            skipped_low_id_sources,
            post_filter_source_count,
            source_requery_round
        );
        if skipped_low_id_sources != 0 {
            info!(
                "native ED2K download filtered callback-only sources file_hash={} skipped_low_id_sources={} requery_round={}",
                request.file_hash, skipped_low_id_sources, source_requery_round
            );
        }

        if !callback_only_sources.is_empty() {
            let cancel = CancellationToken::new();
            for source in &callback_only_sources {
                let source_key = ed2k_source_attempt_key(source);
                if !requested_callback_sources.insert(source_key) {
                    continue;
                }
                runtime
                    .ed2k_transfer
                    .register_callback_intent(Ed2kCallbackIntent {
                        client_id: source.client_id,
                        file_hash: request.file_hash.clone(),
                        canonical_name: canonical_name.clone(),
                        file_size,
                        source: Ed2kSourceHint {
                            ip: source.ip.to_string(),
                            tcp_port: source.tcp_port,
                            user_hash: source.user_hash.map(hex::encode),
                        },
                    })
                    .await;
                info!(
                    "native ED2K download requesting server callback file_hash={} client_id={} tcp_port={} source_server={} requery_round={}",
                    request.file_hash,
                    source.client_id,
                    source.tcp_port,
                    source
                        .source_server
                        .map_or_else(|| "-".to_string(), |endpoint| endpoint.to_string()),
                    source_requery_round
                );
                let callback_result = if let Some(source_server) = source.source_server {
                    request_callback_on_server(Ed2kCallbackRequestOptions {
                        bind_ip: runtime.bind_ip,
                        config: &config.p2p.ed2k,
                        hello_identity,
                        shared_catalog: &shared_catalog,
                        server_endpoint: source_server,
                        client_id: source.client_id,
                        timeout: callback_timeout,
                        cancel: &cancel,
                    })
                    .await
                } else {
                    request_callback_via_background_session(
                        &runtime.ed2k_server_search,
                        source.client_id,
                        callback_timeout,
                        &cancel,
                    )
                    .await
                };
                match callback_result {
                    Ok(()) => {}
                    Err(error) => warn!(
                        "native ED2K server callback request failed file_hash={} client_id={} source_server={}: {error}",
                        request.file_hash,
                        source.client_id,
                        source
                            .source_server
                            .map_or_else(|| "-".to_string(), |endpoint| endpoint.to_string())
                    ),
                }
            }
        }

        let direct_sources =
            direct_download_candidate_sources(&sources, &attempted_direct_endpoints);
        had_direct_sources |= !direct_sources.is_empty();
        if direct_sources.is_empty() && requested_callback_sources.is_empty() {
            info!(
                "native ED2K download source filtering left no direct-dialable sources file_hash={} callback_only_source_count={} requery_round={}",
                request.file_hash, skipped_low_id_sources, source_requery_round
            );
        }
        for source in &direct_sources {
            dump_ed2k_tcp_download_meta(
                SocketAddr::new(IpAddr::V4(source.ip), source.tcp_port),
                None,
                "source_candidate",
                format!(
                    "file_hash={} client_id={} low_id={} obfuscated={} has_user_hash={} requery_round={}",
                    request.file_hash,
                    source.client_id,
                    source.low_id,
                    source.obfuscated,
                    source.user_hash.is_some(),
                    source_requery_round
                ),
            );
            attempted_direct_endpoints.insert(ed2k_source_endpoint_key(source));
        }
        if !direct_sources.is_empty() {
            let outcome = run_native_ed2k_direct_downloads(
                NativeDirectDownloadOptions {
                    bind_ip: runtime.bind_ip,
                    hello_identity,
                    secure_ident: Arc::clone(&runtime.ed2k_secure_ident),
                    transfer_runtime: Arc::clone(&runtime.ed2k_transfer),
                    file_hash_hex: request.file_hash.clone(),
                    file_name: canonical_name.clone(),
                    file_size,
                    sources: direct_sources,
                    connect_timeout: Duration::from_secs(
                        config.p2p.ed2k.connect_timeout_secs.max(10),
                    ),
                    max_parallel_download_peers: config.p2p.ed2k.max_parallel_download_peers,
                },
                |bind_ip,
                 source,
                 hello_identity,
                 secure_ident,
                 transfer_runtime,
                 file_name,
                 file_size,
                 connect_timeout| async move {
                    download_file_from_peer(Ed2kPeerDownloadOptions {
                        bind_ip,
                        peer: &source,
                        hello_identity,
                        secure_ident: &secure_ident,
                        transfer_runtime: transfer_runtime.as_ref(),
                        canonical_name: file_name,
                        file_size,
                        timeout: connect_timeout,
                    })
                    .await
                },
            )
            .await?;

            if outcome.completed {
                let manifest = runtime.ed2k_transfer.manifest(&request.file_hash).await?;
                dump_ed2k_tcp_download_meta(
                    SocketAddr::new(IpAddr::V4(runtime.bind_ip), config.p2p.ed2k.listen_port),
                    None,
                    "download_completed",
                    format!(
                        "file_hash={} file_name={} expected_size={} manifest_size={} verified_ranges={} completed={}",
                        request.file_hash,
                        manifest.canonical_name,
                        file_size,
                        manifest.file_size,
                        manifest.verified_ranges.len(),
                        manifest.completed
                    ),
                );
                info!(
                    "native ED2K download completed file_hash={} file_name={} size={}",
                    request.file_hash, manifest.canonical_name, manifest.file_size
                );
                return Ok(());
            }
            if outcome.accepted_incomplete_peers != 0 {
                accepted_incomplete_peers =
                    accepted_incomplete_peers.saturating_add(outcome.accepted_incomplete_peers);
                dump_ed2k_tcp_download_meta(
                    SocketAddr::new(IpAddr::V4(runtime.bind_ip), config.p2p.ed2k.listen_port),
                    None,
                    "download_accepted_incomplete_peers",
                    format!(
                        "file_hash={} accepted_incomplete_peers={} total_accepted_incomplete_peers={}",
                        request.file_hash,
                        outcome.accepted_incomplete_peers,
                        accepted_incomplete_peers
                    ),
                );
            }
            if let Some(error) = outcome.last_error {
                last_direct_error = Some(error);
            }
        }

        if auto_acquire_sources
            && file_size != 0
            && source_requery_round < ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS
        {
            let manifest = runtime.ed2k_transfer.manifest(&request.file_hash).await?;
            let known_new_direct_source_count =
                new_direct_ed2k_source_count(&sources, &attempted_direct_endpoints);
            if should_skip_no_progress_source_requery(
                had_direct_sources,
                manifest_has_ed2k_transfer_progress(&manifest),
                known_new_direct_source_count,
            ) {
                info!(
                    "native ED2K download skipping source refresh file_hash={} reason=no_progress_repeated_endpoints attempted_direct_endpoints={} known_new_direct_source_count={} md4_hashset_acquired={} verified_ranges={}",
                    request.file_hash,
                    attempted_direct_endpoints.len(),
                    known_new_direct_source_count,
                    manifest.md4_hashset_acquired,
                    manifest.verified_ranges.len()
                );
                break;
            }
            source_requery_round += 1;
            info!(
                "native ED2K download refreshing sources file_hash={} requery_round={} attempted_direct_endpoints={}",
                request.file_hash,
                source_requery_round,
                attempted_direct_endpoints.len()
            );
            if source_requery_round > 1 {
                tokio::time::sleep(Duration::from_secs(ED2K_DOWNLOAD_SOURCE_REQUERY_DELAY_SECS))
                    .await;
            }
            match native_ed2k_download_sources(
                &runtime,
                &config,
                file_hash,
                file_size,
                ed2k_user_hash,
            )
            .await
            {
                Ok(refreshed_sources) => {
                    let refreshed_source_count = refreshed_sources.len();
                    let previous_source_count = sources.len();
                    merge_download_sources(&mut sources, refreshed_sources);
                    let added_source_count = sources.len().saturating_sub(previous_source_count);
                    let new_direct_source_count =
                        new_direct_ed2k_source_count(&sources, &attempted_direct_endpoints);
                    info!(
                        "native ED2K download source refresh completed file_hash={} requery_round={} refreshed_source_count={} added_source_count={} aggregated_source_count={} new_direct_source_count={}",
                        request.file_hash,
                        source_requery_round,
                        refreshed_source_count,
                        added_source_count,
                        sources.len(),
                        new_direct_source_count
                    );
                    let manifest = runtime.ed2k_transfer.manifest(&request.file_hash).await?;
                    let manifest_has_progress = manifest_has_ed2k_transfer_progress(&manifest);
                    if manifest_has_progress {
                        info!(
                            "native ED2K download source refresh preserving in-progress transfer file_hash={} requery_round={} md4_hashset_acquired={} verified_ranges={}",
                            request.file_hash,
                            source_requery_round,
                            manifest.md4_hashset_acquired,
                            manifest.verified_ranges.len()
                        );
                        continue;
                    }
                    if new_direct_source_count != 0 {
                        continue;
                    }
                    if !had_direct_sources
                        && source_requery_round < ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS
                    {
                        continue;
                    }
                }
                Err(error) => {
                    warn!(
                        "native ED2K download source refresh failed file_hash={} requery_round={}: {error}",
                        request.file_hash, source_requery_round
                    );
                    if source_requery_round < ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS {
                        continue;
                    }
                }
            }
        }
        break;
    }

    if !requested_callback_sources.is_empty() {
        tokio::time::sleep(callback_timeout).await;
        let manifest = await_callback_transfer_completion(
            runtime.ed2k_transfer.as_ref(),
            &request.file_hash,
            &runtime.ed2k_transfer.manifest(&request.file_hash).await?,
            Duration::from_secs(callback_timeout.as_secs().max(90)),
        )
        .await?;
        if manifest.completed {
            return Ok(());
        }
        if manifest_has_ed2k_transfer_progress(&manifest) {
            info!(
                "native ED2K callback transfer remains in progress after grace window file_hash={} bytes_written={} md4_hashset_acquired={}",
                request.file_hash,
                manifest
                    .pieces
                    .iter()
                    .map(|piece| piece.bytes_written)
                    .sum::<u64>(),
                manifest.md4_hashset_acquired
            );
            return Ok(());
        }
    }

    let manifest = runtime.ed2k_transfer.manifest(&request.file_hash).await?;
    if manifest.completed {
        return Ok(());
    }
    if had_direct_sources {
        if let Some(error) = last_direct_error {
            return Err(error).with_context(|| {
                format!(
                    "native ED2K download did not complete for {} after trying discovered sources",
                    request.file_hash
                )
            });
        }
        if accepted_incomplete_peers != 0 {
            anyhow::bail!(
                "native ED2K download for {} did not complete after {} accepted incomplete peer sessions",
                request.file_hash,
                accepted_incomplete_peers
            );
        }
        anyhow::bail!(
            "native ED2K download for {} did not complete and no peer reported a concrete error",
            request.file_hash
        );
    }
    anyhow::bail!(
        "native ED2K download found only callback-only or otherwise non-dialable sources for {}",
        request.file_hash
    );
}

async fn await_callback_transfer_completion(
    transfer_runtime: &Ed2kTransferRuntime,
    file_hash: &str,
    initial_manifest: &Ed2kResumeManifest,
    wait_budget: Duration,
) -> Result<Ed2kResumeManifest> {
    if initial_manifest.completed {
        return Ok(initial_manifest.clone());
    }
    let started = Instant::now();
    let poll_interval = Duration::from_secs(2);
    let mut last_manifest = initial_manifest.clone();
    while started.elapsed() < wait_budget {
        tokio::time::sleep(poll_interval).await;
        let manifest = transfer_runtime.manifest(file_hash).await?;
        if manifest.completed || !manifest.verified_ranges.is_empty() {
            return Ok(manifest);
        }
        last_manifest = manifest;
    }
    Ok(last_manifest)
}
