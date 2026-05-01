use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::{
    AgentNetworkRuntime, ED2K_DOWNLOAD_KAD_SOURCE_TIMEOUT_FLOOR_SECS,
    ED2K_DOWNLOAD_SOURCE_REQUERY_DELAY_SECS, ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS,
    ed2k_enrich::{EnrichEd2kDownloadRequest, is_hash_only_ed2k_placeholder_name},
    ed2k_runtime::{
        Ed2kSourceEndpointKey, direct_download_candidate_sources, ed2k_source_attempt_key,
        ed2k_source_endpoint_key, is_retryable_direct_download_error,
        manifest_has_ed2k_transfer_progress, new_direct_ed2k_source_count,
        plaintext_fallback_for_obfuscated_source, should_skip_no_progress_source_requery,
        sort_native_ed2k_download_sources,
    },
    ed2k_search::{
        collect_kad_ed2k_sources, ed2k_download_source_server_attempt_budget,
        ed2k_source_search_timeout, resolve_hash_only_ed2k_metadata,
    },
    merge_download_sources,
};
use crate::{
    config::EmuleAgentConfig,
    ed2k_server::{
        Ed2kCallbackRequestOptions, Ed2kFoundSource, Ed2kSourceSearchOptions,
        Ed2kUdpSourceSearchOptions, request_callback_on_server,
        request_callback_via_background_session, search_source_servers, search_source_udp_servers,
        search_source_via_background_session,
    },
    ed2k_tcp::{
        Ed2kHelloIdentity, Ed2kPeerDownloadOptions, Ed2kPeerDownloadOutcome, Ed2kSecureIdent,
        download_file_from_peer, dump_ed2k_tcp_download_meta, emule_connect_options,
    },
    ed2k_transfer::{
        Ed2kCallbackIntent, Ed2kResumeManifest, Ed2kSourceHint, Ed2kTransferRuntime,
        new_transfer_job,
    },
};
use overlord_kad_proto::Ed2kHash;

pub(super) struct NativeDirectDownloadOutcome {
    pub(super) completed: bool,
    pub(super) accepted_incomplete_peers: u32,
    pub(super) last_error: Option<anyhow::Error>,
}

pub(super) struct NativeDirectDownloadOptions {
    pub(super) bind_ip: Ipv4Addr,
    pub(super) hello_identity: Ed2kHelloIdentity,
    pub(super) secure_ident: Arc<Ed2kSecureIdent>,
    pub(super) transfer_runtime: Arc<Ed2kTransferRuntime>,
    pub(super) file_hash_hex: String,
    pub(super) file_name: String,
    pub(super) file_size: u64,
    pub(super) sources: Vec<Ed2kFoundSource>,
    pub(super) connect_timeout: Duration,
    pub(super) max_parallel_download_peers: usize,
}

/// Attempts direct-dial ED2K peer downloads until the transfer manifest
/// completes or all discovered direct peers fail.
///
/// The native download path keeps several peers in flight concurrently so a
/// single dead or non-serving source does not block completion when another
/// discovered peer can provide the file.
pub(super) async fn run_native_ed2k_direct_downloads<DownloadFn, DownloadFuture>(
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

pub(super) async fn native_ed2k_download_sources(
    runtime: &AgentNetworkRuntime,
    config: &EmuleAgentConfig,
    file_hash: Ed2kHash,
    file_size: u64,
    ed2k_user_hash: [u8; 16],
) -> Result<Vec<Ed2kFoundSource>> {
    let cancel = CancellationToken::new();
    let mut sources = Vec::new();
    let shared_catalog = runtime.ed2k_shared_catalog.read().await.clone();
    let source_search_timeout = ed2k_source_search_timeout(&config.p2p.ed2k);
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
    let (preferred_endpoint, background_search) = {
        let server_state = runtime.ed2k_server_state.read().await;
        if server_state.connected {
            (
                server_state.endpoint,
                Some(runtime.ed2k_server_search.clone()),
            )
        } else {
            (None, None)
        }
    };

    let has_background_search = background_search.is_some();
    if let Some(background_search) = background_search {
        match search_source_via_background_session(
            &background_search,
            file_hash,
            file_size,
            source_search_timeout,
            &cancel,
        )
        .await
        {
            Ok(results) if !results.is_empty() => {
                let source_count = results.len();
                merge_download_sources(&mut sources, results);
                info!(
                    "native ED2K download background source acquisition completed file_hash={} source_count={} aggregated_source_count={}",
                    file_hash,
                    source_count,
                    sources.len()
                );
            }
            Ok(_) => {
                info!(
                    "native ED2K download background source acquisition completed file_hash={} source_count=0 aggregated_source_count={}",
                    file_hash,
                    sources.len()
                );
                warn!(
                    "native ED2K download background source search returned no sources for file_hash={file_hash}"
                );
            }
            Err(error) => {
                warn!(
                    "native ED2K download background source search failed for file_hash={file_hash}: {error}"
                );
            }
        }
    }

    let active_source_attempts = ed2k_download_source_server_attempt_budget(&config.p2p.ed2k);
    match search_source_servers(Ed2kSourceSearchOptions {
        bind_ip: runtime.bind_ip,
        config: &config.p2p.ed2k,
        hello_identity,
        shared_catalog: &shared_catalog,
        preferred_endpoint,
        excluded_endpoint: has_background_search
            .then_some(preferred_endpoint)
            .flatten(),
        max_attempts: active_source_attempts,
        file_hash,
        file_size,
        cancel: &cancel,
    })
    .await
    {
        Ok(server_results) => {
            let source_count = server_results.len();
            merge_download_sources(&mut sources, server_results);
            info!(
                "native ED2K download active source acquisition completed file_hash={} source_count={} aggregated_source_count={}",
                file_hash,
                source_count,
                sources.len()
            );
        }
        Err(error) => {
            warn!(
                "native ED2K download active server source search failed for file_hash={file_hash}: {error}"
            );
        }
    }
    if sources.is_empty() {
        match search_source_udp_servers(Ed2kUdpSourceSearchOptions {
            bind_ip: runtime.bind_ip,
            config: &config.p2p.ed2k,
            preferred_endpoint,
            excluded_endpoint: has_background_search
                .then_some(preferred_endpoint)
                .flatten(),
            max_attempts: active_source_attempts,
            file_hash,
            file_size,
            timeout: source_search_timeout,
            cancel: &cancel,
        })
        .await
        {
            Ok(udp_results) => {
                let source_count = udp_results.len();
                merge_download_sources(&mut sources, udp_results);
                info!(
                    "native ED2K download UDP source acquisition completed file_hash={} source_count={} aggregated_source_count={}",
                    file_hash,
                    source_count,
                    sources.len()
                );
            }
            Err(error) => {
                warn!(
                    "native ED2K download UDP source search failed for file_hash={file_hash}: {error}"
                );
            }
        }
    }
    if file_size != 0 {
        let existing_source_count = sources.len();
        let kad_supplement_threshold = config.p2p.ed2k.kad_source_supplement_max_existing_sources;
        let should_query_kad =
            existing_source_count == 0 || existing_source_count <= kad_supplement_threshold;
        if should_query_kad {
            let kad_sources = collect_kad_ed2k_sources(
                &runtime.dht,
                file_hash,
                file_size,
                source_search_timeout.max(Duration::from_secs(
                    ED2K_DOWNLOAD_KAD_SOURCE_TIMEOUT_FLOOR_SECS,
                )),
            )
            .await;
            let kad_source_count = kad_sources.len();
            if kad_source_count != 0 {
                merge_download_sources(&mut sources, kad_sources);
                let added_source_count = sources.len().saturating_sub(existing_source_count);
                info!(
                    "native ED2K download Kad source {} produced file_hash={} source_count={} added_source_count={} aggregated_source_count={}",
                    if existing_source_count == 0 {
                        "fallback"
                    } else {
                        "supplement"
                    },
                    file_hash,
                    kad_source_count,
                    added_source_count,
                    sources.len()
                );
            } else {
                info!(
                    "native ED2K download Kad source {} returned no sources for file_hash={} aggregated_source_count={}",
                    if existing_source_count == 0 {
                        "fallback"
                    } else {
                        "supplement"
                    },
                    file_hash,
                    sources.len()
                );
            }
        } else {
            info!(
                "native ED2K download Kad source supplement skipped file_hash={} existing_source_count={} threshold={}",
                file_hash, existing_source_count, kad_supplement_threshold
            );
        }
    } else if sources.is_empty() {
        info!(
            "native ED2K download skipped Kad source fallback for file_hash={} because file_size is unknown",
            file_hash
        );
    }
    info!(
        "native ED2K download source acquisition completed file_hash={} aggregated_source_count={} background_search_enabled={}",
        file_hash,
        sources.len(),
        has_background_search
    );
    Ok(sources)
}

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
