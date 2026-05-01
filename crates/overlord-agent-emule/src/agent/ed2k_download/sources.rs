use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    config::EmuleAgentConfig,
    ed2k_server::{
        Ed2kFoundSource, Ed2kServerSearchHandle, Ed2kSourceSearchOptions,
        Ed2kUdpSourceSearchOptions, search_source_servers, search_source_udp_servers,
        search_source_via_background_session,
    },
    ed2k_tcp::{Ed2kHelloIdentity, emule_connect_options},
    ed2k_transfer::Ed2kSharedEntry,
};
use overlord_kad_proto::Ed2kHash;

use super::super::{
    AgentNetworkRuntime, ED2K_DOWNLOAD_KAD_SOURCE_TIMEOUT_FLOOR_SECS,
    ed2k_search::{
        collect_kad_ed2k_sources, ed2k_download_source_server_attempt_budget,
        ed2k_source_search_timeout,
    },
    merge_download_sources,
};
#[derive(Clone, Copy)]
struct ServerSourceSearchContext<'a> {
    runtime: &'a AgentNetworkRuntime,
    config: &'a EmuleAgentConfig,
    preferred_endpoint: Option<SocketAddr>,
    has_background_search: bool,
    active_source_attempts: usize,
    file_hash: Ed2kHash,
    file_size: u64,
    cancel: &'a CancellationToken,
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
    collect_background_session_sources(
        &mut sources,
        background_search,
        file_hash,
        file_size,
        source_search_timeout,
        &cancel,
    )
    .await;
    let active_source_attempts = ed2k_download_source_server_attempt_budget(&config.p2p.ed2k);
    let server_source_context = ServerSourceSearchContext {
        runtime,
        config,
        preferred_endpoint,
        has_background_search,
        active_source_attempts,
        file_hash,
        file_size,
        cancel: &cancel,
    };
    collect_active_server_sources(
        &mut sources,
        server_source_context,
        hello_identity,
        &shared_catalog,
    )
    .await;
    if sources.is_empty() {
        collect_udp_server_sources(&mut sources, server_source_context, source_search_timeout)
            .await;
    }
    collect_kad_source_supplement(
        &mut sources,
        runtime,
        config,
        file_hash,
        file_size,
        source_search_timeout,
    )
    .await;
    info!(
        "native ED2K download source acquisition completed file_hash={} aggregated_source_count={} background_search_enabled={}",
        file_hash,
        sources.len(),
        has_background_search
    );
    Ok(sources)
}

async fn collect_background_session_sources(
    sources: &mut Vec<Ed2kFoundSource>,
    background_search: Option<Ed2kServerSearchHandle>,
    file_hash: Ed2kHash,
    file_size: u64,
    source_search_timeout: Duration,
    cancel: &CancellationToken,
) {
    let Some(background_search) = background_search else {
        return;
    };
    match search_source_via_background_session(
        &background_search,
        file_hash,
        file_size,
        source_search_timeout,
        cancel,
    )
    .await
    {
        Ok(results) if !results.is_empty() => {
            let source_count = results.len();
            merge_download_sources(sources, results);
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

async fn collect_active_server_sources(
    sources: &mut Vec<Ed2kFoundSource>,
    context: ServerSourceSearchContext<'_>,
    hello_identity: Ed2kHelloIdentity,
    shared_catalog: &[Ed2kSharedEntry],
) {
    match search_source_servers(Ed2kSourceSearchOptions {
        bind_ip: context.runtime.bind_ip,
        config: &context.config.p2p.ed2k,
        hello_identity,
        shared_catalog,
        preferred_endpoint: context.preferred_endpoint,
        excluded_endpoint: context
            .has_background_search
            .then_some(context.preferred_endpoint)
            .flatten(),
        max_attempts: context.active_source_attempts,
        file_hash: context.file_hash,
        file_size: context.file_size,
        cancel: context.cancel,
    })
    .await
    {
        Ok(server_results) => {
            let source_count = server_results.len();
            merge_download_sources(sources, server_results);
            info!(
                "native ED2K download active source acquisition completed file_hash={} source_count={} aggregated_source_count={}",
                context.file_hash,
                source_count,
                sources.len()
            );
        }
        Err(error) => {
            warn!(
                "native ED2K download active server source search failed for file_hash={}: {error}",
                context.file_hash
            );
        }
    }
}

async fn collect_udp_server_sources(
    sources: &mut Vec<Ed2kFoundSource>,
    context: ServerSourceSearchContext<'_>,
    source_search_timeout: Duration,
) {
    match search_source_udp_servers(Ed2kUdpSourceSearchOptions {
        bind_ip: context.runtime.bind_ip,
        config: &context.config.p2p.ed2k,
        preferred_endpoint: context.preferred_endpoint,
        excluded_endpoint: context
            .has_background_search
            .then_some(context.preferred_endpoint)
            .flatten(),
        max_attempts: context.active_source_attempts,
        file_hash: context.file_hash,
        file_size: context.file_size,
        timeout: source_search_timeout,
        cancel: context.cancel,
    })
    .await
    {
        Ok(udp_results) => {
            let source_count = udp_results.len();
            merge_download_sources(sources, udp_results);
            info!(
                "native ED2K download UDP source acquisition completed file_hash={} source_count={} aggregated_source_count={}",
                context.file_hash,
                source_count,
                sources.len()
            );
        }
        Err(error) => {
            warn!(
                "native ED2K download UDP source search failed for file_hash={}: {error}",
                context.file_hash
            );
        }
    }
}

async fn collect_kad_source_supplement(
    sources: &mut Vec<Ed2kFoundSource>,
    runtime: &AgentNetworkRuntime,
    config: &EmuleAgentConfig,
    file_hash: Ed2kHash,
    file_size: u64,
    source_search_timeout: Duration,
) {
    if file_size == 0 {
        if sources.is_empty() {
            info!(
                "native ED2K download skipped Kad source fallback for file_hash={} because file_size is unknown",
                file_hash
            );
        }
        return;
    }

    let existing_source_count = sources.len();
    let kad_supplement_threshold = config.p2p.ed2k.kad_source_supplement_max_existing_sources;
    let should_query_kad =
        existing_source_count == 0 || existing_source_count <= kad_supplement_threshold;
    if !should_query_kad {
        info!(
            "native ED2K download Kad source supplement skipped file_hash={} existing_source_count={} threshold={}",
            file_hash, existing_source_count, kad_supplement_threshold
        );
        return;
    }

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
    let kad_mode = if existing_source_count == 0 {
        "fallback"
    } else {
        "supplement"
    };
    if kad_source_count != 0 {
        merge_download_sources(sources, kad_sources);
        let added_source_count = sources.len().saturating_sub(existing_source_count);
        info!(
            "native ED2K download Kad source {} produced file_hash={} source_count={} added_source_count={} aggregated_source_count={}",
            kad_mode,
            file_hash,
            kad_source_count,
            added_source_count,
            sources.len()
        );
    } else {
        info!(
            "native ED2K download Kad source {} returned no sources for file_hash={} aggregated_source_count={}",
            kad_mode,
            file_hash,
            sources.len()
        );
    }
}
