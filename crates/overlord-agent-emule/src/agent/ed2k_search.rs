use std::{
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::Result;
use overlord_agent_common::{ContentType, FileRecord, HashType, Protocol, Source, TagEntry};
use overlord_agent_common::{CoordinatorClient, SearchJob};
use overlord_kad_dht::{DhtNode, RpcWorkClass, SearchResult, SourceResult};
use overlord_kad_proto::Ed2kHash;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::{Ed2kConfig, EmuleAgentConfig};
use crate::ed2k_server::{
    Ed2kFoundSource, Ed2kKeywordSearchOptions, Ed2kSearchFile, Ed2kServerSearchHandle,
    Ed2kSourceSearchOptions, search_keyword_servers, search_keyword_via_background_session,
    search_source_servers, search_source_via_background_session,
};
use crate::ed2k_transfer::Ed2kSharedEntry;

use super::ed2k_runtime::ed2k_hello_identity_from_config;
use super::search::{
    SearchRunStats, post_search_batch, search_file_hash, search_file_size, search_query,
};
use super::{
    AgentNetworkRuntime, ED2K_ACTIVE_SEARCH_MAX_SERVER_ATTEMPTS, ED2K_DOWNLOAD_KAD_SOURCE_CAP,
    ED2K_DOWNLOAD_KAD_SOURCE_RETRY_DELAY_MS, ED2K_HASH_ONLY_QUERY_PREFIX, keyword_target,
    merge_download_sources,
};

fn ed2k_content_type(file_type: Option<&str>) -> Option<ContentType> {
    match file_type {
        Some("Video") => Some(ContentType::Video),
        Some("Audio") => Some(ContentType::Audio),
        Some("Doc") => Some(ContentType::Document),
        Some("Pro") | Some("EmuleCollection") => Some(ContentType::Software),
        Some(_) => Some(ContentType::Unknown),
        None => None,
    }
}

pub(super) fn map_ed2k_keyword_result(result: &Ed2kSearchFile) -> FileRecord {
    let mut tags = Vec::new();
    if let Some(file_type) = result.file_type.as_deref() {
        tags.push(TagEntry {
            key: "ed2k_file_type".to_string(),
            value: serde_json::json!(file_type),
        });
    }
    if let Some(source_count) = result.source_count {
        tags.push(TagEntry {
            key: "ed2k_source_count".to_string(),
            value: serde_json::json!(source_count),
        });
    }

    FileRecord {
        hashes: vec![HashType::Ed2k(result.file_hash.to_string())],
        names: result.file_name.iter().cloned().collect(),
        size: result.file_size,
        content_type: ed2k_content_type(result.file_type.as_deref()),
        tags,
        sources: Vec::new(),
    }
}

pub(super) fn map_ed2k_source_result(result: &Ed2kFoundSource, file_size: u64) -> FileRecord {
    FileRecord {
        hashes: vec![HashType::Ed2k(result.file_hash.to_string())],
        names: Vec::new(),
        size: Some(file_size),
        content_type: None,
        tags: Vec::new(),
        sources: vec![Source {
            protocol: Protocol::Ed2k,
            address: format!("{}:{}", result.ip, result.tcp_port),
            extra: serde_json::json!({
                "search_mode": "server_source",
                "client_id": result.client_id,
                "direct_dialable": result.is_direct_dialable(),
                "low_id": result.low_id,
                "obfuscated": result.obfuscated,
                "obfuscation_options": result.obfuscation_options,
                "user_hash": result.user_hash.map(hex::encode),
            }),
        }],
    }
}

/// Live `OP_GETSOURCES` replies often arrive later than the initial ED2K
/// login/status handshake, so source discovery needs a wider timeout budget
/// than the generic connect timeout.
pub(super) fn ed2k_source_search_timeout(config: &Ed2kConfig) -> Duration {
    Duration::from_secs(config.connect_timeout_secs.max(15))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct LearnedEd2kMetadata {
    pub(super) canonical_name: Option<String>,
    pub(super) file_size: Option<u64>,
}

impl LearnedEd2kMetadata {
    pub(super) fn merge_missing_from(&mut self, other: Self) {
        if self.canonical_name.is_none() {
            self.canonical_name = other.canonical_name;
        }
        if self.file_size.is_none() {
            self.file_size = other.file_size;
        }
    }

    pub(super) fn is_complete(&self) -> bool {
        self.canonical_name.is_some() && self.file_size.is_some()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.canonical_name.is_none() && self.file_size.is_none()
    }
}

fn normalized_optional_canonical_name(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(super) fn hash_only_ed2k_search_query(file_hash: Ed2kHash) -> String {
    format!("{ED2K_HASH_ONLY_QUERY_PREFIX}{file_hash}")
}

pub(super) fn exact_ed2k_hash_query_token(query: &str) -> Option<String> {
    let trimmed = query.trim();
    let candidate = trimmed
        .strip_prefix(ED2K_HASH_ONLY_QUERY_PREFIX)
        .unwrap_or(trimmed)
        .trim();
    if candidate.len() == 32 && candidate.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(candidate.to_ascii_lowercase())
    } else {
        None
    }
}

fn ed2k_configured_server_attempt_budget(config: &Ed2kConfig) -> usize {
    config
        .server_entries
        .len()
        .max(config.server_endpoints.len())
        .max(1)
}

pub(super) fn ed2k_keyword_server_attempt_budget(config: &Ed2kConfig, query: &str) -> usize {
    let configured_budget = ed2k_configured_server_attempt_budget(config);
    if exact_ed2k_hash_query_token(query).is_some() {
        config
            .exact_hash_keyword_server_attempt_budget
            .max(1)
            .min(configured_budget)
    } else {
        config
            .keyword_server_attempt_budget
            .max(1)
            .min(configured_budget)
    }
}

pub(super) fn ed2k_download_source_server_attempt_budget(config: &Ed2kConfig) -> usize {
    config
        .source_server_attempt_budget
        .max(1)
        .min(ed2k_configured_server_attempt_budget(config))
}

pub(super) fn select_ed2k_keyword_metadata(
    results: &[Ed2kSearchFile],
    file_hash: Ed2kHash,
) -> Option<LearnedEd2kMetadata> {
    results
        .iter()
        .filter(|result| result.file_hash == file_hash)
        .filter_map(|result| {
            let metadata = LearnedEd2kMetadata {
                canonical_name: normalized_optional_canonical_name(result.file_name.as_deref()),
                file_size: result.file_size.filter(|file_size| *file_size != 0),
            };
            if metadata.is_empty() {
                None
            } else {
                Some((
                    metadata.file_size.is_some(),
                    metadata.canonical_name.is_some(),
                    result.source_count.unwrap_or(0),
                    metadata,
                ))
            }
        })
        .max_by_key(|(has_size, has_name, source_count, _)| (*has_size, *has_name, *source_count))
        .map(|(_, _, _, metadata)| metadata)
}

pub(super) fn select_kad_keyword_metadata(
    result: &SearchResult,
    file_hash: Ed2kHash,
) -> Option<LearnedEd2kMetadata> {
    if result.hash != file_hash {
        return None;
    }
    let metadata = LearnedEd2kMetadata {
        canonical_name: result
            .names
            .iter()
            .find_map(|name| normalized_optional_canonical_name(Some(name))),
        file_size: result.size.filter(|file_size| *file_size != 0),
    };
    (!metadata.is_empty()).then_some(metadata)
}

/// Kad source search remains a viable fallback when ED2K servers accept login
/// traffic but never answer `OP_GETSOURCES` for a concrete file.
pub(super) fn kad_source_result_to_ed2k_found_source(result: SourceResult) -> Ed2kFoundSource {
    Ed2kFoundSource {
        file_hash: result.file_hash,
        ip: result.ip,
        tcp_port: result.tcp_port,
        client_id: u32::from(result.ip),
        low_id: false,
        obfuscated: result.obfuscation_options.is_some(),
        obfuscation_options: result.obfuscation_options,
        user_hash: Some(result.source_id.0),
        source_server: None,
    }
}

async fn collect_kad_ed2k_metadata(
    dht: &DhtNode,
    query: &str,
    file_hash: Ed2kHash,
    timeout: Duration,
) -> Option<LearnedEd2kMetadata> {
    let cancel = CancellationToken::new();
    let mut stream = dht.search_keywords_with_cancel_and_class(
        keyword_target(query),
        cancel.clone(),
        RpcWorkClass::Interactive,
    );
    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);
    let mut learned = LearnedEd2kMetadata::default();

    loop {
        tokio::select! {
            _ = &mut sleep => break,
            result = stream.next() => {
                let Some(result) = result else {
                    break;
                };
                if let Some(candidate) = select_kad_keyword_metadata(&result, file_hash) {
                    learned.merge_missing_from(candidate);
                    if learned.is_complete() {
                        break;
                    }
                }
            }
        }
    }

    cancel.cancel();
    (!learned.is_empty()).then_some(learned)
}

pub(super) async fn resolve_hash_only_ed2k_metadata(
    runtime: &AgentNetworkRuntime,
    config: &EmuleAgentConfig,
    file_hash: Ed2kHash,
    ed2k_user_hash: [u8; 16],
) -> Result<Option<LearnedEd2kMetadata>> {
    let cancel = CancellationToken::new();
    let mut learned = LearnedEd2kMetadata::default();
    let shared_catalog = runtime.ed2k_shared_catalog.read().await.clone();
    let keyword_search_timeout = ed2k_source_search_timeout(&config.p2p.ed2k);
    let keyword_query = hash_only_ed2k_search_query(file_hash);
    let hello_identity = ed2k_hello_identity_from_config(config, ed2k_user_hash);
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
    let background_search_available = background_search.is_some();

    if let Some(background_search) = background_search {
        match search_keyword_via_background_session(
            &background_search,
            &keyword_query,
            keyword_search_timeout,
            &cancel,
        )
        .await
        {
            Ok(results) => {
                if let Some(candidate) = select_ed2k_keyword_metadata(&results, file_hash) {
                    learned.merge_missing_from(candidate);
                    info!(
                        "native ED2K download learned metadata from background keyword search file_hash={} file_name={} file_size={}",
                        file_hash,
                        learned.canonical_name.as_deref().unwrap_or("-"),
                        learned.file_size.unwrap_or(0)
                    );
                } else {
                    info!(
                        "native ED2K download background keyword search returned no exact metadata match file_hash={}",
                        file_hash
                    );
                }
            }
            Err(error) => warn!(
                "native ED2K download background keyword search failed for file_hash={file_hash}: {error}"
            ),
        }
    }

    if !learned.is_complete() {
        let active_server_attempts =
            ed2k_keyword_server_attempt_budget(&config.p2p.ed2k, &keyword_query);
        match search_keyword_servers(Ed2kKeywordSearchOptions {
            bind_ip: runtime.bind_ip,
            config: &config.p2p.ed2k,
            hello_identity,
            shared_catalog: &shared_catalog,
            preferred_endpoint: (!background_search_available)
                .then_some(preferred_endpoint)
                .flatten(),
            max_attempts: active_server_attempts,
            query: &keyword_query,
            cancel: &cancel,
        })
        .await
        {
            Ok(results) => {
                if let Some(candidate) = select_ed2k_keyword_metadata(&results, file_hash) {
                    learned.merge_missing_from(candidate);
                    info!(
                        "native ED2K download learned metadata from active server keyword search file_hash={} file_name={} file_size={}",
                        file_hash,
                        learned.canonical_name.as_deref().unwrap_or("-"),
                        learned.file_size.unwrap_or(0)
                    );
                } else {
                    info!(
                        "native ED2K download active keyword search returned no exact metadata match file_hash={}",
                        file_hash
                    );
                }
            }
            Err(error) => warn!(
                "native ED2K download active server keyword search failed for file_hash={file_hash}: {error}"
            ),
        }
    }

    if !learned.is_complete()
        && let Some(candidate) = collect_kad_ed2k_metadata(
            &runtime.dht,
            &keyword_query,
            file_hash,
            keyword_search_timeout,
        )
        .await
    {
        learned.merge_missing_from(candidate);
        info!(
            "native ED2K download learned metadata from Kad keyword search file_hash={} file_name={} file_size={}",
            file_hash,
            learned.canonical_name.as_deref().unwrap_or("-"),
            learned.file_size.unwrap_or(0)
        );
    }

    Ok((!learned.is_empty()).then_some(learned))
}

/// Collects Kad-advertised ED2K sources for a bounded window so downloads can
/// proceed even when server-assisted source discovery is flaky.
pub(super) async fn collect_kad_ed2k_sources(
    dht: &DhtNode,
    file_hash: Ed2kHash,
    file_size: u64,
    timeout: Duration,
) -> Vec<Ed2kFoundSource> {
    let mut sources = Vec::new();
    let deadline = Instant::now() + timeout;
    let retry_delay = Duration::from_millis(ED2K_DOWNLOAD_KAD_SOURCE_RETRY_DELAY_MS);
    let mut attempts = 0usize;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        attempts += 1;
        let cancel = CancellationToken::new();
        let mut stream = dht.search_sources_with_cancel_and_class(
            file_hash,
            file_size,
            cancel.clone(),
            RpcWorkClass::Interactive,
        );
        let sleep = tokio::time::sleep(remaining);
        tokio::pin!(sleep);

        loop {
            tokio::select! {
                _ = &mut sleep => {
                    cancel.cancel();
                    break;
                }
                result = stream.next() => {
                    let Some(result) = result else {
                        break;
                    };
                    merge_download_sources(
                        &mut sources,
                        vec![kad_source_result_to_ed2k_found_source(result)],
                    );
                    if sources.len() >= ED2K_DOWNLOAD_KAD_SOURCE_CAP {
                        cancel.cancel();
                        info!(
                            "Kad source lookup reached cap file_hash={} attempts={} source_count={}",
                            file_hash,
                            attempts,
                            sources.len()
                        );
                        return sources;
                    }
                }
            }
        }

        cancel.cancel();
        if !sources.is_empty() {
            info!(
                "Kad source lookup produced file_hash={} attempts={} source_count={}",
                file_hash,
                attempts,
                sources.len()
            );
            return sources;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining <= retry_delay {
            break;
        }
        tokio::time::sleep(retry_delay).await;
    }

    info!(
        "Kad source lookup exhausted file_hash={} attempts={} source_count=0",
        file_hash, attempts
    );
    sources
}

pub(super) struct ActiveEd2kSearchContext<'a> {
    pub(super) bind_ip: Ipv4Addr,
    pub(super) indexer_id: Uuid,
    pub(super) ed2k_user_hash: [u8; 16],
    pub(super) shared_catalog: &'a [Ed2kSharedEntry],
    pub(super) job: &'a SearchJob,
    pub(super) config: &'a EmuleAgentConfig,
    pub(super) background_search: Option<Ed2kServerSearchHandle>,
    pub(super) preferred_endpoint: Option<SocketAddr>,
    pub(super) cancel: CancellationToken,
}

pub(super) async fn do_active_ed2k_keyword_search(
    context: ActiveEd2kSearchContext<'_>,
) -> Result<SearchRunStats> {
    let ActiveEd2kSearchContext {
        bind_ip,
        indexer_id,
        ed2k_user_hash,
        shared_catalog,
        job,
        config,
        background_search,
        preferred_endpoint,
        cancel,
    } = context;
    let callback_client = CoordinatorClient::new(&job.callback_url)?;
    let hello_identity = ed2k_hello_identity_from_config(config, ed2k_user_hash);
    let query = search_query(job)?;
    let search_timeout = Duration::from_secs(config.p2p.ed2k.connect_timeout_secs.max(5));
    let active_server_attempts = ed2k_keyword_server_attempt_budget(&config.p2p.ed2k, query);
    let files = if let Some(background_search) = background_search {
        match search_keyword_via_background_session(
            &background_search,
            query,
            search_timeout,
            &cancel,
        )
        .await
        {
            Ok(results) if !results.is_empty() => {
                info!(
                    "ED2K active keyword search used background session endpoint={} query_len={} result_count={}",
                    preferred_endpoint
                        .map(|endpoint| endpoint.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    query.len(),
                    results.len()
                );
                results
                    .into_iter()
                    .map(|result| map_ed2k_keyword_result(&result))
                    .collect()
            }
            Ok(_) => {
                warn!(
                    "ED2K background session search returned no results for query={query:?}; falling back to one-shot search"
                );
                search_keyword_servers(Ed2kKeywordSearchOptions {
                    bind_ip,
                    config: &config.p2p.ed2k,
                    hello_identity,
                    shared_catalog,
                    preferred_endpoint,
                    max_attempts: active_server_attempts,
                    query,
                    cancel: &cancel,
                })
                .await?
                .into_iter()
                .map(|result| map_ed2k_keyword_result(&result))
                .collect()
            }
            Err(error) => {
                warn!(
                    "ED2K background session search failed for query={query:?}; falling back to one-shot search: {error}"
                );
                search_keyword_servers(Ed2kKeywordSearchOptions {
                    bind_ip,
                    config: &config.p2p.ed2k,
                    hello_identity,
                    shared_catalog,
                    preferred_endpoint,
                    max_attempts: active_server_attempts,
                    query,
                    cancel: &cancel,
                })
                .await?
                .into_iter()
                .map(|result| map_ed2k_keyword_result(&result))
                .collect()
            }
        }
    } else {
        search_keyword_servers(Ed2kKeywordSearchOptions {
            bind_ip,
            config: &config.p2p.ed2k,
            hello_identity,
            shared_catalog,
            preferred_endpoint,
            max_attempts: active_server_attempts,
            query,
            cancel: &cancel,
        })
        .await?
        .into_iter()
        .map(|result| map_ed2k_keyword_result(&result))
        .collect()
    };
    let mut stats = SearchRunStats::default();
    post_search_batch(
        &callback_client,
        job.job_id,
        indexer_id,
        Protocol::Ed2k,
        files,
        &mut stats,
    )
    .await?;
    Ok(stats)
}

pub(super) async fn do_active_ed2k_source_search(
    context: ActiveEd2kSearchContext<'_>,
) -> Result<SearchRunStats> {
    let ActiveEd2kSearchContext {
        bind_ip,
        indexer_id,
        ed2k_user_hash,
        shared_catalog,
        job,
        config,
        background_search,
        preferred_endpoint,
        cancel,
    } = context;
    let callback_client = CoordinatorClient::new(&job.callback_url)?;
    let hello_identity = ed2k_hello_identity_from_config(config, ed2k_user_hash);
    let file_hash = search_file_hash(job)?;
    let file_size = search_file_size(job)?;
    let source_search_timeout = ed2k_source_search_timeout(&config.p2p.ed2k);
    let files = if let Some(background_search) = background_search {
        // Keep source-search fallback off the already connected background
        // server. eMule issues local source requests on its one live server
        // session instead of opening a second parallel login to the same
        // endpoint with the same client identity.
        let fallback_excluded_endpoint = preferred_endpoint;
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
                info!(
                    "ED2K active source search used background session endpoint={} file_hash={} source_count={}",
                    preferred_endpoint
                        .map(|endpoint| endpoint.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    file_hash,
                    results.len()
                );
                results
                    .into_iter()
                    .map(|result| map_ed2k_source_result(&result, file_size))
                    .collect()
            }
            Ok(_) => {
                warn!(
                    "ED2K background session source search returned no sources for file_hash={file_hash}; falling back to one-shot search"
                );
                search_source_servers(Ed2kSourceSearchOptions {
                    bind_ip,
                    config: &config.p2p.ed2k,
                    hello_identity,
                    shared_catalog,
                    preferred_endpoint,
                    excluded_endpoint: fallback_excluded_endpoint,
                    max_attempts: ED2K_ACTIVE_SEARCH_MAX_SERVER_ATTEMPTS,
                    file_hash,
                    file_size,
                    cancel: &cancel,
                })
                .await?
                .into_iter()
                .map(|result| map_ed2k_source_result(&result, file_size))
                .collect()
            }
            Err(error) => {
                warn!(
                    "ED2K background session source search failed for file_hash={file_hash}; falling back to one-shot search: {error}"
                );
                search_source_servers(Ed2kSourceSearchOptions {
                    bind_ip,
                    config: &config.p2p.ed2k,
                    hello_identity,
                    shared_catalog,
                    preferred_endpoint,
                    excluded_endpoint: fallback_excluded_endpoint,
                    max_attempts: ED2K_ACTIVE_SEARCH_MAX_SERVER_ATTEMPTS,
                    file_hash,
                    file_size,
                    cancel: &cancel,
                })
                .await?
                .into_iter()
                .map(|result| map_ed2k_source_result(&result, file_size))
                .collect()
            }
        }
    } else {
        search_source_servers(Ed2kSourceSearchOptions {
            bind_ip,
            config: &config.p2p.ed2k,
            hello_identity,
            shared_catalog,
            preferred_endpoint,
            excluded_endpoint: None,
            max_attempts: ED2K_ACTIVE_SEARCH_MAX_SERVER_ATTEMPTS,
            file_hash,
            file_size,
            cancel: &cancel,
        })
        .await?
        .into_iter()
        .map(|result| map_ed2k_source_result(&result, file_size))
        .collect()
    };
    let mut stats = SearchRunStats::default();
    post_search_batch(
        &callback_client,
        job.job_id,
        indexer_id,
        Protocol::Ed2k,
        files,
        &mut stats,
    )
    .await?;
    Ok(stats)
}
