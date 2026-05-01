use std::time::Duration;

use overlord_agent_common::{ContentType, FileRecord, HashType, Protocol, Source, TagEntry};
use overlord_kad_dht::{SearchResult, SourceResult};
use overlord_kad_proto::Ed2kHash;

use crate::config::Ed2kConfig;
use crate::ed2k_server::{Ed2kFoundSource, Ed2kSearchFile};

use super::ED2K_HASH_ONLY_QUERY_PREFIX;

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
