use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::ed2k_server::Ed2kFoundSource;
use overlord_kad_proto::Ed2kHash;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct EnrichEd2kDownloadSource {
    pub(super) ip: Ipv4Addr,
    #[serde(alias = "tcp_port")]
    pub(super) tcp_port: u16,
    #[serde(default, alias = "client_id")]
    pub(super) client_id: Option<u32>,
    #[serde(default, alias = "low_id")]
    pub(super) low_id: Option<bool>,
    #[serde(default, alias = "obfuscation_options")]
    pub(super) obfuscation_options: Option<u8>,
    #[serde(default, alias = "user_hash")]
    pub(super) user_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct EnrichEd2kDownloadRequest {
    pub(super) kind: String,
    #[serde(alias = "file_hash")]
    pub(super) file_hash: String,
    #[serde(default, alias = "file_name", alias = "canonical_name")]
    pub(super) file_name: Option<String>,
    #[serde(default, alias = "file_size")]
    pub(super) file_size: Option<u64>,
    #[serde(default)]
    pub(super) sources: Vec<EnrichEd2kDownloadSource>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IngestLocalFileRequest {
    #[serde(alias = "source_path", alias = "file_path")]
    pub(super) source_path: String,
    #[serde(default, alias = "canonical_name", alias = "file_name")]
    pub(super) canonical_name: Option<String>,
}

impl EnrichEd2kDownloadSource {
    pub(super) fn into_found_source(self, file_hash: Ed2kHash) -> Result<Ed2kFoundSource> {
        let user_hash = self
            .user_hash
            .map(|value| -> Result<[u8; 16]> {
                let bytes = hex::decode(&value)
                    .with_context(|| format!("invalid source user hash {value}"))?;
                let bytes: [u8; 16] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("source user hash must be 16 bytes"))?;
                Ok(bytes)
            })
            .transpose()?;
        Ok(Ed2kFoundSource {
            file_hash,
            ip: self.ip,
            tcp_port: self.tcp_port,
            client_id: self.client_id.unwrap_or_else(|| u32::from(self.ip)),
            low_id: self.low_id.unwrap_or(false),
            obfuscated: self.obfuscation_options.is_some(),
            obfuscation_options: self.obfuscation_options,
            user_hash,
            source_server: None,
        })
    }
}

impl EnrichEd2kDownloadRequest {
    pub(super) fn canonical_name(&self) -> String {
        self.file_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .unwrap_or_else(|| hash_only_ed2k_placeholder_name(&self.file_hash))
    }

    pub(super) fn file_size_or_unknown(&self) -> u64 {
        self.file_size.unwrap_or(0)
    }
}

impl IngestLocalFileRequest {
    pub(super) fn canonical_name(&self) -> Result<String> {
        self.canonical_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .ok_or_else(|| anyhow::anyhow!("local ingest payload requires canonicalName"))
    }
}

pub(super) fn hash_only_ed2k_placeholder_name(file_hash: &str) -> String {
    format!("ed2k-{file_hash}.bin")
}

pub(super) fn is_hash_only_ed2k_placeholder_name(name: &str, file_hash: &str) -> bool {
    name.eq_ignore_ascii_case(&hash_only_ed2k_placeholder_name(file_hash))
}
