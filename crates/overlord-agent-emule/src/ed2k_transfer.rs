//! Native ED2K transfer runtime state for piece-store persistence and
//! transfer-backed shared-file serving.
//!
//! This module does not yet implement the full downloader scheduler, but it
//! establishes the durable storage and shared-catalog boundary the rest of the
//! runtime can build on:
//! - resumable per-download manifests
//! - deterministic piece-store payload paths
//! - transfer job bookkeeping
//! - verified local file exposure for upload serving
//! - compatibility catalog hints for server-side `OP_OFFERFILES`

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use md4::{Digest, Md4};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use overlord_agent_common::{HashType, PopularHash};
use overlord_kad_proto::Ed2kHash;

pub(crate) const ED2K_PART_SIZE: u64 = 9_728_000;
const MANIFEST_FILE_NAME: &str = "resume-manifest.json";
const PAYLOAD_FILE_NAME: &str = "pieces.bin";

/// Shared ED2K advertised file catalog used by the long-lived server session.
pub type Ed2kSharedCatalog = Arc<RwLock<Vec<Ed2kSharedEntry>>>;

/// One persisted or hinted ED2K shared-file entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kSharedEntry {
    /// Stable ED2K file hash in lowercase hex.
    pub file_hash: String,
    /// Canonical file name used in offer-files and filename answers.
    pub canonical_name: String,
    /// Full file size in bytes.
    pub file_size: u64,
    /// Whether the payload is fully verified and safe to serve to peers.
    pub verified_complete: bool,
    /// Byte ranges that are safe to upload. This slice only exposes verified
    /// complete files, but the schema is future-ready for finer-grained ranges.
    pub verified_ranges: Vec<Ed2kSharedRange>,
    /// Whether the entry is only a compatibility hint for offer-files.
    pub compatibility_hint: bool,
    /// Source count carried over from seed/popular-hash inputs when known.
    pub source_count_hint: Option<u32>,
}

impl Ed2kSharedEntry {
    /// Builds a compatibility-only entry from a popular-hash hint.
    #[must_use]
    pub fn from_popular_hash(hash: &PopularHash) -> Option<Self> {
        let HashType::Ed2k(value) = &hash.hash;
        let _ = Ed2kHash::from_str(value).ok()?;
        Some(Self {
            file_hash: value.clone(),
            canonical_name: hash.canonical_name.clone(),
            file_size: hash.size,
            verified_complete: false,
            verified_ranges: Vec::new(),
            compatibility_hint: true,
            source_count_hint: Some(hash.source_count),
        })
    }

    /// Builds a fully verified shared entry from a manifest.
    #[must_use]
    pub fn from_manifest(manifest: &Ed2kResumeManifest) -> Self {
        Self {
            file_hash: manifest.file_hash.clone(),
            canonical_name: manifest.canonical_name.clone(),
            file_size: manifest.file_size,
            verified_complete: manifest.completed,
            verified_ranges: manifest.verified_ranges.clone(),
            compatibility_hint: false,
            source_count_hint: None,
        }
    }

    /// Parse the ED2K hash carried by this entry.
    pub fn parsed_hash(&self) -> Result<Ed2kHash> {
        Ed2kHash::from_str(&self.file_hash)
            .with_context(|| format!("invalid ED2K hash in shared entry {}", self.file_hash))
    }
}

/// One verified byte range that may be served to a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kSharedRange {
    /// Inclusive start offset.
    pub start: u64,
    /// Exclusive end offset.
    pub end: u64,
}

/// One persisted ED2K transfer job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kTransferJob {
    /// ED2K file hash in lowercase hex.
    pub file_hash: String,
    /// Canonical file name.
    pub canonical_name: String,
    /// Target file size.
    pub file_size: u64,
    /// Piece size used by the local piece store.
    pub piece_size: u64,
}

/// Coarse piece lifecycle tracked in the resume manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ed2kTransferState {
    Missing,
    Requested,
    Written,
    Verified,
}

/// Per-piece status tracked by the resume manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kPieceState {
    /// Piece index inside the piece store.
    pub piece_index: u32,
    /// Current lifecycle state for the piece.
    pub state: Ed2kTransferState,
    /// Last persisted byte count written into the piece store for this piece.
    pub bytes_written: u64,
}

/// One source hint remembered across restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kSourceHint {
    /// Remote source IP address.
    pub ip: String,
    /// Remote ED2K TCP port.
    pub tcp_port: u16,
    /// Optional peer user hash when known.
    pub user_hash: Option<String>,
}

/// One pending LowID callback download intent remembered until a peer calls back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kCallbackIntent {
    /// Raw server-reported LowID/client-id used when requesting the callback.
    pub client_id: u32,
    /// File hash in lowercase hex.
    pub file_hash: String,
    /// Canonical file name.
    pub canonical_name: String,
    /// Expected file size.
    pub file_size: u64,
    /// Best-effort source hint captured when the callback was requested.
    pub source: Ed2kSourceHint,
}

/// Durable download resume metadata stored next to the piece payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed2kResumeManifest {
    /// ED2K file hash in lowercase hex.
    pub file_hash: String,
    /// Canonical file name.
    pub canonical_name: String,
    /// Target file size.
    pub file_size: u64,
    /// Piece size used in the piece store.
    pub piece_size: u64,
    /// Whether the entire local payload has been structurally completed and
    /// verified for upload serving.
    pub completed: bool,
    /// Whether the canonical ED2K MD4 hashset for this file has been learned
    /// and validated against the file hash.
    pub md4_hashset_acquired: bool,
    /// Canonical ED2K MD4 part hashes in lowercase hex. For one-part files this
    /// list is empty and the file hash itself is the verification authority.
    #[serde(default)]
    pub md4_hashset: Vec<String>,
    /// Upload-safe verified ranges.
    pub verified_ranges: Vec<Ed2kSharedRange>,
    /// Piece states keyed by piece index.
    pub pieces: Vec<Ed2kPieceState>,
    /// Remembered source hints.
    pub sources: Vec<Ed2kSourceHint>,
}

impl Ed2kResumeManifest {
    /// Build an empty manifest for a new transfer.
    #[must_use]
    pub fn new(job: &Ed2kTransferJob) -> Self {
        let piece_count = piece_count(job.file_size, job.piece_size);
        Self {
            file_hash: job.file_hash.clone(),
            canonical_name: job.canonical_name.clone(),
            file_size: job.file_size,
            piece_size: job.piece_size,
            completed: false,
            md4_hashset_acquired: false,
            md4_hashset: Vec::new(),
            verified_ranges: Vec::new(),
            pieces: (0..piece_count)
                .map(|piece_index| Ed2kPieceState {
                    piece_index,
                    state: Ed2kTransferState::Missing,
                    bytes_written: 0,
                })
                .collect(),
            sources: Vec::new(),
        }
    }

    /// Returns true when all expected parts have been individually verified.
    #[must_use]
    pub fn is_fully_verified(&self) -> bool {
        self.pieces
            .iter()
            .all(|piece| piece.state == Ed2kTransferState::Verified)
    }
}

/// Runtime owner for ED2K transfer manifests, piece-store payloads, and the
/// transfer-backed shared catalog.
#[derive(Debug)]
pub struct Ed2kTransferRuntime {
    root_dir: PathBuf,
    shared_catalog: Ed2kSharedCatalog,
    callback_intents: Arc<RwLock<Vec<Ed2kCallbackIntent>>>,
}

impl Ed2kTransferRuntime {
    /// Load any persisted transfer manifests and create the runtime root if it
    /// does not exist yet.
    pub fn load_or_create(root_dir: &Path) -> Result<Self> {
        fs::create_dir_all(root_dir).with_context(|| {
            format!("failed to create ED2K transfer root {}", root_dir.display())
        })?;
        let shared_catalog = Arc::new(RwLock::new(load_catalog_from_manifests(root_dir)?));
        Ok(Self {
            root_dir: root_dir.to_path_buf(),
            shared_catalog,
            callback_intents: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Borrow the shared catalog used by server-session advertisement and
    /// listener-side upload serving.
    #[must_use]
    pub fn shared_catalog(&self) -> Ed2kSharedCatalog {
        Arc::clone(&self.shared_catalog)
    }

    /// Register one pending LowID callback download intent.
    pub async fn register_callback_intent(&self, intent: Ed2kCallbackIntent) {
        let mut intents = self.callback_intents.write().await;
        if !intents.iter().any(|existing| existing == &intent) {
            intents.push(intent);
        }
    }

    /// Claim the oldest pending LowID callback intent for the specified peer client-id.
    pub async fn claim_callback_intent(&self, client_id: u32) -> Option<Ed2kCallbackIntent> {
        let mut intents = self.callback_intents.write().await;
        let index = intents
            .iter()
            .position(|intent| intent.client_id == client_id)?;
        Some(intents.remove(index))
    }

    /// Replace compatibility-hint catalog entries while preserving verified
    /// local files loaded from manifests.
    pub async fn replace_catalog_hints(&self, hashes: &[PopularHash]) {
        let mut preserved_verified = {
            let guard = self.shared_catalog.read().await;
            guard
                .iter()
                .filter(|entry| !entry.compatibility_hint)
                .cloned()
                .collect::<Vec<_>>()
        };
        preserved_verified.extend(hashes.iter().filter_map(Ed2kSharedEntry::from_popular_hash));
        let mut guard = self.shared_catalog.write().await;
        *guard = dedupe_entries(preserved_verified);
    }

    /// Ensure a transfer manifest exists for the provided job.
    pub async fn ensure_job(&self, job: &Ed2kTransferJob) -> Result<Ed2kResumeManifest> {
        let transfer_dir = self.transfer_dir(&job.file_hash);
        tokio::fs::create_dir_all(&transfer_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to create ED2K transfer directory {}",
                    transfer_dir.display()
                )
            })?;
        let manifest_path = transfer_dir.join(MANIFEST_FILE_NAME);
        if tokio::fs::try_exists(&manifest_path).await? {
            return self.load_manifest_or_rebuild(job).await;
        }
        let manifest = Ed2kResumeManifest::new(job);
        self.store_manifest(&manifest).await?;
        Ok(manifest)
    }

    /// Persist the canonical ED2K MD4 hashset after validating it against the
    /// expected file hash.
    pub async fn store_md4_hashset(
        &self,
        file_hash: &str,
        md4_hashset: Vec<[u8; 16]>,
    ) -> Result<Ed2kResumeManifest> {
        let mut manifest = self.load_manifest(file_hash).await?;
        let expected_hash_count = expected_md4_hash_count(manifest.file_size);
        if md4_hashset.len() != usize::from(expected_hash_count) {
            anyhow::bail!(
                "unexpected MD4 hashset length {} expected {} for {}",
                md4_hashset.len(),
                expected_hash_count,
                file_hash
            );
        }
        validate_md4_hashset(file_hash, &md4_hashset)?;
        manifest.md4_hashset = md4_hashset.iter().map(hex::encode).collect();
        manifest.md4_hashset_acquired = true;
        self.store_manifest(&manifest).await?;
        Ok(manifest)
    }

    /// Record one remembered source hint for a job.
    pub async fn remember_source(&self, file_hash: &str, source: Ed2kSourceHint) -> Result<()> {
        let mut manifest = self.load_manifest(file_hash).await?;
        if !manifest.sources.contains(&source) {
            manifest.sources.push(source);
            self.store_manifest(&manifest).await?;
        }
        Ok(())
    }

    /// Mark a specific missing piece as requested.
    #[cfg(test)]
    pub async fn mark_piece_requested(&self, file_hash: &str, piece_index: u32) -> Result<bool> {
        let mut manifest = self.load_manifest(file_hash).await?;
        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == piece_index)
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        if piece.state == Ed2kTransferState::Missing {
            piece.state = Ed2kTransferState::Requested;
            self.store_manifest(&manifest).await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Claim the next missing part atomically for one peer session.
    pub async fn claim_next_missing_part(&self, file_hash: &str) -> Result<Option<u32>> {
        let mut manifest = self.load_manifest(file_hash).await?;
        let Some(piece) = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.state == Ed2kTransferState::Missing)
        else {
            return Ok(None);
        };
        piece.state = Ed2kTransferState::Requested;
        let piece_index = piece.piece_index;
        self.store_manifest(&manifest).await?;
        Ok(Some(piece_index))
    }

    /// Release a previously requested part back to the missing pool.
    pub async fn release_piece_request(&self, file_hash: &str, piece_index: u32) -> Result<()> {
        let mut manifest = self.load_manifest(file_hash).await?;
        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == piece_index)
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        if piece.state == Ed2kTransferState::Requested {
            piece.state = Ed2kTransferState::Missing;
            piece.bytes_written = 0;
            self.store_manifest(&manifest).await?;
        }
        Ok(())
    }

    /// Persist one downloaded piece into the local piece store.
    pub async fn store_piece_data(
        &self,
        file_hash: &str,
        piece_index: u32,
        data: &[u8],
    ) -> Result<()> {
        let mut manifest = self.load_manifest(file_hash).await?;
        let piece_size = manifest.piece_size;
        let expected_piece_len =
            expected_piece_length(manifest.file_size, piece_size, u64::from(piece_index));
        if u64::try_from(data.len()).unwrap_or(u64::MAX) != expected_piece_len {
            anyhow::bail!(
                "piece {} for {} has unexpected size {} expected {}",
                piece_index,
                file_hash,
                data.len(),
                expected_piece_len
            );
        }
        let payload_path = self.transfer_dir(file_hash).join(PAYLOAD_FILE_NAME);
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&payload_path)
            .await
            .with_context(|| format!("failed to open piece store {}", payload_path.display()))?;
        use tokio::io::{AsyncSeekExt, AsyncWriteExt};
        file.seek(std::io::SeekFrom::Start(
            u64::from(piece_index) * piece_size,
        ))
        .await?;
        file.write_all(data).await?;
        file.flush().await?;
        let verified = verify_piece_against_manifest(&manifest, piece_index, data)?;
        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == piece_index)
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        if verified {
            piece.bytes_written = expected_piece_len;
            piece.state = Ed2kTransferState::Verified;
        } else {
            piece.bytes_written = 0;
            piece.state = Ed2kTransferState::Missing;
        }
        rebuild_verified_ranges(&mut manifest);
        manifest.completed = manifest.is_fully_verified();
        self.upsert_verified_catalog_entry(&manifest).await;
        self.store_manifest(&manifest).await
    }

    /// Read a fully verified range for upload serving.
    pub async fn read_verified_range(
        &self,
        file_hash: &Ed2kHash,
        start: u64,
        end: u64,
    ) -> Result<Option<Vec<u8>>> {
        let hash_hex = file_hash.to_string();
        let manifest = self.load_manifest(&hash_hex).await?;
        if !manifest
            .verified_ranges
            .iter()
            .any(|range| start >= range.start && end <= range.end)
        {
            return Ok(None);
        }
        let payload_path = self.transfer_dir(&hash_hex).join(PAYLOAD_FILE_NAME);
        let mut file = tokio::fs::OpenOptions::new()
            .read(true)
            .open(&payload_path)
            .await
            .with_context(|| format!("failed to open piece store {}", payload_path.display()))?;
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        file.seek(std::io::SeekFrom::Start(start)).await?;
        let mut bytes = vec![0u8; usize::try_from(end.saturating_sub(start)).unwrap_or(0)];
        file.read_exact(&mut bytes).await?;
        Ok(Some(bytes))
    }

    /// Return local manifest-backed file metadata even when only part of the
    /// payload has been verified already.
    pub async fn local_entry(&self, file_hash: &Ed2kHash) -> Result<Option<Ed2kSharedEntry>> {
        let hash_hex = file_hash.to_string();
        let path = self.transfer_dir(&hash_hex).join(MANIFEST_FILE_NAME);
        if !tokio::fs::try_exists(&path).await? {
            return Ok(None);
        }
        let manifest = self.load_manifest(&hash_hex).await?;
        Ok(Some(Ed2kSharedEntry::from_manifest(&manifest)))
    }

    /// Return the canonical MD4 hashset for this file when known.
    pub async fn md4_hashset(&self, file_hash: &Ed2kHash) -> Result<Option<Vec<[u8; 16]>>> {
        let hash_hex = file_hash.to_string();
        let path = self.transfer_dir(&hash_hex).join(MANIFEST_FILE_NAME);
        if !tokio::fs::try_exists(&path).await? {
            return Ok(None);
        }
        let manifest = self.load_manifest(&hash_hex).await?;
        if !manifest.md4_hashset_acquired {
            return Ok(None);
        }
        manifest
            .md4_hashset
            .iter()
            .map(|hash| {
                let bytes = hex::decode(hash).with_context(|| {
                    format!("invalid stored MD4 hashset entry for {}", file_hash)
                })?;
                let array: [u8; 16] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("stored MD4 hashset entry has wrong length"))?;
                Ok(array)
            })
            .collect::<Result<Vec<_>>>()
            .map(Some)
    }

    /// Returns the persisted manifest for orchestration code that needs to read
    /// the current verification or hashset state.
    pub async fn manifest(&self, file_hash: &str) -> Result<Ed2kResumeManifest> {
        self.load_manifest(file_hash).await
    }

    async fn load_manifest_or_rebuild(&self, job: &Ed2kTransferJob) -> Result<Ed2kResumeManifest> {
        match self.load_manifest(&job.file_hash).await {
            Ok(manifest) => Ok(manifest),
            Err(error) => {
                let manifest_path = self.transfer_dir(&job.file_hash).join(MANIFEST_FILE_NAME);
                quarantine_corrupt_manifest(&manifest_path).await?;
                let manifest = Ed2kResumeManifest::new(job);
                self.store_manifest(&manifest).await?;
                tracing::warn!(
                    "rebuilt ED2K manifest after corrupt state for {}: {error}",
                    job.file_hash
                );
                Ok(manifest)
            }
        }
    }

    async fn upsert_verified_catalog_entry(&self, manifest: &Ed2kResumeManifest) {
        let mut entries = self.shared_catalog.write().await;
        entries.retain(|entry| entry.file_hash != manifest.file_hash || entry.compatibility_hint);
        if manifest.completed || !manifest.verified_ranges.is_empty() {
            entries.push(Ed2kSharedEntry::from_manifest(manifest));
        }
        *entries = dedupe_entries(entries.clone());
    }

    async fn load_manifest(&self, file_hash: &str) -> Result<Ed2kResumeManifest> {
        let path = self.transfer_dir(file_hash).join(MANIFEST_FILE_NAME);
        let bytes = tokio::fs::read(&path)
            .await
            .with_context(|| format!("failed to read ED2K manifest {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to decode ED2K manifest {}", path.display()))
    }

    async fn store_manifest(&self, manifest: &Ed2kResumeManifest) -> Result<()> {
        let transfer_dir = self.transfer_dir(&manifest.file_hash);
        tokio::fs::create_dir_all(&transfer_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to create ED2K transfer directory {}",
                    transfer_dir.display()
                )
            })?;
        let path = transfer_dir.join(MANIFEST_FILE_NAME);
        let encoded = serde_json::to_vec_pretty(manifest)?;
        tokio::fs::write(&path, encoded)
            .await
            .with_context(|| format!("failed to write ED2K manifest {}", path.display()))
    }

    fn transfer_dir(&self, file_hash: &str) -> PathBuf {
        self.root_dir.join(file_hash)
    }
}

fn load_catalog_from_manifests(root_dir: &Path) -> Result<Vec<Ed2kSharedEntry>> {
    if !root_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for child in fs::read_dir(root_dir)
        .with_context(|| format!("failed to enumerate {}", root_dir.display()))?
    {
        let child = child?;
        let manifest_path = child.path().join(MANIFEST_FILE_NAME);
        if !manifest_path.exists() {
            continue;
        }
        let bytes = fs::read(&manifest_path)
            .with_context(|| format!("failed to read {}", manifest_path.display()))?;
        let manifest: Ed2kResumeManifest = match serde_json::from_slice(&bytes) {
            Ok(manifest) => manifest,
            Err(error) => {
                tracing::warn!(
                    "skipping malformed ED2K manifest {} during catalog load: {error}",
                    manifest_path.display()
                );
                continue;
            }
        };
        if manifest.completed {
            entries.push(Ed2kSharedEntry::from_manifest(&manifest));
        }
    }
    Ok(dedupe_entries(entries))
}

fn dedupe_entries(entries: Vec<Ed2kSharedEntry>) -> Vec<Ed2kSharedEntry> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::with_capacity(entries.len());
    for entry in entries.into_iter().rev() {
        if seen.insert((entry.file_hash.clone(), entry.compatibility_hint)) {
            deduped.push(entry);
        }
    }
    deduped.reverse();
    deduped
}

async fn quarantine_corrupt_manifest(path: &Path) -> Result<()> {
    if !tokio::fs::try_exists(path).await? {
        return Ok(());
    }
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let quarantine_path = path.with_extension(format!("json.corrupt-{suffix}"));
    tokio::fs::rename(path, &quarantine_path)
        .await
        .with_context(|| {
            format!(
                "failed to quarantine corrupt ED2K manifest {} -> {}",
                path.display(),
                quarantine_path.display()
            )
        })
}

fn piece_count(file_size: u64, piece_size: u64) -> u32 {
    if file_size == 0 {
        return 0;
    }
    u32::try_from(file_size.div_ceil(piece_size)).unwrap_or(u32::MAX)
}

pub(crate) fn expected_piece_length(file_size: u64, piece_size: u64, piece_index: u64) -> u64 {
    let start = piece_index.saturating_mul(piece_size);
    let end = (start + piece_size).min(file_size);
    end.saturating_sub(start)
}

/// Build a default slice-1 transfer job from a file identity.
#[must_use]
pub fn new_transfer_job(
    file_hash: Ed2kHash,
    canonical_name: String,
    file_size: u64,
) -> Ed2kTransferJob {
    Ed2kTransferJob {
        file_hash: file_hash.to_string(),
        canonical_name,
        file_size,
        piece_size: ED2K_PART_SIZE,
    }
}

fn expected_md4_hash_count(file_size: u64) -> u16 {
    if file_size == 0 {
        return 0;
    }
    let whole_parts = file_size / ED2K_PART_SIZE;
    let count = whole_parts + u64::from(whole_parts > 0);
    u16::try_from(count).unwrap_or(u16::MAX)
}

fn validate_md4_hashset(file_hash: &str, md4_hashset: &[[u8; 16]]) -> Result<()> {
    let expected = Ed2kHash::from_str(file_hash)
        .with_context(|| format!("invalid ED2K file hash {}", file_hash))?;
    if md4_hashset.is_empty() {
        return Ok(());
    }
    let mut hasher = Md4::new();
    for part_hash in md4_hashset {
        hasher.update(part_hash);
    }
    let digest: [u8; 16] = hasher.finalize().into();
    if digest != expected.0 {
        anyhow::bail!(
            "MD4 hashset does not reconstruct ED2K file hash {}",
            file_hash
        );
    }
    Ok(())
}

fn verify_piece_against_manifest(
    manifest: &Ed2kResumeManifest,
    piece_index: u32,
    data: &[u8],
) -> Result<bool> {
    let digest: [u8; 16] = Md4::digest(data).into();
    if manifest.md4_hashset_acquired {
        if manifest.md4_hashset.is_empty() {
            let expected = Ed2kHash::from_str(&manifest.file_hash)
                .with_context(|| format!("invalid ED2K file hash {}", manifest.file_hash))?;
            return Ok(digest == expected.0);
        }
        let expected = manifest
            .md4_hashset
            .get(piece_index as usize)
            .with_context(|| format!("missing MD4 hashset entry for part {}", piece_index))?;
        let expected = hex::decode(expected)
            .with_context(|| format!("invalid stored MD4 hashset entry {}", expected))?;
        let expected: [u8; 16] = expected
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored MD4 hashset entry has wrong length"))?;
        return Ok(digest == expected);
    }
    Ok(false)
}

fn rebuild_verified_ranges(manifest: &mut Ed2kResumeManifest) {
    let mut ranges = Vec::new();
    let mut active_start: Option<u64> = None;
    for piece in &manifest.pieces {
        let piece_start = u64::from(piece.piece_index) * manifest.piece_size;
        let piece_end = (piece_start + manifest.piece_size).min(manifest.file_size);
        if piece.state == Ed2kTransferState::Verified {
            if active_start.is_none() {
                active_start = Some(piece_start);
            }
            if piece_end == manifest.file_size {
                ranges.push(Ed2kSharedRange {
                    start: active_start.expect("active start"),
                    end: piece_end,
                });
                active_start = None;
            }
        } else if let Some(start) = active_start.take() {
            ranges.push(Ed2kSharedRange {
                start,
                end: piece_start,
            });
        }
    }
    manifest.verified_ranges = ranges;
}

#[cfg(test)]
mod tests {
    use super::{
        ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kSharedEntry, Ed2kSourceHint, Ed2kTransferRuntime,
        Ed2kTransferState, new_transfer_job,
    };
    use crate::paths::unique_test_dir;
    use md4::{Digest, Md4};
    use overlord_agent_common::{HashType, PopularHash};
    use overlord_kad_proto::Ed2kHash;
    use std::str::FromStr;

    #[tokio::test]
    async fn ensure_job_tracks_verified_parts_via_md4_hashset() {
        let root = unique_test_dir("ed2k-transfer-runtime");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let first_piece = vec![1u8; ED2K_PART_SIZE as usize];
        let last_piece = [2u8; 7];
        let first_piece_hash: [u8; 16] = Md4::digest(&first_piece).into();
        let last_piece_hash: [u8; 16] = Md4::digest(last_piece).into();
        let mut file_hasher = Md4::new();
        file_hasher.update(first_piece_hash);
        file_hasher.update(last_piece_hash);
        let file_hash = Ed2kHash::from_bytes(file_hasher.finalize().into());
        let job = new_transfer_job(
            file_hash,
            "ubuntu-linux.iso".to_string(),
            ED2K_PART_SIZE + 7,
        );
        let manifest = runtime.ensure_job(&job).await.unwrap();
        assert_eq!(manifest.pieces.len(), 2);
        runtime
            .store_md4_hashset(&job.file_hash, vec![first_piece_hash, last_piece_hash])
            .await
            .unwrap();

        runtime
            .mark_piece_requested(&job.file_hash, 0)
            .await
            .unwrap();
        runtime
            .store_piece_data(&job.file_hash, 0, &first_piece)
            .await
            .unwrap();
        let partial = runtime.ensure_job(&job).await.unwrap();
        assert_eq!(partial.pieces[0].state, Ed2kTransferState::Verified);
        assert!(!partial.completed);
        assert_eq!(partial.verified_ranges.len(), 1);
        assert_eq!(partial.verified_ranges[0].start, 0);
        assert_eq!(partial.verified_ranges[0].end, ED2K_PART_SIZE);

        runtime
            .store_piece_data(&job.file_hash, 1, &last_piece)
            .await
            .unwrap();
        let complete = runtime.ensure_job(&job).await.unwrap();
        assert!(complete.completed);
        assert!(
            complete
                .pieces
                .iter()
                .all(|piece| piece.state == Ed2kTransferState::Verified)
        );

        let shared = runtime.shared_catalog().read().await.clone();
        assert!(
            shared
                .iter()
                .any(|entry| entry.file_hash == job.file_hash && entry.verified_complete)
        );
    }

    #[tokio::test]
    async fn replace_catalog_hints_preserves_verified_entries() {
        let root = unique_test_dir("ed2k-transfer-hints");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = [9u8, 8, 7, 6];
        let file_hash = Ed2kHash::from_bytes(Md4::digest(payload).into());
        let job = new_transfer_job(file_hash, "verified.bin".to_string(), payload.len() as u64);
        runtime.ensure_job(&job).await.unwrap();
        runtime
            .store_md4_hashset(&job.file_hash, Vec::new())
            .await
            .unwrap();
        runtime
            .store_piece_data(&job.file_hash, 0, &payload)
            .await
            .unwrap();

        runtime
            .replace_catalog_hints(&[PopularHash {
                hash: HashType::Ed2k("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
                canonical_name: "hint.bin".to_string(),
                size: 12,
                source_count: 3,
            }])
            .await;

        let shared = runtime.shared_catalog().read().await.clone();
        assert!(
            shared
                .iter()
                .any(|entry| entry.file_hash == job.file_hash && entry.verified_complete)
        );
        assert!(shared.iter().any(
            |entry| entry.file_hash == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                && entry.compatibility_hint
        ));
    }

    #[test]
    fn shared_entry_from_popular_hash_requires_valid_ed2k_hash() {
        let popular = PopularHash {
            hash: HashType::Ed2k("not-a-real-hash".to_string()),
            canonical_name: "bad.bin".to_string(),
            size: 1,
            source_count: 1,
        };
        assert!(Ed2kSharedEntry::from_popular_hash(&popular).is_none());
    }

    #[test]
    fn manifest_new_initializes_missing_piece_state() {
        let file_hash = Ed2kHash::from_str("fedcba9876543210fedcba9876543210").unwrap();
        let job = new_transfer_job(file_hash, "ubuntu.iso".to_string(), ED2K_PART_SIZE * 2);
        let manifest = Ed2kResumeManifest::new(&job);
        assert_eq!(manifest.pieces.len(), 2);
        assert!(
            manifest
                .pieces
                .iter()
                .all(|piece| piece.state == Ed2kTransferState::Missing)
        );
        assert_eq!(manifest.sources, Vec::<Ed2kSourceHint>::new());
    }
}
