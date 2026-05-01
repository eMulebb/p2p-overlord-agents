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
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

use overlord_agent_common::PopularHash;
use overlord_kad_proto::Ed2kHash;

mod catalog;
mod hashset;
mod manifest;
mod upload_queue;

pub use catalog::{Ed2kSharedCatalog, Ed2kSharedEntry, Ed2kSharedRange};
pub(crate) use hashset::decode_aich_hash_hex;
use hashset::{
    build_aich_hashset_from_payload, build_md4_hashset_from_payload, decode_manifest_aich_hashset,
    expected_md4_hash_count, refresh_completed_manifest_aich_hashset, validate_aich_hashset,
    validate_md4_hashset,
};
pub(crate) use manifest::expected_piece_length;
pub use manifest::new_transfer_job;
use manifest::{
    Ed2kManifestCheckpointState, dedupe_entries, load_catalog_from_manifests,
    manifest_has_structural_progress, manifest_progress_bytes, piece_count,
    quarantine_corrupt_manifest, rebuild_verified_ranges, verify_piece_against_manifest,
};
use upload_queue::Ed2kUploadQueueState;
pub(crate) use upload_queue::{
    Ed2kUploadPeerIdentity, Ed2kUploadQueueConfig, Ed2kUploadSessionHandle, Ed2kUploadSessionStatus,
};

pub(crate) const ED2K_PART_SIZE: u64 = 9_728_000;
/// Canonical eMule upload block size used inside one ED2K part request.
pub(crate) const ED2K_EMBLOCK_SIZE: u64 = 184_320;
const MANIFEST_FILE_NAME: &str = "resume-manifest.json";
const PAYLOAD_FILE_NAME: &str = "pieces.bin";
const ED2K_RESUME_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(2);
const ED2K_RESUME_CHECKPOINT_BYTES: u64 = ED2K_EMBLOCK_SIZE * 16;

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

/// One claimed download piece plus the already persisted byte prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ed2kClaimedPart {
    /// Piece index inside the resume manifest.
    pub piece_index: u32,
    /// Number of contiguous bytes already persisted for this piece.
    pub bytes_written: u64,
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

/// Canonical AICH master hash plus per-part hashes for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ed2kAichHashset {
    pub master_hash: [u8; 20],
    pub part_hashes: Vec<[u8; 20]>,
}

/// Summary returned after a local payload is ingested into the transfer store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ed2kLocalIngestSummary {
    pub file_hash: String,
    pub canonical_name: String,
    pub file_size: u64,
    pub md4_hashset_count: usize,
    pub aich_root: String,
    pub aich_hashset_count: usize,
    pub transfer_dir: String,
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
    /// Whether the canonical AICH part-hash set for this file has been
    /// learned or derived locally.
    pub aich_hashset_acquired: bool,
    /// Canonical AICH root in lowercase hex when known.
    pub aich_root: Option<String>,
    /// Canonical AICH per-part hashes in lowercase hex.
    pub aich_hashset: Vec<String>,
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
            aich_hashset_acquired: false,
            aich_root: None,
            aich_hashset: Vec::new(),
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
    manifest_io: Arc<Mutex<()>>,
    manifest_cache: Arc<Mutex<HashMap<String, Ed2kResumeManifest>>>,
    manifest_checkpoint_state: Arc<Mutex<HashMap<String, Ed2kManifestCheckpointState>>>,
    upload_queue: Arc<Mutex<Ed2kUploadQueueState>>,
    next_upload_connection_id: AtomicU64,
}

impl Ed2kTransferRuntime {
    /// Load any persisted transfer manifests and create the runtime root if it
    /// does not exist yet.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn load_or_create(root_dir: &Path) -> Result<Self> {
        Self::load_or_create_with_upload_queue(root_dir, Ed2kUploadQueueConfig::default())
    }

    /// Load any persisted transfer manifests with an explicit inbound upload
    /// queue policy and create the runtime root if it does not exist yet.
    pub fn load_or_create_with_upload_queue(
        root_dir: &Path,
        upload_queue_config: Ed2kUploadQueueConfig,
    ) -> Result<Self> {
        fs::create_dir_all(root_dir).with_context(|| {
            format!("failed to create ED2K transfer root {}", root_dir.display())
        })?;
        let shared_catalog = Arc::new(RwLock::new(load_catalog_from_manifests(root_dir)?));
        Ok(Self {
            root_dir: root_dir.to_path_buf(),
            shared_catalog,
            callback_intents: Arc::new(RwLock::new(Vec::new())),
            manifest_io: Arc::new(Mutex::new(())),
            manifest_cache: Arc::new(Mutex::new(HashMap::new())),
            manifest_checkpoint_state: Arc::new(Mutex::new(HashMap::new())),
            upload_queue: Arc::new(Mutex::new(Ed2kUploadQueueState::new(upload_queue_config))),
            next_upload_connection_id: AtomicU64::new(1),
        })
    }

    /// Override inbound uploader queue policy for controlled scenarios and tests.
    #[cfg(test)]
    pub async fn configure_upload_queue(&self, config: Ed2kUploadQueueConfig) {
        self.upload_queue.lock().await.configure(config);
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
        let _guard = self.manifest_io.lock().await;
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
            return self.load_manifest_or_rebuild_unlocked(job).await;
        }
        let manifest = Ed2kResumeManifest::new(job);
        self.store_manifest_unlocked(&manifest).await?;
        Ok(manifest)
    }

    /// Reconcile canonical metadata for an existing transfer after a peer
    /// reveals a better file name or previously unknown file size.
    pub async fn reconcile_job_metadata(
        &self,
        file_hash: &str,
        canonical_name: Option<&str>,
        file_size: Option<u64>,
    ) -> Result<Ed2kResumeManifest> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let mut changed = false;

        if let Some(canonical_name) = canonical_name.map(str::trim)
            && !canonical_name.is_empty()
            && manifest.canonical_name != canonical_name
        {
            manifest.canonical_name = canonical_name.to_string();
            changed = true;
        }

        if let Some(file_size) = file_size.filter(|file_size| *file_size != 0) {
            if manifest.file_size == 0 {
                if manifest_has_structural_progress(&manifest) {
                    anyhow::bail!(
                        "cannot adopt ED2K file size {} for {} after transfer progress already exists",
                        file_size,
                        file_hash
                    );
                }
                manifest.file_size = file_size;
                manifest.pieces = (0..piece_count(file_size, manifest.piece_size))
                    .map(|piece_index| Ed2kPieceState {
                        piece_index,
                        state: Ed2kTransferState::Missing,
                        bytes_written: 0,
                    })
                    .collect();
                changed = true;
            } else if manifest.file_size != file_size {
                anyhow::bail!(
                    "refusing to change ED2K file size for {} from {} to {}",
                    file_hash,
                    manifest.file_size,
                    file_size
                );
            }
        }

        if changed {
            self.store_manifest_unlocked(&manifest).await?;
            self.upsert_verified_catalog_entry(&manifest).await;
        }

        Ok(manifest)
    }

    /// Persist the canonical ED2K MD4 hashset after validating it against the
    /// expected file hash.
    pub async fn store_md4_hashset(
        &self,
        file_hash: &str,
        md4_hashset: Vec<[u8; 16]>,
    ) -> Result<Ed2kResumeManifest> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
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
        self.store_manifest_unlocked(&manifest).await?;
        Ok(manifest)
    }

    /// Persist the canonical ED2K AICH root and part hashset after validating
    /// the payload against the expected file size.
    pub async fn store_aich_hashset(
        &self,
        file_hash: &str,
        aich_hashset: Ed2kAichHashset,
    ) -> Result<Ed2kResumeManifest> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        if let Some(existing_root) = manifest.aich_root.as_deref() {
            let existing_root = decode_aich_hash_hex(existing_root)?;
            if existing_root != aich_hashset.master_hash {
                anyhow::bail!(
                    "refusing to replace AICH root for {} with conflicting data",
                    file_hash
                );
            }
        }
        validate_aich_hashset(manifest.file_size, &aich_hashset)?;
        manifest.aich_root = Some(hex::encode(aich_hashset.master_hash));
        manifest.aich_hashset = aich_hashset.part_hashes.iter().map(hex::encode).collect();
        manifest.aich_hashset_acquired = true;
        self.store_manifest_unlocked(&manifest).await?;
        self.upsert_verified_catalog_entry(&manifest).await;
        Ok(manifest)
    }

    /// Persist only the canonical AICH root learned from peer file metadata.
    pub async fn reconcile_aich_root(
        &self,
        file_hash: &str,
        aich_root: Option<[u8; 20]>,
    ) -> Result<Ed2kResumeManifest> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let mut changed = false;
        if let Some(aich_root) = aich_root {
            let encoded = hex::encode(aich_root);
            if let Some(existing_root) = manifest.aich_root.as_deref() {
                if existing_root != encoded {
                    anyhow::bail!(
                        "refusing to replace AICH root for {} with conflicting metadata",
                        file_hash
                    );
                }
            } else {
                manifest.aich_root = Some(encoded);
                changed = true;
            }
        }
        if changed {
            self.store_manifest_unlocked(&manifest).await?;
            self.upsert_verified_catalog_entry(&manifest).await;
        }
        Ok(manifest)
    }

    /// Record one remembered source hint for a job.
    pub async fn remember_source(&self, file_hash: &str, source: Ed2kSourceHint) -> Result<()> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        if !manifest.sources.contains(&source) {
            manifest.sources.push(source);
            self.store_manifest_unlocked(&manifest).await?;
        }
        Ok(())
    }

    /// Mark a specific missing piece as requested.
    #[cfg(test)]
    pub async fn mark_piece_requested(&self, file_hash: &str, piece_index: u32) -> Result<bool> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == piece_index)
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        if piece.state == Ed2kTransferState::Missing {
            piece.state = Ed2kTransferState::Requested;
            self.store_manifest_unlocked(&manifest).await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Claim the next incomplete part atomically for one peer session.
    pub async fn claim_next_missing_part(
        &self,
        file_hash: &str,
    ) -> Result<Option<Ed2kClaimedPart>> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let Some(piece) = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.state == Ed2kTransferState::Missing)
        else {
            return Ok(None);
        };
        let claimed = Ed2kClaimedPart {
            piece_index: piece.piece_index,
            bytes_written: piece.bytes_written,
        };
        piece.state = Ed2kTransferState::Requested;
        self.store_manifest_unlocked(&manifest).await?;
        Ok(Some(claimed))
    }

    /// Release a previously requested part back to the missing pool.
    ///
    /// Any already persisted byte prefix is kept so a later peer session can
    /// resume from the exact missing range instead of discarding good data.
    pub async fn release_piece_request(&self, file_hash: &str, piece_index: u32) -> Result<()> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let piece = manifest
            .pieces
            .iter_mut()
            .find(|piece| piece.piece_index == piece_index)
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        if piece.state == Ed2kTransferState::Requested {
            piece.state = Ed2kTransferState::Missing;
            self.store_manifest_unlocked(&manifest).await?;
        }
        Ok(())
    }

    /// Requeue any persisted requested pieces after a downloader restart.
    ///
    /// Requested pieces are session-local claims. If the process exits before
    /// the downloader releases them, the next process instance must move them
    /// back to `Missing` so resume can continue from the already persisted byte
    /// prefix instead of deadlocking on a stale in-flight marker.
    pub async fn reclaim_stale_piece_requests(&self, file_hash: &str) -> Result<bool> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let mut changed = false;
        for piece in &mut manifest.pieces {
            if piece.state == Ed2kTransferState::Requested {
                piece.state = Ed2kTransferState::Missing;
                changed = true;
            }
        }
        if changed {
            self.store_manifest_unlocked(&manifest).await?;
        }
        Ok(changed)
    }

    /// Persist one downloaded piece into the local piece store.
    #[allow(dead_code)]
    pub async fn store_piece_data(
        &self,
        file_hash: &str,
        piece_index: u32,
        data: &[u8],
    ) -> Result<()> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
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
            .read(true)
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
        if manifest.completed {
            refresh_completed_manifest_aich_hashset(
                &self.transfer_dir(manifest.file_hash.as_str()),
                &mut manifest,
            )?;
        }
        self.upsert_verified_catalog_entry(&manifest).await;
        self.store_manifest_unlocked(&manifest).await
    }

    /// Append one contiguous download block into a requested piece.
    ///
    /// This is used for single-part ED2K downloads where peers expect
    /// eMule-sized `OP_REQUESTPARTS` block ranges instead of one whole-file
    /// range. The method only accepts strictly contiguous writes for the
    /// claimed piece and verifies the full piece once the final block arrives.
    pub async fn append_piece_block(
        &self,
        file_hash: &str,
        piece_index: u32,
        start: u64,
        end: u64,
        data: &[u8],
    ) -> Result<bool> {
        let _guard = self.manifest_io.lock().await;
        let mut manifest = self.load_manifest_unlocked(file_hash).await?;
        let block_received_at = Instant::now();
        let piece_size = manifest.piece_size;
        let piece_start = u64::from(piece_index) * piece_size;
        let expected_piece_len =
            expected_piece_length(manifest.file_size, piece_size, u64::from(piece_index));
        let piece_end = piece_start + expected_piece_len;
        let data_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let current_piece_bytes_written = manifest
            .pieces
            .iter()
            .find(|piece| piece.piece_index == piece_index)
            .map(|piece| piece.bytes_written)
            .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
        let expected_start = piece_start + current_piece_bytes_written;
        let expected_end = expected_start + data_len;
        if start != expected_start || end != expected_end || end > piece_end {
            anyhow::bail!(
                "piece {piece_index} for {file_hash} received unexpected block {start}..{end} expected {expected_start}..{expected_end} within {piece_start}..{piece_end}"
            );
        }

        let payload_path = self.transfer_dir(file_hash).join(PAYLOAD_FILE_NAME);
        let mut file = Some(
            tokio::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&payload_path)
                .await
                .with_context(|| {
                    format!("failed to open piece store {}", payload_path.display())
                })?,
        );
        use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
        let file_handle = file.as_mut().expect("piece store handle missing");
        file_handle.seek(std::io::SeekFrom::Start(start)).await?;
        file_handle.write_all(data).await?;

        let next_piece_bytes_written = current_piece_bytes_written + data_len;
        let mut piece_completed = false;
        let mut checkpoint_reason = None;
        if next_piece_bytes_written == expected_piece_len {
            file.as_mut()
                .expect("piece store handle missing")
                .flush()
                .await?;
            let mut piece_bytes = vec![0u8; usize::try_from(expected_piece_len).unwrap_or(0)];
            drop(file.take());
            let mut read_file = tokio::fs::OpenOptions::new()
                .read(true)
                .open(&payload_path)
                .await
                .with_context(|| {
                    format!("failed to reopen piece store {}", payload_path.display())
                })?;
            read_file
                .seek(std::io::SeekFrom::Start(piece_start))
                .await?;
            read_file.read_exact(&mut piece_bytes).await?;
            let verified = verify_piece_against_manifest(&manifest, piece_index, &piece_bytes)?;
            let piece = manifest
                .pieces
                .iter_mut()
                .find(|piece| piece.piece_index == piece_index)
                .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
            if verified {
                piece.bytes_written = expected_piece_len;
                piece.state = Ed2kTransferState::Verified;
                piece_completed = true;
                checkpoint_reason = Some("piece_verified");
            } else {
                piece.state = Ed2kTransferState::Missing;
                piece.bytes_written = 0;
                checkpoint_reason = Some("piece_verification_failed");
            }
            rebuild_verified_ranges(&mut manifest);
            manifest.completed = manifest.is_fully_verified();
            if manifest.completed {
                refresh_completed_manifest_aich_hashset(
                    &self.transfer_dir(manifest.file_hash.as_str()),
                    &mut manifest,
                )?;
            }
            if piece_completed {
                self.upsert_verified_catalog_entry(&manifest).await;
            }
        } else {
            let piece = manifest
                .pieces
                .iter_mut()
                .find(|piece| piece.piece_index == piece_index)
                .with_context(|| format!("missing piece index {piece_index} in {file_hash}"))?;
            piece.bytes_written = next_piece_bytes_written;
            piece.state = Ed2kTransferState::Requested;
        }

        let should_checkpoint = checkpoint_reason.is_some()
            || self.should_checkpoint_manifest_unlocked(&manifest).await;
        if should_checkpoint {
            if checkpoint_reason.is_none() {
                checkpoint_reason = Some("periodic_progress");
            }
            if let Some(file_handle) = file.as_mut() {
                file_handle.flush().await?;
            }
            drop(file.take());
            self.store_manifest_unlocked(&manifest).await?;
        } else {
            drop(file.take());
            self.cache_manifest_unlocked(&manifest).await;
        }
        debug!(
            file_hash = %manifest.file_hash,
            piece_index,
            start,
            end,
            block_write_ms = block_received_at.elapsed().as_millis(),
            checkpoint = should_checkpoint,
            checkpoint_reason = checkpoint_reason.unwrap_or("cached_only"),
            completed = manifest.completed,
            "ED2K append_piece_block applied"
        );
        Ok(piece_completed)
    }

    /// Read a fully verified range for upload serving.
    pub async fn read_verified_range(
        &self,
        file_hash: &Ed2kHash,
        start: u64,
        end: u64,
    ) -> Result<Option<Vec<u8>>> {
        let hash_hex = file_hash.to_string();
        let _guard = self.manifest_io.lock().await;
        let manifest = self.load_manifest_unlocked(&hash_hex).await?;
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
        let _guard = self.manifest_io.lock().await;
        let manifest = self.load_manifest_unlocked(&hash_hex).await?;
        Ok(Some(Ed2kSharedEntry::from_manifest(&manifest)))
    }

    /// Return the canonical MD4 hashset for this file when known.
    pub async fn md4_hashset(&self, file_hash: &Ed2kHash) -> Result<Option<Vec<[u8; 16]>>> {
        let hash_hex = file_hash.to_string();
        let path = self.transfer_dir(&hash_hex).join(MANIFEST_FILE_NAME);
        if !tokio::fs::try_exists(&path).await? {
            return Ok(None);
        }
        let _guard = self.manifest_io.lock().await;
        let manifest = self.load_manifest_unlocked(&hash_hex).await?;
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

    /// Return the canonical AICH root plus per-part hashes for this file when known.
    pub async fn aich_hashset(&self, file_hash: &Ed2kHash) -> Result<Option<Ed2kAichHashset>> {
        let hash_hex = file_hash.to_string();
        let path = self.transfer_dir(&hash_hex).join(MANIFEST_FILE_NAME);
        if !tokio::fs::try_exists(&path).await? {
            return Ok(None);
        }
        let _guard = self.manifest_io.lock().await;
        let manifest = self.load_manifest_unlocked(&hash_hex).await?;
        if !manifest.aich_hashset_acquired || manifest.aich_root.is_none() {
            return Ok(None);
        }
        decode_manifest_aich_hashset(&manifest).map(Some)
    }

    /// Returns the persisted manifest for orchestration code that needs to read
    /// the current verification or hashset state.
    pub async fn manifest(&self, file_hash: &str) -> Result<Ed2kResumeManifest> {
        let _guard = self.manifest_io.lock().await;
        self.load_manifest_unlocked(file_hash).await
    }

    /// Copy a local payload into the canonical ED2K transfer store and expose
    /// it as a fully verified shared file.
    pub async fn ingest_local_file(
        &self,
        source_path: &Path,
        canonical_name: &str,
    ) -> Result<Ed2kLocalIngestSummary> {
        let canonical_name = canonical_name.trim();
        if canonical_name.is_empty() {
            anyhow::bail!("local ED2K ingest requires a non-empty canonical name");
        }
        let source_path = source_path.canonicalize().with_context(|| {
            format!(
                "failed to resolve local ingest source {}",
                source_path.display()
            )
        })?;
        let metadata = tokio::fs::metadata(&source_path).await.with_context(|| {
            format!(
                "failed to stat local ingest source {}",
                source_path.display()
            )
        })?;
        if metadata.len() == 0 {
            anyhow::bail!("local ED2K ingest does not support zero-sized payloads");
        }

        let _guard = self.manifest_io.lock().await;
        let (file_hash, md4_hashset) =
            build_md4_hashset_from_payload(&source_path, metadata.len())?;
        let job = new_transfer_job(file_hash, canonical_name.to_string(), metadata.len());
        let transfer_dir = self.transfer_dir(&job.file_hash);
        tokio::fs::create_dir_all(&transfer_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to create ED2K transfer directory {}",
                    transfer_dir.display()
                )
            })?;
        let payload_path = transfer_dir.join(PAYLOAD_FILE_NAME);
        let source_matches_payload = payload_path.exists()
            && payload_path.canonicalize().ok().as_deref() == Some(source_path.as_path());
        if !source_matches_payload {
            tokio::fs::copy(&source_path, &payload_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to copy local ingest payload {} -> {}",
                        source_path.display(),
                        payload_path.display()
                    )
                })?;
        }

        let aich_hashset = build_aich_hashset_from_payload(&payload_path, metadata.len())?;
        let mut manifest = Ed2kResumeManifest::new(&job);
        manifest.completed = true;
        manifest.md4_hashset_acquired = true;
        manifest.md4_hashset = md4_hashset.iter().map(hex::encode).collect();
        manifest.aich_hashset_acquired = true;
        manifest.aich_root = Some(hex::encode(aich_hashset.master_hash));
        manifest.aich_hashset = aich_hashset.part_hashes.iter().map(hex::encode).collect();
        manifest.pieces = (0..piece_count(manifest.file_size, manifest.piece_size))
            .map(|piece_index| Ed2kPieceState {
                piece_index,
                state: Ed2kTransferState::Verified,
                bytes_written: expected_piece_length(
                    manifest.file_size,
                    manifest.piece_size,
                    u64::from(piece_index),
                ),
            })
            .collect();
        rebuild_verified_ranges(&mut manifest);
        self.store_manifest_unlocked(&manifest).await?;
        self.upsert_verified_catalog_entry(&manifest).await;

        Ok(Ed2kLocalIngestSummary {
            file_hash: manifest.file_hash,
            canonical_name: manifest.canonical_name,
            file_size: manifest.file_size,
            md4_hashset_count: manifest.md4_hashset.len(),
            aich_root: manifest.aich_root.unwrap_or_default(),
            aich_hashset_count: manifest.aich_hashset.len(),
            transfer_dir: transfer_dir.display().to_string(),
        })
    }

    /// Admit or refresh one inbound uploader session and return the queue-visible state.
    pub async fn begin_upload_session(
        &self,
        peer: Ed2kUploadPeerIdentity,
        file_hash: &Ed2kHash,
    ) -> (Ed2kUploadSessionHandle, Ed2kUploadSessionStatus) {
        let connection_id = self
            .next_upload_connection_id
            .fetch_add(1, Ordering::Relaxed);
        let handle = Ed2kUploadSessionHandle::new(peer, file_hash.to_string(), connection_id);
        let status = self.upload_queue.lock().await.begin_session(
            handle.key().clone(),
            connection_id,
            Instant::now(),
        );
        (handle, status)
    }

    /// Poll the current queue-visible state for one upload session.
    pub async fn poll_upload_session(
        &self,
        handle: &Ed2kUploadSessionHandle,
        refresh_activity: bool,
    ) -> Ed2kUploadSessionStatus {
        self.upload_queue
            .lock()
            .await
            .poll_session(handle, Instant::now(), refresh_activity)
    }

    /// Mark a part request as activity and return whether the peer may receive data.
    pub async fn note_upload_request_parts(
        &self,
        handle: &Ed2kUploadSessionHandle,
    ) -> Ed2kUploadSessionStatus {
        self.upload_queue
            .lock()
            .await
            .note_request_parts(handle, Instant::now())
    }

    /// Release one upload slot or waiting entry after disconnect or explicit cancel.
    pub async fn release_upload_session(&self, handle: &Ed2kUploadSessionHandle) {
        self.upload_queue
            .lock()
            .await
            .release_session(handle, Instant::now());
    }

    async fn load_manifest_or_rebuild_unlocked(
        &self,
        job: &Ed2kTransferJob,
    ) -> Result<Ed2kResumeManifest> {
        match self.load_manifest_unlocked(&job.file_hash).await {
            Ok(manifest) => Ok(manifest),
            Err(error) => {
                let manifest_path = self.transfer_dir(&job.file_hash).join(MANIFEST_FILE_NAME);
                quarantine_corrupt_manifest(&manifest_path).await?;
                let manifest = Ed2kResumeManifest::new(job);
                self.store_manifest_unlocked(&manifest).await?;
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

    async fn load_manifest_unlocked(&self, file_hash: &str) -> Result<Ed2kResumeManifest> {
        if let Some(manifest) = self.manifest_cache.lock().await.get(file_hash).cloned() {
            return Ok(manifest);
        }
        let path = self.transfer_dir(file_hash).join(MANIFEST_FILE_NAME);
        let bytes = tokio::fs::read(&path)
            .await
            .with_context(|| format!("failed to read ED2K manifest {}", path.display()))?;
        let manifest = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to decode ED2K manifest {}", path.display()))?;
        self.mark_manifest_persisted_unlocked(&manifest).await;
        Ok(manifest)
    }

    async fn store_manifest_unlocked(&self, manifest: &Ed2kResumeManifest) -> Result<()> {
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
            .with_context(|| format!("failed to write ED2K manifest {}", path.display()))?;
        self.mark_manifest_persisted_unlocked(manifest).await;
        Ok(())
    }

    async fn cache_manifest_unlocked(&self, manifest: &Ed2kResumeManifest) {
        self.manifest_cache
            .lock()
            .await
            .insert(manifest.file_hash.clone(), manifest.clone());
    }

    async fn mark_manifest_persisted_unlocked(&self, manifest: &Ed2kResumeManifest) {
        self.cache_manifest_unlocked(manifest).await;
        self.manifest_checkpoint_state.lock().await.insert(
            manifest.file_hash.clone(),
            Ed2kManifestCheckpointState {
                persisted_bytes_written: manifest_progress_bytes(manifest),
                last_persisted_at: Instant::now(),
            },
        );
    }

    async fn should_checkpoint_manifest_unlocked(&self, manifest: &Ed2kResumeManifest) -> bool {
        let current_progress = manifest_progress_bytes(manifest);
        let mut states = self.manifest_checkpoint_state.lock().await;
        let state = states.entry(manifest.file_hash.clone()).or_insert_with(|| {
            Ed2kManifestCheckpointState {
                persisted_bytes_written: current_progress,
                last_persisted_at: Instant::now(),
            }
        });
        let dirty_bytes = current_progress.saturating_sub(state.persisted_bytes_written);
        dirty_bytes >= ED2K_RESUME_CHECKPOINT_BYTES
            || (dirty_bytes != 0
                && state.last_persisted_at.elapsed() >= ED2K_RESUME_CHECKPOINT_INTERVAL)
    }

    fn transfer_dir(&self, file_hash: &str) -> PathBuf {
        self.root_dir.join(file_hash)
    }
}

#[cfg(test)]
mod tests;
