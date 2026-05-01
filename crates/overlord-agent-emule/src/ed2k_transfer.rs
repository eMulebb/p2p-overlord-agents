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
    time::Instant,
};

use anyhow::{Context, Result};
use tokio::sync::{Mutex, RwLock};

use overlord_agent_common::PopularHash;
use overlord_kad_proto::Ed2kHash;

mod catalog;
mod hashset;
mod manifest;
mod model;
mod piece_store;
mod store;
mod upload_queue;

pub use catalog::{Ed2kSharedCatalog, Ed2kSharedEntry, Ed2kSharedRange};
pub(crate) use hashset::decode_aich_hash_hex;
use hashset::{
    build_aich_hashset_from_payload, build_md4_hashset_from_payload, decode_manifest_aich_hashset,
    expected_md4_hash_count, validate_aich_hashset, validate_md4_hashset,
};
pub(crate) use manifest::expected_piece_length;
pub use manifest::new_transfer_job;
use manifest::{
    Ed2kManifestCheckpointState, dedupe_entries, load_catalog_from_manifests,
    manifest_has_structural_progress, piece_count, rebuild_verified_ranges,
};
pub(crate) use model::{Ed2kAichHashset, Ed2kClaimedPart};
pub use model::{
    Ed2kCallbackIntent, Ed2kLocalIngestSummary, Ed2kPieceState, Ed2kResumeManifest, Ed2kSourceHint,
    Ed2kTransferJob, Ed2kTransferState,
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

    async fn upsert_verified_catalog_entry(&self, manifest: &Ed2kResumeManifest) {
        let mut entries = self.shared_catalog.write().await;
        entries.retain(|entry| entry.file_hash != manifest.file_hash || entry.compatibility_hint);
        if manifest.completed || !manifest.verified_ranges.is_empty() {
            entries.push(Ed2kSharedEntry::from_manifest(manifest));
        }
        *entries = dedupe_entries(entries.clone());
    }
}

#[cfg(test)]
mod tests;
