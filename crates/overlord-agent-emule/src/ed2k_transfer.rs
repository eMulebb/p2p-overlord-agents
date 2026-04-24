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
    collections::{HashMap, HashSet, VecDeque},
    fs,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use md4::{Digest as Md4Digest, Md4};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

use overlord_agent_common::{HashType, PopularHash};
use overlord_kad_proto::Ed2kHash;

pub(crate) const ED2K_PART_SIZE: u64 = 9_728_000;
/// Canonical eMule upload block size used inside one ED2K part request.
pub(crate) const ED2K_EMBLOCK_SIZE: u64 = 184_320;
const MANIFEST_FILE_NAME: &str = "resume-manifest.json";
const PAYLOAD_FILE_NAME: &str = "pieces.bin";
const ED2K_RESUME_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(2);
const ED2K_RESUME_CHECKPOINT_BYTES: u64 = ED2K_EMBLOCK_SIZE * 16;

/// Upload-slot and waiting-queue policy used by the inbound ED2K listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ed2kUploadQueueConfig {
    /// Maximum number of concurrently granted upload sessions.
    pub active_slots: usize,
    /// Maximum number of queued waiters retained at once.
    pub waiting_capacity: usize,
    /// Maximum idle time for a queued waiter before it is discarded.
    pub waiting_timeout: Duration,
    /// Maximum stall time after grant before the peer requests data.
    pub granted_timeout: Duration,
    /// Maximum idle time while a peer already has an active upload slot.
    pub upload_timeout: Duration,
}

impl Default for Ed2kUploadQueueConfig {
    fn default() -> Self {
        Self {
            active_slots: 3,
            waiting_capacity: 512,
            waiting_timeout: Duration::from_secs(180),
            granted_timeout: Duration::from_secs(30),
            upload_timeout: Duration::from_secs(90),
        }
    }
}

/// Stable peer identity used to keep uploader queue decisions deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Ed2kUploadPeerIdentity {
    /// Remote peer IP address.
    pub ip: IpAddr,
    /// Remote peer TCP port advertised in hello or observed on the socket.
    pub tcp_port: u16,
    /// Remote peer user hash when known.
    pub user_hash: Option<[u8; 16]>,
    /// Remote peer client-id when known.
    pub client_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Ed2kUploadSessionKey {
    peer: Ed2kUploadPeerIdentity,
    file_hash: String,
}

/// Opaque handle bound to one live uploader transport session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ed2kUploadSessionHandle {
    key: Ed2kUploadSessionKey,
    connection_id: u64,
}

/// Queue-visible state of one inbound upload session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ed2kUploadSessionStatus {
    /// The peer is queued and should see a rank.
    Waiting { rank: u16 },
    /// The peer currently owns an upload slot.
    Granted,
    /// The session expired, was cancelled, or was replaced by a reconnect.
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ed2kUploadSessionPhase {
    Waiting,
    Granted,
    Uploading,
}

#[derive(Debug, Clone)]
struct Ed2kUploadSessionEntry {
    phase: Ed2kUploadSessionPhase,
    connection_id: u64,
    last_activity: Instant,
}

#[derive(Debug)]
struct Ed2kUploadQueueState {
    config: Ed2kUploadQueueConfig,
    sessions: HashMap<Ed2kUploadSessionKey, Ed2kUploadSessionEntry>,
    waiting_order: VecDeque<Ed2kUploadSessionKey>,
}

impl Ed2kUploadQueueState {
    fn new(config: Ed2kUploadQueueConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            waiting_order: VecDeque::new(),
        }
    }

    #[cfg(test)]
    fn configure(&mut self, config: Ed2kUploadQueueConfig) {
        self.config = config;
        let now = Instant::now();
        self.reap_expired_sessions(now);
        self.trim_waiting_queue();
        self.promote_waiters(now);
    }

    fn begin_session(
        &mut self,
        key: Ed2kUploadSessionKey,
        connection_id: u64,
        now: Instant,
    ) -> Ed2kUploadSessionStatus {
        self.reap_expired_sessions(now);
        if let Some(session) = self.sessions.get_mut(&key) {
            session.connection_id = connection_id;
            session.last_activity = now;
            return self.status_for_key(&key);
        }
        if let Some(existing_key) = self.session_key_for_peer(&key.peer) {
            let Some(mut session) = self.sessions.remove(&existing_key) else {
                unreachable!("existing peer queue key missing from session map");
            };
            if session.phase == Ed2kUploadSessionPhase::Waiting {
                self.replace_waiting_key(&existing_key, &key);
            }
            session.connection_id = connection_id;
            session.last_activity = now;
            self.sessions.insert(key.clone(), session);
            return self.status_for_key(&key);
        }

        let phase = if self.active_session_count() < self.config.active_slots {
            Ed2kUploadSessionPhase::Granted
        } else {
            self.trim_waiting_queue();
            self.waiting_order.push_back(key.clone());
            Ed2kUploadSessionPhase::Waiting
        };
        self.sessions.insert(
            key.clone(),
            Ed2kUploadSessionEntry {
                phase,
                connection_id,
                last_activity: now,
            },
        );
        self.status_for_key(&key)
    }

    fn poll_session(
        &mut self,
        handle: &Ed2kUploadSessionHandle,
        now: Instant,
        refresh_activity: bool,
    ) -> Ed2kUploadSessionStatus {
        self.reap_expired_sessions(now);
        let Some(session) = self.sessions.get_mut(&handle.key) else {
            return Ed2kUploadSessionStatus::Stale;
        };
        if session.connection_id != handle.connection_id {
            return Ed2kUploadSessionStatus::Stale;
        }
        if refresh_activity {
            session.last_activity = now;
        }
        self.status_for_key(&handle.key)
    }

    fn note_request_parts(
        &mut self,
        handle: &Ed2kUploadSessionHandle,
        now: Instant,
    ) -> Ed2kUploadSessionStatus {
        self.reap_expired_sessions(now);
        let Some(session) = self.sessions.get_mut(&handle.key) else {
            return Ed2kUploadSessionStatus::Stale;
        };
        if session.connection_id != handle.connection_id {
            return Ed2kUploadSessionStatus::Stale;
        }
        session.last_activity = now;
        if matches!(
            session.phase,
            Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading
        ) {
            session.phase = Ed2kUploadSessionPhase::Uploading;
            return Ed2kUploadSessionStatus::Granted;
        }
        self.status_for_key(&handle.key)
    }

    fn release_session(&mut self, handle: &Ed2kUploadSessionHandle, now: Instant) {
        let Some(session) = self.sessions.get(&handle.key) else {
            return;
        };
        if session.connection_id != handle.connection_id {
            return;
        }
        let phase = session.phase;
        self.sessions.remove(&handle.key);
        if phase == Ed2kUploadSessionPhase::Waiting {
            self.waiting_order.retain(|key| key != &handle.key);
        }
        self.reap_expired_sessions(now);
        self.promote_waiters(now);
    }

    fn status_for_key(&self, key: &Ed2kUploadSessionKey) -> Ed2kUploadSessionStatus {
        match self.sessions.get(key).map(|session| session.phase) {
            Some(Ed2kUploadSessionPhase::Waiting) => Ed2kUploadSessionStatus::Waiting {
                rank: self.rank_for_key(key),
            },
            Some(Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading) => {
                Ed2kUploadSessionStatus::Granted
            }
            None => Ed2kUploadSessionStatus::Stale,
        }
    }

    fn rank_for_key(&self, key: &Ed2kUploadSessionKey) -> u16 {
        let Some(position) = self.waiting_order.iter().position(|queued| queued == key) else {
            return 0;
        };
        u16::try_from(position.saturating_add(1)).unwrap_or(u16::MAX)
    }

    fn active_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|session| {
                matches!(
                    session.phase,
                    Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading
                )
            })
            .count()
    }

    fn session_key_for_peer(&self, peer: &Ed2kUploadPeerIdentity) -> Option<Ed2kUploadSessionKey> {
        self.sessions
            .keys()
            .find(|existing_key| existing_key.peer == *peer)
            .cloned()
    }

    fn replace_waiting_key(
        &mut self,
        existing_key: &Ed2kUploadSessionKey,
        new_key: &Ed2kUploadSessionKey,
    ) {
        for queued in &mut self.waiting_order {
            if *queued == *existing_key {
                *queued = new_key.clone();
                return;
            }
        }
    }

    fn trim_waiting_queue(&mut self) {
        while self.waiting_order.len() >= self.config.waiting_capacity {
            let Some(evicted) = self.waiting_order.pop_front() else {
                break;
            };
            self.sessions.remove(&evicted);
        }
    }

    fn reap_expired_sessions(&mut self, now: Instant) {
        let expired = self
            .sessions
            .iter()
            .filter_map(|(key, session)| {
                let timeout = match session.phase {
                    Ed2kUploadSessionPhase::Waiting => self.config.waiting_timeout,
                    Ed2kUploadSessionPhase::Granted => self.config.granted_timeout,
                    Ed2kUploadSessionPhase::Uploading => self.config.upload_timeout,
                };
                (now.duration_since(session.last_activity) > timeout).then(|| key.clone())
            })
            .collect::<Vec<_>>();
        for key in expired {
            self.sessions.remove(&key);
            self.waiting_order.retain(|queued| queued != &key);
        }
        self.promote_waiters(now);
    }

    fn promote_waiters(&mut self, now: Instant) {
        while self.active_session_count() < self.config.active_slots {
            let Some(next_key) = self.waiting_order.pop_front() else {
                break;
            };
            let Some(next_session) = self.sessions.get_mut(&next_key) else {
                continue;
            };
            next_session.phase = Ed2kUploadSessionPhase::Granted;
            next_session.last_activity = now;
        }
    }
}

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
    /// Canonical AICH root in lowercase hex when known.
    #[serde(default)]
    pub aich_root: Option<String>,
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
            aich_root: None,
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
            aich_root: manifest.aich_root.clone(),
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

#[derive(Debug, Clone, Copy)]
struct Ed2kManifestCheckpointState {
    persisted_bytes_written: u64,
    last_persisted_at: Instant,
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
        let handle = Ed2kUploadSessionHandle {
            key: Ed2kUploadSessionKey {
                peer,
                file_hash: file_hash.to_string(),
            },
            connection_id,
        };
        let status = self.upload_queue.lock().await.begin_session(
            handle.key.clone(),
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

fn manifest_progress_bytes(manifest: &Ed2kResumeManifest) -> u64 {
    manifest
        .pieces
        .iter()
        .map(|piece| piece.bytes_written)
        .sum::<u64>()
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

fn build_md4_hashset_from_payload(
    payload_path: &Path,
    file_size: u64,
) -> Result<(Ed2kHash, Vec<[u8; 16]>)> {
    if file_size == 0 {
        anyhow::bail!("cannot build ED2K MD4 hashset for zero-sized file");
    }
    let mut file = fs::File::open(payload_path)
        .with_context(|| format!("failed to open ED2K payload {}", payload_path.display()))?;
    if file_size < ED2K_PART_SIZE {
        let digest = read_md4_digest_from_reader(&mut file, file_size)?;
        return Ok((Ed2kHash::from_bytes(digest), Vec::new()));
    }

    let part_count = chunk_count_for_size(file_size, ED2K_PART_SIZE);
    let mut part_hashes = Vec::with_capacity(usize::try_from(part_count + 1).unwrap_or(0));
    let mut remaining = file_size;
    while remaining > 0 {
        let part_size = remaining.min(ED2K_PART_SIZE);
        part_hashes.push(read_md4_digest_from_reader(&mut file, part_size)?);
        remaining -= part_size;
    }
    if file_size.is_multiple_of(ED2K_PART_SIZE) {
        part_hashes.push(read_md4_digest_from_reader(&mut file, 0)?);
    }

    let mut file_hasher = Md4::new();
    for part_hash in &part_hashes {
        file_hasher.update(part_hash);
    }
    Ok((
        Ed2kHash::from_bytes(file_hasher.finalize().into()),
        part_hashes,
    ))
}

fn read_md4_digest_from_reader(file: &mut fs::File, size: u64) -> Result<[u8; 16]> {
    let mut hasher = Md4::new();
    let mut remaining = size;
    let mut buffer = vec![0u8; 65_536];
    while remaining > 0 {
        let chunk_len =
            usize::try_from(remaining.min(u64::try_from(buffer.len()).unwrap_or(0))).unwrap_or(0);
        file.read_exact(&mut buffer[..chunk_len])
            .context("failed to read ED2K MD4 payload data")?;
        hasher.update(&buffer[..chunk_len]);
        remaining -= u64::try_from(chunk_len).unwrap_or(0);
    }
    Ok(hasher.finalize().into())
}

pub(crate) fn decode_aich_hash_hex(hash: &str) -> Result<[u8; 20]> {
    let bytes = hex::decode(hash).with_context(|| format!("invalid AICH hash {hash}"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid AICH hash length {len}"))
}

fn decode_manifest_aich_hashset(manifest: &Ed2kResumeManifest) -> Result<Ed2kAichHashset> {
    let root = manifest
        .aich_root
        .as_deref()
        .context("AICH root not available in manifest")?;
    let master_hash = decode_aich_hash_hex(root)?;
    let part_hashes = manifest
        .aich_hashset
        .iter()
        .map(|hash| decode_aich_hash_hex(hash))
        .collect::<Result<Vec<_>>>()?;
    if manifest.aich_hashset_acquired {
        validate_aich_hashset(
            manifest.file_size,
            &Ed2kAichHashset {
                master_hash,
                part_hashes: part_hashes.clone(),
            },
        )?;
    }
    Ok(Ed2kAichHashset {
        master_hash,
        part_hashes,
    })
}

fn expected_aich_hash_count(file_size: u64) -> u16 {
    if file_size <= ED2K_PART_SIZE {
        return 0;
    }
    let count = file_size.div_ceil(ED2K_PART_SIZE);
    u16::try_from(count).unwrap_or(u16::MAX)
}

fn validate_aich_hashset(file_size: u64, aich_hashset: &Ed2kAichHashset) -> Result<()> {
    let expected = usize::from(expected_aich_hash_count(file_size));
    if aich_hashset.part_hashes.len() != expected {
        anyhow::bail!(
            "unexpected AICH hashset length {} expected {} for file size {}",
            aich_hashset.part_hashes.len(),
            expected,
            file_size
        );
    }
    if expected == 0 {
        return Ok(());
    }
    let reconstructed =
        reconstruct_aich_root_from_part_hashes(file_size, &aich_hashset.part_hashes)?;
    if reconstructed != aich_hashset.master_hash {
        anyhow::bail!("AICH hashset does not reconstruct the advertised master hash");
    }
    Ok(())
}

fn reconstruct_aich_root_from_part_hashes(
    file_size: u64,
    part_hashes: &[[u8; 20]],
) -> Result<[u8; 20]> {
    fn build_part_root(
        start: u64,
        size: u64,
        is_left_branch: bool,
        part_hashes: &[[u8; 20]],
    ) -> Result<[u8; 20]> {
        if size <= ED2K_PART_SIZE {
            let part_index =
                usize::try_from(start / ED2K_PART_SIZE).context("AICH part index exceeds usize")?;
            return part_hashes
                .get(part_index)
                .copied()
                .with_context(|| format!("missing AICH part hash at index {part_index}"));
        }
        let part_count = size / ED2K_PART_SIZE + u64::from(!size.is_multiple_of(ED2K_PART_SIZE));
        let left_size = ((part_count + u64::from(is_left_branch)) / 2) * ED2K_PART_SIZE;
        let right_size = size - left_size;
        let left = build_part_root(start, left_size, true, part_hashes)?;
        let right = build_part_root(start + left_size, right_size, false, part_hashes)?;
        Ok(sha1_pair(left, right))
    }

    build_part_root(0, file_size, true, part_hashes)
}

fn refresh_completed_manifest_aich_hashset(
    transfer_dir: &Path,
    manifest: &mut Ed2kResumeManifest,
) -> Result<()> {
    // Once a modern peer has supplied a canonical AICH identity, keep serving
    // that network-learned root/hashset instead of replacing it on completion.
    // Completion-time synthesis is only for files that finished without any
    // prior AICH metadata.
    if manifest.aich_root.is_some() {
        return Ok(());
    }
    let payload_path = transfer_dir.join(PAYLOAD_FILE_NAME);
    let aich_hashset = build_aich_hashset_from_payload(&payload_path, manifest.file_size)?;
    manifest.aich_root = Some(hex::encode(aich_hashset.master_hash));
    manifest.aich_hashset = aich_hashset.part_hashes.iter().map(hex::encode).collect();
    manifest.aich_hashset_acquired = true;
    Ok(())
}

fn build_aich_hashset_from_payload(payload_path: &Path, file_size: u64) -> Result<Ed2kAichHashset> {
    if file_size == 0 {
        anyhow::bail!("cannot build AICH hashset for zero-sized file");
    }
    let mut file = fs::File::open(payload_path)
        .with_context(|| format!("failed to open AICH payload {}", payload_path.display()))?;
    if file_size <= ED2K_PART_SIZE {
        let master_hash = build_aich_part_root_from_reader(&mut file, file_size, true)?;
        return Ok(Ed2kAichHashset {
            master_hash,
            part_hashes: Vec::new(),
        });
    }

    let mut part_hashes = Vec::with_capacity(usize::from(expected_aich_hash_count(file_size)));
    collect_aich_part_hashes_from_reader(&mut file, file_size, true, &mut part_hashes)?;
    let master_hash = reconstruct_aich_root_from_part_hashes(file_size, &part_hashes)?;
    Ok(Ed2kAichHashset {
        master_hash,
        part_hashes,
    })
}

fn collect_aich_part_hashes_from_reader(
    file: &mut fs::File,
    size: u64,
    is_left_branch: bool,
    part_hashes: &mut Vec<[u8; 20]>,
) -> Result<()> {
    if size <= ED2K_PART_SIZE {
        part_hashes.push(build_aich_part_root_from_reader(
            file,
            size,
            is_left_branch,
        )?);
        return Ok(());
    }

    let part_count = chunk_count_for_size(size, ED2K_PART_SIZE);
    let left_size = ((part_count + u64::from(is_left_branch)) / 2) * ED2K_PART_SIZE;
    let right_size = size - left_size;
    collect_aich_part_hashes_from_reader(file, left_size, true, part_hashes)?;
    collect_aich_part_hashes_from_reader(file, right_size, false, part_hashes)
}

fn build_aich_part_root_from_reader(
    file: &mut fs::File,
    part_size: u64,
    is_left_branch: bool,
) -> Result<[u8; 20]> {
    let block_hashes = read_aich_block_hashes_from_reader(file, part_size)?;
    build_aich_block_tree_root(part_size, is_left_branch, &block_hashes, 0)
}

fn read_aich_block_hashes_from_reader(file: &mut fs::File, size: u64) -> Result<Vec<[u8; 20]>> {
    let mut block_hashes = Vec::with_capacity(
        usize::try_from(chunk_count_for_size(size, ED2K_EMBLOCK_SIZE)).unwrap_or(0),
    );
    let mut remaining = size;
    let mut buffer = vec![0u8; usize::try_from(ED2K_EMBLOCK_SIZE).unwrap_or(0)];
    while remaining > 0 {
        let block_len = usize::try_from(remaining.min(ED2K_EMBLOCK_SIZE)).unwrap_or(0);
        file.read_exact(&mut buffer[..block_len])
            .context("failed to read AICH block data from payload")?;
        let digest = Sha1::digest(&buffer[..block_len]);
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&digest);
        block_hashes.push(hash);
        remaining -= u64::try_from(block_len).unwrap_or(0);
    }
    Ok(block_hashes)
}

fn build_aich_block_tree_root(
    size: u64,
    is_left_branch: bool,
    block_hashes: &[[u8; 20]],
    block_offset: usize,
) -> Result<[u8; 20]> {
    if size <= ED2K_EMBLOCK_SIZE {
        return block_hashes
            .get(block_offset)
            .copied()
            .with_context(|| format!("missing AICH block hash at index {block_offset}"));
    }

    let block_count = chunk_count_for_size(size, ED2K_EMBLOCK_SIZE);
    let left_size = ((block_count + u64::from(is_left_branch)) / 2) * ED2K_EMBLOCK_SIZE;
    let right_size = size - left_size;
    let left_hash = build_aich_block_tree_root(left_size, true, block_hashes, block_offset)?;
    let right_offset = block_offset
        + usize::try_from(chunk_count_for_size(left_size, ED2K_EMBLOCK_SIZE))
            .context("AICH block offset exceeds usize")?;
    let right_hash = build_aich_block_tree_root(right_size, false, block_hashes, right_offset)?;
    Ok(sha1_pair(left_hash, right_hash))
}

fn chunk_count_for_size(size: u64, chunk_size: u64) -> u64 {
    size / chunk_size + u64::from(!size.is_multiple_of(chunk_size))
}

fn sha1_pair(left: [u8; 20], right: [u8; 20]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&digest);
    hash
}

fn manifest_has_structural_progress(manifest: &Ed2kResumeManifest) -> bool {
    manifest.completed
        || manifest.md4_hashset_acquired
        || manifest.aich_hashset_acquired
        || manifest.aich_root.is_some()
        || !manifest.verified_ranges.is_empty()
        || manifest.pieces.iter().any(|piece| piece.bytes_written != 0)
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
        Ed2kTransferState, Ed2kUploadPeerIdentity, Ed2kUploadQueueConfig, Ed2kUploadSessionStatus,
        MANIFEST_FILE_NAME, PAYLOAD_FILE_NAME, new_transfer_job,
    };
    use crate::paths::unique_test_dir;
    use md4::{Digest, Md4};
    use overlord_agent_common::{HashType, PopularHash};
    use overlord_kad_proto::Ed2kHash;
    use std::{
        fs,
        io::Write,
        net::{IpAddr, Ipv4Addr},
        path::Path,
        str::FromStr,
        time::Duration,
    };

    fn write_repeating_pattern_file(path: &Path, size: usize, pattern: &[u8]) {
        assert!(!pattern.is_empty());
        let mut payload = Vec::with_capacity(size);
        while payload.len() < size {
            let remaining = size - payload.len();
            let chunk_len = remaining.min(pattern.len());
            payload.extend_from_slice(&pattern[..chunk_len]);
        }
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&payload).unwrap();
    }

    fn read_manifest_from_disk(root: &Path, file_hash: &str) -> Ed2kResumeManifest {
        serde_json::from_slice(&fs::read(root.join(file_hash).join(MANIFEST_FILE_NAME)).unwrap())
            .unwrap()
    }

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
    async fn completed_manifest_persists_and_reloads_truthful_aich_hashset() {
        let root = unique_test_dir("ed2k-transfer-runtime-aich");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let first_piece = vec![0x31; ED2K_PART_SIZE as usize];
        let last_piece = vec![0x7A; 32_768];
        let first_piece_hash: [u8; 16] = Md4::digest(&first_piece).into();
        let last_piece_hash: [u8; 16] = Md4::digest(&last_piece).into();
        let mut file_hasher = Md4::new();
        file_hasher.update(first_piece_hash);
        file_hasher.update(last_piece_hash);
        let file_hash = Ed2kHash::from_bytes(file_hasher.finalize().into());
        let job = new_transfer_job(
            file_hash,
            "captured-aich.iso".to_string(),
            u64::try_from(first_piece.len() + last_piece.len()).unwrap(),
        );

        runtime.ensure_job(&job).await.unwrap();
        runtime
            .store_md4_hashset(&job.file_hash, vec![first_piece_hash, last_piece_hash])
            .await
            .unwrap();
        runtime
            .store_piece_data(&job.file_hash, 0, &first_piece)
            .await
            .unwrap();
        runtime
            .store_piece_data(&job.file_hash, 1, &last_piece)
            .await
            .unwrap();

        let manifest = runtime.manifest(&job.file_hash).await.unwrap();
        assert!(manifest.completed);
        assert!(manifest.aich_hashset_acquired);
        assert_eq!(manifest.aich_hashset.len(), 2);
        let stored_root = manifest.aich_root.clone().expect("missing AICH root");
        let reloaded_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let reloaded = reloaded_runtime
            .aich_hashset(&Ed2kHash::from_str(&job.file_hash).unwrap())
            .await
            .unwrap()
            .expect("missing reloaded AICH hashset");
        assert_eq!(hex::encode(reloaded.master_hash), stored_root);
        assert_eq!(reloaded.part_hashes.len(), 2);

        let local_entry = reloaded_runtime
            .local_entry(&Ed2kHash::from_str(&job.file_hash).unwrap())
            .await
            .unwrap()
            .expect("missing local entry");
        assert_eq!(local_entry.aich_root.as_deref(), Some(stored_root.as_str()));
    }

    #[tokio::test]
    async fn completed_manifest_preserves_remote_aich_identity_over_local_rebuild() {
        let root = unique_test_dir("ed2k-transfer-runtime-remote-aich");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let first_piece = vec![0x31; ED2K_PART_SIZE as usize];
        let last_piece_len = usize::try_from(10_485_760u64 - ED2K_PART_SIZE).unwrap();
        let last_piece = vec![0x7A; last_piece_len];
        let first_piece_hash: [u8; 16] = Md4::digest(&first_piece).into();
        let last_piece_hash: [u8; 16] = Md4::digest(&last_piece).into();
        let mut file_hasher = Md4::new();
        file_hasher.update(first_piece_hash);
        file_hasher.update(last_piece_hash);
        let file_hash = Ed2kHash::from_bytes(file_hasher.finalize().into());
        let job = new_transfer_job(
            file_hash,
            "captured-remote-aich.iso".to_string(),
            u64::try_from(first_piece.len() + last_piece.len()).unwrap(),
        );

        runtime.ensure_job(&job).await.unwrap();
        runtime
            .store_md4_hashset(&job.file_hash, vec![first_piece_hash, last_piece_hash])
            .await
            .unwrap();

        let remote_aich = super::Ed2kAichHashset {
            master_hash: hex::decode("050066b767710d1bd84377e71b1b23e522cce4af")
                .unwrap()
                .try_into()
                .unwrap(),
            part_hashes: vec![
                hex::decode("80ebdc35e9618aa7617fa988f756a33b79aa0d6c")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                hex::decode("b05ae2f6c5a179ec4b7ecffdcc18045151be0437")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ],
        };
        runtime
            .store_aich_hashset(&job.file_hash, remote_aich.clone())
            .await
            .unwrap();

        runtime
            .store_piece_data(&job.file_hash, 0, &first_piece)
            .await
            .unwrap();
        runtime
            .store_piece_data(&job.file_hash, 1, &last_piece)
            .await
            .unwrap();

        let manifest = runtime.manifest(&job.file_hash).await.unwrap();
        assert!(manifest.completed);
        assert!(manifest.aich_hashset_acquired);
        assert_eq!(
            manifest.aich_root.as_deref(),
            Some("050066b767710d1bd84377e71b1b23e522cce4af")
        );
        assert_eq!(
            manifest.aich_hashset,
            vec![
                "80ebdc35e9618aa7617fa988f756a33b79aa0d6c".to_string(),
                "b05ae2f6c5a179ec4b7ecffdcc18045151be0437".to_string(),
            ]
        );

        let transfer_dir = Path::new(&root).join(job.file_hash.as_str());
        let rebuilt = super::build_aich_hashset_from_payload(
            &transfer_dir.join(super::PAYLOAD_FILE_NAME),
            manifest.file_size,
        )
        .unwrap();
        assert_ne!(
            hex::encode(rebuilt.master_hash),
            manifest.aich_root.clone().unwrap()
        );

        let local_entry = runtime
            .local_entry(&Ed2kHash::from_str(&job.file_hash).unwrap())
            .await
            .unwrap()
            .expect("missing local entry");
        assert_eq!(
            local_entry.aich_root.as_deref(),
            Some("050066b767710d1bd84377e71b1b23e522cce4af")
        );
    }

    #[test]
    fn build_aich_hashset_matches_stock_tracing_harness_large_roundtrip_fixture() {
        let root = unique_test_dir("ed2k-transfer-stock-aich-fixture");
        let transfer_dir = Path::new(&root).join("fixture");
        fs::create_dir_all(&transfer_dir).unwrap();
        let payload_path = transfer_dir.join(PAYLOAD_FILE_NAME);
        write_repeating_pattern_file(
            &payload_path,
            10_485_760,
            b"ubuntu-linux-ed2k-private-roundtrip-large",
        );

        let rebuilt = super::build_aich_hashset_from_payload(&payload_path, 10_485_760).unwrap();
        assert_eq!(
            hex::encode(rebuilt.master_hash),
            "050066b767710d1bd84377e71b1b23e522cce4af"
        );
        assert_eq!(
            rebuilt
                .part_hashes
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            vec![
                "80ebdc35e9618aa7617fa988f756a33b79aa0d6c".to_string(),
                "b05ae2f6c5a179ec4b7ecffdcc18045151be0437".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn ingest_local_file_marks_payload_complete_with_stock_aich_identity() {
        let root = unique_test_dir("ed2k-transfer-local-ingest");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let source_dir = Path::new(&root).join("source");
        fs::create_dir_all(&source_dir).unwrap();
        let source_path = source_dir.join("ubuntu-linux-private-roundtrip-large.bin");
        write_repeating_pattern_file(
            &source_path,
            10_485_760,
            b"ubuntu-linux-ed2k-private-roundtrip-large",
        );

        let summary = runtime
            .ingest_local_file(&source_path, "ubuntu-linux-private-roundtrip-large.bin")
            .await
            .unwrap();
        assert_eq!(summary.file_size, 10_485_760);
        assert_eq!(summary.md4_hashset_count, 2);
        assert_eq!(summary.aich_hashset_count, 2);
        assert_eq!(
            summary.aich_root,
            "050066b767710d1bd84377e71b1b23e522cce4af"
        );

        let manifest = runtime.manifest(&summary.file_hash).await.unwrap();
        assert!(manifest.completed);
        assert!(manifest.aich_hashset_acquired);
        assert_eq!(
            manifest.aich_root.as_deref(),
            Some("050066b767710d1bd84377e71b1b23e522cce4af")
        );
        assert_eq!(manifest.md4_hashset.len(), 2);
        assert_eq!(manifest.aich_hashset.len(), 2);
    }

    #[tokio::test]
    async fn ensure_job_rebuilds_legacy_manifest_missing_aich_fields() {
        let root = unique_test_dir("ed2k-transfer-legacy-aich-manifest");
        let file_hash = hex::encode([0x41; 16]);
        let transfer_dir = Path::new(&root).join(&file_hash);
        fs::create_dir_all(&transfer_dir).unwrap();
        fs::write(
            transfer_dir.join(MANIFEST_FILE_NAME),
            format!(
                "{{\"file_hash\":\"{}\",\"canonical_name\":\"legacy.iso\",\"file_size\":{},\"piece_size\":{},\"completed\":false,\"md4_hashset_acquired\":false,\"md4_hashset\":[],\"verified_ranges\":[],\"pieces\":[],\"sources\":[]}}",
                file_hash,
                ED2K_PART_SIZE + 1,
                ED2K_PART_SIZE,
            ),
        )
        .unwrap();

        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let rebuilt = runtime
            .ensure_job(&new_transfer_job(
                Ed2kHash::from_str(&file_hash).unwrap(),
                "legacy.iso".to_string(),
                ED2K_PART_SIZE + 1,
            ))
            .await
            .unwrap();
        assert!(!rebuilt.aich_hashset_acquired);
        assert!(rebuilt.aich_root.is_none());
        assert!(rebuilt.aich_hashset.is_empty());

        let quarantined = fs::read_dir(&transfer_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("resume-manifest.json.corrupt-"))
            .collect::<Vec<_>>();
        assert_eq!(quarantined.len(), 1);
    }

    #[tokio::test]
    async fn store_aich_hashset_rejects_internally_inconsistent_root() {
        let root = unique_test_dir("ed2k-transfer-invalid-aich");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let file_hash = Ed2kHash::from_bytes([0x61; 16]);
        let job = new_transfer_job(
            file_hash,
            "invalid-aich.iso".to_string(),
            ED2K_PART_SIZE + 7,
        );
        runtime.ensure_job(&job).await.unwrap();

        let error = runtime
            .store_aich_hashset(
                &job.file_hash,
                super::Ed2kAichHashset {
                    master_hash: [0x44; 20],
                    part_hashes: vec![[0x11; 20], [0x22; 20]],
                },
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("does not reconstruct"));
    }

    #[tokio::test]
    async fn reconcile_job_metadata_adopts_unknown_size_and_name() {
        let root = unique_test_dir("ed2k-transfer-reconcile-metadata");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let file_hash = Ed2kHash::from_bytes([0x61; 16]);
        let placeholder_job = new_transfer_job(file_hash, "ed2k-placeholder.bin".to_string(), 0);
        let initial = runtime.ensure_job(&placeholder_job).await.unwrap();
        assert_eq!(initial.file_size, 0);
        assert!(initial.pieces.is_empty());

        let updated = runtime
            .reconcile_job_metadata(
                &placeholder_job.file_hash,
                Some("ubuntu-live.iso"),
                Some(ED2K_PART_SIZE + 7),
            )
            .await
            .unwrap();
        assert_eq!(updated.canonical_name, "ubuntu-live.iso");
        assert_eq!(updated.file_size, ED2K_PART_SIZE + 7);
        assert_eq!(updated.pieces.len(), 2);
        assert!(
            updated
                .pieces
                .iter()
                .all(|piece| piece.state == Ed2kTransferState::Missing)
        );
    }

    #[tokio::test]
    async fn release_piece_request_preserves_partial_piece_progress() {
        let root = unique_test_dir("ed2k-transfer-release-request-progress");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5Au8; 32_768];
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let job = new_transfer_job(file_hash, "resume.bin".to_string(), payload.len() as u64);
        runtime.ensure_job(&job).await.unwrap();

        let claimed = runtime
            .claim_next_missing_part(&job.file_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.piece_index, 0);
        assert_eq!(claimed.bytes_written, 0);

        let split = 8_192usize;
        let completed = runtime
            .append_piece_block(&job.file_hash, 0, 0, split as u64, &payload[..split])
            .await
            .unwrap();
        assert!(!completed);

        runtime
            .release_piece_request(&job.file_hash, 0)
            .await
            .unwrap();

        let manifest = runtime.manifest(&job.file_hash).await.unwrap();
        assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Missing);
        assert_eq!(manifest.pieces[0].bytes_written, split as u64);

        let reclaimed = runtime
            .claim_next_missing_part(&job.file_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reclaimed.piece_index, 0);
        assert_eq!(reclaimed.bytes_written, split as u64);
    }

    #[tokio::test]
    async fn append_piece_block_keeps_partial_progress_in_memory_until_checkpoint() {
        let root = unique_test_dir("ed2k-transfer-cached-partial-progress");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5Au8; 65_536];
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let job = new_transfer_job(
            file_hash,
            "cached-progress.bin".to_string(),
            payload.len() as u64,
        );
        runtime.ensure_job(&job).await.unwrap();
        runtime
            .store_md4_hashset(&job.file_hash, Vec::new())
            .await
            .unwrap();
        runtime
            .claim_next_missing_part(&job.file_hash)
            .await
            .unwrap()
            .unwrap();

        let split = 8_192usize;
        let piece_completed = runtime
            .append_piece_block(&job.file_hash, 0, 0, split as u64, &payload[..split])
            .await
            .unwrap();
        assert!(!piece_completed);

        let cached_manifest = runtime.manifest(&job.file_hash).await.unwrap();
        assert_eq!(
            cached_manifest.pieces[0].state,
            Ed2kTransferState::Requested
        );
        assert_eq!(cached_manifest.pieces[0].bytes_written, split as u64);

        let persisted_manifest = read_manifest_from_disk(&root, &job.file_hash);
        assert_eq!(
            persisted_manifest.pieces[0].state,
            Ed2kTransferState::Requested
        );
        assert_eq!(persisted_manifest.pieces[0].bytes_written, 0);
    }

    #[tokio::test]
    async fn reclaim_stale_piece_requests_restores_missing_state_with_progress() {
        let root = unique_test_dir("ed2k-transfer-reclaim-stale-request");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x6Bu8; 32_768];
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let job = new_transfer_job(file_hash, "resume.bin".to_string(), payload.len() as u64);
        runtime.ensure_job(&job).await.unwrap();

        runtime
            .claim_next_missing_part(&job.file_hash)
            .await
            .unwrap()
            .unwrap();
        let split = 8_192usize;
        runtime
            .append_piece_block(&job.file_hash, 0, 0, split as u64, &payload[..split])
            .await
            .unwrap();

        assert!(
            runtime
                .reclaim_stale_piece_requests(&job.file_hash)
                .await
                .unwrap()
        );

        let manifest = runtime.manifest(&job.file_hash).await.unwrap();
        assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Missing);
        assert_eq!(manifest.pieces[0].bytes_written, split as u64);
    }

    #[tokio::test]
    async fn append_piece_block_persists_piece_completion_after_cached_progress() {
        let root = unique_test_dir("ed2k-transfer-piece-completion-checkpoint");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x6Bu8; 65_536];
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let job = new_transfer_job(
            file_hash,
            "completion-checkpoint.bin".to_string(),
            payload.len() as u64,
        );
        runtime.ensure_job(&job).await.unwrap();
        runtime
            .store_md4_hashset(&job.file_hash, Vec::new())
            .await
            .unwrap();
        runtime
            .claim_next_missing_part(&job.file_hash)
            .await
            .unwrap()
            .unwrap();

        let split = 8_192usize;
        let first_completed = runtime
            .append_piece_block(&job.file_hash, 0, 0, split as u64, &payload[..split])
            .await
            .unwrap();
        assert!(!first_completed);

        let final_completed = runtime
            .append_piece_block(
                &job.file_hash,
                0,
                split as u64,
                payload.len() as u64,
                &payload[split..],
            )
            .await
            .unwrap();
        assert!(final_completed);

        let persisted_manifest = read_manifest_from_disk(&root, &job.file_hash);
        assert!(persisted_manifest.completed);
        assert_eq!(
            persisted_manifest.pieces[0].state,
            Ed2kTransferState::Verified
        );
        assert_eq!(
            persisted_manifest.pieces[0].bytes_written,
            payload.len() as u64
        );

        let reloaded_runtime = Ed2kTransferRuntime::load_or_create(Path::new(&root)).unwrap();
        let reloaded_manifest = reloaded_runtime.manifest(&job.file_hash).await.unwrap();
        assert!(reloaded_manifest.completed);
        assert_eq!(
            reloaded_manifest.pieces[0].state,
            Ed2kTransferState::Verified
        );
        assert_eq!(
            reloaded_manifest.pieces[0].bytes_written,
            payload.len() as u64
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

    #[tokio::test]
    async fn upload_queue_grants_immediately_then_promotes_waiter() {
        let root = unique_test_dir("ed2k-upload-queue-promote");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        runtime
            .configure_upload_queue(Ed2kUploadQueueConfig {
                active_slots: 1,
                waiting_capacity: 8,
                waiting_timeout: Duration::from_secs(30),
                granted_timeout: Duration::from_secs(30),
                upload_timeout: Duration::from_secs(30),
            })
            .await;
        let file_hash = Ed2kHash::from_bytes([0x5A; 16]);

        let first_peer = Ed2kUploadPeerIdentity {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            tcp_port: 4662,
            user_hash: Some([0x11; 16]),
            client_id: Some(1),
        };
        let second_peer = Ed2kUploadPeerIdentity {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            tcp_port: 4662,
            user_hash: Some([0x22; 16]),
            client_id: Some(2),
        };

        let (first_handle, first_status) =
            runtime.begin_upload_session(first_peer, &file_hash).await;
        assert_eq!(first_status, Ed2kUploadSessionStatus::Granted);

        let (second_handle, second_status) =
            runtime.begin_upload_session(second_peer, &file_hash).await;
        assert_eq!(second_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

        runtime.release_upload_session(&first_handle).await;
        assert_eq!(
            runtime.poll_upload_session(&second_handle, true).await,
            Ed2kUploadSessionStatus::Granted
        );
    }

    #[tokio::test]
    async fn upload_queue_reconnect_replaces_stale_connection() {
        let root = unique_test_dir("ed2k-upload-queue-reconnect");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        runtime
            .configure_upload_queue(Ed2kUploadQueueConfig {
                active_slots: 1,
                waiting_capacity: 8,
                waiting_timeout: Duration::from_secs(30),
                granted_timeout: Duration::from_secs(30),
                upload_timeout: Duration::from_secs(30),
            })
            .await;
        let file_hash = Ed2kHash::from_bytes([0xA5; 16]);
        let peer = Ed2kUploadPeerIdentity {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
            tcp_port: 4662,
            user_hash: Some([0x44; 16]),
            client_id: Some(9),
        };

        let (first_handle, first_status) =
            runtime.begin_upload_session(peer.clone(), &file_hash).await;
        assert_eq!(first_status, Ed2kUploadSessionStatus::Granted);

        let (second_handle, second_status) = runtime.begin_upload_session(peer, &file_hash).await;
        assert_eq!(second_status, Ed2kUploadSessionStatus::Granted);
        assert_eq!(
            runtime.poll_upload_session(&first_handle, true).await,
            Ed2kUploadSessionStatus::Stale
        );
        runtime.release_upload_session(&first_handle).await;
        assert_eq!(
            runtime.poll_upload_session(&second_handle, true).await,
            Ed2kUploadSessionStatus::Granted
        );
    }

    #[tokio::test]
    async fn upload_queue_same_peer_different_file_preserves_waiting_rank() {
        let root = unique_test_dir("ed2k-upload-queue-peer-file-switch");
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        runtime
            .configure_upload_queue(Ed2kUploadQueueConfig {
                active_slots: 1,
                waiting_capacity: 8,
                waiting_timeout: Duration::from_secs(30),
                granted_timeout: Duration::from_secs(30),
                upload_timeout: Duration::from_secs(30),
            })
            .await;
        let first_file_hash = Ed2kHash::from_bytes([0xA1; 16]);
        let second_file_hash = Ed2kHash::from_bytes([0xB2; 16]);
        let third_file_hash = Ed2kHash::from_bytes([0xC3; 16]);

        let first_peer = Ed2kUploadPeerIdentity {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            tcp_port: 4661,
            user_hash: Some([0x11; 16]),
            client_id: Some(1),
        };
        let waiting_peer = Ed2kUploadPeerIdentity {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            tcp_port: 4662,
            user_hash: Some([0x22; 16]),
            client_id: Some(2),
        };
        let trailing_peer = Ed2kUploadPeerIdentity {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            tcp_port: 4663,
            user_hash: Some([0x33; 16]),
            client_id: Some(3),
        };

        let (_first_handle, first_status) = runtime
            .begin_upload_session(first_peer, &first_file_hash)
            .await;
        assert_eq!(first_status, Ed2kUploadSessionStatus::Granted);

        let (waiting_handle, waiting_status) = runtime
            .begin_upload_session(waiting_peer.clone(), &first_file_hash)
            .await;
        assert_eq!(waiting_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

        let (trailing_handle, trailing_status) = runtime
            .begin_upload_session(trailing_peer, &third_file_hash)
            .await;
        assert_eq!(
            trailing_status,
            Ed2kUploadSessionStatus::Waiting { rank: 2 }
        );

        let (replacement_handle, replacement_status) = runtime
            .begin_upload_session(waiting_peer, &second_file_hash)
            .await;
        assert_eq!(
            replacement_status,
            Ed2kUploadSessionStatus::Waiting { rank: 1 }
        );
        assert_eq!(
            runtime.poll_upload_session(&waiting_handle, true).await,
            Ed2kUploadSessionStatus::Stale
        );
        assert_eq!(
            runtime.poll_upload_session(&replacement_handle, true).await,
            Ed2kUploadSessionStatus::Waiting { rank: 1 }
        );
        assert_eq!(
            runtime.poll_upload_session(&trailing_handle, true).await,
            Ed2kUploadSessionStatus::Waiting { rank: 2 }
        );
    }
}
