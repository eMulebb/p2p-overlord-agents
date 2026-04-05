use chrono::{DateTime, Utc};
use overlord_agent_nat::NatStatusSnapshot;
pub use overlord_agent_nat::{AgentNetworkReport, AgentNetworkingConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Kad2,
    Ed2k,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum HashType {
    Ed2k(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    Video,
    Audio,
    Document,
    Archive,
    Software,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TagEntry {
    pub key: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Source {
    pub protocol: Protocol,
    pub address: String,
    #[serde(default)]
    pub extra: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileRecord {
    #[serde(default)]
    pub hashes: Vec<HashType>,
    #[serde(default)]
    pub names: Vec<String>,
    pub size: Option<u64>,
    pub content_type: Option<ContentType>,
    #[serde(default)]
    pub tags: Vec<TagEntry>,
    #[serde(default)]
    pub sources: Vec<Source>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchKind {
    Keyword,
    Source,
    Notes,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchJob {
    pub job_id: Uuid,
    pub protocol: Protocol,
    pub kind: SearchKind,
    pub query: Option<String>,
    pub file_hash: Option<HashType>,
    pub file_size: Option<u64>,
    pub callback_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchEventStatus {
    Started,
    BatchReceived,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchEvent {
    pub job_id: Uuid,
    pub indexer_id: Uuid,
    pub status: SearchEventStatus,
    pub result_count: Option<u32>,
    pub batch_count: Option<u32>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchCancelRequest {
    pub job_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultBatch {
    pub job_id: Option<Uuid>,
    pub indexer_id: Uuid,
    pub protocol: Protocol,
    /// Optional metadata that links a passive replay batch back to the harvested Kad shape that produced it.
    #[serde(default)]
    pub harvest_context: Option<HarvestReplayContext>,
    #[serde(default)]
    pub files: Vec<FileRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexerStats {
    pub indexer_id: Uuid,
    pub protocol: Protocol,
    pub peers_connected: u32,
    pub crawl_rate: f32,
    pub snoop_queue_depth: u32,
    pub staging_queue_depth: u32,
    pub uptime_secs: u64,
    pub nat: Option<NatStatusSnapshot>,
    pub interface_report: Option<AgentNetworkReport>,
    pub agent_activity: Option<AgentActivitySnapshot>,
    pub publish_observability: Option<KadPublishObservability>,
    pub harvest_observability: Option<KadHarvestObservability>,
    pub rpc_observability: Option<KadRpcObservability>,
}

/// High-level current activity state for the running agent process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentActivityState {
    Starting,
    Bootstrapping,
    Idle,
    Downloading,
    ActiveSearch,
    PassiveHarvestReplay,
    Publishing,
    FlushingSnoops,
    Reconfiguring,
    Degraded,
}

/// Snapshot of the single operator-facing activity the agent is currently prioritizing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentActivitySnapshot {
    pub state: AgentActivityState,
    pub since: DateTime<Utc>,
    pub job_id: Option<Uuid>,
    pub protocol: Option<Protocol>,
    pub kind: Option<SearchKind>,
    pub query_or_target: Option<String>,
    pub progress_current: Option<u32>,
    pub progress_total: Option<u32>,
    pub last_update_at: DateTime<Utc>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishSeedSource {
    Coordinator,
    SyntheticFallback,
    ManualApi,
}

impl PublishSeedSource {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::SyntheticFallback => "synthetic_fallback",
            Self::ManualApi => "manual_api",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishBatchSummary {
    pub seed_source: PublishSeedSource,
    pub published_items: u32,
    pub closest_contacts_considered: u32,
    pub attempted_contacts: u32,
    pub acked_contacts: u32,
    pub failed_contacts: u32,
    pub timed_out_contacts: u32,
    pub completed_at: DateTime<Utc>,
    pub last_success_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PublishCounters {
    pub batches: u64,
    pub published_items: u64,
    pub closest_contacts_considered: u64,
    pub attempted_contacts: u64,
    pub acked_contacts: u64,
    pub failed_contacts: u64,
    pub timed_out_contacts: u64,
    pub last_batch_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLogFileStatus {
    pub path: String,
    pub rotation: String,
    pub max_files: usize,
    pub last_write_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KadPublishObservability {
    pub last_seed_source: Option<PublishSeedSource>,
    pub last_seed_at: Option<DateTime<Utc>>,
    pub latest_keyword_batch: Option<PublishBatchSummary>,
    pub latest_source_batch: Option<PublishBatchSummary>,
    #[serde(default)]
    pub keyword_counters: PublishCounters,
    #[serde(default)]
    pub source_counters: PublishCounters,
    pub log_file: Option<AgentLogFileStatus>,
}

/// Per-family harvested Kad search-request telemetry for the current agent process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KadHarvestFamilyObservability {
    pub observed_requests: u64,
    pub unique_shapes_observed: u64,
    pub queued_entries: u32,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub last_from: Option<String>,
    pub last_target: Option<String>,
    pub last_start_position: Option<u16>,
    pub last_size: Option<u64>,
    pub last_restrictive_bytes: Option<u32>,
}

/// Passive replay telemetry for harvested keyword searches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KadPassiveReplayTierSummary {
    /// Phase-2 responder ceiling used for this tier.
    pub responder_ceiling: u32,
    /// Unique results added by this tier.
    pub result_count: u32,
}

/// Passive replay telemetry for harvested Kad searches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KadPassiveReplayObservability {
    pub started_cycles: u64,
    pub completed_cycles: u64,
    pub idle_cycles: u64,
    pub emitted_results: u64,
    pub widened_cycles: u64,
    pub posted_batches: u64,
    pub post_failures: u64,
    pub enqueue_backpressure_events: u64,
    pub post_callbacks: u64,
    pub enqueue_wait_millis: u64,
    pub post_latency_millis: u64,
    pub last_started_at: Option<DateTime<Utc>>,
    pub last_completed_at: Option<DateTime<Utc>>,
    pub last_idle_at: Option<DateTime<Utc>>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub last_target: Option<String>,
    pub last_start_position: Option<u16>,
    pub last_restrictive_bytes: Option<u32>,
    pub last_result_count: u32,
    pub last_batches_posted: u32,
    pub last_enqueue_wait_millis: u32,
    pub last_post_latency_millis: u32,
    pub last_tiers_attempted: u32,
    pub last_widest_responder_ceiling: Option<u32>,
    pub last_widened: bool,
    #[serde(default)]
    pub last_tiers: Vec<KadPassiveReplayTierSummary>,
    pub last_error: Option<String>,
}

/// Kad harvest telemetry that complements publish observability during live runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KadHarvestObservability {
    pub keyword_requests: KadHarvestFamilyObservability,
    pub source_requests: KadHarvestFamilyObservability,
    pub notes_requests: KadHarvestFamilyObservability,
    pub passive_keyword_replay: KadPassiveReplayObservability,
    pub passive_source_replay: KadPassiveReplayObservability,
    pub passive_notes_replay: KadPassiveReplayObservability,
}

/// Aggregate Kad RPC tracker counters for one oracle request bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KadRpcTrackerBucketObservability {
    pub bucket: String,
    pub accepted_requests: u64,
    pub tracker_drops: u64,
    pub tracker_massive_drops: u64,
}

/// Aggregate Kad RPC response counters for one opcode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KadRpcResponseOpcodeObservability {
    pub opcode: String,
    pub matched_pending: u64,
    pub matched_tracked: u64,
    pub dropped_unrequested: u64,
    pub accepted_unsolicited: u64,
}

/// Machine-readable Kad RPC tracker and response-handling counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KadRpcObservability {
    pub decode_failures: u64,
    #[serde(default)]
    pub tracker_buckets: Vec<KadRpcTrackerBucketObservability>,
    #[serde(default)]
    pub response_opcodes: Vec<KadRpcResponseOpcodeObservability>,
}

/// Kad search-request family observed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarvestFamily {
    Keyword,
    Source,
    Notes,
}

/// Stable context that ties passive replay result batches back to one harvested request shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarvestReplayContext {
    pub replay_id: Uuid,
    pub family: HarvestFamily,
    pub logical_key: String,
    pub target: String,
    pub start_position: Option<u16>,
    pub size: Option<u64>,
    pub restrictive_payload_hex: Option<String>,
}

/// Summary record for one passive replay cycle, including zero-result replays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarvestReplayRecord {
    pub replay_id: Uuid,
    pub indexer_id: Uuid,
    pub family: HarvestFamily,
    pub logical_key: String,
    pub target: String,
    pub start_position: Option<u16>,
    pub size: Option<u64>,
    pub restrictive_payload_hex: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub result_count: u32,
    pub batch_count: u32,
    pub error: Option<String>,
}

/// Append-only harvested Kad observation captured from unsolicited inbound search traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnoopObservation {
    pub family: HarvestFamily,
    pub logical_key: String,
    pub target: String,
    pub start_position: Option<u16>,
    pub size: Option<u64>,
    pub restrictive_payload_hex: Option<String>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigUpdate {
    pub protocol: Protocol,
    #[serde(default)]
    pub config: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum SnoopEntry {
    Keyword {
        logical_key: String,
        target: String,
        start_position: u16,
        restrictive_payload_hex: Option<String>,
        hit_count: u32,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        last_drained_at: Option<DateTime<Utc>>,
    },
    Source {
        logical_key: String,
        target: String,
        start_position: u16,
        size: u64,
        hit_count: u32,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        last_drained_at: Option<DateTime<Utc>>,
    },
    Notes {
        logical_key: String,
        target: String,
        size: u64,
        hit_count: u32,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        last_drained_at: Option<DateTime<Utc>>,
    },
}

impl SnoopEntry {
    #[must_use]
    pub fn logical_key(&self) -> &str {
        match self {
            SnoopEntry::Keyword { logical_key, .. }
            | SnoopEntry::Source { logical_key, .. }
            | SnoopEntry::Notes { logical_key, .. } => logical_key,
        }
    }

    #[must_use]
    pub fn target(&self) -> &str {
        match self {
            SnoopEntry::Keyword { target, .. }
            | SnoopEntry::Source { target, .. }
            | SnoopEntry::Notes { target, .. } => target,
        }
    }

    #[must_use]
    pub fn hit_count(&self) -> u32 {
        match self {
            SnoopEntry::Keyword { hit_count, .. }
            | SnoopEntry::Source { hit_count, .. }
            | SnoopEntry::Notes { hit_count, .. } => *hit_count,
        }
    }

    pub fn set_hit_count(&mut self, value: u32) {
        match self {
            SnoopEntry::Keyword { hit_count, .. }
            | SnoopEntry::Source { hit_count, .. }
            | SnoopEntry::Notes { hit_count, .. } => *hit_count = value,
        }
    }

    #[must_use]
    pub fn first_seen(&self) -> DateTime<Utc> {
        match self {
            SnoopEntry::Keyword { first_seen, .. }
            | SnoopEntry::Source { first_seen, .. }
            | SnoopEntry::Notes { first_seen, .. } => *first_seen,
        }
    }

    pub fn set_first_seen(&mut self, value: DateTime<Utc>) {
        match self {
            SnoopEntry::Keyword { first_seen, .. }
            | SnoopEntry::Source { first_seen, .. }
            | SnoopEntry::Notes { first_seen, .. } => *first_seen = value,
        }
    }

    #[must_use]
    pub fn last_seen(&self) -> DateTime<Utc> {
        match self {
            SnoopEntry::Keyword { last_seen, .. }
            | SnoopEntry::Source { last_seen, .. }
            | SnoopEntry::Notes { last_seen, .. } => *last_seen,
        }
    }

    pub fn set_last_seen(&mut self, value: DateTime<Utc>) {
        match self {
            SnoopEntry::Keyword { last_seen, .. }
            | SnoopEntry::Source { last_seen, .. }
            | SnoopEntry::Notes { last_seen, .. } => *last_seen = value,
        }
    }

    #[must_use]
    pub fn last_drained_at(&self) -> Option<DateTime<Utc>> {
        match self {
            SnoopEntry::Keyword {
                last_drained_at, ..
            }
            | SnoopEntry::Source {
                last_drained_at, ..
            }
            | SnoopEntry::Notes {
                last_drained_at, ..
            } => *last_drained_at,
        }
    }

    pub fn set_last_drained_at(&mut self, value: Option<DateTime<Utc>>) {
        match self {
            SnoopEntry::Keyword {
                last_drained_at, ..
            }
            | SnoopEntry::Source {
                last_drained_at, ..
            }
            | SnoopEntry::Notes {
                last_drained_at, ..
            } => *last_drained_at = value,
        }
    }

    #[must_use]
    pub fn restrictive_payload_hex(&self) -> Option<&str> {
        match self {
            SnoopEntry::Keyword {
                restrictive_payload_hex,
                ..
            } => restrictive_payload_hex.as_deref(),
            SnoopEntry::Source { .. } | SnoopEntry::Notes { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PopularHash {
    pub hash: HashType,
    pub canonical_name: String,
    pub size: u64,
    pub source_count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub indexer_id: Uuid,
    pub protocol: Protocol,
    pub url: String,
    pub hostname: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexerRegistration {
    pub indexer_id: Uuid,
    pub protocol: Protocol,
    pub url: String,
    pub hostname: String,
    pub version: String,
    pub registered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub registered: IndexerRegistration,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentInterfacesView {
    pub registration: IndexerRegistration,
    pub report: Option<AgentNetworkReport>,
    pub config: AgentNetworkingConfig,
    pub nat: Option<NatStatusSnapshot>,
    pub agent_activity: Option<AgentActivitySnapshot>,
    pub publish_observability: Option<KadPublishObservability>,
    pub harvest_observability: Option<KadHarvestObservability>,
    pub last_error: Option<String>,
}
