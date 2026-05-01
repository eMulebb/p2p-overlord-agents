//! Serializable agent configuration types and defaults.

use overlord_agent_nat::default_upnp_backend_order;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EmuleAgentConfig {
    /// Coordinator HTTP endpoint and registration settings.
    pub coordinator: CoordinatorConfig,
    /// Agent identity and local state paths.
    pub agent: AgentConfig,
    /// HTTP control-plane binding settings.
    pub control: ControlConfig,
    /// P2P protocol listeners and Kad/eD2k runtime settings.
    pub p2p: P2pConfig,
    /// NAT traversal and UPnP behavior.
    pub nat: NatConfig,
    /// Local logging settings.
    pub log: LogConfig,
    /// Whether startup TOML sections should stay authoritative over later
    /// coordinator-sourced networking snapshots.
    #[serde(skip)]
    pub(super) networking_authority: NetworkingSectionAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct NetworkingSectionAuthority {
    pub(super) control: bool,
    pub(super) p2p: bool,
    pub(super) nat: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CoordinatorConfig {
    /// Base coordinator URL used for registration, search jobs, and result posting.
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// Path of the persisted stable indexer UUID.
    pub indexer_id_path: String,
    /// Directory that owns persisted runtime state such as `nodes.dat`.
    pub state_dir: String,
    /// Hostname reported to the coordinator.
    pub hostname: String,
    /// Agent version string reported to the coordinator.
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlConfig {
    /// Optional interface name for the HTTP control surface.
    pub bind_iface: Option<String>,
    /// Optional explicit IP for the HTTP control surface.
    pub bind_ip: Option<String>,
    /// Whether the operator already confirmed this bind selection.
    pub selection_confirmed: bool,
    /// Agent HTTP control port.
    pub listen_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct P2pConfig {
    /// Optional interface name for P2P listeners.
    pub bind_iface: Option<String>,
    /// Optional explicit P2P bind IP.
    pub bind_ip: Option<String>,
    /// Whether the operator already confirmed this P2P bind selection.
    pub selection_confirmed: bool,
    /// Kad runtime settings.
    pub kad: KadConfig,
    /// ED2K runtime settings.
    pub ed2k: Ed2kConfig,
    /// Passive snoop-queue scheduling and replay settings.
    pub snoop_queue: SnoopQueueConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KadConfig {
    /// Local Kad UDP port.
    pub listen_port: u16,
    /// Path of the persisted `nodes.dat`.
    pub nodes_dat_path: String,
    /// Optional plaintext bootstrap contact list.
    pub bootstrap_nodes: Vec<String>,
    /// Minimum number of routing contacts required before Kad-dependent workflows may run.
    ///
    /// The default remains `10` for real-network behavior. Smaller local harness
    /// clusters may lower this explicitly in their private config.
    pub bootstrap_min_routing_contacts: usize,
    pub search_timeout_secs: u64,
    pub store_timeout_secs: u64,
    pub republish_interval_secs: u64,
    /// Maximum number of closest contacts to publish to per Kad publish round.
    pub publish_contact_fanout: usize,
    /// Interval between random-target Kad routing refresh walks.
    pub routing_refresh_interval_secs: u64,
    /// Interval between low-priority proactive Kad HELLO introductions.
    pub hello_intro_interval_secs: u64,
    /// Maximum number of peers to introduce ourselves to each HELLO round.
    pub hello_intro_fanout: usize,
    /// Maximum delay between `nodes.dat` snapshots while the routing table changes.
    pub nodes_dat_refresh_interval_secs: u64,
    /// Whether the agent should actively verify UDP reachability using Kad helper peers.
    pub udp_firewall_check_enabled: bool,
    /// Delay between active Kad UDP firewall re-check rounds.
    pub udp_firewall_recheck_interval_secs: u64,
    /// Timeout budget for one active Kad UDP firewall-check round.
    pub udp_firewall_check_timeout_secs: u64,
    /// Number of helper peers to ask during each active Kad UDP firewall-check round.
    pub udp_firewall_check_contact_count: usize,
    /// Whether the agent should retain inbound Kad publishes and serve them back to peers.
    pub local_store_enabled: bool,
    /// Retention window for locally stored keyword publishes.
    pub local_store_keyword_ttl_secs: u64,
    /// Retention window for locally stored source publishes.
    pub local_store_source_ttl_secs: u64,
    /// Retention window for locally stored note publishes.
    pub local_store_notes_ttl_secs: u64,
    /// Maximum number of retained keyword publish entries.
    pub local_store_keyword_capacity: usize,
    /// Maximum number of retained source publish entries.
    pub local_store_source_capacity: usize,
    /// Maximum number of retained notes publish entries.
    pub local_store_notes_capacity: usize,
    /// Global Kad outbound safety cap.
    pub max_outbound_pps: u32,
    /// Reserved interactive Kad budget layered under `max_outbound_pps`.
    pub interactive_max_outbound_pps: u32,
    /// Reserved passive-harvest Kad budget layered under `max_outbound_pps`.
    pub harvest_max_outbound_pps: u32,
    /// Reserved maintenance Kad budget layered under `max_outbound_pps`.
    pub maintenance_max_outbound_pps: u32,
    /// Reserved background publish Kad budget layered under `max_outbound_pps`.
    pub publish_max_outbound_pps: u32,
    pub search_phase2_fanout: usize,
    pub keyword_result_cap: usize,
    pub source_result_cap: usize,
    pub notes_result_cap: usize,
    /// Interval between synthetic fallback publish drip ticks while the coordinator is unavailable.
    pub synthetic_publish_interval_secs: u64,
    /// Maximum number of synthetic fallback entries to publish per drip tick.
    pub synthetic_publish_batch_items: usize,
    /// Fanout used by low-priority synthetic fallback publishes.
    pub synthetic_publish_contact_fanout: usize,
    /// Whether seed-popular runs should emit synthetic notes publishes in addition to
    /// keyword and source publishes.
    ///
    /// This remains disabled by default so normal runtime behavior does not change.
    /// Enable it only for controlled live validation of notes-publish parity.
    pub seed_notes_publish_enabled: bool,
    pub obfuscation_enabled: bool,
    pub enable_mock_results: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ed2kConfig {
    /// Local ED2K peer TCP listener port.
    pub listen_port: u16,
    /// Ordered ED2K server bootstrap entries mirrored from `server.met`.
    pub server_entries: Vec<Ed2kServerEntry>,
    /// Ordered ED2K server bootstrap endpoints in `host:port` form.
    ///
    /// This legacy flattened list is still accepted so existing runtime config
    /// files keep working while parity helpers migrate to metadata-rich
    /// `server_entries`.
    pub server_endpoints: Vec<String>,
    /// Whether the agent should advertise and use eD2k TCP obfuscation.
    pub obfuscation_enabled: bool,
    /// Optional one-shot ED2K server search probe term used for parity runs.
    pub probe_search_term: Option<String>,
    /// Timeout for one outbound ED2K server connection attempt.
    pub connect_timeout_secs: u64,
    /// Delay before retrying the next ED2K server endpoint.
    pub reconnect_interval_secs: u64,
    /// Idle interval before the client refreshes the ED2K server session.
    pub keepalive_secs: u64,
    /// Maximum lifetime of one ED2K server session before rotating to the next endpoint.
    ///
    /// A value of `0` disables proactive rotation and keeps the current session
    /// alive until the remote side disconnects or the agent shuts down.
    pub session_rotation_secs: u64,
    /// Maximum number of ED2K download jobs allowed to run active metadata/source
    /// acquisition and peer sessions at once.
    pub max_concurrent_downloads: usize,
    /// Maximum number of direct ED2K peers one download may keep in flight at once.
    pub max_parallel_download_peers: usize,
    /// Maximum number of one-shot ED2K servers to probe for a normal keyword search.
    pub keyword_server_attempt_budget: usize,
    /// Maximum number of one-shot ED2K servers to probe for an exact `ed2k::<hash>`
    /// metadata lookup before the job falls back to later retry paths.
    pub exact_hash_keyword_server_attempt_budget: usize,
    /// Maximum number of one-shot ED2K servers to probe while acquiring sources
    /// for one active file download.
    pub source_server_attempt_budget: usize,
    /// Only run Kad source supplementation when the ED2K server path found at
    /// most this many sources for the file.
    pub kad_source_supplement_max_existing_sources: usize,
    /// Deterministic inbound upload queue policy for peer download sessions.
    pub upload_queue: Ed2kUploadQueuePolicyConfig,
}

/// Agent-configurable ED2K upload queue policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ed2kUploadQueuePolicyConfig {
    /// Maximum number of concurrently granted upload sessions.
    pub active_slots: usize,
    /// Maximum number of queued waiters retained at once.
    pub waiting_capacity: usize,
    /// Maximum idle time for a queued waiter before it expires.
    pub waiting_timeout_secs: u64,
    /// Maximum stall time after a grant before the peer requests part data.
    pub granted_timeout_secs: u64,
    /// Maximum idle time while a peer is actively uploading.
    pub upload_timeout_secs: u64,
}

/// Metadata-rich ED2K server bootstrap entry mirrored from eMule's
/// `server.met` format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Ed2kServerEntry {
    /// DNS hostname or IPv4 address used for the base ED2K TCP connection.
    pub host: String,
    /// Base ED2K TCP port.
    pub port: u16,
    /// Optional human-readable server name.
    pub name: Option<String>,
    /// Optional human-readable server description.
    pub description: Option<String>,
    /// Server UDP capability flags mirrored from `ST_UDPFLAGS`.
    pub udp_flags: u32,
    /// Server UDP verify key mirrored from `ST_UDPKEY`.
    pub udp_key: u32,
    /// IP affinity for `udp_key`, mirrored from `ST_UDPKEYIP`.
    pub udp_key_ip: u32,
    /// Alternate TCP port used for obfuscated ED2K server sessions.
    pub obfuscation_port_tcp: u16,
    /// Alternate UDP port used for obfuscated ED2K server UDP traffic.
    pub obfuscation_port_udp: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SnoopQueueConfig {
    /// Window used to decide whether a harvested query is still fresh demand.
    pub dedup_window_secs: u64,
    /// Shared passive drain budget for keyword and notes requests over ten minutes.
    pub general_max_queries_per_600s: u32,
    /// Shared cooldown before keyword or notes requests may be replayed again.
    pub general_drain_cooldown_secs: u64,
    /// Dedicated passive drain budget for source requests over ten minutes.
    pub source_max_queries_per_600s: u32,
    /// Cooldown before one source request may be replayed again.
    pub source_drain_cooldown_secs: u64,
    /// Result count that is considered good enough for one passive source replay cycle.
    pub source_stop_after_results: usize,
}

/// NAT runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NatConfig {
    /// P2P-facing NAT mapping settings.
    pub p2p: NatP2pConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NatP2pConfig {
    /// Whether NAT mapping maintenance is enabled.
    pub enabled: bool,
    /// Preferred NAT backends in priority order.
    pub backend_order: Vec<String>,
    /// Optional fixed IGD address.
    pub igd_ip: Option<String>,
    /// Optional minissdpd socket path.
    pub minissdpd_socket: Option<String>,
    /// Optional local SSDP source port override.
    pub ssdp_local_port: Option<u16>,
    /// Discovery timeout budget.
    pub discovery_timeout_secs: u64,
    /// Requested mapping lease duration.
    pub lease_duration_secs: u32,
    /// Renewal lead time before lease expiry.
    pub renew_margin_secs: u64,
    /// Forced external IP override when discovery is unavailable.
    pub external_ip_override: Option<String>,
}

/// File-based logging configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// Default tracing level filter.
    pub level: String,
    /// Optional log directory override.
    pub dir: Option<String>,
    /// Rotation cadence for file sinks.
    pub rotation: LogRotation,
    /// Maximum number of rotated files to retain.
    pub max_files: usize,
}

/// Supported file-rotation policies for agent logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogRotation {
    Minutely,
    Hourly,
    #[default]
    Daily,
    Never,
}

impl LogRotation {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Minutely => "minutely",
            Self::Hourly => "hourly",
            Self::Daily => "daily",
            Self::Never => "never",
        }
    }
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:13300".to_string(),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            indexer_id_path: "./runtime/overlord-agent-emule.indexer-id".to_string(),
            state_dir: "./runtime".to_string(),
            hostname: "localhost".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            bind_iface: None,
            bind_ip: None,
            selection_confirmed: false,
            listen_port: 13_301,
        }
    }
}

impl Default for KadConfig {
    fn default() -> Self {
        Self {
            listen_port: 41_000,
            nodes_dat_path: "./runtime/overlord-kad.nodes.dat".to_string(),
            bootstrap_nodes: Vec::new(),
            bootstrap_min_routing_contacts: 10,
            search_timeout_secs: 45,
            store_timeout_secs: 140,
            republish_interval_secs: 18_000,
            publish_contact_fanout: 4,
            routing_refresh_interval_secs: 900,
            hello_intro_interval_secs: 300,
            hello_intro_fanout: 2,
            nodes_dat_refresh_interval_secs: 300,
            udp_firewall_check_enabled: true,
            udp_firewall_recheck_interval_secs: 1_800,
            udp_firewall_check_timeout_secs: 20,
            udp_firewall_check_contact_count: 2,
            local_store_enabled: true,
            local_store_keyword_ttl_secs: 86_400,
            local_store_source_ttl_secs: 21_600,
            local_store_notes_ttl_secs: 86_400,
            local_store_keyword_capacity: 20_000,
            local_store_source_capacity: 20_000,
            local_store_notes_capacity: 5_000,
            max_outbound_pps: 8,
            interactive_max_outbound_pps: 4,
            harvest_max_outbound_pps: 1,
            maintenance_max_outbound_pps: 1,
            publish_max_outbound_pps: 1,
            search_phase2_fanout: 50,
            keyword_result_cap: 5_000,
            source_result_cap: 1_000,
            notes_result_cap: 1_000,
            synthetic_publish_interval_secs: 120,
            synthetic_publish_batch_items: 1,
            synthetic_publish_contact_fanout: 1,
            seed_notes_publish_enabled: false,
            obfuscation_enabled: true,
            enable_mock_results: false,
        }
    }
}

impl Default for Ed2kConfig {
    fn default() -> Self {
        Self {
            listen_port: 41_001,
            server_entries: Vec::new(),
            server_endpoints: Vec::new(),
            obfuscation_enabled: true,
            probe_search_term: None,
            connect_timeout_secs: 15,
            reconnect_interval_secs: 30,
            keepalive_secs: 60,
            session_rotation_secs: 0,
            max_concurrent_downloads: 1,
            max_parallel_download_peers: 2,
            keyword_server_attempt_budget: 3,
            exact_hash_keyword_server_attempt_budget: 4,
            source_server_attempt_budget: 3,
            kad_source_supplement_max_existing_sources: 2,
            upload_queue: Ed2kUploadQueuePolicyConfig::default(),
        }
    }
}

impl Default for Ed2kUploadQueuePolicyConfig {
    fn default() -> Self {
        Self {
            active_slots: 3,
            waiting_capacity: 512,
            waiting_timeout_secs: 180,
            granted_timeout_secs: 30,
            upload_timeout_secs: 90,
        }
    }
}

impl Default for SnoopQueueConfig {
    fn default() -> Self {
        Self {
            dedup_window_secs: 28_800,
            general_max_queries_per_600s: 24,
            general_drain_cooldown_secs: 900,
            source_max_queries_per_600s: 60,
            source_drain_cooldown_secs: 300,
            source_stop_after_results: 2,
        }
    }
}

impl Default for NatP2pConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend_order: default_upnp_backend_order(),
            igd_ip: None,
            minissdpd_socket: None,
            ssdp_local_port: None,
            discovery_timeout_secs: 5,
            lease_duration_secs: 3_600,
            renew_margin_secs: 300,
            external_ip_override: None,
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            dir: None,
            rotation: LogRotation::Daily,
            max_files: 7,
        }
    }
}
