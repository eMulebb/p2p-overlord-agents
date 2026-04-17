//! Agent configuration model for the eMule/Kad runtime.
//!
//! The config layer is the boundary between TOML/runtime state and the
//! long-lived agent tasks. Public structs here should therefore document which
//! fields affect oracle-facing wire behavior versus purely local control-plane
//! behavior.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use overlord_agent_nat::{
    AgentControlConfig, AgentEd2kConfig, AgentKadConfig, AgentNatConfig, AgentNatP2pConfig,
    AgentNetworkingConfig, AgentP2pConfig, default_upnp_backend_order,
};
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
    networking_authority: NetworkingSectionAuthority,
}

const PERSISTED_NETWORKING_STATE_FILE: &str = "overlord-agent.networking.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct NetworkingSectionAuthority {
    control: bool,
    p2p: bool,
    nat: bool,
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
    pub max_outbound_pps: u32,
    pub search_phase2_fanout: usize,
    pub keyword_result_cap: usize,
    pub source_result_cap: usize,
    pub notes_result_cap: usize,
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
            publish_contact_fanout: 20,
            routing_refresh_interval_secs: 120,
            nodes_dat_refresh_interval_secs: 300,
            udp_firewall_check_enabled: true,
            udp_firewall_recheck_interval_secs: 300,
            udp_firewall_check_timeout_secs: 20,
            udp_firewall_check_contact_count: 2,
            local_store_enabled: true,
            local_store_keyword_ttl_secs: 86_400,
            local_store_source_ttl_secs: 21_600,
            local_store_notes_ttl_secs: 86_400,
            local_store_keyword_capacity: 20_000,
            local_store_source_capacity: 20_000,
            local_store_notes_capacity: 5_000,
            max_outbound_pps: 50,
            search_phase2_fanout: 50,
            keyword_result_cap: 5_000,
            source_result_cap: 1_000,
            notes_result_cap: 1_000,
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

impl EmuleAgentConfig {
    /// Merge a coordinator networking snapshot with the locally authoritative
    /// startup networking sections.
    ///
    /// This keeps explicit local test/runtime choices, such as firewalled
    /// no-UPnP runs with fresh ports, from being overwritten by a stale
    /// persisted snapshot pushed back through the coordinator.
    #[must_use]
    pub(crate) fn effective_coordinator_networking(
        &self,
        desired: &AgentNetworkingConfig,
    ) -> AgentNetworkingConfig {
        let mut effective = desired.clone();
        if self.networking_authority.control {
            effective.control = AgentControlConfig {
                bind_iface: self.control.bind_iface.clone(),
                bind_ip: self.control.bind_ip.clone(),
                selection_confirmed: self.control.selection_confirmed,
                listen_port: self.control.listen_port,
            };
        }
        if self.networking_authority.p2p {
            effective.p2p = AgentP2pConfig {
                bind_iface: self.p2p.bind_iface.clone(),
                bind_ip: self.p2p.bind_ip.clone(),
                selection_confirmed: self.p2p.selection_confirmed,
                kad: AgentKadConfig {
                    listen_port: self.p2p.kad.listen_port,
                },
                ed2k: AgentEd2kConfig {
                    listen_port: self.p2p.ed2k.listen_port,
                },
            };
        }
        if self.networking_authority.nat {
            effective.nat = AgentNatConfig {
                p2p: AgentNatP2pConfig {
                    enabled: self.nat.p2p.enabled,
                    backend_order: if self.nat.p2p.backend_order.is_empty() {
                        default_upnp_backend_order()
                    } else {
                        self.nat.p2p.backend_order.clone()
                    },
                    igd_ip: self.nat.p2p.igd_ip.clone(),
                    minissdpd_socket: self.nat.p2p.minissdpd_socket.clone(),
                    ssdp_local_port: self.nat.p2p.ssdp_local_port,
                    discovery_timeout_secs: self.nat.p2p.discovery_timeout_secs,
                    lease_duration_secs: self.nat.p2p.lease_duration_secs,
                    renew_margin_secs: self.nat.p2p.renew_margin_secs,
                    external_ip_override: self.nat.p2p.external_ip_override.clone(),
                },
            };
        }
        effective
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            let mut config = Self::default();
            merge_persisted_networking_fallback(
                &mut config,
                NetworkingSectionAuthority::default(),
            )?;
            return Ok(config);
        }
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config from {}", path.display()))?;
        let raw_value: toml::Value = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config from {}", path.display()))?;
        let authority = detect_networking_section_authority(&raw_value);
        let mut config: Self = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config from {}", path.display()))?;
        config.networking_authority = authority;
        normalize_control_config(&mut config.control);
        normalize_p2p_config(&mut config.p2p);
        normalize_nat_config(&mut config.nat);
        normalize_log_config(&mut config.log);
        merge_persisted_networking_fallback(&mut config, authority)?;
        Ok(config)
    }
}

fn detect_networking_section_authority(value: &toml::Value) -> NetworkingSectionAuthority {
    let Some(table) = value.as_table() else {
        return NetworkingSectionAuthority::default();
    };

    NetworkingSectionAuthority {
        control: table.contains_key("control"),
        p2p: table.contains_key("p2p"),
        nat: table.contains_key("nat"),
    }
}

fn merge_persisted_networking_fallback(
    config: &mut EmuleAgentConfig,
    authority: NetworkingSectionAuthority,
) -> Result<()> {
    let networking_path = Path::new(&config.agent.state_dir).join(PERSISTED_NETWORKING_STATE_FILE);
    if !networking_path.exists() {
        return Ok(());
    }

    let contents = fs::read_to_string(&networking_path).with_context(|| {
        format!(
            "failed to read networking state from {}",
            networking_path.display()
        )
    })?;
    let desired: AgentNetworkingConfig = serde_json::from_str(&contents).with_context(|| {
        format!(
            "failed to parse networking state from {}",
            networking_path.display()
        )
    })?;

    if !authority.control {
        apply_control_networking_fallback(config, &desired.control);
    }
    if !authority.p2p {
        apply_p2p_networking_fallback(config, &desired.p2p);
    }
    if !authority.nat {
        apply_nat_networking_fallback(config, &desired.nat);
    }
    Ok(())
}

fn apply_control_networking_fallback(config: &mut EmuleAgentConfig, desired: &AgentControlConfig) {
    config.control.bind_iface = desired.bind_iface.clone();
    config.control.bind_ip = desired.bind_ip.clone();
    config.control.selection_confirmed = desired.selection_confirmed;
    config.control.listen_port = desired.listen_port;
}

fn apply_p2p_networking_fallback(config: &mut EmuleAgentConfig, desired: &AgentP2pConfig) {
    config.p2p.bind_iface = desired.bind_iface.clone();
    config.p2p.bind_ip = desired.bind_ip.clone();
    config.p2p.selection_confirmed = desired.selection_confirmed;
    config.p2p.kad.listen_port = desired.kad.listen_port;
    config.p2p.ed2k.listen_port = desired.ed2k.listen_port;
}

fn apply_nat_networking_fallback(config: &mut EmuleAgentConfig, desired: &AgentNatConfig) {
    config.nat.p2p.enabled = desired.p2p.enabled;
    config.nat.p2p.backend_order = if desired.p2p.backend_order.is_empty() {
        default_upnp_backend_order()
    } else {
        desired.p2p.backend_order.clone()
    };
    config.nat.p2p.igd_ip = desired.p2p.igd_ip.clone();
    config.nat.p2p.minissdpd_socket = desired.p2p.minissdpd_socket.clone();
    config.nat.p2p.ssdp_local_port = desired.p2p.ssdp_local_port;
    config.nat.p2p.discovery_timeout_secs = desired.p2p.discovery_timeout_secs;
    config.nat.p2p.lease_duration_secs = desired.p2p.lease_duration_secs;
    config.nat.p2p.renew_margin_secs = desired.p2p.renew_margin_secs;
    config.nat.p2p.external_ip_override = desired.p2p.external_ip_override.clone();
}

fn normalize_control_config(config: &mut ControlConfig) {
    for value in [&mut config.bind_iface, &mut config.bind_ip] {
        if value
            .as_deref()
            .is_some_and(|inner| inner.trim().is_empty())
        {
            *value = None;
        }
    }
}

fn normalize_p2p_config(config: &mut P2pConfig) {
    for value in [&mut config.bind_iface, &mut config.bind_ip] {
        if value
            .as_deref()
            .is_some_and(|inner| inner.trim().is_empty())
        {
            *value = None;
        }
    }
}

fn normalize_nat_config(config: &mut NatConfig) {
    for value in [
        &mut config.p2p.igd_ip,
        &mut config.p2p.minissdpd_socket,
        &mut config.p2p.external_ip_override,
    ] {
        if value
            .as_deref()
            .is_some_and(|inner| inner.trim().is_empty())
        {
            *value = None;
        }
    }

    if config.p2p.ssdp_local_port == Some(0) {
        config.p2p.ssdp_local_port = None;
    }
}

fn normalize_log_config(config: &mut LogConfig) {
    if config
        .dir
        .as_deref()
        .is_some_and(|inner| inner.trim().is_empty())
    {
        config.dir = None;
    }

    if config.max_files == 0 {
        config.max_files = LogConfig::default().max_files;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ControlConfig, EmuleAgentConfig, LogConfig, LogRotation, NatConfig, NatP2pConfig,
        P2pConfig, PERSISTED_NETWORKING_STATE_FILE, normalize_control_config, normalize_log_config,
        normalize_nat_config, normalize_p2p_config,
    };
    use crate::paths::unique_test_dir;
    use overlord_agent_nat::{
        AgentControlConfig, AgentEd2kConfig, AgentKadConfig, AgentNatConfig, AgentNatP2pConfig,
        AgentNetworkingConfig, AgentP2pConfig, UPNP_MINIUPNPC_BACKEND, UPNP_RUPNP_BACKEND,
        default_upnp_backend_order,
    };
    use std::fs;

    #[test]
    fn normalize_nat_config_drops_blank_optional_fields() {
        let mut config = NatConfig {
            p2p: NatP2pConfig {
                igd_ip: Some(String::new()),
                minissdpd_socket: Some(" ".to_string()),
                ssdp_local_port: Some(0),
                external_ip_override: Some("\t".to_string()),
                ..NatP2pConfig::default()
            },
        };

        normalize_nat_config(&mut config);

        assert_eq!(config.p2p.igd_ip, None);
        assert_eq!(config.p2p.minissdpd_socket, None);
        assert_eq!(config.p2p.ssdp_local_port, None);
        assert_eq!(config.p2p.external_ip_override, None);
    }

    #[test]
    fn default_nat_config_prefers_miniupnpc_only() {
        assert_eq!(
            NatP2pConfig::default().backend_order,
            vec![UPNP_MINIUPNPC_BACKEND.to_string()]
        );
    }

    #[test]
    fn normalize_control_config_drops_blank_optional_fields() {
        let mut config = ControlConfig {
            bind_iface: Some(" ".to_string()),
            bind_ip: Some("\t".to_string()),
            ..ControlConfig::default()
        };

        normalize_control_config(&mut config);

        assert_eq!(config.bind_iface, None);
        assert_eq!(config.bind_ip, None);
    }

    #[test]
    fn normalize_p2p_config_drops_blank_optional_fields() {
        let mut config = P2pConfig {
            bind_iface: Some(" ".to_string()),
            bind_ip: Some("\t".to_string()),
            ..P2pConfig::default()
        };

        normalize_p2p_config(&mut config);

        assert_eq!(config.bind_iface, None);
        assert_eq!(config.bind_ip, None);
    }

    #[test]
    fn normalize_log_config_drops_blank_dir_and_zero_max_files() {
        let mut config = LogConfig {
            level: "debug".to_string(),
            dir: Some(" ".to_string()),
            rotation: LogRotation::Hourly,
            max_files: 0,
        };

        normalize_log_config(&mut config);

        assert_eq!(config.dir, None);
        assert_eq!(config.max_files, LogConfig::default().max_files);
    }

    #[test]
    fn load_prefers_explicit_toml_networking_over_persisted_snapshot() {
        let temp_root = unique_test_dir("overlord-agent-emule-config-test");
        let state_dir = temp_root.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(
            state_dir.join(PERSISTED_NETWORKING_STATE_FILE),
            serde_json::to_vec_pretty(&AgentNetworkingConfig {
                control: AgentControlConfig {
                    bind_iface: Some("persisted-control".to_string()),
                    bind_ip: Some("10.0.0.10".to_string()),
                    selection_confirmed: false,
                    listen_port: 19_999,
                },
                p2p: AgentP2pConfig {
                    bind_iface: Some("persisted-p2p".to_string()),
                    bind_ip: Some("10.0.0.20".to_string()),
                    selection_confirmed: false,
                    kad: AgentKadConfig {
                        listen_port: 41_999,
                    },
                    ed2k: AgentEd2kConfig {
                        listen_port: 42_999,
                    },
                },
                nat: AgentNatConfig {
                    p2p: AgentNatP2pConfig {
                        enabled: false,
                        backend_order: vec![UPNP_RUPNP_BACKEND.to_string()],
                        igd_ip: Some("10.0.0.1".to_string()),
                        minissdpd_socket: Some("persisted.sock".to_string()),
                        ssdp_local_port: Some(1901),
                        discovery_timeout_secs: 15,
                        lease_duration_secs: 7200,
                        renew_margin_secs: 600,
                        external_ip_override: Some("203.0.113.10".to_string()),
                    },
                },
            })
            .unwrap(),
        )
        .unwrap();

        let config_path = temp_root.join("overlord.toml");
        fs::write(
            &config_path,
            format!(
                r#"
[agent]
state_dir = "{state_dir}"

[control]
bind_iface = "toml-control"
bind_ip = "127.0.0.1"
selection_confirmed = true
listen_port = 13301

[p2p]
bind_iface = "toml-p2p"
bind_ip = "127.0.0.1"
selection_confirmed = true

[p2p.kad]
listen_port = 41000

[p2p.ed2k]
listen_port = 41001

[p2p.ed2k.upload_queue]
active_slots = 2
waiting_capacity = 64
waiting_timeout_secs = 45
granted_timeout_secs = 12
upload_timeout_secs = 33

[nat.p2p]
enabled = true
backend_order = ["upnp_miniupnpc"]
discovery_timeout_secs = 5
lease_duration_secs = 3600
renew_margin_secs = 300
"#,
                state_dir = state_dir.display().to_string().replace('\\', "\\\\")
            ),
        )
        .unwrap();

        let config = EmuleAgentConfig::load(&config_path).unwrap();

        assert_eq!(config.control.bind_iface.as_deref(), Some("toml-control"));
        assert_eq!(config.control.bind_ip.as_deref(), Some("127.0.0.1"));
        assert!(config.control.selection_confirmed);
        assert_eq!(config.control.listen_port, 13_301);
        assert_eq!(config.p2p.bind_iface.as_deref(), Some("toml-p2p"));
        assert_eq!(config.p2p.bind_ip.as_deref(), Some("127.0.0.1"));
        assert!(config.p2p.selection_confirmed);
        assert_eq!(config.p2p.kad.listen_port, 41_000);
        assert_eq!(config.p2p.ed2k.listen_port, 41_001);
        assert_eq!(config.p2p.ed2k.upload_queue.active_slots, 2);
        assert_eq!(config.p2p.ed2k.upload_queue.waiting_capacity, 64);
        assert_eq!(config.p2p.ed2k.upload_queue.waiting_timeout_secs, 45);
        assert_eq!(config.p2p.ed2k.upload_queue.granted_timeout_secs, 12);
        assert_eq!(config.p2p.ed2k.upload_queue.upload_timeout_secs, 33);
        assert!(config.nat.p2p.enabled);
        assert_eq!(
            config.nat.p2p.backend_order,
            vec![UPNP_MINIUPNPC_BACKEND.to_string()]
        );

        fs::remove_dir_all(&temp_root).unwrap();
    }

    #[test]
    fn load_uses_persisted_networking_for_absent_sections() {
        let temp_root = unique_test_dir("overlord-agent-emule-config-test");
        let state_dir = temp_root.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(
            state_dir.join(PERSISTED_NETWORKING_STATE_FILE),
            serde_json::to_vec_pretty(&AgentNetworkingConfig {
                control: AgentControlConfig {
                    bind_iface: Some("persisted-control".to_string()),
                    bind_ip: Some("127.0.0.2".to_string()),
                    selection_confirmed: true,
                    listen_port: 14_001,
                },
                p2p: AgentP2pConfig {
                    bind_iface: Some("persisted-p2p".to_string()),
                    bind_ip: Some("127.0.0.3".to_string()),
                    selection_confirmed: true,
                    kad: AgentKadConfig {
                        listen_port: 44_100,
                    },
                    ed2k: AgentEd2kConfig {
                        listen_port: 44_101,
                    },
                },
                nat: AgentNatConfig {
                    p2p: AgentNatP2pConfig {
                        enabled: true,
                        backend_order: vec![UPNP_RUPNP_BACKEND.to_string()],
                        igd_ip: None,
                        minissdpd_socket: None,
                        ssdp_local_port: Some(1900),
                        discovery_timeout_secs: 5,
                        lease_duration_secs: 3600,
                        renew_margin_secs: 300,
                        external_ip_override: None,
                    },
                },
            })
            .unwrap(),
        )
        .unwrap();

        let config_path = temp_root.join("overlord.toml");
        fs::write(
            &config_path,
            format!(
                r#"
[agent]
state_dir = "{state_dir}"
"#,
                state_dir = state_dir.display().to_string().replace('\\', "\\\\")
            ),
        )
        .unwrap();

        let config = EmuleAgentConfig::load(&config_path).unwrap();

        assert_eq!(
            config.control.bind_iface.as_deref(),
            Some("persisted-control")
        );
        assert_eq!(config.control.bind_ip.as_deref(), Some("127.0.0.2"));
        assert!(config.control.selection_confirmed);
        assert_eq!(config.control.listen_port, 14_001);
        assert_eq!(config.p2p.bind_iface.as_deref(), Some("persisted-p2p"));
        assert_eq!(config.p2p.bind_ip.as_deref(), Some("127.0.0.3"));
        assert!(config.p2p.selection_confirmed);
        assert_eq!(config.p2p.kad.listen_port, 44_100);
        assert_eq!(config.p2p.ed2k.listen_port, 44_101);
        assert!(config.nat.p2p.enabled);
        assert_eq!(
            config.nat.p2p.backend_order,
            vec![UPNP_RUPNP_BACKEND.to_string()]
        );

        fs::remove_dir_all(&temp_root).unwrap();
    }

    #[test]
    fn coordinator_networking_keeps_locally_authoritative_sections() {
        let temp_root = unique_test_dir("overlord-agent-emule-config-authority");
        fs::create_dir_all(&temp_root).unwrap();
        let config_path = temp_root.join("overlord.toml");
        fs::write(
            &config_path,
            r#"
[control]
bind_ip = "127.0.0.10"
listen_port = 13310

[p2p]
bind_ip = "10.0.0.10"
selection_confirmed = true

[p2p.kad]
listen_port = 41120

[p2p.ed2k]
listen_port = 41121

[nat.p2p]
enabled = false
backend_order = []
discovery_timeout_secs = 5
lease_duration_secs = 3600
renew_margin_secs = 300
"#,
        )
        .unwrap();

        let config = EmuleAgentConfig::load(&config_path).unwrap();
        let effective = config.effective_coordinator_networking(&AgentNetworkingConfig {
            control: AgentControlConfig {
                bind_iface: Some("coordinator-control".to_string()),
                bind_ip: Some("127.0.0.20".to_string()),
                selection_confirmed: false,
                listen_port: 14000,
            },
            p2p: AgentP2pConfig {
                bind_iface: Some("coordinator-p2p".to_string()),
                bind_ip: Some("10.0.0.20".to_string()),
                selection_confirmed: false,
                kad: AgentKadConfig { listen_port: 42000 },
                ed2k: AgentEd2kConfig { listen_port: 42001 },
            },
            nat: AgentNatConfig {
                p2p: AgentNatP2pConfig {
                    enabled: true,
                    backend_order: vec![UPNP_RUPNP_BACKEND.to_string()],
                    igd_ip: Some("10.0.0.1".to_string()),
                    minissdpd_socket: Some("coordinator.sock".to_string()),
                    ssdp_local_port: Some(1901),
                    discovery_timeout_secs: 15,
                    lease_duration_secs: 7200,
                    renew_margin_secs: 600,
                    external_ip_override: Some("203.0.113.10".to_string()),
                },
            },
        });

        assert_eq!(effective.control.bind_ip.as_deref(), Some("127.0.0.10"));
        assert_eq!(effective.control.listen_port, 13310);
        assert_eq!(effective.p2p.bind_ip.as_deref(), Some("10.0.0.10"));
        assert!(effective.p2p.selection_confirmed);
        assert_eq!(effective.p2p.kad.listen_port, 41120);
        assert_eq!(effective.p2p.ed2k.listen_port, 41121);
        assert!(!effective.nat.p2p.enabled);
        assert_eq!(
            effective.nat.p2p.backend_order,
            default_upnp_backend_order()
        );

        fs::remove_dir_all(&temp_root).unwrap();
    }

    #[test]
    fn default_kad_config_enables_periodic_routing_refresh() {
        let config = EmuleAgentConfig::default();

        assert_eq!(config.p2p.kad.routing_refresh_interval_secs, 120);
        assert_eq!(config.p2p.kad.nodes_dat_refresh_interval_secs, 300);
        assert_eq!(config.p2p.kad.publish_contact_fanout, 20);
        assert!(config.p2p.kad.udp_firewall_check_enabled);
        assert_eq!(config.p2p.kad.udp_firewall_recheck_interval_secs, 300);
        assert_eq!(config.p2p.kad.udp_firewall_check_timeout_secs, 20);
        assert_eq!(config.p2p.kad.udp_firewall_check_contact_count, 2);
        assert!(config.p2p.kad.local_store_enabled);
        assert_eq!(config.p2p.kad.local_store_keyword_ttl_secs, 86_400);
        assert_eq!(config.p2p.kad.local_store_source_ttl_secs, 21_600);
        assert_eq!(config.p2p.kad.local_store_notes_ttl_secs, 86_400);
        assert_eq!(config.p2p.kad.local_store_keyword_capacity, 20_000);
        assert_eq!(config.p2p.kad.local_store_source_capacity, 20_000);
        assert_eq!(config.p2p.kad.local_store_notes_capacity, 5_000);
        assert!(!config.p2p.kad.seed_notes_publish_enabled);
    }

    #[test]
    fn default_snoop_queue_config_is_harvest_oriented() {
        let config = EmuleAgentConfig::default();

        assert_eq!(config.p2p.snoop_queue.general_max_queries_per_600s, 24);
        assert_eq!(config.p2p.snoop_queue.general_drain_cooldown_secs, 900);
        assert_eq!(config.p2p.snoop_queue.source_max_queries_per_600s, 60);
        assert_eq!(config.p2p.snoop_queue.source_drain_cooldown_secs, 300);
        assert_eq!(config.p2p.snoop_queue.source_stop_after_results, 2);
    }
}
