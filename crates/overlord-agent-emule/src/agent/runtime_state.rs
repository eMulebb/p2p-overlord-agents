use crate::config::EmuleAgentConfig;
use crate::ed2k_server::{Ed2kServerSearchHandle, Ed2kServerState};
use crate::ed2k_tcp::Ed2kSecureIdent;
use crate::ed2k_transfer::{Ed2kSharedCatalog, Ed2kTransferRuntime};
use crate::kad_firewall::KadFirewallState;
use crate::kad_store::KadLocalStore;
use crate::snoop_queue::SnoopQueue;
use overlord_agent_common::{
    CoordinatorClient, KadHarvestObservability, KadPublishObservability, RunningIndexerServer,
    SnoopObservation,
};
use overlord_agent_nat::{NatManager, ResolvedInterfaceBindingReport};
use overlord_kad_dht::DhtNode;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::activity::AgentActivityTracker;
use super::lifecycle::AgentStatePaths;

#[derive(Clone)]
pub(super) struct AgentNetworkRuntime {
    pub(super) bind_ip: Ipv4Addr,
    pub(super) dht: DhtNode,
    pub(super) ed2k_listener: Arc<TcpListener>,
    pub(super) ed2k_shared_catalog: Ed2kSharedCatalog,
    pub(super) ed2k_transfer: Arc<Ed2kTransferRuntime>,
    pub(super) ed2k_server_search: Ed2kServerSearchHandle,
    pub(super) ed2k_server_search_inbox:
        Arc<Mutex<Option<crate::ed2k_server::Ed2kServerSearchInbox>>>,
    pub(super) ed2k_server_state: Arc<RwLock<Ed2kServerState>>,
    pub(super) ed2k_secure_ident: Arc<Ed2kSecureIdent>,
    pub(super) nat: Arc<NatManager>,
    pub(super) kad_firewall: Arc<Mutex<KadFirewallState>>,
    pub(super) tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    pub(super) shutdown: Arc<AtomicBool>,
    pub(super) passive_result_count: Arc<std::sync::atomic::AtomicU64>,
    pub(super) passive_replay_gate: Arc<Semaphore>,
}

pub(super) struct ControlServerRuntime {
    pub(super) bind_addr: SocketAddr,
    pub(super) server: RunningIndexerServer,
}

#[derive(Clone)]
pub(super) struct ActiveSearchHandle {
    pub(super) cancel: CancellationToken,
}

pub struct OverlordAgentEmule {
    pub(super) config: Arc<RwLock<EmuleAgentConfig>>,
    pub(super) coordinator: CoordinatorClient,
    pub(super) indexer_id: Uuid,
    pub(super) ed2k_user_hash: [u8; 16],
    pub(super) started_at: Instant,
    pub(super) state_paths: AgentStatePaths,
    pub(super) snoop_queue: Arc<Mutex<SnoopQueue>>,
    pub(super) observed_snoop_events: Arc<Mutex<Vec<SnoopObservation>>>,
    pub(super) local_store: Arc<Mutex<KadLocalStore>>,
    pub(super) publish_batch_gate: Arc<Mutex<()>>,
    pub(super) publish_observability: Arc<Mutex<KadPublishObservability>>,
    pub(super) harvest_observability: Arc<Mutex<KadHarvestObservability>>,
    pub(super) agent_activity: Arc<Mutex<AgentActivityTracker>>,
    pub(super) runtime: Arc<Mutex<Option<AgentNetworkRuntime>>>,
    pub(super) control_server: Arc<Mutex<Option<ControlServerRuntime>>>,
    pub(super) control_selection_state: Arc<RwLock<ResolvedInterfaceBindingReport>>,
    pub(super) p2p_selection_state: Arc<RwLock<ResolvedInterfaceBindingReport>>,
    pub(super) active_searches: Arc<Mutex<HashMap<Uuid, ActiveSearchHandle>>>,
    pub(super) active_ed2k_downloads: Arc<Mutex<HashSet<String>>>,
    pub(super) ed2k_download_gate: Arc<Semaphore>,
    pub(super) restart_requested: Arc<AtomicBool>,
    pub(super) restart_notify: Arc<Notify>,
    pub(super) started: AtomicBool,
}

pub enum AgentExit {
    Stopped,
    RestartRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkingConfigApplyOutcome {
    Unchanged,
    ReconciledInPlace,
    RestartRequired,
}
