use std::{
    collections::{HashMap, HashSet},
    fs,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use anyhow::{Context, Result};
use chrono::Utc;
use overlord_agent_nat::detect_interfaces;
use tokio::sync::{Mutex, Notify, RwLock, Semaphore};
use tracing::{info, warn};

use overlord_agent_common::{
    CoordinatorClient, IndexerService, KadHarvestObservability, KadPublishObservability, Protocol,
    RegisterRequest,
};

use crate::config::EmuleAgentConfig;
use crate::kad_store::{KadLocalStore, KadLocalStoreConfig};
use crate::snoop_queue::SnoopQueue;

mod activity;
mod background_ed2k;
mod background_firewall;
mod background_kad;
mod background_passive;
mod background_publish;
mod background_routing;
mod background_snoop;
mod background_tasks;
mod control_runtime;
mod ed2k_download;
mod ed2k_enrich;
mod ed2k_runtime;
mod ed2k_search;
mod kad_firewall_runtime;
mod kad_runtime;
mod kad_unsolicited;
mod keyword;
mod lifecycle;
mod networking;
mod p2p_runtime;
mod passive_replay;
mod passive_runtime;
mod publish;
mod publish_runtime;
mod rpc_observability;
mod runtime_state;
mod search;
mod service;
mod signals;
mod snoop;
mod source_merge;
#[cfg(test)]
mod test_support;

use self::activity::AgentActivityTracker;
use self::keyword::keyword_target;
#[cfg(test)]
use self::keyword::significant_keyword_words;
use self::lifecycle::{AgentStatePaths, ensure_parent_dir, load_or_create_indexer_id};
use self::publish::load_or_create_ed2k_user_hash;
pub use self::runtime_state::{AgentExit, OverlordAgentEmule};
use self::runtime_state::{
    AgentNetworkRuntime, ControlServerRuntime, NetworkingConfigApplyOutcome,
};
use self::signals::wait_for_shutdown_signal;
use self::source_merge::merge_download_sources;

const ACTIVE_BATCH_SIZE: usize = 25;
/// Large passive harvest floods should be posted in bigger coordinator batches
/// than user-facing active searches. This reduces local callback overhead
/// without changing any Kad outbound behavior.
const PASSIVE_BATCH_SIZE: usize = 200;
/// Large keyword floods should not wait for a completely full batch before the
/// coordinator sees progress. A short timer keeps partial batches moving.
const PASSIVE_BATCH_FLUSH_INTERVAL_MS: u64 = 300;
/// Passive harvest should keep ingesting inbound Kad results while coordinator
/// callbacks are in flight, but the local queue must stay bounded so the agent
/// remains polite on memory usage even during large floods.
const PASSIVE_POST_QUEUE_DEPTH: usize = 16;
const BOOTSTRAP_RETRY_SECS: u64 = 30;
#[cfg(not(test))]
const COORDINATOR_RECONNECT_SECS: u64 = 30;
#[cfg(test)]
const COORDINATOR_RECONNECT_SECS: u64 = 1;
const SNOOP_FLUSH_SECS: u64 = 30;
const PASSIVE_GENERAL_CRAWL_SECS: u64 = 45;
const PASSIVE_SOURCE_CRAWL_SECS: u64 = 15;
const PASSIVE_REPLAY_CONCURRENCY: usize = 2;
const PASSIVE_KEYWORD_THIN_RESULT_THRESHOLD: usize = 10;
const PASSIVE_SOURCE_THIN_RESULT_THRESHOLD: usize = 3;
const PASSIVE_NOTES_THIN_RESULT_THRESHOLD: usize = 3;
const KAD_EXTERNAL_PORT_DISCOVERY_MAX_ATTEMPTS: usize = 8;
const KAD_EXTERNAL_PORT_DISCOVERY_QUERY_TIMEOUT_SECS: u64 = 3;
const UDP_FIREWALL_HELPER_CANDIDATE_MULTIPLIER: usize = 4;
const EMULE_LARGE_FILE_SIZE_THRESHOLD: u64 = u32::MAX as u64;
const LOCAL_SEARCH_RESPONSE_LIMIT: usize = 64;
const FIREWALLED_TCP_PROBE_TIMEOUT_SECS: u64 = 5;
const KAD_FIREWALLED_RESPONSE_TIMEOUT_SECS: u64 = 10;
const ED2K_ACTIVE_SEARCH_MAX_SERVER_ATTEMPTS: usize = 3;
const ED2K_BACKGROUND_SEARCH_QUEUE_CAPACITY: usize = 4;
const ED2K_DOWNLOAD_KAD_SOURCE_CAP: usize = 64;
const ED2K_DOWNLOAD_KAD_SOURCE_TIMEOUT_FLOOR_SECS: u64 = 45;
const ED2K_DOWNLOAD_KAD_SOURCE_RETRY_DELAY_MS: u64 = 500;
const ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS: usize = 2;
const ED2K_DOWNLOAD_SOURCE_REQUERY_DELAY_SECS: u64 = 5;
const ED2K_SOURCE_OBFUSCATION_REQUIRES_CRYPT: u8 = 0x04;
const ED2K_HASH_ONLY_QUERY_PREFIX: &str = "ed2k::";

impl OverlordAgentEmule {
    pub async fn new(config: EmuleAgentConfig) -> Result<Self> {
        let indexer_id = load_or_create_indexer_id(&config.agent.indexer_id_path)?;
        let coordinator = CoordinatorClient::new(&config.coordinator.url)?;
        let state_paths = AgentStatePaths::from_config(&config);
        ensure_parent_dir(&state_paths.node_id_path)?;
        ensure_parent_dir(&state_paths.udp_key_path)?;
        ensure_parent_dir(&state_paths.ed2k_user_hash_path)?;
        ensure_parent_dir(&state_paths.ed2k_secure_ident_path)?;
        fs::create_dir_all(&state_paths.ed2k_transfer_root).with_context(|| {
            format!(
                "failed to create ED2K transfer root {}",
                state_paths.ed2k_transfer_root.display()
            )
        })?;
        ensure_parent_dir(&state_paths.nodes_dat_path)?;
        ensure_parent_dir(&state_paths.networking_config_path)?;
        let ed2k_user_hash = load_or_create_ed2k_user_hash(&state_paths.ed2k_user_hash_path)?;
        let interfaces = detect_interfaces().unwrap_or_default();
        let control_selection_state =
            Self::resolve_control_selection_state(&config, &interfaces, None, false, false);
        let p2p_selection_state =
            Self::resolve_p2p_selection_state(&config, &interfaces, None, false, false);
        let snoop_queue_config = config.p2p.snoop_queue.clone();
        let local_store = KadLocalStore::new(KadLocalStoreConfig::from_kad_config(&config.p2p.kad));
        let ed2k_download_gate = Arc::new(Semaphore::new(
            config.p2p.ed2k.max_concurrent_downloads.max(1),
        ));
        let activity_started_at = Utc::now();

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            coordinator,
            indexer_id,
            ed2k_user_hash,
            started_at: Instant::now(),
            state_paths,
            snoop_queue: Arc::new(Mutex::new(SnoopQueue::new(snoop_queue_config))),
            observed_snoop_events: Arc::new(Mutex::new(Vec::new())),
            local_store: Arc::new(Mutex::new(local_store)),
            publish_batch_gate: Arc::new(Mutex::new(())),
            publish_observability: Arc::new(Mutex::new(KadPublishObservability::default())),
            harvest_observability: Arc::new(Mutex::new(KadHarvestObservability::default())),
            agent_activity: Arc::new(Mutex::new(AgentActivityTracker::new(activity_started_at))),
            runtime: Arc::new(Mutex::new(None)),
            control_server: Arc::new(Mutex::new(None)),
            control_selection_state: Arc::new(RwLock::new(control_selection_state)),
            p2p_selection_state: Arc::new(RwLock::new(p2p_selection_state)),
            active_searches: Arc::new(Mutex::new(HashMap::new())),
            active_ed2k_downloads: Arc::new(Mutex::new(HashSet::new())),
            ed2k_download_gate,
            restart_requested: Arc::new(AtomicBool::new(false)),
            restart_notify: Arc::new(Notify::new()),
            started: AtomicBool::new(false),
        })
    }

    pub async fn register_with_coordinator(&self) -> Result<()> {
        let config = self.config.read().await.clone();
        let url = self.current_registration_url(&config).await?;
        let registration = self
            .coordinator
            .register(&RegisterRequest {
                indexer_id: self.indexer_id,
                protocol: Protocol::Kad2,
                url,
                hostname: config.agent.hostname,
                version: config.agent.version,
            })
            .await?;
        info!(
            "registered agent {} at {}",
            registration.indexer_id, registration.url
        );
        Ok(())
    }

    pub async fn serve(self: Arc<Self>) -> Result<AgentExit> {
        let config = self.config.read().await.clone();
        let bind_addr = Self::startup_control_bind_addr(&config)?;
        self.start_control_server_with_retry(bind_addr).await?;
        // Startup sync can immediately request a process restart when the
        // coordinator-sourced networking config changes the control endpoint.
        // Later restart requests are deferred through `restart_notify` (for
        // reconnect/config-update flows) so serve() can stop cleanly first.
        let reconnect_task = match self.connect_to_coordinator().await {
            Ok(NetworkingConfigApplyOutcome::RestartRequired) => {
                self.stop().await?;
                self.stop_control_server().await?;
                return Ok(AgentExit::RestartRequested);
            }
            Ok(NetworkingConfigApplyOutcome::Unchanged)
            | Ok(NetworkingConfigApplyOutcome::ReconciledInPlace) => None,
            Err(error) => {
                warn!(
                    "coordinator unavailable during startup; continuing with local config: {error}"
                );
                Some(Arc::clone(&self).spawn_coordinator_reconnect_task())
            }
        };

        tokio::select! {
            shutdown_signal = wait_for_shutdown_signal() => {
                info!("shutdown signal received: {}", shutdown_signal?);
            }
            _ = self.restart_notify.notified() => {}
        }
        if let Some(task) = reconnect_task {
            task.abort();
            let _ = task.await;
        }
        self.stop().await?;
        self.stop_control_server().await?;
        Ok(if self.restart_requested.load(Ordering::SeqCst) {
            AgentExit::RestartRequested
        } else {
            AgentExit::Stopped
        })
    }
}

#[cfg(test)]
mod tests;
