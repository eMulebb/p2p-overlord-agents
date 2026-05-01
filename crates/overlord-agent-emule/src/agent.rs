#[cfg(test)]
use std::future::Future;
#[cfg(test)]
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use md4::{Digest, Md4};
use overlord_agent_nat::{
    AgentNetworkReport, AgentNetworkingConfig, NatManager, ResolvedInterfaceBindingReport,
    detect_interfaces,
};
use serde_json::Value;
use tokio::{
    net::TcpListener,
    sync::{Mutex, Notify, RwLock, Semaphore},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

use overlord_agent_common::{
    AgentActivityState, ConfigUpdate, CoordinatorClient, IndexerService, IndexerStats,
    KadHarvestObservability, KadPublishObservability, KadRpcObservability,
    KadRpcResponseOpcodeObservability, KadRpcTrackerBucketObservability,
    KadRpcWorkClassObservability, PopularHash, Protocol, PublishSeedSource, RegisterRequest,
    RunningIndexerServer, SearchEventStatus, SearchJob, SearchKind, SnoopEntry, SnoopObservation,
};
use overlord_kad_dht::{DhtNode, RpcObservabilitySnapshot, RpcWorkClass};
use overlord_kad_proto::NodeId;

use crate::config::EmuleAgentConfig;
use crate::ed2k_server::{Ed2kFoundSource, Ed2kServerSearchHandle, Ed2kServerState};
#[cfg(test)]
use crate::ed2k_tcp::Ed2kHelloIdentity;
#[cfg(test)]
use crate::ed2k_tcp::Ed2kPeerDownloadOutcome;
use crate::ed2k_tcp::Ed2kSecureIdent;
use crate::ed2k_transfer::{Ed2kLocalIngestSummary, Ed2kSharedCatalog, Ed2kTransferRuntime};
use crate::kad_firewall::KadFirewallState;
use crate::kad_store::{KadLocalStore, KadLocalStoreConfig};
use crate::logging::current_log_file_status;
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
mod lifecycle;
mod networking;
mod p2p_runtime;
mod passive_replay;
mod passive_runtime;
mod publish;
mod publish_runtime;
mod search;
mod snoop;
#[cfg(test)]
mod test_support;

use self::activity::{
    ACTIVITY_KEY_RECONFIGURING, ACTIVITY_KEY_STARTING, AgentActivityTracker,
    active_ed2k_download_key, active_search_key, begin_agent_activity,
    clear_agent_degraded_activity, finish_agent_activity, new_activity_snapshot,
    publish_activity_key, record_agent_degraded_activity, runtime_activity_error,
    search_activity_context,
};
#[cfg(test)]
use self::ed2k_download::{NativeDirectDownloadOptions, NativeDirectDownloadOutcome};
use self::ed2k_enrich::{EnrichEd2kDownloadRequest, IngestLocalFileRequest};
use self::ed2k_runtime::manifest_has_ed2k_transfer_progress;
use self::ed2k_search::{
    ActiveEd2kSearchContext, do_active_ed2k_keyword_search, do_active_ed2k_source_search,
    exact_ed2k_hash_query_token,
};
use self::lifecycle::{AgentStatePaths, ensure_parent_dir, load_or_create_indexer_id};
use self::passive_replay::apply_queue_family_counts;
use self::publish::{
    SourcePublishSettings, effective_publish_counters, load_or_create_ed2k_user_hash,
    source_publish_client_hash,
};
use self::publish_runtime::{PublishExecutionContext, seed_popular_from_source};
use self::search::{
    SearchRunStats, do_active_keyword_search, do_active_notes_search, do_active_source_search,
    emit_search_event,
};
use self::snoop::{flush_snoop_queue, restore_snoop_queue};

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

async fn wait_for_shutdown_signal() -> Result<&'static str> {
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown};

        let mut ctrl_c_stream = ctrl_c().context("failed to install Ctrl+C handler")?;
        let mut ctrl_break_stream = ctrl_break().context("failed to install Ctrl+Break handler")?;
        let mut ctrl_close_stream =
            ctrl_close().context("failed to install console-close handler")?;
        let mut ctrl_shutdown_stream =
            ctrl_shutdown().context("failed to install console-shutdown handler")?;

        tokio::select! {
            _ = ctrl_c_stream.recv() => Ok("Ctrl+C"),
            _ = ctrl_break_stream.recv() => Ok("Ctrl+Break"),
            _ = ctrl_close_stream.recv() => Ok("ConsoleClose"),
            _ = ctrl_shutdown_stream.recv() => Ok("ConsoleShutdown"),
        }
    }

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigint =
            signal(SignalKind::interrupt()).context("failed to install SIGINT handler")?;
        let mut sigterm =
            signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;

        tokio::select! {
            _ = sigint.recv() => Ok("SIGINT"),
            _ = sigterm.recv() => Ok("SIGTERM"),
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed while waiting for Ctrl+C")?;
        Ok("Ctrl+C")
    }
}

fn map_rpc_observability(snapshot: RpcObservabilitySnapshot) -> KadRpcObservability {
    KadRpcObservability {
        decode_failures: snapshot.decode_failures,
        global_max_outbound_pps: snapshot.global_max_outbound_pps,
        tracker_buckets: snapshot
            .tracker_buckets
            .into_iter()
            .map(|bucket| KadRpcTrackerBucketObservability {
                bucket: bucket.bucket.to_string(),
                accepted_requests: bucket.accepted_requests,
                tracker_drops: bucket.tracker_drops,
                tracker_massive_drops: bucket.tracker_massive_drops,
            })
            .collect(),
        response_opcodes: snapshot
            .response_opcodes
            .into_iter()
            .map(|opcode| KadRpcResponseOpcodeObservability {
                opcode: opcode.opcode.to_string(),
                matched_pending: opcode.matched_pending,
                matched_tracked: opcode.matched_tracked,
                dropped_unrequested: opcode.dropped_unrequested,
                accepted_unsolicited: opcode.accepted_unsolicited,
            })
            .collect(),
        work_classes: snapshot
            .work_classes
            .into_iter()
            .map(|work_class| KadRpcWorkClassObservability {
                class: work_class.class.label().to_string(),
                max_outbound_pps: work_class.max_outbound_pps,
                sent_packets: work_class.sent_packets,
                delayed_packets: work_class.delayed_packets,
                total_wait_millis: work_class.total_wait_millis,
                last_sent_at: work_class.last_sent_at,
            })
            .collect(),
    }
}

#[derive(Clone)]
struct AgentNetworkRuntime {
    bind_ip: Ipv4Addr,
    dht: DhtNode,
    ed2k_listener: Arc<TcpListener>,
    ed2k_shared_catalog: Ed2kSharedCatalog,
    ed2k_transfer: Arc<Ed2kTransferRuntime>,
    ed2k_server_search: Ed2kServerSearchHandle,
    ed2k_server_search_inbox: Arc<Mutex<Option<crate::ed2k_server::Ed2kServerSearchInbox>>>,
    ed2k_server_state: Arc<RwLock<Ed2kServerState>>,
    ed2k_secure_ident: Arc<Ed2kSecureIdent>,
    nat: Arc<NatManager>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    shutdown: Arc<AtomicBool>,
    passive_result_count: Arc<std::sync::atomic::AtomicU64>,
    passive_replay_gate: Arc<Semaphore>,
}

struct ControlServerRuntime {
    bind_addr: SocketAddr,
    server: RunningIndexerServer,
}

#[derive(Clone)]
struct ActiveSearchHandle {
    cancel: CancellationToken,
}

pub struct OverlordAgentEmule {
    config: Arc<RwLock<EmuleAgentConfig>>,
    coordinator: CoordinatorClient,
    indexer_id: Uuid,
    ed2k_user_hash: [u8; 16],
    started_at: Instant,
    state_paths: AgentStatePaths,
    snoop_queue: Arc<Mutex<SnoopQueue>>,
    observed_snoop_events: Arc<Mutex<Vec<SnoopObservation>>>,
    local_store: Arc<Mutex<KadLocalStore>>,
    publish_batch_gate: Arc<Mutex<()>>,
    publish_observability: Arc<Mutex<KadPublishObservability>>,
    harvest_observability: Arc<Mutex<KadHarvestObservability>>,
    agent_activity: Arc<Mutex<AgentActivityTracker>>,
    runtime: Arc<Mutex<Option<AgentNetworkRuntime>>>,
    control_server: Arc<Mutex<Option<ControlServerRuntime>>>,
    control_selection_state: Arc<RwLock<ResolvedInterfaceBindingReport>>,
    p2p_selection_state: Arc<RwLock<ResolvedInterfaceBindingReport>>,
    active_searches: Arc<Mutex<HashMap<Uuid, ActiveSearchHandle>>>,
    active_ed2k_downloads: Arc<Mutex<HashSet<String>>>,
    ed2k_download_gate: Arc<Semaphore>,
    restart_requested: Arc<AtomicBool>,
    restart_notify: Arc<Notify>,
    started: AtomicBool,
}

pub enum AgentExit {
    Stopped,
    RestartRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkingConfigApplyOutcome {
    Unchanged,
    ReconciledInPlace,
    RestartRequired,
}

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

fn significant_keyword_words(query: &str) -> Vec<String> {
    let words: Vec<String> = query
        .split(|char: char| !char.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(|word| word.to_lowercase())
        .filter(|word| word.len() >= 3)
        .collect();
    if words.is_empty() {
        vec![query.to_lowercase()]
    } else {
        words
    }
}

fn keyword_target(query: &str) -> NodeId {
    let first_word = exact_ed2k_hash_query_token(query).unwrap_or_else(|| {
        significant_keyword_words(query)
            .into_iter()
            .next()
            .unwrap_or_else(|| query.to_lowercase())
    });
    let mut hasher = Md4::new();
    hasher.update(first_word.as_bytes());
    let digest: [u8; 16] = hasher.finalize().into();
    NodeId::from_be_bytes(digest)
}

#[async_trait]
impl IndexerService for OverlordAgentEmule {
    fn protocol(&self) -> Protocol {
        Protocol::Kad2
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn indexer_id(&self) -> Uuid {
        self.indexer_id
    }

    async fn start(&self) -> Result<()> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        restore_snoop_queue(&self.coordinator, self.indexer_id, &self.snoop_queue).await;
        self.reconcile_runtime().await?;
        finish_agent_activity(&self.agent_activity, ACTIVITY_KEY_STARTING, Utc::now()).await;
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.stop_runtime().await?;
        if let Err(error) = flush_snoop_queue(
            &self.coordinator,
            self.indexer_id,
            &self.snoop_queue,
            &self.observed_snoop_events,
        )
        .await
        {
            warn!("failed to flush snoop queue during shutdown: {error}");
        }
        Ok(())
    }

    async fn search(&self, job: SearchJob) -> Result<()> {
        self.reconcile_p2p_runtime_if_interface_moved().await?;
        let runtime = self.runtime.lock().await.clone();
        let Some(runtime) = runtime else {
            anyhow::bail!("agent networking is waiting for interface selection");
        };
        let dht = runtime.dht.clone();
        let bind_ip = runtime.bind_ip;
        let ed2k_user_hash = self.ed2k_user_hash;
        let ed2k_server_search = runtime.ed2k_server_search.clone();
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let ed2k_shared_catalog = runtime.ed2k_shared_catalog.read().await.clone();
        let indexer_id = self.indexer_id;
        let config = self.config.clone();
        let callback_client = CoordinatorClient::new(&job.callback_url)
            .with_context(|| format!("invalid search callback url for job {}", job.job_id))?;
        let active_searches = Arc::clone(&self.active_searches);
        let agent_activity = Arc::clone(&self.agent_activity);
        let cancel = CancellationToken::new();
        {
            let mut active = active_searches.lock().await;
            if active.contains_key(&job.job_id) {
                anyhow::bail!("search {} is already active", job.job_id);
            }
            active.insert(
                job.job_id,
                ActiveSearchHandle {
                    cancel: cancel.clone(),
                },
            );
        }
        tokio::spawn(async move {
            let activity_key = active_search_key(job.job_id);
            let activity_started_at = Utc::now();
            let mut activity_snapshot =
                new_activity_snapshot(AgentActivityState::ActiveSearch, activity_started_at);
            activity_snapshot.job_id = Some(job.job_id);
            activity_snapshot.protocol = Some(job.protocol);
            activity_snapshot.kind = Some(job.kind.clone());
            activity_snapshot.query_or_target = search_activity_context(&job);
            begin_agent_activity(
                &agent_activity,
                activity_key.clone(),
                activity_snapshot.clone(),
            )
            .await;
            let started_stats = SearchRunStats::default();
            if let Err(error) = emit_search_event(
                &callback_client,
                job.job_id,
                indexer_id,
                SearchEventStatus::Started,
                &started_stats,
                None,
            )
            .await
            {
                warn!("failed to report search start: {error}");
            }

            let config_snapshot = config.read().await.clone();
            let outcome = match (job.protocol, &job.kind) {
                (Protocol::Kad2, SearchKind::Keyword) => {
                    do_active_keyword_search(
                        &dht,
                        indexer_id,
                        &job,
                        config_snapshot.p2p.kad.enable_mock_results,
                        cancel.clone(),
                    )
                    .await
                }
                (Protocol::Kad2, SearchKind::Source) => {
                    do_active_source_search(&dht, indexer_id, &job, cancel.clone()).await
                }
                (Protocol::Kad2, SearchKind::Notes) => {
                    do_active_notes_search(&dht, indexer_id, &job, cancel.clone()).await
                }
                (Protocol::Ed2k, SearchKind::Keyword) => {
                    let (preferred_endpoint, background_search) = {
                        let server_state = ed2k_server_state.read().await;
                        if server_state.connected {
                            (server_state.endpoint, Some(ed2k_server_search.clone()))
                        } else {
                            (None, None)
                        }
                    };
                    do_active_ed2k_keyword_search(ActiveEd2kSearchContext {
                        bind_ip,
                        indexer_id,
                        ed2k_user_hash,
                        shared_catalog: &ed2k_shared_catalog,
                        job: &job,
                        config: &config_snapshot,
                        background_search,
                        preferred_endpoint,
                        cancel: cancel.clone(),
                    })
                    .await
                }
                (Protocol::Ed2k, SearchKind::Source) => {
                    let (preferred_endpoint, background_search) = {
                        let server_state = ed2k_server_state.read().await;
                        if server_state.connected {
                            (server_state.endpoint, Some(ed2k_server_search.clone()))
                        } else {
                            (None, None)
                        }
                    };
                    do_active_ed2k_source_search(ActiveEd2kSearchContext {
                        bind_ip,
                        indexer_id,
                        ed2k_user_hash,
                        shared_catalog: &ed2k_shared_catalog,
                        job: &job,
                        config: &config_snapshot,
                        background_search,
                        preferred_endpoint,
                        cancel: cancel.clone(),
                    })
                    .await
                }
                (Protocol::Ed2k, SearchKind::Notes) => {
                    Err(anyhow::anyhow!("ED2K notes search is not wired yet"))
                }
            };

            let final_event = match outcome {
                Ok(stats) if cancel.is_cancelled() => (SearchEventStatus::Cancelled, stats, None),
                Ok(stats) => (SearchEventStatus::Completed, stats, None),
                Err(_error) if cancel.is_cancelled() => (
                    SearchEventStatus::Cancelled,
                    SearchRunStats::default(),
                    None,
                ),
                Err(error) => (
                    SearchEventStatus::Failed,
                    SearchRunStats::default(),
                    Some(error.to_string()),
                ),
            };

            if let Err(error) = emit_search_event(
                &callback_client,
                job.job_id,
                indexer_id,
                final_event.0,
                &final_event.1,
                final_event.2.clone(),
            )
            .await
            {
                warn!("failed to report search completion: {error}");
            }

            finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
            if let Some(error) = final_event.2 {
                activity_snapshot.last_error = Some(error.to_string());
                activity_snapshot.last_update_at = Utc::now();
                record_agent_degraded_activity(&agent_activity, activity_snapshot).await;
            } else {
                clear_agent_degraded_activity(&agent_activity).await;
            }
            active_searches.lock().await.remove(&job.job_id);
        });
        Ok(())
    }

    async fn cancel_search(&self, job_id: Uuid) -> Result<()> {
        let Some(handle) = self.active_searches.lock().await.get(&job_id).cloned() else {
            anyhow::bail!("search {job_id} is not active");
        };
        handle.cancel.cancel();
        Ok(())
    }

    async fn stats(&self) -> Result<IndexerStats> {
        let queue = self.snoop_queue.lock().await;
        let queue_depth = queue.len() as u32;
        let queue_family_counts = queue.family_counts();
        drop(queue);
        let uptime_secs = self.started_at.elapsed().as_secs();
        let runtime = self.runtime.lock().await.clone();
        let crawl_rate = if uptime_secs == 0 {
            0.0
        } else {
            runtime
                .as_ref()
                .map(|runtime| runtime.passive_result_count.load(Ordering::Relaxed) as f32)
                .unwrap_or(0.0)
                / uptime_secs as f32
        };
        let config = self.config.read().await.clone();
        let interface_report = self.interface_report().await;
        let nat_status = match runtime.clone() {
            Some(runtime) => Some(runtime.nat.status().await.snapshot()),
            None => None,
        };
        let agent_activity = self.agent_activity.lock().await.current_snapshot(
            runtime_activity_error(&interface_report, nat_status.as_ref()),
            Utc::now(),
        );
        let mut publish_observability = self.publish_observability.lock().await.clone();
        publish_observability.keyword_counters = effective_publish_counters(
            &publish_observability.keyword_counters,
            publish_observability.latest_keyword_batch.as_ref(),
            publish_observability.last_seed_at,
        );
        publish_observability.source_counters = effective_publish_counters(
            &publish_observability.source_counters,
            publish_observability.latest_source_batch.as_ref(),
            publish_observability.last_seed_at,
        );
        publish_observability.notes_counters = effective_publish_counters(
            &publish_observability.notes_counters,
            publish_observability.latest_notes_batch.as_ref(),
            publish_observability.last_seed_at,
        );
        publish_observability.synthetic_drip_interval_secs =
            Some(config.p2p.kad.synthetic_publish_interval_secs);
        publish_observability.synthetic_drip_batch_items =
            Some(config.p2p.kad.synthetic_publish_batch_items as u32);
        publish_observability.log_file = Some(current_log_file_status(&config));
        let mut harvest_observability = self.harvest_observability.lock().await.clone();
        apply_queue_family_counts(&mut harvest_observability, queue_family_counts);
        let rpc_observability = runtime
            .as_ref()
            .map(|runtime| map_rpc_observability(runtime.dht.rpc_observability()));

        Ok(IndexerStats {
            indexer_id: self.indexer_id,
            protocol: Protocol::Kad2,
            peers_connected: runtime
                .as_ref()
                .map(|runtime| runtime.dht.routing_table_size() as u32)
                .unwrap_or(0),
            kad_bootstrapped: runtime
                .as_ref()
                .is_some_and(|runtime| runtime.dht.is_bootstrapped()),
            crawl_rate,
            snoop_queue_depth: queue_depth,
            staging_queue_depth: 0,
            uptime_secs,
            nat: nat_status,
            interface_report: Some(interface_report),
            agent_activity: Some(agent_activity),
            publish_observability: Some(publish_observability),
            harvest_observability: Some(harvest_observability),
            rpc_observability,
        })
    }

    async fn apply_config(&self, config: ConfigUpdate) -> Result<()> {
        let reconfigure_started_at = Utc::now();
        let mut reconfigure_snapshot =
            new_activity_snapshot(AgentActivityState::Reconfiguring, reconfigure_started_at);
        reconfigure_snapshot.protocol = Some(config.protocol);
        begin_agent_activity(
            &self.agent_activity,
            ACTIVITY_KEY_RECONFIGURING.to_string(),
            reconfigure_snapshot.clone(),
        )
        .await;
        let next: AgentNetworkingConfig = match serde_json::from_value(config.config) {
            Ok(next) => next,
            Err(error) => {
                let observed_at = Utc::now();
                finish_agent_activity(
                    &self.agent_activity,
                    ACTIVITY_KEY_RECONFIGURING,
                    observed_at,
                )
                .await;
                let mut degraded_snapshot =
                    new_activity_snapshot(AgentActivityState::Degraded, observed_at);
                degraded_snapshot.query_or_target = Some("config update".to_string());
                degraded_snapshot.last_error = Some(error.to_string());
                record_agent_degraded_activity(&self.agent_activity, degraded_snapshot).await;
                return Err(error).context("invalid config payload for overlord-agent-emule");
            }
        };
        // `/api/internal/config-update` requests restart only when the updated
        // networking shape changes the control endpoint; otherwise we reconcile
        // NAT/P2P runtime state in-process.
        let apply_result = self.apply_networking_config_update(&next).await;
        finish_agent_activity(&self.agent_activity, ACTIVITY_KEY_RECONFIGURING, Utc::now()).await;
        match apply_result {
            Ok(NetworkingConfigApplyOutcome::RestartRequired) => {
                self.request_restart();
                clear_agent_degraded_activity(&self.agent_activity).await;
                Ok(())
            }
            Ok(NetworkingConfigApplyOutcome::Unchanged)
            | Ok(NetworkingConfigApplyOutcome::ReconciledInPlace) => {
                clear_agent_degraded_activity(&self.agent_activity).await;
                Ok(())
            }
            Err(error) => {
                let mut degraded_snapshot =
                    new_activity_snapshot(AgentActivityState::Degraded, Utc::now());
                degraded_snapshot.query_or_target = Some("config update".to_string());
                degraded_snapshot.last_error = Some(error.to_string());
                record_agent_degraded_activity(&self.agent_activity, degraded_snapshot).await;
                Err(error)
            }
        }
    }

    async fn enrich(&self, payload: Value) -> Result<()> {
        let request: EnrichEd2kDownloadRequest = serde_json::from_value(payload)
            .context("invalid enrich payload for overlord-agent-emule")?;
        self.spawn_native_ed2k_download(request).await
    }

    async fn ingest_local_file(&self, payload: Value) -> Result<Value> {
        let request: IngestLocalFileRequest = serde_json::from_value(payload)
            .context("invalid local ingest payload for overlord-agent-emule")?;
        serde_json::to_value(self.ingest_local_file_impl(request).await?)
            .context("failed to encode local ingest response")
    }

    async fn seed_popular(&self, hashes: Vec<PopularHash>) -> Result<()> {
        self.reconcile_p2p_runtime_if_interface_moved().await?;
        let runtime = self.runtime.lock().await.clone();
        let Some(runtime) = runtime else {
            anyhow::bail!("agent networking is waiting for interface selection");
        };
        let source_publish_identity = source_publish_client_hash(self.ed2k_user_hash);
        let config = self.config.read().await;
        let source_publish_settings = SourcePublishSettings {
            tcp_port: config.p2p.ed2k.listen_port,
            obfuscation_enabled: config.p2p.ed2k.obfuscation_enabled,
        };
        let notes_publish_enabled = config.p2p.kad.seed_notes_publish_enabled;
        let publish_started_at = Utc::now();
        let activity_key = publish_activity_key(PublishSeedSource::ManualApi, publish_started_at);
        let mut activity_snapshot =
            new_activity_snapshot(AgentActivityState::Publishing, publish_started_at);
        activity_snapshot.query_or_target = Some(PublishSeedSource::ManualApi.label().to_string());
        activity_snapshot.progress_current = Some(0);
        activity_snapshot.progress_total = Some(hashes.len() as u32);
        begin_agent_activity(
            &self.agent_activity,
            activity_key.clone(),
            activity_snapshot,
        )
        .await;
        let seed_result = seed_popular_from_source(
            &runtime.dht,
            source_publish_identity,
            source_publish_settings,
            PublishSeedSource::ManualApi,
            hashes,
            &runtime.ed2k_shared_catalog,
            PublishExecutionContext {
                local_store: &self.local_store,
                publish_batch_gate: &self.publish_batch_gate,
                publish_observability: &self.publish_observability,
                agent_activity: &self.agent_activity,
                activity_key: Some(activity_key.as_str()),
                notes_publish_enabled,
                work_class: RpcWorkClass::Publish,
                publish_contact_fanout: config.p2p.kad.publish_contact_fanout,
            },
        )
        .await;
        finish_agent_activity(&self.agent_activity, &activity_key, Utc::now()).await;
        match seed_result {
            Ok(()) => {
                clear_agent_degraded_activity(&self.agent_activity).await;
                Ok(())
            }
            Err(error) => {
                let mut degraded_snapshot =
                    new_activity_snapshot(AgentActivityState::Degraded, Utc::now());
                degraded_snapshot.query_or_target =
                    Some(PublishSeedSource::ManualApi.label().to_string());
                degraded_snapshot.last_error = Some(error.to_string());
                record_agent_degraded_activity(&self.agent_activity, degraded_snapshot).await;
                Err(error)
            }
        }
    }

    async fn flush_snoop(&self) -> Result<Vec<SnoopEntry>> {
        Ok(self.snoop_queue.lock().await.snapshot())
    }

    async fn interfaces(&self) -> Result<AgentNetworkReport> {
        Ok(self.interface_report().await)
    }
}

impl OverlordAgentEmule {
    #[cfg(test)]
    /// Attempts direct-dial ED2K peer downloads until the transfer manifest
    /// completes or all discovered direct peers fail.
    ///
    /// The native download path keeps several peers in flight concurrently so a
    /// single dead or non-serving source does not block completion when another
    /// discovered peer can provide the file.
    async fn run_native_ed2k_direct_downloads<DownloadFn, DownloadFuture>(
        options: NativeDirectDownloadOptions,
        download_peer: DownloadFn,
    ) -> Result<NativeDirectDownloadOutcome>
    where
        DownloadFn: Fn(
                Ipv4Addr,
                Ed2kFoundSource,
                Ed2kHelloIdentity,
                Arc<Ed2kSecureIdent>,
                Arc<Ed2kTransferRuntime>,
                String,
                u64,
                Duration,
            ) -> DownloadFuture
            + Clone
            + Send
            + Sync
            + 'static,
        DownloadFuture: Future<Output = Result<Ed2kPeerDownloadOutcome>> + Send + 'static,
    {
        ed2k_download::run_native_ed2k_direct_downloads(options, download_peer).await
    }

    async fn spawn_native_ed2k_download(&self, request: EnrichEd2kDownloadRequest) -> Result<()> {
        if request.kind != "ed2k_download" {
            anyhow::bail!("unsupported enrich kind {}", request.kind);
        }

        self.reconcile_p2p_runtime_if_interface_moved().await?;
        let normalized_file_hash = request.file_hash.to_lowercase();
        {
            let mut active = self.active_ed2k_downloads.lock().await;
            if !active.insert(normalized_file_hash.clone()) {
                anyhow::bail!("ED2K download {normalized_file_hash} is already active");
            }
        }

        let runtime_handle = Arc::clone(&self.runtime);
        let config_handle = Arc::clone(&self.config);
        let agent_activity = Arc::clone(&self.agent_activity);
        let active_downloads = Arc::clone(&self.active_ed2k_downloads);
        let download_gate = Arc::clone(&self.ed2k_download_gate);
        let ed2k_user_hash = self.ed2k_user_hash;
        tokio::spawn(async move {
            let download_permit = match Arc::clone(&download_gate).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    info!(
                        "native ED2K download queued behind active limit file_hash={normalized_file_hash}"
                    );
                    match Arc::clone(&download_gate).acquire_owned().await {
                        Ok(permit) => permit,
                        Err(error) => {
                            let mut degraded_snapshot =
                                new_activity_snapshot(AgentActivityState::Degraded, Utc::now());
                            degraded_snapshot.query_or_target =
                                Some(format!("ED2K download {normalized_file_hash}"));
                            degraded_snapshot.last_error = Some(error.to_string());
                            record_agent_degraded_activity(&agent_activity, degraded_snapshot)
                                .await;
                            active_downloads.lock().await.remove(&normalized_file_hash);
                            return;
                        }
                    }
                }
            };
            let activity_key = active_ed2k_download_key(&normalized_file_hash);
            let started_at = Utc::now();
            let mut activity_snapshot =
                new_activity_snapshot(AgentActivityState::Downloading, started_at);
            activity_snapshot.protocol = Some(Protocol::Ed2k);
            let activity_name = request.canonical_name();
            activity_snapshot.query_or_target =
                Some(format!("{} ({})", activity_name, normalized_file_hash));
            begin_agent_activity(&agent_activity, activity_key.clone(), activity_snapshot).await;

            if let Some(runtime) = runtime_handle.lock().await.clone()
                && let Ok(manifest) = runtime.ed2k_transfer.manifest(&normalized_file_hash).await
            {
                let persisted_bytes = manifest
                    .pieces
                    .iter()
                    .map(|piece| piece.bytes_written)
                    .sum::<u64>();
                if manifest.completed {
                    info!(
                        "native ED2K download already completed file_hash={} bytes_written={} md4_hashset_acquired={}",
                        normalized_file_hash, persisted_bytes, manifest.md4_hashset_acquired
                    );
                    finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
                    clear_agent_degraded_activity(&agent_activity).await;
                    active_downloads.lock().await.remove(&normalized_file_hash);
                    drop(download_permit);
                    return;
                }
                if manifest_has_ed2k_transfer_progress(&manifest) {
                    info!(
                        "native ED2K download resuming persisted progress file_hash={} bytes_written={} md4_hashset_acquired={}",
                        normalized_file_hash, persisted_bytes, manifest.md4_hashset_acquired
                    );
                }
            }

            let outcome = ed2k_download::start_native_ed2k_download(
                runtime_handle,
                config_handle,
                ed2k_user_hash,
                request,
            )
            .await;
            finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
            match outcome {
                Ok(()) => {
                    clear_agent_degraded_activity(&agent_activity).await;
                }
                Err(error) => {
                    let mut degraded_snapshot =
                        new_activity_snapshot(AgentActivityState::Degraded, Utc::now());
                    degraded_snapshot.query_or_target =
                        Some(format!("ED2K download {normalized_file_hash}"));
                    degraded_snapshot.last_error = Some(error.to_string());
                    record_agent_degraded_activity(&agent_activity, degraded_snapshot).await;
                }
            }
            active_downloads.lock().await.remove(&normalized_file_hash);
            drop(download_permit);
        });
        Ok(())
    }

    async fn ingest_local_file_impl(
        &self,
        request: IngestLocalFileRequest,
    ) -> Result<Ed2kLocalIngestSummary> {
        let runtime = self.runtime.lock().await.clone();
        let Some(runtime) = runtime else {
            anyhow::bail!("agent networking is waiting for interface selection");
        };
        runtime
            .ed2k_transfer
            .ingest_local_file(Path::new(&request.source_path), &request.canonical_name()?)
            .await
    }
}

fn merge_download_sources(
    aggregated_sources: &mut Vec<Ed2kFoundSource>,
    new_sources: Vec<Ed2kFoundSource>,
) {
    for source in new_sources {
        if aggregated_sources.iter().any(|existing| {
            existing.ip == source.ip
                && existing.tcp_port == source.tcp_port
                && existing.obfuscation_options == source.obfuscation_options
                && existing.user_hash == source.user_hash
        }) {
            continue;
        }
        aggregated_sources.push(source);
    }
}

#[cfg(test)]
mod tests;
