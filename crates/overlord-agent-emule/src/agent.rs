use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use md4::{Digest, Md4};
use overlord_agent_nat::{
    AgentControlConfig, AgentEd2kConfig, AgentInterface, AgentKadConfig, AgentNatConfig,
    AgentNatP2pConfig, AgentNetworkReport, AgentNetworkingConfig, AgentP2pConfig,
    InterfaceBindingSelection, InterfaceSelectionState, MappingExposure, MappingSpec,
    NatCapableAgent, NatManager, NatManagerBuilder, ResolvedInterfaceBindingReport,
    TransportProtocol, build_interface_binding_report, built_in_upnp_port_mapping_providers,
    default_upnp_backend_order, detect_interfaces, recommend_interface, resolve_bind_ip,
};
use tokio::{
    sync::{Mutex, Notify, RwLock},
    task::JoinHandle,
};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use uuid::Uuid;

use overlord_agent_common::{
    AgentInterfacesView, ConfigUpdate, ContentType, CoordinatorClient, FileRecord, HashType,
    IndexerServer, IndexerService, IndexerStats, KadHarvestFamilyObservability,
    KadHarvestObservability, KadPublishObservability, PopularHash, Protocol, PublishBatchSummary,
    PublishCounters, PublishSeedSource, RegisterRequest, ResultBatch, RunningIndexerServer,
    SearchEvent, SearchEventStatus, SearchJob, SearchKind, SnoopEntry, Source, TagEntry,
};
use overlord_kad_dht::{
    DhtConfig, DhtNode, PublishAttemptStats, SearchResult, SourceResult,
    bootstrap::{BootstrapContact, encode_nodes_dat},
};
use overlord_kad_proto::{
    Ed2kHash, KadPacket, KadUdpKey, NodeId, SearchKeyReq, SearchNotesReq, SearchSourceReq, Tag,
    TagName, TagValue, constants::K, packet::ContactEntry, tag_name,
};
use overlord_kad_routing::Contact;

use crate::config::EmuleAgentConfig;
use crate::logging::current_log_file_status;
use crate::snoop_queue::{SnoopQueue, SnoopQueueFamilyCounts};

const ACTIVE_BATCH_SIZE: usize = 25;
const PASSIVE_BATCH_SIZE: usize = 50;
const BOOTSTRAP_RETRY_SECS: u64 = 30;
#[cfg(not(test))]
const COORDINATOR_RECONNECT_SECS: u64 = 30;
#[cfg(test)]
const COORDINATOR_RECONNECT_SECS: u64 = 1;
const SNOOP_FLUSH_SECS: u64 = 30;
const PASSIVE_CRAWL_SECS: u64 = 45;
const EMULE_LARGE_FILE_SIZE_THRESHOLD: u64 = u32::MAX as u64;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyntheticPopularSeed {
    title: &'static str,
    size: u64,
    source_count: u32,
}

const SYNTHETIC_POPULAR_SEEDS: [SyntheticPopularSeed; 40] = [
    SyntheticPopularSeed {
        title: "ubuntu linux 24.04 desktop amd64.iso",
        size: 734_003_200,
        source_count: 31,
    },
    SyntheticPopularSeed {
        title: "mario paint quorlith orchestra live at the moon.avi",
        size: 1_417_965_568,
        source_count: 24,
    },
    SyntheticPopularSeed {
        title: "10 hours of nyan cat.mp4",
        size: 92_381_184,
        source_count: 19,
    },
    SyntheticPopularSeed {
        title: "laser dolphin documentary 1997.mkv",
        size: 2_486_124_544,
        source_count: 16,
    },
    SyntheticPopularSeed {
        title: "cat-powered data center walkthrough.iso",
        size: 4_597_211_136,
        source_count: 11,
    },
    SyntheticPopularSeed {
        title: "unofficial windows 98 vaporwave patch.zip",
        size: 803_471_360,
        source_count: 27,
    },
    SyntheticPopularSeed {
        title: "beep test but every beep is a fax machine.flac",
        size: 558_366_720,
        source_count: 14,
    },
    SyntheticPopularSeed {
        title: "office 2010 professional plus x86.iso",
        size: 128_661_504,
        source_count: 22,
    },
    SyntheticPopularSeed {
        title: "retro hamster workstation benchmark.mov",
        size: 1_934_155_776,
        source_count: 17,
    },
    SyntheticPopularSeed {
        title: "flying toaster championship finals.mp4",
        size: 1_215_102_976,
        source_count: 29,
    },
    SyntheticPopularSeed {
        title: "synthwave aquarium screensaver collection.rar",
        size: 677_478_400,
        source_count: 13,
    },
    SyntheticPopularSeed {
        title: "ubuntu linux server 24.04 live amd64.iso",
        size: 18_456_321,
        source_count: 18,
    },
    SyntheticPopularSeed {
        title: "very long train horn ambience.wav",
        size: 2_812_747_776,
        source_count: 12,
    },
    SyntheticPopularSeed {
        title: "adobe photoshop cs6 portable.rar",
        size: 943_128_576,
        source_count: 15,
    },
    SyntheticPopularSeed {
        title: "windows 7 ultimate sp1 x64 dvd.iso",
        size: 421_388_288,
        source_count: 9,
    },
    SyntheticPopularSeed {
        title: "museum of broken gamepads.pdf",
        size: 67_210_240,
        source_count: 21,
    },
    SyntheticPopularSeed {
        title: "game of thrones season 1 complete 720p.mkv",
        size: 44_992_610,
        source_count: 10,
    },
    SyntheticPopularSeed {
        title: "the office us season 2 dvdrip xvid.avi",
        size: 134_742_016,
        source_count: 8,
    },
    SyntheticPopularSeed {
        title: "midnight subway cat rave.mkv",
        size: 3_288_334_336,
        source_count: 26,
    },
    SyntheticPopularSeed {
        title: "top 100 dance hits 2009.mp3",
        size: 77_414_400,
        source_count: 23,
    },
    SyntheticPopularSeed {
        title: "vhs rip of the internet weather channel.ts",
        size: 5_188_911_104,
        source_count: 14,
    },
    SyntheticPopularSeed {
        title: "ubuntu linux 22.04 desktop amd64.iso",
        size: 1_104_199_680,
        source_count: 28,
    },
    SyntheticPopularSeed {
        title: "the lord of the rings extended trilogy 1080p.mkv",
        size: 612_892_672,
        source_count: 20,
    },
    SyntheticPopularSeed {
        title: "microsoft office 2007 enterprise.iso",
        size: 695_205_888,
        source_count: 17,
    },
    SyntheticPopularSeed {
        title: "grand theft auto vice city full rip.iso",
        size: 1_544_269_824,
        source_count: 12,
    },
    SyntheticPopularSeed {
        title: "breaking bad season 3 complete 720p.mkv",
        size: 88_199_168,
        source_count: 25,
    },
    SyntheticPopularSeed {
        title: "ubuntu linux 20.04.6 live server amd64.iso",
        size: 3_964_108_800,
        source_count: 16,
    },
    SyntheticPopularSeed {
        title: "top gear complete specials collection x264.mp4",
        size: 233_308_160,
        source_count: 13,
    },
    SyntheticPopularSeed {
        title: "the beatles abbey road remastered.flac",
        size: 1_572_864,
        source_count: 7,
    },
    SyntheticPopularSeed {
        title: "harry potter complete 1080p bluray x264.mkv",
        size: 376_877_056,
        source_count: 11,
    },
    SyntheticPopularSeed {
        title: "visual studio 2010 professional.iso",
        size: 190_513_152,
        source_count: 9,
    },
    SyntheticPopularSeed {
        title: "ubuntu linux 18.04 desktop amd64.iso",
        size: 1_672_331_264,
        source_count: 18,
    },
    SyntheticPopularSeed {
        title: "pink floyd the wall remastered.flac",
        size: 49_283_072,
        source_count: 15,
    },
    SyntheticPopularSeed {
        title: "friends complete season 5 dvdrip xvid.avi",
        size: 2_965_983_232,
        source_count: 19,
    },
    SyntheticPopularSeed {
        title: "ubuntu linux handbook 2026.pdf",
        size: 821_051_392,
        source_count: 24,
    },
    SyntheticPopularSeed {
        title: "windows xp professional sp3 corporate.iso",
        size: 1_281_286_144,
        source_count: 17,
    },
    SyntheticPopularSeed {
        title: "portable rave lighthouse screensaver.scr",
        size: 28_311_552,
        source_count: 12,
    },
    SyntheticPopularSeed {
        title: "greatest floppy disk solos anthology.flac",
        size: 607_518_720,
        source_count: 20,
    },
    SyntheticPopularSeed {
        title: "galactic sandwich emulator setup.exe",
        size: 509_607_936,
        source_count: 14,
    },
    SyntheticPopularSeed {
        title: "vintage webcam ghost sightings collection.mkv",
        size: 2_118_541_312,
        source_count: 22,
    },
];

fn build_publish_batch_summary(
    seed_source: PublishSeedSource,
    published_items: usize,
    stats: PublishAttemptStats,
    completed_at: DateTime<Utc>,
) -> PublishBatchSummary {
    PublishBatchSummary {
        seed_source,
        published_items: published_items as u32,
        closest_contacts_considered: stats.closest_contacts_considered,
        attempted_contacts: stats.attempted_contacts,
        acked_contacts: stats.acked_contacts,
        failed_contacts: stats.failed_contacts(),
        timed_out_contacts: stats.timed_out_contacts,
        completed_at,
        last_success_at: (stats.acked_contacts > 0).then_some(completed_at),
    }
}

fn apply_publish_summary(counters: &mut PublishCounters, summary: &PublishBatchSummary) {
    counters.batches += 1;
    counters.published_items += u64::from(summary.published_items);
    counters.closest_contacts_considered += u64::from(summary.closest_contacts_considered);
    counters.attempted_contacts += u64::from(summary.attempted_contacts);
    counters.acked_contacts += u64::from(summary.acked_contacts);
    counters.failed_contacts += u64::from(summary.failed_contacts);
    counters.timed_out_contacts += u64::from(summary.timed_out_contacts);
    counters.last_batch_at = Some(summary.completed_at);
    if summary.last_success_at.is_some() {
        counters.last_success_at = summary.last_success_at;
    }
}

fn log_publish_summary(family: &str, summary: &PublishBatchSummary) {
    let other_failures = summary
        .failed_contacts
        .saturating_sub(summary.timed_out_contacts);
    info!(
        "kad publish family={} seed_source={} items={} closest={} attempted={} acked={} failed={} timed_out={} other_failures={}",
        family,
        summary.seed_source.label(),
        summary.published_items,
        summary.closest_contacts_considered,
        summary.attempted_contacts,
        summary.acked_contacts,
        summary.failed_contacts,
        summary.timed_out_contacts,
        other_failures
    );
}

async fn record_publish_summaries(
    publish_observability: &Arc<Mutex<KadPublishObservability>>,
    seed_source: PublishSeedSource,
    published_items: usize,
    keyword_stats: PublishAttemptStats,
    source_stats: PublishAttemptStats,
    completed_at: DateTime<Utc>,
) {
    let keyword_summary =
        build_publish_batch_summary(seed_source, published_items, keyword_stats, completed_at);
    let source_summary =
        build_publish_batch_summary(seed_source, published_items, source_stats, completed_at);

    log_publish_summary("keyword", &keyword_summary);
    log_publish_summary("source", &source_summary);

    let mut observability = publish_observability.lock().await;
    observability.last_seed_source = Some(seed_source);
    observability.last_seed_at = Some(completed_at);
    observability.latest_keyword_batch = Some(keyword_summary.clone());
    observability.latest_source_batch = Some(source_summary.clone());
    apply_publish_summary(&mut observability.keyword_counters, &keyword_summary);
    apply_publish_summary(&mut observability.source_counters, &source_summary);
}

/// Refreshes the live publish snapshot while a long seed batch is still running.
///
/// The cumulative counters are only committed once the whole batch completes, but
/// the latest batch snapshots are updated continuously so operators can tell that
/// startup seeding is still making progress.
async fn update_publish_progress(
    publish_observability: &Arc<Mutex<KadPublishObservability>>,
    seed_source: PublishSeedSource,
    processed_items: usize,
    keyword_stats: PublishAttemptStats,
    source_stats: PublishAttemptStats,
    observed_at: DateTime<Utc>,
) {
    let mut observability = publish_observability.lock().await;
    observability.last_seed_source = Some(seed_source);
    observability.last_seed_at = Some(observed_at);
    observability.latest_keyword_batch = Some(build_publish_batch_summary(
        seed_source,
        processed_items,
        keyword_stats,
        observed_at,
    ));
    observability.latest_source_batch = Some(build_publish_batch_summary(
        seed_source,
        processed_items,
        source_stats,
        observed_at,
    ));
}

fn harvest_family_mut<'a>(
    observability: &'a mut KadHarvestObservability,
    entry: &SnoopEntry,
) -> &'a mut KadHarvestFamilyObservability {
    match entry {
        SnoopEntry::Keyword { .. } => &mut observability.keyword_requests,
        SnoopEntry::Source { .. } => &mut observability.source_requests,
        SnoopEntry::Notes { .. } => &mut observability.notes_requests,
    }
}

fn apply_harvest_record(
    observability: &mut KadHarvestObservability,
    from: SocketAddr,
    entry: &SnoopEntry,
    is_new: bool,
) {
    let family = harvest_family_mut(observability, entry);
    family.observed_requests += 1;
    if is_new {
        family.unique_shapes_observed += 1;
    }
    family.last_seen_at = Some(entry.last_seen());
    family.last_from = Some(from.to_string());
    family.last_target = Some(entry.target().to_string());
    match entry {
        SnoopEntry::Keyword {
            start_position,
            restrictive_payload_hex,
            ..
        } => {
            family.last_start_position = Some(*start_position);
            family.last_size = None;
            family.last_restrictive_bytes = Some(
                restrictive_payload_hex
                    .as_ref()
                    .map(|payload| payload.len() / 2)
                    .unwrap_or(0) as u32,
            );
        }
        SnoopEntry::Source {
            start_position,
            size,
            ..
        } => {
            family.last_start_position = Some(*start_position);
            family.last_size = Some(*size);
            family.last_restrictive_bytes = None;
        }
        SnoopEntry::Notes { size, .. } => {
            family.last_start_position = None;
            family.last_size = Some(*size);
            family.last_restrictive_bytes = None;
        }
    }
}

fn apply_queue_family_counts(
    observability: &mut KadHarvestObservability,
    counts: SnoopQueueFamilyCounts,
) {
    observability.keyword_requests.queued_entries = counts.keyword as u32;
    observability.source_requests.queued_entries = counts.source as u32;
    observability.notes_requests.queued_entries = counts.notes as u32;
}

fn record_passive_keyword_replay_idle(
    observability: &mut KadHarvestObservability,
    observed_at: DateTime<Utc>,
) {
    let replay = &mut observability.passive_keyword_replay;
    replay.idle_cycles += 1;
    replay.last_idle_at = Some(observed_at);
}

fn record_passive_keyword_replay_start(
    observability: &mut KadHarvestObservability,
    request: &SearchKeyReq,
    started_at: DateTime<Utc>,
) {
    let replay = &mut observability.passive_keyword_replay;
    replay.started_cycles += 1;
    replay.last_started_at = Some(started_at);
    replay.last_target = Some(request.target.to_string());
    replay.last_start_position = Some(request.start_position);
    replay.last_restrictive_bytes = Some(request.restrictive_payload.len() as u32);
    replay.last_error = None;
    replay.last_error_at = None;
}

fn record_passive_keyword_replay_complete(
    observability: &mut KadHarvestObservability,
    completed_at: DateTime<Utc>,
    replayed_results: usize,
    batches_posted: usize,
) {
    let replay = &mut observability.passive_keyword_replay;
    replay.completed_cycles += 1;
    replay.emitted_results += replayed_results as u64;
    replay.posted_batches += batches_posted as u64;
    replay.last_completed_at = Some(completed_at);
    replay.last_result_count = replayed_results as u32;
    replay.last_batches_posted = batches_posted as u32;
}

fn record_passive_keyword_post_failure(
    observability: &mut KadHarvestObservability,
    observed_at: DateTime<Utc>,
    error: &str,
) {
    let replay = &mut observability.passive_keyword_replay;
    replay.post_failures += 1;
    replay.last_error_at = Some(observed_at);
    replay.last_error = Some(error.to_string());
}

#[derive(Clone)]
struct AgentStatePaths {
    node_id_path: PathBuf,
    udp_key_path: PathBuf,
    nodes_dat_path: PathBuf,
    networking_config_path: PathBuf,
}

#[derive(Clone)]
struct AgentNetworkRuntime {
    dht: DhtNode,
    nat: Arc<NatManager>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    shutdown: Arc<AtomicBool>,
    passive_result_count: Arc<std::sync::atomic::AtomicU64>,
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
    started_at: Instant,
    state_paths: AgentStatePaths,
    snoop_queue: Arc<Mutex<SnoopQueue>>,
    publish_observability: Arc<Mutex<KadPublishObservability>>,
    harvest_observability: Arc<Mutex<KadHarvestObservability>>,
    runtime: Arc<Mutex<Option<AgentNetworkRuntime>>>,
    control_server: Arc<Mutex<Option<ControlServerRuntime>>>,
    control_selection_state: Arc<RwLock<ResolvedInterfaceBindingReport>>,
    p2p_selection_state: Arc<RwLock<ResolvedInterfaceBindingReport>>,
    active_searches: Arc<Mutex<HashMap<Uuid, ActiveSearchHandle>>>,
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
        ensure_parent_dir(&state_paths.nodes_dat_path)?;
        ensure_parent_dir(&state_paths.networking_config_path)?;
        let interfaces = detect_interfaces().unwrap_or_default();
        let control_selection_state =
            Self::resolve_control_selection_state(&config, &interfaces, None, false, false);
        let p2p_selection_state =
            Self::resolve_p2p_selection_state(&config, &interfaces, None, false, false);
        let snoop_queue_config = config.p2p.snoop_queue.clone();

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            coordinator,
            indexer_id,
            started_at: Instant::now(),
            state_paths,
            snoop_queue: Arc::new(Mutex::new(SnoopQueue::new(snoop_queue_config))),
            publish_observability: Arc::new(Mutex::new(KadPublishObservability::default())),
            harvest_observability: Arc::new(Mutex::new(KadHarvestObservability::default())),
            runtime: Arc::new(Mutex::new(None)),
            control_server: Arc::new(Mutex::new(None)),
            control_selection_state: Arc::new(RwLock::new(control_selection_state)),
            p2p_selection_state: Arc::new(RwLock::new(p2p_selection_state)),
            active_searches: Arc::new(Mutex::new(HashMap::new())),
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

    fn control_selection(config: &EmuleAgentConfig) -> InterfaceBindingSelection {
        InterfaceBindingSelection {
            bind_iface: config.control.bind_iface.clone(),
            bind_ip: config.control.bind_ip.clone(),
            selection_confirmed: config.control.selection_confirmed,
        }
    }

    fn p2p_selection(config: &EmuleAgentConfig) -> InterfaceBindingSelection {
        InterfaceBindingSelection {
            bind_iface: config.p2p.bind_iface.clone(),
            bind_ip: config.p2p.bind_ip.clone(),
            selection_confirmed: config.p2p.selection_confirmed,
        }
    }

    fn control_config(config: &EmuleAgentConfig) -> AgentControlConfig {
        AgentControlConfig {
            bind_iface: config.control.bind_iface.clone(),
            bind_ip: config.control.bind_ip.clone(),
            selection_confirmed: config.control.selection_confirmed,
            listen_port: config.control.listen_port,
        }
    }

    fn p2p_config(config: &EmuleAgentConfig) -> AgentP2pConfig {
        AgentP2pConfig {
            bind_iface: config.p2p.bind_iface.clone(),
            bind_ip: config.p2p.bind_ip.clone(),
            selection_confirmed: config.p2p.selection_confirmed,
            kad: AgentKadConfig {
                listen_port: config.p2p.kad.listen_port,
            },
            ed2k: AgentEd2kConfig {
                listen_port: config.p2p.ed2k.listen_port,
            },
        }
    }

    fn desired_nat_config(config: &EmuleAgentConfig) -> AgentNatConfig {
        AgentNatConfig {
            p2p: AgentNatP2pConfig {
                enabled: config.nat.p2p.enabled,
                backend_order: if config.nat.p2p.backend_order.is_empty() {
                    default_upnp_backend_order()
                } else {
                    config.nat.p2p.backend_order.clone()
                },
                igd_ip: config.nat.p2p.igd_ip.clone(),
                minissdpd_socket: config.nat.p2p.minissdpd_socket.clone(),
                ssdp_local_port: config.nat.p2p.ssdp_local_port,
                discovery_timeout_secs: config.nat.p2p.discovery_timeout_secs,
                lease_duration_secs: config.nat.p2p.lease_duration_secs,
                renew_margin_secs: config.nat.p2p.renew_margin_secs,
                external_ip_override: config.nat.p2p.external_ip_override.clone(),
            },
        }
    }

    fn networking_config(config: &EmuleAgentConfig) -> AgentNetworkingConfig {
        AgentNetworkingConfig {
            control: Self::control_config(config),
            p2p: Self::p2p_config(config),
            nat: Self::desired_nat_config(config),
        }
    }

    fn bootstrap_control_bind_addr(config: &EmuleAgentConfig) -> Result<SocketAddr> {
        resolved_socket_addr(config.control.listen_port, None)
    }

    fn startup_control_bind_addr(config: &EmuleAgentConfig) -> Result<SocketAddr> {
        let interfaces = detect_interfaces().unwrap_or_default();
        let selection = Self::control_selection(config);
        if selection.selection_confirmed
            && let Some(bind_ip) = resolve_bind_ip(
                &interfaces,
                selection.bind_iface.as_deref(),
                selection.bind_ip.as_deref(),
            )
        {
            return Self::selected_control_bind_addr(config, Some(&bind_ip));
        }

        Self::bootstrap_control_bind_addr(config)
    }

    fn selected_control_bind_addr(
        config: &EmuleAgentConfig,
        bind_ip: Option<&str>,
    ) -> Result<SocketAddr> {
        resolved_socket_addr(config.control.listen_port, bind_ip)
    }

    fn resolve_binding_state(
        interfaces: &[AgentInterface],
        selection: InterfaceBindingSelection,
        runtime_error: Option<String>,
        ready: bool,
        applied: bool,
    ) -> ResolvedInterfaceBindingReport {
        let recommended_interface_name = recommend_interface(interfaces);
        let resolved_bind_ip = resolve_bind_ip(
            interfaces,
            selection.bind_iface.as_deref(),
            selection.bind_ip.as_deref(),
        );

        let (state, last_error) = if let Some(error) = runtime_error {
            (InterfaceSelectionState::Error, Some(error))
        } else if applied {
            (InterfaceSelectionState::Applied, None)
        } else if !selection.selection_confirmed {
            (InterfaceSelectionState::Pending, None)
        } else if resolved_bind_ip.is_some() {
            (InterfaceSelectionState::Confirmed, None)
        } else {
            (
                InterfaceSelectionState::Error,
                Some(
                    "selected interface does not currently resolve to an IPv4 bind address"
                        .to_string(),
                ),
            )
        };

        ResolvedInterfaceBindingReport {
            bind_iface: selection.bind_iface,
            bind_ip: resolved_bind_ip,
            recommended_interface_name,
            selection_confirmed: selection.selection_confirmed,
            ready,
            state,
            last_error,
        }
    }

    fn resolve_control_selection_state(
        config: &EmuleAgentConfig,
        interfaces: &[AgentInterface],
        runtime_error: Option<String>,
        ready: bool,
        applied: bool,
    ) -> ResolvedInterfaceBindingReport {
        Self::resolve_binding_state(
            interfaces,
            Self::control_selection(config),
            runtime_error,
            ready,
            applied,
        )
    }

    fn resolve_p2p_selection_state(
        config: &EmuleAgentConfig,
        interfaces: &[AgentInterface],
        runtime_error: Option<String>,
        ready: bool,
        applied: bool,
    ) -> ResolvedInterfaceBindingReport {
        Self::resolve_binding_state(
            interfaces,
            Self::p2p_selection(config),
            runtime_error,
            ready,
            applied,
        )
    }

    async fn current_control_bind_addr(&self) -> Option<SocketAddr> {
        self.control_server
            .lock()
            .await
            .as_ref()
            .map(|runtime| runtime.bind_addr)
    }

    async fn current_registration_url(&self, config: &EmuleAgentConfig) -> Result<String> {
        let bind_addr = self
            .current_control_bind_addr()
            .await
            .unwrap_or(Self::bootstrap_control_bind_addr(config)?);
        let host = if bind_addr.ip().is_unspecified() {
            config.agent.hostname.clone()
        } else {
            bind_addr.ip().to_string()
        };
        Ok(format!("http://{}:{}", host, bind_addr.port()))
    }

    async fn start_control_server(self: &Arc<Self>, bind_addr: SocketAddr) -> Result<()> {
        let server = IndexerServer::new(Arc::clone(self))
            .spawn(bind_addr)
            .await?;
        let local_addr = server.local_addr();
        *self.control_server.lock().await = Some(ControlServerRuntime {
            bind_addr: local_addr,
            server,
        });
        Ok(())
    }

    async fn start_control_server_with_retry(
        self: &Arc<Self>,
        bind_addr: SocketAddr,
    ) -> Result<()> {
        let mut last_error = None;
        for _attempt in 0..20 {
            match self.start_control_server(bind_addr).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("control server failed to start")))
    }

    async fn connect_to_coordinator(&self) -> Result<NetworkingConfigApplyOutcome> {
        self.register_with_coordinator().await?;
        self.sync_networking_config_from_coordinator().await
    }

    fn spawn_coordinator_reconnect_task(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(COORDINATOR_RECONNECT_SECS)).await;
                if self.restart_requested.load(Ordering::SeqCst) {
                    break;
                }

                match self.connect_to_coordinator().await {
                    Ok(NetworkingConfigApplyOutcome::RestartRequired) => {
                        info!(
                            "reconnected to coordinator and received updated networking config; restarting agent"
                        );
                        self.request_restart();
                        break;
                    }
                    Ok(NetworkingConfigApplyOutcome::ReconciledInPlace) => {
                        info!(
                            "reconnected to coordinator and applied networking config without restarting agent"
                        );
                        break;
                    }
                    Ok(NetworkingConfigApplyOutcome::Unchanged) => {
                        info!("reconnected to coordinator; coordinator integration resumed");
                        break;
                    }
                    Err(error) => {
                        debug!("coordinator reconnect attempt failed: {error}");
                    }
                }
            }
        })
    }

    async fn stop_control_server(&self) -> Result<()> {
        if let Some(runtime) = self.control_server.lock().await.take() {
            runtime.server.shutdown().await?;
        }
        Ok(())
    }

    fn request_restart(&self) {
        self.restart_requested.store(true, Ordering::SeqCst);
        self.restart_notify.notify_waiters();
    }

    /// Returns `true` only when the startup control listener endpoint changes.
    ///
    /// That endpoint cannot be safely rebound in-process, so the agent exits
    /// with `RestartRequested` and the binary relaunches it. NAT-only and P2P
    /// endpoint changes are applied in-process via runtime reconciliation.
    fn restart_required_for_networking_change(
        old: &AgentNetworkingConfig,
        new: &AgentNetworkingConfig,
    ) -> bool {
        let old_config = Self::config_for_restart_decision(old);
        let new_config = Self::config_for_restart_decision(new);
        Self::startup_control_bind_addr(&old_config).ok()
            != Self::startup_control_bind_addr(&new_config).ok()
    }

    fn config_for_restart_decision(networking: &AgentNetworkingConfig) -> EmuleAgentConfig {
        let mut config = EmuleAgentConfig::default();
        apply_networking_config(&mut config, networking);
        config
    }

    async fn apply_networking_config_update(
        &self,
        desired: &AgentNetworkingConfig,
    ) -> Result<NetworkingConfigApplyOutcome> {
        let (old_networking, new_networking, restart_required) = {
            let mut guard = self.config.write().await;
            let old_networking = Self::networking_config(&guard);
            if old_networking == *desired {
                return Ok(NetworkingConfigApplyOutcome::Unchanged);
            }

            apply_networking_config(&mut guard, desired);
            let new_networking = Self::networking_config(&guard);
            let restart_required =
                Self::restart_required_for_networking_change(&old_networking, &new_networking);
            (old_networking, new_networking, restart_required)
        };

        debug!(
            restart_required,
            old_control_bind_ip = ?old_networking.control.bind_ip,
            new_control_bind_ip = ?new_networking.control.bind_ip,
            old_control_port = old_networking.control.listen_port,
            new_control_port = new_networking.control.listen_port,
            old_p2p_bind_ip = ?old_networking.p2p.bind_ip,
            new_p2p_bind_ip = ?new_networking.p2p.bind_ip,
            old_kad_port = old_networking.p2p.kad.listen_port,
            new_kad_port = new_networking.p2p.kad.listen_port,
            old_ed2k_port = old_networking.p2p.ed2k.listen_port,
            new_ed2k_port = new_networking.p2p.ed2k.listen_port,
            "applied networking config update"
        );

        persist_networking_config(&self.state_paths, &new_networking)?;
        if restart_required {
            return Ok(NetworkingConfigApplyOutcome::RestartRequired);
        }

        self.reconcile_runtime().await?;
        Ok(NetworkingConfigApplyOutcome::ReconciledInPlace)
    }

    fn nat_mappings_from_config(
        config: &EmuleAgentConfig,
        bind_ip: Option<&str>,
    ) -> Result<Vec<MappingSpec>> {
        let kad_addr = resolved_socket_addr(config.p2p.kad.listen_port, bind_ip)
            .context("invalid p2p.kad.listen_port for NAT mapping")?;
        let ed2k_addr = resolved_socket_addr(config.p2p.ed2k.listen_port, bind_ip)
            .context("invalid p2p.ed2k.listen_port for NAT mapping")?;

        Ok(vec![
            MappingSpec {
                name: "kad".to_string(),
                local_addr: kad_addr,
                protocol: TransportProtocol::Udp,
                exposure: MappingExposure::Required,
                preferred_external_port: None,
            },
            MappingSpec {
                name: "ed2k".to_string(),
                local_addr: ed2k_addr,
                protocol: TransportProtocol::Tcp,
                exposure: MappingExposure::Preferred,
                preferred_external_port: None,
            },
        ])
    }

    async fn sync_networking_config_from_coordinator(
        &self,
    ) -> Result<NetworkingConfigApplyOutcome> {
        let view = self
            .coordinator
            .agent_interfaces_view(self.indexer_id)
            .await?;
        self.sync_networking_config_from_view(&view).await
    }

    async fn sync_networking_config_from_view(
        &self,
        view: &AgentInterfacesView,
    ) -> Result<NetworkingConfigApplyOutcome> {
        self.apply_networking_config_update(&view.config).await
    }

    async fn interface_report(&self) -> AgentNetworkReport {
        let config = self.config.read().await.clone();
        let interfaces = detect_interfaces().unwrap_or_default();
        let runtime_active = self.runtime.lock().await.is_some();
        let control_bind_addr = self.current_control_bind_addr().await;

        let control_error = self
            .control_selection_state
            .try_read()
            .ok()
            .and_then(|state| {
                matches!(state.state, InterfaceSelectionState::Error)
                    .then(|| state.last_error.clone())
                    .flatten()
            });
        let p2p_error = self.p2p_selection_state.try_read().ok().and_then(|state| {
            matches!(state.state, InterfaceSelectionState::Error)
                .then(|| state.last_error.clone())
                .flatten()
        });

        let control_applied = Self::control_selection(&config).selection_confirmed
            && control_bind_addr.is_some_and(|bind_addr| {
                resolve_bind_ip(
                    &interfaces,
                    config.control.bind_iface.as_deref(),
                    config.control.bind_ip.as_deref(),
                )
                .is_some_and(|resolved_ip| bind_addr.ip().to_string() == resolved_ip)
            });
        let control = Self::resolve_control_selection_state(
            &config,
            &interfaces,
            control_error,
            control_bind_addr.is_some(),
            control_applied,
        );
        let p2p = Self::resolve_p2p_selection_state(
            &config,
            &interfaces,
            p2p_error,
            runtime_active,
            runtime_active,
        );

        AgentNetworkReport {
            interfaces,
            control: build_interface_binding_report(&control),
            p2p: build_interface_binding_report(&p2p),
        }
    }

    async fn reconcile_runtime(&self) -> Result<()> {
        let config = self.config.read().await.clone();
        let interfaces = detect_interfaces().unwrap_or_default();
        let binding = Self::resolve_p2p_selection_state(&config, &interfaces, None, false, false);
        {
            let mut selection_state = self.p2p_selection_state.write().await;
            *selection_state = binding.clone();
        }

        if !binding.selection_confirmed {
            self.stop_runtime().await?;
            return Ok(());
        }

        let Some(bind_ip) = binding.bind_ip.clone() else {
            self.stop_runtime().await?;
            return Ok(());
        };

        self.stop_runtime().await?;
        match self.build_runtime(&config, &bind_ip).await {
            Ok(runtime) => {
                let dht_task = runtime.dht.start();
                runtime.tasks.lock().await.push(dht_task);
                runtime.nat.start().await?;
                self.spawn_background_tasks(&runtime, &config).await;
                *self.runtime.lock().await = Some(runtime);
                let mut selection_state = self.p2p_selection_state.write().await;
                selection_state.state = InterfaceSelectionState::Applied;
                selection_state.ready = true;
                selection_state.last_error = None;
            }
            Err(error) => {
                let mut selection_state = self.p2p_selection_state.write().await;
                selection_state.state = InterfaceSelectionState::Error;
                selection_state.last_error = Some(error.to_string());
            }
        }

        Ok(())
    }

    async fn stop_runtime(&self) -> Result<()> {
        self.cancel_active_searches().await;
        if let Some(runtime) = self.runtime.lock().await.take() {
            runtime.shutdown.store(true, Ordering::SeqCst);
            let tasks = {
                let mut tasks = runtime.tasks.lock().await;
                std::mem::take(&mut *tasks)
            };
            for task in tasks {
                task.abort();
            }
            runtime.nat.stop().await?;
        }
        Ok(())
    }

    async fn cancel_active_searches(&self) {
        let handles = {
            let mut active = self.active_searches.lock().await;
            active.drain().map(|(_, handle)| handle).collect::<Vec<_>>()
        };
        for handle in handles {
            handle.cancel.cancel();
        }
    }

    async fn build_runtime(
        &self,
        config: &EmuleAgentConfig,
        bind_ip: &str,
    ) -> Result<AgentNetworkRuntime> {
        let node_id = load_or_create_node_id(&self.state_paths.node_id_path)?;
        let udp_key = load_or_create_udp_key(&self.state_paths.udp_key_path)?;
        let bind_addr = resolved_socket_addr(config.p2p.kad.listen_port, Some(bind_ip))
            .context("invalid p2p.kad.listen_port")?;
        let nodes_dat = read_optional_bytes(&self.state_paths.nodes_dat_path)?;
        let nodes_text = (!config.p2p.kad.bootstrap_nodes.is_empty())
            .then(|| config.p2p.kad.bootstrap_nodes.join("\n"));

        let dht = DhtNode::new(DhtConfig {
            bind_addr,
            node_id,
            max_routing_table_size: 12_000,
            max_concurrent_searches: 5,
            search_timeout: Duration::from_secs(config.p2p.kad.search_timeout_secs),
            store_timeout: Duration::from_secs(config.p2p.kad.store_timeout_secs),
            republish_interval: Duration::from_secs(config.p2p.kad.republish_interval_secs),
            max_outbound_pps: config.p2p.kad.max_outbound_pps,
            search_phase2_fanout: config.p2p.kad.search_phase2_fanout,
            keyword_result_cap: config.p2p.kad.keyword_result_cap,
            source_result_cap: config.p2p.kad.source_result_cap,
            notes_result_cap: config.p2p.kad.notes_result_cap,
            obfuscation_enabled: config.p2p.kad.obfuscation_enabled,
            udp_key,
            nodes_dat,
            nodes_text,
        })
        .await?;

        let nat_config = overlord_agent_nat::NatConfig {
            enabled: config.nat.p2p.enabled,
            backend_order: if config.nat.p2p.backend_order.is_empty() {
                default_upnp_backend_order()
            } else {
                config.nat.p2p.backend_order.clone()
            },
            bind_ip: Some(bind_ip.to_string()),
            igd_ip: config.nat.p2p.igd_ip.clone(),
            minissdpd_socket: config.nat.p2p.minissdpd_socket.clone(),
            ssdp_local_port: config.nat.p2p.ssdp_local_port,
            discovery_timeout_secs: config.nat.p2p.discovery_timeout_secs,
            lease_duration_secs: config.nat.p2p.lease_duration_secs,
            renew_margin_secs: config.nat.p2p.renew_margin_secs,
            external_ip_override: config.nat.p2p.external_ip_override.clone(),
        };

        let nat = Arc::new(
            NatManagerBuilder::new(nat_config)
                .with_mappings(Self::nat_mappings_from_config(config, Some(bind_ip))?)
                .with_providers(built_in_upnp_port_mapping_providers())
                .build(),
        );

        Ok(AgentNetworkRuntime {
            dht,
            nat,
            tasks: Arc::new(Mutex::new(Vec::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            passive_result_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }
}

#[derive(Default)]
struct SearchRunStats {
    result_count: u32,
    batch_count: u32,
}

async fn emit_search_event(
    callback_client: &CoordinatorClient,
    job_id: Uuid,
    indexer_id: Uuid,
    status: SearchEventStatus,
    stats: &SearchRunStats,
    error: Option<String>,
) -> Result<()> {
    callback_client
        .post_search_event(&SearchEvent {
            job_id,
            indexer_id,
            status,
            result_count: Some(stats.result_count),
            batch_count: Some(stats.batch_count),
            error,
        })
        .await
}

async fn post_search_batch(
    callback_client: &CoordinatorClient,
    job_id: Uuid,
    indexer_id: Uuid,
    files: Vec<FileRecord>,
    stats: &mut SearchRunStats,
) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    stats.result_count += files.len() as u32;
    stats.batch_count += 1;
    callback_client
        .post_results(&ResultBatch {
            job_id: Some(job_id),
            indexer_id,
            protocol: Protocol::Kad2,
            files,
        })
        .await?;
    emit_search_event(
        callback_client,
        job_id,
        indexer_id,
        SearchEventStatus::BatchReceived,
        stats,
        None,
    )
    .await
}

fn search_query(job: &SearchJob) -> Result<&str> {
    job.query
        .as_deref()
        .filter(|query| !query.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("search job is missing query text"))
}

fn search_file_hash(job: &SearchJob) -> Result<Ed2kHash> {
    let Some(HashType::Ed2k(value)) = job.file_hash.as_ref() else {
        anyhow::bail!("search job is missing ed2k file hash");
    };
    Ed2kHash::from_str(value).with_context(|| format!("invalid Ed2k hash {value}"))
}

fn search_file_size(job: &SearchJob) -> Result<u64> {
    job.file_size
        .filter(|size| *size > 0)
        .ok_or_else(|| anyhow::anyhow!("search job is missing file size"))
}

fn map_source_result(result: &SourceResult, file_size: u64) -> FileRecord {
    FileRecord {
        hashes: vec![HashType::Ed2k(result.file_hash.to_string())],
        names: Vec::new(),
        size: Some(file_size),
        content_type: None,
        tags: Vec::new(),
        sources: vec![Source {
            protocol: Protocol::Kad2,
            address: format!("{}:{}", result.ip, result.tcp_port),
            extra: serde_json::json!({
                "udp_port": result.udp_port,
                "search_mode": "source"
            }),
        }],
    }
}

async fn do_active_keyword_search(
    dht: &DhtNode,
    indexer_id: Uuid,
    job: &SearchJob,
    config: Arc<RwLock<EmuleAgentConfig>>,
    cancel: CancellationToken,
) -> Result<SearchRunStats> {
    let target = keyword_target(search_query(job)?);
    let mut stream = dht.search_keywords_with_cancel(target, cancel.clone());
    let callback_client = CoordinatorClient::new(&job.callback_url)?;
    let mut files = Vec::new();
    let mut seen = 0usize;
    let mut stats = SearchRunStats::default();

    while let Some(result) = stream.next().await {
        seen += 1;
        files.push(map_search_result_for(dht, &result)?);
        if files.len() >= ACTIVE_BATCH_SIZE {
            post_search_batch(
                &callback_client,
                job.job_id,
                indexer_id,
                std::mem::take(&mut files),
                &mut stats,
            )
            .await?;
        }
    }

    post_search_batch(&callback_client, job.job_id, indexer_id, files, &mut stats).await?;

    if seen == 0 && !cancel.is_cancelled() && config.read().await.p2p.kad.enable_mock_results {
        post_search_batch(
            &callback_client,
            job.job_id,
            indexer_id,
            vec![mock_file_record(
                search_query(job)?,
                dht.bind_addr()?.to_string(),
            )],
            &mut stats,
        )
        .await?;
    }

    Ok(stats)
}

async fn do_active_source_search(
    dht: &DhtNode,
    indexer_id: Uuid,
    job: &SearchJob,
    cancel: CancellationToken,
) -> Result<SearchRunStats> {
    let file_hash = search_file_hash(job)?;
    let file_size = search_file_size(job)?;
    let callback_client = CoordinatorClient::new(&job.callback_url)?;
    let mut stream = dht.search_sources_with_cancel(file_hash, file_size, cancel);
    let mut files = Vec::new();
    let mut stats = SearchRunStats::default();

    while let Some(result) = stream.next().await {
        files.push(map_source_result(&result, file_size));
        if files.len() >= ACTIVE_BATCH_SIZE {
            post_search_batch(
                &callback_client,
                job.job_id,
                indexer_id,
                std::mem::take(&mut files),
                &mut stats,
            )
            .await?;
        }
    }

    post_search_batch(&callback_client, job.job_id, indexer_id, files, &mut stats).await?;
    Ok(stats)
}

/// Builds the fixed synthetic seed list used when the coordinator has no popular hashes yet.
fn synthetic_popular_hashes() -> Vec<PopularHash> {
    SYNTHETIC_POPULAR_SEEDS
        .iter()
        .enumerate()
        .map(|(index, seed)| synthetic_popular_hash(index, seed))
        .collect()
}

/// Produces a deterministic fake Ed2k hash so the synthetic seed set is stable across restarts.
fn synthetic_file_hash(index: usize, seed: &SyntheticPopularSeed) -> Ed2kHash {
    let mut hasher = Md4::new();
    hasher.update(
        format!(
            "overlord-synthetic-kad-seed|{index}|{}|{}|{}",
            seed.title, seed.size, seed.source_count
        )
        .as_bytes(),
    );
    let digest: [u8; 16] = hasher.finalize().into();
    Ed2kHash::from_bytes(digest)
}

fn synthetic_popular_hash(index: usize, seed: &SyntheticPopularSeed) -> PopularHash {
    PopularHash {
        hash: HashType::Ed2k(hex::encode(synthetic_file_hash(index, seed).0)),
        canonical_name: seed.title.to_string(),
        size: seed.size,
        source_count: seed.source_count,
    }
}

/// Chooses coordinator-provided hashes when available and otherwise falls back to the
/// built-in synthetic seed set.
fn select_popular_hashes_for_seeding(
    hashes: Vec<PopularHash>,
) -> (PublishSeedSource, Vec<PopularHash>) {
    if hashes.is_empty() {
        (
            PublishSeedSource::SyntheticFallback,
            synthetic_popular_hashes(),
        )
    } else {
        (PublishSeedSource::Coordinator, hashes)
    }
}

/// Fetches the current seed set from the coordinator and applies the synthetic fallback only
/// when the coordinator returned no popular hashes.
async fn fetch_popular_hashes_for_seeding(
    coordinator: &CoordinatorClient,
) -> Result<(PublishSeedSource, Vec<PopularHash>)> {
    Ok(select_popular_hashes_for_seeding(
        coordinator.popular_hashes().await?,
    ))
}

/// Publishes one seeding batch and logs which source produced it.
async fn seed_popular_from_source(
    dht: &DhtNode,
    source_publish_identity: NodeId,
    source: PublishSeedSource,
    hashes: Vec<PopularHash>,
    publish_observability: &Arc<Mutex<KadPublishObservability>>,
) -> Result<()> {
    info!(
        "kad seeding source={} entries={}",
        source.label(),
        hashes.len()
    );
    seed_popular_impl(
        dht,
        source_publish_identity,
        source,
        hashes,
        publish_observability,
    )
    .await
}

async fn seed_popular_from_coordinator_or_fallback(
    dht: &DhtNode,
    source_publish_identity: NodeId,
    coordinator: &CoordinatorClient,
    publish_observability: &Arc<Mutex<KadPublishObservability>>,
) -> Result<()> {
    let (source, hashes) = fetch_popular_hashes_for_seeding(coordinator).await?;
    seed_popular_from_source(
        dht,
        source_publish_identity,
        source,
        hashes,
        publish_observability,
    )
    .await
}

/// Returns the eMule high-ID source type used for source publishes in the non-firewalled case.
fn emule_high_id_source_type(file_size: u64) -> u32 {
    if file_size > EMULE_LARGE_FILE_SIZE_THRESHOLD {
        4
    } else {
        1
    }
}

/// Derive a stable 16-byte source-publish identity from the persisted indexer UUID.
///
/// The oracle source-publish path sends the eMule client hash rather than the Kad node ID in the
/// second `KADEMLIA2_PUBLISH_SOURCE_REQ` field. We do not yet persist a separate client hash, so
/// we reuse the stable indexer UUID bytes to keep the identity fixed across restarts.
fn source_publish_client_hash(indexer_id: Uuid) -> NodeId {
    NodeId::from_bytes(*indexer_id.as_bytes())
}

/// Return the eMule-style `TAG_ENCRYPTION` bits for the current non-firewalled agent.
///
/// At the moment the agent only models "crypt layer supported", so the other eMule bits remain 0.
fn emule_source_encryption_options() -> u8 {
    0x01
}

async fn seed_popular_impl(
    dht: &DhtNode,
    source_publish_identity: NodeId,
    seed_source: PublishSeedSource,
    hashes: Vec<PopularHash>,
    publish_observability: &Arc<Mutex<KadPublishObservability>>,
) -> Result<()> {
    if !dht.is_bootstrapped() {
        anyhow::bail!("kad node is not bootstrapped yet");
    }

    let bind_addr = dht.bind_addr()?;
    let mut keyword_totals = PublishAttemptStats::default();
    let mut source_totals = PublishAttemptStats::default();
    let published_items = hashes.len();
    update_publish_progress(
        publish_observability,
        seed_source,
        0,
        keyword_totals,
        source_totals,
        Utc::now(),
    )
    .await;

    for (index, hash) in hashes.into_iter().enumerate() {
        let HashType::Ed2k(raw_hash) = hash.hash;
        let file_hash = Ed2kHash::from_str(&raw_hash)
            .with_context(|| format!("invalid Ed2k hash {raw_hash}"))?;
        let keyword_hash = keyword_target(&hash.canonical_name);
        let item_no = index + 1;
        // Keep synthetic seed publishes indistinguishable from normal eMule-style content
        // publishes: filename/filesize/source count on the keyword publish and the normal
        // high-ID source port/type tags on the source publish.
        let keyword_tags = vec![
            Tag::filename(hash.canonical_name.clone()),
            Tag::filesize(hash.size),
            Tag::sources(hash.source_count),
        ];
        info!(
            "kad publish start family=keyword seed_source={} item={}/{} target={} hash={}",
            seed_source.label(),
            item_no,
            published_items,
            keyword_hash,
            raw_hash
        );
        match dht
            .publish_keyword(keyword_hash, file_hash, keyword_tags)
            .await
        {
            Ok(stats) => {
                keyword_totals.closest_contacts_considered += stats.closest_contacts_considered;
                keyword_totals.attempted_contacts += stats.attempted_contacts;
                keyword_totals.acked_contacts += stats.acked_contacts;
                keyword_totals.timed_out_contacts += stats.timed_out_contacts;
            }
            Err(error) => {
                debug!(
                    "keyword publish failed for target={} hash={}: {error}",
                    keyword_hash, raw_hash
                );
            }
        }
        let source_tags = vec![
            Tag::new_short(
                tag_name::SOURCETYPE,
                TagValue::UInt(u64::from(emule_high_id_source_type(hash.size))),
            ),
            Tag::new_short(
                tag_name::SOURCEPORT,
                TagValue::UInt(u64::from(bind_addr.port())),
            ),
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(bind_addr.port())),
            Tag::filesize(hash.size),
            Tag::new_short(
                tag_name::ENCRYPTION,
                TagValue::U8(emule_source_encryption_options()),
            ),
        ];
        info!(
            "kad publish start family=source seed_source={} item={}/{} target={} hash={}",
            seed_source.label(),
            item_no,
            published_items,
            file_hash,
            raw_hash
        );
        match dht
            .publish_source(file_hash, source_publish_identity, source_tags)
            .await
        {
            Ok(stats) => {
                source_totals.closest_contacts_considered += stats.closest_contacts_considered;
                source_totals.attempted_contacts += stats.attempted_contacts;
                source_totals.acked_contacts += stats.acked_contacts;
                source_totals.timed_out_contacts += stats.timed_out_contacts;
            }
            Err(error) => {
                debug!("source publish failed for hash={}: {error}", raw_hash);
            }
        }
        let observed_at = Utc::now();
        update_publish_progress(
            publish_observability,
            seed_source,
            item_no,
            keyword_totals,
            source_totals,
            observed_at,
        )
        .await;
        info!(
            "kad publish progress seed_source={} items_done={}/{} keyword_attempted={} keyword_acked={} source_attempted={} source_acked={}",
            seed_source.label(),
            item_no,
            published_items,
            keyword_totals.attempted_contacts,
            keyword_totals.acked_contacts,
            source_totals.attempted_contacts,
            source_totals.acked_contacts
        );
    }

    record_publish_summaries(
        publish_observability,
        seed_source,
        published_items,
        keyword_totals,
        source_totals,
        Utc::now(),
    )
    .await;

    Ok(())
}

async fn restore_snoop_queue(
    coordinator: &CoordinatorClient,
    indexer_id: Uuid,
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
) {
    match coordinator.restore_snoop(indexer_id).await {
        Ok(entries) => {
            let mut queue = snoop_queue.lock().await;
            queue.merge_snapshot(entries);
            let counts = queue.family_counts();
            info!(
                "kad snoop restore keyword={} source={} notes={} total={}",
                counts.keyword,
                counts.source,
                counts.notes,
                queue.len()
            );
        }
        Err(error) => warn!("failed to restore snoop queue: {error}"),
    }
}

async fn flush_snoop_queue(
    coordinator: &CoordinatorClient,
    indexer_id: Uuid,
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
) -> Result<()> {
    let (entries, counts) = {
        let queue = snoop_queue.lock().await;
        (queue.snapshot(), queue.family_counts())
    };
    info!(
        "kad snoop flush keyword={} source={} notes={} total={}",
        counts.keyword,
        counts.source,
        counts.notes,
        entries.len()
    );
    coordinator.flush_snoop(indexer_id, &entries).await
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}

fn read_optional_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(fs::read(path).with_context(|| {
        format!("failed to read {}", path.display())
    })?))
}

fn resolved_socket_addr(listen_port: u16, bind_ip: Option<&str>) -> Result<SocketAddr> {
    let ip = match bind_ip {
        Some(bind_ip) => bind_ip
            .parse::<IpAddr>()
            .with_context(|| format!("invalid bind ip {bind_ip}"))?,
        None => IpAddr::from([0, 0, 0, 0]),
    };
    Ok(SocketAddr::new(ip, listen_port))
}

fn load_or_create_indexer_id(path: &str) -> Result<Uuid> {
    let path = Path::new(path);
    if path.exists() {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        return Uuid::parse_str(contents.trim())
            .with_context(|| format!("invalid uuid in {}", path.display()));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let generated = Uuid::new_v4();
    fs::write(path, generated.to_string())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(generated)
}

fn load_or_create_node_id(path: &Path) -> Result<NodeId> {
    if path.exists() {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        return NodeId::from_str(contents.trim())
            .with_context(|| format!("invalid node id in {}", path.display()));
    }
    let node_id = NodeId::from_bytes(rand::random());
    fs::write(path, node_id.to_string())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(node_id)
}

fn load_or_create_udp_key(path: &Path) -> Result<u32> {
    if path.exists() {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        return contents
            .trim()
            .parse::<u32>()
            .with_context(|| format!("invalid udp key in {}", path.display()));
    }
    let udp_key: u32 = rand::random();
    fs::write(path, udp_key.to_string())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(udp_key)
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
    let first_word = significant_keyword_words(query)
        .into_iter()
        .next()
        .unwrap_or_else(|| query.to_lowercase());
    let mut hasher = Md4::new();
    hasher.update(first_word.as_bytes());
    let digest: [u8; 16] = hasher.finalize().into();
    let mut wire = [0u8; 16];
    for chunk in 0..4 {
        let base = chunk * 4;
        wire[base] = digest[base + 3];
        wire[base + 1] = digest[base + 2];
        wire[base + 2] = digest[base + 1];
        wire[base + 3] = digest[base];
    }
    NodeId::from_bytes(wire)
}

fn guess_content_type(name: Option<&String>) -> Option<ContentType> {
    let Some(name) = name else {
        return Some(ContentType::Unknown);
    };
    let lower = name.to_lowercase();
    let value = if [".mkv", ".mp4", ".avi", ".mov"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        ContentType::Video
    } else if [".mp3", ".flac", ".wav", ".ogg"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        ContentType::Audio
    } else if [".pdf", ".epub", ".txt", ".doc", ".docx"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        ContentType::Document
    } else if [".zip", ".rar", ".7z", ".tar"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        ContentType::Archive
    } else if [".exe", ".msi", ".iso"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        ContentType::Software
    } else {
        ContentType::Unknown
    };
    Some(value)
}

fn mock_file_record(query: &str, bind_addr: String) -> FileRecord {
    FileRecord {
        hashes: vec![HashType::Ed2k(hex::encode(keyword_target(query).0))],
        names: vec![format!(
            "{}.bin",
            query.trim().replace(' ', "_").to_lowercase()
        )],
        size: Some(1_048_576),
        content_type: Some(ContentType::Unknown),
        tags: vec![TagEntry {
            key: "origin".into(),
            value: serde_json::json!("mock_fallback"),
        }],
        sources: vec![Source {
            protocol: Protocol::Kad2,
            address: bind_addr,
            extra: serde_json::json!({ "search_mode": "mock" }),
        }],
    }
}

fn tag_to_entry(tag: &Tag) -> TagEntry {
    let key = match &tag.name {
        TagName::Short(value) => format!("tag_{value:02x}"),
        TagName::Long(value) => value.clone(),
    };
    let value = match &tag.value {
        TagValue::Hash(value) => serde_json::json!(value.to_string()),
        TagValue::String(value) => serde_json::json!(value),
        TagValue::UInt(value) => serde_json::json!(value),
        TagValue::U64(value) => serde_json::json!(value),
        TagValue::U32(value) => serde_json::json!(value),
        TagValue::U16(value) => serde_json::json!(value),
        TagValue::U8(value) => serde_json::json!(value),
        TagValue::Float(value) => serde_json::json!(value),
        TagValue::Bool(value) => serde_json::json!(value),
        TagValue::Blob(value) => serde_json::json!(hex::encode(value)),
    };
    TagEntry { key, value }
}

fn map_search_result_for(dht: &DhtNode, result: &SearchResult) -> Result<FileRecord> {
    Ok(FileRecord {
        hashes: vec![HashType::Ed2k(result.hash.to_string())],
        names: result.names.clone(),
        size: result.size,
        content_type: guess_content_type(result.names.first()),
        tags: result.tags.iter().map(tag_to_entry).collect(),
        sources: vec![Source {
            protocol: Protocol::Kad2,
            address: dht.bind_addr()?.to_string(),
            extra: serde_json::json!({
                "search_mode": "network",
                "availability": result.availability,
            }),
        }],
    })
}

fn build_keyword_snoop_entry(req: &SearchKeyReq, now: chrono::DateTime<Utc>) -> SnoopEntry {
    let payload_hex = if req.restrictive_payload.is_empty() {
        None
    } else {
        Some(hex::encode(&req.restrictive_payload))
    };
    let logical_key = format!(
        "keyword:{}:{:04x}:{}",
        req.target,
        req.start_position,
        payload_hex.as_deref().unwrap_or_default()
    );
    SnoopEntry::Keyword {
        logical_key,
        target: req.target.to_string(),
        start_position: req.start_position,
        restrictive_payload_hex: payload_hex,
        hit_count: 1,
        first_seen: now,
        last_seen: now,
        last_drained_at: None,
    }
}

fn build_source_snoop_entry(req: &SearchSourceReq, now: chrono::DateTime<Utc>) -> SnoopEntry {
    SnoopEntry::Source {
        logical_key: format!(
            "source:{}:{:04x}:{}",
            req.target, req.start_position, req.size
        ),
        target: req.target.to_string(),
        start_position: req.start_position,
        size: req.size,
        hit_count: 1,
        first_seen: now,
        last_seen: now,
        last_drained_at: None,
    }
}

fn build_notes_snoop_entry(req: &SearchNotesReq, now: chrono::DateTime<Utc>) -> SnoopEntry {
    SnoopEntry::Notes {
        logical_key: format!("notes:{}:{}", req.target, req.size),
        target: req.target.to_string(),
        size: req.size,
        hit_count: 1,
        first_seen: now,
        last_seen: now,
        last_drained_at: None,
    }
}

async fn record_snoop_entry(
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
    harvest_observability: &Arc<Mutex<KadHarvestObservability>>,
    from: SocketAddr,
    entry: SnoopEntry,
) {
    let (family, target, detail) = match &entry {
        SnoopEntry::Keyword {
            target,
            start_position,
            restrictive_payload_hex,
            ..
        } => (
            "keyword",
            target.clone(),
            format!(
                "start_position={start_position} restrictive_bytes={}",
                restrictive_payload_hex
                    .as_ref()
                    .map(|payload| payload.len() / 2)
                    .unwrap_or(0)
            ),
        ),
        SnoopEntry::Source {
            target,
            start_position,
            size,
            ..
        } => (
            "source",
            target.clone(),
            format!("start_position={start_position} size={size}"),
        ),
        SnoopEntry::Notes { target, size, .. } => ("notes", target.clone(), format!("size={size}")),
    };
    let observed_at = entry.last_seen();
    let outcome = {
        let mut queue = snoop_queue.lock().await;
        queue.record(entry.clone())
    };
    {
        let mut observability = harvest_observability.lock().await;
        apply_harvest_record(&mut observability, from, &entry, outcome.is_new);
    }
    if outcome.is_new || outcome.hit_count <= 3 || outcome.hit_count % 10 == 0 {
        info!(
            "kad snoop family={} from={} target={} {} queue_depth={} family_queue_depth={} hit_count={} state={} seen_at={}",
            family,
            from,
            target,
            detail,
            outcome.queue_depth,
            outcome.family_queue_depth,
            outcome.hit_count,
            if outcome.is_new { "new" } else { "repeat" },
            observed_at
        );
    }
}

async fn next_passive_keyword_request(
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
) -> Option<SearchKeyReq> {
    snoop_queue
        .lock()
        .await
        .select_next_keyword_request(Utc::now())
}

async fn persist_nodes_dat_for(dht: &DhtNode, state_paths: &AgentStatePaths) -> Result<()> {
    let contacts = dht
        .routing_contacts()
        .await
        .into_iter()
        .map(|contact| BootstrapContact {
            node_id: contact.id,
            ip: contact.ip,
            udp_port: contact.udp_port,
            tcp_port: contact.tcp_port,
            version: contact.kad_version,
            udp_key: contact.udp_key,
        })
        .collect::<Vec<_>>();
    let bytes = encode_nodes_dat(&contacts)?;
    fs::write(&state_paths.nodes_dat_path, bytes)
        .with_context(|| format!("failed to write {}", state_paths.nodes_dat_path.display()))?;
    Ok(())
}

async fn handle_unsolicited_packet(
    dht: &DhtNode,
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
    harvest_observability: &Arc<Mutex<KadHarvestObservability>>,
    packet: KadPacket,
    from: SocketAddr,
) -> Result<()> {
    match packet {
        KadPacket::Ping => dht.send_packet(from, &KadPacket::Pong).await?,
        KadPacket::HelloReq(req) => {
            if let Some(udp_key) = req.udp_key {
                dht.register_peer_key(from, udp_key);
            }
            if let std::net::IpAddr::V4(ip) = from.ip() {
                let mut contact =
                    Contact::new(req.node_id, ip, from.port(), req.tcp_port, req.version);
                if let Some(udp_key) = req.udp_key {
                    contact.udp_key = KadUdpKey::new(udp_key);
                }
                let _ = dht.add_contact(contact).await;
            }
            let bind_addr = dht.bind_addr()?;
            let tcp_ip = match bind_addr.ip() {
                std::net::IpAddr::V4(ip) => u32::from_be_bytes(ip.octets()),
                std::net::IpAddr::V6(_) => 0,
            };
            let _ = dht
                .send_packet(
                    from,
                    &KadPacket::HelloRes(overlord_kad_proto::HelloRes {
                        node_id: dht.own_id(),
                        tcp_ip,
                        tcp_port: bind_addr.port(),
                        version: overlord_kad_proto::KAD_VERSION,
                        udp_key: Some(dht.udp_key()),
                        tags: Vec::new(),
                    }),
                )
                .await;
        }
        KadPacket::HelloRes(res) => {
            if let Some(udp_key) = res.udp_key {
                dht.register_peer_key(from, udp_key);
            }
            if let std::net::IpAddr::V4(ip) = from.ip() {
                let mut contact =
                    Contact::new(res.node_id, ip, from.port(), res.tcp_port, res.version);
                if let Some(udp_key) = res.udp_key {
                    contact.udp_key = KadUdpKey::new(udp_key);
                }
                let _ = dht.add_contact(contact).await;
            }
            let _ = dht.send_packet(from, &KadPacket::HelloResAck).await;
        }
        KadPacket::BootstrapReq => {
            let bind_addr = dht.bind_addr()?;
            let contacts = dht
                .closest_contacts(&dht.own_id(), K)
                .await
                .into_iter()
                .map(contact_to_entry)
                .collect();
            dht.send_packet(
                from,
                &KadPacket::BootstrapRes(overlord_kad_proto::BootstrapRes {
                    sender_id: dht.own_id(),
                    sender_tcp_port: bind_addr.port(),
                    sender_version: overlord_kad_proto::KAD_VERSION,
                    contacts,
                }),
            )
            .await?;
        }
        KadPacket::Req(req) => {
            let contacts = dht
                .closest_contacts(&req.target, req.count as usize)
                .await
                .into_iter()
                .map(contact_to_entry)
                .collect();
            dht.send_packet(
                from,
                &KadPacket::Res(overlord_kad_proto::Res {
                    target: req.target,
                    contacts,
                }),
            )
            .await?;
        }
        KadPacket::SearchKeyReq(req) => {
            record_snoop_entry(
                snoop_queue,
                harvest_observability,
                from,
                build_keyword_snoop_entry(&req, Utc::now()),
            )
            .await
        }
        KadPacket::SearchSourceReq(req) => {
            record_snoop_entry(
                snoop_queue,
                harvest_observability,
                from,
                build_source_snoop_entry(&req, Utc::now()),
            )
            .await
        }
        KadPacket::SearchNotesReq(req) => {
            record_snoop_entry(
                snoop_queue,
                harvest_observability,
                from,
                build_notes_snoop_entry(&req, Utc::now()),
            )
            .await
        }
        KadPacket::PublishKeyReq(req) => {
            let _ = dht
                .send_packet(
                    from,
                    &KadPacket::PublishRes(overlord_kad_proto::PublishRes {
                        target: req.target,
                        load: 0,
                    }),
                )
                .await;
        }
        KadPacket::PublishSourceReq(req) => {
            let _ = dht
                .send_packet(
                    from,
                    &KadPacket::PublishRes(overlord_kad_proto::PublishRes {
                        target: req.target,
                        load: 0,
                    }),
                )
                .await;
        }
        KadPacket::PublishNotesReq(req) => {
            let _ = dht
                .send_packet(
                    from,
                    &KadPacket::PublishRes(overlord_kad_proto::PublishRes {
                        target: req.target,
                        load: 0,
                    }),
                )
                .await;
        }
        _ => {}
    }
    Ok(())
}

fn contact_to_entry(contact: Contact) -> ContactEntry {
    ContactEntry {
        node_id: contact.id,
        ip: u32::from_be_bytes(contact.ip.octets()),
        udp_port: contact.udp_port,
        tcp_port: contact.tcp_port,
        version: contact.kad_version,
    }
}

impl AgentStatePaths {
    fn from_config(config: &EmuleAgentConfig) -> Self {
        let state_dir = PathBuf::from(&config.agent.state_dir);
        let nodes_dat_path = if config.p2p.kad.nodes_dat_path.trim().is_empty() {
            state_dir.join("overlord-kad.nodes.dat")
        } else {
            PathBuf::from(&config.p2p.kad.nodes_dat_path)
        };
        Self {
            node_id_path: state_dir.join("overlord-kad.node-id"),
            udp_key_path: state_dir.join("overlord-kad.udp-key"),
            nodes_dat_path,
            networking_config_path: state_dir.join("overlord-agent.networking.json"),
        }
    }
}

#[cfg(test)]
fn empty_networking_config() -> AgentNetworkingConfig {
    AgentNetworkingConfig {
        control: AgentControlConfig {
            bind_iface: None,
            bind_ip: None,
            selection_confirmed: false,
            listen_port: 13_301,
        },
        p2p: AgentP2pConfig {
            bind_iface: None,
            bind_ip: None,
            selection_confirmed: false,
            kad: AgentKadConfig {
                listen_port: 41_000,
            },
            ed2k: AgentEd2kConfig {
                listen_port: 41_001,
            },
        },
        nat: AgentNatConfig {
            p2p: AgentNatP2pConfig {
                enabled: false,
                backend_order: default_upnp_backend_order(),
                igd_ip: None,
                minissdpd_socket: None,
                ssdp_local_port: None,
                discovery_timeout_secs: 5,
                lease_duration_secs: 3_600,
                renew_margin_secs: 300,
                external_ip_override: None,
            },
        },
    }
}

fn apply_networking_config(config: &mut EmuleAgentConfig, desired: &AgentNetworkingConfig) {
    config.control.bind_iface = desired.control.bind_iface.clone();
    config.control.bind_ip = desired.control.bind_ip.clone();
    config.control.selection_confirmed = desired.control.selection_confirmed;
    config.control.listen_port = desired.control.listen_port;
    config.p2p.bind_iface = desired.p2p.bind_iface.clone();
    config.p2p.bind_ip = desired.p2p.bind_ip.clone();
    config.p2p.selection_confirmed = desired.p2p.selection_confirmed;
    config.p2p.kad.listen_port = desired.p2p.kad.listen_port;
    config.p2p.ed2k.listen_port = desired.p2p.ed2k.listen_port;
    config.nat.p2p.enabled = desired.nat.p2p.enabled;
    config.nat.p2p.backend_order = if desired.nat.p2p.backend_order.is_empty() {
        default_upnp_backend_order()
    } else {
        desired.nat.p2p.backend_order.clone()
    };
    config.nat.p2p.igd_ip = desired.nat.p2p.igd_ip.clone();
    config.nat.p2p.minissdpd_socket = desired.nat.p2p.minissdpd_socket.clone();
    config.nat.p2p.ssdp_local_port = desired.nat.p2p.ssdp_local_port;
    config.nat.p2p.discovery_timeout_secs = desired.nat.p2p.discovery_timeout_secs;
    config.nat.p2p.lease_duration_secs = desired.nat.p2p.lease_duration_secs;
    config.nat.p2p.renew_margin_secs = desired.nat.p2p.renew_margin_secs;
    config.nat.p2p.external_ip_override = desired.nat.p2p.external_ip_override.clone();
}

fn persist_networking_config(
    state_paths: &AgentStatePaths,
    desired: &AgentNetworkingConfig,
) -> Result<()> {
    ensure_parent_dir(&state_paths.networking_config_path)?;
    let payload =
        serde_json::to_vec_pretty(desired).context("failed to serialize networking state")?;
    fs::write(&state_paths.networking_config_path, payload).with_context(|| {
        format!(
            "failed to persist networking state to {}",
            state_paths.networking_config_path.display()
        )
    })?;
    Ok(())
}

#[async_trait]
impl NatCapableAgent for OverlordAgentEmule {
    fn nat_config(&self) -> overlord_agent_nat::NatConfig {
        self.config
            .try_read()
            .map(|config| overlord_agent_nat::NatConfig {
                enabled: config.nat.p2p.enabled,
                backend_order: if config.nat.p2p.backend_order.is_empty() {
                    default_upnp_backend_order()
                } else {
                    config.nat.p2p.backend_order.clone()
                },
                bind_ip: config.p2p.bind_ip.clone(),
                igd_ip: config.nat.p2p.igd_ip.clone(),
                minissdpd_socket: config.nat.p2p.minissdpd_socket.clone(),
                ssdp_local_port: config.nat.p2p.ssdp_local_port,
                discovery_timeout_secs: config.nat.p2p.discovery_timeout_secs,
                lease_duration_secs: config.nat.p2p.lease_duration_secs,
                renew_margin_secs: config.nat.p2p.renew_margin_secs,
                external_ip_override: config.nat.p2p.external_ip_override.clone(),
            })
            .unwrap_or_default()
    }

    fn nat_mappings(&self) -> Vec<MappingSpec> {
        self.config
            .try_read()
            .ok()
            .and_then(|config| {
                Self::nat_mappings_from_config(&config, config.p2p.bind_ip.as_deref()).ok()
            })
            .unwrap_or_default()
    }
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
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.stop_runtime().await?;
        if let Err(error) =
            flush_snoop_queue(&self.coordinator, self.indexer_id, &self.snoop_queue).await
        {
            warn!("failed to flush snoop queue during shutdown: {error}");
        }
        Ok(())
    }

    async fn search(&self, job: SearchJob) -> Result<()> {
        let runtime = self.runtime.lock().await.clone();
        let Some(runtime) = runtime else {
            anyhow::bail!("agent networking is waiting for interface selection");
        };
        let dht = runtime.dht.clone();
        let indexer_id = self.indexer_id;
        let config = self.config.clone();
        let callback_client = self.coordinator.clone();
        let active_searches = Arc::clone(&self.active_searches);
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

            let outcome = match job.kind {
                SearchKind::Keyword => {
                    do_active_keyword_search(&dht, indexer_id, &job, config, cancel.clone()).await
                }
                SearchKind::Source => {
                    do_active_source_search(&dht, indexer_id, &job, cancel.clone()).await
                }
                SearchKind::Notes => Err(anyhow::anyhow!("notes search is not wired yet")),
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
                final_event.2,
            )
            .await
            {
                warn!("failed to report search completion: {error}");
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
        let mut publish_observability = self.publish_observability.lock().await.clone();
        publish_observability.log_file = Some(current_log_file_status(&config));
        let mut harvest_observability = self.harvest_observability.lock().await.clone();
        apply_queue_family_counts(&mut harvest_observability, queue_family_counts);

        Ok(IndexerStats {
            indexer_id: self.indexer_id,
            protocol: Protocol::Kad2,
            peers_connected: runtime
                .as_ref()
                .map(|runtime| runtime.dht.routing_table_size() as u32)
                .unwrap_or(0),
            crawl_rate,
            snoop_queue_depth: queue_depth,
            staging_queue_depth: 0,
            uptime_secs,
            nat: match runtime {
                Some(runtime) => Some(runtime.nat.status().await.snapshot()),
                None => None,
            },
            interface_report: Some(interface_report),
            publish_observability: Some(publish_observability),
            harvest_observability: Some(harvest_observability),
        })
    }

    async fn apply_config(&self, config: ConfigUpdate) -> Result<()> {
        let next: AgentNetworkingConfig = serde_json::from_value(config.config)
            .context("invalid config payload for overlord-agent-emule")?;
        // `/api/internal/config-update` requests restart only when the updated
        // networking shape changes the control endpoint; otherwise we reconcile
        // NAT/P2P runtime state in-process.
        if let NetworkingConfigApplyOutcome::RestartRequired =
            self.apply_networking_config_update(&next).await?
        {
            self.request_restart();
        }
        Ok(())
    }

    async fn seed_popular(&self, hashes: Vec<PopularHash>) -> Result<()> {
        let runtime = self.runtime.lock().await.clone();
        let Some(runtime) = runtime else {
            anyhow::bail!("agent networking is waiting for interface selection");
        };
        let source_publish_identity = source_publish_client_hash(self.indexer_id);
        seed_popular_impl(
            &runtime.dht,
            source_publish_identity,
            PublishSeedSource::ManualApi,
            hashes,
            &self.publish_observability,
        )
        .await
    }

    async fn flush_snoop(&self) -> Result<Vec<SnoopEntry>> {
        Ok(self.snoop_queue.lock().await.snapshot())
    }

    async fn interfaces(&self) -> Result<AgentNetworkReport> {
        Ok(self.interface_report().await)
    }
}

impl OverlordAgentEmule {
    async fn spawn_background_tasks(
        &self,
        runtime: &AgentNetworkRuntime,
        config: &EmuleAgentConfig,
    ) {
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let state_paths = self.state_paths.clone();
        let coordinator = self.coordinator.clone();
        let publish_observability = Arc::clone(&self.publish_observability);
        let source_publish_identity = source_publish_client_hash(self.indexer_id);
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !shutdown.load(Ordering::Relaxed) && !dht.is_bootstrapped() {
                match dht.bootstrap().await {
                    Ok(()) => {
                        if let Err(error) = persist_nodes_dat_for(&dht, &state_paths).await {
                            warn!("failed to persist nodes.dat after bootstrap: {error}");
                        }
                        if let Err(error) = seed_popular_from_coordinator_or_fallback(
                            &dht,
                            source_publish_identity,
                            &coordinator,
                            &publish_observability,
                        )
                        .await
                        {
                            debug!("post-bootstrap seeding failed: {error}");
                        }
                        break;
                    }
                    Err(error) => debug!("bootstrap retry failed: {error}"),
                }
                tokio::time::sleep(Duration::from_secs(BOOTSTRAP_RETRY_SECS)).await;
            }
        }));

        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let snoop_queue = Arc::clone(&self.snoop_queue);
        let harvest_observability = Arc::clone(&self.harvest_observability);
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let mut packets = dht.subscribe_packets();
            while !shutdown.load(Ordering::Relaxed) {
                match packets.recv().await {
                    Ok((packet, from)) => {
                        if let Err(error) = handle_unsolicited_packet(
                            &dht,
                            &snoop_queue,
                            &harvest_observability,
                            packet,
                            from,
                        )
                        .await
                        {
                            debug!("unsolicited packet handling failed: {error}");
                        }
                    }
                    Err(error) => {
                        debug!("packet subscription closed: {error}");
                        break;
                    }
                }
            }
        }));

        let coordinator = self.coordinator.clone();
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let snoop_queue = Arc::clone(&self.snoop_queue);
        let indexer_id = self.indexer_id;
        let passive_result_count = Arc::clone(&runtime.passive_result_count);
        let harvest_observability = Arc::clone(&self.harvest_observability);
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(PASSIVE_CRAWL_SECS)).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }
                let Some(request) = next_passive_keyword_request(&snoop_queue).await else {
                    let mut observability = harvest_observability.lock().await;
                    record_passive_keyword_replay_idle(&mut observability, Utc::now());
                    continue;
                };
                {
                    let mut observability = harvest_observability.lock().await;
                    record_passive_keyword_replay_start(&mut observability, &request, Utc::now());
                }
                info!(
                    "kad passive replay start target={} start_position={} restrictive_bytes={}",
                    request.target,
                    request.start_position,
                    request.restrictive_payload.len()
                );
                let mut stream = dht.search_keyword_request(request);
                let mut files = Vec::new();
                let mut replayed_results = 0usize;
                let mut batches_posted = 0usize;
                while let Some(result) = stream.next().await {
                    if let Ok(file) = map_search_result_for(&dht, &result) {
                        passive_result_count.fetch_add(1, Ordering::Relaxed);
                        replayed_results += 1;
                        files.push(file);
                        if files.len() >= PASSIVE_BATCH_SIZE {
                            let payload = ResultBatch {
                                job_id: None,
                                indexer_id,
                                protocol: Protocol::Kad2,
                                files: std::mem::take(&mut files),
                            };
                            if let Err(error) = coordinator.post_results(&payload).await {
                                warn!("failed to post passive result batch: {error}");
                                let mut observability = harvest_observability.lock().await;
                                record_passive_keyword_post_failure(
                                    &mut observability,
                                    Utc::now(),
                                    &error.to_string(),
                                );
                            } else {
                                batches_posted += 1;
                            }
                        }
                    }
                }
                if !files.is_empty() {
                    let payload = ResultBatch {
                        job_id: None,
                        indexer_id,
                        protocol: Protocol::Kad2,
                        files,
                    };
                    if let Err(error) = coordinator.post_results(&payload).await {
                        warn!("failed to post passive result batch: {error}");
                        let mut observability = harvest_observability.lock().await;
                        record_passive_keyword_post_failure(
                            &mut observability,
                            Utc::now(),
                            &error.to_string(),
                        );
                    } else {
                        batches_posted += 1;
                    }
                }
                {
                    let mut observability = harvest_observability.lock().await;
                    record_passive_keyword_replay_complete(
                        &mut observability,
                        Utc::now(),
                        replayed_results,
                        batches_posted,
                    );
                }
                info!(
                    "kad passive replay done results={} batches_posted={}",
                    replayed_results, batches_posted
                );
            }
        }));

        let coordinator = self.coordinator.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let snoop_queue = Arc::clone(&self.snoop_queue);
        let indexer_id = self.indexer_id;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(SNOOP_FLUSH_SECS)).await;
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(error) = flush_snoop_queue(&coordinator, indexer_id, &snoop_queue).await
                {
                    debug!("snoop flush failed: {error}");
                }
            }
        }));

        let coordinator = self.coordinator.clone();
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let republish_secs = config.p2p.kad.republish_interval_secs;
        let publish_observability = Arc::clone(&self.publish_observability);
        let source_publish_identity = source_publish_client_hash(self.indexer_id);
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(republish_secs)).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }
                if let Err(error) = seed_popular_from_coordinator_or_fallback(
                    &dht,
                    source_publish_identity,
                    &coordinator,
                    &publish_observability,
                )
                .await
                {
                    debug!("republish cycle failed: {error}");
                }
            }
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COORDINATOR_RECONNECT_SECS, EMULE_LARGE_FILE_SIZE_THRESHOLD, EmuleAgentConfig,
        OverlordAgentEmule, SYNTHETIC_POPULAR_SEEDS, apply_harvest_record, apply_networking_config,
        apply_publish_summary, apply_queue_family_counts, build_publish_batch_summary,
        empty_networking_config, emule_high_id_source_type, flush_snoop_queue, keyword_target,
        record_passive_keyword_post_failure, record_passive_keyword_replay_complete,
        record_passive_keyword_replay_idle, record_passive_keyword_replay_start,
        restore_snoop_queue, select_popular_hashes_for_seeding, significant_keyword_words,
        synthetic_file_hash, synthetic_popular_hashes,
    };
    use crate::{
        config::SnoopQueueConfig,
        paths::unique_test_dir,
        snoop_queue::{SnoopQueue, SnoopQueueFamilyCounts},
    };
    use axum::{
        Json, Router,
        extract::{Path as AxumPath, State},
        routing::{get, post},
    };
    use chrono::{TimeZone, Utc};
    use overlord_agent_common::{
        AgentInterfacesView, ConfigUpdate, CoordinatorClient, HashType, IndexerRegistration,
        IndexerService, KadHarvestObservability, PopularHash, Protocol, PublishCounters,
        PublishSeedSource, RegisterRequest, RegistrationResponse, SnoopEntry,
    };
    use overlord_agent_nat::{UPNP_MINIUPNPC_BACKEND, UPNP_RUPNP_BACKEND};
    use overlord_kad_dht::PublishAttemptStats;
    use overlord_kad_proto::SearchKeyReq;
    use std::{
        collections::HashSet,
        fs,
        net::SocketAddr,
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering, Ordering as AtomicOrdering},
        },
        time::Duration,
    };
    use tokio::sync::Mutex;
    use uuid::Uuid;

    #[derive(Clone)]
    struct MockCoordinatorState {
        restore_entries: Arc<Vec<SnoopEntry>>,
        flushed_entries: Arc<Mutex<Vec<SnoopEntry>>>,
        networking_view: Arc<Mutex<Option<AgentInterfacesView>>>,
        register_calls: Arc<AtomicUsize>,
    }

    #[derive(Debug, serde::Deserialize)]
    struct FlushPayload {
        indexer_id: Uuid,
        entries: Vec<SnoopEntry>,
    }

    async fn restore_handler(
        AxumPath(_indexer_id): AxumPath<Uuid>,
        State(state): State<MockCoordinatorState>,
    ) -> Json<Vec<SnoopEntry>> {
        Json(state.restore_entries.as_ref().clone())
    }

    async fn flush_handler(
        State(state): State<MockCoordinatorState>,
        Json(payload): Json<FlushPayload>,
    ) -> Json<serde_json::Value> {
        let mut entries = state.flushed_entries.lock().await;
        assert_eq!(
            payload.indexer_id,
            Uuid::from_u128(0x22222222222222222222222222222222)
        );
        *entries = payload.entries;
        Json(serde_json::json!({ "accepted": true }))
    }

    async fn register_handler(
        State(state): State<MockCoordinatorState>,
        Json(payload): Json<RegisterRequest>,
    ) -> Json<RegistrationResponse> {
        state.register_calls.fetch_add(1, AtomicOrdering::Relaxed);
        Json(RegistrationResponse {
            registered: IndexerRegistration {
                indexer_id: payload.indexer_id,
                protocol: payload.protocol,
                url: payload.url,
                hostname: payload.hostname,
                version: payload.version,
                registered_at: Utc::now(),
            },
        })
    }

    async fn agent_interfaces_handler(
        AxumPath(_indexer_id): AxumPath<Uuid>,
        State(state): State<MockCoordinatorState>,
    ) -> Json<AgentInterfacesView> {
        Json(
            state
                .networking_view
                .lock()
                .await
                .clone()
                .expect("networking view should be configured"),
        )
    }

    async fn spawn_mock_coordinator(
        restore_entries: Vec<SnoopEntry>,
    ) -> (SocketAddr, Arc<Mutex<Vec<SnoopEntry>>>) {
        let flushed_entries = Arc::new(Mutex::new(Vec::new()));
        let state = MockCoordinatorState {
            restore_entries: Arc::new(restore_entries),
            flushed_entries: Arc::clone(&flushed_entries),
            networking_view: Arc::new(Mutex::new(None)),
            register_calls: Arc::new(AtomicUsize::new(0)),
        };
        let app = Router::new()
            .route(
                "/api/internal/snoop-restore/{indexer_id}",
                get(restore_handler),
            )
            .route("/api/internal/snoop-flush", post(flush_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (addr, flushed_entries)
    }

    async fn spawn_full_mock_coordinator(
        bind_addr: SocketAddr,
        view: AgentInterfacesView,
    ) -> Arc<AtomicUsize> {
        let register_calls = Arc::new(AtomicUsize::new(0));
        let state = MockCoordinatorState {
            restore_entries: Arc::new(Vec::new()),
            flushed_entries: Arc::new(Mutex::new(Vec::new())),
            networking_view: Arc::new(Mutex::new(Some(view))),
            register_calls: Arc::clone(&register_calls),
        };
        let app = Router::new()
            .route("/api/internal/register", post(register_handler))
            .route(
                "/api/agents/{indexer_id}/interfaces",
                get(agent_interfaces_handler),
            )
            .route(
                "/api/internal/snoop-restore/{indexer_id}",
                get(restore_handler),
            )
            .route("/api/internal/snoop-flush", post(flush_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        register_calls
    }

    fn build_test_config(temp_root: &Path, coordinator_url: String) -> EmuleAgentConfig {
        let state_dir = temp_root.join("state");
        fs::create_dir_all(&state_dir).unwrap();

        let mut config = EmuleAgentConfig::default();
        config.coordinator.url = coordinator_url;
        config.agent.state_dir = state_dir.display().to_string();
        config.agent.indexer_id_path = state_dir
            .join("overlord-agent-emule.indexer-id")
            .display()
            .to_string();
        config.control.bind_ip = Some("127.0.0.1".to_string());
        config.control.selection_confirmed = true;
        config.control.listen_port = 0;
        config.p2p.bind_ip = Some("127.0.0.1".to_string());
        config.p2p.selection_confirmed = true;
        config.p2p.kad.listen_port = 0;
        config.p2p.ed2k.listen_port = 0;
        config.nat.p2p.enabled = false;
        config
    }

    #[test]
    fn significant_words_ignore_short_tokens() {
        assert_eq!(
            significant_keyword_words("A torino x train"),
            vec!["torino".to_string(), "train".to_string()]
        );
    }

    #[test]
    fn keyword_target_is_stable() {
        assert_eq!(
            hex::encode(keyword_target("Torino Train").0),
            "b2bc3aa39f375069e7c27eb83ce6baf3"
        );
    }

    #[test]
    fn empty_networking_config_prefers_miniupnpc_only() {
        assert_eq!(
            empty_networking_config().nat.p2p.backend_order,
            vec![UPNP_MINIUPNPC_BACKEND.to_string()]
        );
    }

    #[test]
    fn apply_networking_config_preserves_explicit_backend_order() {
        let mut config = EmuleAgentConfig::default();
        let mut desired = empty_networking_config();
        desired.nat.p2p.backend_order = vec![UPNP_RUPNP_BACKEND.to_string()];

        apply_networking_config(&mut config, &desired);

        assert_eq!(
            config.nat.p2p.backend_order,
            vec![UPNP_RUPNP_BACKEND.to_string()]
        );
    }

    #[test]
    fn restart_required_only_for_control_endpoint_changes() {
        let old = empty_networking_config();

        let mut nat_only = old.clone();
        nat_only.nat.p2p.enabled = true;
        nat_only.nat.p2p.backend_order = vec![UPNP_RUPNP_BACKEND.to_string()];
        assert!(!OverlordAgentEmule::restart_required_for_networking_change(
            &old, &nat_only
        ));

        let mut control_bind_ip = old.clone();
        control_bind_ip.control.bind_ip = Some("127.0.0.1".to_string());
        control_bind_ip.control.selection_confirmed = true;
        assert!(OverlordAgentEmule::restart_required_for_networking_change(
            &old,
            &control_bind_ip
        ));

        let mut control_port = old.clone();
        control_port.control.listen_port = 14_001;
        assert!(OverlordAgentEmule::restart_required_for_networking_change(
            &old,
            &control_port
        ));

        let mut p2p_port = old.clone();
        p2p_port.p2p.kad.listen_port = 41_999;
        assert!(!OverlordAgentEmule::restart_required_for_networking_change(
            &old, &p2p_port
        ));
    }

    #[test]
    fn synthetic_dataset_contains_expected_entry_count() {
        assert_eq!(SYNTHETIC_POPULAR_SEEDS.len(), 40);
    }

    #[test]
    fn synthetic_hashes_are_deterministic() {
        let seed = &SYNTHETIC_POPULAR_SEEDS[0];
        assert_eq!(synthetic_file_hash(0, seed), synthetic_file_hash(0, seed));
    }

    #[test]
    fn synthetic_hashes_are_unique() {
        let hashes = synthetic_popular_hashes();
        let unique = hashes
            .iter()
            .map(|entry| match &entry.hash {
                HashType::Ed2k(hash) => hash.clone(),
            })
            .collect::<HashSet<_>>();
        assert_eq!(unique.len(), hashes.len());
    }

    #[test]
    fn seeding_prefers_coordinator_hashes_when_present() {
        let coordinator_hashes = vec![PopularHash {
            hash: HashType::Ed2k("00112233445566778899aabbccddeeff".to_string()),
            canonical_name: "ubuntu linux".to_string(),
            size: 3_221_225_472,
            source_count: 42,
        }];

        let (source, selected) = select_popular_hashes_for_seeding(coordinator_hashes.clone());

        assert_eq!(source, PublishSeedSource::Coordinator);
        assert_eq!(selected, coordinator_hashes);
    }

    #[test]
    fn seeding_falls_back_to_synthetic_hashes_when_empty() {
        let (source, selected) = select_popular_hashes_for_seeding(Vec::new());

        assert_eq!(source, PublishSeedSource::SyntheticFallback);
        assert_eq!(selected.len(), SYNTHETIC_POPULAR_SEEDS.len());
    }

    #[test]
    fn emule_source_type_matches_large_file_convention() {
        assert_eq!(emule_high_id_source_type(123), 1);
        assert_eq!(
            emule_high_id_source_type(EMULE_LARGE_FILE_SIZE_THRESHOLD + 1),
            4
        );
    }

    #[test]
    fn build_publish_batch_summary_marks_success_timestamp_when_acked() {
        let completed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 0, 0).unwrap();
        let summary = build_publish_batch_summary(
            PublishSeedSource::Coordinator,
            40,
            PublishAttemptStats {
                closest_contacts_considered: 10,
                attempted_contacts: 10,
                acked_contacts: 6,
                timed_out_contacts: 3,
            },
            completed_at,
        );

        assert_eq!(summary.failed_contacts, 4);
        assert_eq!(summary.last_success_at, Some(completed_at));
    }

    #[test]
    fn apply_publish_summary_accumulates_counters() {
        let completed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 5, 0).unwrap();
        let summary = build_publish_batch_summary(
            PublishSeedSource::SyntheticFallback,
            40,
            PublishAttemptStats {
                closest_contacts_considered: 8,
                attempted_contacts: 8,
                acked_contacts: 5,
                timed_out_contacts: 2,
            },
            completed_at,
        );
        let mut counters = PublishCounters::default();

        apply_publish_summary(&mut counters, &summary);

        assert_eq!(counters.batches, 1);
        assert_eq!(counters.published_items, 40);
        assert_eq!(counters.attempted_contacts, 8);
        assert_eq!(counters.acked_contacts, 5);
        assert_eq!(counters.failed_contacts, 3);
        assert_eq!(counters.timed_out_contacts, 2);
        assert_eq!(counters.last_batch_at, Some(completed_at));
        assert_eq!(counters.last_success_at, Some(completed_at));
    }

    #[test]
    fn apply_harvest_record_tracks_keyword_request_shape() {
        let mut observability = KadHarvestObservability::default();
        let entry = SnoopEntry::Keyword {
            logical_key: "keyword:00112233445566778899aabbccddeeff:8000:aabb".to_string(),
            target: "00112233445566778899aabbccddeeff".to_string(),
            start_position: 0x8000,
            restrictive_payload_hex: Some("aabb".to_string()),
            hit_count: 1,
            first_seen: Utc.with_ymd_and_hms(2026, 3, 22, 19, 58, 0).unwrap(),
            last_seen: Utc.with_ymd_and_hms(2026, 3, 22, 19, 58, 0).unwrap(),
            last_drained_at: None,
        };

        apply_harvest_record(
            &mut observability,
            "127.0.0.1:41000".parse().unwrap(),
            &entry,
            true,
        );

        assert_eq!(observability.keyword_requests.observed_requests, 1);
        assert_eq!(observability.keyword_requests.unique_shapes_observed, 1);
        assert_eq!(
            observability.keyword_requests.last_target.as_deref(),
            Some("00112233445566778899aabbccddeeff")
        );
        assert_eq!(
            observability.keyword_requests.last_start_position,
            Some(0x8000)
        );
        assert_eq!(
            observability.keyword_requests.last_restrictive_bytes,
            Some(2)
        );
        assert_eq!(
            observability.keyword_requests.last_from.as_deref(),
            Some("127.0.0.1:41000")
        );
    }

    #[test]
    fn apply_queue_family_counts_updates_live_depths() {
        let mut observability = KadHarvestObservability::default();

        apply_queue_family_counts(
            &mut observability,
            SnoopQueueFamilyCounts {
                keyword: 2,
                source: 3,
                notes: 1,
            },
        );

        assert_eq!(observability.keyword_requests.queued_entries, 2);
        assert_eq!(observability.source_requests.queued_entries, 3);
        assert_eq!(observability.notes_requests.queued_entries, 1);
    }

    #[test]
    fn passive_keyword_replay_observability_tracks_cycle_lifecycle() {
        let mut observability = KadHarvestObservability::default();
        let request = SearchKeyReq {
            target: "00112233445566778899aabbccddeeff".parse().unwrap(),
            start_position: 0x8000,
            restrictive_payload: vec![0xAA, 0xBB, 0xCC],
        };
        let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 20, 0, 0).unwrap();
        let idle_at = Utc.with_ymd_and_hms(2026, 3, 22, 20, 1, 0).unwrap();
        let completed_at = Utc.with_ymd_and_hms(2026, 3, 22, 20, 2, 0).unwrap();
        let failed_at = Utc.with_ymd_and_hms(2026, 3, 22, 20, 3, 0).unwrap();

        record_passive_keyword_replay_idle(&mut observability, idle_at);
        record_passive_keyword_replay_start(&mut observability, &request, started_at);
        record_passive_keyword_replay_complete(&mut observability, completed_at, 7, 2);
        record_passive_keyword_post_failure(&mut observability, failed_at, "post failed");

        assert_eq!(observability.passive_keyword_replay.idle_cycles, 1);
        assert_eq!(observability.passive_keyword_replay.started_cycles, 1);
        assert_eq!(observability.passive_keyword_replay.completed_cycles, 1);
        assert_eq!(observability.passive_keyword_replay.emitted_results, 7);
        assert_eq!(observability.passive_keyword_replay.posted_batches, 2);
        assert_eq!(observability.passive_keyword_replay.post_failures, 1);
        assert_eq!(
            observability.passive_keyword_replay.last_target.as_deref(),
            Some("00112233445566778899aabbccddeeff")
        );
        assert_eq!(
            observability.passive_keyword_replay.last_start_position,
            Some(0x8000)
        );
        assert_eq!(
            observability.passive_keyword_replay.last_restrictive_bytes,
            Some(3)
        );
        assert_eq!(observability.passive_keyword_replay.last_result_count, 7);
        assert_eq!(observability.passive_keyword_replay.last_batches_posted, 2);
        assert_eq!(
            observability.passive_keyword_replay.last_error.as_deref(),
            Some("post failed")
        );
        assert_eq!(
            observability.passive_keyword_replay.last_completed_at,
            Some(completed_at)
        );
        assert_eq!(
            observability.passive_keyword_replay.last_error_at,
            Some(failed_at)
        );
    }

    #[tokio::test]
    async fn restore_and_flush_preserve_last_drained_at() {
        let restored_entry = SnoopEntry::Keyword {
            logical_key: "keyword:00112233445566778899aabbccddeeff:8000:aabb".to_string(),
            target: "00112233445566778899aabbccddeeff".to_string(),
            start_position: 0x8000,
            restrictive_payload_hex: Some("aabb".to_string()),
            hit_count: 4,
            first_seen: Utc.with_ymd_and_hms(2026, 3, 21, 10, 0, 0).unwrap(),
            last_seen: Utc.with_ymd_and_hms(2026, 3, 21, 10, 5, 0).unwrap(),
            last_drained_at: Some(Utc.with_ymd_and_hms(2026, 3, 21, 10, 6, 0).unwrap()),
        };
        let (addr, flushed_entries) = spawn_mock_coordinator(vec![restored_entry.clone()]).await;
        let coordinator = CoordinatorClient::new(&format!("http://{addr}")).unwrap();
        let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig::default())));
        let indexer_id = Uuid::from_u128(0x22222222222222222222222222222222);

        restore_snoop_queue(&coordinator, indexer_id, &queue).await;
        flush_snoop_queue(&coordinator, indexer_id, &queue)
            .await
            .unwrap();

        let flushed_entries = flushed_entries.lock().await.clone();
        assert_eq!(flushed_entries, vec![restored_entry]);
    }

    #[tokio::test]
    async fn start_runs_runtime_without_coordinator() {
        let temp_root = unique_test_dir("overlord-agent-emule-offline-start");
        let config = build_test_config(&temp_root, "http://127.0.0.1:9".to_string());
        let agent = OverlordAgentEmule::new(config).await.unwrap();

        agent.start().await.unwrap();
        assert!(agent.runtime.lock().await.is_some());
        let stats = agent.stats().await.unwrap();
        assert!(
            stats
                .interface_report
                .as_ref()
                .is_some_and(|report| report.p2p.ready)
        );

        agent.stop().await.unwrap();
        fs::remove_dir_all(&temp_root).unwrap();
    }

    #[tokio::test]
    async fn serve_continues_when_initial_coordinator_registration_fails() {
        let temp_root = unique_test_dir("overlord-agent-emule-offline-serve");
        let config = build_test_config(&temp_root, "http://127.0.0.1:9".to_string());
        let agent = Arc::new(OverlordAgentEmule::new(config).await.unwrap());
        agent.start().await.unwrap();

        let serve_agent = Arc::clone(&agent);
        let serve_task = tokio::spawn(async move { serve_agent.serve().await.unwrap() });
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!serve_task.is_finished());
        serve_task.abort();
        let _ = serve_task.await;

        fs::remove_dir_all(&temp_root).unwrap();
    }

    #[tokio::test]
    async fn reconnect_loop_registers_after_startup_fallback() {
        let probe_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let coordinator_addr = probe_listener.local_addr().unwrap();
        drop(probe_listener);

        let temp_root = unique_test_dir("overlord-agent-emule-reconnect");
        let config = build_test_config(&temp_root, format!("http://{coordinator_addr}"));
        let networking_view = AgentInterfacesView {
            registration: IndexerRegistration {
                indexer_id: Uuid::nil(),
                protocol: Protocol::Kad2,
                url: String::new(),
                hostname: String::new(),
                version: String::new(),
                registered_at: Utc::now(),
            },
            report: None,
            config: OverlordAgentEmule::networking_config(&config),
            nat: None,
            publish_observability: None,
            harvest_observability: None,
            last_error: None,
        };
        let agent = Arc::new(OverlordAgentEmule::new(config).await.unwrap());
        agent.start().await.unwrap();

        let serve_agent = Arc::clone(&agent);
        let serve_task = tokio::spawn(async move { serve_agent.serve().await.unwrap() });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let register_calls = spawn_full_mock_coordinator(coordinator_addr, networking_view).await;
        tokio::time::timeout(
            Duration::from_secs(COORDINATOR_RECONNECT_SECS + 10),
            async {
                loop {
                    if register_calls.load(AtomicOrdering::Relaxed) > 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        )
        .await
        .unwrap();

        agent.request_restart();
        let _ = tokio::time::timeout(Duration::from_secs(15), serve_task)
            .await
            .unwrap()
            .unwrap();

        fs::remove_dir_all(&temp_root).unwrap();
    }

    #[tokio::test]
    async fn apply_config_without_endpoint_change_reconciles_in_place() {
        let temp_root = unique_test_dir("overlord-agent-emule-config-update");
        let config = build_test_config(&temp_root, "http://127.0.0.1:9".to_string());
        let agent = OverlordAgentEmule::new(config).await.unwrap();
        agent.start().await.unwrap();

        let current = agent.config.read().await.clone();
        let mut desired = OverlordAgentEmule::networking_config(&current);
        desired.nat.p2p.enabled = true;
        desired.nat.p2p.backend_order = vec![UPNP_RUPNP_BACKEND.to_string()];

        agent
            .apply_config(ConfigUpdate {
                protocol: Protocol::Kad2,
                config: serde_json::to_value(desired).unwrap(),
            })
            .await
            .unwrap();

        assert!(!agent.restart_requested.load(Ordering::SeqCst));
        assert!(agent.runtime.lock().await.is_some());

        agent.stop().await.unwrap();
        fs::remove_dir_all(&temp_root).unwrap();
    }

    #[tokio::test]
    async fn apply_config_with_control_endpoint_change_requests_restart() {
        let temp_root = unique_test_dir("overlord-agent-emule-control-endpoint-update");
        let config = build_test_config(&temp_root, "http://127.0.0.1:9".to_string());
        let agent = OverlordAgentEmule::new(config).await.unwrap();
        agent.start().await.unwrap();

        let current = agent.config.read().await.clone();
        let mut desired = OverlordAgentEmule::networking_config(&current);
        desired.control.listen_port = 13_302;

        agent
            .apply_config(ConfigUpdate {
                protocol: Protocol::Kad2,
                config: serde_json::to_value(desired).unwrap(),
            })
            .await
            .unwrap();

        assert!(agent.restart_requested.load(Ordering::SeqCst));

        agent.stop().await.unwrap();
        fs::remove_dir_all(&temp_root).unwrap();
    }

    #[tokio::test]
    async fn apply_config_with_p2p_endpoint_change_reconciles_in_place() {
        let temp_root = unique_test_dir("overlord-agent-emule-p2p-endpoint-update");
        let config = build_test_config(&temp_root, "http://127.0.0.1:9".to_string());
        let agent = OverlordAgentEmule::new(config).await.unwrap();
        agent.start().await.unwrap();

        let current = agent.config.read().await.clone();
        let mut desired = OverlordAgentEmule::networking_config(&current);
        desired.p2p.kad.listen_port = 42_000;

        agent
            .apply_config(ConfigUpdate {
                protocol: Protocol::Kad2,
                config: serde_json::to_value(desired).unwrap(),
            })
            .await
            .unwrap();

        assert!(!agent.restart_requested.load(Ordering::SeqCst));
        assert!(agent.runtime.lock().await.is_some());

        agent.stop().await.unwrap();
        fs::remove_dir_all(&temp_root).unwrap();
    }

    #[tokio::test]
    async fn stop_succeeds_when_shutdown_flush_cannot_reach_coordinator() {
        let temp_root = unique_test_dir("overlord-agent-emule-shutdown-flush");
        let config = build_test_config(&temp_root, "http://127.0.0.1:9".to_string());
        let agent = OverlordAgentEmule::new(config).await.unwrap();

        agent.start().await.unwrap();
        agent.stop().await.unwrap();

        fs::remove_dir_all(&temp_root).unwrap();
    }
}
