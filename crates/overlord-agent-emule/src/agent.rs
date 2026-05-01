use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use md4::{Digest, Md4};
use overlord_agent_nat::{
    AgentControlConfig, AgentEd2kConfig, AgentInterface, AgentKadConfig, AgentNatConfig,
    AgentNatP2pConfig, AgentNetworkReport, AgentNetworkingConfig, AgentP2pConfig,
    InterfaceBindingSelection, InterfaceSelectionState, MappingExposure, MappingSpec, NatManager,
    NatManagerBuilder, NatStatus, ResolvedInterfaceBindingReport, TransportProtocol,
    build_interface_binding_report, built_in_upnp_port_mapping_providers,
    default_upnp_backend_order, detect_interfaces, recommend_interface, resolve_bind_ip,
};
use rand::seq::SliceRandom;
use serde::Deserialize;
use serde_json::Value;
use sha1::Sha1;
use tokio::{
    net::TcpListener,
    sync::{Mutex, Notify, RwLock, Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use uuid::Uuid;

use overlord_agent_common::{
    AgentActivityState, AgentInterfacesView, ConfigUpdate, CoordinatorClient, FileRecord,
    HarvestFamily, HarvestReplayContext, HarvestReplayRecord, HashType, IndexerServer,
    IndexerService, IndexerStats, KadHarvestObservability, KadPassiveReplayTierSummary,
    KadPublishObservability, KadRpcObservability, KadRpcResponseOpcodeObservability,
    KadRpcTrackerBucketObservability, KadRpcWorkClassObservability, PopularHash, Protocol,
    PublishSeedSource, RegisterRequest, ResultBatch, RunningIndexerServer, SearchEventStatus,
    SearchJob, SearchKind, SnoopEntry, SnoopObservation,
};
use overlord_kad_dht::{
    DhtConfig, DhtNode, PublishAttemptStats, ReceivedKadPacket, RpcClassBudgetConfig,
    RpcObservabilitySnapshot, RpcWorkClass,
};
use overlord_kad_proto::{
    Ed2kHash, KadPacket, KadUdpKey, NodeId, SearchKeyReq, SearchNotesReq, SearchSourceReq, Tag,
    constants::{K, opcode},
    packet::ContactEntry,
};
use overlord_kad_routing::{Contact, ContactType};

use crate::config::{Ed2kUploadQueuePolicyConfig, EmuleAgentConfig};
use crate::ed2k_server::{
    Ed2kCallbackRequestOptions, Ed2kFoundSource, Ed2kServerLoopOptions, Ed2kServerSearchHandle,
    Ed2kServerState, Ed2kSourceSearchOptions, Ed2kUdpSourceSearchOptions,
    new_ed2k_server_search_channel, request_callback_on_server,
    request_callback_via_background_session, run_ed2k_server_loop, search_source_servers,
    search_source_udp_servers, search_source_via_background_session,
};
use crate::ed2k_tcp::{
    Ed2kHelloIdentity, Ed2kListenerOptions, Ed2kPeerDownloadOptions, Ed2kPeerDownloadOutcome,
    Ed2kSecureIdent, FirewallCheckUdpRequest, download_file_from_peer, dump_ed2k_tcp_download_meta,
    emule_connect_options, enrich_hello_identity, request_udp_firewall_check, run_ed2k_listener,
};
use crate::ed2k_transfer::{
    Ed2kCallbackIntent, Ed2kLocalIngestSummary, Ed2kResumeManifest, Ed2kSharedCatalog,
    Ed2kSourceHint, Ed2kTransferRuntime, Ed2kUploadQueueConfig, new_transfer_job,
};
use crate::kad_firewall::{
    ExternalPortDiscoveryOutcome, FirewallUdpPacketOutcome, FirewalledResponseOutcome,
    KadFirewallState,
};
use crate::kad_store::{KadLocalStore, KadLocalStoreConfig};
use crate::logging::current_log_file_status;
use crate::snoop_queue::SnoopQueue;

mod activity;
mod ed2k_runtime;
mod ed2k_search;
mod kad_runtime;
mod lifecycle;
mod networking;
mod passive_replay;
mod publish;
mod search;
mod snoop;

use self::activity::{
    ACTIVITY_KEY_BOOTSTRAPPING, ACTIVITY_KEY_FLUSHING_SNOOPS, ACTIVITY_KEY_RECONFIGURING,
    ACTIVITY_KEY_STARTING, AgentActivityTracker, active_ed2k_download_key, active_search_key,
    begin_agent_activity, clear_agent_degraded_activity, finish_agent_activity,
    new_activity_snapshot, passive_replay_activity_context, passive_replay_key,
    publish_activity_key, record_agent_degraded_activity, runtime_activity_error,
    search_activity_context, update_agent_activity_error, update_agent_activity_progress,
};
use self::ed2k_runtime::{
    Ed2kSourceEndpointKey, direct_download_candidate_sources, ed2k_source_attempt_key,
    ed2k_source_endpoint_key, is_retryable_direct_download_error,
    manifest_has_ed2k_transfer_progress, new_direct_ed2k_source_count,
    plaintext_fallback_for_obfuscated_source, should_skip_no_progress_source_requery,
    sort_native_ed2k_download_sources,
};
use self::ed2k_search::{
    ActiveEd2kSearchContext, collect_kad_ed2k_sources, do_active_ed2k_keyword_search,
    do_active_ed2k_source_search, ed2k_download_source_server_attempt_budget,
    ed2k_source_search_timeout, exact_ed2k_hash_query_token, resolve_hash_only_ed2k_metadata,
};
#[cfg(test)]
use self::ed2k_search::{
    ed2k_keyword_server_attempt_budget, kad_source_result_to_ed2k_found_source,
    select_ed2k_keyword_metadata, select_kad_keyword_metadata,
};
use self::kad_runtime::{
    add_contact_from_hello, build_hello_request, build_hello_response, current_tcp_firewalled,
    should_request_hello_response_ack,
};
#[cfg(test)]
use self::kad_runtime::{
    build_kad_hello_request_tags, build_kad_hello_response_tags, parse_kad_hello_metadata,
};
use self::lifecycle::{
    AgentStatePaths, ensure_parent_dir, load_or_create_indexer_id, load_or_create_node_id,
    load_or_create_udp_key, persist_nodes_dat_for, random_routing_refresh_target,
    read_optional_bytes, resolved_socket_addr,
};
#[cfg(test)]
use self::networking::empty_networking_config;
use self::networking::{
    apply_networking_config, p2p_interface_reconcile_target, persist_networking_config,
};
use self::passive_replay::{
    PassiveReplaySelection, apply_queue_family_counts, next_passive_replay_request,
    next_passive_replay_request_for_family, passive_replay_thin_result_threshold,
    passive_replay_tier_contact_limits, record_passive_replay_complete,
    record_passive_replay_enqueue_wait, record_passive_replay_idle_for_worker,
    record_passive_replay_outcome, record_passive_replay_post_failure,
    record_passive_replay_post_latency, record_passive_replay_start,
    try_acquire_passive_replay_gate,
};
#[cfg(test)]
use self::passive_replay::{apply_harvest_record, record_passive_replay_idle};
#[cfg(test)]
use self::publish::{apply_publish_summary, build_publish_batch_summary};
use self::publish::{
    build_notes_publish_tags, build_source_publish_tags, effective_publish_counters,
    load_or_create_ed2k_user_hash, record_publish_summaries, set_synthetic_publish_queue_depth,
    source_publish_client_hash, update_publish_progress,
};
#[cfg(test)]
use self::publish::{emule_high_id_source_type, normalize_ed2k_user_hash_markers};
use self::search::{
    SearchRunStats, do_active_keyword_search, do_active_notes_search, do_active_source_search,
    emit_search_event, map_note_result, map_search_result_for, map_source_result,
};
use self::snoop::{
    build_keyword_snoop_entry, build_notes_snoop_entry, build_source_snoop_entry,
    flush_snoop_queue, record_snoop_entry, restore_snoop_queue,
};

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

struct NativeDirectDownloadOutcome {
    completed: bool,
    accepted_incomplete_peers: u32,
    last_error: Option<anyhow::Error>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnrichEd2kDownloadSource {
    ip: Ipv4Addr,
    #[serde(alias = "tcp_port")]
    tcp_port: u16,
    #[serde(default, alias = "client_id")]
    client_id: Option<u32>,
    #[serde(default, alias = "low_id")]
    low_id: Option<bool>,
    #[serde(default, alias = "obfuscation_options")]
    obfuscation_options: Option<u8>,
    #[serde(default, alias = "user_hash")]
    user_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnrichEd2kDownloadRequest {
    kind: String,
    #[serde(alias = "file_hash")]
    file_hash: String,
    #[serde(default, alias = "file_name", alias = "canonical_name")]
    file_name: Option<String>,
    #[serde(default, alias = "file_size")]
    file_size: Option<u64>,
    #[serde(default)]
    sources: Vec<EnrichEd2kDownloadSource>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IngestLocalFileRequest {
    #[serde(alias = "source_path", alias = "file_path")]
    source_path: String,
    #[serde(default, alias = "canonical_name", alias = "file_name")]
    canonical_name: Option<String>,
}

impl EnrichEd2kDownloadSource {
    fn into_found_source(self, file_hash: Ed2kHash) -> Result<Ed2kFoundSource> {
        let user_hash = self
            .user_hash
            .map(|value| -> Result<[u8; 16]> {
                let bytes = hex::decode(&value)
                    .with_context(|| format!("invalid source user hash {value}"))?;
                let bytes: [u8; 16] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("source user hash must be 16 bytes"))?;
                Ok(bytes)
            })
            .transpose()?;
        Ok(Ed2kFoundSource {
            file_hash,
            ip: self.ip,
            tcp_port: self.tcp_port,
            client_id: self.client_id.unwrap_or_else(|| u32::from(self.ip)),
            low_id: self.low_id.unwrap_or(false),
            obfuscated: self.obfuscation_options.is_some(),
            obfuscation_options: self.obfuscation_options,
            user_hash,
            source_server: None,
        })
    }
}

impl EnrichEd2kDownloadRequest {
    fn canonical_name(&self) -> String {
        self.file_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .unwrap_or_else(|| hash_only_ed2k_placeholder_name(&self.file_hash))
    }

    fn file_size_or_unknown(&self) -> u64 {
        self.file_size.unwrap_or(0)
    }
}

impl IngestLocalFileRequest {
    fn canonical_name(&self) -> Result<String> {
        self.canonical_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .ok_or_else(|| anyhow::anyhow!("local ingest payload requires canonicalName"))
    }
}

fn hash_only_ed2k_placeholder_name(file_hash: &str) -> String {
    format!("ed2k-{file_hash}.bin")
}

fn is_hash_only_ed2k_placeholder_name(name: &str, file_hash: &str) -> bool {
    name.eq_ignore_ascii_case(&hash_only_ed2k_placeholder_name(file_hash))
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

struct NativeDirectDownloadOptions {
    bind_ip: Ipv4Addr,
    hello_identity: Ed2kHelloIdentity,
    secure_ident: Arc<Ed2kSecureIdent>,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    file_hash_hex: String,
    file_name: String,
    file_size: u64,
    sources: Vec<Ed2kFoundSource>,
    connect_timeout: Duration,
    max_parallel_download_peers: usize,
}

impl OverlordAgentEmule {
    fn ed2k_upload_queue_config(config: &Ed2kUploadQueuePolicyConfig) -> Ed2kUploadQueueConfig {
        Ed2kUploadQueueConfig {
            active_slots: config.active_slots,
            waiting_capacity: config.waiting_capacity,
            waiting_timeout: Duration::from_secs(config.waiting_timeout_secs),
            granted_timeout: Duration::from_secs(config.granted_timeout_secs),
            upload_timeout: Duration::from_secs(config.upload_timeout_secs),
        }
    }

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
            let effective_desired = guard.effective_coordinator_networking(desired);
            let old_networking = Self::networking_config(&guard);
            if old_networking == effective_desired {
                return Ok(NetworkingConfigApplyOutcome::Unchanged);
            }

            apply_networking_config(&mut guard, &effective_desired);
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

    async fn reconcile_p2p_runtime_if_interface_moved(&self) -> Result<()> {
        let config = self.config.read().await.clone();
        if !config.p2p.selection_confirmed {
            return Ok(());
        }
        if config
            .p2p
            .bind_ip
            .as_deref()
            .is_some_and(|bind_ip| !bind_ip.trim().is_empty())
        {
            return Ok(());
        }

        let Some(bind_iface) = config
            .p2p
            .bind_iface
            .as_deref()
            .filter(|bind_iface| !bind_iface.trim().is_empty())
        else {
            return Ok(());
        };
        let Some(runtime_bind_ip) = self
            .runtime
            .lock()
            .await
            .as_ref()
            .map(|runtime| runtime.bind_ip)
        else {
            return Ok(());
        };

        let interfaces = detect_interfaces().unwrap_or_default();
        let Some(next_bind_ip) =
            p2p_interface_reconcile_target(&config, &interfaces, runtime_bind_ip)
        else {
            return Ok(());
        };

        info!(
            "p2p bind interface resolved to a new IPv4 address; reconciling runtime bind_iface={} old_bind_ip={} new_bind_ip={}",
            bind_iface, runtime_bind_ip, next_bind_ip
        );
        self.reconcile_runtime().await
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
        let bind_ipv4 = bind_ip
            .parse::<Ipv4Addr>()
            .with_context(|| format!("bind_ip is not a valid IPv4 address: {bind_ip}"))?;
        let node_id = load_or_create_node_id(&self.state_paths.node_id_path)?;
        let udp_key = load_or_create_udp_key(&self.state_paths.udp_key_path)?;
        let ed2k_secure_ident =
            Ed2kSecureIdent::load_or_create(&self.state_paths.ed2k_secure_ident_path)?;
        let bind_addr = resolved_socket_addr(config.p2p.kad.listen_port, Some(bind_ip))
            .context("invalid p2p.kad.listen_port")?;
        let ed2k_bind_addr = resolved_socket_addr(config.p2p.ed2k.listen_port, Some(bind_ip))
            .context("invalid p2p.ed2k.listen_port")?;
        let nodes_dat = read_optional_bytes(&self.state_paths.nodes_dat_path)?;
        let nodes_text = (!config.p2p.kad.bootstrap_nodes.is_empty())
            .then(|| config.p2p.kad.bootstrap_nodes.join("\n"));

        let dht = DhtNode::new(DhtConfig {
            bind_addr,
            node_id,
            max_routing_table_size: 12_000,
            bootstrap_min_routing_contacts: config.p2p.kad.bootstrap_min_routing_contacts,
            max_concurrent_searches: 5,
            search_timeout: Duration::from_secs(config.p2p.kad.search_timeout_secs),
            store_timeout: Duration::from_secs(config.p2p.kad.store_timeout_secs),
            republish_interval: Duration::from_secs(config.p2p.kad.republish_interval_secs),
            publish_contact_fanout: config.p2p.kad.publish_contact_fanout,
            max_outbound_pps: config.p2p.kad.max_outbound_pps,
            class_budgets: RpcClassBudgetConfig {
                interactive_max_outbound_pps: config.p2p.kad.interactive_max_outbound_pps,
                harvest_max_outbound_pps: config.p2p.kad.harvest_max_outbound_pps,
                maintenance_max_outbound_pps: config.p2p.kad.maintenance_max_outbound_pps,
                publish_max_outbound_pps: config.p2p.kad.publish_max_outbound_pps,
            },
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
        let ed2k_listener =
            Arc::new(TcpListener::bind(ed2k_bind_addr).await.with_context(|| {
                format!("failed to bind eD2k TCP listener on {ed2k_bind_addr}")
            })?);
        let (ed2k_server_search, ed2k_server_search_inbox) =
            new_ed2k_server_search_channel(ED2K_BACKGROUND_SEARCH_QUEUE_CAPACITY);
        let ed2k_transfer = Arc::new(Ed2kTransferRuntime::load_or_create_with_upload_queue(
            &self.state_paths.ed2k_transfer_root,
            Self::ed2k_upload_queue_config(&config.p2p.ed2k.upload_queue),
        )?);
        ed2k_transfer
            .replace_catalog_hints(&synthetic_popular_hashes())
            .await;
        let ed2k_shared_catalog = ed2k_transfer.shared_catalog();

        Ok(AgentNetworkRuntime {
            bind_ip: bind_ipv4,
            dht,
            ed2k_listener,
            ed2k_shared_catalog,
            ed2k_transfer,
            ed2k_server_search,
            ed2k_server_search_inbox: Arc::new(Mutex::new(Some(ed2k_server_search_inbox))),
            ed2k_server_state: Arc::new(RwLock::new(Ed2kServerState::default())),
            ed2k_secure_ident: Arc::new(ed2k_secure_ident),
            nat,
            kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
            tasks: Arc::new(Mutex::new(Vec::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            passive_result_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            passive_replay_gate: Arc::new(Semaphore::new(PASSIVE_REPLAY_CONCURRENCY)),
        })
    }
}

#[derive(Debug, Default)]
struct PassiveReplayRunOutcome {
    result_count: usize,
    batch_count: usize,
    tier_summaries: Vec<KadPassiveReplayTierSummary>,
    last_post_error: Option<String>,
}

struct PassiveReplayContext<'a> {
    dht: &'a DhtNode,
    coordinator: &'a CoordinatorClient,
    indexer_id: Uuid,
    replay_context: &'a HarvestReplayContext,
    max_phase2_fanout: usize,
    source_stop_after_results: usize,
    passive_result_count: &'a Arc<std::sync::atomic::AtomicU64>,
    harvest_observability: &'a Arc<Mutex<KadHarvestObservability>>,
}

#[derive(Debug, Default)]
struct PassiveBatchPosterOutcome {
    batch_count: usize,
    last_post_error: Option<String>,
}

struct PassivePostBatch {
    files: Vec<FileRecord>,
}

async fn post_passive_result_batch(
    coordinator: &CoordinatorClient,
    indexer_id: Uuid,
    replay_context: &HarvestReplayContext,
    files: Vec<FileRecord>,
) -> Result<()> {
    coordinator
        .post_results(&ResultBatch {
            job_id: None,
            indexer_id,
            protocol: Protocol::Kad2,
            harvest_context: Some(replay_context.clone()),
            files,
        })
        .await
}

fn spawn_passive_batch_poster(
    coordinator: CoordinatorClient,
    indexer_id: Uuid,
    replay_context: HarvestReplayContext,
    family: HarvestFamily,
    harvest_observability: Arc<Mutex<KadHarvestObservability>>,
) -> (
    mpsc::Sender<PassivePostBatch>,
    JoinHandle<PassiveBatchPosterOutcome>,
) {
    let (tx, mut rx) = mpsc::channel::<PassivePostBatch>(PASSIVE_POST_QUEUE_DEPTH);
    let task = tokio::spawn(async move {
        let mut outcome = PassiveBatchPosterOutcome::default();
        while let Some(batch) = rx.recv().await {
            let post_started_at = Instant::now();
            match post_passive_result_batch(&coordinator, indexer_id, &replay_context, batch.files)
                .await
            {
                Ok(()) => {
                    outcome.batch_count += 1;
                    let mut observability = harvest_observability.lock().await;
                    record_passive_replay_post_latency(
                        &mut observability,
                        family,
                        post_started_at.elapsed(),
                    );
                }
                Err(error) => {
                    warn!("failed to post passive {:?} result batch: {error}", family);
                    outcome.last_post_error = Some(error.to_string());
                    let mut observability = harvest_observability.lock().await;
                    record_passive_replay_post_latency(
                        &mut observability,
                        family,
                        post_started_at.elapsed(),
                    );
                    record_passive_replay_post_failure(
                        &mut observability,
                        family,
                        Utc::now(),
                        outcome.last_post_error.as_deref().unwrap_or("post failed"),
                    );
                }
            }
        }
        outcome
    });
    (tx, task)
}

async fn finish_passive_batch_poster(
    sender: mpsc::Sender<PassivePostBatch>,
    task: JoinHandle<PassiveBatchPosterOutcome>,
) -> PassiveBatchPosterOutcome {
    drop(sender);
    match task.await {
        Ok(outcome) => outcome,
        Err(error) => PassiveBatchPosterOutcome {
            batch_count: 0,
            last_post_error: Some(format!("passive batch poster join failed: {error}")),
        },
    }
}

async fn send_passive_result_batch(
    sender: &mpsc::Sender<PassivePostBatch>,
    harvest_observability: &Arc<Mutex<KadHarvestObservability>>,
    family: HarvestFamily,
    files: Vec<FileRecord>,
) -> Result<()> {
    let batch = PassivePostBatch { files };
    match sender.try_send(batch) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(batch)) => {
            let enqueue_started_at = Instant::now();
            sender.send(batch).await.map_err(|_| {
                anyhow::anyhow!("passive batch poster stopped accepting {family:?} batches")
            })?;
            let mut observability = harvest_observability.lock().await;
            record_passive_replay_enqueue_wait(
                &mut observability,
                family,
                enqueue_started_at.elapsed(),
                true,
            );
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(_batch)) => {
            anyhow::bail!("passive batch poster stopped accepting {family:?} batches");
        }
    }
}

async fn flush_passive_result_batch(
    sender: &mpsc::Sender<PassivePostBatch>,
    harvest_observability: &Arc<Mutex<KadHarvestObservability>>,
    family: HarvestFamily,
    files: &mut Vec<FileRecord>,
    started_at: &mut Option<Instant>,
) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    let batch = std::mem::take(files);
    *started_at = None;
    send_passive_result_batch(sender, harvest_observability, family, batch).await
}

async fn run_passive_keyword_replay(
    context: PassiveReplayContext<'_>,
    request: &SearchKeyReq,
) -> PassiveReplayRunOutcome {
    let mut outcome = PassiveReplayRunOutcome::default();
    let mut seen_hashes = HashSet::new();
    let mut files = Vec::new();
    let mut pending_batch_started_at = None;
    let (batch_tx, batch_task) = spawn_passive_batch_poster(
        context.coordinator.clone(),
        context.indexer_id,
        context.replay_context.clone(),
        HarvestFamily::Keyword,
        Arc::clone(context.harvest_observability),
    );

    for responder_ceiling in passive_replay_tier_contact_limits(context.max_phase2_fanout) {
        let tier_result_start = outcome.result_count;
        debug!(
            "kad passive replay tier start family=keyword target={} responder_ceiling={} restrictive_bytes={}",
            request.target,
            responder_ceiling,
            request.restrictive_payload.len()
        );
        let mut stream = context
            .dht
            .search_keyword_request_with_phase2_fanout_and_cancel_and_class(
                request.clone(),
                responder_ceiling,
                CancellationToken::new(),
                RpcWorkClass::Harvest,
            );
        while let Some(result) = stream.next().await {
            if !seen_hashes.insert(result.hash) {
                continue;
            }
            if let Ok(file) = map_search_result_for(context.dht, &result) {
                context.passive_result_count.fetch_add(1, Ordering::Relaxed);
                outcome.result_count += 1;
                if files.is_empty() {
                    pending_batch_started_at = Some(Instant::now());
                }
                files.push(file);
                let batch_age = pending_batch_started_at.map(|started_at| started_at.elapsed());
                let should_flush = files.len() >= PASSIVE_BATCH_SIZE
                    || batch_age.is_some_and(|age| {
                        age >= Duration::from_millis(PASSIVE_BATCH_FLUSH_INTERVAL_MS)
                    });
                if should_flush
                    && let Err(error) = flush_passive_result_batch(
                        &batch_tx,
                        context.harvest_observability,
                        HarvestFamily::Keyword,
                        &mut files,
                        &mut pending_batch_started_at,
                    )
                    .await
                {
                    outcome.last_post_error = Some(error.to_string());
                    break;
                }
            }
        }

        let tier_results = outcome.result_count - tier_result_start;
        debug!(
            "kad passive replay tier done family=keyword target={} responder_ceiling={} tier_results={} cumulative_results={}",
            request.target, responder_ceiling, tier_results, outcome.result_count
        );
        outcome.tier_summaries.push(KadPassiveReplayTierSummary {
            responder_ceiling: responder_ceiling as u32,
            result_count: tier_results as u32,
        });

        if outcome.result_count >= passive_replay_thin_result_threshold(HarvestFamily::Keyword) {
            break;
        }
    }

    if let Err(error) = flush_passive_result_batch(
        &batch_tx,
        context.harvest_observability,
        HarvestFamily::Keyword,
        &mut files,
        &mut pending_batch_started_at,
    )
    .await
    {
        outcome.last_post_error = Some(error.to_string());
    }
    let poster_outcome = finish_passive_batch_poster(batch_tx, batch_task).await;
    outcome.batch_count = poster_outcome.batch_count;
    if poster_outcome.last_post_error.is_some() {
        outcome.last_post_error = poster_outcome.last_post_error;
    }

    outcome
}

async fn run_passive_source_replay(
    context: PassiveReplayContext<'_>,
    request: &SearchSourceReq,
) -> PassiveReplayRunOutcome {
    let mut outcome = PassiveReplayRunOutcome::default();
    let mut seen_sources = HashSet::<(std::net::Ipv4Addr, u16, u16)>::new();
    let mut files = Vec::new();
    let source_stop_after_results = context.source_stop_after_results.max(1);
    let (batch_tx, batch_task) = spawn_passive_batch_poster(
        context.coordinator.clone(),
        context.indexer_id,
        context.replay_context.clone(),
        HarvestFamily::Source,
        Arc::clone(context.harvest_observability),
    );

    for responder_ceiling in passive_replay_tier_contact_limits(context.max_phase2_fanout) {
        let tier_result_start = outcome.result_count;
        debug!(
            "kad passive replay tier start family=source target={} responder_ceiling={} size={}",
            request.target, responder_ceiling, request.size
        );
        let cancel = CancellationToken::new();
        let mut stream = context
            .dht
            .search_source_request_with_phase2_fanout_and_cancel_and_class(
                request.clone(),
                responder_ceiling,
                cancel.clone(),
                RpcWorkClass::Harvest,
            );
        while let Some(result) = stream.next().await {
            let source_key = (result.ip, result.tcp_port, result.udp_port);
            if !seen_sources.insert(source_key) {
                continue;
            }
            context.passive_result_count.fetch_add(1, Ordering::Relaxed);
            outcome.result_count += 1;
            files.push(map_source_result(&result, request.size));
            if files.len() >= PASSIVE_BATCH_SIZE
                && let Err(error) = send_passive_result_batch(
                    &batch_tx,
                    context.harvest_observability,
                    HarvestFamily::Source,
                    std::mem::take(&mut files),
                )
                .await
            {
                outcome.last_post_error = Some(error.to_string());
                break;
            }
            if outcome.result_count >= source_stop_after_results {
                cancel.cancel();
                break;
            }
        }

        let tier_results = outcome.result_count - tier_result_start;
        debug!(
            "kad passive replay tier done family=source target={} responder_ceiling={} tier_results={} cumulative_results={}",
            request.target, responder_ceiling, tier_results, outcome.result_count
        );
        outcome.tier_summaries.push(KadPassiveReplayTierSummary {
            responder_ceiling: responder_ceiling as u32,
            result_count: tier_results as u32,
        });

        if outcome.result_count >= source_stop_after_results {
            break;
        }
    }

    if !files.is_empty()
        && let Err(error) = send_passive_result_batch(
            &batch_tx,
            context.harvest_observability,
            HarvestFamily::Source,
            files,
        )
        .await
    {
        outcome.last_post_error = Some(error.to_string());
    }
    let poster_outcome = finish_passive_batch_poster(batch_tx, batch_task).await;
    outcome.batch_count = poster_outcome.batch_count;
    if poster_outcome.last_post_error.is_some() {
        outcome.last_post_error = poster_outcome.last_post_error;
    }

    outcome
}

async fn run_passive_notes_replay(
    context: PassiveReplayContext<'_>,
    request: &SearchNotesReq,
) -> PassiveReplayRunOutcome {
    let mut outcome = PassiveReplayRunOutcome::default();
    let mut seen_note_sources = HashSet::new();
    let mut files = Vec::new();
    let file_hash = Ed2kHash::from_bytes(request.target.to_be_bytes());
    let (batch_tx, batch_task) = spawn_passive_batch_poster(
        context.coordinator.clone(),
        context.indexer_id,
        context.replay_context.clone(),
        HarvestFamily::Notes,
        Arc::clone(context.harvest_observability),
    );

    for responder_ceiling in passive_replay_tier_contact_limits(context.max_phase2_fanout) {
        let tier_result_start = outcome.result_count;
        info!(
            "kad passive notes replay tier start target={} responder_ceiling={} size={}",
            request.target, responder_ceiling, request.size
        );
        let mut stream = context
            .dht
            .search_notes_with_phase2_fanout_and_cancel_and_class(
                file_hash,
                request.size,
                responder_ceiling,
                CancellationToken::new(),
                RpcWorkClass::Harvest,
            );
        while let Some(result) = stream.next().await {
            if !seen_note_sources.insert(result.source_id) {
                continue;
            }
            context.passive_result_count.fetch_add(1, Ordering::Relaxed);
            outcome.result_count += 1;
            files.push(map_note_result(&result, request.size));
            if files.len() >= PASSIVE_BATCH_SIZE
                && let Err(error) = send_passive_result_batch(
                    &batch_tx,
                    context.harvest_observability,
                    HarvestFamily::Notes,
                    std::mem::take(&mut files),
                )
                .await
            {
                outcome.last_post_error = Some(error.to_string());
                break;
            }
        }

        let tier_results = outcome.result_count - tier_result_start;
        info!(
            "kad passive notes replay tier done target={} responder_ceiling={} tier_results={} cumulative_results={}",
            request.target, responder_ceiling, tier_results, outcome.result_count
        );
        outcome.tier_summaries.push(KadPassiveReplayTierSummary {
            responder_ceiling: responder_ceiling as u32,
            result_count: tier_results as u32,
        });

        if outcome.result_count >= passive_replay_thin_result_threshold(HarvestFamily::Notes) {
            break;
        }
    }

    if !files.is_empty()
        && let Err(error) = send_passive_result_batch(
            &batch_tx,
            context.harvest_observability,
            HarvestFamily::Notes,
            files,
        )
        .await
    {
        outcome.last_post_error = Some(error.to_string());
    }
    let poster_outcome = finish_passive_batch_poster(batch_tx, batch_task).await;
    outcome.batch_count = poster_outcome.batch_count;
    if poster_outcome.last_post_error.is_some() {
        outcome.last_post_error = poster_outcome.last_post_error;
    }

    outcome
}

/// Infer the oracle-style eD2k search term for a filename's published file type.
///
/// eMule publishes keyword `FILETYPE` tags using a compact search vocabulary:
/// `Audio`, `Video`, `Image`, `Doc`, `Pro`, or `EmuleCollection`.
/// Archives, programs, and CD-image style extensions all collapse to `Pro`.
#[must_use]
fn ed2k_file_type_search_term(file_name: &str) -> Option<&'static str> {
    let extension = file_name.rsplit('.').next()?;
    if extension == file_name {
        return None;
    }

    match extension.to_ascii_lowercase().as_str() {
        "mp3" | "aac" | "ac3" | "flac" | "m4a" | "ogg" | "wav" | "wma" => Some("Audio"),
        "avi" | "mkv" | "mov" | "mp4" | "mpeg" | "mpg" | "wmv" => Some("Video"),
        "bmp" | "gif" | "jpeg" | "jpg" | "png" | "tif" | "tiff" | "webp" => Some("Image"),
        "chm" | "csv" | "doc" | "docx" | "epub" | "htm" | "html" | "odt" | "pdf" | "pps"
        | "ppt" | "pptx" | "rtf" | "txt" | "xls" | "xlsx" => Some("Doc"),
        "7z" | "ace" | "apk" | "bat" | "bin" | "bz2" | "cab" | "cmd" | "com" | "dll" | "dmg"
        | "exe" | "gz" | "img" | "iso" | "jar" | "msi" | "pkg" | "rar" | "sh" | "tar" | "tgz"
        | "xz" | "zip" => Some("Pro"),
        "emulecollection" => Some("EmuleCollection"),
        _ => None,
    }
}

/// Derive a stable synthetic AICH root for seeded publishes.
///
/// Seeded hashes do not have a real AICH tree behind them, but eMule adds an
/// AICH root on keyword publishes to Kad v9+ peers. A deterministic SHA-1 over
/// the advertised file identity keeps our wire shape stable across runs and
/// lets the publish fanout mirror the oracle's version-gated tag branch.
#[must_use]
fn synthetic_publish_aich_hash(file_hash: &Ed2kHash, file_name: &str, file_size: u64) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(file_hash.0);
    hasher.update(file_size.to_le_bytes());
    hasher.update(file_name.as_bytes());
    let digest = hasher.finalize();
    let mut aich_hash = [0u8; 20];
    aich_hash.copy_from_slice(&digest);
    aich_hash
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

async fn refresh_ed2k_shared_catalog(shared_catalog: &Ed2kSharedCatalog, hashes: &[PopularHash]) {
    let mut guard = shared_catalog.write().await;
    guard.retain(|entry| !entry.compatibility_hint);
    let replacements = if hashes.is_empty() {
        synthetic_popular_hashes()
    } else {
        hashes.to_vec()
    };
    guard.extend(
        replacements
            .iter()
            .filter_map(crate::ed2k_transfer::Ed2kSharedEntry::from_popular_hash),
    );
}

/// Static settings that make source publishes look like a stable eMule-style
/// high-ID client on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourcePublishSettings {
    tcp_port: u16,
    obfuscation_enabled: bool,
}

/// Shared publish-side dependencies that need to flow into both startup and
/// manual seed runs.
///
/// The seed loop owns the operator-visible publishing state, so these handles
/// are threaded through the helper instead of being reconstructed ad hoc.
#[derive(Clone, Copy)]
struct PublishExecutionContext<'a> {
    local_store: &'a Arc<Mutex<KadLocalStore>>,
    publish_batch_gate: &'a Arc<Mutex<()>>,
    publish_observability: &'a Arc<Mutex<KadPublishObservability>>,
    agent_activity: &'a Arc<Mutex<AgentActivityTracker>>,
    activity_key: Option<&'a str>,
    notes_publish_enabled: bool,
    work_class: RpcWorkClass,
    publish_contact_fanout: usize,
}

async fn run_publish_batch_with_gate<T, Operation, OperationFuture>(
    publish_batch_gate: &Arc<Mutex<()>>,
    operation: Operation,
) -> T
where
    Operation: FnOnce() -> OperationFuture,
    OperationFuture: Future<Output = T>,
{
    let _publish_batch_guard = publish_batch_gate.lock().await;
    operation().await
}

async fn fetch_coordinator_popular_hashes(
    coordinator: &CoordinatorClient,
) -> Result<Option<Vec<PopularHash>>> {
    let hashes = coordinator.popular_hashes().await?;
    Ok((!hashes.is_empty()).then_some(hashes))
}

fn synthetic_publish_queue_depth(cursor: usize) -> usize {
    let total = SYNTHETIC_POPULAR_SEEDS.len();
    if total == 0 {
        return 0;
    }
    let normalized = cursor % total;
    if normalized == 0 {
        total
    } else {
        total - normalized
    }
}

fn next_synthetic_publish_batch(cursor: &mut usize, batch_items: usize) -> Vec<PopularHash> {
    if SYNTHETIC_POPULAR_SEEDS.is_empty() {
        return Vec::new();
    }

    let total = SYNTHETIC_POPULAR_SEEDS.len();
    let start = *cursor % total;
    let batch_len = batch_items.max(1).min(total);
    let batch = (0..batch_len)
        .map(|offset| {
            let index = (start + offset) % total;
            synthetic_popular_hash(index, &SYNTHETIC_POPULAR_SEEDS[index])
        })
        .collect::<Vec<_>>();
    *cursor = (start + batch_len) % total;
    batch
}

/// Publishes one seeding batch and logs which source produced it.
async fn seed_popular_from_source(
    dht: &DhtNode,
    source_publish_identity: NodeId,
    source_publish_settings: SourcePublishSettings,
    source: PublishSeedSource,
    hashes: Vec<PopularHash>,
    shared_catalog: &Ed2kSharedCatalog,
    context: PublishExecutionContext<'_>,
) -> Result<()> {
    run_publish_batch_with_gate(context.publish_batch_gate, || async move {
        info!(
            "kad seeding source={} entries={} notes_publish_enabled={}",
            source.label(),
            hashes.len(),
            context.notes_publish_enabled
        );
        refresh_ed2k_shared_catalog(shared_catalog, &hashes).await;
        seed_popular_impl(
            dht,
            source_publish_identity,
            source_publish_settings,
            source,
            hashes,
            context,
        )
        .await
    })
    .await
}

async fn seed_popular_with_activity(
    dht: &DhtNode,
    source_publish_identity: NodeId,
    source_publish_settings: SourcePublishSettings,
    source: PublishSeedSource,
    hashes: Vec<PopularHash>,
    shared_catalog: &Ed2kSharedCatalog,
    context: PublishExecutionContext<'_>,
) -> Result<bool> {
    if hashes.is_empty() {
        return Ok(false);
    }
    let publish_started_at = Utc::now();
    let activity_key = publish_activity_key(source, publish_started_at);
    let mut activity_snapshot =
        new_activity_snapshot(AgentActivityState::Publishing, publish_started_at);
    activity_snapshot.query_or_target = Some(source.label().to_string());
    activity_snapshot.progress_current = Some(0);
    activity_snapshot.progress_total = Some(hashes.len() as u32);
    begin_agent_activity(
        context.agent_activity,
        activity_key.clone(),
        activity_snapshot,
    )
    .await;
    let result = seed_popular_from_source(
        dht,
        source_publish_identity,
        source_publish_settings,
        source,
        hashes,
        shared_catalog,
        PublishExecutionContext {
            activity_key: Some(activity_key.as_str()),
            ..context
        },
    )
    .await;
    finish_agent_activity(context.agent_activity, &activity_key, Utc::now()).await;
    match result {
        Ok(()) => {
            clear_agent_degraded_activity(context.agent_activity).await;
            Ok(true)
        }
        Err(error) => {
            let mut degraded_snapshot =
                new_activity_snapshot(AgentActivityState::Degraded, Utc::now());
            degraded_snapshot.query_or_target = Some(source.label().to_string());
            degraded_snapshot.last_error = Some(error.to_string());
            record_agent_degraded_activity(context.agent_activity, degraded_snapshot).await;
            Err(error)
        }
    }
}

async fn seed_coordinator_popular_if_available(
    dht: &DhtNode,
    source_publish_identity: NodeId,
    source_publish_settings: SourcePublishSettings,
    coordinator: &CoordinatorClient,
    shared_catalog: &Ed2kSharedCatalog,
    context: PublishExecutionContext<'_>,
) -> Result<bool> {
    let hashes = match fetch_coordinator_popular_hashes(coordinator).await {
        Ok(Some(hashes)) => hashes,
        Ok(None) => return Ok(false),
        Err(error) => {
            warn!("coordinator popular-hash fetch failed; deferring to synthetic drip: {error}");
            return Ok(false);
        }
    };

    seed_popular_with_activity(
        dht,
        source_publish_identity,
        source_publish_settings,
        PublishSeedSource::Coordinator,
        hashes,
        shared_catalog,
        context,
    )
    .await
}

/// Executes one complete keyword/source/(optional) notes seeding pass.
///
/// Keyword and source publishes remain the default seeding behavior. Notes
/// publishes are guarded by `PublishExecutionContext::notes_publish_enabled` so
/// real-network validation can exercise the path without making synthetic notes
/// part of the default runtime posture.
async fn seed_popular_impl(
    dht: &DhtNode,
    source_publish_identity: NodeId,
    source_publish_settings: SourcePublishSettings,
    seed_source: PublishSeedSource,
    hashes: Vec<PopularHash>,
    context: PublishExecutionContext<'_>,
) -> Result<()> {
    if !dht.is_bootstrapped() {
        anyhow::bail!("kad node is not bootstrapped yet");
    }

    let bind_addr = dht.bind_addr()?;
    let mut keyword_totals = PublishAttemptStats::default();
    let mut source_totals = PublishAttemptStats::default();
    let mut notes_totals = PublishAttemptStats::default();
    let notes_publish_identity = dht.own_id();
    let published_items = hashes.len();
    update_publish_progress(
        context.publish_observability,
        seed_source,
        0,
        keyword_totals,
        source_totals,
        context.notes_publish_enabled.then_some(notes_totals),
        Utc::now(),
    )
    .await;
    if let Some(activity_key) = context.activity_key {
        update_agent_activity_progress(
            context.agent_activity,
            activity_key,
            Some(0),
            Some(published_items as u32),
            Utc::now(),
        )
        .await;
    }

    for (index, hash) in hashes.into_iter().enumerate() {
        let HashType::Ed2k(raw_hash) = hash.hash;
        let file_hash = Ed2kHash::from_str(&raw_hash)
            .with_context(|| format!("invalid Ed2k hash {raw_hash}"))?;
        let keyword_hash = keyword_target(&hash.canonical_name);
        let keyword_aich_hash =
            synthetic_publish_aich_hash(&file_hash, &hash.canonical_name, hash.size);
        let item_no = index + 1;
        // Keep synthetic seed publishes indistinguishable from normal eMule-style content
        // publishes: filename/filesize/source count on the keyword publish and the normal
        // high-ID source port/type tags on the source publish.
        let mut keyword_tags = vec![
            Tag::filename(hash.canonical_name.clone()),
            Tag::filesize(hash.size),
            Tag::sources(hash.source_count),
        ];
        if let Some(file_type) = ed2k_file_type_search_term(&hash.canonical_name) {
            keyword_tags.push(Tag::filetype(file_type));
        }
        {
            let mut store = context.local_store.lock().await;
            store.record_keyword_publish_batch(
                keyword_hash,
                &[overlord_kad_proto::PublishEntry {
                    hash: file_hash,
                    tags: keyword_tags.clone(),
                }],
                Utc::now(),
            );
        }
        info!(
            "kad publish start family=keyword seed_source={} item={}/{} target={} hash={}",
            seed_source.label(),
            item_no,
            published_items,
            keyword_hash,
            raw_hash
        );
        match dht
            .publish_keyword_with_class_and_fanout(
                keyword_hash,
                file_hash,
                keyword_tags,
                Some(keyword_aich_hash),
                context.work_class,
                context.publish_contact_fanout,
            )
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
        let source_tags = build_source_publish_tags(bind_addr, source_publish_settings, hash.size);
        if let IpAddr::V4(source_ip) = bind_addr.ip() {
            let mut store = context.local_store.lock().await;
            store.record_source_publish(
                NodeId::from_be_bytes(file_hash.0),
                source_publish_identity,
                source_ip,
                &source_tags,
                Utc::now(),
            );
        }
        info!(
            "kad publish start family=source seed_source={} item={}/{} target={} hash={}",
            seed_source.label(),
            item_no,
            published_items,
            file_hash,
            raw_hash
        );
        match dht
            .publish_source_with_class_and_fanout(
                file_hash,
                source_publish_identity,
                source_tags,
                context.work_class,
                context.publish_contact_fanout,
            )
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
        if context.notes_publish_enabled {
            let notes_tags = build_notes_publish_tags(&hash.canonical_name, hash.size);
            {
                let mut store = context.local_store.lock().await;
                store.record_notes_publish(
                    NodeId::from_be_bytes(file_hash.0),
                    notes_publish_identity,
                    &notes_tags,
                    Utc::now(),
                );
            }
            info!(
                "kad publish start family=notes seed_source={} item={}/{} target={} hash={} publisher_id={}",
                seed_source.label(),
                item_no,
                published_items,
                file_hash,
                raw_hash,
                notes_publish_identity
            );
            match dht
                .publish_notes_with_class_and_fanout(
                    file_hash,
                    notes_publish_identity,
                    notes_tags,
                    context.work_class,
                    context.publish_contact_fanout,
                )
                .await
            {
                Ok(stats) => {
                    notes_totals.closest_contacts_considered += stats.closest_contacts_considered;
                    notes_totals.attempted_contacts += stats.attempted_contacts;
                    notes_totals.acked_contacts += stats.acked_contacts;
                    notes_totals.timed_out_contacts += stats.timed_out_contacts;
                }
                Err(error) => {
                    debug!("notes publish failed for hash={}: {error}", raw_hash);
                }
            }
        }
        let observed_at = Utc::now();
        update_publish_progress(
            context.publish_observability,
            seed_source,
            item_no,
            keyword_totals,
            source_totals,
            context.notes_publish_enabled.then_some(notes_totals),
            observed_at,
        )
        .await;
        if let Some(activity_key) = context.activity_key {
            update_agent_activity_progress(
                context.agent_activity,
                activity_key,
                Some(item_no as u32),
                Some(published_items as u32),
                observed_at,
            )
            .await;
        }
        info!(
            "kad publish progress seed_source={} items_done={}/{} keyword_attempted={} keyword_acked={} source_attempted={} source_acked={} notes_attempted={} notes_acked={}",
            seed_source.label(),
            item_no,
            published_items,
            keyword_totals.attempted_contacts,
            keyword_totals.acked_contacts,
            source_totals.attempted_contacts,
            source_totals.acked_contacts,
            notes_totals.attempted_contacts,
            notes_totals.acked_contacts
        );
    }

    record_publish_summaries(
        context.publish_observability,
        seed_source,
        published_items,
        keyword_totals,
        source_totals,
        context.notes_publish_enabled.then_some(notes_totals),
        Utc::now(),
    )
    .await;

    Ok(())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActiveUdpFirewallPorts {
    internal: u16,
    external: u16,
}

impl ActiveUdpFirewallPorts {
    fn expected_ports(self) -> Vec<u16> {
        let mut ports = vec![self.internal];
        if self.external != 0 && self.external != self.internal {
            ports.push(self.external);
        }
        ports
    }
}

fn nat_external_udp_port(status: &NatStatus) -> Option<u16> {
    status
        .mappings
        .iter()
        .find(|mapping| mapping.name == "kad" && mapping.protocol == TransportProtocol::Udp)
        .map(|mapping| mapping.external_addr.port())
}

async fn discover_external_kad_udp_port(
    dht: &DhtNode,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
) -> u16 {
    let bind_ip = match dht.bind_addr() {
        Ok(bind_addr) => match bind_addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return 0,
        },
        Err(_) => return 0,
    };

    {
        let mut firewall = kad_firewall.lock().await;
        firewall.begin_external_port_discovery(Utc::now());
    }

    let mut contacts = dht
        .routing_contacts()
        .await
        .into_iter()
        .filter(|contact| {
            contact.kad_version >= 6 && contact.udp_port != 0 && contact.ip != bind_ip
        })
        .collect::<Vec<_>>();
    contacts.shuffle(&mut rand::thread_rng());

    for contact in contacts
        .into_iter()
        .take(KAD_EXTERNAL_PORT_DISCOVERY_MAX_ATTEMPTS)
    {
        let needs_discovery = {
            let firewall = kad_firewall.lock().await;
            firewall.needs_external_port_discovery()
        };
        if !needs_discovery {
            break;
        }

        let addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.udp_port);
        match dht
            .request_packet(
                addr,
                &KadPacket::Ping,
                opcode::PONG,
                Duration::from_secs(KAD_EXTERNAL_PORT_DISCOVERY_QUERY_TIMEOUT_SECS),
            )
            .await
        {
            Ok(KadPacket::Pong(pong)) => {
                let outcome = {
                    let mut firewall = kad_firewall.lock().await;
                    firewall.record_external_port_candidate(addr.ip(), pong.udp_port, Utc::now())
                };
                match outcome {
                    ExternalPortDiscoveryOutcome::Recorded => {
                        debug!(
                            "kad external UDP port candidate reporter={} reported_port={}",
                            addr, pong.udp_port
                        );
                    }
                    ExternalPortDiscoveryOutcome::Resolved(port) => {
                        info!(
                            "resolved external Kad UDP port reporter={} external_port={}",
                            addr, port
                        );
                    }
                    ExternalPortDiscoveryOutcome::Unreliable => {
                        warn!(
                            "external Kad UDP port discovery became unreliable after reporter={} reported_port={}",
                            addr, pong.udp_port
                        );
                    }
                    ExternalPortDiscoveryOutcome::Ignored => {}
                }
            }
            Ok(other) => {
                debug!(
                    "unexpected Kad packet while probing external UDP port from {addr}: {other:?}"
                );
            }
            Err(error) => {
                debug!("failed Kad external UDP port probe against {addr}: {error}");
            }
        }
    }

    let mut firewall = kad_firewall.lock().await;
    firewall.finish_external_port_discovery(Utc::now());
    firewall.external_udp_port_for_request()
}

async fn active_udp_firewall_ports(
    dht: &DhtNode,
    nat: &NatManager,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    internal_udp_port: u16,
) -> ActiveUdpFirewallPorts {
    let status = nat.status().await;
    if let Some(external_udp_port) = nat_external_udp_port(&status) {
        return ActiveUdpFirewallPorts {
            internal: internal_udp_port,
            external: external_udp_port,
        };
    }

    let external_udp_port = discover_external_kad_udp_port(dht, kad_firewall).await;
    ActiveUdpFirewallPorts {
        internal: internal_udp_port,
        external: external_udp_port,
    }
}

async fn select_udp_firewall_helpers(dht: &DhtNode, helper_count: usize) -> Result<Vec<Contact>> {
    let local_ip = dht.bind_addr()?.ip();
    let mut contacts = dht
        .routing_contacts()
        .await
        .into_iter()
        .filter(|contact| {
            contact.kad_version >= 6
                && contact.tcp_port != 0
                && contact.udp_port != 0
                && contact.contact_type != ContactType::Dead
                && IpAddr::V4(contact.ip) != local_ip
        })
        .collect::<Vec<_>>();
    contacts.shuffle(&mut rand::thread_rng());
    contacts.sort_by_key(|contact| std::cmp::Reverse(score_udp_firewall_helper(contact)));

    let mut selected = Vec::with_capacity(helper_count);
    let mut seen_ips = std::collections::HashSet::new();
    for contact in contacts {
        if seen_ips.insert(contact.ip) {
            selected.push(contact);
            if selected.len() >= helper_count {
                break;
            }
        }
    }
    Ok(selected)
}

fn score_udp_firewall_helper(contact: &Contact) -> (u8, u8, u8, u8, u8, u8) {
    (
        u8::from(contact.contact_type == ContactType::Active),
        u8::from(contact.verified),
        u8::from(!contact.tcp_firewalled),
        u8::from(!contact.udp_firewalled),
        u8::from(contact.udp_key != KadUdpKey::ZERO),
        contact.kad_version,
    )
}

async fn tcp_firewall_probe(addr: SocketAddr, timeout: Duration) -> Result<()> {
    let stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .with_context(|| format!("timed out connecting to TCP firewall probe target {addr}"))??;
    stream
        .set_nodelay(true)
        .with_context(|| format!("failed to enable TCP_NODELAY for probe target {addr}"))?;
    Ok(())
}

fn spawn_firewalled_response(dht: DhtNode, from: SocketAddr, tcp_port: u16) {
    tokio::spawn(async move {
        let IpAddr::V4(ip) = from.ip() else {
            return;
        };
        let target = SocketAddr::new(IpAddr::V4(ip), tcp_port);
        if tcp_firewall_probe(
            target,
            Duration::from_secs(FIREWALLED_TCP_PROBE_TIMEOUT_SECS),
        )
        .await
        .is_err()
        {
            return;
        }

        let _ = dht
            .send_packet(
                from,
                &KadPacket::FirewalledRes(overlord_kad_proto::FirewalledRes {
                    ip: u32::from_be_bytes(ip.octets()),
                }),
            )
            .await;
    });
}

/// Mirror the oracle's HELLO-triggered Kad TCP firewall/IP recheck.
///
/// When the local runtime still looks TCP-firewalled, eMule emits up to four
/// `KADEMLIA_FIREWALLED2_REQ` probes after successful HELLO exchanges. Each
/// matching `KADEMLIA_FIREWALLED_RES` reports the externally observed IP and
/// advances the bounded recheck loop.
struct KadFirewalledCheckContext {
    dht: DhtNode,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    ed2k_listener: Arc<TcpListener>,
    ed2k_server_state: Arc<RwLock<Ed2kServerState>>,
    ed2k_user_hash: Ed2kHash,
    ed2k_obfuscation_enabled: bool,
}

fn spawn_kad_firewalled_check(
    context: KadFirewalledCheckContext,
    from: SocketAddr,
    peer_version: u8,
) {
    tokio::spawn(async move {
        let KadFirewalledCheckContext {
            dht,
            kad_firewall,
            ed2k_listener,
            ed2k_server_state,
            ed2k_user_hash,
            ed2k_obfuscation_enabled,
        } = context;
        let started_at = Utc::now();
        let tcp_firewalled = current_tcp_firewalled(&ed2k_listener, &ed2k_server_state).await;
        if !tcp_firewalled {
            let mut firewall = kad_firewall.lock().await;
            firewall.refresh_tcp_recheck(false, started_at);
            return;
        }

        let IpAddr::V4(_) = from.ip() else {
            return;
        };

        {
            let mut firewall = kad_firewall.lock().await;
            firewall.refresh_tcp_recheck(true, started_at);
            if !firewall.try_begin_tcp_firewall_probe(from.ip(), started_at) {
                return;
            }
        }

        let tcp_port = match ed2k_listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(error) => {
                let mut firewall = kad_firewall.lock().await;
                firewall.record_tcp_firewall_probe_failed(
                    from.ip(),
                    &format!("failed to read local eD2k TCP port: {error}"),
                );
                return;
            }
        };

        let request = if peer_version > 6 {
            KadPacket::Firewalled2Req(overlord_kad_proto::Firewalled2Req {
                tcp_port,
                user_hash: ed2k_user_hash,
                connect_options: emule_connect_options(ed2k_obfuscation_enabled),
            })
        } else {
            KadPacket::FirewalledReq(overlord_kad_proto::FirewalledReq { tcp_port })
        };

        debug!(
            "sending Kad firewalled check to={} peer_version={} request_opcode={}",
            from,
            peer_version,
            if peer_version > 6 {
                "KADEMLIA_FIREWALLED2_REQ"
            } else {
                "KADEMLIA_FIREWALLED_REQ"
            }
        );

        match dht
            .request_packet(
                from,
                &request,
                opcode::FIREWALLED_RES,
                Duration::from_secs(KAD_FIREWALLED_RESPONSE_TIMEOUT_SECS),
            )
            .await
        {
            Ok(KadPacket::FirewalledRes(response)) => {
                let reported_ip = IpAddr::V4(Ipv4Addr::from(response.ip));
                let outcome = {
                    let mut firewall = kad_firewall.lock().await;
                    firewall.record_firewalled_response(from.ip(), reported_ip, Utc::now())
                };
                match outcome {
                    FirewalledResponseOutcome::Recorded => {
                        info!(
                            "kad firewalled check recorded helper={} reported_ip={}",
                            from, reported_ip
                        );
                    }
                    FirewalledResponseOutcome::Completed => {
                        info!(
                            "kad firewalled check completed helper={} reported_ip={}",
                            from, reported_ip
                        );
                    }
                    FirewalledResponseOutcome::Ignored => {
                        debug!(
                            "ignored unmatched Kad firewalled response helper={} reported_ip={}",
                            from, reported_ip
                        );
                    }
                }
            }
            Ok(other) => {
                let mut firewall = kad_firewall.lock().await;
                firewall.record_tcp_firewall_probe_failed(
                    from.ip(),
                    &format!("unexpected Kad firewalled response {other:?}"),
                );
            }
            Err(error) => {
                let mut firewall = kad_firewall.lock().await;
                firewall.record_tcp_firewall_probe_failed(from.ip(), &error.to_string());
                debug!("Kad firewalled check failed for {}: {}", from, error);
            }
        }
    });
}

struct UnsolicitedPacketContext<'a> {
    snoop_queue: &'a Arc<Mutex<SnoopQueue>>,
    observed_snoop_events: &'a Arc<Mutex<Vec<SnoopObservation>>>,
    local_store: &'a Arc<Mutex<KadLocalStore>>,
    harvest_observability: &'a Arc<Mutex<KadHarvestObservability>>,
    kad_firewall: &'a Arc<Mutex<KadFirewallState>>,
    ed2k_listener: &'a Arc<TcpListener>,
    ed2k_server_state: &'a Arc<RwLock<Ed2kServerState>>,
    ed2k_user_hash: Ed2kHash,
    ed2k_obfuscation_enabled: bool,
}

async fn handle_unsolicited_packet(
    dht: &DhtNode,
    context: UnsolicitedPacketContext<'_>,
    received: ReceivedKadPacket,
) -> Result<()> {
    let ReceivedKadPacket {
        packet,
        from,
        sender_verify_key,
        receiver_verify_key_valid,
        ..
    } = received;

    match packet {
        KadPacket::Ping => {
            dht.send_packet(
                from,
                &KadPacket::Pong(overlord_kad_proto::Pong {
                    udp_port: from.port(),
                }),
            )
            .await?
        }
        KadPacket::FirewalledReq(req) => {
            spawn_firewalled_response(dht.clone(), from, req.tcp_port);
        }
        KadPacket::Firewalled2Req(req) => {
            spawn_firewalled_response(dht.clone(), from, req.tcp_port);
        }
        KadPacket::FirewallUdp(packet) => {
            let outcome = {
                let mut firewall = context.kad_firewall.lock().await;
                firewall.record_firewall_udp_packet(
                    from.ip(),
                    packet.error_code,
                    packet.udp_port,
                    Utc::now(),
                )
            };
            match outcome {
                FirewallUdpPacketOutcome::Open(summary) => {
                    info!(
                        "kad udp firewall-check open helpers_selected={} helpers_requested={} helpers_succeeded={} helpers_failed={} elapsed_ms={}",
                        summary.helpers_selected,
                        summary.helpers_requested,
                        summary.helpers_succeeded,
                        summary.helpers_failed,
                        (summary.completed_at - summary.started_at).num_milliseconds()
                    );
                }
                FirewallUdpPacketOutcome::Recorded => {
                    debug!(
                        "recorded kad firewall UDP packet from={} error_code={} reported_port={}",
                        from, packet.error_code, packet.udp_port
                    );
                }
                FirewallUdpPacketOutcome::Ignored => {}
            }
        }
        KadPacket::FindBuddyReq(req) => {
            debug!(
                "ignoring Kad find-buddy request from={} buddy_id={} tcp_port={} until buddy runtime is implemented",
                from, req.buddy_id, req.tcp_port
            );
        }
        KadPacket::FindBuddyRes(res) => {
            debug!(
                "ignoring unsolicited Kad find-buddy response from={} buddy_id={} tcp_port={} connect_options={:?}",
                from, res.buddy_id, res.tcp_port, res.connect_options
            );
        }
        KadPacket::CallbackReq(req) => {
            debug!(
                "ignoring Kad callback request from={} buddy_id={} file_hash={} tcp_port={} until buddy runtime is implemented",
                from, req.buddy_id, req.file_hash, req.tcp_port
            );
        }
        KadPacket::HelloReq(req) => {
            if let Some(udp_key) = sender_verify_key {
                dht.register_peer_key(from, udp_key);
            }
            let peer_metadata = add_contact_from_hello(
                dht,
                from,
                req.node_id,
                req.tcp_port,
                req.version,
                sender_verify_key,
                &req.tags,
            )
            .await;
            let request_ack = should_request_hello_response_ack(
                req.version,
                receiver_verify_key_valid,
                sender_verify_key,
            );
            let hello_res = build_hello_response(
                dht,
                context.ed2k_listener,
                context.ed2k_server_state,
                context.kad_firewall,
                request_ack,
            )
            .await?;
            let peer_metadata = peer_metadata.unwrap_or_default();
            debug!(
                "sending Kad hello response to={} request_ack={} receiver_key_valid={} peer_udp_firewalled={} peer_tcp_firewalled={} peer_requests_ack={}",
                from,
                request_ack,
                receiver_verify_key_valid,
                peer_metadata.udp_firewalled,
                peer_metadata.tcp_firewalled,
                peer_metadata.requests_hello_res_ack
            );
            if req.version >= 8 && !receiver_verify_key_valid && sender_verify_key.is_none() {
                debug!(
                    "skipping HELLO_RES ACK request to={} because sender verify key is unavailable",
                    from
                );
            }
            let _ = dht.send_packet(from, &KadPacket::HelloRes(hello_res)).await;
            spawn_kad_firewalled_check(
                KadFirewalledCheckContext {
                    dht: dht.clone(),
                    kad_firewall: Arc::clone(context.kad_firewall),
                    ed2k_listener: Arc::clone(context.ed2k_listener),
                    ed2k_server_state: Arc::clone(context.ed2k_server_state),
                    ed2k_user_hash: context.ed2k_user_hash,
                    ed2k_obfuscation_enabled: context.ed2k_obfuscation_enabled,
                },
                from,
                req.version,
            );
        }
        KadPacket::HelloRes(res) => {
            if let Some(udp_key) = sender_verify_key {
                dht.register_peer_key(from, udp_key);
            }
            let peer_metadata = add_contact_from_hello(
                dht,
                from,
                res.node_id,
                res.tcp_port,
                res.version,
                sender_verify_key,
                &res.tags,
            )
            .await
            .unwrap_or_default();
            if peer_metadata.requests_hello_res_ack {
                if sender_verify_key.is_none() {
                    warn!(
                        "peer requested HELLO_RES_ACK without a UDP key from={}",
                        from
                    );
                } else {
                    debug!(
                        "sending Kad hello response ACK to={} peer_udp_firewalled={} peer_tcp_firewalled={}",
                        from, peer_metadata.udp_firewalled, peer_metadata.tcp_firewalled
                    );
                    let _ = dht
                        .send_packet(
                            from,
                            &KadPacket::HelloResAck(overlord_kad_proto::HelloResAck {
                                node_id: dht.own_id(),
                                tags: Vec::new(),
                            }),
                        )
                        .await;
                }
            }
            spawn_kad_firewalled_check(
                KadFirewalledCheckContext {
                    dht: dht.clone(),
                    kad_firewall: Arc::clone(context.kad_firewall),
                    ed2k_listener: Arc::clone(context.ed2k_listener),
                    ed2k_server_state: Arc::clone(context.ed2k_server_state),
                    ed2k_user_hash: context.ed2k_user_hash,
                    ed2k_obfuscation_enabled: context.ed2k_obfuscation_enabled,
                },
                from,
                res.version,
            );
        }
        KadPacket::HelloResAck(_ack) => {}
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
            let observed_at = Utc::now();
            record_snoop_entry(
                context.snoop_queue,
                context.observed_snoop_events,
                context.harvest_observability,
                from,
                build_keyword_snoop_entry(&req, observed_at),
            )
            .await;
            let response = {
                let mut store = context.local_store.lock().await;
                // Restrictive keyword searches carry opaque payloads which we
                // do not parse yet, so only non-restrictive queries are served
                // from the local store in v1.
                store.keyword_search_response(
                    dht.own_id(),
                    &req,
                    LOCAL_SEARCH_RESPONSE_LIMIT,
                    observed_at,
                )
            };
            if let Some(response) = response {
                let _ = dht.send_packet(from, &KadPacket::SearchRes(response)).await;
            }
        }
        KadPacket::SearchSourceReq(req) => {
            let observed_at = Utc::now();
            record_snoop_entry(
                context.snoop_queue,
                context.observed_snoop_events,
                context.harvest_observability,
                from,
                build_source_snoop_entry(&req, observed_at),
            )
            .await;
            let response = {
                let mut store = context.local_store.lock().await;
                store.source_search_response(
                    dht.own_id(),
                    &req,
                    LOCAL_SEARCH_RESPONSE_LIMIT,
                    observed_at,
                )
            };
            if let Some(response) = response {
                let _ = dht.send_packet(from, &KadPacket::SearchRes(response)).await;
            }
        }
        KadPacket::SearchNotesReq(req) => {
            let observed_at = Utc::now();
            record_snoop_entry(
                context.snoop_queue,
                context.observed_snoop_events,
                context.harvest_observability,
                from,
                build_notes_snoop_entry(&req, observed_at),
            )
            .await;
            let response = {
                let mut store = context.local_store.lock().await;
                store.notes_search_response(
                    dht.own_id(),
                    &req,
                    LOCAL_SEARCH_RESPONSE_LIMIT,
                    observed_at,
                )
            };
            if let Some(response) = response {
                let _ = dht.send_packet(from, &KadPacket::SearchRes(response)).await;
            }
        }
        KadPacket::PublishKeyReq(req) => {
            let observed_at = Utc::now();
            {
                let mut store = context.local_store.lock().await;
                store.record_keyword_publish_batch(req.target, &req.entries, observed_at);
            }
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
            if let IpAddr::V4(ip) = from.ip() {
                let mut store = context.local_store.lock().await;
                store.record_source_publish(
                    req.target,
                    req.publisher_id,
                    ip,
                    &req.tags,
                    Utc::now(),
                );
            }
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
            {
                let mut store = context.local_store.lock().await;
                store.record_notes_publish(req.target, req.publisher_id, &req.tags, Utc::now());
            }
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
        let NativeDirectDownloadOptions {
            bind_ip,
            hello_identity,
            secure_ident,
            transfer_runtime,
            file_hash_hex,
            file_name,
            file_size,
            sources,
            connect_timeout,
            max_parallel_download_peers,
        } = options;
        let max_parallel_download_peers = max_parallel_download_peers.max(1);
        let retry_deadline =
            if !sources.is_empty() && sources.iter().all(|source| source.ip.is_loopback()) {
                Some(tokio::time::Instant::now() + Duration::from_secs(360))
            } else {
                None
            };
        let retry_sources = sources;
        let mut retry_round = 0u32;
        let mut last_error: Option<anyhow::Error> = None;

        loop {
            let mut accepted_incomplete_peers = 0u32;
            let mut retryable_error_seen = false;
            let mut pending_sources = VecDeque::from(retry_sources.clone());
            let mut active_downloads = JoinSet::new();

            while active_downloads.len() < max_parallel_download_peers {
                let Some(source) = pending_sources.pop_front() else {
                    break;
                };
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let secure_ident = Arc::clone(&secure_ident);
                let download_peer = download_peer.clone();
                let file_name = file_name.clone();
                let file_hash_hex = file_hash_hex.clone();
                let peer_addr = SocketAddr::new(IpAddr::V4(source.ip), source.tcp_port);
                info!(
                    "native ED2K download attempt file_hash={} peer={}:{} client_id={} obfuscated={} has_user_hash={}",
                    file_hash_hex,
                    source.ip,
                    source.tcp_port,
                    source.client_id,
                    source.obfuscated,
                    source.user_hash.is_some()
                );
                dump_ed2k_tcp_download_meta(
                    peer_addr,
                    None,
                    "attempt_start",
                    format!(
                        "file_hash={} client_id={} obfuscated={} has_user_hash={} retry_round={}",
                        file_hash_hex,
                        source.client_id,
                        source.obfuscated,
                        source.user_hash.is_some(),
                        retry_round
                    ),
                );
                active_downloads.spawn(async move {
                    let result = download_peer(
                        bind_ip,
                        source.clone(),
                        hello_identity,
                        secure_ident,
                        transfer_runtime,
                        file_name,
                        file_size,
                        connect_timeout,
                    )
                    .await;
                    (peer_addr, source, result)
                });
            }

            while let Some(joined) = active_downloads.join_next().await {
                let (peer_addr, source, result) =
                    joined.context("native ED2K download worker panicked")?;
                match result {
                    Ok(Ed2kPeerDownloadOutcome::Completed) => {
                        let manifest = transfer_runtime.manifest(&file_hash_hex).await?;
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            None,
                            "attempt_success",
                            format!(
                                "file_hash={} manifest_completed={} verified_ranges={} file_size={}",
                                file_hash_hex,
                                manifest.completed,
                                manifest.verified_ranges.len(),
                                manifest.file_size
                            ),
                        );
                        if manifest.completed {
                            active_downloads.abort_all();
                            while active_downloads.join_next().await.is_some() {}
                            return Ok(NativeDirectDownloadOutcome {
                                completed: true,
                                accepted_incomplete_peers,
                                last_error: last_error
                                    .as_ref()
                                    .map(|error| anyhow::anyhow!(error.to_string())),
                            });
                        }
                    }
                    Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete) => {
                        accepted_incomplete_peers += 1;
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            None,
                            "attempt_accepted_incomplete",
                            format!("file_hash={file_hash_hex}"),
                        );
                        info!(
                            "native ED2K download peer accepted session but did not complete file_hash={} peer={}",
                            file_hash_hex, peer_addr
                        );
                    }
                    Err(error) => {
                        retryable_error_seen |= is_retryable_direct_download_error(&error);
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            None,
                            "attempt_failure",
                            format!("file_hash={} error={error}", file_hash_hex),
                        );
                        warn!(
                            "native ED2K download peer failed file_hash={} peer={}: {error}",
                            file_hash_hex, peer_addr
                        );
                        last_error = Some(error);
                        if let Some(fallback_source) =
                            plaintext_fallback_for_obfuscated_source(&source)
                        {
                            info!(
                                "native ED2K download scheduling plaintext fallback file_hash={} peer={}:{}",
                                file_hash_hex, source.ip, source.tcp_port
                            );
                            pending_sources.push_front(fallback_source);
                        }
                    }
                }

                while active_downloads.len() < max_parallel_download_peers {
                    let Some(source) = pending_sources.pop_front() else {
                        break;
                    };
                    let transfer_runtime = Arc::clone(&transfer_runtime);
                    let secure_ident = Arc::clone(&secure_ident);
                    let download_peer = download_peer.clone();
                    let file_name = file_name.clone();
                    let file_hash_hex = file_hash_hex.clone();
                    let peer_addr = SocketAddr::new(IpAddr::V4(source.ip), source.tcp_port);
                    info!(
                        "native ED2K download attempt file_hash={} peer={}:{} client_id={} obfuscated={} has_user_hash={}",
                        file_hash_hex,
                        source.ip,
                        source.tcp_port,
                        source.client_id,
                        source.obfuscated,
                        source.user_hash.is_some()
                    );
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        None,
                        "attempt_start",
                        format!(
                            "file_hash={} client_id={} obfuscated={} has_user_hash={} retry_round={}",
                            file_hash_hex,
                            source.client_id,
                            source.obfuscated,
                            source.user_hash.is_some(),
                            retry_round
                        ),
                    );
                    active_downloads.spawn(async move {
                        let result = download_peer(
                            bind_ip,
                            source.clone(),
                            hello_identity,
                            secure_ident,
                            transfer_runtime,
                            file_name,
                            file_size,
                            connect_timeout,
                        )
                        .await;
                        (peer_addr, source, result)
                    });
                }
            }

            let outcome = NativeDirectDownloadOutcome {
                completed: transfer_runtime.manifest(&file_hash_hex).await?.completed,
                accepted_incomplete_peers,
                last_error: last_error
                    .as_ref()
                    .map(|error| anyhow::anyhow!(error.to_string())),
            };
            if outcome.completed || outcome.accepted_incomplete_peers != 0 {
                return Ok(outcome);
            }

            let Some(deadline) = retry_deadline else {
                return Ok(outcome);
            };
            if !retryable_error_seen || tokio::time::Instant::now() >= deadline {
                return Ok(outcome);
            }

            let last_error_summary = outcome
                .last_error
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "connection refused".to_string());
            retry_round += 1;
            info!(
                "native ED2K download retrying loopback sources file_hash={} retry_round={} reason={}",
                file_hash_hex, retry_round, last_error_summary
            );
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    async fn native_ed2k_download_sources(
        runtime: &AgentNetworkRuntime,
        config: &EmuleAgentConfig,
        file_hash: Ed2kHash,
        file_size: u64,
        ed2k_user_hash: [u8; 16],
    ) -> Result<Vec<Ed2kFoundSource>> {
        let cancel = CancellationToken::new();
        let mut sources = Vec::new();
        let shared_catalog = runtime.ed2k_shared_catalog.read().await.clone();
        let source_search_timeout = ed2k_source_search_timeout(&config.p2p.ed2k);
        let hello_identity = Ed2kHelloIdentity {
            user_hash: ed2k_user_hash,
            client_id: 0,
            tcp_port: config.p2p.ed2k.listen_port,
            udp_port: config.p2p.kad.listen_port,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(config.p2p.ed2k.obfuscation_enabled),
            direct_udp_callback: false,
        };
        let (preferred_endpoint, background_search) = {
            let server_state = runtime.ed2k_server_state.read().await;
            if server_state.connected {
                (
                    server_state.endpoint,
                    Some(runtime.ed2k_server_search.clone()),
                )
            } else {
                (None, None)
            }
        };

        let has_background_search = background_search.is_some();
        if let Some(background_search) = background_search {
            match search_source_via_background_session(
                &background_search,
                file_hash,
                file_size,
                source_search_timeout,
                &cancel,
            )
            .await
            {
                Ok(results) if !results.is_empty() => {
                    let source_count = results.len();
                    merge_download_sources(&mut sources, results);
                    info!(
                        "native ED2K download background source acquisition completed file_hash={} source_count={} aggregated_source_count={}",
                        file_hash,
                        source_count,
                        sources.len()
                    );
                }
                Ok(_) => {
                    info!(
                        "native ED2K download background source acquisition completed file_hash={} source_count=0 aggregated_source_count={}",
                        file_hash,
                        sources.len()
                    );
                    warn!(
                        "native ED2K download background source search returned no sources for file_hash={file_hash}"
                    );
                }
                Err(error) => {
                    warn!(
                        "native ED2K download background source search failed for file_hash={file_hash}: {error}"
                    );
                }
            }
        }

        let active_source_attempts = ed2k_download_source_server_attempt_budget(&config.p2p.ed2k);
        match search_source_servers(Ed2kSourceSearchOptions {
            bind_ip: runtime.bind_ip,
            config: &config.p2p.ed2k,
            hello_identity,
            shared_catalog: &shared_catalog,
            preferred_endpoint,
            excluded_endpoint: has_background_search
                .then_some(preferred_endpoint)
                .flatten(),
            max_attempts: active_source_attempts,
            file_hash,
            file_size,
            cancel: &cancel,
        })
        .await
        {
            Ok(server_results) => {
                let source_count = server_results.len();
                merge_download_sources(&mut sources, server_results);
                info!(
                    "native ED2K download active source acquisition completed file_hash={} source_count={} aggregated_source_count={}",
                    file_hash,
                    source_count,
                    sources.len()
                );
            }
            Err(error) => {
                warn!(
                    "native ED2K download active server source search failed for file_hash={file_hash}: {error}"
                );
            }
        }
        if sources.is_empty() {
            match search_source_udp_servers(Ed2kUdpSourceSearchOptions {
                bind_ip: runtime.bind_ip,
                config: &config.p2p.ed2k,
                preferred_endpoint,
                excluded_endpoint: has_background_search
                    .then_some(preferred_endpoint)
                    .flatten(),
                max_attempts: active_source_attempts,
                file_hash,
                file_size,
                timeout: source_search_timeout,
                cancel: &cancel,
            })
            .await
            {
                Ok(udp_results) => {
                    let source_count = udp_results.len();
                    merge_download_sources(&mut sources, udp_results);
                    info!(
                        "native ED2K download UDP source acquisition completed file_hash={} source_count={} aggregated_source_count={}",
                        file_hash,
                        source_count,
                        sources.len()
                    );
                }
                Err(error) => {
                    warn!(
                        "native ED2K download UDP source search failed for file_hash={file_hash}: {error}"
                    );
                }
            }
        }
        if file_size != 0 {
            let existing_source_count = sources.len();
            let kad_supplement_threshold =
                config.p2p.ed2k.kad_source_supplement_max_existing_sources;
            let should_query_kad =
                existing_source_count == 0 || existing_source_count <= kad_supplement_threshold;
            if should_query_kad {
                let kad_sources = collect_kad_ed2k_sources(
                    &runtime.dht,
                    file_hash,
                    file_size,
                    source_search_timeout.max(Duration::from_secs(
                        ED2K_DOWNLOAD_KAD_SOURCE_TIMEOUT_FLOOR_SECS,
                    )),
                )
                .await;
                let kad_source_count = kad_sources.len();
                if kad_source_count != 0 {
                    merge_download_sources(&mut sources, kad_sources);
                    let added_source_count = sources.len().saturating_sub(existing_source_count);
                    info!(
                        "native ED2K download Kad source {} produced file_hash={} source_count={} added_source_count={} aggregated_source_count={}",
                        if existing_source_count == 0 {
                            "fallback"
                        } else {
                            "supplement"
                        },
                        file_hash,
                        kad_source_count,
                        added_source_count,
                        sources.len()
                    );
                } else {
                    info!(
                        "native ED2K download Kad source {} returned no sources for file_hash={} aggregated_source_count={}",
                        if existing_source_count == 0 {
                            "fallback"
                        } else {
                            "supplement"
                        },
                        file_hash,
                        sources.len()
                    );
                }
            } else {
                info!(
                    "native ED2K download Kad source supplement skipped file_hash={} existing_source_count={} threshold={}",
                    file_hash, existing_source_count, kad_supplement_threshold
                );
            }
        } else if sources.is_empty() {
            info!(
                "native ED2K download skipped Kad source fallback for file_hash={} because file_size is unknown",
                file_hash
            );
        }
        info!(
            "native ED2K download source acquisition completed file_hash={} aggregated_source_count={} background_search_enabled={}",
            file_hash,
            sources.len(),
            has_background_search
        );
        Ok(sources)
    }

    async fn start_native_ed2k_download(
        runtime_handle: Arc<Mutex<Option<AgentNetworkRuntime>>>,
        config_handle: Arc<RwLock<EmuleAgentConfig>>,
        ed2k_user_hash: [u8; 16],
        request: EnrichEd2kDownloadRequest,
    ) -> Result<()> {
        if request.kind != "ed2k_download" {
            anyhow::bail!("unsupported enrich kind {}", request.kind);
        }

        let file_hash = Ed2kHash::from_str(&request.file_hash)
            .with_context(|| format!("invalid ED2K file hash {}", request.file_hash))?;
        let runtime = runtime_handle.lock().await.clone();
        let Some(runtime) = runtime else {
            anyhow::bail!("agent networking is waiting for interface selection");
        };
        let config = config_handle.read().await.clone();
        let mut canonical_name = request.canonical_name();
        let mut file_size = request.file_size_or_unknown();
        let adopt_learned_name =
            is_hash_only_ed2k_placeholder_name(&canonical_name, &request.file_hash);
        let shared_catalog = runtime.ed2k_shared_catalog.read().await.clone();
        runtime
            .ed2k_transfer
            .ensure_job(&new_transfer_job(
                file_hash,
                canonical_name.clone(),
                file_size,
            ))
            .await?;
        runtime
            .ed2k_transfer
            .reclaim_stale_piece_requests(&request.file_hash)
            .await?;
        if request.sources.is_empty()
            && (file_size == 0 || adopt_learned_name)
            && let Some(learned_metadata) =
                resolve_hash_only_ed2k_metadata(&runtime, &config, file_hash, ed2k_user_hash)
                    .await?
        {
            let manifest = runtime
                .ed2k_transfer
                .reconcile_job_metadata(
                    &request.file_hash,
                    adopt_learned_name
                        .then_some(learned_metadata.canonical_name.as_deref())
                        .flatten(),
                    learned_metadata.file_size,
                )
                .await?;
            canonical_name = manifest.canonical_name.clone();
            file_size = manifest.file_size;
            info!(
                "native ED2K download reconciled hash-only metadata file_hash={} file_name={} file_size={}",
                request.file_hash, canonical_name, file_size
            );
        }
        let hello_identity = Ed2kHelloIdentity {
            user_hash: ed2k_user_hash,
            client_id: 0,
            tcp_port: config.p2p.ed2k.listen_port,
            udp_port: config.p2p.kad.listen_port,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(config.p2p.ed2k.obfuscation_enabled),
            direct_udp_callback: false,
        };
        let auto_acquire_sources = request.sources.is_empty();
        let mut sources = if auto_acquire_sources {
            Self::native_ed2k_download_sources(
                &runtime,
                &config,
                file_hash,
                file_size,
                ed2k_user_hash,
            )
            .await?
        } else {
            request
                .sources
                .into_iter()
                .map(|source| source.into_found_source(file_hash))
                .collect::<Result<Vec<_>>>()?
        };
        if sources.is_empty() {
            anyhow::bail!("no ED2K sources available for {}", request.file_hash);
        }

        sort_native_ed2k_download_sources(&mut sources);

        // Low-ID peers often arrive noticeably later than direct ED2K connects
        // because the server-mediated callback has to propagate first.
        let callback_timeout = Duration::from_secs(config.p2p.ed2k.connect_timeout_secs.max(30));
        let mut attempted_direct_endpoints: HashSet<Ed2kSourceEndpointKey> = HashSet::new();
        let mut requested_callback_sources = HashSet::new();
        let mut had_direct_sources = false;
        let mut accepted_incomplete_peers = 0u32;
        let mut last_direct_error: Option<anyhow::Error> = None;
        let mut source_requery_round = 0usize;

        loop {
            sort_native_ed2k_download_sources(&mut sources);
            let pre_filter_source_count = sources.len();
            let post_filter_source_count = sources
                .iter()
                .filter(|source| source.is_direct_dialable())
                .count();
            let callback_only_sources: Vec<_> = sources
                .iter()
                .filter(|source| source.low_id)
                .cloned()
                .collect();
            let skipped_low_id_sources = callback_only_sources.len();
            info!(
                "native ED2K download source filtering file_hash={} pre_filter_source_count={} callback_only_source_count={} post_filter_source_count={} requery_round={}",
                request.file_hash,
                pre_filter_source_count,
                skipped_low_id_sources,
                post_filter_source_count,
                source_requery_round
            );
            if skipped_low_id_sources != 0 {
                info!(
                    "native ED2K download filtered callback-only sources file_hash={} skipped_low_id_sources={} requery_round={}",
                    request.file_hash, skipped_low_id_sources, source_requery_round
                );
            }

            if !callback_only_sources.is_empty() {
                let cancel = CancellationToken::new();
                for source in &callback_only_sources {
                    let source_key = ed2k_source_attempt_key(source);
                    if !requested_callback_sources.insert(source_key) {
                        continue;
                    }
                    runtime
                        .ed2k_transfer
                        .register_callback_intent(Ed2kCallbackIntent {
                            client_id: source.client_id,
                            file_hash: request.file_hash.clone(),
                            canonical_name: canonical_name.clone(),
                            file_size,
                            source: Ed2kSourceHint {
                                ip: source.ip.to_string(),
                                tcp_port: source.tcp_port,
                                user_hash: source.user_hash.map(hex::encode),
                            },
                        })
                        .await;
                    info!(
                        "native ED2K download requesting server callback file_hash={} client_id={} tcp_port={} source_server={} requery_round={}",
                        request.file_hash,
                        source.client_id,
                        source.tcp_port,
                        source
                            .source_server
                            .map_or_else(|| "-".to_string(), |endpoint| endpoint.to_string()),
                        source_requery_round
                    );
                    let callback_result = if let Some(source_server) = source.source_server {
                        request_callback_on_server(Ed2kCallbackRequestOptions {
                            bind_ip: runtime.bind_ip,
                            config: &config.p2p.ed2k,
                            hello_identity,
                            shared_catalog: &shared_catalog,
                            server_endpoint: source_server,
                            client_id: source.client_id,
                            timeout: callback_timeout,
                            cancel: &cancel,
                        })
                        .await
                    } else {
                        request_callback_via_background_session(
                            &runtime.ed2k_server_search,
                            source.client_id,
                            callback_timeout,
                            &cancel,
                        )
                        .await
                    };
                    match callback_result {
                        Ok(()) => {}
                        Err(error) => warn!(
                            "native ED2K server callback request failed file_hash={} client_id={} source_server={}: {error}",
                            request.file_hash,
                            source.client_id,
                            source
                                .source_server
                                .map_or_else(|| "-".to_string(), |endpoint| endpoint.to_string())
                        ),
                    }
                }
            }

            let direct_sources =
                direct_download_candidate_sources(&sources, &attempted_direct_endpoints);
            had_direct_sources |= !direct_sources.is_empty();
            if direct_sources.is_empty() && requested_callback_sources.is_empty() {
                info!(
                    "native ED2K download source filtering left no direct-dialable sources file_hash={} callback_only_source_count={} requery_round={}",
                    request.file_hash, skipped_low_id_sources, source_requery_round
                );
            }
            for source in &direct_sources {
                dump_ed2k_tcp_download_meta(
                    SocketAddr::new(IpAddr::V4(source.ip), source.tcp_port),
                    None,
                    "source_candidate",
                    format!(
                        "file_hash={} client_id={} low_id={} obfuscated={} has_user_hash={} requery_round={}",
                        request.file_hash,
                        source.client_id,
                        source.low_id,
                        source.obfuscated,
                        source.user_hash.is_some(),
                        source_requery_round
                    ),
                );
                attempted_direct_endpoints.insert(ed2k_source_endpoint_key(source));
            }
            if !direct_sources.is_empty() {
                let outcome = Self::run_native_ed2k_direct_downloads(
                    NativeDirectDownloadOptions {
                        bind_ip: runtime.bind_ip,
                        hello_identity,
                        secure_ident: Arc::clone(&runtime.ed2k_secure_ident),
                        transfer_runtime: Arc::clone(&runtime.ed2k_transfer),
                        file_hash_hex: request.file_hash.clone(),
                        file_name: canonical_name.clone(),
                        file_size,
                        sources: direct_sources,
                        connect_timeout: Duration::from_secs(
                            config.p2p.ed2k.connect_timeout_secs.max(10),
                        ),
                        max_parallel_download_peers: config.p2p.ed2k.max_parallel_download_peers,
                    },
                    |bind_ip,
                     source,
                     hello_identity,
                     secure_ident,
                     transfer_runtime,
                     file_name,
                     file_size,
                     connect_timeout| async move {
                        download_file_from_peer(Ed2kPeerDownloadOptions {
                            bind_ip,
                            peer: &source,
                            hello_identity,
                            secure_ident: &secure_ident,
                            transfer_runtime: transfer_runtime.as_ref(),
                            canonical_name: file_name,
                            file_size,
                            timeout: connect_timeout,
                        })
                        .await
                    },
                )
                .await?;

                if outcome.completed {
                    let manifest = runtime.ed2k_transfer.manifest(&request.file_hash).await?;
                    dump_ed2k_tcp_download_meta(
                        SocketAddr::new(IpAddr::V4(runtime.bind_ip), config.p2p.ed2k.listen_port),
                        None,
                        "download_completed",
                        format!(
                            "file_hash={} file_name={} expected_size={} manifest_size={} verified_ranges={} completed={}",
                            request.file_hash,
                            manifest.canonical_name,
                            file_size,
                            manifest.file_size,
                            manifest.verified_ranges.len(),
                            manifest.completed
                        ),
                    );
                    info!(
                        "native ED2K download completed file_hash={} file_name={} size={}",
                        request.file_hash, manifest.canonical_name, manifest.file_size
                    );
                    return Ok(());
                }
                if outcome.accepted_incomplete_peers != 0 {
                    accepted_incomplete_peers =
                        accepted_incomplete_peers.saturating_add(outcome.accepted_incomplete_peers);
                    dump_ed2k_tcp_download_meta(
                        SocketAddr::new(IpAddr::V4(runtime.bind_ip), config.p2p.ed2k.listen_port),
                        None,
                        "download_accepted_incomplete_peers",
                        format!(
                            "file_hash={} accepted_incomplete_peers={} total_accepted_incomplete_peers={}",
                            request.file_hash,
                            outcome.accepted_incomplete_peers,
                            accepted_incomplete_peers
                        ),
                    );
                }
                if let Some(error) = outcome.last_error {
                    last_direct_error = Some(error);
                }
            }

            if auto_acquire_sources
                && file_size != 0
                && source_requery_round < ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS
            {
                let manifest = runtime.ed2k_transfer.manifest(&request.file_hash).await?;
                let known_new_direct_source_count =
                    new_direct_ed2k_source_count(&sources, &attempted_direct_endpoints);
                if should_skip_no_progress_source_requery(
                    had_direct_sources,
                    manifest_has_ed2k_transfer_progress(&manifest),
                    known_new_direct_source_count,
                ) {
                    info!(
                        "native ED2K download skipping source refresh file_hash={} reason=no_progress_repeated_endpoints attempted_direct_endpoints={} known_new_direct_source_count={} md4_hashset_acquired={} verified_ranges={}",
                        request.file_hash,
                        attempted_direct_endpoints.len(),
                        known_new_direct_source_count,
                        manifest.md4_hashset_acquired,
                        manifest.verified_ranges.len()
                    );
                    break;
                }
                source_requery_round += 1;
                info!(
                    "native ED2K download refreshing sources file_hash={} requery_round={} attempted_direct_endpoints={}",
                    request.file_hash,
                    source_requery_round,
                    attempted_direct_endpoints.len()
                );
                if source_requery_round > 1 {
                    tokio::time::sleep(Duration::from_secs(
                        ED2K_DOWNLOAD_SOURCE_REQUERY_DELAY_SECS,
                    ))
                    .await;
                }
                match Self::native_ed2k_download_sources(
                    &runtime,
                    &config,
                    file_hash,
                    file_size,
                    ed2k_user_hash,
                )
                .await
                {
                    Ok(refreshed_sources) => {
                        let refreshed_source_count = refreshed_sources.len();
                        let previous_source_count = sources.len();
                        merge_download_sources(&mut sources, refreshed_sources);
                        let added_source_count =
                            sources.len().saturating_sub(previous_source_count);
                        let new_direct_source_count =
                            new_direct_ed2k_source_count(&sources, &attempted_direct_endpoints);
                        info!(
                            "native ED2K download source refresh completed file_hash={} requery_round={} refreshed_source_count={} added_source_count={} aggregated_source_count={} new_direct_source_count={}",
                            request.file_hash,
                            source_requery_round,
                            refreshed_source_count,
                            added_source_count,
                            sources.len(),
                            new_direct_source_count
                        );
                        let manifest = runtime.ed2k_transfer.manifest(&request.file_hash).await?;
                        let manifest_has_progress = manifest_has_ed2k_transfer_progress(&manifest);
                        if manifest_has_progress {
                            info!(
                                "native ED2K download source refresh preserving in-progress transfer file_hash={} requery_round={} md4_hashset_acquired={} verified_ranges={}",
                                request.file_hash,
                                source_requery_round,
                                manifest.md4_hashset_acquired,
                                manifest.verified_ranges.len()
                            );
                            continue;
                        }
                        if new_direct_source_count != 0 {
                            continue;
                        }
                        if !had_direct_sources
                            && source_requery_round < ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS
                        {
                            continue;
                        }
                    }
                    Err(error) => {
                        warn!(
                            "native ED2K download source refresh failed file_hash={} requery_round={}: {error}",
                            request.file_hash, source_requery_round
                        );
                        if source_requery_round < ED2K_DOWNLOAD_SOURCE_REQUERY_ROUNDS {
                            continue;
                        }
                    }
                }
            }
            break;
        }

        if !requested_callback_sources.is_empty() {
            tokio::time::sleep(callback_timeout).await;
            let manifest = Self::await_callback_transfer_completion(
                runtime.ed2k_transfer.as_ref(),
                &request.file_hash,
                &runtime.ed2k_transfer.manifest(&request.file_hash).await?,
                Duration::from_secs(callback_timeout.as_secs().max(90)),
            )
            .await?;
            if manifest.completed {
                return Ok(());
            }
            if manifest_has_ed2k_transfer_progress(&manifest) {
                info!(
                    "native ED2K callback transfer remains in progress after grace window file_hash={} bytes_written={} md4_hashset_acquired={}",
                    request.file_hash,
                    manifest
                        .pieces
                        .iter()
                        .map(|piece| piece.bytes_written)
                        .sum::<u64>(),
                    manifest.md4_hashset_acquired
                );
                return Ok(());
            }
        }

        let manifest = runtime.ed2k_transfer.manifest(&request.file_hash).await?;
        if manifest.completed {
            return Ok(());
        }
        if had_direct_sources {
            if let Some(error) = last_direct_error {
                return Err(error).with_context(|| {
                    format!(
                        "native ED2K download did not complete for {} after trying discovered sources",
                        request.file_hash
                    )
                });
            }
            if accepted_incomplete_peers != 0 {
                anyhow::bail!(
                    "native ED2K download for {} did not complete after {} accepted incomplete peer sessions",
                    request.file_hash,
                    accepted_incomplete_peers
                );
            }
            anyhow::bail!(
                "native ED2K download for {} did not complete and no peer reported a concrete error",
                request.file_hash
            );
        }
        anyhow::bail!(
            "native ED2K download found only callback-only or otherwise non-dialable sources for {}",
            request.file_hash
        );
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

            let outcome = Self::start_native_ed2k_download(
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

    async fn await_callback_transfer_completion(
        transfer_runtime: &Ed2kTransferRuntime,
        file_hash: &str,
        initial_manifest: &Ed2kResumeManifest,
        wait_budget: Duration,
    ) -> Result<Ed2kResumeManifest> {
        if initial_manifest.completed {
            return Ok(initial_manifest.clone());
        }
        let started = Instant::now();
        let poll_interval = Duration::from_secs(2);
        let mut last_manifest = initial_manifest.clone();
        while started.elapsed() < wait_budget {
            tokio::time::sleep(poll_interval).await;
            let manifest = transfer_runtime.manifest(file_hash).await?;
            if manifest.completed || !manifest.verified_ranges.is_empty() {
                return Ok(manifest);
            }
            last_manifest = manifest;
        }
        Ok(last_manifest)
    }

    async fn spawn_background_tasks(
        &self,
        runtime: &AgentNetworkRuntime,
        config: &EmuleAgentConfig,
    ) {
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let state_paths = self.state_paths.clone();
        let routing_refresh_interval =
            Duration::from_secs(config.p2p.kad.routing_refresh_interval_secs.max(1));
        let nodes_dat_refresh_interval =
            Duration::from_secs(config.p2p.kad.nodes_dat_refresh_interval_secs.max(1));
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let mut last_nodes_dat_persist = Instant::now();
            let mut last_persisted_contact_count = dht.routing_contacts().await.len();
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(routing_refresh_interval).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }

                let target = random_routing_refresh_target();
                let started_at = Instant::now();
                let contacts_before = dht.routing_contacts().await.len();
                match dht
                    .lookup_nodes_with_class(&target, RpcWorkClass::Maintenance)
                    .await
                {
                    Ok(closest) => {
                        let contacts_after = dht.routing_contacts().await.len();
                        info!(
                            "kad routing refresh target={} closest={} contacts_before={} contacts_after={} elapsed_ms={}",
                            target,
                            closest.len(),
                            contacts_before,
                            contacts_after,
                            started_at.elapsed().as_millis()
                        );

                        let snapshot_due =
                            last_nodes_dat_persist.elapsed() >= nodes_dat_refresh_interval;
                        if contacts_after != last_persisted_contact_count || snapshot_due {
                            if let Err(error) = persist_nodes_dat_for(&dht, &state_paths).await {
                                warn!("failed to persist nodes.dat after routing refresh: {error}");
                            } else {
                                last_nodes_dat_persist = Instant::now();
                                last_persisted_contact_count = contacts_after;
                            }
                        }
                    }
                    Err(error) => debug!("kad routing refresh failed target={target}: {error}"),
                }
            }
        }));

        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let state_paths = self.state_paths.clone();
        let coordinator = self.coordinator.clone();
        let local_store = Arc::clone(&self.local_store);
        let publish_batch_gate = Arc::clone(&self.publish_batch_gate);
        let publish_observability = Arc::clone(&self.publish_observability);
        let agent_activity = Arc::clone(&self.agent_activity);
        let ed2k_shared_catalog = Arc::clone(&runtime.ed2k_shared_catalog);
        let source_publish_identity = source_publish_client_hash(self.ed2k_user_hash);
        let source_publish_settings = SourcePublishSettings {
            tcp_port: config.p2p.ed2k.listen_port,
            obfuscation_enabled: config.p2p.ed2k.obfuscation_enabled,
        };
        let notes_publish_enabled = config.p2p.kad.seed_notes_publish_enabled;
        let publish_contact_fanout = config.p2p.kad.publish_contact_fanout;
        let synthetic_publish_interval_secs = config.p2p.kad.synthetic_publish_interval_secs;
        let synthetic_publish_batch_items = config.p2p.kad.synthetic_publish_batch_items;
        let synthetic_publish_contact_fanout = config.p2p.kad.synthetic_publish_contact_fanout;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let bootstrap_started_at = Utc::now();
            let mut bootstrap_snapshot =
                new_activity_snapshot(AgentActivityState::Bootstrapping, bootstrap_started_at);
            bootstrap_snapshot.query_or_target = Some("kad dht".to_string());
            begin_agent_activity(
                &agent_activity,
                ACTIVITY_KEY_BOOTSTRAPPING.to_string(),
                bootstrap_snapshot,
            )
            .await;
            while !shutdown.load(Ordering::Relaxed) && !dht.is_bootstrapped() {
                match dht.bootstrap_with_class(RpcWorkClass::Maintenance).await {
                    Ok(()) => {
                        if let Err(error) = persist_nodes_dat_for(&dht, &state_paths).await {
                            warn!("failed to persist nodes.dat after bootstrap: {error}");
                        }
                        if let Err(error) = seed_coordinator_popular_if_available(
                            &dht,
                            source_publish_identity,
                            source_publish_settings,
                            &coordinator,
                            &ed2k_shared_catalog,
                            PublishExecutionContext {
                                local_store: &local_store,
                                publish_batch_gate: &publish_batch_gate,
                                publish_observability: &publish_observability,
                                agent_activity: &agent_activity,
                                activity_key: None,
                                notes_publish_enabled,
                                work_class: RpcWorkClass::Publish,
                                publish_contact_fanout,
                            },
                        )
                        .await
                        {
                            debug!("post-bootstrap coordinator seeding failed: {error}");
                        }
                        set_synthetic_publish_queue_depth(
                            &publish_observability,
                            SYNTHETIC_POPULAR_SEEDS.len(),
                        )
                        .await;
                        finish_agent_activity(
                            &agent_activity,
                            ACTIVITY_KEY_BOOTSTRAPPING,
                            Utc::now(),
                        )
                        .await;
                        clear_agent_degraded_activity(&agent_activity).await;
                        break;
                    }
                    Err(error) => {
                        let error_message = error.to_string();
                        debug!("bootstrap retry failed: {error_message}");
                        update_agent_activity_error(
                            &agent_activity,
                            ACTIVITY_KEY_BOOTSTRAPPING,
                            error_message,
                            Utc::now(),
                        )
                        .await;
                    }
                }
                tokio::time::sleep(Duration::from_secs(BOOTSTRAP_RETRY_SECS)).await;
            }
            finish_agent_activity(&agent_activity, ACTIVITY_KEY_BOOTSTRAPPING, Utc::now()).await;
        }));

        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let snoop_queue = Arc::clone(&self.snoop_queue);
        let observed_snoop_events = Arc::clone(&self.observed_snoop_events);
        let local_store = Arc::clone(&self.local_store);
        let harvest_observability = Arc::clone(&self.harvest_observability);
        let kad_firewall = Arc::clone(&runtime.kad_firewall);
        let ed2k_listener = Arc::clone(&runtime.ed2k_listener);
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let ed2k_user_hash = self.ed2k_user_hash;
        let ed2k_obfuscation_enabled = config.p2p.ed2k.obfuscation_enabled;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let mut packets = dht.subscribe_packets();
            while !shutdown.load(Ordering::Relaxed) {
                match packets.recv().await {
                    Ok(received) => {
                        if let Err(error) = handle_unsolicited_packet(
                            &dht,
                            UnsolicitedPacketContext {
                                snoop_queue: &snoop_queue,
                                observed_snoop_events: &observed_snoop_events,
                                local_store: &local_store,
                                harvest_observability: &harvest_observability,
                                kad_firewall: &kad_firewall,
                                ed2k_listener: &ed2k_listener,
                                ed2k_server_state: &ed2k_server_state,
                                ed2k_user_hash: Ed2kHash::from_bytes(ed2k_user_hash),
                                ed2k_obfuscation_enabled,
                            },
                            received,
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

        let dht = runtime.dht.clone();
        let ed2k_listener = Arc::clone(&runtime.ed2k_listener);
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let kad_firewall = Arc::clone(&runtime.kad_firewall);
        let ed2k_secure_ident = Arc::clone(&runtime.ed2k_secure_ident);
        let ed2k_transfer = Arc::clone(&runtime.ed2k_transfer);
        let shutdown = Arc::clone(&runtime.shutdown);
        let ed2k_user_hash = self.ed2k_user_hash;
        let ed2k_hello_identity = Ed2kHelloIdentity {
            user_hash: ed2k_user_hash,
            client_id: 0,
            tcp_port: config.p2p.ed2k.listen_port,
            udp_port: config.p2p.kad.listen_port,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(config.p2p.ed2k.obfuscation_enabled),
            direct_udp_callback: false,
        };
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            run_ed2k_listener(Ed2kListenerOptions {
                listener: ed2k_listener,
                dht,
                server_state: ed2k_server_state,
                kad_firewall,
                secure_ident: ed2k_secure_ident,
                transfer_runtime: ed2k_transfer,
                hello_identity: ed2k_hello_identity,
                shutdown,
            })
            .await;
        }));

        let bind_ip = runtime.bind_ip;
        let nat = Arc::clone(&runtime.nat);
        let shutdown = Arc::clone(&runtime.shutdown);
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let ed2k_shared_catalog = Arc::clone(&runtime.ed2k_shared_catalog);
        let ed2k_server_search_inbox = runtime.ed2k_server_search_inbox.lock().await.take();
        let kad_firewall = Arc::clone(&runtime.kad_firewall);
        let ed2k_server_config = config.p2p.ed2k.clone();
        let ed2k_user_hash = self.ed2k_user_hash;
        let ed2k_hello_identity = Ed2kHelloIdentity {
            user_hash: ed2k_user_hash,
            client_id: 0,
            tcp_port: config.p2p.ed2k.listen_port,
            udp_port: config.p2p.kad.listen_port,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(config.p2p.ed2k.obfuscation_enabled),
            direct_udp_callback: false,
        };
        if let Some(ed2k_server_search_inbox) = ed2k_server_search_inbox {
            runtime.tasks.lock().await.push(tokio::spawn(async move {
                run_ed2k_server_loop(Ed2kServerLoopOptions {
                    bind_ip,
                    nat,
                    config: ed2k_server_config,
                    hello_identity: ed2k_hello_identity,
                    shared_catalog: ed2k_shared_catalog,
                    state: ed2k_server_state,
                    search_inbox: ed2k_server_search_inbox,
                    kad_firewall,
                    shutdown,
                })
                .await;
            }));
        } else {
            warn!("ED2K server loop inbox was already taken; skipping ED2K server loop spawn");
        }

        let dht = runtime.dht.clone();
        let nat = Arc::clone(&runtime.nat);
        let shutdown = Arc::clone(&runtime.shutdown);
        let kad_firewall = Arc::clone(&runtime.kad_firewall);
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let ed2k_secure_ident = Arc::clone(&runtime.ed2k_secure_ident);
        let udp_firewall_check_enabled = config.p2p.kad.udp_firewall_check_enabled;
        let udp_firewall_recheck_interval =
            Duration::from_secs(config.p2p.kad.udp_firewall_recheck_interval_secs.max(1));
        let udp_firewall_check_timeout =
            Duration::from_secs(config.p2p.kad.udp_firewall_check_timeout_secs.max(1));
        let udp_firewall_check_contact_count = config.p2p.kad.udp_firewall_check_contact_count;
        let ed2k_user_hash = self.ed2k_user_hash;
        let ed2k_hello_identity = Ed2kHelloIdentity {
            user_hash: ed2k_user_hash,
            client_id: 0,
            tcp_port: config.p2p.ed2k.listen_port,
            udp_port: config.p2p.kad.listen_port,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(config.p2p.ed2k.obfuscation_enabled),
            direct_udp_callback: false,
        };
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            if !udp_firewall_check_enabled {
                return;
            }

            while !shutdown.load(Ordering::Relaxed) {
                if !dht.is_bootstrapped() {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    continue;
                }

                let bind_addr = match dht.bind_addr() {
                    Ok(bind_addr) => bind_addr,
                    Err(error) => {
                        debug!("kad firewall-check skipped: failed to resolve bind addr: {error}");
                        continue;
                    }
                };
                let helper_hello_identity = enrich_hello_identity(
                    ed2k_hello_identity,
                    &ed2k_server_state,
                    &kad_firewall,
                )
                .await;
                if helper_hello_identity.client_id == 0
                    || helper_hello_identity.server_ip == 0
                    || helper_hello_identity.server_port == 0
                {
                    debug!(
                        "kad firewall-check skipped: ED2K helper hello not ready client_id={} server_ip={} server_port={}",
                        helper_hello_identity.client_id,
                        Ipv4Addr::from(helper_hello_identity.server_ip.to_le_bytes()),
                        helper_hello_identity.server_port
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                let helper_contacts = match select_udp_firewall_helpers(
                    &dht,
                    udp_firewall_check_contact_count
                        .saturating_mul(UDP_FIREWALL_HELPER_CANDIDATE_MULTIPLIER),
                )
                .await
                {
                    Ok(contacts) => contacts,
                    Err(error) => {
                        debug!("kad firewall-check helper selection failed: {error}");
                        continue;
                    }
                };
                if helper_contacts.is_empty() {
                    debug!("kad firewall-check skipped: no helper contacts available");
                    continue;
                }

                let bind_ip = match bind_addr.ip() {
                    IpAddr::V4(ip) => ip,
                    IpAddr::V6(_) => {
                        debug!("kad firewall-check skipped: IPv6 bind addr is not supported");
                        continue;
                    }
                };
                let active_ports =
                    active_udp_firewall_ports(&dht, &nat, &kad_firewall, bind_addr.port()).await;
                let expected_ports = active_ports.expected_ports();
                let started_at = Utc::now();
                {
                    let mut firewall = kad_firewall.lock().await;
                    if !firewall.begin_udp_check(
                        helper_contacts.iter().map(|contact| IpAddr::V4(contact.ip)),
                        expected_ports.iter().copied(),
                        started_at,
                    ) {
                        continue;
                    }
                }

                let internal_udp_port = active_ports.internal;
                let external_udp_port = active_ports.external;
                info!(
                    "starting kad udp firewall-check target_helpers={} candidate_helpers={} internal_port={} external_port={}",
                    udp_firewall_check_contact_count,
                    helper_contacts.len(),
                    internal_udp_port,
                    external_udp_port
                );
                debug!(
                    "kad udp firewall-check helper hello client_id={} server_ip={} server_port={} direct_udp_callback={}",
                    helper_hello_identity.client_id,
                    Ipv4Addr::from(helper_hello_identity.server_ip.to_le_bytes()),
                    helper_hello_identity.server_port,
                    helper_hello_identity.direct_udp_callback
                );

                let mut request_tasks = Vec::with_capacity(helper_contacts.len());
                for contact in helper_contacts {
                    let helper_addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.tcp_port);
                    let helper_ip = IpAddr::V4(contact.ip);
                    let request = FirewallCheckUdpRequest {
                        internal_udp_port,
                        external_udp_port,
                        sender_udp_key: dht.verify_key_for_ip(contact.ip),
                    };
                    let secure_ident = Arc::clone(&ed2k_secure_ident);
                    let helper_dht = dht.clone();
                    request_tasks.push(tokio::spawn(async move {
                        let result = request_udp_firewall_check(
                            Some(helper_dht),
                            bind_ip,
                            helper_addr,
                            helper_hello_identity,
                            secure_ident,
                            request,
                            udp_firewall_check_timeout,
                        )
                        .await;
                        (helper_ip, helper_addr, result)
                    }));
                }

                for task in request_tasks {
                    match task.await {
                        Ok((_helper_ip, helper_addr, Ok(()))) => {
                            debug!("sent OP_FWCHECKUDPREQ to helper {helper_addr}");
                        }
                        Ok((helper_ip, helper_addr, Err(error))) => {
                            let mut firewall = kad_firewall.lock().await;
                            firewall.record_helper_request_failed(helper_ip, &error.to_string());
                            debug!("failed to send OP_FWCHECKUDPREQ to helper {helper_addr}: {error}");
                        }
                        Err(error) => {
                            debug!("UDP firewall-check helper task failed: {error}");
                        }
                    }
                }

                tokio::time::sleep(udp_firewall_check_timeout).await;
                let summary = {
                    let mut firewall = kad_firewall.lock().await;
                    firewall.finish_udp_check(Utc::now())
                };
                if let Some(summary) = summary {
                    if summary.open {
                        info!(
                            "kad udp firewall-check completed open helpers_selected={} helpers_requested={} helpers_succeeded={} helpers_failed={} elapsed_ms={}",
                            summary.helpers_selected,
                            summary.helpers_requested,
                            summary.helpers_succeeded,
                            summary.helpers_failed,
                            (summary.completed_at - summary.started_at).num_milliseconds()
                        );
                    } else {
                        warn!(
                            "kad udp firewall-check completed firewalled helpers_selected={} helpers_requested={} helpers_succeeded={} helpers_failed={} elapsed_ms={}",
                            summary.helpers_selected,
                            summary.helpers_requested,
                            summary.helpers_succeeded,
                            summary.helpers_failed,
                            (summary.completed_at - summary.started_at).num_milliseconds()
                        );
                    }
                }
                tokio::time::sleep(udp_firewall_recheck_interval).await;
            }
        }));

        let dht = runtime.dht.clone();
        let ed2k_listener = Arc::clone(&runtime.ed2k_listener);
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let kad_firewall = Arc::clone(&runtime.kad_firewall);
        let shutdown = Arc::clone(&runtime.shutdown);
        let hello_intro_interval_secs = config.p2p.kad.hello_intro_interval_secs;
        let hello_intro_fanout = config.p2p.kad.hello_intro_fanout;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let mut introduced = std::collections::HashSet::new();
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(hello_intro_interval_secs.max(1))).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }

                let local_ip = match dht.bind_addr() {
                    Ok(bind_addr) => bind_addr.ip(),
                    Err(error) => {
                        debug!("kad hello intro skipped: failed to resolve bind addr: {error}");
                        continue;
                    }
                };
                let mut contacts = dht
                    .routing_contacts()
                    .await
                    .into_iter()
                    .filter_map(|contact| {
                        let addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.udp_port);
                        (contact.udp_port != 0
                            && contact.kad_version >= 6
                            && IpAddr::V4(contact.ip) != local_ip
                            && !introduced.contains(&addr))
                        .then_some((contact, addr))
                    })
                    .collect::<Vec<_>>();
                contacts.shuffle(&mut rand::thread_rng());

                for (contact, addr) in contacts.into_iter().take(hello_intro_fanout.max(1)) {
                    // eMule requests HELLO_RES_ACK from HELLO_RES, not from proactive HELLO_REQ.
                    let request_ack = false;
                    let hello = match build_hello_request(
                        &dht,
                        &ed2k_listener,
                        &ed2k_server_state,
                        &kad_firewall,
                        request_ack,
                    )
                    .await
                    {
                        Ok(hello) => hello,
                        Err(error) => {
                            debug!("failed to build Kad hello request for {addr}: {error}");
                            continue;
                        }
                    };
                    debug!(
                        "sending Kad hello request to={} contact_id={} contact_version={} request_ack={}",
                        addr,
                        contact.id,
                        contact.kad_version,
                        request_ack
                    );
                    if let Err(error) = dht
                        .send_packet_with_class(
                            addr,
                            &KadPacket::HelloReq(hello),
                            RpcWorkClass::Maintenance,
                        )
                        .await
                    {
                        debug!("failed to send Kad hello request to {addr}: {error}");
                        continue;
                    }
                    introduced.insert(addr);
                }
            }
        }));

        let coordinator = self.coordinator.clone();
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let snoop_queue = Arc::clone(&self.snoop_queue);
        let indexer_id = self.indexer_id;
        let passive_result_count = Arc::clone(&runtime.passive_result_count);
        let passive_replay_gate = Arc::clone(&runtime.passive_replay_gate);
        let harvest_observability = Arc::clone(&self.harvest_observability);
        let agent_activity = Arc::clone(&self.agent_activity);
        let passive_replay_phase2_fanout = config.p2p.kad.search_phase2_fanout;
        let passive_source_stop_after_results = config.p2p.snoop_queue.source_stop_after_results;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(PASSIVE_SOURCE_CRAWL_SECS)).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }
                let Some(_replay_permit) =
                    try_acquire_passive_replay_gate(&passive_replay_gate, "source-fast-path")
                else {
                    continue;
                };
                let Some(selected_request) =
                    next_passive_replay_request_for_family(&snoop_queue, HarvestFamily::Source)
                        .await
                else {
                    record_passive_replay_idle_for_worker(
                        &harvest_observability,
                        Some(HarvestFamily::Source),
                        Utc::now(),
                    )
                    .await;
                    continue;
                };
                match selected_request {
                    PassiveReplaySelection::Keyword(selected_request) => {
                        let request = selected_request.request;
                        let replay_started_at = Utc::now();
                        let replay_context = HarvestReplayContext {
                            replay_id: Uuid::new_v4(),
                            family: HarvestFamily::Keyword,
                            logical_key: selected_request.logical_key,
                            target: request.target.to_string(),
                            start_position: Some(request.start_position),
                            size: None,
                            restrictive_payload_hex: (!request.restrictive_payload.is_empty())
                                .then(|| hex::encode(&request.restrictive_payload)),
                        };
                        let activity_key = passive_replay_key(replay_context.replay_id);
                        let mut activity_snapshot = new_activity_snapshot(
                            AgentActivityState::PassiveHarvestReplay,
                            replay_started_at,
                        );
                        activity_snapshot.query_or_target = Some(
                            passive_replay_activity_context(
                                HarvestFamily::Keyword,
                                replay_context.target.as_str(),
                            ),
                        );
                        begin_agent_activity(
                            &agent_activity,
                            activity_key.clone(),
                            activity_snapshot.clone(),
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_start(
                                &mut observability,
                                HarvestFamily::Keyword,
                                request.target.to_string(),
                                Some(request.start_position),
                                Some(request.restrictive_payload.len() as u32),
                                replay_started_at,
                            );
                        }
                        info!(
                            "kad passive replay start target={} start_position={} restrictive_bytes={}",
                            request.target,
                            request.start_position,
                            request.restrictive_payload.len()
                        );
                        let outcome = run_passive_keyword_replay(
                            PassiveReplayContext {
                                dht: &dht,
                                coordinator: &coordinator,
                                indexer_id,
                                replay_context: &replay_context,
                                max_phase2_fanout: passive_replay_phase2_fanout,
                                source_stop_after_results: passive_source_stop_after_results,
                                passive_result_count: &passive_result_count,
                                harvest_observability: &harvest_observability,
                            },
                            &request,
                        )
                        .await;
                        let replay_completed_at = Utc::now();
                        record_passive_replay_outcome(
                            &snoop_queue,
                            &replay_context.logical_key,
                            replay_completed_at,
                            outcome.result_count,
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_complete(
                                &mut observability,
                                HarvestFamily::Keyword,
                                replay_completed_at,
                                outcome.result_count,
                                outcome.batch_count,
                                outcome.tier_summaries.clone(),
                            );
                        }
                        if let Err(error) = coordinator
                            .post_harvest_replay(&HarvestReplayRecord {
                                replay_id: replay_context.replay_id,
                                indexer_id,
                                family: replay_context.family,
                                logical_key: replay_context.logical_key.clone(),
                                target: replay_context.target.clone(),
                                start_position: replay_context.start_position,
                                size: replay_context.size,
                                restrictive_payload_hex: replay_context
                                    .restrictive_payload_hex
                                    .clone(),
                                started_at: replay_started_at,
                                completed_at: replay_completed_at,
                                result_count: outcome.result_count as u32,
                                batch_count: outcome.batch_count as u32,
                                error: outcome.last_post_error.clone(),
                            })
                            .await
                        {
                            debug!("failed to post harvest replay summary: {error}");
                        }
                        info!(
                            "kad passive replay done results={} batches_posted={}",
                            outcome.result_count, outcome.batch_count
                        );
                        finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
                        if let Some(error) = outcome.last_post_error.clone() {
                            activity_snapshot.last_error = Some(error);
                            activity_snapshot.last_update_at = Utc::now();
                            record_agent_degraded_activity(&agent_activity, activity_snapshot).await;
                        } else {
                            clear_agent_degraded_activity(&agent_activity).await;
                        }
                    }
                    PassiveReplaySelection::Source(selected_request) => {
                        let request = selected_request.request;
                        let replay_started_at = Utc::now();
                        let replay_context = HarvestReplayContext {
                            replay_id: Uuid::new_v4(),
                            family: HarvestFamily::Source,
                            logical_key: selected_request.logical_key,
                            target: request.target.to_string(),
                            start_position: Some(request.start_position),
                            size: Some(request.size),
                            restrictive_payload_hex: None,
                        };
                        let activity_key = passive_replay_key(replay_context.replay_id);
                        let mut activity_snapshot = new_activity_snapshot(
                            AgentActivityState::PassiveHarvestReplay,
                            replay_started_at,
                        );
                        activity_snapshot.query_or_target = Some(
                            passive_replay_activity_context(
                                HarvestFamily::Source,
                                replay_context.target.as_str(),
                            ),
                        );
                        begin_agent_activity(
                            &agent_activity,
                            activity_key.clone(),
                            activity_snapshot.clone(),
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_start(
                                &mut observability,
                                HarvestFamily::Source,
                                request.target.to_string(),
                                Some(request.start_position),
                                None,
                                replay_started_at,
                            );
                        }
                        debug!(
                            "kad passive source replay start target={} start_position={} size={}",
                            request.target, request.start_position, request.size
                        );
                        let outcome = run_passive_source_replay(
                            PassiveReplayContext {
                                dht: &dht,
                                coordinator: &coordinator,
                                indexer_id,
                                replay_context: &replay_context,
                                max_phase2_fanout: passive_replay_phase2_fanout,
                                source_stop_after_results: passive_source_stop_after_results,
                                passive_result_count: &passive_result_count,
                                harvest_observability: &harvest_observability,
                            },
                            &request,
                        )
                        .await;
                        let replay_completed_at = Utc::now();
                        record_passive_replay_outcome(
                            &snoop_queue,
                            &replay_context.logical_key,
                            replay_completed_at,
                            outcome.result_count,
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_complete(
                                &mut observability,
                                HarvestFamily::Source,
                                replay_completed_at,
                                outcome.result_count,
                                outcome.batch_count,
                                outcome.tier_summaries.clone(),
                            );
                        }
                        if let Err(error) = coordinator
                            .post_harvest_replay(&HarvestReplayRecord {
                                replay_id: replay_context.replay_id,
                                indexer_id,
                                family: replay_context.family,
                                logical_key: replay_context.logical_key.clone(),
                                target: replay_context.target.clone(),
                                start_position: replay_context.start_position,
                                size: replay_context.size,
                                restrictive_payload_hex: replay_context
                                    .restrictive_payload_hex
                                    .clone(),
                                started_at: replay_started_at,
                                completed_at: replay_completed_at,
                                result_count: outcome.result_count as u32,
                                batch_count: outcome.batch_count as u32,
                                error: outcome.last_post_error.clone(),
                            })
                            .await
                        {
                            debug!("failed to post source harvest replay summary: {error}");
                        }
                        debug!(
                            "kad passive source replay done results={} batches_posted={}",
                            outcome.result_count, outcome.batch_count
                        );
                        finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
                        if let Some(error) = outcome.last_post_error.clone() {
                            activity_snapshot.last_error = Some(error);
                            activity_snapshot.last_update_at = Utc::now();
                            record_agent_degraded_activity(&agent_activity, activity_snapshot).await;
                        } else {
                            clear_agent_degraded_activity(&agent_activity).await;
                        }
                    }
                    PassiveReplaySelection::Notes(selected_request) => {
                        let request = selected_request.request;
                        let replay_started_at = Utc::now();
                        let replay_context = HarvestReplayContext {
                            replay_id: Uuid::new_v4(),
                            family: HarvestFamily::Notes,
                            logical_key: selected_request.logical_key,
                            target: request.target.to_string(),
                            start_position: None,
                            size: Some(request.size),
                            restrictive_payload_hex: None,
                        };
                        let activity_key = passive_replay_key(replay_context.replay_id);
                        let mut activity_snapshot = new_activity_snapshot(
                            AgentActivityState::PassiveHarvestReplay,
                            replay_started_at,
                        );
                        activity_snapshot.query_or_target = Some(
                            passive_replay_activity_context(
                                HarvestFamily::Notes,
                                replay_context.target.as_str(),
                            ),
                        );
                        begin_agent_activity(
                            &agent_activity,
                            activity_key.clone(),
                            activity_snapshot.clone(),
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_start(
                                &mut observability,
                                HarvestFamily::Notes,
                                request.target.to_string(),
                                None,
                                None,
                                replay_started_at,
                            );
                        }
                        info!(
                            "kad passive notes replay start target={} size={}",
                            request.target, request.size
                        );
                        let outcome = run_passive_notes_replay(
                            PassiveReplayContext {
                                dht: &dht,
                                coordinator: &coordinator,
                                indexer_id,
                                replay_context: &replay_context,
                                max_phase2_fanout: passive_replay_phase2_fanout,
                                source_stop_after_results: passive_source_stop_after_results,
                                passive_result_count: &passive_result_count,
                                harvest_observability: &harvest_observability,
                            },
                            &request,
                        )
                        .await;
                        let replay_completed_at = Utc::now();
                        record_passive_replay_outcome(
                            &snoop_queue,
                            &replay_context.logical_key,
                            replay_completed_at,
                            outcome.result_count,
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_complete(
                                &mut observability,
                                HarvestFamily::Notes,
                                replay_completed_at,
                                outcome.result_count,
                                outcome.batch_count,
                                outcome.tier_summaries.clone(),
                            );
                        }
                        if let Err(error) = coordinator
                            .post_harvest_replay(&HarvestReplayRecord {
                                replay_id: replay_context.replay_id,
                                indexer_id,
                                family: replay_context.family,
                                logical_key: replay_context.logical_key.clone(),
                                target: replay_context.target.clone(),
                                start_position: replay_context.start_position,
                                size: replay_context.size,
                                restrictive_payload_hex: replay_context
                                    .restrictive_payload_hex
                                    .clone(),
                                started_at: replay_started_at,
                                completed_at: replay_completed_at,
                                result_count: outcome.result_count as u32,
                                batch_count: outcome.batch_count as u32,
                                error: outcome.last_post_error.clone(),
                            })
                            .await
                        {
                            debug!("failed to post notes harvest replay summary: {error}");
                        }
                        info!(
                            "kad passive notes replay done results={} batches_posted={}",
                            outcome.result_count, outcome.batch_count
                        );
                        finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
                        if let Some(error) = outcome.last_post_error.clone() {
                            activity_snapshot.last_error = Some(error);
                            activity_snapshot.last_update_at = Utc::now();
                            record_agent_degraded_activity(&agent_activity, activity_snapshot).await;
                        } else {
                            clear_agent_degraded_activity(&agent_activity).await;
                        }
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
        let passive_replay_gate = Arc::clone(&runtime.passive_replay_gate);
        let harvest_observability = Arc::clone(&self.harvest_observability);
        let agent_activity = Arc::clone(&self.agent_activity);
        let passive_replay_phase2_fanout = config.p2p.kad.search_phase2_fanout;
        let passive_source_stop_after_results = config.p2p.snoop_queue.source_stop_after_results;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(PASSIVE_GENERAL_CRAWL_SECS)).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }
                let Some(_replay_permit) =
                    try_acquire_passive_replay_gate(&passive_replay_gate, "general")
                else {
                    continue;
                };
                let Some(selected_request) = next_passive_replay_request(&snoop_queue).await else {
                    record_passive_replay_idle_for_worker(
                        &harvest_observability,
                        None,
                        Utc::now(),
                    )
                    .await;
                    continue;
                };
                match selected_request {
                    PassiveReplaySelection::Keyword(selected_request) => {
                        let request = selected_request.request;
                        let replay_started_at = Utc::now();
                        let replay_context = HarvestReplayContext {
                            replay_id: Uuid::new_v4(),
                            family: HarvestFamily::Keyword,
                            logical_key: selected_request.logical_key,
                            target: request.target.to_string(),
                            start_position: Some(request.start_position),
                            size: None,
                            restrictive_payload_hex: (!request.restrictive_payload.is_empty())
                                .then(|| hex::encode(&request.restrictive_payload)),
                        };
                        let activity_key = passive_replay_key(replay_context.replay_id);
                        let mut activity_snapshot = new_activity_snapshot(
                            AgentActivityState::PassiveHarvestReplay,
                            replay_started_at,
                        );
                        activity_snapshot.query_or_target = Some(
                            passive_replay_activity_context(
                                HarvestFamily::Keyword,
                                replay_context.target.as_str(),
                            ),
                        );
                        begin_agent_activity(
                            &agent_activity,
                            activity_key.clone(),
                            activity_snapshot.clone(),
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_start(
                                &mut observability,
                                HarvestFamily::Keyword,
                                request.target.to_string(),
                                Some(request.start_position),
                                Some(request.restrictive_payload.len() as u32),
                                replay_started_at,
                            );
                        }
                        info!(
                            "kad passive replay start target={} start_position={} restrictive_bytes={}",
                            request.target,
                            request.start_position,
                            request.restrictive_payload.len()
                        );
                        let outcome = run_passive_keyword_replay(
                            PassiveReplayContext {
                                dht: &dht,
                                coordinator: &coordinator,
                                indexer_id,
                                replay_context: &replay_context,
                                max_phase2_fanout: passive_replay_phase2_fanout,
                                source_stop_after_results: passive_source_stop_after_results,
                                passive_result_count: &passive_result_count,
                                harvest_observability: &harvest_observability,
                            },
                            &request,
                        )
                        .await;
                        let replay_completed_at = Utc::now();
                        record_passive_replay_outcome(
                            &snoop_queue,
                            &replay_context.logical_key,
                            replay_completed_at,
                            outcome.result_count,
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_complete(
                                &mut observability,
                                HarvestFamily::Keyword,
                                replay_completed_at,
                                outcome.result_count,
                                outcome.batch_count,
                                outcome.tier_summaries.clone(),
                            );
                        }
                        if let Err(error) = coordinator
                            .post_harvest_replay(&HarvestReplayRecord {
                                replay_id: replay_context.replay_id,
                                indexer_id,
                                family: replay_context.family,
                                logical_key: replay_context.logical_key.clone(),
                                target: replay_context.target.clone(),
                                start_position: replay_context.start_position,
                                size: replay_context.size,
                                restrictive_payload_hex: replay_context
                                    .restrictive_payload_hex
                                    .clone(),
                                started_at: replay_started_at,
                                completed_at: replay_completed_at,
                                result_count: outcome.result_count as u32,
                                batch_count: outcome.batch_count as u32,
                                error: outcome.last_post_error.clone(),
                            })
                            .await
                        {
                            debug!("failed to post harvest replay summary: {error}");
                        }
                        info!(
                            "kad passive replay done results={} batches_posted={}",
                            outcome.result_count, outcome.batch_count
                        );
                        finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
                        if let Some(error) = outcome.last_post_error.clone() {
                            activity_snapshot.last_error = Some(error);
                            activity_snapshot.last_update_at = Utc::now();
                            record_agent_degraded_activity(&agent_activity, activity_snapshot).await;
                        } else {
                            clear_agent_degraded_activity(&agent_activity).await;
                        }
                    }
                    PassiveReplaySelection::Source(selected_request) => {
                        let request = selected_request.request;
                        let replay_started_at = Utc::now();
                        let replay_context = HarvestReplayContext {
                            replay_id: Uuid::new_v4(),
                            family: HarvestFamily::Source,
                            logical_key: selected_request.logical_key,
                            target: request.target.to_string(),
                            start_position: Some(request.start_position),
                            size: Some(request.size),
                            restrictive_payload_hex: None,
                        };
                        let activity_key = passive_replay_key(replay_context.replay_id);
                        let mut activity_snapshot = new_activity_snapshot(
                            AgentActivityState::PassiveHarvestReplay,
                            replay_started_at,
                        );
                        activity_snapshot.query_or_target = Some(
                            passive_replay_activity_context(
                                HarvestFamily::Source,
                                replay_context.target.as_str(),
                            ),
                        );
                        begin_agent_activity(
                            &agent_activity,
                            activity_key.clone(),
                            activity_snapshot.clone(),
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_start(
                                &mut observability,
                                HarvestFamily::Source,
                                request.target.to_string(),
                                Some(request.start_position),
                                None,
                                replay_started_at,
                            );
                        }
                        debug!(
                            "kad passive source replay start target={} start_position={} size={}",
                            request.target, request.start_position, request.size
                        );
                        let outcome = run_passive_source_replay(
                            PassiveReplayContext {
                                dht: &dht,
                                coordinator: &coordinator,
                                indexer_id,
                                replay_context: &replay_context,
                                max_phase2_fanout: passive_replay_phase2_fanout,
                                source_stop_after_results: passive_source_stop_after_results,
                                passive_result_count: &passive_result_count,
                                harvest_observability: &harvest_observability,
                            },
                            &request,
                        )
                        .await;
                        let replay_completed_at = Utc::now();
                        record_passive_replay_outcome(
                            &snoop_queue,
                            &replay_context.logical_key,
                            replay_completed_at,
                            outcome.result_count,
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_complete(
                                &mut observability,
                                HarvestFamily::Source,
                                replay_completed_at,
                                outcome.result_count,
                                outcome.batch_count,
                                outcome.tier_summaries.clone(),
                            );
                        }
                        if let Err(error) = coordinator
                            .post_harvest_replay(&HarvestReplayRecord {
                                replay_id: replay_context.replay_id,
                                indexer_id,
                                family: replay_context.family,
                                logical_key: replay_context.logical_key.clone(),
                                target: replay_context.target.clone(),
                                start_position: replay_context.start_position,
                                size: replay_context.size,
                                restrictive_payload_hex: replay_context
                                    .restrictive_payload_hex
                                    .clone(),
                                started_at: replay_started_at,
                                completed_at: replay_completed_at,
                                result_count: outcome.result_count as u32,
                                batch_count: outcome.batch_count as u32,
                                error: outcome.last_post_error.clone(),
                            })
                            .await
                        {
                            debug!("failed to post source harvest replay summary: {error}");
                        }
                        debug!(
                            "kad passive source replay done results={} batches_posted={}",
                            outcome.result_count, outcome.batch_count
                        );
                        finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
                        if let Some(error) = outcome.last_post_error.clone() {
                            activity_snapshot.last_error = Some(error);
                            activity_snapshot.last_update_at = Utc::now();
                            record_agent_degraded_activity(&agent_activity, activity_snapshot).await;
                        } else {
                            clear_agent_degraded_activity(&agent_activity).await;
                        }
                    }
                    PassiveReplaySelection::Notes(selected_request) => {
                        let request = selected_request.request;
                        let replay_started_at = Utc::now();
                        let replay_context = HarvestReplayContext {
                            replay_id: Uuid::new_v4(),
                            family: HarvestFamily::Notes,
                            logical_key: selected_request.logical_key,
                            target: request.target.to_string(),
                            start_position: None,
                            size: Some(request.size),
                            restrictive_payload_hex: None,
                        };
                        let activity_key = passive_replay_key(replay_context.replay_id);
                        let mut activity_snapshot = new_activity_snapshot(
                            AgentActivityState::PassiveHarvestReplay,
                            replay_started_at,
                        );
                        activity_snapshot.query_or_target = Some(
                            passive_replay_activity_context(
                                HarvestFamily::Notes,
                                replay_context.target.as_str(),
                            ),
                        );
                        begin_agent_activity(
                            &agent_activity,
                            activity_key.clone(),
                            activity_snapshot.clone(),
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_start(
                                &mut observability,
                                HarvestFamily::Notes,
                                request.target.to_string(),
                                None,
                                None,
                                replay_started_at,
                            );
                        }
                        info!(
                            "kad passive notes replay start target={} size={}",
                            request.target, request.size
                        );
                        let outcome = run_passive_notes_replay(
                            PassiveReplayContext {
                                dht: &dht,
                                coordinator: &coordinator,
                                indexer_id,
                                replay_context: &replay_context,
                                max_phase2_fanout: passive_replay_phase2_fanout,
                                source_stop_after_results: passive_source_stop_after_results,
                                passive_result_count: &passive_result_count,
                                harvest_observability: &harvest_observability,
                            },
                            &request,
                        )
                        .await;
                        let replay_completed_at = Utc::now();
                        record_passive_replay_outcome(
                            &snoop_queue,
                            &replay_context.logical_key,
                            replay_completed_at,
                            outcome.result_count,
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_complete(
                                &mut observability,
                                HarvestFamily::Notes,
                                replay_completed_at,
                                outcome.result_count,
                                outcome.batch_count,
                                outcome.tier_summaries.clone(),
                            );
                        }
                        if let Err(error) = coordinator
                            .post_harvest_replay(&HarvestReplayRecord {
                                replay_id: replay_context.replay_id,
                                indexer_id,
                                family: replay_context.family,
                                logical_key: replay_context.logical_key.clone(),
                                target: replay_context.target.clone(),
                                start_position: replay_context.start_position,
                                size: replay_context.size,
                                restrictive_payload_hex: replay_context
                                    .restrictive_payload_hex
                                    .clone(),
                                started_at: replay_started_at,
                                completed_at: replay_completed_at,
                                result_count: outcome.result_count as u32,
                                batch_count: outcome.batch_count as u32,
                                error: outcome.last_post_error.clone(),
                            })
                            .await
                        {
                            debug!("failed to post notes harvest replay summary: {error}");
                        }
                        info!(
                            "kad passive notes replay done results={} batches_posted={}",
                            outcome.result_count, outcome.batch_count
                        );
                        finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
                        if let Some(error) = outcome.last_post_error.clone() {
                            activity_snapshot.last_error = Some(error);
                            activity_snapshot.last_update_at = Utc::now();
                            record_agent_degraded_activity(&agent_activity, activity_snapshot).await;
                        } else {
                            clear_agent_degraded_activity(&agent_activity).await;
                        }
                    }
                }
            }
        }));

        let coordinator = self.coordinator.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let snoop_queue = Arc::clone(&self.snoop_queue);
        let observed_snoop_events = Arc::clone(&self.observed_snoop_events);
        let indexer_id = self.indexer_id;
        let agent_activity = Arc::clone(&self.agent_activity);
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(SNOOP_FLUSH_SECS)).await;
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                let flush_started_at = Utc::now();
                let mut flush_snapshot =
                    new_activity_snapshot(AgentActivityState::FlushingSnoops, flush_started_at);
                flush_snapshot.query_or_target = Some(format!("indexer={indexer_id}"));
                begin_agent_activity(
                    &agent_activity,
                    ACTIVITY_KEY_FLUSHING_SNOOPS.to_string(),
                    flush_snapshot,
                )
                .await;
                if let Err(error) = flush_snoop_queue(
                    &coordinator,
                    indexer_id,
                    &snoop_queue,
                    &observed_snoop_events,
                )
                .await
                {
                    let error_message = error.to_string();
                    debug!("snoop flush failed: {error_message}");
                    update_agent_activity_error(
                        &agent_activity,
                        ACTIVITY_KEY_FLUSHING_SNOOPS,
                        error_message.clone(),
                        Utc::now(),
                    )
                    .await;
                    let mut degraded_snapshot =
                        new_activity_snapshot(AgentActivityState::Degraded, Utc::now());
                    degraded_snapshot.query_or_target = Some("snoop flush".to_string());
                    degraded_snapshot.last_error = Some(error_message);
                    record_agent_degraded_activity(&agent_activity, degraded_snapshot).await;
                } else {
                    clear_agent_degraded_activity(&agent_activity).await;
                }
                finish_agent_activity(&agent_activity, ACTIVITY_KEY_FLUSHING_SNOOPS, Utc::now())
                    .await;
            }
        }));

        let coordinator = self.coordinator.clone();
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let local_store = Arc::clone(&self.local_store);
        let publish_batch_gate = Arc::clone(&self.publish_batch_gate);
        let publish_observability = Arc::clone(&self.publish_observability);
        let agent_activity = Arc::clone(&self.agent_activity);
        let ed2k_shared_catalog = Arc::clone(&runtime.ed2k_shared_catalog);
        let active_ed2k_downloads = Arc::clone(&self.active_ed2k_downloads);
        let source_publish_identity = source_publish_client_hash(self.ed2k_user_hash);
        let source_publish_settings = SourcePublishSettings {
            tcp_port: config.p2p.ed2k.listen_port,
            obfuscation_enabled: config.p2p.ed2k.obfuscation_enabled,
        };
        let notes_publish_enabled = config.p2p.kad.seed_notes_publish_enabled;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let mut synthetic_cursor = 0usize;
            let mut deferred_active_download_ticks = 0u8;
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(synthetic_publish_interval_secs.max(1)))
                    .await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }
                if !active_ed2k_downloads.lock().await.is_empty() {
                    deferred_active_download_ticks =
                        deferred_active_download_ticks.saturating_add(1);
                    if deferred_active_download_ticks < 8 {
                        debug!("deferring synthetic publish drip while ED2K downloads are active");
                        continue;
                    }
                } else {
                    deferred_active_download_ticks = 0;
                }

                match fetch_coordinator_popular_hashes(&coordinator).await {
                    Ok(Some(_)) => {
                        set_synthetic_publish_queue_depth(
                            &publish_observability,
                            SYNTHETIC_POPULAR_SEEDS.len(),
                        )
                        .await;
                        continue;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        debug!("synthetic publish drip coordinator fetch failed: {error}");
                    }
                }

                let batch = next_synthetic_publish_batch(
                    &mut synthetic_cursor,
                    synthetic_publish_batch_items,
                );
                let remaining_items = synthetic_publish_queue_depth(synthetic_cursor);
                set_synthetic_publish_queue_depth(&publish_observability, remaining_items).await;
                if batch.is_empty() {
                    continue;
                }
                if let Err(error) = seed_popular_with_activity(
                    &dht,
                    source_publish_identity,
                    source_publish_settings,
                    PublishSeedSource::SyntheticFallback,
                    batch,
                    &ed2k_shared_catalog,
                    PublishExecutionContext {
                        local_store: &local_store,
                        publish_batch_gate: &publish_batch_gate,
                        publish_observability: &publish_observability,
                        agent_activity: &agent_activity,
                        activity_key: None,
                        notes_publish_enabled,
                        work_class: RpcWorkClass::Publish,
                        publish_contact_fanout: synthetic_publish_contact_fanout,
                    },
                )
                .await
                {
                    debug!("synthetic publish drip failed: {error}");
                }
            }
        }));

        let coordinator = self.coordinator.clone();
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let republish_secs = config.p2p.kad.republish_interval_secs;
        let local_store = Arc::clone(&self.local_store);
        let publish_batch_gate = Arc::clone(&self.publish_batch_gate);
        let publish_observability = Arc::clone(&self.publish_observability);
        let agent_activity = Arc::clone(&self.agent_activity);
        let ed2k_shared_catalog = Arc::clone(&runtime.ed2k_shared_catalog);
        let source_publish_identity = source_publish_client_hash(self.ed2k_user_hash);
        let source_publish_settings = SourcePublishSettings {
            tcp_port: config.p2p.ed2k.listen_port,
            obfuscation_enabled: config.p2p.ed2k.obfuscation_enabled,
        };
        let notes_publish_enabled = config.p2p.kad.seed_notes_publish_enabled;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(republish_secs)).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }
                if let Err(error) = seed_coordinator_popular_if_available(
                    &dht,
                    source_publish_identity,
                    source_publish_settings,
                    &coordinator,
                    &ed2k_shared_catalog,
                    PublishExecutionContext {
                        local_store: &local_store,
                        publish_batch_gate: &publish_batch_gate,
                        publish_observability: &publish_observability,
                        agent_activity: &agent_activity,
                        activity_key: None,
                        notes_publish_enabled,
                        work_class: RpcWorkClass::Publish,
                        publish_contact_fanout,
                    },
                )
                .await
                {
                    debug!("coordinator republish cycle failed: {error}");
                }
            }
        }));
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
