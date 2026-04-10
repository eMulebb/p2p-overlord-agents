use std::{
    collections::{HashMap, HashSet},
    fs,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
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
    NatCapableAgent, NatManager, NatManagerBuilder, NatStatus, NatStatusSnapshot,
    ResolvedInterfaceBindingReport, TransportProtocol, build_interface_binding_report,
    built_in_upnp_port_mapping_providers, default_upnp_backend_order, detect_interfaces,
    recommend_interface, resolve_bind_ip,
};
use rand::{RngCore, seq::SliceRandom};
use serde::Deserialize;
use serde_json::Value;
use sha1::Sha1;
use tokio::{
    net::TcpListener,
    sync::{Mutex, Notify, OwnedSemaphorePermit, RwLock, Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use uuid::Uuid;

use overlord_agent_common::{
    AgentActivitySnapshot, AgentActivityState, AgentInterfacesView, ConfigUpdate, ContentType,
    CoordinatorClient, FileRecord, HarvestFamily, HarvestReplayContext, HarvestReplayRecord,
    HashType, IndexerServer, IndexerService, IndexerStats, KadHarvestFamilyObservability,
    KadHarvestObservability, KadPassiveReplayObservability, KadPassiveReplayTierSummary,
    KadPublishObservability, KadRpcObservability, KadRpcResponseOpcodeObservability,
    KadRpcTrackerBucketObservability, PopularHash, Protocol, PublishBatchSummary, PublishCounters,
    PublishSeedSource, RegisterRequest, ResultBatch, RunningIndexerServer, SearchEvent,
    SearchEventStatus, SearchJob, SearchKind, SnoopEntry, SnoopObservation, Source, TagEntry,
};
use overlord_kad_dht::{
    DhtConfig, DhtNode, NoteResult, PublishAttemptStats, ReceivedKadPacket,
    RpcObservabilitySnapshot, SearchResult, SourceResult,
    bootstrap::{BootstrapContact, encode_nodes_dat},
};
use overlord_kad_proto::{
    Ed2kHash, KadPacket, KadUdpKey, NodeId, SearchKeyReq, SearchNotesReq, SearchSourceReq, Tag,
    TagName, TagValue,
    constants::{K, opcode},
    packet::ContactEntry,
    tag_name,
};
use overlord_kad_routing::{Contact, ContactType};

use crate::config::{Ed2kConfig, Ed2kUploadQueuePolicyConfig, EmuleAgentConfig};
use crate::ed2k_server::{
    Ed2kFoundSource, Ed2kSearchFile, Ed2kServerSearchHandle, Ed2kServerState,
    new_ed2k_server_search_channel, request_callback_on_server,
    request_callback_via_background_session, run_ed2k_server_loop, search_keyword_servers,
    search_keyword_via_background_session, search_source_servers,
    search_source_via_background_session,
};
use crate::ed2k_tcp::{
    Ed2kHelloIdentity, Ed2kPeerDownloadOutcome, Ed2kSecureIdent, FirewallCheckUdpRequest,
    download_file_from_peer, dump_ed2k_tcp_download_meta, emule_connect_options,
    enrich_hello_identity, request_udp_firewall_check, run_ed2k_listener,
};
use crate::ed2k_transfer::{
    Ed2kCallbackIntent, Ed2kResumeManifest, Ed2kSharedCatalog, Ed2kSharedEntry, Ed2kSourceHint,
    Ed2kTransferRuntime, Ed2kUploadQueueConfig, new_transfer_job,
};
use crate::kad_firewall::{
    ExternalPortDiscoveryOutcome, FirewallUdpPacketOutcome, FirewalledResponseOutcome,
    KadFirewallState,
};
use crate::kad_store::{KadLocalStore, KadLocalStoreConfig};
use crate::logging::current_log_file_status;
use crate::snoop_queue::{ScheduledSnoopRequest, SnoopQueue, SnoopQueueFamilyCounts};

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
const KAD_HELLO_INTRO_SECS: u64 = 30;
const KAD_HELLO_INTRO_FANOUT: usize = 24;
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
const ACTIVITY_KEY_STARTING: &str = "starting";
const ACTIVITY_KEY_BOOTSTRAPPING: &str = "bootstrapping";
const ACTIVITY_KEY_FLUSHING_SNOOPS: &str = "flushing_snoops";
const ACTIVITY_KEY_RECONFIGURING: &str = "reconfiguring";

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

/// Returns whether the current batch snapshot reflects any observable seeding progress yet.
fn publish_summary_has_progress(summary: &PublishBatchSummary) -> bool {
    summary.published_items > 0
        || summary.closest_contacts_considered > 0
        || summary.attempted_contacts > 0
        || summary.acked_contacts > 0
        || summary.failed_contacts > 0
        || summary.timed_out_contacts > 0
}

/// Projects the counters that operators should see right now.
///
/// The stored counters only advance once a batch has fully finished. During long live
/// runs, however, `/api/internal/stats` should still reflect the current in-flight batch
/// so the roll-up totals stay aligned with the latest per-batch snapshot.
fn effective_publish_counters(
    counters: &PublishCounters,
    latest_batch: Option<&PublishBatchSummary>,
    last_seed_at: Option<DateTime<Utc>>,
) -> PublishCounters {
    let mut effective = counters.clone();
    let Some(summary) = latest_batch else {
        return effective;
    };

    let batch_committed = counters.last_batch_at == Some(summary.completed_at);
    let batch_in_flight = match (last_seed_at, counters.last_batch_at) {
        (Some(observed_at), Some(committed_at)) => observed_at > committed_at,
        (Some(_), None) => true,
        (None, _) => false,
    };

    if batch_in_flight && !batch_committed && publish_summary_has_progress(summary) {
        apply_publish_summary(&mut effective, summary);
    }

    effective
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

fn map_rpc_observability(snapshot: RpcObservabilitySnapshot) -> KadRpcObservability {
    KadRpcObservability {
        decode_failures: snapshot.decode_failures,
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
    }
}

fn passive_replay_observability_mut(
    observability: &mut KadHarvestObservability,
    family: HarvestFamily,
) -> &mut KadPassiveReplayObservability {
    match family {
        HarvestFamily::Keyword => &mut observability.passive_keyword_replay,
        HarvestFamily::Source => &mut observability.passive_source_replay,
        HarvestFamily::Notes => &mut observability.passive_notes_replay,
    }
}

fn passive_replay_tier_contact_limits(max_phase2_fanout: usize) -> Vec<usize> {
    let mut tiers = vec![K, K.saturating_mul(2), max_phase2_fanout];
    tiers.retain(|limit| *limit > 0);
    tiers.sort_unstable();
    tiers.dedup();
    tiers
}

fn passive_replay_thin_result_threshold(family: HarvestFamily) -> usize {
    match family {
        HarvestFamily::Keyword => PASSIVE_KEYWORD_THIN_RESULT_THRESHOLD,
        HarvestFamily::Source => PASSIVE_SOURCE_THIN_RESULT_THRESHOLD,
        HarvestFamily::Notes => PASSIVE_NOTES_THIN_RESULT_THRESHOLD,
    }
}

fn record_passive_replay_idle(
    observability: &mut KadHarvestObservability,
    family: HarvestFamily,
    observed_at: DateTime<Utc>,
) {
    let replay = passive_replay_observability_mut(observability, family);
    replay.idle_cycles += 1;
    replay.last_idle_at = Some(observed_at);
}

fn record_passive_replay_start(
    observability: &mut KadHarvestObservability,
    family: HarvestFamily,
    target: String,
    start_position: Option<u16>,
    restrictive_bytes: Option<u32>,
    started_at: DateTime<Utc>,
) {
    let replay = passive_replay_observability_mut(observability, family);
    replay.started_cycles += 1;
    replay.last_started_at = Some(started_at);
    replay.last_target = Some(target);
    replay.last_start_position = start_position;
    replay.last_restrictive_bytes = restrictive_bytes;
    replay.last_tiers.clear();
    replay.last_tiers_attempted = 0;
    replay.last_widest_responder_ceiling = None;
    replay.last_widened = false;
    replay.last_error = None;
    replay.last_error_at = None;
}

fn record_passive_replay_complete(
    observability: &mut KadHarvestObservability,
    family: HarvestFamily,
    completed_at: DateTime<Utc>,
    replayed_results: usize,
    batches_posted: usize,
    tier_summaries: Vec<KadPassiveReplayTierSummary>,
) {
    let replay = passive_replay_observability_mut(observability, family);
    replay.completed_cycles += 1;
    replay.emitted_results += replayed_results as u64;
    replay.posted_batches += batches_posted as u64;
    replay.last_completed_at = Some(completed_at);
    replay.last_result_count = replayed_results as u32;
    replay.last_batches_posted = batches_posted as u32;
    replay.last_tiers_attempted = tier_summaries.len() as u32;
    replay.last_widest_responder_ceiling = tier_summaries.last().map(|tier| tier.responder_ceiling);
    replay.last_widened = tier_summaries.len() > 1;
    if replay.last_widened {
        replay.widened_cycles += 1;
    }
    replay.last_tiers = tier_summaries;
}

fn record_passive_replay_enqueue_wait(
    observability: &mut KadHarvestObservability,
    family: HarvestFamily,
    wait: Duration,
    backpressured: bool,
) {
    let replay = passive_replay_observability_mut(observability, family);
    if backpressured {
        replay.enqueue_backpressure_events += 1;
    }
    let waited_millis = wait.as_millis().min(u32::MAX as u128) as u32;
    replay.enqueue_wait_millis += waited_millis as u64;
    replay.last_enqueue_wait_millis = waited_millis;
}

fn record_passive_replay_post_latency(
    observability: &mut KadHarvestObservability,
    family: HarvestFamily,
    latency: Duration,
) {
    let replay = passive_replay_observability_mut(observability, family);
    let latency_millis = latency.as_millis().min(u32::MAX as u128) as u32;
    replay.post_callbacks += 1;
    replay.post_latency_millis += latency_millis as u64;
    replay.last_post_latency_millis = latency_millis;
}

fn record_passive_replay_post_failure(
    observability: &mut KadHarvestObservability,
    family: HarvestFamily,
    observed_at: DateTime<Utc>,
    error: &str,
) {
    let replay = passive_replay_observability_mut(observability, family);
    replay.post_failures += 1;
    replay.last_error_at = Some(observed_at);
    replay.last_error = Some(error.to_string());
}

#[derive(Clone)]
struct AgentStatePaths {
    node_id_path: PathBuf,
    udp_key_path: PathBuf,
    ed2k_user_hash_path: PathBuf,
    ed2k_secure_ident_path: PathBuf,
    ed2k_transfer_root: PathBuf,
    nodes_dat_path: PathBuf,
    networking_config_path: PathBuf,
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
    #[serde(alias = "file_name", alias = "canonical_name")]
    file_name: String,
    #[serde(alias = "file_size")]
    file_size: u64,
    #[serde(default)]
    sources: Vec<EnrichEd2kDownloadSource>,
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
    publish_observability: Arc<Mutex<KadPublishObservability>>,
    harvest_observability: Arc<Mutex<KadHarvestObservability>>,
    agent_activity: Arc<Mutex<AgentActivityTracker>>,
    runtime: Arc<Mutex<Option<AgentNetworkRuntime>>>,
    control_server: Arc<Mutex<Option<ControlServerRuntime>>>,
    control_selection_state: Arc<RwLock<ResolvedInterfaceBindingReport>>,
    p2p_selection_state: Arc<RwLock<ResolvedInterfaceBindingReport>>,
    active_searches: Arc<Mutex<HashMap<Uuid, ActiveSearchHandle>>>,
    active_ed2k_downloads: Arc<Mutex<HashSet<String>>>,
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

/// Small in-memory tracker that resolves overlapping runtime work into one operator-facing
/// activity snapshot using a fixed precedence order.
#[derive(Debug, Clone)]
struct AgentActivityTracker {
    active: HashMap<String, AgentActivitySnapshot>,
    degraded: Option<AgentActivitySnapshot>,
    idle_since: DateTime<Utc>,
}

impl AgentActivityTracker {
    fn new(now: DateTime<Utc>) -> Self {
        let mut active = HashMap::new();
        active.insert(
            ACTIVITY_KEY_STARTING.to_string(),
            new_activity_snapshot(AgentActivityState::Starting, now),
        );
        Self {
            active,
            degraded: None,
            idle_since: now,
        }
    }

    fn enter(&mut self, key: String, snapshot: AgentActivitySnapshot) {
        self.active.insert(key, snapshot);
    }

    fn leave(&mut self, key: &str, observed_at: DateTime<Utc>) {
        if self.active.remove(key).is_some() && self.active.is_empty() {
            self.idle_since = observed_at;
        }
    }

    fn update_progress(
        &mut self,
        key: &str,
        progress_current: Option<u32>,
        progress_total: Option<u32>,
        observed_at: DateTime<Utc>,
    ) {
        if let Some(snapshot) = self.active.get_mut(key) {
            snapshot.progress_current = progress_current;
            snapshot.progress_total = progress_total;
            snapshot.last_update_at = observed_at;
        }
    }

    fn update_error(&mut self, key: &str, error: String, observed_at: DateTime<Utc>) {
        if let Some(snapshot) = self.active.get_mut(key) {
            snapshot.last_error = Some(error);
            snapshot.last_update_at = observed_at;
        }
    }

    fn clear_degraded(&mut self) {
        self.degraded = None;
    }

    fn record_degraded(&mut self, mut snapshot: AgentActivitySnapshot) {
        snapshot.state = AgentActivityState::Degraded;
        self.degraded = Some(snapshot);
    }

    fn current_snapshot(
        &self,
        external_error: Option<String>,
        observed_at: DateTime<Utc>,
    ) -> AgentActivitySnapshot {
        if let Some(snapshot) = self
            .active
            .values()
            .max_by_key(|snapshot| (activity_precedence(snapshot.state), snapshot.last_update_at))
        {
            return snapshot.clone();
        }

        if let Some(snapshot) = &self.degraded {
            return snapshot.clone();
        }

        if let Some(error) = external_error {
            let mut snapshot = new_activity_snapshot(AgentActivityState::Degraded, self.idle_since);
            snapshot.last_update_at = observed_at;
            snapshot.last_error = Some(error);
            return snapshot;
        }

        let mut snapshot = new_activity_snapshot(AgentActivityState::Idle, self.idle_since);
        snapshot.last_update_at = observed_at;
        snapshot
    }
}

fn activity_precedence(state: AgentActivityState) -> u8 {
    match state {
        AgentActivityState::Degraded => 9,
        AgentActivityState::Reconfiguring => 8,
        AgentActivityState::Downloading => 7,
        AgentActivityState::ActiveSearch => 6,
        AgentActivityState::PassiveHarvestReplay => 5,
        AgentActivityState::Publishing => 4,
        AgentActivityState::FlushingSnoops => 3,
        AgentActivityState::Bootstrapping => 2,
        AgentActivityState::Starting => 1,
        AgentActivityState::Idle => 0,
    }
}

fn new_activity_snapshot(
    state: AgentActivityState,
    observed_at: DateTime<Utc>,
) -> AgentActivitySnapshot {
    AgentActivitySnapshot {
        state,
        since: observed_at,
        job_id: None,
        protocol: None,
        kind: None,
        query_or_target: None,
        progress_current: None,
        progress_total: None,
        last_update_at: observed_at,
        last_error: None,
    }
}

fn active_search_key(job_id: Uuid) -> String {
    format!("active_search:{job_id}")
}

fn active_ed2k_download_key(file_hash: &str) -> String {
    format!("ed2k_download:{file_hash}")
}

fn passive_replay_key(replay_id: Uuid) -> String {
    format!("passive_replay:{replay_id}")
}

fn publish_activity_key(seed_source: PublishSeedSource, observed_at: DateTime<Utc>) -> String {
    format!(
        "publishing:{}:{}",
        seed_source.label(),
        observed_at.timestamp_millis()
    )
}

fn search_activity_context(job: &SearchJob) -> Option<String> {
    match job.kind {
        SearchKind::Keyword => job.query.clone(),
        SearchKind::Source | SearchKind::Notes => job
            .file_hash
            .as_ref()
            .map(|hash| format!("{:?}", hash))
            .or_else(|| job.file_size.map(|size| format!("size={size}"))),
    }
}

fn passive_replay_activity_context(family: HarvestFamily, target: &str) -> String {
    format!("{family:?} {target}")
}

fn runtime_activity_error(
    interface_report: &AgentNetworkReport,
    nat_status: Option<&NatStatusSnapshot>,
) -> Option<String> {
    interface_report
        .control
        .last_error
        .clone()
        .or_else(|| interface_report.p2p.last_error.clone())
        .or_else(|| nat_status.and_then(|status| status.last_error.clone()))
}

async fn begin_agent_activity(
    tracker: &Arc<Mutex<AgentActivityTracker>>,
    key: String,
    snapshot: AgentActivitySnapshot,
) {
    tracker.lock().await.enter(key, snapshot);
}

async fn finish_agent_activity(
    tracker: &Arc<Mutex<AgentActivityTracker>>,
    key: &str,
    observed_at: DateTime<Utc>,
) {
    tracker.lock().await.leave(key, observed_at);
}

async fn update_agent_activity_progress(
    tracker: &Arc<Mutex<AgentActivityTracker>>,
    key: &str,
    progress_current: Option<u32>,
    progress_total: Option<u32>,
    observed_at: DateTime<Utc>,
) {
    tracker
        .lock()
        .await
        .update_progress(key, progress_current, progress_total, observed_at);
}

async fn update_agent_activity_error(
    tracker: &Arc<Mutex<AgentActivityTracker>>,
    key: &str,
    error: String,
    observed_at: DateTime<Utc>,
) {
    tracker.lock().await.update_error(key, error, observed_at);
}

async fn record_agent_degraded_activity(
    tracker: &Arc<Mutex<AgentActivityTracker>>,
    snapshot: AgentActivitySnapshot,
) {
    tracker.lock().await.record_degraded(snapshot);
}

async fn clear_agent_degraded_activity(tracker: &Arc<Mutex<AgentActivityTracker>>) {
    tracker.lock().await.clear_degraded();
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
            publish_observability: Arc::new(Mutex::new(KadPublishObservability::default())),
            harvest_observability: Arc::new(Mutex::new(KadHarvestObservability::default())),
            agent_activity: Arc::new(Mutex::new(AgentActivityTracker::new(activity_started_at))),
            runtime: Arc::new(Mutex::new(None)),
            control_server: Arc::new(Mutex::new(None)),
            control_selection_state: Arc::new(RwLock::new(control_selection_state)),
            p2p_selection_state: Arc::new(RwLock::new(p2p_selection_state)),
            active_searches: Arc::new(Mutex::new(HashMap::new())),
            active_ed2k_downloads: Arc::new(Mutex::new(HashSet::new())),
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
    protocol: Protocol,
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
            protocol,
            harvest_context: None,
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

fn map_note_result(result: &NoteResult, file_size: u64) -> FileRecord {
    FileRecord {
        hashes: vec![HashType::Ed2k(result.file_hash.to_string())],
        names: Vec::new(),
        size: Some(file_size),
        content_type: None,
        tags: vec![TagEntry {
            key: "kad_note".to_string(),
            value: serde_json::json!({
                "source_id": result.source_id.to_string(),
                "rating": result.rating,
                "comment": result.comment,
            }),
        }],
        sources: Vec::new(),
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
        info!(
            "kad passive replay tier start family=keyword target={} responder_ceiling={} restrictive_bytes={}",
            request.target,
            responder_ceiling,
            request.restrictive_payload.len()
        );
        let mut stream = context
            .dht
            .search_keyword_request_with_phase2_fanout_and_cancel(
                request.clone(),
                responder_ceiling,
                CancellationToken::new(),
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
        info!(
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
        info!(
            "kad passive replay tier start family=source target={} responder_ceiling={} size={}",
            request.target, responder_ceiling, request.size
        );
        let cancel = CancellationToken::new();
        let mut stream = context
            .dht
            .search_source_request_with_phase2_fanout_and_cancel(
                request.clone(),
                responder_ceiling,
                cancel.clone(),
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
        info!(
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
    let file_hash = Ed2kHash::from_bytes(request.target.0);
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
        let mut stream = context.dht.search_notes_with_phase2_fanout_and_cancel(
            file_hash,
            request.size,
            responder_ceiling,
            CancellationToken::new(),
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

async fn do_active_keyword_search(
    dht: &DhtNode,
    indexer_id: Uuid,
    job: &SearchJob,
    enable_mock_results: bool,
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
                Protocol::Kad2,
                std::mem::take(&mut files),
                &mut stats,
            )
            .await?;
        }
    }

    post_search_batch(
        &callback_client,
        job.job_id,
        indexer_id,
        Protocol::Kad2,
        files,
        &mut stats,
    )
    .await?;

    if seen == 0 && !cancel.is_cancelled() && enable_mock_results {
        post_search_batch(
            &callback_client,
            job.job_id,
            indexer_id,
            Protocol::Kad2,
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
                Protocol::Kad2,
                std::mem::take(&mut files),
                &mut stats,
            )
            .await?;
        }
    }

    post_search_batch(
        &callback_client,
        job.job_id,
        indexer_id,
        Protocol::Kad2,
        files,
        &mut stats,
    )
    .await?;
    Ok(stats)
}

async fn do_active_notes_search(
    dht: &DhtNode,
    indexer_id: Uuid,
    job: &SearchJob,
    cancel: CancellationToken,
) -> Result<SearchRunStats> {
    let file_hash = search_file_hash(job)?;
    let file_size = search_file_size(job)?;
    let callback_client = CoordinatorClient::new(&job.callback_url)?;
    let mut stream = dht.search_notes_with_cancel(file_hash, file_size, cancel);
    let mut files = Vec::new();
    let mut stats = SearchRunStats::default();

    while let Some(result) = stream.next().await {
        files.push(map_note_result(&result, file_size));
        if files.len() >= ACTIVE_BATCH_SIZE {
            post_search_batch(
                &callback_client,
                job.job_id,
                indexer_id,
                Protocol::Kad2,
                std::mem::take(&mut files),
                &mut stats,
            )
            .await?;
        }
    }

    post_search_batch(
        &callback_client,
        job.job_id,
        indexer_id,
        Protocol::Kad2,
        files,
        &mut stats,
    )
    .await?;
    Ok(stats)
}

fn ed2k_content_type(file_type: Option<&str>) -> Option<ContentType> {
    match file_type {
        Some("Video") => Some(ContentType::Video),
        Some("Audio") => Some(ContentType::Audio),
        Some("Doc") => Some(ContentType::Document),
        Some("Pro") | Some("EmuleCollection") => Some(ContentType::Software),
        Some(_) => Some(ContentType::Unknown),
        None => None,
    }
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

fn map_ed2k_keyword_result(result: &Ed2kSearchFile) -> FileRecord {
    let mut tags = Vec::new();
    if let Some(file_type) = result.file_type.as_deref() {
        tags.push(TagEntry {
            key: "ed2k_file_type".to_string(),
            value: serde_json::json!(file_type),
        });
    }
    if let Some(source_count) = result.source_count {
        tags.push(TagEntry {
            key: "ed2k_source_count".to_string(),
            value: serde_json::json!(source_count),
        });
    }

    FileRecord {
        hashes: vec![HashType::Ed2k(result.file_hash.to_string())],
        names: result.file_name.iter().cloned().collect(),
        size: result.file_size,
        content_type: ed2k_content_type(result.file_type.as_deref()),
        tags,
        sources: Vec::new(),
    }
}

fn map_ed2k_source_result(result: &Ed2kFoundSource, file_size: u64) -> FileRecord {
    FileRecord {
        hashes: vec![HashType::Ed2k(result.file_hash.to_string())],
        names: Vec::new(),
        size: Some(file_size),
        content_type: None,
        tags: Vec::new(),
        sources: vec![Source {
            protocol: Protocol::Ed2k,
            address: format!("{}:{}", result.ip, result.tcp_port),
            extra: serde_json::json!({
                "search_mode": "server_source",
                "client_id": result.client_id,
                "direct_dialable": result.is_direct_dialable(),
                "low_id": result.low_id,
                "obfuscated": result.obfuscated,
                "obfuscation_options": result.obfuscation_options,
                "user_hash": result.user_hash.map(hex::encode),
            }),
        }],
    }
}

/// Live `OP_GETSOURCES` replies often arrive later than the initial ED2K
/// login/status handshake, so source discovery needs a wider timeout budget
/// than the generic connect timeout.
fn ed2k_source_search_timeout(config: &Ed2kConfig) -> Duration {
    Duration::from_secs(config.connect_timeout_secs.max(15))
}

/// Kad source search remains a viable fallback when ED2K servers accept login
/// traffic but never answer `OP_GETSOURCES` for a concrete file.
fn kad_source_result_to_ed2k_found_source(result: SourceResult) -> Ed2kFoundSource {
    Ed2kFoundSource {
        file_hash: result.file_hash,
        ip: result.ip,
        tcp_port: result.tcp_port,
        client_id: u32::from(result.ip),
        low_id: false,
        obfuscated: false,
        obfuscation_options: None,
        user_hash: None,
        source_server: None,
    }
}

/// Callback-driven ED2K downloads can continue after the initial server-side
/// callback request completes. Treat persisted piece/hashset progress as proof
/// that a real transfer is in flight instead of reporting a terminal failure
/// immediately after the first callback grace window.
fn manifest_has_ed2k_transfer_progress(manifest: &Ed2kResumeManifest) -> bool {
    manifest.completed
        || manifest.md4_hashset_acquired
        || !manifest.verified_ranges.is_empty()
        || manifest.pieces.iter().any(|piece| piece.bytes_written != 0)
}

/// Collects Kad-advertised ED2K sources for a bounded window so downloads can
/// proceed even when server-assisted source discovery is flaky.
async fn collect_kad_ed2k_sources(
    dht: &DhtNode,
    file_hash: Ed2kHash,
    file_size: u64,
    timeout: Duration,
) -> Vec<Ed2kFoundSource> {
    let cancel = CancellationToken::new();
    let mut stream = dht.search_sources_with_cancel(file_hash, file_size, cancel.clone());
    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);
    let mut sources = Vec::new();

    loop {
        tokio::select! {
            _ = &mut sleep => break,
            result = stream.next() => {
                let Some(result) = result else {
                    break;
                };
                merge_download_sources(
                    &mut sources,
                    vec![kad_source_result_to_ed2k_found_source(result)],
                );
                if sources.len() >= ED2K_DOWNLOAD_KAD_SOURCE_CAP {
                    break;
                }
            }
        }
    }

    cancel.cancel();
    sources
}

#[allow(clippy::too_many_arguments)]
async fn do_active_ed2k_keyword_search(
    bind_ip: Ipv4Addr,
    indexer_id: Uuid,
    ed2k_user_hash: [u8; 16],
    shared_catalog: &[Ed2kSharedEntry],
    job: &SearchJob,
    config: &EmuleAgentConfig,
    background_search: Option<Ed2kServerSearchHandle>,
    preferred_endpoint: Option<SocketAddr>,
    cancel: CancellationToken,
) -> Result<SearchRunStats> {
    let callback_client = CoordinatorClient::new(&job.callback_url)?;
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
    let query = search_query(job)?;
    let search_timeout = Duration::from_secs(config.p2p.ed2k.connect_timeout_secs.max(5));
    let files = if let Some(background_search) = background_search {
        match search_keyword_via_background_session(
            &background_search,
            query,
            search_timeout,
            &cancel,
        )
        .await
        {
            Ok(results) if !results.is_empty() => {
                info!(
                    "ED2K active keyword search used background session endpoint={} query_len={} result_count={}",
                    preferred_endpoint
                        .map(|endpoint| endpoint.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    query.len(),
                    results.len()
                );
                results
                    .into_iter()
                    .map(|result| map_ed2k_keyword_result(&result))
                    .collect()
            }
            Ok(_) => {
                warn!(
                    "ED2K background session search returned no results for query={query:?}; falling back to one-shot search"
                );
                search_keyword_servers(
                    bind_ip,
                    &config.p2p.ed2k,
                    hello_identity,
                    shared_catalog,
                    preferred_endpoint,
                    ED2K_ACTIVE_SEARCH_MAX_SERVER_ATTEMPTS,
                    query,
                    &cancel,
                )
                .await?
                .into_iter()
                .map(|result| map_ed2k_keyword_result(&result))
                .collect()
            }
            Err(error) => {
                warn!(
                    "ED2K background session search failed for query={query:?}; falling back to one-shot search: {error}"
                );
                search_keyword_servers(
                    bind_ip,
                    &config.p2p.ed2k,
                    hello_identity,
                    shared_catalog,
                    preferred_endpoint,
                    ED2K_ACTIVE_SEARCH_MAX_SERVER_ATTEMPTS,
                    query,
                    &cancel,
                )
                .await?
                .into_iter()
                .map(|result| map_ed2k_keyword_result(&result))
                .collect()
            }
        }
    } else {
        search_keyword_servers(
            bind_ip,
            &config.p2p.ed2k,
            hello_identity,
            shared_catalog,
            preferred_endpoint,
            ED2K_ACTIVE_SEARCH_MAX_SERVER_ATTEMPTS,
            query,
            &cancel,
        )
        .await?
        .into_iter()
        .map(|result| map_ed2k_keyword_result(&result))
        .collect()
    };
    let mut stats = SearchRunStats::default();
    post_search_batch(
        &callback_client,
        job.job_id,
        indexer_id,
        Protocol::Ed2k,
        files,
        &mut stats,
    )
    .await?;
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
async fn do_active_ed2k_source_search(
    bind_ip: Ipv4Addr,
    indexer_id: Uuid,
    ed2k_user_hash: [u8; 16],
    shared_catalog: &[Ed2kSharedEntry],
    job: &SearchJob,
    config: &EmuleAgentConfig,
    background_search: Option<Ed2kServerSearchHandle>,
    preferred_endpoint: Option<SocketAddr>,
    cancel: CancellationToken,
) -> Result<SearchRunStats> {
    let callback_client = CoordinatorClient::new(&job.callback_url)?;
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
    let file_hash = search_file_hash(job)?;
    let file_size = search_file_size(job)?;
    let source_search_timeout = ed2k_source_search_timeout(&config.p2p.ed2k);
    let files = if let Some(background_search) = background_search {
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
                info!(
                    "ED2K active source search used background session endpoint={} file_hash={} source_count={}",
                    preferred_endpoint
                        .map(|endpoint| endpoint.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    file_hash,
                    results.len()
                );
                results
                    .into_iter()
                    .map(|result| map_ed2k_source_result(&result, file_size))
                    .collect()
            }
            Ok(_) => {
                warn!(
                    "ED2K background session source search returned no sources for file_hash={file_hash}; falling back to one-shot search"
                );
                search_source_servers(
                    bind_ip,
                    &config.p2p.ed2k,
                    hello_identity,
                    shared_catalog,
                    preferred_endpoint,
                    ED2K_ACTIVE_SEARCH_MAX_SERVER_ATTEMPTS,
                    file_hash,
                    file_size,
                    &cancel,
                )
                .await?
                .into_iter()
                .map(|result| map_ed2k_source_result(&result, file_size))
                .collect()
            }
            Err(error) => {
                warn!(
                    "ED2K background session source search failed for file_hash={file_hash}; falling back to one-shot search: {error}"
                );
                search_source_servers(
                    bind_ip,
                    &config.p2p.ed2k,
                    hello_identity,
                    shared_catalog,
                    preferred_endpoint,
                    ED2K_ACTIVE_SEARCH_MAX_SERVER_ATTEMPTS,
                    file_hash,
                    file_size,
                    &cancel,
                )
                .await?
                .into_iter()
                .map(|result| map_ed2k_source_result(&result, file_size))
                .collect()
            }
        }
    } else {
        search_source_servers(
            bind_ip,
            &config.p2p.ed2k,
            hello_identity,
            shared_catalog,
            preferred_endpoint,
            ED2K_ACTIVE_SEARCH_MAX_SERVER_ATTEMPTS,
            file_hash,
            file_size,
            &cancel,
        )
        .await?
        .into_iter()
        .map(|result| map_ed2k_source_result(&result, file_size))
        .collect()
    };
    let mut stats = SearchRunStats::default();
    post_search_batch(
        &callback_client,
        job.job_id,
        indexer_id,
        Protocol::Ed2k,
        files,
        &mut stats,
    )
    .await?;
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
    publish_observability: &'a Arc<Mutex<KadPublishObservability>>,
    agent_activity: &'a Arc<Mutex<AgentActivityTracker>>,
    activity_key: Option<&'a str>,
    notes_publish_enabled: bool,
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

/// Applies the synthetic fallback whenever the coordinator cannot currently provide a seed set.
fn select_popular_hashes_from_fetch_result(
    fetch_result: Result<Vec<PopularHash>>,
) -> (PublishSeedSource, Vec<PopularHash>) {
    match fetch_result {
        Ok(hashes) => select_popular_hashes_for_seeding(hashes),
        Err(error) => {
            warn!("coordinator popular-hash fetch failed; using synthetic fallback: {error}");
            (
                PublishSeedSource::SyntheticFallback,
                synthetic_popular_hashes(),
            )
        }
    }
}

/// Fetches the current seed set from the coordinator and degrades to the synthetic fallback
/// whenever the coordinator is offline or returns no popular hashes.
async fn fetch_popular_hashes_for_seeding(
    coordinator: &CoordinatorClient,
) -> (PublishSeedSource, Vec<PopularHash>) {
    select_popular_hashes_from_fetch_result(coordinator.popular_hashes().await)
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
}

/// Fetches the current seed set and runs one publish batch against it.
///
/// This is the long-lived seeding state machine used after bootstrap and during
/// periodic republish cycles.
async fn seed_popular_from_coordinator_or_fallback(
    dht: &DhtNode,
    source_publish_identity: NodeId,
    source_publish_settings: SourcePublishSettings,
    coordinator: &CoordinatorClient,
    shared_catalog: &Ed2kSharedCatalog,
    context: PublishExecutionContext<'_>,
) -> Result<()> {
    let (source, hashes) = fetch_popular_hashes_for_seeding(coordinator).await;
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
            Ok(())
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

/// Applies the classic eMule client marker bytes to an ED2K user hash.
fn normalize_ed2k_user_hash_markers(mut user_hash: [u8; 16]) -> [u8; 16] {
    user_hash[5] = 0x0E;
    user_hash[14] = 0x6F;
    user_hash
}

/// Mirrors the oracle `isbadhash` check for persisted ED2K user hashes.
fn ed2k_user_hash_is_bad(user_hash: &[u8; 16]) -> bool {
    let lo = u64::from_le_bytes(user_hash[..8].try_into().expect("slice has 8 bytes"));
    let hi = u64::from_le_bytes(user_hash[8..].try_into().expect("slice has 8 bytes"));
    (lo & 0xffff_00ff_ffff_ffff) == 0 && (hi & 0xff00_ffff_ffff_ffff) == 0
}

/// Creates a fresh eMule-style ED2K user hash.
fn create_ed2k_user_hash() -> [u8; 16] {
    loop {
        let mut user_hash = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut user_hash);
        let user_hash = normalize_ed2k_user_hash_markers(user_hash);
        if !ed2k_user_hash_is_bad(&user_hash) {
            return user_hash;
        }
    }
}

/// Loads the persisted ED2K user hash, or creates one that mirrors eMule semantics.
fn load_or_create_ed2k_user_hash(path: &Path) -> Result<[u8; 16]> {
    if path.exists() {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read ED2K user hash from {}", path.display()))?;
        if bytes.len() == 16 {
            let mut user_hash = [0u8; 16];
            user_hash.copy_from_slice(&bytes);
            let normalized = normalize_ed2k_user_hash_markers(user_hash);
            if !ed2k_user_hash_is_bad(&normalized) {
                if normalized != user_hash {
                    fs::write(path, normalized).with_context(|| {
                        format!("failed to normalize ED2K user hash at {}", path.display())
                    })?;
                }
                return Ok(normalized);
            }
        }
    }

    let user_hash = create_ed2k_user_hash();
    fs::write(path, user_hash)
        .with_context(|| format!("failed to persist ED2K user hash to {}", path.display()))?;
    Ok(user_hash)
}

/// Return the eMule-style `TAG_ENCRYPTION` bits for the current non-firewalled agent.
///
/// This mirrors the oracle `GetMyConnectOptions(true, false)` shape we also expose over TCP hello.
fn emule_source_encryption_options(obfuscation_enabled: bool) -> u8 {
    emule_connect_options(obfuscation_enabled)
}

/// Builds the oracle-style source publish tag set for one file announcement.
fn build_source_publish_tags(
    bind_addr: SocketAddr,
    source_publish_settings: SourcePublishSettings,
    file_size: u64,
) -> Vec<Tag> {
    vec![
        Tag::new_short(
            tag_name::SOURCETYPE,
            TagValue::UInt(u64::from(emule_high_id_source_type(file_size))),
        ),
        // Mirror the oracle: SOURCEPORT carries the ED2K TCP listener while
        // SOURCEUPORT carries the Kad UDP listener.
        Tag::new_short(
            tag_name::SOURCEPORT,
            TagValue::UInt(u64::from(source_publish_settings.tcp_port)),
        ),
        Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(bind_addr.port())),
        Tag::filesize(file_size),
        Tag::new_short(
            tag_name::ENCRYPTION,
            TagValue::U8(emule_source_encryption_options(
                source_publish_settings.obfuscation_enabled,
            )),
        ),
    ]
}

/// Builds a deterministic notes-publish payload for controlled live validation.
///
/// The notes-seeding path remains opt-in so the runtime can exercise notes
/// publish parity without making synthetic notes part of the default behavior.
fn build_notes_publish_tags(canonical_name: &str, file_size: u64) -> Vec<Tag> {
    vec![
        Tag::filename(canonical_name.to_string()),
        Tag::filesize(file_size),
        Tag::new_short(tag_name::FILERATING, TagValue::U8(4)),
        Tag::new_short(
            tag_name::DESCRIPTION,
            TagValue::String(format!("overlord validation note for {canonical_name}")),
        ),
    ]
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
            .publish_keyword(
                keyword_hash,
                file_hash,
                keyword_tags,
                Some(keyword_aich_hash),
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
                NodeId::from_bytes(file_hash.0),
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
        if context.notes_publish_enabled {
            let notes_tags = build_notes_publish_tags(&hash.canonical_name, hash.size);
            {
                let mut store = context.local_store.lock().await;
                store.record_notes_publish(
                    NodeId::from_bytes(file_hash.0),
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
                .publish_notes(file_hash, notes_publish_identity, notes_tags)
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
    observed_snoop_events: &Arc<Mutex<Vec<SnoopObservation>>>,
) -> Result<()> {
    let (entries, counts) = {
        let queue = snoop_queue.lock().await;
        (queue.snapshot(), queue.family_counts())
    };
    let observations = {
        let mut observed = observed_snoop_events.lock().await;
        std::mem::take(&mut *observed)
    };
    info!(
        "kad snoop flush keyword={} source={} notes={} total={} observations={}",
        counts.keyword,
        counts.source,
        counts.notes,
        entries.len(),
        observations.len()
    );
    match coordinator
        .flush_snoop(indexer_id, &entries, &observations)
        .await
    {
        Ok(()) => Ok(()),
        Err(error) => {
            let mut observed = observed_snoop_events.lock().await;
            observations
                .into_iter()
                .rev()
                .for_each(|event| observed.insert(0, event));
            Err(error)
        }
    }
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

/// Generate a random Kad target so background refreshes gradually cover the wider keyspace.
fn random_routing_refresh_target() -> NodeId {
    NodeId::from_bytes(rand::random())
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
        TagValue::SmallBlob(value) => serde_json::json!(hex::encode(value)),
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
                "source_count": result.source_count,
            }),
        }],
    })
}

fn keyword_logical_key(req: &SearchKeyReq) -> String {
    let payload_hex = if req.restrictive_payload.is_empty() {
        None
    } else {
        Some(hex::encode(&req.restrictive_payload))
    };
    format!(
        "keyword:{}:{:04x}:{}",
        req.target,
        req.start_position,
        payload_hex.as_deref().unwrap_or_default()
    )
}

fn source_logical_key(req: &SearchSourceReq) -> String {
    format!(
        "source:{}:{:04x}:{}",
        req.target, req.start_position, req.size
    )
}

fn notes_logical_key(req: &SearchNotesReq) -> String {
    format!("notes:{}:{}", req.target, req.size)
}

fn build_keyword_snoop_entry(req: &SearchKeyReq, now: chrono::DateTime<Utc>) -> SnoopEntry {
    let payload_hex = if req.restrictive_payload.is_empty() {
        None
    } else {
        Some(hex::encode(&req.restrictive_payload))
    };
    SnoopEntry::Keyword {
        logical_key: keyword_logical_key(req),
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
        logical_key: source_logical_key(req),
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
        logical_key: notes_logical_key(req),
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
    observed_snoop_events: &Arc<Mutex<Vec<SnoopObservation>>>,
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
    observed_snoop_events.lock().await.push(match entry {
        SnoopEntry::Keyword {
            logical_key,
            target,
            start_position,
            restrictive_payload_hex,
            last_seen,
            ..
        } => SnoopObservation {
            family: HarvestFamily::Keyword,
            logical_key,
            target,
            start_position: Some(start_position),
            size: None,
            restrictive_payload_hex,
            observed_at: last_seen,
        },
        SnoopEntry::Source {
            logical_key,
            target,
            start_position,
            size,
            last_seen,
            ..
        } => SnoopObservation {
            family: HarvestFamily::Source,
            logical_key,
            target,
            start_position: Some(start_position),
            size: Some(size),
            restrictive_payload_hex: None,
            observed_at: last_seen,
        },
        SnoopEntry::Notes {
            logical_key,
            target,
            size,
            last_seen,
            ..
        } => SnoopObservation {
            family: HarvestFamily::Notes,
            logical_key,
            target,
            start_position: None,
            size: Some(size),
            restrictive_payload_hex: None,
            observed_at: last_seen,
        },
    });
}

#[derive(Debug)]
enum PassiveReplaySelection {
    Keyword(ScheduledSnoopRequest<SearchKeyReq>),
    Source(ScheduledSnoopRequest<SearchSourceReq>),
    Notes(ScheduledSnoopRequest<SearchNotesReq>),
}

fn preferred_passive_replay_families(counts: SnoopQueueFamilyCounts) -> [HarvestFamily; 3] {
    let mut families = [
        (HarvestFamily::Keyword, counts.keyword, 0u8),
        (HarvestFamily::Source, counts.source, 1u8),
        (HarvestFamily::Notes, counts.notes, 2u8),
    ];
    families.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.2.cmp(&right.2)));
    [families[0].0, families[1].0, families[2].0]
}

fn select_passive_replay_request(
    queue: &mut SnoopQueue,
    family: HarvestFamily,
    now: DateTime<Utc>,
) -> Option<PassiveReplaySelection> {
    match family {
        HarvestFamily::Keyword => queue
            .select_next_keyword_request(now)
            .map(PassiveReplaySelection::Keyword),
        HarvestFamily::Source => queue
            .select_next_source_request(now)
            .map(PassiveReplaySelection::Source),
        HarvestFamily::Notes => queue
            .select_next_notes_request(now)
            .map(PassiveReplaySelection::Notes),
    }
}

async fn next_passive_replay_request(
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
) -> Option<PassiveReplaySelection> {
    next_passive_replay_request_with_preference(snoop_queue, None).await
}

async fn next_passive_replay_request_for_family(
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
    family: HarvestFamily,
) -> Option<PassiveReplaySelection> {
    let mut queue = snoop_queue.lock().await;
    let now = Utc::now();
    select_passive_replay_request(&mut queue, family, now)
}

async fn next_passive_replay_request_with_preference(
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
    preferred_family: Option<HarvestFamily>,
) -> Option<PassiveReplaySelection> {
    let mut queue = snoop_queue.lock().await;
    let now = Utc::now();
    let mut family_order = Vec::with_capacity(3);
    if let Some(preferred_family) = preferred_family {
        family_order.push(preferred_family);
    }
    for family in preferred_passive_replay_families(queue.family_counts()) {
        if !family_order.contains(&family) {
            family_order.push(family);
        }
    }
    for family in family_order {
        if let Some(selection) = select_passive_replay_request(&mut queue, family, now) {
            return Some(selection);
        }
    }
    None
}

async fn record_passive_replay_outcome(
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
    logical_key: &str,
    completed_at: DateTime<Utc>,
    result_count: usize,
) {
    snoop_queue
        .lock()
        .await
        .record_replay_outcome(logical_key, completed_at, result_count);
}

/// Acquire one passive replay slot without blocking the background loop.
///
/// Passive keyword and passive source replays are an Overlord-only indexing
/// extension, so we serialize them explicitly to avoid non-oracle overlap on
/// the live network.
fn try_acquire_passive_replay_gate(
    passive_replay_gate: &Arc<Semaphore>,
    family: &str,
) -> Option<OwnedSemaphorePermit> {
    match Arc::clone(passive_replay_gate).try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            debug!("skipping passive {family} replay because another passive replay is active");
            None
        }
    }
}

async fn record_passive_replay_idle_for_worker(
    harvest_observability: &Arc<Mutex<KadHarvestObservability>>,
    preferred_family: Option<HarvestFamily>,
    now: DateTime<Utc>,
) {
    let mut observability = harvest_observability.lock().await;
    match preferred_family {
        Some(family) => record_passive_replay_idle(&mut observability, family, now),
        None => {
            record_passive_replay_idle(&mut observability, HarvestFamily::Keyword, now);
            record_passive_replay_idle(&mut observability, HarvestFamily::Source, now);
            record_passive_replay_idle(&mut observability, HarvestFamily::Notes, now);
        }
    }
}

async fn persist_nodes_dat_for(dht: &DhtNode, state_paths: &AgentStatePaths) -> Result<()> {
    let contacts = dht
        .routing_contacts()
        .await
        .into_iter()
        .map(|contact| {
            let addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.udp_port);
            let udp_key = dht.known_peer_key(addr).unwrap_or(contact.udp_key);
            BootstrapContact {
                node_id: contact.id,
                ip: contact.ip,
                udp_port: contact.udp_port,
                tcp_port: contact.tcp_port,
                version: contact.kad_version,
                udp_key,
            }
        })
        .collect::<Vec<_>>();
    let bytes = encode_nodes_dat(&contacts)?;
    fs::write(&state_paths.nodes_dat_path, bytes)
        .with_context(|| format!("failed to write {}", state_paths.nodes_dat_path.display()))?;
    Ok(())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct KadHelloPeerMetadata {
    hello_source_udp_port: Option<u16>,
    udp_firewalled: bool,
    tcp_firewalled: bool,
    requests_hello_res_ack: bool,
}

fn read_u16_tag_value(value: &TagValue) -> Option<u16> {
    match value {
        TagValue::U16(port) => Some(*port),
        TagValue::U32(port) => u16::try_from(*port).ok(),
        TagValue::U8(port) => Some(u16::from(*port)),
        TagValue::UInt(port) => u16::try_from(*port).ok(),
        _ => None,
    }
}

fn read_u8_tag_value(value: &TagValue) -> Option<u8> {
    match value {
        TagValue::U8(bits) => Some(*bits),
        TagValue::U16(bits) => u8::try_from(*bits).ok(),
        TagValue::U32(bits) => u8::try_from(*bits).ok(),
        TagValue::UInt(bits) => u8::try_from(*bits).ok(),
        _ => None,
    }
}

fn parse_kad_hello_metadata(tags: &[Tag]) -> KadHelloPeerMetadata {
    let mut metadata = KadHelloPeerMetadata::default();

    for tag in tags {
        match &tag.name {
            TagName::Short(name) if *name == tag_name::SOURCEUPORT => {
                metadata.hello_source_udp_port =
                    read_u16_tag_value(&tag.value).filter(|port| *port != 0);
            }
            TagName::Short(name) if *name == tag_name::KADMISCOPTIONS => {
                let Some(bits) = read_u8_tag_value(&tag.value) else {
                    continue;
                };
                metadata.udp_firewalled = (bits & 0x01) != 0;
                metadata.tcp_firewalled = (bits & 0x02) != 0;
                metadata.requests_hello_res_ack = (bits & 0x04) != 0;
            }
            _ => {}
        }
    }

    metadata
}

async fn current_tcp_firewalled(
    ed2k_listener: &TcpListener,
    ed2k_server_state: &Arc<RwLock<Ed2kServerState>>,
) -> bool {
    if let Some(tcp_firewalled) = ed2k_server_state.read().await.tcp_firewalled() {
        return tcp_firewalled;
    }

    // Before the first ED2K server verdict arrives, a bound listener is still the
    // best local fallback signal we have.
    ed2k_listener
        .local_addr()
        .map(|addr| addr.port() == 0)
        .unwrap_or(true)
}

fn build_kad_hello_response_tags(
    kad_udp_port: u16,
    udp_firewalled: bool,
    tcp_firewalled: bool,
    request_ack: bool,
) -> Vec<Tag> {
    let mut tags = vec![Tag::new_short(
        tag_name::SOURCEUPORT,
        TagValue::U16(kad_udp_port),
    )];
    let misc_options =
        u8::from(udp_firewalled) | (u8::from(tcp_firewalled) << 1) | (u8::from(request_ack) << 2);
    tags.push(Tag::new_short(
        tag_name::KADMISCOPTIONS,
        TagValue::U8(misc_options),
    ));
    tags
}

fn build_kad_hello_request_tags(
    kad_udp_port: u16,
    can_advertise_source_udp_port: bool,
    udp_firewalled: bool,
    tcp_firewalled: bool,
    request_ack: bool,
) -> Vec<Tag> {
    // The matched oracle HELLO_REQ traffic in the live parity run emitted a
    // narrower tag shape than HELLO_RES: it sent either SOURCEUPORT or
    // KADMISCOPTIONS here, but not both in the same request.
    if request_ack || udp_firewalled || tcp_firewalled {
        let misc_options = u8::from(udp_firewalled)
            | (u8::from(tcp_firewalled) << 1)
            | (u8::from(request_ack) << 2);
        return vec![Tag::new_short(
            tag_name::KADMISCOPTIONS,
            TagValue::U8(misc_options),
        )];
    }

    if can_advertise_source_udp_port {
        return vec![Tag::new_short(
            tag_name::SOURCEUPORT,
            TagValue::U16(kad_udp_port),
        )];
    }

    Vec::new()
}

async fn build_hello_response(
    dht: &DhtNode,
    ed2k_listener: &TcpListener,
    ed2k_server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    request_ack: bool,
) -> Result<overlord_kad_proto::HelloRes> {
    let bind_addr = dht.bind_addr()?;
    let tcp_port = ed2k_listener
        .local_addr()
        .context("failed to read eD2k listener address while building hello")?
        .port();
    let firewall = kad_firewall.lock().await;

    Ok(overlord_kad_proto::HelloRes {
        node_id: dht.own_id(),
        tcp_port,
        version: overlord_kad_proto::KAD_VERSION,
        tags: build_kad_hello_response_tags(
            bind_addr.port(),
            firewall.udp_verified && !firewall.udp_open,
            current_tcp_firewalled(ed2k_listener, ed2k_server_state).await,
            request_ack,
        ),
    })
}

async fn build_hello_request(
    dht: &DhtNode,
    ed2k_listener: &TcpListener,
    ed2k_server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    request_ack: bool,
) -> Result<overlord_kad_proto::HelloReq> {
    let bind_addr = dht.bind_addr()?;
    let tcp_port = ed2k_listener
        .local_addr()
        .context("failed to read eD2k listener address while building hello request")?
        .port();
    let firewall = kad_firewall.lock().await;

    Ok(overlord_kad_proto::HelloReq {
        node_id: dht.own_id(),
        tcp_port,
        version: overlord_kad_proto::KAD_VERSION,
        tags: build_kad_hello_request_tags(
            bind_addr.port(),
            firewall.udp_verified && firewall.udp_open,
            firewall.udp_verified && !firewall.udp_open,
            current_tcp_firewalled(ed2k_listener, ed2k_server_state).await,
            request_ack,
        ),
    })
}

async fn add_contact_from_hello(
    dht: &DhtNode,
    from: SocketAddr,
    node_id: NodeId,
    tcp_port: u16,
    version: u8,
    udp_key: Option<u32>,
    tags: &[Tag],
) -> Option<KadHelloPeerMetadata> {
    let mut metadata = parse_kad_hello_metadata(tags);
    if version < 8 {
        metadata.requests_hello_res_ack = false;
    }

    let std::net::IpAddr::V4(ip) = from.ip() else {
        return Some(metadata);
    };

    let mut contact = Contact::new(
        node_id,
        ip,
        metadata.hello_source_udp_port.unwrap_or(from.port()),
        tcp_port,
        version,
    );
    let routed_udp_port = contact.udp_port;
    contact.hello_source_udp_port = metadata.hello_source_udp_port;
    contact.udp_firewalled = metadata.udp_firewalled;
    contact.tcp_firewalled = metadata.tcp_firewalled;
    contact.requests_hello_res_ack = metadata.requests_hello_res_ack;
    if let Some(udp_key) = udp_key {
        contact.udp_key = KadUdpKey::new(udp_key);
    }

    if metadata.udp_firewalled {
        debug!(
            "skipping UDP-firewalled hello contact node_id={} from={} routed_udp_port={} source_uport={:?} tcp_firewalled={} requests_ack={}",
            node_id,
            from,
            routed_udp_port,
            metadata.hello_source_udp_port,
            metadata.tcp_firewalled,
            metadata.requests_hello_res_ack
        );
        return Some(metadata);
    }

    match dht.add_contact(contact).await {
        Ok(()) => {
            debug!(
                "accepted hello contact node_id={} from={} routed_udp_port={} source_uport={:?} tcp_firewalled={} requests_ack={}",
                node_id,
                from,
                routed_udp_port,
                metadata.hello_source_udp_port,
                metadata.tcp_firewalled,
                metadata.requests_hello_res_ack
            );
        }
        Err(error) => {
            debug!("failed to add hello contact from {from}: {error}");
        }
    }

    Some(metadata)
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
            let request_ack = req.version >= 8 && !receiver_verify_key_valid;
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
            ed2k_user_hash_path: state_dir.join("overlord-ed2k.user-hash.bin"),
            ed2k_secure_ident_path: state_dir.join("overlord-ed2k.secident.pkcs8.der"),
            ed2k_transfer_root: state_dir.join("overlord-ed2k-transfer"),
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
        let callback_client = self.coordinator.clone();
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
                    do_active_ed2k_keyword_search(
                        bind_ip,
                        indexer_id,
                        ed2k_user_hash,
                        &ed2k_shared_catalog,
                        &job,
                        &config_snapshot,
                        background_search,
                        preferred_endpoint,
                        cancel.clone(),
                    )
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
                    do_active_ed2k_source_search(
                        bind_ip,
                        indexer_id,
                        ed2k_user_hash,
                        &ed2k_shared_catalog,
                        &job,
                        &config_snapshot,
                        background_search,
                        preferred_endpoint,
                        cancel.clone(),
                    )
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

    async fn seed_popular(&self, hashes: Vec<PopularHash>) -> Result<()> {
        let runtime = self.runtime.lock().await.clone();
        let Some(runtime) = runtime else {
            anyhow::bail!("agent networking is waiting for interface selection");
        };
        let source_publish_identity = source_publish_client_hash(self.indexer_id);
        let ed2k_shared_catalog = Arc::clone(&runtime.ed2k_shared_catalog);
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
        refresh_ed2k_shared_catalog(&ed2k_shared_catalog, &hashes).await;
        let seed_result = seed_popular_impl(
            &runtime.dht,
            source_publish_identity,
            source_publish_settings,
            PublishSeedSource::ManualApi,
            hashes,
            PublishExecutionContext {
                local_store: &self.local_store,
                publish_observability: &self.publish_observability,
                agent_activity: &self.agent_activity,
                activity_key: Some(activity_key.as_str()),
                notes_publish_enabled,
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
    #[allow(clippy::too_many_arguments)]
    async fn run_native_ed2k_direct_downloads<DownloadFn, DownloadFuture>(
        bind_ip: Ipv4Addr,
        hello_identity: Ed2kHelloIdentity,
        secure_ident: Arc<Ed2kSecureIdent>,
        transfer_runtime: Arc<Ed2kTransferRuntime>,
        file_hash_hex: String,
        file_name: String,
        file_size: u64,
        sources: Vec<Ed2kFoundSource>,
        connect_timeout: Duration,
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
        const MAX_PARALLEL_DOWNLOAD_PEERS: usize = 5;

        let mut last_error: Option<anyhow::Error> = None;
        let mut accepted_incomplete_peers = 0u32;
        let mut source_iter = sources.into_iter();
        let mut active_downloads = JoinSet::new();

        while active_downloads.len() < MAX_PARALLEL_DOWNLOAD_PEERS {
            let Some(source) = source_iter.next() else {
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
                    "file_hash={} client_id={} obfuscated={} has_user_hash={}",
                    file_hash_hex,
                    source.client_id,
                    source.obfuscated,
                    source.user_hash.is_some()
                ),
            );
            active_downloads.spawn(async move {
                let result = download_peer(
                    bind_ip,
                    source,
                    hello_identity,
                    secure_ident,
                    transfer_runtime,
                    file_name,
                    file_size,
                    connect_timeout,
                )
                .await;
                (peer_addr, result)
            });
        }

        while let Some(joined) = active_downloads.join_next().await {
            let (peer_addr, result) = joined.context("native ED2K download worker panicked")?;
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
                            last_error,
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
                }
            }

            while active_downloads.len() < MAX_PARALLEL_DOWNLOAD_PEERS {
                let Some(source) = source_iter.next() else {
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
                        "file_hash={} client_id={} obfuscated={} has_user_hash={}",
                        file_hash_hex,
                        source.client_id,
                        source.obfuscated,
                        source.user_hash.is_some()
                    ),
                );
                active_downloads.spawn(async move {
                    let result = download_peer(
                        bind_ip,
                        source,
                        hello_identity,
                        secure_ident,
                        transfer_runtime,
                        file_name,
                        file_size,
                        connect_timeout,
                    )
                    .await;
                    (peer_addr, result)
                });
            }
        }

        Ok(NativeDirectDownloadOutcome {
            completed: transfer_runtime.manifest(&file_hash_hex).await?.completed,
            accepted_incomplete_peers,
            last_error,
        })
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
                Ok(results) if !results.is_empty() => merge_download_sources(&mut sources, results),
                Ok(_) => {
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

        match search_source_servers(
            runtime.bind_ip,
            &config.p2p.ed2k,
            hello_identity,
            &shared_catalog,
            preferred_endpoint,
            ED2K_ACTIVE_SEARCH_MAX_SERVER_ATTEMPTS,
            file_hash,
            file_size,
            &cancel,
        )
        .await
        {
            Ok(server_results) => merge_download_sources(&mut sources, server_results),
            Err(error) => {
                warn!(
                    "native ED2K download active server source search failed for file_hash={file_hash}: {error}"
                );
            }
        }
        if sources.is_empty() {
            let kad_sources =
                collect_kad_ed2k_sources(&runtime.dht, file_hash, file_size, source_search_timeout)
                    .await;
            if !kad_sources.is_empty() {
                info!(
                    "native ED2K download Kad source fallback produced file_hash={} source_count={}",
                    file_hash,
                    kad_sources.len()
                );
                merge_download_sources(&mut sources, kad_sources);
            }
        }
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
        let shared_catalog = runtime.ed2k_shared_catalog.read().await.clone();
        runtime
            .ed2k_transfer
            .ensure_job(&new_transfer_job(
                file_hash,
                request.file_name.clone(),
                request.file_size,
            ))
            .await?;
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
        let mut sources = if request.sources.is_empty() {
            Self::native_ed2k_download_sources(
                &runtime,
                &config,
                file_hash,
                request.file_size,
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

        // Prefer sources with user-hash metadata first so obfuscation-capable
        // peers get the first attempt without blocking on more complex ranking.
        sources.sort_by_key(|source| {
            (
                !source.is_direct_dialable(),
                source.user_hash.is_none(),
                source.obfuscation_options.is_none(),
            )
        });

        let callback_only_sources: Vec<_> = sources
            .iter()
            .filter(|source| source.low_id)
            .cloned()
            .collect();
        let skipped_low_id_sources = callback_only_sources.len();
        if skipped_low_id_sources != 0 {
            info!(
                "native ED2K download filtered callback-only sources file_hash={} skipped_low_id_sources={}",
                request.file_hash, skipped_low_id_sources
            );
        }
        // Low-ID peers often arrive noticeably later than direct ED2K connects
        // because the server-mediated callback has to propagate first.
        let callback_timeout = Duration::from_secs(config.p2p.ed2k.connect_timeout_secs.max(30));
        if !callback_only_sources.is_empty() {
            let cancel = CancellationToken::new();
            for source in &callback_only_sources {
                runtime
                    .ed2k_transfer
                    .register_callback_intent(Ed2kCallbackIntent {
                        client_id: source.client_id,
                        file_hash: request.file_hash.clone(),
                        canonical_name: request.file_name.clone(),
                        file_size: request.file_size,
                        source: Ed2kSourceHint {
                            ip: source.ip.to_string(),
                            tcp_port: source.tcp_port,
                            user_hash: source.user_hash.map(hex::encode),
                        },
                    })
                    .await;
                info!(
                    "native ED2K download requesting server callback file_hash={} client_id={} tcp_port={} source_server={}",
                    request.file_hash,
                    source.client_id,
                    source.tcp_port,
                    source
                        .source_server
                        .map_or_else(|| "-".to_string(), |endpoint| endpoint.to_string())
                );
                let callback_result = if let Some(source_server) = source.source_server {
                    request_callback_on_server(
                        runtime.bind_ip,
                        &config.p2p.ed2k,
                        hello_identity,
                        &shared_catalog,
                        source_server,
                        source.client_id,
                        callback_timeout,
                        &cancel,
                    )
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
        sources.retain(Ed2kFoundSource::is_direct_dialable);
        let had_direct_sources = !sources.is_empty();
        for source in &sources {
            dump_ed2k_tcp_download_meta(
                SocketAddr::new(IpAddr::V4(source.ip), source.tcp_port),
                None,
                "source_candidate",
                format!(
                    "file_hash={} client_id={} low_id={} obfuscated={} has_user_hash={}",
                    request.file_hash,
                    source.client_id,
                    source.low_id,
                    source.obfuscated,
                    source.user_hash.is_some()
                ),
            );
        }
        if had_direct_sources {
            let outcome = Self::run_native_ed2k_direct_downloads(
                runtime.bind_ip,
                hello_identity,
                Arc::clone(&runtime.ed2k_secure_ident),
                Arc::clone(&runtime.ed2k_transfer),
                request.file_hash.clone(),
                request.file_name.clone(),
                request.file_size,
                sources,
                Duration::from_secs(config.p2p.ed2k.connect_timeout_secs.max(10)),
                |bind_ip,
                 source,
                 hello_identity,
                 secure_ident,
                 transfer_runtime,
                 file_name,
                 file_size,
                 connect_timeout| async move {
                    download_file_from_peer(
                        bind_ip,
                        &source,
                        hello_identity,
                        &secure_ident,
                        transfer_runtime.as_ref(),
                        file_name,
                        file_size,
                        connect_timeout,
                    )
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
                        request.file_name,
                        request.file_size,
                        manifest.file_size,
                        manifest.verified_ranges.len(),
                        manifest.completed
                    ),
                );
                info!(
                    "native ED2K download completed file_hash={} file_name={} size={}",
                    request.file_hash, request.file_name, request.file_size
                );
                return Ok(());
            }
            let last_error = outcome.last_error;
            if outcome.accepted_incomplete_peers != 0 {
                dump_ed2k_tcp_download_meta(
                    SocketAddr::new(IpAddr::V4(runtime.bind_ip), config.p2p.ed2k.listen_port),
                    None,
                    "download_accepted_incomplete_peers",
                    format!(
                        "file_hash={} accepted_incomplete_peers={}",
                        request.file_hash, outcome.accepted_incomplete_peers
                    ),
                );
            }
            if !callback_only_sources.is_empty() {
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
            if let Some(error) = last_error {
                return Err(error).with_context(|| {
                    format!(
                        "native ED2K download did not complete for {} after trying discovered sources",
                        request.file_hash
                    )
                });
            }
        }

        if !callback_only_sources.is_empty() {
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

        let normalized_file_hash = request.file_hash.to_lowercase();
        if let Some(runtime) = self.runtime.lock().await.clone()
            && let Ok(manifest) = runtime.ed2k_transfer.manifest(&normalized_file_hash).await
            && (manifest.completed || manifest_has_ed2k_transfer_progress(&manifest))
        {
            info!(
                "native ED2K download already has persisted progress file_hash={} completed={} bytes_written={} md4_hashset_acquired={}",
                normalized_file_hash,
                manifest.completed,
                manifest
                    .pieces
                    .iter()
                    .map(|piece| piece.bytes_written)
                    .sum::<u64>(),
                manifest.md4_hashset_acquired
            );
            return Ok(());
        }
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
        let ed2k_user_hash = self.ed2k_user_hash;
        tokio::spawn(async move {
            let activity_key = active_ed2k_download_key(&normalized_file_hash);
            let started_at = Utc::now();
            let mut activity_snapshot =
                new_activity_snapshot(AgentActivityState::Downloading, started_at);
            activity_snapshot.protocol = Some(Protocol::Ed2k);
            activity_snapshot.query_or_target =
                Some(format!("{} ({})", request.file_name, normalized_file_hash));
            begin_agent_activity(&agent_activity, activity_key.clone(), activity_snapshot).await;

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
        });
        Ok(())
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
                match dht.lookup_nodes(&target).await {
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
        let publish_observability = Arc::clone(&self.publish_observability);
        let agent_activity = Arc::clone(&self.agent_activity);
        let ed2k_shared_catalog = Arc::clone(&runtime.ed2k_shared_catalog);
        let source_publish_identity = source_publish_client_hash(self.indexer_id);
        let source_publish_settings = SourcePublishSettings {
            tcp_port: config.p2p.ed2k.listen_port,
            obfuscation_enabled: config.p2p.ed2k.obfuscation_enabled,
        };
        let notes_publish_enabled = config.p2p.kad.seed_notes_publish_enabled;
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
                match dht.bootstrap().await {
                    Ok(()) => {
                        if let Err(error) = persist_nodes_dat_for(&dht, &state_paths).await {
                            warn!("failed to persist nodes.dat after bootstrap: {error}");
                        }
                        if let Err(error) = seed_popular_from_coordinator_or_fallback(
                            &dht,
                            source_publish_identity,
                            source_publish_settings,
                            &coordinator,
                            &ed2k_shared_catalog,
                            PublishExecutionContext {
                                local_store: &local_store,
                                publish_observability: &publish_observability,
                                agent_activity: &agent_activity,
                                activity_key: None,
                                notes_publish_enabled,
                            },
                        )
                        .await
                        {
                            debug!("post-bootstrap seeding failed: {error}");
                        }
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
            run_ed2k_listener(
                ed2k_listener,
                dht,
                ed2k_server_state,
                kad_firewall,
                ed2k_secure_ident,
                ed2k_transfer,
                ed2k_hello_identity,
                shutdown,
            )
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
                run_ed2k_server_loop(
                    bind_ip,
                    nat,
                    ed2k_server_config,
                    ed2k_hello_identity,
                    ed2k_shared_catalog,
                    ed2k_server_state,
                    ed2k_server_search_inbox,
                    kad_firewall,
                    shutdown,
                )
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
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let mut introduced = std::collections::HashSet::new();
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(KAD_HELLO_INTRO_SECS)).await;
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

                for (contact, addr) in contacts.into_iter().take(KAD_HELLO_INTRO_FANOUT) {
                    let request_ack = contact.kad_version >= 8;
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
                    if let Err(error) = dht.send_packet(addr, &KadPacket::HelloReq(hello)).await {
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
                        info!(
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
                        info!(
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
                        info!(
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
                        info!(
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
        let republish_secs = config.p2p.kad.republish_interval_secs;
        let local_store = Arc::clone(&self.local_store);
        let publish_observability = Arc::clone(&self.publish_observability);
        let agent_activity = Arc::clone(&self.agent_activity);
        let ed2k_shared_catalog = Arc::clone(&runtime.ed2k_shared_catalog);
        let source_publish_identity = source_publish_client_hash(self.indexer_id);
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
                if let Err(error) = seed_popular_from_coordinator_or_fallback(
                    &dht,
                    source_publish_identity,
                    source_publish_settings,
                    &coordinator,
                    &ed2k_shared_catalog,
                    PublishExecutionContext {
                        local_store: &local_store,
                        publish_observability: &publish_observability,
                        agent_activity: &agent_activity,
                        activity_key: None,
                        notes_publish_enabled,
                    },
                )
                .await
                {
                    debug!("republish cycle failed: {error}");
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
mod tests {
    use super::{
        COORDINATOR_RECONNECT_SECS, EMULE_LARGE_FILE_SIZE_THRESHOLD, EmuleAgentConfig,
        OverlordAgentEmule, PASSIVE_REPLAY_CONCURRENCY, PassiveReplaySelection,
        SYNTHETIC_POPULAR_SEEDS, SourcePublishSettings, apply_harvest_record,
        apply_networking_config, apply_publish_summary, apply_queue_family_counts,
        build_hello_request, build_hello_response, build_kad_hello_request_tags,
        build_kad_hello_response_tags, build_keyword_snoop_entry, build_notes_publish_tags,
        build_notes_snoop_entry, build_publish_batch_summary, build_source_publish_tags,
        build_source_snoop_entry, current_tcp_firewalled, ed2k_file_type_search_term,
        effective_publish_counters, empty_networking_config, emule_high_id_source_type,
        flush_snoop_queue, keyword_target, next_passive_replay_request,
        next_passive_replay_request_for_family, normalize_ed2k_user_hash_markers,
        parse_kad_hello_metadata, record_passive_replay_complete,
        record_passive_replay_enqueue_wait, record_passive_replay_idle,
        record_passive_replay_post_failure, record_passive_replay_post_latency,
        record_passive_replay_start, restore_snoop_queue, select_popular_hashes_for_seeding,
        select_popular_hashes_from_fetch_result, significant_keyword_words, synthetic_file_hash,
        synthetic_popular_hashes, synthetic_publish_aich_hash, try_acquire_passive_replay_gate,
    };
    use crate::{
        config::SnoopQueueConfig,
        ed2k_server::{Ed2kFoundSource, Ed2kServerState},
        ed2k_tcp::{
            Ed2kHelloIdentity, Ed2kPeerDownloadOutcome, Ed2kSecureIdent, emule_connect_options,
        },
        ed2k_transfer::{Ed2kTransferRuntime, new_transfer_job},
        kad_firewall::KadFirewallState,
        paths::unique_test_dir,
        snoop_queue::{SnoopQueue, SnoopQueueFamilyCounts},
    };
    use axum::{
        Json, Router,
        extract::{Path as AxumPath, State},
        routing::{get, post},
    };
    use chrono::{TimeZone, Utc};
    use md4::{Digest, Md4};
    use overlord_agent_common::{
        AgentInterfacesView, ConfigUpdate, CoordinatorClient, HarvestFamily, HashType,
        IndexerRegistration, IndexerService, KadHarvestObservability, KadPassiveReplayTierSummary,
        PopularHash, Protocol, PublishCounters, PublishSeedSource, RegisterRequest,
        RegistrationResponse, SnoopEntry,
    };
    use overlord_agent_nat::{UPNP_MINIUPNPC_BACKEND, UPNP_RUPNP_BACKEND};
    use overlord_kad_dht::{DhtConfig, DhtNode, PublishAttemptStats};
    use overlord_kad_proto::{
        Ed2kHash, NodeId, SearchKeyReq, SearchNotesReq, SearchSourceReq, Tag, TagName, TagValue,
        tag_name,
    };
    use std::{
        collections::HashSet,
        fs,
        net::{Ipv4Addr, SocketAddr},
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering, Ordering as AtomicOrdering},
        },
        time::Duration,
    };
    use tokio::sync::{Mutex, RwLock, Semaphore};
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

    #[tokio::test]
    async fn native_direct_download_retries_other_direct_peer_after_failure() {
        let temp_root = unique_test_dir("overlord-agent-emule-direct-download-retry");
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&temp_root).unwrap());
        let payload = b"captured small file payload".repeat(32);
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "captured.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();
        let secure_ident =
            Arc::new(Ed2kSecureIdent::load_or_create(&temp_root.join("secure-ident.der")).unwrap());
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let payload = Arc::new(payload);
        let file_hash_hex_for_download = file_hash_hex.clone();
        let outcome = OverlordAgentEmule::run_native_ed2k_direct_downloads(
            Ipv4Addr::LOCALHOST,
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            secure_ident,
            Arc::clone(&transfer_runtime),
            file_hash_hex.clone(),
            "captured.epub".to_string(),
            payload.len() as u64,
            vec![
                Ed2kFoundSource {
                    file_hash,
                    ip: Ipv4Addr::LOCALHOST,
                    tcp_port: 41001,
                    client_id: 1,
                    low_id: false,
                    obfuscated: false,
                    obfuscation_options: None,
                    user_hash: None,
                    source_server: None,
                },
                Ed2kFoundSource {
                    file_hash,
                    ip: Ipv4Addr::LOCALHOST,
                    tcp_port: 41002,
                    client_id: 2,
                    low_id: false,
                    obfuscated: false,
                    obfuscation_options: None,
                    user_hash: None,
                    source_server: None,
                },
            ],
            Duration::from_secs(1),
            {
                let attempts = Arc::clone(&attempts);
                move |_bind_ip,
                      source,
                      _hello_identity,
                      _secure_ident,
                      transfer_runtime,
                      _file_name,
                      _file_size,
                      _connect_timeout| {
                    let attempts = Arc::clone(&attempts);
                    let payload = Arc::clone(&payload);
                    let file_hash_hex = file_hash_hex_for_download.clone();
                    async move {
                        attempts.lock().await.push(source.tcp_port);
                        if source.tcp_port == 41001 {
                            anyhow::bail!("simulated first peer failure");
                        }
                        transfer_runtime
                            .store_md4_hashset(&file_hash_hex, Vec::new())
                            .await?;
                        transfer_runtime
                            .store_piece_data(&file_hash_hex, 0, payload.as_slice())
                            .await?;
                        Ok(Ed2kPeerDownloadOutcome::Completed)
                    }
                }
            },
        )
        .await
        .unwrap();

        assert!(outcome.completed);
        assert_eq!(outcome.accepted_incomplete_peers, 0);
        assert!(outcome.last_error.is_some());
        assert_eq!(*attempts.lock().await, vec![41001, 41002]);
        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(manifest.completed);
    }

    #[tokio::test]
    async fn native_direct_download_tracks_accepted_incomplete_peer_separately_from_failure() {
        let temp_root = unique_test_dir("overlord-agent-emule-direct-download-accepted-incomplete");
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&temp_root).unwrap());
        let payload = b"captured small file payload".repeat(32);
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "captured.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();
        let secure_ident =
            Arc::new(Ed2kSecureIdent::load_or_create(&temp_root.join("secure-ident.der")).unwrap());
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let payload = Arc::new(payload);
        let file_hash_hex_for_download = file_hash_hex.clone();
        let outcome = OverlordAgentEmule::run_native_ed2k_direct_downloads(
            Ipv4Addr::LOCALHOST,
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            secure_ident,
            Arc::clone(&transfer_runtime),
            file_hash_hex.clone(),
            "captured.epub".to_string(),
            payload.len() as u64,
            vec![
                Ed2kFoundSource {
                    file_hash,
                    ip: Ipv4Addr::LOCALHOST,
                    tcp_port: 41001,
                    client_id: 1,
                    low_id: false,
                    obfuscated: false,
                    obfuscation_options: None,
                    user_hash: None,
                    source_server: None,
                },
                Ed2kFoundSource {
                    file_hash,
                    ip: Ipv4Addr::LOCALHOST,
                    tcp_port: 41002,
                    client_id: 2,
                    low_id: false,
                    obfuscated: false,
                    obfuscation_options: None,
                    user_hash: None,
                    source_server: None,
                },
            ],
            Duration::from_secs(1),
            {
                let attempts = Arc::clone(&attempts);
                move |_bind_ip,
                      source,
                      _hello_identity,
                      _secure_ident,
                      transfer_runtime,
                      _file_name,
                      _file_size,
                      _connect_timeout| {
                    let attempts = Arc::clone(&attempts);
                    let payload = Arc::clone(&payload);
                    let file_hash_hex = file_hash_hex_for_download.clone();
                    async move {
                        attempts.lock().await.push(source.tcp_port);
                        if source.tcp_port == 41001 {
                            return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                        }
                        transfer_runtime
                            .store_md4_hashset(&file_hash_hex, Vec::new())
                            .await?;
                        transfer_runtime
                            .store_piece_data(&file_hash_hex, 0, payload.as_slice())
                            .await?;
                        Ok(Ed2kPeerDownloadOutcome::Completed)
                    }
                }
            },
        )
        .await
        .unwrap();

        assert!(outcome.completed);
        assert_eq!(outcome.accepted_incomplete_peers, 1);
        assert!(outcome.last_error.is_none());
        assert_eq!(*attempts.lock().await, vec![41001, 41002]);
        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(manifest.completed);
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
    fn ed2k_user_hash_uses_oracle_emule_markers() {
        let user_hash = normalize_ed2k_user_hash_markers([0xAA; 16]);

        assert_eq!(user_hash[5], 0x0E);
        assert_eq!(user_hash[14], 0x6F);
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
    fn seeding_falls_back_to_synthetic_hashes_when_fetch_fails() {
        let (source, selected) =
            select_popular_hashes_from_fetch_result(Err(anyhow::anyhow!("coordinator offline")));

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
    fn effective_publish_counters_include_in_flight_batch_progress() {
        let previous_completed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 5, 0).unwrap();
        let live_observed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 10, 0).unwrap();
        let committed_summary = build_publish_batch_summary(
            PublishSeedSource::Coordinator,
            10,
            PublishAttemptStats {
                closest_contacts_considered: 6,
                attempted_contacts: 6,
                acked_contacts: 4,
                timed_out_contacts: 1,
            },
            previous_completed_at,
        );
        let live_summary = build_publish_batch_summary(
            PublishSeedSource::SyntheticFallback,
            7,
            PublishAttemptStats {
                closest_contacts_considered: 5,
                attempted_contacts: 5,
                acked_contacts: 2,
                timed_out_contacts: 2,
            },
            live_observed_at,
        );
        let mut committed_counters = PublishCounters::default();
        apply_publish_summary(&mut committed_counters, &committed_summary);

        let effective = effective_publish_counters(
            &committed_counters,
            Some(&live_summary),
            Some(live_observed_at),
        );

        assert_eq!(effective.batches, 2);
        assert_eq!(effective.published_items, 17);
        assert_eq!(effective.closest_contacts_considered, 11);
        assert_eq!(effective.attempted_contacts, 11);
        assert_eq!(effective.acked_contacts, 6);
        assert_eq!(effective.failed_contacts, 5);
        assert_eq!(effective.timed_out_contacts, 3);
        assert_eq!(effective.last_batch_at, Some(live_observed_at));
        assert_eq!(effective.last_success_at, Some(live_observed_at));
    }

    #[test]
    fn effective_publish_counters_do_not_double_count_committed_batch() {
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

        let effective = effective_publish_counters(&counters, Some(&summary), Some(completed_at));

        assert_eq!(effective, counters);
    }

    #[test]
    fn effective_publish_counters_ignore_empty_initial_snapshot() {
        let observed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 0, 0).unwrap();
        let empty_summary = build_publish_batch_summary(
            PublishSeedSource::Coordinator,
            0,
            PublishAttemptStats::default(),
            observed_at,
        );

        let effective = effective_publish_counters(
            &PublishCounters::default(),
            Some(&empty_summary),
            Some(observed_at),
        );

        assert_eq!(effective, PublishCounters::default());
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
        let tier_summaries = vec![
            KadPassiveReplayTierSummary {
                responder_ceiling: 10,
                result_count: 2,
            },
            KadPassiveReplayTierSummary {
                responder_ceiling: 20,
                result_count: 5,
            },
        ];

        record_passive_replay_idle(&mut observability, HarvestFamily::Keyword, idle_at);
        record_passive_replay_start(
            &mut observability,
            HarvestFamily::Keyword,
            request.target.to_string(),
            Some(request.start_position),
            Some(request.restrictive_payload.len() as u32),
            started_at,
        );
        record_passive_replay_complete(
            &mut observability,
            HarvestFamily::Keyword,
            completed_at,
            7,
            2,
            tier_summaries.clone(),
        );
        record_passive_replay_post_failure(
            &mut observability,
            HarvestFamily::Keyword,
            failed_at,
            "post failed",
        );
        record_passive_replay_enqueue_wait(
            &mut observability,
            HarvestFamily::Keyword,
            Duration::from_millis(12),
            true,
        );
        record_passive_replay_post_latency(
            &mut observability,
            HarvestFamily::Keyword,
            Duration::from_millis(34),
        );

        assert_eq!(observability.passive_keyword_replay.idle_cycles, 1);
        assert_eq!(observability.passive_keyword_replay.started_cycles, 1);
        assert_eq!(observability.passive_keyword_replay.completed_cycles, 1);
        assert_eq!(observability.passive_keyword_replay.emitted_results, 7);
        assert_eq!(observability.passive_keyword_replay.widened_cycles, 1);
        assert_eq!(observability.passive_keyword_replay.posted_batches, 2);
        assert_eq!(observability.passive_keyword_replay.post_failures, 1);
        assert_eq!(
            observability
                .passive_keyword_replay
                .enqueue_backpressure_events,
            1
        );
        assert_eq!(observability.passive_keyword_replay.post_callbacks, 1);
        assert_eq!(observability.passive_keyword_replay.enqueue_wait_millis, 12);
        assert_eq!(observability.passive_keyword_replay.post_latency_millis, 34);
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
            observability
                .passive_keyword_replay
                .last_enqueue_wait_millis,
            12
        );
        assert_eq!(
            observability
                .passive_keyword_replay
                .last_post_latency_millis,
            34
        );
        assert_eq!(observability.passive_keyword_replay.last_tiers_attempted, 2);
        assert_eq!(
            observability
                .passive_keyword_replay
                .last_widest_responder_ceiling,
            Some(20)
        );
        assert!(observability.passive_keyword_replay.last_widened);
        assert_eq!(
            observability.passive_keyword_replay.last_tiers,
            tier_summaries
        );
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

    #[test]
    fn passive_source_replay_observability_tracks_tiered_cycle_lifecycle() {
        let mut observability = KadHarvestObservability::default();
        let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 21, 0, 0).unwrap();
        let idle_at = Utc.with_ymd_and_hms(2026, 3, 22, 21, 1, 0).unwrap();
        let completed_at = Utc.with_ymd_and_hms(2026, 3, 22, 21, 2, 0).unwrap();
        let tier_summaries = vec![KadPassiveReplayTierSummary {
            responder_ceiling: 10,
            result_count: 4,
        }];

        record_passive_replay_idle(&mut observability, HarvestFamily::Source, idle_at);
        record_passive_replay_start(
            &mut observability,
            HarvestFamily::Source,
            "ffeeddccbbaa99887766554433221100".to_string(),
            Some(0),
            None,
            started_at,
        );
        record_passive_replay_complete(
            &mut observability,
            HarvestFamily::Source,
            completed_at,
            4,
            1,
            tier_summaries.clone(),
        );

        assert_eq!(observability.passive_source_replay.idle_cycles, 1);
        assert_eq!(observability.passive_source_replay.started_cycles, 1);
        assert_eq!(observability.passive_source_replay.completed_cycles, 1);
        assert_eq!(observability.passive_source_replay.emitted_results, 4);
        assert_eq!(observability.passive_source_replay.posted_batches, 1);
        assert_eq!(
            observability.passive_source_replay.last_target.as_deref(),
            Some("ffeeddccbbaa99887766554433221100")
        );
        assert_eq!(
            observability.passive_source_replay.last_start_position,
            Some(0)
        );
        assert_eq!(
            observability.passive_source_replay.last_restrictive_bytes,
            None
        );
        assert_eq!(observability.passive_source_replay.last_tiers_attempted, 1);
        assert_eq!(
            observability
                .passive_source_replay
                .last_widest_responder_ceiling,
            Some(10)
        );
        assert!(!observability.passive_source_replay.last_widened);
        assert_eq!(
            observability.passive_source_replay.last_tiers,
            tier_summaries
        );
        assert_eq!(
            observability.passive_source_replay.last_completed_at,
            Some(completed_at)
        );
    }

    #[test]
    fn passive_notes_replay_observability_uses_dedicated_bucket() {
        let mut observability = KadHarvestObservability::default();
        let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 0, 0).unwrap();
        let idle_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 1, 0).unwrap();
        let completed_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 2, 0).unwrap();
        let tier_summaries = vec![KadPassiveReplayTierSummary {
            responder_ceiling: 10,
            result_count: 2,
        }];

        record_passive_replay_idle(&mut observability, HarvestFamily::Notes, idle_at);
        record_passive_replay_start(
            &mut observability,
            HarvestFamily::Notes,
            "1234567890abcdef1234567890abcdef".to_string(),
            None,
            None,
            started_at,
        );
        record_passive_replay_complete(
            &mut observability,
            HarvestFamily::Notes,
            completed_at,
            2,
            1,
            tier_summaries.clone(),
        );

        assert_eq!(observability.passive_notes_replay.idle_cycles, 1);
        assert_eq!(observability.passive_notes_replay.started_cycles, 1);
        assert_eq!(observability.passive_notes_replay.completed_cycles, 1);
        assert_eq!(observability.passive_notes_replay.emitted_results, 2);
        assert_eq!(observability.passive_notes_replay.posted_batches, 1);
        assert_eq!(
            observability.passive_notes_replay.last_target.as_deref(),
            Some("1234567890abcdef1234567890abcdef")
        );
        assert_eq!(observability.passive_notes_replay.last_start_position, None);
        assert_eq!(
            observability.passive_notes_replay.last_restrictive_bytes,
            None
        );
        assert_eq!(
            observability.passive_notes_replay.last_tiers,
            tier_summaries
        );
        assert_eq!(
            observability.passive_notes_replay.last_completed_at,
            Some(completed_at)
        );
        assert_eq!(observability.passive_keyword_replay.started_cycles, 0);
    }

    #[tokio::test]
    async fn next_passive_replay_request_prefers_source_when_backlog_is_heavier() {
        let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig {
            dedup_window_secs: 60,
            general_max_queries_per_600s: 10,
            general_drain_cooldown_secs: 30,
            source_max_queries_per_600s: 10,
            source_drain_cooldown_secs: 30,
            source_stop_after_results: 2,
        })));
        let now = Utc.with_ymd_and_hms(2026, 3, 24, 15, 12, 0).unwrap();
        {
            let mut guard = queue.lock().await;
            guard.record(build_keyword_snoop_entry(
                &SearchKeyReq {
                    target: NodeId::from_bytes([0x11; 16]),
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
                now,
            ));
            guard.record(build_source_snoop_entry(
                &SearchSourceReq {
                    target: NodeId::from_bytes([0x22; 16]),
                    start_position: 0,
                    size: 1_024,
                },
                now,
            ));
            guard.record(build_source_snoop_entry(
                &SearchSourceReq {
                    target: NodeId::from_bytes([0x33; 16]),
                    start_position: 0,
                    size: 2_048,
                },
                now,
            ));
            guard.record(build_source_snoop_entry(
                &SearchSourceReq {
                    target: NodeId::from_bytes([0x33; 16]),
                    start_position: 0,
                    size: 2_048,
                },
                now,
            ));
        }

        let selected = next_passive_replay_request(&queue).await;
        assert!(matches!(selected, Some(PassiveReplaySelection::Source(_))));
    }

    #[tokio::test]
    async fn next_passive_replay_request_selects_notes_when_only_notes_are_queued() {
        let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig {
            dedup_window_secs: 60,
            general_max_queries_per_600s: 10,
            general_drain_cooldown_secs: 30,
            source_max_queries_per_600s: 10,
            source_drain_cooldown_secs: 30,
            source_stop_after_results: 2,
        })));
        let now = Utc.with_ymd_and_hms(2026, 3, 24, 15, 14, 0).unwrap();
        {
            let mut guard = queue.lock().await;
            guard.record(build_notes_snoop_entry(
                &SearchNotesReq {
                    target: NodeId::from_bytes([0x44; 16]),
                    size: 4_096,
                },
                now,
            ));
        }

        let selected = next_passive_replay_request(&queue).await;
        assert!(matches!(selected, Some(PassiveReplaySelection::Notes(_))));
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
        let observed_snoop_events = Arc::new(Mutex::new(Vec::new()));
        let indexer_id = Uuid::from_u128(0x22222222222222222222222222222222);

        restore_snoop_queue(&coordinator, indexer_id, &queue).await;
        flush_snoop_queue(&coordinator, indexer_id, &queue, &observed_snoop_events)
            .await
            .unwrap();

        let flushed_entries = flushed_entries.lock().await.clone();
        assert_eq!(flushed_entries, vec![restored_entry]);
    }

    #[tokio::test]
    async fn passive_replay_gate_allows_two_workers_but_blocks_a_third() {
        let gate = Arc::new(Semaphore::new(PASSIVE_REPLAY_CONCURRENCY));
        let first = try_acquire_passive_replay_gate(&gate, "source-fast-path");
        assert!(first.is_some());
        let second = try_acquire_passive_replay_gate(&gate, "general");
        assert!(second.is_some());
        assert!(try_acquire_passive_replay_gate(&gate, "overflow").is_none());
        drop(first);
        assert!(try_acquire_passive_replay_gate(&gate, "overflow").is_some());
    }

    #[tokio::test]
    async fn source_fast_path_prefers_source_replays() {
        let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig {
            dedup_window_secs: 600,
            general_max_queries_per_600s: 10,
            general_drain_cooldown_secs: 30,
            source_max_queries_per_600s: 10,
            source_drain_cooldown_secs: 30,
            source_stop_after_results: 2,
        })));
        let now = Utc::now();
        queue.lock().await.record(build_keyword_snoop_entry(
            &SearchKeyReq {
                target: "00112233445566778899aabbccddeeff".parse().unwrap(),
                start_position: 0,
                restrictive_payload: Vec::new(),
            },
            now,
        ));
        queue.lock().await.record(build_source_snoop_entry(
            &SearchSourceReq {
                target: "11112222333344445555666677778888".parse().unwrap(),
                start_position: 0,
                size: 4096,
            },
            now,
        ));
        queue.lock().await.record(build_source_snoop_entry(
            &SearchSourceReq {
                target: "11112222333344445555666677778888".parse().unwrap(),
                start_position: 0,
                size: 4096,
            },
            now,
        ));

        let selected = next_passive_replay_request_for_family(&queue, HarvestFamily::Source).await;

        assert!(matches!(selected, Some(PassiveReplaySelection::Source(_))));
    }

    #[tokio::test]
    async fn source_fast_path_stays_idle_without_source_backlog() {
        let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig {
            dedup_window_secs: 600,
            general_max_queries_per_600s: 10,
            general_drain_cooldown_secs: 30,
            source_max_queries_per_600s: 10,
            source_drain_cooldown_secs: 30,
            source_stop_after_results: 2,
        })));
        queue.lock().await.record(build_keyword_snoop_entry(
            &SearchKeyReq {
                target: "00112233445566778899aabbccddeeff".parse().unwrap(),
                start_position: 0,
                restrictive_payload: Vec::new(),
            },
            Utc::now(),
        ));

        let selected = next_passive_replay_request_for_family(&queue, HarvestFamily::Source).await;

        assert!(selected.is_none());
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
            agent_activity: None,
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

    #[test]
    fn kad_hello_metadata_parses_misc_bits_and_source_uport() {
        let metadata = parse_kad_hello_metadata(&[
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
            Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x07)),
        ]);

        assert_eq!(metadata.hello_source_udp_port, Some(41000));
        assert!(metadata.udp_firewalled);
        assert!(metadata.tcp_firewalled);
        assert!(metadata.requests_hello_res_ack);
    }

    #[test]
    fn kad_hello_response_tags_encode_expected_misc_bits() {
        let tags = build_kad_hello_response_tags(41000, true, false, true);

        assert_eq!(
            tags,
            vec![
                Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
                Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05)),
            ]
        );
    }

    #[test]
    fn kad_hello_request_tags_prefer_misc_options_when_ack_is_requested() {
        let tags = build_kad_hello_request_tags(41000, true, false, false, true);

        assert_eq!(
            tags,
            vec![Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x04))]
        );
    }

    #[test]
    fn kad_hello_request_tags_advertise_source_uport_for_verified_open_udp() {
        let tags = build_kad_hello_request_tags(41000, true, false, false, false);

        assert_eq!(
            tags,
            vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))]
        );
    }

    #[test]
    fn kad_hello_request_tags_can_be_empty_before_udp_state_is_verified() {
        let tags = build_kad_hello_request_tags(41000, false, false, false, false);

        assert!(tags.is_empty());
    }

    #[test]
    fn source_publish_tags_match_oracle_plaintext_shape() {
        let tags = build_source_publish_tags(
            "10.54.206.206:41000".parse().unwrap(),
            SourcePublishSettings {
                tcp_port: 41001,
                obfuscation_enabled: false,
            },
            2_097_152,
        );

        assert_eq!(
            tags,
            vec![
                Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
                Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(41001)),
                Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
                Tag::filesize(2_097_152),
                Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0)),
            ]
        );
    }

    #[test]
    fn source_publish_tags_set_obfuscated_encryption_bits() {
        let tags = build_source_publish_tags(
            "10.54.206.206:41000".parse().unwrap(),
            SourcePublishSettings {
                tcp_port: 41001,
                obfuscation_enabled: true,
            },
            2_097_152,
        );

        assert_eq!(
            tags.last(),
            Some(&Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(3)))
        );
    }

    #[test]
    fn notes_publish_tags_are_deterministic_and_note_shaped() {
        let tags = build_notes_publish_tags("ubuntu linux.iso", 2_097_152);

        assert_eq!(
            tags,
            vec![
                Tag::filename("ubuntu linux.iso"),
                Tag::filesize(2_097_152),
                Tag::new_short(tag_name::FILERATING, TagValue::U8(4)),
                Tag::new_short(
                    tag_name::DESCRIPTION,
                    TagValue::String("overlord validation note for ubuntu linux.iso".to_string()),
                ),
            ]
        );
    }

    #[test]
    fn ed2k_file_type_search_term_matches_oracle_program_family() {
        assert_eq!(
            ed2k_file_type_search_term("ubuntu-linux-oracle-sample.iso"),
            Some("Pro")
        );
        assert_eq!(ed2k_file_type_search_term("archive.7z"), Some("Pro"));
    }

    #[test]
    fn ed2k_file_type_search_term_matches_common_media_families() {
        assert_eq!(ed2k_file_type_search_term("album.flac"), Some("Audio"));
        assert_eq!(ed2k_file_type_search_term("movie.mkv"), Some("Video"));
        assert_eq!(ed2k_file_type_search_term("scan.png"), Some("Image"));
        assert_eq!(ed2k_file_type_search_term("manual.pdf"), Some("Doc"));
        assert_eq!(
            ed2k_file_type_search_term("bundle.emulecollection"),
            Some("EmuleCollection")
        );
        assert_eq!(ed2k_file_type_search_term("README"), None);
    }

    #[test]
    fn synthetic_publish_aich_hash_is_stable_for_same_file_identity() {
        let file_hash = Ed2kHash::from_bytes([0xAB; 16]);
        let first = synthetic_publish_aich_hash(&file_hash, "ubuntu.iso", 734_003_200);
        let second = synthetic_publish_aich_hash(&file_hash, "ubuntu.iso", 734_003_200);
        assert_eq!(first, second);
        assert_eq!(first.len(), 20);
    }

    #[test]
    fn synthetic_publish_aich_hash_changes_when_file_identity_changes() {
        let file_hash = Ed2kHash::from_bytes([0xAB; 16]);
        let first = synthetic_publish_aich_hash(&file_hash, "ubuntu.iso", 734_003_200);
        let second = synthetic_publish_aich_hash(&file_hash, "ubuntu.iso", 734_003_201);
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn bound_ed2k_listener_is_treated_as_tcp_open() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ed2k_server_state = Arc::new(RwLock::new(Ed2kServerState::default()));

        assert!(!current_tcp_firewalled(&listener, &ed2k_server_state).await);
    }

    #[tokio::test]
    async fn low_id_server_verdict_marks_tcp_as_firewalled() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ed2k_server_state = Arc::new(RwLock::new(Ed2kServerState {
            client_id: Some(0x0000_2222),
            ..Ed2kServerState::default()
        }));

        assert!(current_tcp_firewalled(&listener, &ed2k_server_state).await);
    }

    #[tokio::test]
    async fn hello_response_uses_oracle_hello_shape() {
        let dht = DhtNode::new(DhtConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            node_id: NodeId::from_bytes([0x33; 16]),
            udp_key: 0x1122_3344,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ed2k_server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));

        let hello = build_hello_response(&dht, &listener, &ed2k_server_state, &kad_firewall, true)
            .await
            .unwrap();

        assert_eq!(hello.node_id, dht.own_id());
        assert!(hello.tags.iter().any(|tag| matches!(
            (&tag.name, &tag.value),
            (TagName::Short(name), TagValue::U16(_))
                if *name == tag_name::SOURCEUPORT
        )));
    }

    #[tokio::test]
    async fn hello_request_uses_oracle_hello_shape() {
        let dht = DhtNode::new(DhtConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            node_id: NodeId::from_bytes([0x44; 16]),
            udp_key: 0x5566_7788,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ed2k_server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));

        let hello = build_hello_request(&dht, &listener, &ed2k_server_state, &kad_firewall, true)
            .await
            .unwrap();

        assert_eq!(hello.node_id, dht.own_id());
        assert!(hello.tags.iter().any(|tag| matches!(
            (&tag.name, &tag.value),
            (TagName::Short(name), TagValue::U8(bits))
                if *name == tag_name::KADMISCOPTIONS && (*bits & 0x04) != 0
        )));
    }
}
