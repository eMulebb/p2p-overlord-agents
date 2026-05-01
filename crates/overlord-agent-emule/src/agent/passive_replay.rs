use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use overlord_agent_common::{
    HarvestFamily, KadHarvestFamilyObservability, KadHarvestObservability,
    KadPassiveReplayObservability, KadPassiveReplayTierSummary, SnoopEntry,
};
use overlord_kad_proto::{SearchKeyReq, SearchNotesReq, SearchSourceReq, constants::K};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tracing::debug;

use super::{
    PASSIVE_KEYWORD_THIN_RESULT_THRESHOLD, PASSIVE_NOTES_THIN_RESULT_THRESHOLD,
    PASSIVE_SOURCE_THIN_RESULT_THRESHOLD,
};
use crate::snoop_queue::{ScheduledSnoopRequest, SnoopQueue, SnoopQueueFamilyCounts};

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

pub(super) fn apply_harvest_record(
    observability: &mut KadHarvestObservability,
    from: std::net::SocketAddr,
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

pub(super) fn apply_queue_family_counts(
    observability: &mut KadHarvestObservability,
    counts: SnoopQueueFamilyCounts,
) {
    observability.keyword_requests.queued_entries = counts.keyword as u32;
    observability.source_requests.queued_entries = counts.source as u32;
    observability.notes_requests.queued_entries = counts.notes as u32;
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

pub(super) fn passive_replay_tier_contact_limits(max_phase2_fanout: usize) -> Vec<usize> {
    let mut tiers = vec![K, K.saturating_mul(2), max_phase2_fanout];
    tiers.retain(|limit| *limit > 0);
    tiers.sort_unstable();
    tiers.dedup();
    tiers
}

pub(super) fn passive_replay_thin_result_threshold(family: HarvestFamily) -> usize {
    match family {
        HarvestFamily::Keyword => PASSIVE_KEYWORD_THIN_RESULT_THRESHOLD,
        HarvestFamily::Source => PASSIVE_SOURCE_THIN_RESULT_THRESHOLD,
        HarvestFamily::Notes => PASSIVE_NOTES_THIN_RESULT_THRESHOLD,
    }
}

pub(super) fn record_passive_replay_idle(
    observability: &mut KadHarvestObservability,
    family: HarvestFamily,
    observed_at: DateTime<Utc>,
) {
    let replay = passive_replay_observability_mut(observability, family);
    replay.idle_cycles += 1;
    replay.last_idle_at = Some(observed_at);
}

pub(super) fn record_passive_replay_start(
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

pub(super) fn record_passive_replay_complete(
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

pub(super) fn record_passive_replay_enqueue_wait(
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

pub(super) fn record_passive_replay_post_latency(
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

pub(super) fn record_passive_replay_post_failure(
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

#[derive(Debug)]
pub(super) enum PassiveReplaySelection {
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

pub(super) async fn next_passive_replay_request(
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
) -> Option<PassiveReplaySelection> {
    next_passive_replay_request_with_preference(snoop_queue, None).await
}

pub(super) async fn next_passive_replay_request_for_family(
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

pub(super) async fn record_passive_replay_outcome(
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
pub(super) fn try_acquire_passive_replay_gate(
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

pub(super) async fn record_passive_replay_idle_for_worker(
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
