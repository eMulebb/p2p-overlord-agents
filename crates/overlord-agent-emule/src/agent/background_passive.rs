use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use overlord_agent_common::{
    AgentActivitySnapshot, AgentActivityState, CoordinatorClient, HarvestFamily,
    HarvestReplayContext, HarvestReplayRecord, KadHarvestObservability,
};
use overlord_kad_dht::DhtNode;
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{config::EmuleAgentConfig, snoop_queue::SnoopQueue};

use super::activity::{
    AgentActivityTracker, begin_agent_activity, clear_agent_degraded_activity,
    finish_agent_activity, new_activity_snapshot, passive_replay_activity_context,
    passive_replay_key, record_agent_degraded_activity,
};
use super::passive_replay::{
    PassiveReplaySelection, next_passive_replay_request, next_passive_replay_request_for_family,
    record_passive_replay_complete, record_passive_replay_idle_for_worker,
    record_passive_replay_outcome, record_passive_replay_start, try_acquire_passive_replay_gate,
};
use super::passive_runtime::{
    PassiveReplayContext, PassiveReplayRunOutcome, run_passive_keyword_replay,
    run_passive_notes_replay, run_passive_source_replay,
};
use super::{
    AgentNetworkRuntime, OverlordAgentEmule, PASSIVE_GENERAL_CRAWL_SECS, PASSIVE_SOURCE_CRAWL_SECS,
};

#[derive(Clone)]
struct PassiveReplayTaskHandles {
    coordinator: CoordinatorClient,
    dht: DhtNode,
    snoop_queue: Arc<Mutex<SnoopQueue>>,
    indexer_id: Uuid,
    passive_result_count: Arc<AtomicU64>,
    passive_replay_gate: Arc<Semaphore>,
    harvest_observability: Arc<Mutex<KadHarvestObservability>>,
    agent_activity: Arc<Mutex<AgentActivityTracker>>,
    passive_replay_phase2_fanout: usize,
    passive_source_stop_after_results: usize,
}

impl OverlordAgentEmule {
    pub(super) async fn spawn_passive_replay_tasks(
        &self,
        runtime: &AgentNetworkRuntime,
        config: &EmuleAgentConfig,
    ) {
        let handles = PassiveReplayTaskHandles {
            coordinator: self.coordinator.clone(),
            dht: runtime.dht.clone(),
            snoop_queue: Arc::clone(&self.snoop_queue),
            indexer_id: self.indexer_id,
            passive_result_count: Arc::clone(&runtime.passive_result_count),
            passive_replay_gate: Arc::clone(&runtime.passive_replay_gate),
            harvest_observability: Arc::clone(&self.harvest_observability),
            agent_activity: Arc::clone(&self.agent_activity),
            passive_replay_phase2_fanout: config.p2p.kad.search_phase2_fanout,
            passive_source_stop_after_results: config.p2p.snoop_queue.source_stop_after_results,
        };

        let source_handles = handles.clone();
        let source_shutdown = Arc::clone(&runtime.shutdown);
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !source_shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(PASSIVE_SOURCE_CRAWL_SECS)).await;
                if source_shutdown.load(Ordering::Relaxed) || !source_handles.dht.is_bootstrapped()
                {
                    continue;
                }
                let Some(_replay_permit) = try_acquire_passive_replay_gate(
                    &source_handles.passive_replay_gate,
                    "source-fast-path",
                ) else {
                    continue;
                };
                let Some(selected_request) = next_passive_replay_request_for_family(
                    &source_handles.snoop_queue,
                    HarvestFamily::Source,
                )
                .await
                else {
                    record_passive_replay_idle_for_worker(
                        &source_handles.harvest_observability,
                        Some(HarvestFamily::Source),
                        Utc::now(),
                    )
                    .await;
                    continue;
                };
                run_selected_passive_replay(&source_handles, selected_request).await;
            }
        }));

        let general_handles = handles;
        let general_shutdown = Arc::clone(&runtime.shutdown);
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !general_shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(PASSIVE_GENERAL_CRAWL_SECS)).await;
                if general_shutdown.load(Ordering::Relaxed)
                    || !general_handles.dht.is_bootstrapped()
                {
                    continue;
                }
                let Some(_replay_permit) = try_acquire_passive_replay_gate(
                    &general_handles.passive_replay_gate,
                    "general",
                ) else {
                    continue;
                };
                let Some(selected_request) =
                    next_passive_replay_request(&general_handles.snoop_queue).await
                else {
                    record_passive_replay_idle_for_worker(
                        &general_handles.harvest_observability,
                        None,
                        Utc::now(),
                    )
                    .await;
                    continue;
                };
                run_selected_passive_replay(&general_handles, selected_request).await;
            }
        }));
    }
}

async fn run_selected_passive_replay(
    handles: &PassiveReplayTaskHandles,
    selected_request: PassiveReplaySelection,
) {
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
            let (activity_key, activity_snapshot) = begin_passive_replay(
                handles,
                &replay_context,
                replay_started_at,
                Some(request.start_position),
                Some(request.restrictive_payload.len() as u32),
            )
            .await;
            info!(
                "kad passive replay start target={} start_position={} restrictive_bytes={}",
                request.target,
                request.start_position,
                request.restrictive_payload.len()
            );
            let outcome = run_passive_keyword_replay(
                passive_runtime_context(handles, &replay_context),
                &request,
            )
            .await;
            finish_passive_replay(
                handles,
                &replay_context,
                replay_started_at,
                activity_key,
                activity_snapshot,
                outcome,
            )
            .await;
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
            let (activity_key, activity_snapshot) = begin_passive_replay(
                handles,
                &replay_context,
                replay_started_at,
                Some(request.start_position),
                None,
            )
            .await;
            debug!(
                "kad passive source replay start target={} start_position={} size={}",
                request.target, request.start_position, request.size
            );
            let outcome = run_passive_source_replay(
                passive_runtime_context(handles, &replay_context),
                &request,
            )
            .await;
            finish_passive_replay(
                handles,
                &replay_context,
                replay_started_at,
                activity_key,
                activity_snapshot,
                outcome,
            )
            .await;
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
            let (activity_key, activity_snapshot) =
                begin_passive_replay(handles, &replay_context, replay_started_at, None, None).await;
            info!(
                "kad passive notes replay start target={} size={}",
                request.target, request.size
            );
            let outcome = run_passive_notes_replay(
                passive_runtime_context(handles, &replay_context),
                &request,
            )
            .await;
            finish_passive_replay(
                handles,
                &replay_context,
                replay_started_at,
                activity_key,
                activity_snapshot,
                outcome,
            )
            .await;
        }
    }
}

async fn begin_passive_replay(
    handles: &PassiveReplayTaskHandles,
    replay_context: &HarvestReplayContext,
    replay_started_at: DateTime<Utc>,
    start_position: Option<u16>,
    restrictive_payload_bytes: Option<u32>,
) -> (String, AgentActivitySnapshot) {
    let activity_key = passive_replay_key(replay_context.replay_id);
    let mut activity_snapshot =
        new_activity_snapshot(AgentActivityState::PassiveHarvestReplay, replay_started_at);
    activity_snapshot.query_or_target = Some(passive_replay_activity_context(
        replay_context.family,
        replay_context.target.as_str(),
    ));
    begin_agent_activity(
        &handles.agent_activity,
        activity_key.clone(),
        activity_snapshot.clone(),
    )
    .await;
    {
        let mut observability = handles.harvest_observability.lock().await;
        record_passive_replay_start(
            &mut observability,
            replay_context.family,
            replay_context.target.clone(),
            start_position,
            restrictive_payload_bytes,
            replay_started_at,
        );
    }
    (activity_key, activity_snapshot)
}

async fn finish_passive_replay(
    handles: &PassiveReplayTaskHandles,
    replay_context: &HarvestReplayContext,
    replay_started_at: DateTime<Utc>,
    activity_key: String,
    mut activity_snapshot: AgentActivitySnapshot,
    outcome: PassiveReplayRunOutcome,
) {
    let replay_completed_at = Utc::now();
    record_passive_replay_outcome(
        &handles.snoop_queue,
        &replay_context.logical_key,
        replay_completed_at,
        outcome.result_count,
    )
    .await;
    {
        let mut observability = handles.harvest_observability.lock().await;
        record_passive_replay_complete(
            &mut observability,
            replay_context.family,
            replay_completed_at,
            outcome.result_count,
            outcome.batch_count,
            outcome.tier_summaries.clone(),
        );
    }
    if let Err(error) = handles
        .coordinator
        .post_harvest_replay(&HarvestReplayRecord {
            replay_id: replay_context.replay_id,
            indexer_id: handles.indexer_id,
            family: replay_context.family,
            logical_key: replay_context.logical_key.clone(),
            target: replay_context.target.clone(),
            start_position: replay_context.start_position,
            size: replay_context.size,
            restrictive_payload_hex: replay_context.restrictive_payload_hex.clone(),
            started_at: replay_started_at,
            completed_at: replay_completed_at,
            result_count: outcome.result_count as u32,
            batch_count: outcome.batch_count as u32,
            error: outcome.last_post_error.clone(),
        })
        .await
    {
        debug!(
            "failed to post {:?} harvest replay summary: {error}",
            replay_context.family
        );
    }
    info!(
        "kad passive {:?} replay done results={} batches_posted={}",
        replay_context.family, outcome.result_count, outcome.batch_count
    );
    finish_agent_activity(&handles.agent_activity, &activity_key, Utc::now()).await;
    if let Some(error) = outcome.last_post_error {
        activity_snapshot.last_error = Some(error);
        activity_snapshot.last_update_at = Utc::now();
        record_agent_degraded_activity(&handles.agent_activity, activity_snapshot).await;
    } else {
        clear_agent_degraded_activity(&handles.agent_activity).await;
    }
}

fn passive_runtime_context<'a>(
    handles: &'a PassiveReplayTaskHandles,
    replay_context: &'a HarvestReplayContext,
) -> PassiveReplayContext<'a> {
    PassiveReplayContext {
        dht: &handles.dht,
        coordinator: &handles.coordinator,
        indexer_id: handles.indexer_id,
        replay_context,
        max_phase2_fanout: handles.passive_replay_phase2_fanout,
        source_stop_after_results: handles.passive_source_stop_after_results,
        passive_result_count: &handles.passive_result_count,
        harvest_observability: &handles.harvest_observability,
    }
}
