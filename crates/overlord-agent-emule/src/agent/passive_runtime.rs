use std::{
    collections::HashSet,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use anyhow::Result;
use chrono::Utc;
use overlord_agent_common::{
    CoordinatorClient, FileRecord, HarvestFamily, HarvestReplayContext, KadHarvestObservability,
    KadPassiveReplayTierSummary, Protocol, ResultBatch,
};
use overlord_kad_dht::{DhtNode, RpcWorkClass};
use overlord_kad_proto::{Ed2kHash, SearchKeyReq, SearchNotesReq, SearchSourceReq};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::{
    PASSIVE_BATCH_FLUSH_INTERVAL_MS, PASSIVE_BATCH_SIZE, PASSIVE_POST_QUEUE_DEPTH,
    passive_replay::{
        passive_replay_thin_result_threshold, passive_replay_tier_contact_limits,
        record_passive_replay_enqueue_wait, record_passive_replay_post_failure,
        record_passive_replay_post_latency,
    },
    search::{map_note_result, map_search_result_for, map_source_result},
};

#[derive(Debug, Default)]
pub(super) struct PassiveReplayRunOutcome {
    pub(super) result_count: usize,
    pub(super) batch_count: usize,
    pub(super) tier_summaries: Vec<KadPassiveReplayTierSummary>,
    pub(super) last_post_error: Option<String>,
}

pub(super) struct PassiveReplayContext<'a> {
    pub(super) dht: &'a DhtNode,
    pub(super) coordinator: &'a CoordinatorClient,
    pub(super) indexer_id: Uuid,
    pub(super) replay_context: &'a HarvestReplayContext,
    pub(super) max_phase2_fanout: usize,
    pub(super) source_stop_after_results: usize,
    pub(super) passive_result_count: &'a Arc<std::sync::atomic::AtomicU64>,
    pub(super) harvest_observability: &'a Arc<Mutex<KadHarvestObservability>>,
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

pub(super) async fn run_passive_keyword_replay(
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

pub(super) async fn run_passive_source_replay(
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

pub(super) async fn run_passive_notes_replay(
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
