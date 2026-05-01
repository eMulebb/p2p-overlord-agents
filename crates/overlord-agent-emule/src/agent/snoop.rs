use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use chrono::Utc;
use overlord_agent_common::{
    CoordinatorClient, HarvestFamily, KadHarvestObservability, SnoopEntry, SnoopObservation,
};
use overlord_kad_proto::{SearchKeyReq, SearchNotesReq, SearchSourceReq};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::snoop_queue::SnoopQueue;

use super::passive_replay::apply_harvest_record;

pub(super) async fn restore_snoop_queue(
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

pub(super) async fn flush_snoop_queue(
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

pub(super) fn keyword_logical_key(req: &SearchKeyReq) -> String {
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

pub(super) fn source_logical_key(req: &SearchSourceReq) -> String {
    format!(
        "source:{}:{:04x}:{}",
        req.target, req.start_position, req.size
    )
}

pub(super) fn notes_logical_key(req: &SearchNotesReq) -> String {
    format!("notes:{}:{}", req.target, req.size)
}

pub(super) fn build_keyword_snoop_entry(
    req: &SearchKeyReq,
    now: chrono::DateTime<Utc>,
) -> SnoopEntry {
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

pub(super) fn build_source_snoop_entry(
    req: &SearchSourceReq,
    now: chrono::DateTime<Utc>,
) -> SnoopEntry {
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

pub(super) fn build_notes_snoop_entry(
    req: &SearchNotesReq,
    now: chrono::DateTime<Utc>,
) -> SnoopEntry {
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

pub(super) async fn record_snoop_entry(
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
        debug!(
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
