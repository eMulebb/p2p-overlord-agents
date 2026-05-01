use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, Utc};
use overlord_agent_common::{
    AgentActivitySnapshot, AgentActivityState, HarvestFamily, PublishSeedSource, SearchJob,
    SearchKind,
};
use overlord_agent_nat::{AgentNetworkReport, NatStatusSnapshot};
use tokio::sync::Mutex;
use uuid::Uuid;

pub(super) const ACTIVITY_KEY_STARTING: &str = "starting";
pub(super) const ACTIVITY_KEY_BOOTSTRAPPING: &str = "bootstrapping";
pub(super) const ACTIVITY_KEY_FLUSHING_SNOOPS: &str = "flushing_snoops";
pub(super) const ACTIVITY_KEY_RECONFIGURING: &str = "reconfiguring";

/// Small in-memory tracker that resolves overlapping runtime work into one operator-facing
/// activity snapshot using a fixed precedence order.
#[derive(Debug, Clone)]
pub(super) struct AgentActivityTracker {
    active: HashMap<String, AgentActivitySnapshot>,
    degraded: Option<AgentActivitySnapshot>,
    idle_since: DateTime<Utc>,
}

impl AgentActivityTracker {
    pub(super) fn new(now: DateTime<Utc>) -> Self {
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

    pub(super) fn current_snapshot(
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

pub(super) fn new_activity_snapshot(
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

pub(super) fn active_search_key(job_id: Uuid) -> String {
    format!("active_search:{job_id}")
}

pub(super) fn active_ed2k_download_key(file_hash: &str) -> String {
    format!("ed2k_download:{file_hash}")
}

pub(super) fn passive_replay_key(replay_id: Uuid) -> String {
    format!("passive_replay:{replay_id}")
}

pub(super) fn publish_activity_key(
    seed_source: PublishSeedSource,
    observed_at: DateTime<Utc>,
) -> String {
    format!(
        "publishing:{}:{}",
        seed_source.label(),
        observed_at.timestamp_millis()
    )
}

pub(super) fn search_activity_context(job: &SearchJob) -> Option<String> {
    match job.kind {
        SearchKind::Keyword => job.query.clone(),
        SearchKind::Source | SearchKind::Notes => job
            .file_hash
            .as_ref()
            .map(|hash| format!("{:?}", hash))
            .or_else(|| job.file_size.map(|size| format!("size={size}"))),
    }
}

pub(super) fn passive_replay_activity_context(family: HarvestFamily, target: &str) -> String {
    format!("{family:?} {target}")
}

pub(super) fn runtime_activity_error(
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

pub(super) async fn begin_agent_activity(
    tracker: &Arc<Mutex<AgentActivityTracker>>,
    key: String,
    snapshot: AgentActivitySnapshot,
) {
    tracker.lock().await.enter(key, snapshot);
}

pub(super) async fn finish_agent_activity(
    tracker: &Arc<Mutex<AgentActivityTracker>>,
    key: &str,
    observed_at: DateTime<Utc>,
) {
    tracker.lock().await.leave(key, observed_at);
}

pub(super) async fn update_agent_activity_progress(
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

pub(super) async fn update_agent_activity_error(
    tracker: &Arc<Mutex<AgentActivityTracker>>,
    key: &str,
    error: String,
    observed_at: DateTime<Utc>,
) {
    tracker.lock().await.update_error(key, error, observed_at);
}

pub(super) async fn record_agent_degraded_activity(
    tracker: &Arc<Mutex<AgentActivityTracker>>,
    snapshot: AgentActivitySnapshot,
) {
    tracker.lock().await.record_degraded(snapshot);
}

pub(super) async fn clear_agent_degraded_activity(tracker: &Arc<Mutex<AgentActivityTracker>>) {
    tracker.lock().await.clear_degraded();
}
