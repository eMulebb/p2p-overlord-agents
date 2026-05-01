use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use chrono::Utc;
use overlord_agent_common::AgentActivityState;
use tracing::debug;

use super::activity::{
    ACTIVITY_KEY_FLUSHING_SNOOPS, begin_agent_activity, clear_agent_degraded_activity,
    finish_agent_activity, new_activity_snapshot, record_agent_degraded_activity,
    update_agent_activity_error,
};
use super::snoop::flush_snoop_queue;
use super::{AgentNetworkRuntime, OverlordAgentEmule, SNOOP_FLUSH_SECS};

impl OverlordAgentEmule {
    pub(super) async fn spawn_snoop_flush_task(&self, runtime: &AgentNetworkRuntime) {
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
    }
}
