use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use chrono::Utc;
use overlord_agent_common::{AgentActivityState, PublishSeedSource};
use overlord_kad_dht::RpcWorkClass;
use tracing::{debug, warn};

use crate::config::EmuleAgentConfig;

use super::activity::{
    ACTIVITY_KEY_BOOTSTRAPPING, begin_agent_activity, clear_agent_degraded_activity,
    finish_agent_activity, new_activity_snapshot, update_agent_activity_error,
};
use super::lifecycle::persist_nodes_dat_for;
use super::publish::{
    SYNTHETIC_POPULAR_SEEDS, SourcePublishSettings, next_synthetic_publish_batch,
    set_synthetic_publish_queue_depth, source_publish_client_hash, synthetic_publish_queue_depth,
};
use super::publish_runtime::{
    PublishExecutionContext, fetch_coordinator_popular_hashes,
    seed_coordinator_popular_if_available, seed_popular_with_activity,
};
use super::{AgentNetworkRuntime, BOOTSTRAP_RETRY_SECS, OverlordAgentEmule};

impl OverlordAgentEmule {
    pub(super) async fn spawn_bootstrap_publish_task(
        &self,
        runtime: &AgentNetworkRuntime,
        config: &EmuleAgentConfig,
    ) {
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
    }

    pub(super) async fn spawn_periodic_publish_tasks(
        &self,
        runtime: &AgentNetworkRuntime,
        config: &EmuleAgentConfig,
    ) {
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
        let publish_contact_fanout = config.p2p.kad.publish_contact_fanout;
        let synthetic_publish_interval_secs = config.p2p.kad.synthetic_publish_interval_secs;
        let synthetic_publish_batch_items = config.p2p.kad.synthetic_publish_batch_items;
        let synthetic_publish_contact_fanout = config.p2p.kad.synthetic_publish_contact_fanout;
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
