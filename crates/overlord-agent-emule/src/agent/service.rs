use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{Ordering, Ordering as AtomicOrdering},
    },
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use overlord_agent_common::{
    AgentActivityState, ConfigUpdate, CoordinatorClient, IndexerService, IndexerStats, PopularHash,
    Protocol, PublishSeedSource, SearchEventStatus, SearchJob, SearchKind, SnoopEntry,
};
use overlord_agent_nat::{AgentNetworkReport, AgentNetworkingConfig};
use overlord_kad_dht::RpcWorkClass;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use uuid::Uuid;

use crate::{ed2k_transfer::Ed2kLocalIngestSummary, logging::current_log_file_status};

use super::{
    activity::{
        ACTIVITY_KEY_RECONFIGURING, ACTIVITY_KEY_STARTING, active_search_key, begin_agent_activity,
        clear_agent_degraded_activity, finish_agent_activity, new_activity_snapshot,
        publish_activity_key, record_agent_degraded_activity, runtime_activity_error,
        search_activity_context,
    },
    ed2k_enrich::{EnrichEd2kDownloadRequest, IngestLocalFileRequest},
    ed2k_search::{
        ActiveEd2kSearchContext, do_active_ed2k_keyword_search, do_active_ed2k_source_search,
    },
    passive_replay::apply_queue_family_counts,
    publish::{SourcePublishSettings, effective_publish_counters, source_publish_client_hash},
    publish_runtime::{PublishExecutionContext, seed_popular_from_source},
    rpc_observability::map_rpc_observability,
    runtime_state::{ActiveSearchHandle, NetworkingConfigApplyOutcome, OverlordAgentEmule},
    search::{
        SearchRunStats, do_active_keyword_search, do_active_notes_search, do_active_source_search,
        emit_search_event, notes_result_protocol,
    },
    snoop::{flush_snoop_queue, restore_snoop_queue},
};

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
        if self.started.swap(true, AtomicOrdering::SeqCst) {
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
                    do_active_notes_search(
                        &dht,
                        indexer_id,
                        &job,
                        notes_result_protocol(job.protocol),
                        cancel.clone(),
                    )
                    .await
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
                    do_active_notes_search(
                        &dht,
                        indexer_id,
                        &job,
                        notes_result_protocol(job.protocol),
                        cancel.clone(),
                    )
                    .await
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
}
