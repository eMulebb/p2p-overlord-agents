use std::{future::Future, net::IpAddr, str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use chrono::Utc;
use overlord_agent_common::{
    AgentActivityState, CoordinatorClient, HashType, KadPublishObservability, PopularHash,
    PublishSeedSource,
};
use overlord_kad_dht::{DhtNode, PublishAttemptStats, RpcWorkClass};
use overlord_kad_proto::{Ed2kHash, NodeId, Tag};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::{
    activity::{
        AgentActivityTracker, begin_agent_activity, clear_agent_degraded_activity,
        finish_agent_activity, new_activity_snapshot, publish_activity_key,
        record_agent_degraded_activity, update_agent_activity_progress,
    },
    keyword_target,
    publish::{
        SourcePublishSettings, build_notes_publish_tags, build_source_publish_tags,
        ed2k_file_type_search_term, record_publish_summaries, refresh_ed2k_shared_catalog,
        synthetic_publish_aich_hash, update_publish_progress,
    },
};
use crate::{ed2k_transfer::Ed2kSharedCatalog, kad_store::KadLocalStore};

/// Shared publish-side dependencies that need to flow into both startup and
/// manual seed runs.
///
/// The seed loop owns the operator-visible publishing state, so these handles
/// are threaded through the helper instead of being reconstructed ad hoc.
#[derive(Clone, Copy)]
pub(super) struct PublishExecutionContext<'a> {
    pub(super) local_store: &'a Arc<Mutex<KadLocalStore>>,
    pub(super) publish_batch_gate: &'a Arc<Mutex<()>>,
    pub(super) publish_observability: &'a Arc<Mutex<KadPublishObservability>>,
    pub(super) agent_activity: &'a Arc<Mutex<AgentActivityTracker>>,
    pub(super) activity_key: Option<&'a str>,
    pub(super) notes_publish_enabled: bool,
    pub(super) work_class: RpcWorkClass,
    pub(super) publish_contact_fanout: usize,
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

pub(super) async fn fetch_coordinator_popular_hashes(
    coordinator: &CoordinatorClient,
) -> Result<Option<Vec<PopularHash>>> {
    let hashes = coordinator.popular_hashes().await?;
    Ok((!hashes.is_empty()).then_some(hashes))
}

/// Publishes one seeding batch and logs which source produced it.
pub(super) async fn seed_popular_from_source(
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

pub(super) async fn seed_popular_with_activity(
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

pub(super) async fn seed_coordinator_popular_if_available(
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
                bind_addr.port(),
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
            if let IpAddr::V4(notes_ip) = bind_addr.ip() {
                let mut store = context.local_store.lock().await;
                store.record_notes_publish(
                    NodeId::from_be_bytes(file_hash.0),
                    notes_publish_identity,
                    notes_ip,
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
