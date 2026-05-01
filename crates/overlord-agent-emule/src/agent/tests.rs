use super::test_support::*;
use crate::{
    config::SnoopQueueConfig,
    ed2k_server::{Ed2kFoundSource, Ed2kSearchFile, Ed2kServerState},
    ed2k_tcp::{
        Ed2kHelloIdentity, Ed2kPeerDownloadOutcome, Ed2kSecureIdent, emule_connect_options,
    },
    ed2k_transfer::{Ed2kTransferRuntime, Ed2kTransferState, new_transfer_job},
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
    KadPublishObservability, Protocol, PublishCounters, PublishSeedSource, RegisterRequest,
    RegistrationResponse, SnoopEntry,
};
use overlord_agent_nat::{
    AgentInterface, InterfaceAddressFamily, UPNP_MINIUPNPC_BACKEND, UPNP_RUPNP_BACKEND,
};
use overlord_kad_dht::{DhtConfig, DhtNode, PublishAttemptStats, SearchResult, SourceResult};
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

mod downloads;
mod kad_runtime;
mod networking;
mod passive_replay;
mod publish;
mod runtime;
mod search;
mod snoop;
