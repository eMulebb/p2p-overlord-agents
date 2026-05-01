use super::{
    COORDINATOR_RECONNECT_SECS, EMULE_LARGE_FILE_SIZE_THRESHOLD, EmuleAgentConfig,
    EnrichEd2kDownloadRequest, EnrichEd2kDownloadSource, NativeDirectDownloadOptions,
    OverlordAgentEmule, PASSIVE_REPLAY_CONCURRENCY, PassiveReplaySelection,
    SYNTHETIC_POPULAR_SEEDS, SourcePublishSettings, apply_harvest_record, apply_networking_config,
    apply_publish_summary, apply_queue_family_counts, build_hello_request, build_hello_response,
    build_kad_hello_request_tags, build_kad_hello_response_tags, build_keyword_snoop_entry,
    build_notes_publish_tags, build_notes_snoop_entry, build_publish_batch_summary,
    build_source_publish_tags, build_source_snoop_entry, current_tcp_firewalled,
    direct_download_candidate_sources, ed2k_download_source_server_attempt_budget,
    ed2k_file_type_search_term, ed2k_keyword_server_attempt_budget, effective_publish_counters,
    empty_networking_config, emule_high_id_source_type, exact_ed2k_hash_query_token,
    flush_snoop_queue, kad_source_result_to_ed2k_found_source, keyword_target,
    manifest_has_ed2k_transfer_progress, next_passive_replay_request,
    next_passive_replay_request_for_family, next_synthetic_publish_batch,
    normalize_ed2k_user_hash_markers, p2p_interface_reconcile_target, parse_kad_hello_metadata,
    plaintext_fallback_for_obfuscated_source, record_passive_replay_complete,
    record_passive_replay_enqueue_wait, record_passive_replay_idle,
    record_passive_replay_post_failure, record_passive_replay_post_latency,
    record_passive_replay_start, record_publish_summaries, restore_snoop_queue,
    select_ed2k_keyword_metadata, should_request_hello_response_ack,
    should_skip_no_progress_source_requery, significant_keyword_words, source_publish_client_hash,
    synthetic_file_hash, synthetic_popular_hash, synthetic_popular_hashes,
    synthetic_publish_aich_hash, synthetic_publish_queue_depth, try_acquire_passive_replay_gate,
};
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

#[tokio::test]
async fn native_direct_download_retries_other_direct_peer_after_failure() {
    let temp_root = unique_test_dir("overlord-agent-emule-direct-download-retry");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&temp_root).unwrap());
    let payload = b"captured small file payload".repeat(32);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "captured.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();
    let secure_ident =
        Arc::new(Ed2kSecureIdent::load_or_create(&temp_root.join("secure-ident.der")).unwrap());
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let payload = Arc::new(payload);
    let file_hash_hex_for_download = file_hash_hex.clone();
    let outcome = OverlordAgentEmule::run_native_ed2k_direct_downloads(
        NativeDirectDownloadOptions {
            bind_ip: Ipv4Addr::LOCALHOST,
            hello_identity: Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            secure_ident,
            transfer_runtime: Arc::clone(&transfer_runtime),
            file_hash_hex: file_hash_hex.clone(),
            file_name: "captured.epub".to_string(),
            file_size: payload.len() as u64,
            sources: vec![
                Ed2kFoundSource {
                    file_hash,
                    ip: Ipv4Addr::LOCALHOST,
                    tcp_port: 41001,
                    client_id: 1,
                    low_id: false,
                    obfuscated: false,
                    obfuscation_options: None,
                    user_hash: None,
                    source_server: None,
                },
                Ed2kFoundSource {
                    file_hash,
                    ip: Ipv4Addr::LOCALHOST,
                    tcp_port: 41002,
                    client_id: 2,
                    low_id: false,
                    obfuscated: false,
                    obfuscation_options: None,
                    user_hash: None,
                    source_server: None,
                },
            ],
            connect_timeout: Duration::from_secs(1),
            max_parallel_download_peers: 2,
        },
        {
            let attempts = Arc::clone(&attempts);
            move |_bind_ip,
                  source,
                  _hello_identity,
                  _secure_ident,
                  transfer_runtime,
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                let payload = Arc::clone(&payload);
                let file_hash_hex = file_hash_hex_for_download.clone();
                async move {
                    attempts.lock().await.push(source.tcp_port);
                    if source.tcp_port == 41001 {
                        anyhow::bail!("simulated first peer failure");
                    }
                    transfer_runtime
                        .store_md4_hashset(&file_hash_hex, Vec::new())
                        .await?;
                    transfer_runtime
                        .store_piece_data(&file_hash_hex, 0, payload.as_slice())
                        .await?;
                    Ok(Ed2kPeerDownloadOutcome::Completed)
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(outcome.completed);
    assert_eq!(outcome.accepted_incomplete_peers, 0);
    assert!(outcome.last_error.is_some());
    assert_eq!(*attempts.lock().await, vec![41001, 41002]);
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
}

#[tokio::test]
async fn native_direct_download_retries_loopback_peer_after_connection_refused() {
    let temp_root = unique_test_dir("overlord-agent-emule-loopback-refused-retry");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&temp_root).unwrap());
    let payload = b"captured small file payload".repeat(32);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "captured.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();
    let secure_ident =
        Arc::new(Ed2kSecureIdent::load_or_create(&temp_root.join("secure-ident.der")).unwrap());
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let payload = Arc::new(payload);
    let file_hash_hex_for_download = file_hash_hex.clone();
    let success_after_attempt = 3usize;
    let outcome = OverlordAgentEmule::run_native_ed2k_direct_downloads(
        NativeDirectDownloadOptions {
            bind_ip: Ipv4Addr::LOCALHOST,
            hello_identity: Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            secure_ident,
            transfer_runtime: Arc::clone(&transfer_runtime),
            file_hash_hex: file_hash_hex.clone(),
            file_name: "captured.epub".to_string(),
            file_size: payload.len() as u64,
            sources: vec![Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: 41001,
                client_id: 1,
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            }],
            connect_timeout: Duration::from_secs(1),
            max_parallel_download_peers: 1,
        },
        {
            let attempts = Arc::clone(&attempts);
            move |_bind_ip,
                  source,
                  _hello_identity,
                  _secure_ident,
                  transfer_runtime,
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                let payload = Arc::clone(&payload);
                let file_hash_hex = file_hash_hex_for_download.clone();
                async move {
                    attempts.lock().await.push(source.tcp_port);
                    let attempt_count = attempts.lock().await.len();
                    if attempt_count < success_after_attempt {
                        return Err(anyhow::anyhow!(std::io::Error::from(
                            std::io::ErrorKind::ConnectionRefused
                        )));
                    }
                    transfer_runtime
                        .store_md4_hashset(&file_hash_hex, Vec::new())
                        .await?;
                    transfer_runtime
                        .store_piece_data(&file_hash_hex, 0, payload.as_slice())
                        .await?;
                    Ok(Ed2kPeerDownloadOutcome::Completed)
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(outcome.completed);
    assert_eq!(outcome.accepted_incomplete_peers, 0);
    assert!(outcome.last_error.is_some());
    assert_eq!(*attempts.lock().await, vec![41001, 41001, 41001]);
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
}

#[tokio::test]
async fn native_direct_download_tries_plaintext_after_optional_obfuscated_failure() {
    let temp_root = unique_test_dir("overlord-agent-emule-obfuscated-plaintext-fallback");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&temp_root).unwrap());
    let payload = b"captured small file payload".repeat(32);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "captured.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();
    let secure_ident =
        Arc::new(Ed2kSecureIdent::load_or_create(&temp_root.join("secure-ident.der")).unwrap());
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let payload = Arc::new(payload);
    let file_hash_hex_for_download = file_hash_hex.clone();
    let outcome = OverlordAgentEmule::run_native_ed2k_direct_downloads(
        NativeDirectDownloadOptions {
            bind_ip: Ipv4Addr::LOCALHOST,
            hello_identity: Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(true),
                direct_udp_callback: false,
            },
            secure_ident,
            transfer_runtime: Arc::clone(&transfer_runtime),
            file_hash_hex: file_hash_hex.clone(),
            file_name: "captured.epub".to_string(),
            file_size: payload.len() as u64,
            sources: vec![Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: 41001,
                client_id: 1,
                low_id: false,
                obfuscated: true,
                obfuscation_options: Some(0x83),
                user_hash: Some([0x22; 16]),
                source_server: None,
            }],
            connect_timeout: Duration::from_secs(1),
            max_parallel_download_peers: 1,
        },
        {
            let attempts = Arc::clone(&attempts);
            move |_bind_ip,
                  source,
                  _hello_identity,
                  _secure_ident,
                  transfer_runtime,
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                let payload = Arc::clone(&payload);
                let file_hash_hex = file_hash_hex_for_download.clone();
                async move {
                    attempts.lock().await.push((
                        source.tcp_port,
                        source.obfuscated,
                        source.user_hash.is_some(),
                    ));
                    if source.obfuscated {
                        anyhow::bail!("simulated obfuscated peer close");
                    }
                    transfer_runtime
                        .store_md4_hashset(&file_hash_hex, Vec::new())
                        .await?;
                    transfer_runtime
                        .store_piece_data(&file_hash_hex, 0, payload.as_slice())
                        .await?;
                    Ok(Ed2kPeerDownloadOutcome::Completed)
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(outcome.completed);
    assert_eq!(
        *attempts.lock().await,
        vec![(41001, true, true), (41001, false, false)]
    );
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
}

#[test]
fn plaintext_fallback_preserves_crypt_required_sources() {
    let file_hash = Ed2kHash::from_bytes([0x33; 16]);
    let source = Ed2kFoundSource {
        file_hash,
        ip: Ipv4Addr::LOCALHOST,
        tcp_port: 41001,
        client_id: 1,
        low_id: false,
        obfuscated: true,
        obfuscation_options: Some(0x87),
        user_hash: Some([0x22; 16]),
        source_server: None,
    };

    assert!(plaintext_fallback_for_obfuscated_source(&source).is_none());
}

#[test]
fn direct_download_candidates_exhaust_endpoint_family_after_attempt() {
    let file_hash = Ed2kHash::from_bytes([0x44; 16]);
    let mut attempted_endpoints = HashSet::new();
    attempted_endpoints.insert((Ipv4Addr::new(10, 0, 0, 1), 41001));
    let sources = vec![
        Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::new(10, 0, 0, 1),
            tcp_port: 41001,
            client_id: 1,
            low_id: false,
            obfuscated: true,
            obfuscation_options: Some(0x83),
            user_hash: Some([0x11; 16]),
            source_server: None,
        },
        Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::new(10, 0, 0, 1),
            tcp_port: 41001,
            client_id: 2,
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
        },
        Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::new(10, 0, 0, 2),
            tcp_port: 41001,
            client_id: 3,
            low_id: false,
            obfuscated: true,
            obfuscation_options: Some(0x83),
            user_hash: Some([0x22; 16]),
            source_server: None,
        },
    ];

    let candidates = direct_download_candidate_sources(&sources, &attempted_endpoints);

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].ip, Ipv4Addr::new(10, 0, 0, 2));
}

#[test]
fn direct_download_candidates_deduplicate_same_endpoint_in_one_round() {
    let file_hash = Ed2kHash::from_bytes([0x45; 16]);
    let sources = vec![
        Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::new(10, 0, 0, 1),
            tcp_port: 41001,
            client_id: 1,
            low_id: false,
            obfuscated: true,
            obfuscation_options: Some(0x83),
            user_hash: Some([0x11; 16]),
            source_server: None,
        },
        Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::new(10, 0, 0, 1),
            tcp_port: 41001,
            client_id: 2,
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
        },
    ];

    let candidates = direct_download_candidate_sources(&sources, &HashSet::new());

    assert_eq!(candidates.len(), 1);
    assert!(candidates[0].obfuscated);
    assert!(candidates[0].user_hash.is_some());
}

#[test]
fn no_progress_source_requery_skips_exhausted_direct_endpoints() {
    assert!(should_skip_no_progress_source_requery(true, false, 0));
    assert!(!should_skip_no_progress_source_requery(true, true, 0));
    assert!(!should_skip_no_progress_source_requery(true, false, 1));
    assert!(!should_skip_no_progress_source_requery(false, false, 0));
}

#[tokio::test]
async fn native_direct_download_tracks_accepted_incomplete_peer_separately_from_failure() {
    let temp_root = unique_test_dir("overlord-agent-emule-direct-download-accepted-incomplete");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&temp_root).unwrap());
    let payload = b"captured small file payload".repeat(32);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "captured.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();
    let secure_ident =
        Arc::new(Ed2kSecureIdent::load_or_create(&temp_root.join("secure-ident.der")).unwrap());
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let payload = Arc::new(payload);
    let file_hash_hex_for_download = file_hash_hex.clone();
    let outcome = OverlordAgentEmule::run_native_ed2k_direct_downloads(
        NativeDirectDownloadOptions {
            bind_ip: Ipv4Addr::LOCALHOST,
            hello_identity: Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            secure_ident,
            transfer_runtime: Arc::clone(&transfer_runtime),
            file_hash_hex: file_hash_hex.clone(),
            file_name: "captured.epub".to_string(),
            file_size: payload.len() as u64,
            sources: vec![
                Ed2kFoundSource {
                    file_hash,
                    ip: Ipv4Addr::LOCALHOST,
                    tcp_port: 41001,
                    client_id: 1,
                    low_id: false,
                    obfuscated: false,
                    obfuscation_options: None,
                    user_hash: None,
                    source_server: None,
                },
                Ed2kFoundSource {
                    file_hash,
                    ip: Ipv4Addr::LOCALHOST,
                    tcp_port: 41002,
                    client_id: 2,
                    low_id: false,
                    obfuscated: false,
                    obfuscation_options: None,
                    user_hash: None,
                    source_server: None,
                },
            ],
            connect_timeout: Duration::from_secs(1),
            max_parallel_download_peers: 2,
        },
        {
            let attempts = Arc::clone(&attempts);
            move |_bind_ip,
                  source,
                  _hello_identity,
                  _secure_ident,
                  transfer_runtime,
                  _file_name,
                  _file_size,
                  _connect_timeout| {
                let attempts = Arc::clone(&attempts);
                let payload = Arc::clone(&payload);
                let file_hash_hex = file_hash_hex_for_download.clone();
                async move {
                    attempts.lock().await.push(source.tcp_port);
                    if source.tcp_port == 41001 {
                        return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                    }
                    transfer_runtime
                        .store_md4_hashset(&file_hash_hex, Vec::new())
                        .await?;
                    transfer_runtime
                        .store_piece_data(&file_hash_hex, 0, payload.as_slice())
                        .await?;
                    Ok(Ed2kPeerDownloadOutcome::Completed)
                }
            }
        },
    )
    .await
    .unwrap();

    assert!(outcome.completed);
    assert_eq!(outcome.accepted_incomplete_peers, 1);
    assert!(outcome.last_error.is_none());
    assert_eq!(*attempts.lock().await, vec![41001, 41002]);
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
}

#[tokio::test]
async fn spawn_native_ed2k_download_reclaims_stale_piece_requests_after_restart() {
    let temp_root = unique_test_dir("overlord-agent-emule-direct-download-resume-spawn");
    let mut config = build_test_config(&temp_root, "http://127.0.0.1:9".to_string());
    config.p2p.ed2k.listen_port = 41001;
    config.p2p.kad.listen_port = 41000;
    let agent = OverlordAgentEmule::new(config).await.unwrap();
    agent.start().await.unwrap();

    let runtime = agent.runtime.lock().await.clone().unwrap();
    let payload = b"captured partial file payload".repeat(1024);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    runtime
        .ed2k_transfer
        .ensure_job(&new_transfer_job(
            file_hash,
            "captured-resume.iso".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();
    let claimed = runtime
        .ed2k_transfer
        .claim_next_missing_part(&file_hash_hex)
        .await
        .unwrap()
        .unwrap();
    let persisted_len = 16_384usize;
    let completed = runtime
        .ed2k_transfer
        .append_piece_block(
            &file_hash_hex,
            claimed.piece_index,
            0,
            persisted_len as u64,
            &payload[..persisted_len],
        )
        .await
        .unwrap();
    assert!(!completed);
    let manifest = runtime
        .ed2k_transfer
        .manifest(&file_hash_hex)
        .await
        .unwrap();
    assert!(manifest_has_ed2k_transfer_progress(&manifest));
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Requested);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_port = listener.local_addr().unwrap().port();
    let connected = Arc::new(tokio::sync::Notify::new());
    let connected_signal = Arc::clone(&connected);
    let peer_task = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        connected_signal.notify_one();
        tokio::time::sleep(Duration::from_millis(250)).await;
    });

    agent
        .spawn_native_ed2k_download(EnrichEd2kDownloadRequest {
            kind: "ed2k_download".to_string(),
            file_hash: file_hash_hex.clone(),
            file_name: Some("captured-resume.iso".to_string()),
            file_size: Some(payload.len() as u64),
            sources: vec![EnrichEd2kDownloadSource {
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_port,
                client_id: Some(1),
                low_id: Some(false),
                obfuscation_options: None,
                user_hash: None,
            }],
        })
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(5), connected.notified())
        .await
        .unwrap();
    peer_task.await.unwrap();
    let reclaimed_manifest = runtime
        .ed2k_transfer
        .manifest(&file_hash_hex)
        .await
        .unwrap();
    assert_ne!(
        reclaimed_manifest.pieces[0].state,
        Ed2kTransferState::Verified
    );
    assert_eq!(
        reclaimed_manifest.pieces[0].bytes_written,
        persisted_len as u64
    );

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !agent
                .active_ed2k_downloads
                .lock()
                .await
                .contains(&file_hash_hex)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();

    agent.stop().await.unwrap();
    fs::remove_dir_all(&temp_root).unwrap();
}

#[test]
fn significant_words_ignore_short_tokens() {
    assert_eq!(
        significant_keyword_words("A torino x train"),
        vec!["torino".to_string(), "train".to_string()]
    );
}

#[test]
fn keyword_target_is_stable() {
    assert_eq!(
        hex::encode(keyword_target("Torino Train").0),
        "b2bc3aa39f375069e7c27eb83ce6baf3"
    );
}

#[test]
fn exact_ed2k_hash_query_token_extracts_hash_only_queries() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    assert_eq!(
        exact_ed2k_hash_query_token(&format!("ed2k::{exact_hash}")),
        Some(exact_hash.clone())
    );
    assert_eq!(
        exact_ed2k_hash_query_token(&exact_hash.to_ascii_uppercase()),
        Some(exact_hash)
    );
    assert_eq!(exact_ed2k_hash_query_token("ed2k::torino train"), None);
}

#[test]
fn keyword_target_uses_hash_token_for_exact_ed2k_hash_queries() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    assert_eq!(
        keyword_target(&format!("ed2k::{exact_hash}")),
        keyword_target(&exact_hash.to_ascii_uppercase())
    );
}

#[test]
fn exact_ed2k_hash_queries_use_configured_server_budgets() {
    let mut config = EmuleAgentConfig::default();
    config.p2p.ed2k.server_endpoints = vec![
        "1.1.1.1:4661".to_string(),
        "2.2.2.2:4661".to_string(),
        "3.3.3.3:4661".to_string(),
        "4.4.4.4:4661".to_string(),
        "5.5.5.5:4661".to_string(),
    ];
    config.p2p.ed2k.keyword_server_attempt_budget = 2;
    config.p2p.ed2k.exact_hash_keyword_server_attempt_budget = 4;
    config.p2p.ed2k.source_server_attempt_budget = 3;
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    assert_eq!(
        ed2k_keyword_server_attempt_budget(&config.p2p.ed2k, &format!("ed2k::{exact_hash}")),
        4
    );
    assert_eq!(
        ed2k_keyword_server_attempt_budget(&config.p2p.ed2k, "ubuntu linux"),
        2
    );
    assert_eq!(
        ed2k_download_source_server_attempt_budget(&config.p2p.ed2k),
        3
    );
}

#[test]
fn select_ed2k_keyword_metadata_prefers_exact_hash_with_size_and_name() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]);
    let other_hash = Ed2kHash::from_bytes([0xAA; 16]);
    let metadata = select_ed2k_keyword_metadata(
        &[
            Ed2kSearchFile {
                file_hash: exact_hash,
                file_name: Some("".to_string()),
                file_size: Some(0),
                file_type: None,
                source_count: Some(100),
            },
            Ed2kSearchFile {
                file_hash: other_hash,
                file_name: Some("wrong.bin".to_string()),
                file_size: Some(123),
                file_type: None,
                source_count: Some(5),
            },
            Ed2kSearchFile {
                file_hash: exact_hash,
                file_name: Some("resolved.bin".to_string()),
                file_size: Some(4_294_967_299),
                file_type: Some("Pro".to_string()),
                source_count: Some(12),
            },
        ],
        exact_hash,
    )
    .unwrap();

    assert_eq!(metadata.canonical_name.as_deref(), Some("resolved.bin"));
    assert_eq!(metadata.file_size, Some(4_294_967_299));
}

#[test]
fn kad_search_result_exposes_exact_hash_metadata() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]);
    let metadata = super::select_kad_keyword_metadata(
        &SearchResult {
            hash: exact_hash,
            names: vec!["resolved.bin".to_string()],
            size: Some(5_000),
            source_count: Some(3),
            tags: Vec::new(),
        },
        exact_hash,
    )
    .unwrap();

    assert_eq!(metadata.canonical_name.as_deref(), Some("resolved.bin"));
    assert_eq!(metadata.file_size, Some(5_000));
}

#[test]
fn ed2k_user_hash_uses_oracle_emule_markers() {
    let user_hash = normalize_ed2k_user_hash_markers([0xAA; 16]);

    assert_eq!(user_hash[5], 0x0E);
    assert_eq!(user_hash[14], 0x6F);
}

#[test]
fn empty_networking_config_prefers_miniupnpc_only() {
    assert_eq!(
        empty_networking_config().nat.p2p.backend_order,
        vec![UPNP_MINIUPNPC_BACKEND.to_string()]
    );
}

#[test]
fn apply_networking_config_preserves_explicit_backend_order() {
    let mut config = EmuleAgentConfig::default();
    let mut desired = empty_networking_config();
    desired.nat.p2p.backend_order = vec![UPNP_RUPNP_BACKEND.to_string()];

    apply_networking_config(&mut config, &desired);

    assert_eq!(
        config.nat.p2p.backend_order,
        vec![UPNP_RUPNP_BACKEND.to_string()]
    );
}

#[test]
fn restart_required_only_for_control_endpoint_changes() {
    let old = empty_networking_config();

    let mut nat_only = old.clone();
    nat_only.nat.p2p.enabled = true;
    nat_only.nat.p2p.backend_order = vec![UPNP_RUPNP_BACKEND.to_string()];
    assert!(!OverlordAgentEmule::restart_required_for_networking_change(
        &old, &nat_only
    ));

    let mut control_bind_ip = old.clone();
    control_bind_ip.control.bind_ip = Some("127.0.0.1".to_string());
    control_bind_ip.control.selection_confirmed = true;
    assert!(OverlordAgentEmule::restart_required_for_networking_change(
        &old,
        &control_bind_ip
    ));

    let mut control_port = old.clone();
    control_port.control.listen_port = 14_001;
    assert!(OverlordAgentEmule::restart_required_for_networking_change(
        &old,
        &control_port
    ));

    let mut p2p_port = old.clone();
    p2p_port.p2p.kad.listen_port = 41_999;
    assert!(!OverlordAgentEmule::restart_required_for_networking_change(
        &old, &p2p_port
    ));
}

#[test]
fn p2p_interface_reconcile_target_tracks_interface_ip_changes() {
    let mut config = EmuleAgentConfig::default();
    config.p2p.selection_confirmed = true;
    config.p2p.bind_iface = Some("hide.me".to_string());
    config.p2p.bind_ip = None;
    let interfaces = vec![AgentInterface {
        name: "hide.me".to_string(),
        description: None,
        is_loopback: false,
        is_vpn_candidate: true,
        has_default_route: false,
        addresses: vec![overlord_agent_nat::AgentInterfaceAddress {
            family: InterfaceAddressFamily::Ipv4,
            address: "10.46.87.221".to_string(),
        }],
    }];

    assert_eq!(
        p2p_interface_reconcile_target(&config, &interfaces, "10.46.102.186".parse().unwrap()),
        Some("10.46.87.221".parse().unwrap())
    );
    assert_eq!(
        p2p_interface_reconcile_target(&config, &interfaces, "10.46.87.221".parse().unwrap()),
        None
    );
}

#[test]
fn p2p_interface_reconcile_target_respects_explicit_bind_ip() {
    let mut config = EmuleAgentConfig::default();
    config.p2p.selection_confirmed = true;
    config.p2p.bind_iface = Some("hide.me".to_string());
    config.p2p.bind_ip = Some("10.46.102.186".to_string());
    let interfaces = vec![AgentInterface {
        name: "hide.me".to_string(),
        description: None,
        is_loopback: false,
        is_vpn_candidate: true,
        has_default_route: false,
        addresses: vec![overlord_agent_nat::AgentInterfaceAddress {
            family: InterfaceAddressFamily::Ipv4,
            address: "10.46.87.221".to_string(),
        }],
    }];

    assert_eq!(
        p2p_interface_reconcile_target(&config, &interfaces, "10.46.102.186".parse().unwrap()),
        None
    );
}

#[test]
fn synthetic_dataset_contains_expected_entry_count() {
    assert_eq!(SYNTHETIC_POPULAR_SEEDS.len(), 40);
}

#[test]
fn synthetic_hashes_are_deterministic() {
    let seed = &SYNTHETIC_POPULAR_SEEDS[0];
    assert_eq!(synthetic_file_hash(0, seed), synthetic_file_hash(0, seed));
}

#[test]
fn synthetic_hashes_are_unique() {
    let hashes = synthetic_popular_hashes();
    let unique = hashes
        .iter()
        .map(|entry| match &entry.hash {
            HashType::Ed2k(hash) => hash.clone(),
        })
        .collect::<HashSet<_>>();
    assert_eq!(unique.len(), hashes.len());
}

#[test]
fn synthetic_publish_queue_depth_tracks_remaining_rotation_window() {
    assert_eq!(
        synthetic_publish_queue_depth(0),
        SYNTHETIC_POPULAR_SEEDS.len()
    );
    assert_eq!(
        synthetic_publish_queue_depth(1),
        SYNTHETIC_POPULAR_SEEDS.len() - 1
    );
    assert_eq!(
        synthetic_publish_queue_depth(SYNTHETIC_POPULAR_SEEDS.len()),
        SYNTHETIC_POPULAR_SEEDS.len()
    );
}

#[test]
fn synthetic_publish_batch_wraps_and_advances_cursor() {
    let total = SYNTHETIC_POPULAR_SEEDS.len();
    let mut cursor = total - 1;

    let batch = next_synthetic_publish_batch(&mut cursor, 3);

    assert_eq!(batch.len(), 3);
    assert_eq!(
        batch[0],
        synthetic_popular_hash(total - 1, &SYNTHETIC_POPULAR_SEEDS[total - 1])
    );
    assert_eq!(
        batch[1],
        synthetic_popular_hash(0, &SYNTHETIC_POPULAR_SEEDS[0])
    );
    assert_eq!(
        batch[2],
        synthetic_popular_hash(1, &SYNTHETIC_POPULAR_SEEDS[1])
    );
    assert_eq!(cursor, 2);
}

#[test]
fn synthetic_publish_batch_treats_zero_request_as_single_item_drip() {
    let mut cursor = 0;

    let batch = next_synthetic_publish_batch(&mut cursor, 0);

    assert_eq!(batch.len(), 1);
    assert_eq!(
        batch[0],
        synthetic_popular_hash(0, &SYNTHETIC_POPULAR_SEEDS[0])
    );
    assert_eq!(cursor, 1);
}

#[test]
fn emule_source_type_matches_large_file_convention() {
    assert_eq!(emule_high_id_source_type(123), 1);
    assert_eq!(
        emule_high_id_source_type(EMULE_LARGE_FILE_SIZE_THRESHOLD + 1),
        4
    );
}

#[test]
fn build_publish_batch_summary_marks_success_timestamp_when_acked() {
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 0, 0).unwrap();
    let summary = build_publish_batch_summary(
        PublishSeedSource::Coordinator,
        40,
        PublishAttemptStats {
            closest_contacts_considered: 10,
            attempted_contacts: 10,
            acked_contacts: 6,
            timed_out_contacts: 3,
        },
        completed_at,
    );

    assert_eq!(summary.failed_contacts, 4);
    assert_eq!(summary.last_success_at, Some(completed_at));
}

#[test]
fn apply_publish_summary_accumulates_counters() {
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 5, 0).unwrap();
    let summary = build_publish_batch_summary(
        PublishSeedSource::SyntheticFallback,
        40,
        PublishAttemptStats {
            closest_contacts_considered: 8,
            attempted_contacts: 8,
            acked_contacts: 5,
            timed_out_contacts: 2,
        },
        completed_at,
    );
    let mut counters = PublishCounters::default();

    apply_publish_summary(&mut counters, &summary);

    assert_eq!(counters.batches, 1);
    assert_eq!(counters.published_items, 40);
    assert_eq!(counters.attempted_contacts, 8);
    assert_eq!(counters.acked_contacts, 5);
    assert_eq!(counters.failed_contacts, 3);
    assert_eq!(counters.timed_out_contacts, 2);
    assert_eq!(counters.last_batch_at, Some(completed_at));
    assert_eq!(counters.last_success_at, Some(completed_at));
}

#[test]
fn effective_publish_counters_include_in_flight_batch_progress() {
    let previous_completed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 5, 0).unwrap();
    let live_observed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 10, 0).unwrap();
    let committed_summary = build_publish_batch_summary(
        PublishSeedSource::Coordinator,
        10,
        PublishAttemptStats {
            closest_contacts_considered: 6,
            attempted_contacts: 6,
            acked_contacts: 4,
            timed_out_contacts: 1,
        },
        previous_completed_at,
    );
    let live_summary = build_publish_batch_summary(
        PublishSeedSource::SyntheticFallback,
        7,
        PublishAttemptStats {
            closest_contacts_considered: 5,
            attempted_contacts: 5,
            acked_contacts: 2,
            timed_out_contacts: 2,
        },
        live_observed_at,
    );
    let mut committed_counters = PublishCounters::default();
    apply_publish_summary(&mut committed_counters, &committed_summary);

    let effective = effective_publish_counters(
        &committed_counters,
        Some(&live_summary),
        Some(live_observed_at),
    );

    assert_eq!(effective.batches, 2);
    assert_eq!(effective.published_items, 17);
    assert_eq!(effective.closest_contacts_considered, 11);
    assert_eq!(effective.attempted_contacts, 11);
    assert_eq!(effective.acked_contacts, 6);
    assert_eq!(effective.failed_contacts, 5);
    assert_eq!(effective.timed_out_contacts, 3);
    assert_eq!(effective.last_batch_at, Some(live_observed_at));
    assert_eq!(effective.last_success_at, Some(live_observed_at));
}

#[test]
fn effective_publish_counters_do_not_double_count_committed_batch() {
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 5, 0).unwrap();
    let summary = build_publish_batch_summary(
        PublishSeedSource::SyntheticFallback,
        40,
        PublishAttemptStats {
            closest_contacts_considered: 8,
            attempted_contacts: 8,
            acked_contacts: 5,
            timed_out_contacts: 2,
        },
        completed_at,
    );
    let mut counters = PublishCounters::default();
    apply_publish_summary(&mut counters, &summary);

    let effective = effective_publish_counters(&counters, Some(&summary), Some(completed_at));

    assert_eq!(effective, counters);
}

#[tokio::test]
async fn record_publish_summaries_tracks_notes_family_when_enabled() {
    let completed_at = Utc.with_ymd_and_hms(2026, 4, 25, 10, 0, 0).unwrap();
    let observability = Arc::new(Mutex::new(KadPublishObservability::default()));

    record_publish_summaries(
        &observability,
        PublishSeedSource::ManualApi,
        2,
        PublishAttemptStats {
            closest_contacts_considered: 3,
            attempted_contacts: 3,
            acked_contacts: 2,
            timed_out_contacts: 0,
        },
        PublishAttemptStats {
            closest_contacts_considered: 4,
            attempted_contacts: 4,
            acked_contacts: 3,
            timed_out_contacts: 1,
        },
        Some(PublishAttemptStats {
            closest_contacts_considered: 5,
            attempted_contacts: 5,
            acked_contacts: 4,
            timed_out_contacts: 1,
        }),
        completed_at,
    )
    .await;

    let snapshot = observability.lock().await;
    let latest_notes = snapshot
        .latest_notes_batch
        .as_ref()
        .expect("notes publish batch summary");
    assert_eq!(latest_notes.seed_source, PublishSeedSource::ManualApi);
    assert_eq!(latest_notes.published_items, 2);
    assert_eq!(latest_notes.attempted_contacts, 5);
    assert_eq!(latest_notes.acked_contacts, 4);
    assert_eq!(snapshot.notes_counters.batches, 1);
    assert_eq!(snapshot.notes_counters.published_items, 2);
    assert_eq!(snapshot.notes_counters.attempted_contacts, 5);
    assert_eq!(snapshot.notes_counters.last_success_at, Some(completed_at));
}

#[test]
fn effective_publish_counters_ignore_empty_initial_snapshot() {
    let observed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 0, 0).unwrap();
    let empty_summary = build_publish_batch_summary(
        PublishSeedSource::Coordinator,
        0,
        PublishAttemptStats::default(),
        observed_at,
    );

    let effective = effective_publish_counters(
        &PublishCounters::default(),
        Some(&empty_summary),
        Some(observed_at),
    );

    assert_eq!(effective, PublishCounters::default());
}

#[test]
fn apply_harvest_record_tracks_keyword_request_shape() {
    let mut observability = KadHarvestObservability::default();
    let entry = SnoopEntry::Keyword {
        logical_key: "keyword:00112233445566778899aabbccddeeff:8000:aabb".to_string(),
        target: "00112233445566778899aabbccddeeff".to_string(),
        start_position: 0x8000,
        restrictive_payload_hex: Some("aabb".to_string()),
        hit_count: 1,
        first_seen: Utc.with_ymd_and_hms(2026, 3, 22, 19, 58, 0).unwrap(),
        last_seen: Utc.with_ymd_and_hms(2026, 3, 22, 19, 58, 0).unwrap(),
        last_drained_at: None,
    };

    apply_harvest_record(
        &mut observability,
        "127.0.0.1:41000".parse().unwrap(),
        &entry,
        true,
    );

    assert_eq!(observability.keyword_requests.observed_requests, 1);
    assert_eq!(observability.keyword_requests.unique_shapes_observed, 1);
    assert_eq!(
        observability.keyword_requests.last_target.as_deref(),
        Some("00112233445566778899aabbccddeeff")
    );
    assert_eq!(
        observability.keyword_requests.last_start_position,
        Some(0x8000)
    );
    assert_eq!(
        observability.keyword_requests.last_restrictive_bytes,
        Some(2)
    );
    assert_eq!(
        observability.keyword_requests.last_from.as_deref(),
        Some("127.0.0.1:41000")
    );
}

#[test]
fn apply_queue_family_counts_updates_live_depths() {
    let mut observability = KadHarvestObservability::default();

    apply_queue_family_counts(
        &mut observability,
        SnoopQueueFamilyCounts {
            keyword: 2,
            source: 3,
            notes: 1,
        },
    );

    assert_eq!(observability.keyword_requests.queued_entries, 2);
    assert_eq!(observability.source_requests.queued_entries, 3);
    assert_eq!(observability.notes_requests.queued_entries, 1);
}

#[test]
fn passive_keyword_replay_observability_tracks_cycle_lifecycle() {
    let mut observability = KadHarvestObservability::default();
    let request = SearchKeyReq {
        target: "00112233445566778899aabbccddeeff".parse().unwrap(),
        start_position: 0x8000,
        restrictive_payload: vec![0xAA, 0xBB, 0xCC],
    };
    let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 20, 0, 0).unwrap();
    let idle_at = Utc.with_ymd_and_hms(2026, 3, 22, 20, 1, 0).unwrap();
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 22, 20, 2, 0).unwrap();
    let failed_at = Utc.with_ymd_and_hms(2026, 3, 22, 20, 3, 0).unwrap();
    let tier_summaries = vec![
        KadPassiveReplayTierSummary {
            responder_ceiling: 10,
            result_count: 2,
        },
        KadPassiveReplayTierSummary {
            responder_ceiling: 20,
            result_count: 5,
        },
    ];

    record_passive_replay_idle(&mut observability, HarvestFamily::Keyword, idle_at);
    record_passive_replay_start(
        &mut observability,
        HarvestFamily::Keyword,
        request.target.to_string(),
        Some(request.start_position),
        Some(request.restrictive_payload.len() as u32),
        started_at,
    );
    record_passive_replay_complete(
        &mut observability,
        HarvestFamily::Keyword,
        completed_at,
        7,
        2,
        tier_summaries.clone(),
    );
    record_passive_replay_post_failure(
        &mut observability,
        HarvestFamily::Keyword,
        failed_at,
        "post failed",
    );
    record_passive_replay_enqueue_wait(
        &mut observability,
        HarvestFamily::Keyword,
        Duration::from_millis(12),
        true,
    );
    record_passive_replay_post_latency(
        &mut observability,
        HarvestFamily::Keyword,
        Duration::from_millis(34),
    );

    assert_eq!(observability.passive_keyword_replay.idle_cycles, 1);
    assert_eq!(observability.passive_keyword_replay.started_cycles, 1);
    assert_eq!(observability.passive_keyword_replay.completed_cycles, 1);
    assert_eq!(observability.passive_keyword_replay.emitted_results, 7);
    assert_eq!(observability.passive_keyword_replay.widened_cycles, 1);
    assert_eq!(observability.passive_keyword_replay.posted_batches, 2);
    assert_eq!(observability.passive_keyword_replay.post_failures, 1);
    assert_eq!(
        observability
            .passive_keyword_replay
            .enqueue_backpressure_events,
        1
    );
    assert_eq!(observability.passive_keyword_replay.post_callbacks, 1);
    assert_eq!(observability.passive_keyword_replay.enqueue_wait_millis, 12);
    assert_eq!(observability.passive_keyword_replay.post_latency_millis, 34);
    assert_eq!(
        observability.passive_keyword_replay.last_target.as_deref(),
        Some("00112233445566778899aabbccddeeff")
    );
    assert_eq!(
        observability.passive_keyword_replay.last_start_position,
        Some(0x8000)
    );
    assert_eq!(
        observability.passive_keyword_replay.last_restrictive_bytes,
        Some(3)
    );
    assert_eq!(observability.passive_keyword_replay.last_result_count, 7);
    assert_eq!(observability.passive_keyword_replay.last_batches_posted, 2);
    assert_eq!(
        observability
            .passive_keyword_replay
            .last_enqueue_wait_millis,
        12
    );
    assert_eq!(
        observability
            .passive_keyword_replay
            .last_post_latency_millis,
        34
    );
    assert_eq!(observability.passive_keyword_replay.last_tiers_attempted, 2);
    assert_eq!(
        observability
            .passive_keyword_replay
            .last_widest_responder_ceiling,
        Some(20)
    );
    assert!(observability.passive_keyword_replay.last_widened);
    assert_eq!(
        observability.passive_keyword_replay.last_tiers,
        tier_summaries
    );
    assert_eq!(
        observability.passive_keyword_replay.last_error.as_deref(),
        Some("post failed")
    );
    assert_eq!(
        observability.passive_keyword_replay.last_completed_at,
        Some(completed_at)
    );
    assert_eq!(
        observability.passive_keyword_replay.last_error_at,
        Some(failed_at)
    );
}

#[test]
fn passive_source_replay_observability_tracks_tiered_cycle_lifecycle() {
    let mut observability = KadHarvestObservability::default();
    let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 21, 0, 0).unwrap();
    let idle_at = Utc.with_ymd_and_hms(2026, 3, 22, 21, 1, 0).unwrap();
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 22, 21, 2, 0).unwrap();
    let tier_summaries = vec![KadPassiveReplayTierSummary {
        responder_ceiling: 10,
        result_count: 4,
    }];

    record_passive_replay_idle(&mut observability, HarvestFamily::Source, idle_at);
    record_passive_replay_start(
        &mut observability,
        HarvestFamily::Source,
        "ffeeddccbbaa99887766554433221100".to_string(),
        Some(0),
        None,
        started_at,
    );
    record_passive_replay_complete(
        &mut observability,
        HarvestFamily::Source,
        completed_at,
        4,
        1,
        tier_summaries.clone(),
    );

    assert_eq!(observability.passive_source_replay.idle_cycles, 1);
    assert_eq!(observability.passive_source_replay.started_cycles, 1);
    assert_eq!(observability.passive_source_replay.completed_cycles, 1);
    assert_eq!(observability.passive_source_replay.emitted_results, 4);
    assert_eq!(observability.passive_source_replay.posted_batches, 1);
    assert_eq!(
        observability.passive_source_replay.last_target.as_deref(),
        Some("ffeeddccbbaa99887766554433221100")
    );
    assert_eq!(
        observability.passive_source_replay.last_start_position,
        Some(0)
    );
    assert_eq!(
        observability.passive_source_replay.last_restrictive_bytes,
        None
    );
    assert_eq!(observability.passive_source_replay.last_tiers_attempted, 1);
    assert_eq!(
        observability
            .passive_source_replay
            .last_widest_responder_ceiling,
        Some(10)
    );
    assert!(!observability.passive_source_replay.last_widened);
    assert_eq!(
        observability.passive_source_replay.last_tiers,
        tier_summaries
    );
    assert_eq!(
        observability.passive_source_replay.last_completed_at,
        Some(completed_at)
    );
}

#[test]
fn passive_notes_replay_observability_uses_dedicated_bucket() {
    let mut observability = KadHarvestObservability::default();
    let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 0, 0).unwrap();
    let idle_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 1, 0).unwrap();
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 2, 0).unwrap();
    let tier_summaries = vec![KadPassiveReplayTierSummary {
        responder_ceiling: 10,
        result_count: 2,
    }];

    record_passive_replay_idle(&mut observability, HarvestFamily::Notes, idle_at);
    record_passive_replay_start(
        &mut observability,
        HarvestFamily::Notes,
        "1234567890abcdef1234567890abcdef".to_string(),
        None,
        None,
        started_at,
    );
    record_passive_replay_complete(
        &mut observability,
        HarvestFamily::Notes,
        completed_at,
        2,
        1,
        tier_summaries.clone(),
    );

    assert_eq!(observability.passive_notes_replay.idle_cycles, 1);
    assert_eq!(observability.passive_notes_replay.started_cycles, 1);
    assert_eq!(observability.passive_notes_replay.completed_cycles, 1);
    assert_eq!(observability.passive_notes_replay.emitted_results, 2);
    assert_eq!(observability.passive_notes_replay.posted_batches, 1);
    assert_eq!(
        observability.passive_notes_replay.last_target.as_deref(),
        Some("1234567890abcdef1234567890abcdef")
    );
    assert_eq!(observability.passive_notes_replay.last_start_position, None);
    assert_eq!(
        observability.passive_notes_replay.last_restrictive_bytes,
        None
    );
    assert_eq!(
        observability.passive_notes_replay.last_tiers,
        tier_summaries
    );
    assert_eq!(
        observability.passive_notes_replay.last_completed_at,
        Some(completed_at)
    );
    assert_eq!(observability.passive_keyword_replay.started_cycles, 0);
}

#[tokio::test]
async fn next_passive_replay_request_prefers_source_when_backlog_is_heavier() {
    let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 60,
        general_max_queries_per_600s: 10,
        general_drain_cooldown_secs: 30,
        source_max_queries_per_600s: 10,
        source_drain_cooldown_secs: 30,
        source_stop_after_results: 2,
    })));
    let now = Utc.with_ymd_and_hms(2026, 3, 24, 15, 12, 0).unwrap();
    {
        let mut guard = queue.lock().await;
        guard.record(build_keyword_snoop_entry(
            &SearchKeyReq {
                target: NodeId::from_bytes([0x11; 16]),
                start_position: 0,
                restrictive_payload: Vec::new(),
            },
            now,
        ));
        guard.record(build_source_snoop_entry(
            &SearchSourceReq {
                target: NodeId::from_bytes([0x22; 16]),
                start_position: 0,
                size: 1_024,
            },
            now,
        ));
        guard.record(build_source_snoop_entry(
            &SearchSourceReq {
                target: NodeId::from_bytes([0x33; 16]),
                start_position: 0,
                size: 2_048,
            },
            now,
        ));
        guard.record(build_source_snoop_entry(
            &SearchSourceReq {
                target: NodeId::from_bytes([0x33; 16]),
                start_position: 0,
                size: 2_048,
            },
            now,
        ));
    }

    let selected = next_passive_replay_request(&queue).await;
    assert!(matches!(selected, Some(PassiveReplaySelection::Source(_))));
}

#[tokio::test]
async fn next_passive_replay_request_selects_notes_when_only_notes_are_queued() {
    let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 60,
        general_max_queries_per_600s: 10,
        general_drain_cooldown_secs: 30,
        source_max_queries_per_600s: 10,
        source_drain_cooldown_secs: 30,
        source_stop_after_results: 2,
    })));
    let now = Utc.with_ymd_and_hms(2026, 3, 24, 15, 14, 0).unwrap();
    {
        let mut guard = queue.lock().await;
        guard.record(build_notes_snoop_entry(
            &SearchNotesReq {
                target: NodeId::from_bytes([0x44; 16]),
                size: 4_096,
            },
            now,
        ));
    }

    let selected = next_passive_replay_request(&queue).await;
    assert!(matches!(selected, Some(PassiveReplaySelection::Notes(_))));
}

#[tokio::test]
async fn restore_and_flush_preserve_last_drained_at() {
    let restored_entry = SnoopEntry::Keyword {
        logical_key: "keyword:00112233445566778899aabbccddeeff:8000:aabb".to_string(),
        target: "00112233445566778899aabbccddeeff".to_string(),
        start_position: 0x8000,
        restrictive_payload_hex: Some("aabb".to_string()),
        hit_count: 4,
        first_seen: Utc.with_ymd_and_hms(2026, 3, 21, 10, 0, 0).unwrap(),
        last_seen: Utc.with_ymd_and_hms(2026, 3, 21, 10, 5, 0).unwrap(),
        last_drained_at: Some(Utc.with_ymd_and_hms(2026, 3, 21, 10, 6, 0).unwrap()),
    };
    let (addr, flushed_entries) = spawn_mock_coordinator(vec![restored_entry.clone()]).await;
    let coordinator = CoordinatorClient::new(&format!("http://{addr}")).unwrap();
    let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig::default())));
    let observed_snoop_events = Arc::new(Mutex::new(Vec::new()));
    let indexer_id = Uuid::from_u128(0x22222222222222222222222222222222);

    restore_snoop_queue(&coordinator, indexer_id, &queue).await;
    flush_snoop_queue(&coordinator, indexer_id, &queue, &observed_snoop_events)
        .await
        .unwrap();

    let flushed_entries = flushed_entries.lock().await.clone();
    assert_eq!(flushed_entries, vec![restored_entry]);
}

#[tokio::test]
async fn passive_replay_gate_allows_two_workers_but_blocks_a_third() {
    let gate = Arc::new(Semaphore::new(PASSIVE_REPLAY_CONCURRENCY));
    let first = try_acquire_passive_replay_gate(&gate, "source-fast-path");
    assert!(first.is_some());
    let second = try_acquire_passive_replay_gate(&gate, "general");
    assert!(second.is_some());
    assert!(try_acquire_passive_replay_gate(&gate, "overflow").is_none());
    drop(first);
    assert!(try_acquire_passive_replay_gate(&gate, "overflow").is_some());
}

#[tokio::test]
async fn source_fast_path_prefers_source_replays() {
    let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 600,
        general_max_queries_per_600s: 10,
        general_drain_cooldown_secs: 30,
        source_max_queries_per_600s: 10,
        source_drain_cooldown_secs: 30,
        source_stop_after_results: 2,
    })));
    let now = Utc::now();
    queue.lock().await.record(build_keyword_snoop_entry(
        &SearchKeyReq {
            target: "00112233445566778899aabbccddeeff".parse().unwrap(),
            start_position: 0,
            restrictive_payload: Vec::new(),
        },
        now,
    ));
    queue.lock().await.record(build_source_snoop_entry(
        &SearchSourceReq {
            target: "11112222333344445555666677778888".parse().unwrap(),
            start_position: 0,
            size: 4096,
        },
        now,
    ));
    queue.lock().await.record(build_source_snoop_entry(
        &SearchSourceReq {
            target: "11112222333344445555666677778888".parse().unwrap(),
            start_position: 0,
            size: 4096,
        },
        now,
    ));

    let selected = next_passive_replay_request_for_family(&queue, HarvestFamily::Source).await;

    assert!(matches!(selected, Some(PassiveReplaySelection::Source(_))));
}

#[tokio::test]
async fn source_fast_path_stays_idle_without_source_backlog() {
    let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 600,
        general_max_queries_per_600s: 10,
        general_drain_cooldown_secs: 30,
        source_max_queries_per_600s: 10,
        source_drain_cooldown_secs: 30,
        source_stop_after_results: 2,
    })));
    queue.lock().await.record(build_keyword_snoop_entry(
        &SearchKeyReq {
            target: "00112233445566778899aabbccddeeff".parse().unwrap(),
            start_position: 0,
            restrictive_payload: Vec::new(),
        },
        Utc::now(),
    ));

    let selected = next_passive_replay_request_for_family(&queue, HarvestFamily::Source).await;

    assert!(selected.is_none());
}

#[tokio::test]
async fn start_runs_runtime_without_coordinator() {
    let temp_root = unique_test_dir("overlord-agent-emule-offline-start");
    let config = build_test_config(&temp_root, "http://127.0.0.1:9".to_string());
    let agent = OverlordAgentEmule::new(config).await.unwrap();

    agent.start().await.unwrap();
    assert!(agent.runtime.lock().await.is_some());
    let stats = agent.stats().await.unwrap();
    assert!(
        stats
            .interface_report
            .as_ref()
            .is_some_and(|report| report.p2p.ready)
    );

    agent.stop().await.unwrap();
    fs::remove_dir_all(&temp_root).unwrap();
}

#[tokio::test]
async fn serve_continues_when_initial_coordinator_registration_fails() {
    let temp_root = unique_test_dir("overlord-agent-emule-offline-serve");
    let config = build_test_config(&temp_root, "http://127.0.0.1:9".to_string());
    let agent = Arc::new(OverlordAgentEmule::new(config).await.unwrap());
    agent.start().await.unwrap();

    let serve_agent = Arc::clone(&agent);
    let serve_task = tokio::spawn(async move { serve_agent.serve().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!serve_task.is_finished());
    serve_task.abort();
    let _ = serve_task.await;

    fs::remove_dir_all(&temp_root).unwrap();
}

#[tokio::test]
async fn reconnect_loop_registers_after_startup_fallback() {
    let probe_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let coordinator_addr = probe_listener.local_addr().unwrap();
    drop(probe_listener);

    let temp_root = unique_test_dir("overlord-agent-emule-reconnect");
    let config = build_test_config(&temp_root, format!("http://{coordinator_addr}"));
    let networking_view = AgentInterfacesView {
        registration: IndexerRegistration {
            indexer_id: Uuid::nil(),
            protocol: Protocol::Kad2,
            url: String::new(),
            hostname: String::new(),
            version: String::new(),
            registered_at: Utc::now(),
        },
        report: None,
        config: OverlordAgentEmule::networking_config(&config),
        nat: None,
        agent_activity: None,
        publish_observability: None,
        harvest_observability: None,
        last_error: None,
    };
    let agent = Arc::new(OverlordAgentEmule::new(config).await.unwrap());
    agent.start().await.unwrap();

    let serve_agent = Arc::clone(&agent);
    let serve_task = tokio::spawn(async move { serve_agent.serve().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let register_calls = spawn_full_mock_coordinator(coordinator_addr, networking_view).await;
    tokio::time::timeout(
        Duration::from_secs(COORDINATOR_RECONNECT_SECS + 10),
        async {
            loop {
                if register_calls.load(AtomicOrdering::Relaxed) > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        },
    )
    .await
    .unwrap();

    agent.request_restart();
    let _ = tokio::time::timeout(Duration::from_secs(15), serve_task)
        .await
        .unwrap()
        .unwrap();

    fs::remove_dir_all(&temp_root).unwrap();
}

#[tokio::test]
async fn apply_config_without_endpoint_change_reconciles_in_place() {
    let temp_root = unique_test_dir("overlord-agent-emule-config-update");
    let config = build_test_config(&temp_root, "http://127.0.0.1:9".to_string());
    let agent = OverlordAgentEmule::new(config).await.unwrap();
    agent.start().await.unwrap();

    let current = agent.config.read().await.clone();
    let mut desired = OverlordAgentEmule::networking_config(&current);
    desired.nat.p2p.enabled = true;
    desired.nat.p2p.backend_order = vec![UPNP_RUPNP_BACKEND.to_string()];

    agent
        .apply_config(ConfigUpdate {
            protocol: Protocol::Kad2,
            config: serde_json::to_value(desired).unwrap(),
        })
        .await
        .unwrap();

    assert!(!agent.restart_requested.load(Ordering::SeqCst));
    assert!(agent.runtime.lock().await.is_some());

    agent.stop().await.unwrap();
    fs::remove_dir_all(&temp_root).unwrap();
}

#[tokio::test]
async fn apply_config_with_control_endpoint_change_requests_restart() {
    let temp_root = unique_test_dir("overlord-agent-emule-control-endpoint-update");
    let config = build_test_config(&temp_root, "http://127.0.0.1:9".to_string());
    let agent = OverlordAgentEmule::new(config).await.unwrap();
    agent.start().await.unwrap();

    let current = agent.config.read().await.clone();
    let mut desired = OverlordAgentEmule::networking_config(&current);
    desired.control.listen_port = 13_302;

    agent
        .apply_config(ConfigUpdate {
            protocol: Protocol::Kad2,
            config: serde_json::to_value(desired).unwrap(),
        })
        .await
        .unwrap();

    assert!(agent.restart_requested.load(Ordering::SeqCst));

    agent.stop().await.unwrap();
    fs::remove_dir_all(&temp_root).unwrap();
}

#[tokio::test]
async fn apply_config_with_p2p_endpoint_change_reconciles_in_place() {
    let temp_root = unique_test_dir("overlord-agent-emule-p2p-endpoint-update");
    let config = build_test_config(&temp_root, "http://127.0.0.1:9".to_string());
    let agent = OverlordAgentEmule::new(config).await.unwrap();
    agent.start().await.unwrap();

    let current = agent.config.read().await.clone();
    let mut desired = OverlordAgentEmule::networking_config(&current);
    desired.p2p.kad.listen_port = 42_000;

    agent
        .apply_config(ConfigUpdate {
            protocol: Protocol::Kad2,
            config: serde_json::to_value(desired).unwrap(),
        })
        .await
        .unwrap();

    assert!(!agent.restart_requested.load(Ordering::SeqCst));
    assert!(agent.runtime.lock().await.is_some());

    agent.stop().await.unwrap();
    fs::remove_dir_all(&temp_root).unwrap();
}

#[tokio::test]
async fn stop_succeeds_when_shutdown_flush_cannot_reach_coordinator() {
    let temp_root = unique_test_dir("overlord-agent-emule-shutdown-flush");
    let config = build_test_config(&temp_root, "http://127.0.0.1:9".to_string());
    let agent = OverlordAgentEmule::new(config).await.unwrap();

    agent.start().await.unwrap();
    agent.stop().await.unwrap();

    fs::remove_dir_all(&temp_root).unwrap();
}

#[test]
fn kad_hello_metadata_parses_misc_bits_and_source_uport() {
    let metadata = parse_kad_hello_metadata(&[
        Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
        Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x07)),
    ]);

    assert_eq!(metadata.hello_source_udp_port, Some(41000));
    assert!(metadata.udp_firewalled);
    assert!(metadata.tcp_firewalled);
    assert!(metadata.requests_hello_res_ack);
}

#[test]
fn kad_hello_response_tags_encode_expected_misc_bits() {
    let tags = build_kad_hello_response_tags(41000, true, false, true);

    assert_eq!(
        tags,
        vec![
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
            Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05)),
        ]
    );
}

#[test]
fn kad_hello_request_tags_prefer_misc_options_when_ack_is_requested() {
    let tags = build_kad_hello_request_tags(41000, true, false, false, true);

    assert_eq!(
        tags,
        vec![Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x04))]
    );
}

#[test]
fn kad_hello_request_tags_advertise_source_uport_for_verified_open_udp() {
    let tags = build_kad_hello_request_tags(41000, true, false, false, false);

    assert_eq!(
        tags,
        vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))]
    );
}

#[test]
fn kad_hello_request_tags_can_be_empty_before_udp_state_is_verified() {
    let tags = build_kad_hello_request_tags(41000, false, false, false, false);

    assert!(tags.is_empty());
}

#[test]
fn hello_response_ack_requires_sender_verify_key() {
    assert!(!should_request_hello_response_ack(8, false, None));
    assert!(should_request_hello_response_ack(
        8,
        false,
        Some(0x1122_3344)
    ));
    assert!(!should_request_hello_response_ack(
        8,
        true,
        Some(0x1122_3344)
    ));
    assert!(!should_request_hello_response_ack(
        7,
        false,
        Some(0x1122_3344)
    ));
}

#[test]
fn source_publish_tags_match_oracle_plaintext_shape() {
    let tags = build_source_publish_tags(
        "10.54.206.206:41000".parse().unwrap(),
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: false,
        },
        2_097_152,
    );

    assert_eq!(
        tags,
        vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(41001)),
            Tag::new_short(tag_name::SOURCEIP, TagValue::U32(0x0A36_CECE)),
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
            Tag::filesize(2_097_152),
            Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0)),
        ]
    );
}

#[test]
fn source_publish_tags_set_obfuscated_encryption_bits() {
    let tags = build_source_publish_tags(
        "10.54.206.206:41000".parse().unwrap(),
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: true,
        },
        2_097_152,
    );

    assert_eq!(
        tags.last(),
        Some(&Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(3)))
    );
}

#[test]
fn source_publish_identity_uses_emule_kad_chunk_order() {
    let user_hash = [
        0xB4, 0x22, 0xCF, 0x1A, 0x44, 0x0E, 0x71, 0x6B, 0xD2, 0xE1, 0xDD, 0x6E, 0x77, 0x21, 0x6F,
        0xE4,
    ];

    let publisher_id = source_publish_client_hash(user_hash);

    assert_eq!(
        publisher_id.0,
        [
            0x1A, 0xCF, 0x22, 0xB4, 0x6B, 0x71, 0x0E, 0x44, 0x6E, 0xDD, 0xE1, 0xD2, 0xE4, 0x6F,
            0x21, 0x77,
        ]
    );
    assert_eq!(publisher_id.to_be_bytes(), user_hash);
}

#[test]
fn kad_source_results_preserve_obfuscation_and_user_hash_metadata() {
    let source = kad_source_result_to_ed2k_found_source(SourceResult {
        file_hash: Ed2kHash::from_bytes([0x44; 16]),
        source_id: Ed2kHash::from_bytes([0x55; 16]),
        ip: Ipv4Addr::new(127, 0, 0, 2),
        tcp_port: 4662,
        udp_port: 4672,
        obfuscation_options: Some(0x03),
    });

    assert!(source.obfuscated);
    assert_eq!(source.obfuscation_options, Some(0x03));
    assert_eq!(source.user_hash, Some([0x55; 16]));
    assert_eq!(source.ip, Ipv4Addr::new(127, 0, 0, 2));
}

#[test]
fn notes_publish_tags_are_deterministic_and_note_shaped() {
    let tags = build_notes_publish_tags("ubuntu linux.iso", 2_097_152);

    assert_eq!(
        tags,
        vec![
            Tag::filename("ubuntu linux.iso"),
            Tag::filesize(2_097_152),
            Tag::new_short(tag_name::FILERATING, TagValue::U8(4)),
            Tag::new_short(
                tag_name::DESCRIPTION,
                TagValue::String("overlord validation note for ubuntu linux.iso".to_string()),
            ),
        ]
    );
}

#[test]
fn ed2k_file_type_search_term_matches_oracle_program_family() {
    assert_eq!(
        ed2k_file_type_search_term("ubuntu-linux-oracle-sample.iso"),
        Some("Pro")
    );
    assert_eq!(ed2k_file_type_search_term("archive.7z"), Some("Pro"));
}

#[test]
fn ed2k_file_type_search_term_matches_common_media_families() {
    assert_eq!(ed2k_file_type_search_term("album.flac"), Some("Audio"));
    assert_eq!(ed2k_file_type_search_term("movie.mkv"), Some("Video"));
    assert_eq!(ed2k_file_type_search_term("scan.png"), Some("Image"));
    assert_eq!(ed2k_file_type_search_term("manual.pdf"), Some("Doc"));
    assert_eq!(
        ed2k_file_type_search_term("bundle.emulecollection"),
        Some("EmuleCollection")
    );
    assert_eq!(ed2k_file_type_search_term("README"), None);
}

#[test]
fn synthetic_publish_aich_hash_is_stable_for_same_file_identity() {
    let file_hash = Ed2kHash::from_bytes([0xAB; 16]);
    let first = synthetic_publish_aich_hash(&file_hash, "ubuntu.iso", 734_003_200);
    let second = synthetic_publish_aich_hash(&file_hash, "ubuntu.iso", 734_003_200);
    assert_eq!(first, second);
    assert_eq!(first.len(), 20);
}

#[test]
fn synthetic_publish_aich_hash_changes_when_file_identity_changes() {
    let file_hash = Ed2kHash::from_bytes([0xAB; 16]);
    let first = synthetic_publish_aich_hash(&file_hash, "ubuntu.iso", 734_003_200);
    let second = synthetic_publish_aich_hash(&file_hash, "ubuntu.iso", 734_003_201);
    assert_ne!(first, second);
}

#[tokio::test]
async fn bound_ed2k_listener_is_treated_as_tcp_open() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ed2k_server_state = Arc::new(RwLock::new(Ed2kServerState::default()));

    assert!(!current_tcp_firewalled(&listener, &ed2k_server_state).await);
}

#[tokio::test]
async fn low_id_server_verdict_marks_tcp_as_firewalled() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ed2k_server_state = Arc::new(RwLock::new(Ed2kServerState {
        client_id: Some(0x0000_2222),
        ..Ed2kServerState::default()
    }));

    assert!(current_tcp_firewalled(&listener, &ed2k_server_state).await);
}

#[tokio::test]
async fn hello_response_uses_oracle_hello_shape() {
    let dht = DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x33; 16]),
        udp_key: 0x1122_3344,
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ed2k_server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));

    let hello = build_hello_response(&dht, &listener, &ed2k_server_state, &kad_firewall, true)
        .await
        .unwrap();

    assert_eq!(hello.node_id, dht.own_id());
    assert!(hello.tags.iter().any(|tag| matches!(
        (&tag.name, &tag.value),
        (TagName::Short(name), TagValue::U16(_))
            if *name == tag_name::SOURCEUPORT
    )));
}

#[tokio::test]
async fn hello_request_uses_oracle_hello_shape() {
    let dht = DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x44; 16]),
        udp_key: 0x5566_7788,
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ed2k_server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));

    let hello = build_hello_request(&dht, &listener, &ed2k_server_state, &kad_firewall, true)
        .await
        .unwrap();

    assert_eq!(hello.node_id, dht.own_id());
    assert!(hello.tags.iter().any(|tag| matches!(
        (&tag.name, &tag.value),
        (TagName::Short(name), TagValue::U8(bits))
            if *name == tag_name::KADMISCOPTIONS && (*bits & 0x04) != 0
    )));
}
