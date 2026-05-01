use super::*;

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
