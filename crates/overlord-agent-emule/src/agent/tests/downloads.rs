use super::*;

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
fn merge_download_sources_preserves_later_server_provenance() {
    let file_hash = Ed2kHash::from_bytes([0x46; 16]);
    let source_server = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 4661));
    let mut sources = vec![Ed2kFoundSource {
        file_hash,
        ip: Ipv4Addr::new(10, 0, 0, 1),
        tcp_port: 41001,
        client_id: 1,
        low_id: false,
        obfuscated: false,
        obfuscation_options: None,
        user_hash: None,
        source_server: None,
    }];

    merge_download_sources(
        &mut sources,
        vec![Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::new(10, 0, 0, 1),
            tcp_port: 41001,
            client_id: 1,
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: Some(source_server),
        }],
    );

    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].source_server, Some(source_server));
}

#[test]
fn no_progress_source_requery_skips_exhausted_direct_endpoints() {
    assert!(!should_skip_no_progress_source_requery(true, false, 0, 0));
    assert!(should_skip_no_progress_source_requery(true, false, 0, 1));
    assert!(!should_skip_no_progress_source_requery(true, true, 0, 1));
    assert!(!should_skip_no_progress_source_requery(true, false, 1, 1));
    assert!(!should_skip_no_progress_source_requery(false, false, 0, 1));
}

#[test]
fn zero_source_background_lookup_keeps_connected_server_eligible() {
    assert!(!should_exclude_background_endpoint(false, 0));
    assert!(!should_exclude_background_endpoint(true, 0));
    assert!(should_exclude_background_endpoint(true, 1));
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
