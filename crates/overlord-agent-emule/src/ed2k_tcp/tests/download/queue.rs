use super::*;

#[tokio::test]
async fn queue_only_peer_is_accepted_without_counting_as_failure() {
    let root = unique_test_dir("ed2k-queue-only-accepted");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 32_768];
    let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "captured.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_public_key = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let hello = read_packet(&mut stream).await;
        assert_eq!(hello[5], OP_HELLO);

        let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [0x42; 16],
            client_id: 0x5912_0559,
            tcp_port: peer_addr.port(),
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });
        stream.write_all(&hello_answer).await.unwrap();

        let secure_ident_probe = read_packet(&mut stream).await;
        assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);
        stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let public_key = read_packet(&mut stream).await;
        assert_eq!(public_key[5], super::OP_PUBLICKEY);
        let peer_public_key_packet = encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_public_key.public_key_payload().unwrap(),
        );
        stream.write_all(&peer_public_key_packet).await.unwrap();

        let signature = read_packet(&mut stream).await;
        assert_eq!(signature[5], super::OP_SIGNATURE);
        drop(stream);
    });

    let result = download_file_from_peer_test!(
        Ipv4Addr::LOCALHOST,
        &Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::LOCALHOST,
            tcp_port: peer_addr.port(),
            client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
        },
        Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        &Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        &transfer_runtime,
        "captured.epub".to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(!manifest.completed);
    server.await.unwrap();
}

#[tokio::test]
async fn queued_peer_waits_past_read_timeout_for_late_accept_upload() {
    let root = unique_test_dir("ed2k-queued-peer-late-accept");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 32_768];
    let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "queued.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_public_key = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let hello = read_packet(&mut stream).await;
        assert_eq!(hello[5], OP_HELLO);

        let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [0x42; 16],
            client_id: 0x5912_0559,
            tcp_port: peer_addr.port(),
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });
        stream.write_all(&hello_answer).await.unwrap();

        let secure_ident_probe = read_packet(&mut stream).await;
        assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);
        stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let public_key = read_packet(&mut stream).await;
        assert_eq!(public_key[5], super::OP_PUBLICKEY);
        let peer_public_key_packet = encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_public_key.public_key_payload().unwrap(),
        );
        stream.write_all(&peer_public_key_packet).await.unwrap();

        let signature = read_packet(&mut stream).await;
        assert_eq!(signature[5], super::OP_SIGNATURE);
        stream
            .write_all(&encode_packet(
                OP_EMULEPROT,
                super::OP_SIGNATURE,
                &[0xAA; 49],
            ))
            .await
            .unwrap();

        let startup_request = read_packet(&mut stream).await;
        assert_startup_multipacket_ext2(
            startup_request[0],
            startup_request[5],
            &startup_request[6..],
            &file_hash,
            payload.len() as u64,
            false,
        );
        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload.len() as u64,
            "queued.epub",
            false,
        );
        stream.write_all(&filename_answer).await.unwrap();

        let start_upload = read_packet(&mut stream).await;
        assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);

        let file_desc = encode_packet(
            OP_EMULEPROT,
            super::OP_FILEDESC,
            &[0x05, 0x00, b'q', b'u', b'e', b'u', b'e'],
        );
        stream.write_all(&file_desc).await.unwrap();

        let queue_ranking = super::encode_queue_ranking(1);
        stream.write_all(&queue_ranking).await.unwrap();

        tokio::time::sleep(Duration::from_millis(1500)).await;

        stream.write_all(&encode_accept_upload_req()).await.unwrap();

        let request_parts = read_packet(&mut stream).await;
        assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        let (requested_hash, ranges) =
            decode_request_parts_payload(&request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(ranges, vec![(0, payload_for_server.len() as u64)]);

        let sending_part = encode_sending_part(
            &file_hash,
            0,
            payload_for_server.len() as u64,
            &payload_for_server,
            false,
        )
        .unwrap();
        stream.write_all(&sending_part).await.unwrap();
    });

    let result = download_file_from_peer_test!(
        Ipv4Addr::LOCALHOST,
        &Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::LOCALHOST,
            tcp_port: peer_addr.port(),
            client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
        },
        Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        &Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        &transfer_runtime,
        "queued.epub".to_string(),
        32_768,
        Duration::from_secs(1),
    )
    .await
    .unwrap();

    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    server.await.unwrap();
}

#[test]
fn download_read_timeout_uses_earliest_queue_deadline() {
    let now = tokio::time::Instant::now();
    let read_timeout = next_download_read_timeout(
        now,
        Duration::from_secs(300),
        None,
        Some(now + Duration::from_secs(20)),
        None,
    );
    assert_eq!(read_timeout, Duration::from_secs(20));
}

#[test]
fn download_read_timeout_uses_earliest_part_deadline() {
    let now = tokio::time::Instant::now();
    let read_timeout = next_download_read_timeout(
        now,
        Duration::from_secs(300),
        Some(Duration::from_secs(120)),
        Some(now + Duration::from_secs(25)),
        Some(now + Duration::from_secs(7)),
    );
    assert_eq!(read_timeout, Duration::from_secs(7));
}

#[test]
fn download_read_timeout_immediately_wakes_for_elapsed_deadline() {
    let now = tokio::time::Instant::now();
    let read_timeout = next_download_read_timeout(
        now,
        Duration::from_secs(300),
        None,
        Some(now - Duration::from_secs(1)),
        None,
    );
    assert_eq!(read_timeout, Duration::ZERO);
}

#[test]
fn download_window_starts_with_one_block_before_any_completed_payload() {
    let job = new_transfer_job(
        Ed2kHash::from_bytes([0x21; 16]),
        "window.iso".to_string(),
        ED2K_PART_SIZE * 5,
    );
    let manifest = Ed2kResumeManifest::new(&job);
    let limits = select_download_window_limits(&manifest, 0, 0, tokio::time::Instant::now());
    assert_eq!(
        limits,
        DownloadWindowLimits {
            max_pending_blocks: 1,
            min_pending_blocks: 1,
        }
    );
}

#[test]
fn download_window_grows_for_fast_large_transfer() {
    let job = new_transfer_job(
        Ed2kHash::from_bytes([0x31; 16]),
        "window.iso".to_string(),
        ED2K_PART_SIZE * 5,
    );
    let manifest = Ed2kResumeManifest::new(&job);
    let limits = select_download_window_limits(
        &manifest,
        3,
        1_024 * 1024,
        tokio::time::Instant::now() - Duration::from_secs(10),
    );
    assert_eq!(
        limits,
        DownloadWindowLimits {
            max_pending_blocks: 6,
            min_pending_blocks: 4,
        }
    );
}

#[test]
fn download_window_stays_small_for_slow_endgame_transfer() {
    let job = new_transfer_job(
        Ed2kHash::from_bytes([0x41; 16]),
        "window.iso".to_string(),
        ED2K_PART_SIZE * 2,
    );
    let manifest = Ed2kResumeManifest::new(&job);
    let limits = select_download_window_limits(
        &manifest,
        1,
        32 * 1024,
        tokio::time::Instant::now() - Duration::from_secs(20),
    );
    assert_eq!(
        limits,
        DownloadWindowLimits {
            max_pending_blocks: 1,
            min_pending_blocks: 1,
        }
    );
}

#[tokio::test]
async fn callback_session_with_completed_hello_starts_upload_flow() {
    let root = unique_test_dir("ed2k-callback-session-start-upload");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 32_768];
    let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "callback.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut stream = TcpStream::connect(peer_addr).await.unwrap();

        stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let public_key = tokio::time::timeout(Duration::from_secs(3), read_packet(&mut stream))
            .await
            .unwrap();
        assert_eq!(public_key[0], OP_EMULEPROT);
        assert_eq!(public_key[5], super::OP_PUBLICKEY);

        let peer_public_key = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let peer_public_key_packet = encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_public_key.public_key_payload().unwrap(),
        );
        stream.write_all(&peer_public_key_packet).await.unwrap();

        let signature = tokio::time::timeout(Duration::from_secs(3), read_packet(&mut stream))
            .await
            .unwrap();
        assert_eq!(signature[0], OP_EMULEPROT);
        assert_eq!(signature[5], super::OP_SIGNATURE);

        let request_filename =
            tokio::time::timeout(Duration::from_secs(3), read_packet(&mut stream))
                .await
                .unwrap();
        assert_eq!(request_filename[0], OP_EDONKEYPROT);
        assert_eq!(request_filename[5], super::OP_REQUESTFILENAME);
        assert_eq!(&request_filename[6..22], &file_hash.0);

        let request_sources =
            tokio::time::timeout(Duration::from_secs(3), read_packet(&mut stream))
                .await
                .unwrap();
        assert_eq!(request_sources[0], OP_EMULEPROT);
        assert_eq!(request_sources[5], super::OP_REQUESTSOURCES2);

        let aich_file_hash_request =
            tokio::time::timeout(Duration::from_secs(3), read_packet(&mut stream))
                .await
                .unwrap();
        assert_eq!(aich_file_hash_request[0], OP_EMULEPROT);
        assert_eq!(aich_file_hash_request[5], super::OP_AICHFILEHASHREQ);
        assert_eq!(&aich_file_hash_request[6..22], &file_hash.0);

        let filename_answer =
            super::encode_request_filename_answer(&file_hash, "callback.epub").unwrap();
        stream.write_all(&filename_answer).await.unwrap();

        let start_upload = tokio::time::timeout(Duration::from_secs(3), read_packet(&mut stream))
            .await
            .unwrap();
        assert_eq!(start_upload[0], OP_EDONKEYPROT);
        assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
        assert_eq!(&start_upload[6..22], &file_hash.0);
    });

    let (stream, remote_addr) = listener.accept().await.unwrap();
    let mut transport = Ed2kTransport {
        stream,
        prefetched: VecDeque::new(),
        receive_cipher: None,
        send_cipher: None,
        mode: Ed2kTransportMode::Plaintext,
    };
    let secure_ident = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );

    let result = drive_download_session(DownloadSessionOptions {
        transport: &mut transport,
        peer_addr: remote_addr,
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
        secure_ident: secure_ident.as_ref(),
        transfer_runtime: &transfer_runtime,
        file_hash,
        file_hash_hex: &file_hash_hex,
        timeout: Duration::from_secs(3),
        send_initial_requests: true,
        initial_hello_complete: true,
        initial_secure_ident_started: true,
    })
    .await
    .unwrap();

    assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(!manifest.completed);
    server.await.unwrap();
}

#[tokio::test]
async fn large_file_download_falls_back_to_upload_request_when_hashset_stalls() {
    let root = unique_test_dir("ed2k-large-file-hashset-stall-fallback");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; (ED2K_PART_SIZE as usize) + 32_768];
    let md4_hashset = payload
        .chunks(ED2K_PART_SIZE as usize)
        .map(|chunk| Md4::digest(chunk).into())
        .collect::<Vec<[u8; 16]>>();
    let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(
        Md4::digest(md4_hashset.iter().flatten().copied().collect::<Vec<u8>>()).into(),
    );
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "captured-fallback.iso".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_public_key_for_server = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let hello = read_packet(&mut stream).await;
        assert_eq!(hello[0], OP_EDONKEYPROT);
        assert_eq!(hello[5], OP_HELLO);

        let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [0x42; 16],
            client_id: 0x5912_0559,
            tcp_port: peer_addr.port(),
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });
        stream.write_all(&hello_answer).await.unwrap();

        let secure_ident_probe = read_packet(&mut stream).await;
        assert_eq!(secure_ident_probe[0], OP_EMULEPROT);
        assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);

        stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let public_key = read_packet(&mut stream).await;
        assert_eq!(public_key[0], OP_EMULEPROT);
        assert_eq!(public_key[5], super::OP_PUBLICKEY);

        let peer_public_key_packet = encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_public_key_for_server.public_key_payload().unwrap(),
        );
        stream.write_all(&peer_public_key_packet).await.unwrap();

        let signature = read_packet(&mut stream).await;
        assert_eq!(signature[0], OP_EMULEPROT);
        assert_eq!(signature[5], super::OP_SIGNATURE);

        let peer_signature = encode_packet(OP_EMULEPROT, super::OP_SIGNATURE, &[0xAA; 49]);
        stream.write_all(&peer_signature).await.unwrap();

        let startup_request = read_packet(&mut stream).await;
        assert_startup_multipacket_ext2(
            startup_request[0],
            startup_request[5],
            &startup_request[6..],
            &file_hash,
            payload_for_server.len() as u64,
            true,
        );

        let startup_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload_for_server.len() as u64,
            "captured.epub",
            true,
        );
        stream.write_all(&startup_answer).await.unwrap();

        let hashset_request = read_packet(&mut stream).await;
        assert_eq!(hashset_request[0], OP_EMULEPROT);
        assert_eq!(hashset_request[5], super::OP_HASHSETREQUEST2);
        let (requested_identifier, request_options) =
            super::decode_hashset_request2(&hashset_request[6..]).unwrap();
        assert_eq!(requested_identifier.file_hash, file_hash);
        assert_eq!(
            requested_identifier.file_size,
            Some(payload_for_server.len() as u64)
        );
        assert!(request_options.request_md4);
        assert!(!request_options.request_aich);

        let start_upload = read_packet(&mut stream).await;
        assert_eq!(start_upload[0], OP_EDONKEYPROT);
        assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
        assert_eq!(&start_upload[6..22], &file_hash.0);

        let hashset_answer = super::encode_hashset_answer2(
            &super::Ed2kFileIdentifier {
                file_hash,
                file_size: Some(payload_for_server.len() as u64),
                aich_root: None,
            },
            Some(&md4_hashset),
            None,
        )
        .unwrap();
        stream.write_all(&hashset_answer).await.unwrap();

        let accept = encode_accept_upload_req();
        stream.write_all(&accept).await.unwrap();

        let request_parts = read_packet(&mut stream).await;
        let request_uses_i64 = request_parts[5] == super::OP_REQUESTPARTS_I64;
        if request_uses_i64 {
            assert_eq!(request_parts[0], OP_EMULEPROT);
        } else {
            assert_eq!(request_parts[0], OP_EDONKEYPROT);
            assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        }
        let (requested_hash, ranges) =
            decode_request_parts_payload(&request_parts[6..], request_uses_i64).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(
            ranges,
            vec![(
                0,
                super::ED2K_EMBLOCK_SIZE.min(payload_for_server.len() as u64)
            )]
        );
        let (start, end) = ranges[0];
        let start_index = usize::try_from(start).unwrap();
        let end_index = usize::try_from(end).unwrap();
        let sending_part = encode_sending_part(
            &file_hash,
            start,
            end,
            &payload_for_server[start_index..end_index],
            request_uses_i64,
        )
        .unwrap();
        stream.write_all(&sending_part).await.unwrap();
    });

    let result = download_file_from_peer_test!(
        Ipv4Addr::LOCALHOST,
        &Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::LOCALHOST,
            tcp_port: peer_addr.port(),
            client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
        },
        Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        &Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        &transfer_runtime,
        "captured-fallback.iso".to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(!manifest.completed);
    assert_eq!(
        manifest.pieces[0].state,
        crate::ed2k_transfer::Ed2kTransferState::Missing
    );
    assert_eq!(manifest.pieces[0].bytes_written, super::ED2K_EMBLOCK_SIZE);
    server.await.unwrap();
}
