use super::*;

#[tokio::test]
async fn hash_only_small_file_download_learns_metadata_from_startup_answer() {
    let root = unique_test_dir("ed2k-hash-only-small-file-download");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x41; 180 * 1024];
    let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let placeholder_name = format!("ed2k-{file_hash_hex}.bin");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_public_key = test_peer_secure_ident();
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        complete_plain_secure_ident_exchange(&mut stream, peer_addr, &peer_public_key).await;
        answer_startup_metadata_with_expected_size(
            &mut stream,
            &file_hash,
            0,
            payload_for_server.len() as u64,
            "captured.epub",
            false,
        )
        .await;
        let source_exchange_answer = encode_answer_sources2(
            &file_hash,
            ED2K_SOURCE_EXCHANGE2_VERSION,
            &[SourceExchangePeer {
                ip: [127, 0, 0, 2],
                tcp_port: 4662,
                server_ip: 0,
                server_port: 0,
                user_hash: Some([0x77; 16]),
                connect_options: 0,
            }],
        );
        stream.write_all(&source_exchange_answer).await.unwrap();
        let (requested_hash, ranges) =
            accept_upload_and_read_parts_request(&mut stream, false).await;
        assert_eq!(requested_hash, file_hash);
        let (start, end) = ranges[0];

        let packet = encode_sending_part(
            &file_hash,
            start,
            end,
            &payload_for_server[usize::try_from(start).unwrap()..usize::try_from(end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&packet).await.unwrap();
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
        placeholder_name,
        0,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    assert_eq!(manifest.canonical_name, "captured.epub");
    assert_eq!(manifest.file_size, payload.len() as u64);
    assert!(manifest.sources.contains(&Ed2kSourceHint {
        ip: "127.0.0.2".to_string(),
        tcp_port: 4662,
        user_hash: Some(hex::encode([0x77; 16])),
    }));
    server.await.unwrap();
}

#[tokio::test]
async fn nofile_answer_for_requested_file_is_incomplete_not_error() {
    let root = unique_test_dir("ed2k-download-nofile-answer");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x6A; 16]);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_public_key = test_peer_secure_ident();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        complete_plain_secure_ident_exchange(&mut stream, peer_addr, &peer_public_key).await;
        stream
            .write_all(&encode_file_req_ans_nofil(&file_hash))
            .await
            .unwrap();
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
            user_hash: [0x12; 16],
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
        "missing.bin".to_string(),
        ED2K_PART_SIZE,
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
    server.await.unwrap();
}
