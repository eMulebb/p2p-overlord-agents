use super::*;

#[tokio::test]
async fn listener_upload_startup_tolerates_source_exchange_and_aich_probe() {
    let payload = b"ubuntu linux upload startup handshake".repeat(512);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let no_sources_payload = b"ubuntu linux no source exchange peers".repeat(512);
    let no_sources_hash = Ed2kHash::from_bytes(Md4::digest(&no_sources_payload).into());
    let no_sources_hash_hex = no_sources_hash.to_string();
    let root = unique_test_dir("ed2k-upload-listener-startup");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let job = new_transfer_job(file_hash, "startup.txt".to_string(), payload.len() as u64);
    transfer_runtime.ensure_job(&job).await.unwrap();
    let no_sources_job = new_transfer_job(
        no_sources_hash,
        "no-sources.txt".to_string(),
        no_sources_payload.len() as u64,
    );
    transfer_runtime.ensure_job(&no_sources_job).await.unwrap();
    transfer_runtime
        .store_md4_hashset(&file_hash_hex, Vec::new())
        .await
        .unwrap();
    let aich_root = [0x7B; 20];
    transfer_runtime
        .reconcile_aich_root(&file_hash_hex, Some(aich_root))
        .await
        .unwrap();
    transfer_runtime
        .store_md4_hashset(&no_sources_hash_hex, Vec::new())
        .await
        .unwrap();
    transfer_runtime
        .store_piece_data(&file_hash_hex, 0, &payload)
        .await
        .unwrap();
    transfer_runtime
        .remember_source(
            &file_hash_hex,
            Ed2kSourceHint {
                ip: "10.20.30.40".to_string(),
                tcp_port: 4662,
                user_hash: Some(hex::encode([0x61; 16])),
            },
        )
        .await
        .unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let dht = test_dht().await;
    let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
    let secure_ident = listener_secure_ident();
    let hello_identity = Ed2kHelloIdentity {
        user_hash: [0x31; 16],
        client_id: 0x1357_2468,
        tcp_port: 41011,
        udp_port: 41010,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };

    let server = spawn_single_listener_connection(
        listener,
        dht,
        server_state,
        kad_firewall,
        secure_ident,
        Arc::clone(&transfer_runtime),
        hello_identity,
    );

    let peer_identity = Ed2kHelloIdentity {
        user_hash: [0x41; 16],
        client_id: 0x2468_1357,
        tcp_port: 4662,
        udp_port: 4672,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let mut stream = connect_peer_and_exchange_hello(peer_addr, peer_identity).await;

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    stream
        .write_all(&super::encode_request_filename(&file_hash, &manifest))
        .await
        .unwrap();
    let filename_answer =
        read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_REQFILENAMEANSWER).await;
    assert_eq!(&filename_answer[6..22], &file_hash.0);

    stream
        .write_all(&super::encode_request_sources2(&file_hash))
        .await
        .unwrap();
    let source_answer =
        read_until_opcode(&mut stream, OP_EMULEPROT, super::OP_ANSWERSOURCES2).await;
    assert_eq!(source_answer[6], super::ED2K_SOURCE_EXCHANGE2_VERSION);
    assert_eq!(&source_answer[7..23], &file_hash.0);
    assert_eq!(
        u16::from_le_bytes([source_answer[23], source_answer[24]]),
        1
    );
    assert_eq!(&source_answer[25..29], &[40, 30, 20, 10]);
    assert_eq!(
        u16::from_le_bytes([source_answer[29], source_answer[30]]),
        4662
    );
    assert_eq!(&source_answer[37..53], &[0x61; 16]);
    assert_eq!(source_answer[53], 0);

    let mut older_source_request = super::encode_request_sources2(&file_hash);
    older_source_request[22] = 2;
    stream.write_all(&older_source_request).await.unwrap();
    let older_source_answer =
        read_until_opcode(&mut stream, OP_EMULEPROT, super::OP_ANSWERSOURCES2).await;
    assert_eq!(older_source_answer[6], 2);
    assert_eq!(&older_source_answer[7..23], &file_hash.0);
    assert_eq!(
        u16::from_le_bytes([older_source_answer[23], older_source_answer[24]]),
        1
    );
    assert_eq!(&older_source_answer[25..29], &[10, 20, 30, 40]);

    let mut invalid_source_request = super::encode_request_sources2(&file_hash);
    invalid_source_request[22] = 0;
    stream.write_all(&invalid_source_request).await.unwrap();

    let no_sources_manifest = transfer_runtime
        .manifest(&no_sources_hash_hex)
        .await
        .unwrap();
    stream
        .write_all(&super::encode_request_sources2(&no_sources_hash))
        .await
        .unwrap();
    let no_sources_hashset_request = super::encode_hashset_request2(
        &super::Ed2kFileIdentifier::from_manifest(&no_sources_manifest).unwrap(),
        super::Ed2kHashsetRequestOptions {
            request_md4: true,
            request_aich: false,
        },
    )
    .unwrap();
    stream.write_all(&no_sources_hashset_request).await.unwrap();
    let no_sources_hashset_answer = read_packet(&mut stream).await;
    assert_eq!(no_sources_hashset_answer[0], OP_EMULEPROT);
    assert_eq!(no_sources_hashset_answer[5], super::OP_HASHSETANSWER2);
    let returned = super::decode_hashset_answer2(&no_sources_hashset_answer[6..]).unwrap();
    assert_eq!(returned.file_identifier.file_hash, no_sources_hash);

    let modern_hashset_request = super::encode_hashset_request2(
        &super::Ed2kFileIdentifier::from_manifest(&manifest).unwrap(),
        super::Ed2kHashsetRequestOptions {
            request_md4: true,
            request_aich: false,
        },
    )
    .unwrap();
    stream.write_all(&modern_hashset_request).await.unwrap();
    let modern_hashset_answer = read_packet(&mut stream).await;
    assert_eq!(modern_hashset_answer[0], OP_EMULEPROT);
    assert_eq!(modern_hashset_answer[5], super::OP_HASHSETANSWER2);
    let returned = super::decode_hashset_answer2(&modern_hashset_answer[6..]).unwrap();
    assert_eq!(returned.file_identifier.file_hash, file_hash);
    assert_eq!(
        returned.file_identifier.file_size,
        Some(payload.len() as u64)
    );
    assert!(returned.md4_hashset.is_none());
    assert!(returned.aich_hashset.is_none());

    let request_filename = super::encode_request_filename(&file_hash, &manifest);
    let mut legacy_multipacket_payload = Vec::new();
    legacy_multipacket_payload.extend_from_slice(&file_hash.0);
    legacy_multipacket_payload.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    legacy_multipacket_payload.push(super::OP_REQUESTFILENAME);
    legacy_multipacket_payload.extend_from_slice(&request_filename[22..]);
    legacy_multipacket_payload.push(super::OP_SETREQFILEID);
    legacy_multipacket_payload.push(super::OP_AICHFILEHASHREQ);
    let legacy_multipacket = super::encode_packet(
        OP_EMULEPROT,
        super::OP_MULTIPACKET_EXT,
        &legacy_multipacket_payload,
    );
    stream.write_all(&legacy_multipacket).await.unwrap();
    let legacy_answer = read_packet(&mut stream).await;
    assert_eq!(legacy_answer[0], OP_EMULEPROT);
    assert_eq!(legacy_answer[5], super::OP_MULTIPACKETANSWER);
    assert_eq!(&legacy_answer[6..22], &file_hash.0);
    let mut legacy_remaining = &legacy_answer[22..];
    assert_eq!(legacy_remaining[0], super::OP_REQFILENAMEANSWER);
    let name_len = usize::from(u16::from_le_bytes([
        legacy_remaining[1],
        legacy_remaining[2],
    ]));
    assert_eq!(&legacy_remaining[3..3 + name_len], b"startup.txt");
    legacy_remaining = &legacy_remaining[3 + name_len..];
    assert_eq!(legacy_remaining[0], super::OP_FILESTATUS);
    assert_eq!(&legacy_remaining[1..3], &0u16.to_le_bytes());
    legacy_remaining = &legacy_remaining[3..];
    assert_eq!(legacy_remaining[0], super::OP_AICHFILEHASHANS);
    assert_eq!(&legacy_remaining[1..21], &aich_root);
    assert_eq!(legacy_remaining.len(), 21);

    stream
        .write_all(&super::encode_aich_file_hash_request(&file_hash))
        .await
        .unwrap();
    let aich_answer = read_packet(&mut stream).await;
    assert_eq!(aich_answer[0], OP_EMULEPROT);
    assert_eq!(aich_answer[5], super::OP_AICHFILEHASHANS);
    let (returned_hash, returned_aich_root) =
        super::decode_aich_file_hash_answer(&aich_answer[6..]).unwrap();
    assert_eq!(returned_hash, file_hash);
    assert_eq!(returned_aich_root, aich_root);

    stream
        .write_all(&super::encode_packet(OP_EMULEPROT, OP_PUBLICIP_REQ, &[]))
        .await
        .unwrap();
    let public_ip_answer = read_packet(&mut stream).await;
    assert_eq!(public_ip_answer[0], OP_EMULEPROT);
    assert_eq!(public_ip_answer[5], OP_PUBLICIP_ANSWER);
    assert_eq!(
        super::decode_public_ip_answer_payload(&public_ip_answer[6..]).unwrap(),
        Ipv4Addr::LOCALHOST
    );

    stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let accept_upload =
        read_until_opcode(&mut stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;
    assert_eq!(accept_upload.len(), 6);

    drop(stream);
    server.await.unwrap();
}
