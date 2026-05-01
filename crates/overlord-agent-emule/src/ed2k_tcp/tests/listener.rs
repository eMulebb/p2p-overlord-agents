use super::*;

#[test]
fn upload_part_packets_split_large_uncompressed_ranges() {
    let file_hash = Ed2kHash::from_bytes([0x5A; 16]);
    let mut lcg = 0x1234_5678u32;
    let payload = (0..32_768)
        .map(|_| {
            lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (lcg >> 24) as u8
        })
        .collect::<Vec<_>>();

    let packets = super::build_upload_part_packets(
        &file_hash,
        "upload.bin",
        0,
        payload.len() as u64,
        &payload,
        false,
    )
    .unwrap();

    assert!(packets.len() > 1);
    let mut reconstructed = Vec::new();
    let mut expected_start = 0u64;
    for packet in packets {
        assert_eq!(packet.phase, "sending_part");
        let (decoded_hash, start, end, bytes) =
            super::decode_sending_part_payload(&packet.packet[6..], false).unwrap();
        assert_eq!(decoded_hash, file_hash);
        assert_eq!(start, expected_start);
        expected_start = end;
        reconstructed.extend_from_slice(&bytes);
    }

    assert_eq!(reconstructed, payload);
}

#[tokio::test]
async fn listener_upload_session_serves_verified_file_via_compressed_parts() {
    let mut payload = Vec::new();
    for index in 0..12_000u32 {
        writeln!(
            &mut payload,
            "ubuntu linux upload parity line {:05} repeated request surface",
            index % 1024
        )
        .unwrap();
    }
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();

    let root = unique_test_dir("ed2k-upload-listener-compressed");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let job = new_transfer_job(file_hash, "upload.txt".to_string(), payload.len() as u64);
    transfer_runtime.ensure_job(&job).await.unwrap();
    transfer_runtime
        .store_md4_hashset(&file_hash_hex, Vec::new())
        .await
        .unwrap();
    transfer_runtime
        .store_piece_data(&file_hash_hex, 0, &payload)
        .await
        .unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let dht = test_dht().await;
    let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
    let secure_ident = listener_secure_ident();
    let hello_identity = listener_hello_identity();

    let server = spawn_single_listener_connection(
        listener,
        dht,
        server_state,
        kad_firewall,
        secure_ident,
        Arc::clone(&transfer_runtime),
        hello_identity,
    );

    let mut stream = connect_peer_and_exchange_hello(peer_addr, peer_hello_identity()).await;

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    stream
        .write_all(&super::encode_request_filename(&file_hash, &manifest))
        .await
        .unwrap();
    let request_filename_answer =
        read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_REQFILENAMEANSWER).await;
    assert_eq!(&request_filename_answer[6..22], &file_hash.0);

    stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let accept_upload =
        read_until_opcode(&mut stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;
    assert_eq!(accept_upload.len(), 6);

    stream
        .write_all(
            &super::encode_request_parts_batch(&file_hash, &[(0, payload.len() as u64)]).unwrap(),
        )
        .await
        .unwrap();

    let mut reconstructed = Vec::new();
    let mut saw_compressed = false;
    let mut pending = None;
    while reconstructed.len() < payload.len() {
        let packet = read_packet(&mut stream).await;
        match (packet[0], packet[5]) {
            (OP_EMULEPROT, super::OP_COMPRESSEDPART) => {
                saw_compressed = true;
                let (decoded_hash, start, advertised_len, fragment) =
                    super::decode_compressed_part_fragment(&packet[6..], false).unwrap();
                assert_eq!(decoded_hash, file_hash);
                assert_eq!(start, 0);
                let pending_stream = pending.get_or_insert_with(|| super::PendingCompressedPart {
                    piece_index: 0,
                    start: 0,
                    end: payload.len() as u64,
                    advertised_compressed_len: advertised_len,
                    compressed_received: 0,
                    uncompressed_written: 0,
                    inflater: Decompress::new(true),
                });
                let (bytes, finished) =
                    super::inflate_compressed_part_fragment(pending_stream, fragment).unwrap();
                reconstructed.extend_from_slice(&bytes);
                if finished {
                    pending = None;
                }
            }
            (OP_EDONKEYPROT, super::OP_SENDINGPART) => {
                let (_, _, _, bytes) =
                    super::decode_sending_part_payload(&packet[6..], false).unwrap();
                reconstructed.extend_from_slice(&bytes);
            }
            _ => {}
        }
    }

    assert!(saw_compressed);
    assert_eq!(reconstructed, payload);
    drop(stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_startup_tolerates_source_exchange_and_aich_probe() {
    let payload = b"ubuntu linux upload startup handshake".repeat(512);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let root = unique_test_dir("ed2k-upload-listener-startup");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let job = new_transfer_job(file_hash, "startup.txt".to_string(), payload.len() as u64);
    transfer_runtime.ensure_job(&job).await.unwrap();
    transfer_runtime
        .store_md4_hashset(&file_hash_hex, Vec::new())
        .await
        .unwrap();
    transfer_runtime
        .store_piece_data(&file_hash_hex, 0, &payload)
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
        0
    );

    let modern_hashset_request = super::encode_hashset_request2(
        &super::Ed2kFileIdentifier::from_manifest(&manifest).unwrap(),
        super::Ed2kHashsetRequestOptions {
            request_md4: true,
            request_aich: false,
        },
    )
    .unwrap();
    stream.write_all(&modern_hashset_request).await.unwrap();
    let modern_hashset_answer =
        read_until_opcode(&mut stream, OP_EMULEPROT, super::OP_HASHSETANSWER2).await;
    let returned = super::decode_hashset_answer2(&modern_hashset_answer[6..]).unwrap();
    assert_eq!(returned.file_identifier.file_hash, file_hash);
    assert_eq!(
        returned.file_identifier.file_size,
        Some(payload.len() as u64)
    );
    assert!(returned.md4_hashset.is_none());
    assert!(returned.aich_hashset.is_none());

    stream
        .write_all(&super::encode_aich_file_hash_request(&file_hash))
        .await
        .unwrap();
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

#[tokio::test]
async fn listener_hashset_request2_returns_aich_when_available() {
    let mut payload = vec![0x5A; ED2K_PART_SIZE as usize];
    payload.extend_from_slice(&vec![0x37; 32_768]);
    let md4_hashset = payload
        .chunks(ED2K_PART_SIZE as usize)
        .map(|chunk| Md4::digest(chunk).into())
        .collect::<Vec<[u8; 16]>>();
    let file_hash = Ed2kHash::from_bytes(
        Md4::digest(md4_hashset.iter().flatten().copied().collect::<Vec<u8>>()).into(),
    );
    let file_hash_hex = file_hash.to_string();
    let root = unique_test_dir("ed2k-upload-listener-modern-aich");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let job = new_transfer_job(
        file_hash,
        "listener-aich.iso".to_string(),
        payload.len() as u64,
    );
    transfer_runtime.ensure_job(&job).await.unwrap();
    transfer_runtime
        .store_md4_hashset(&file_hash_hex, md4_hashset.clone())
        .await
        .unwrap();
    transfer_runtime
        .store_piece_data(&file_hash_hex, 0, &payload[..ED2K_PART_SIZE as usize])
        .await
        .unwrap();
    transfer_runtime
        .store_piece_data(&file_hash_hex, 1, &payload[ED2K_PART_SIZE as usize..])
        .await
        .unwrap();
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.aich_hashset_acquired);
    let requested_identifier = super::Ed2kFileIdentifier::from_manifest(&manifest).unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let dht = DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x5D; 16]),
        udp_key: 0x5566_7788,
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
    let secure_ident = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
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

    let server = tokio::spawn({
        let transfer_runtime = Arc::clone(&transfer_runtime);
        let server_state = Arc::clone(&server_state);
        let kad_firewall = Arc::clone(&kad_firewall);
        let secure_ident = Arc::clone(&secure_ident);
        async move {
            let (stream, remote_addr) = listener.accept().await.unwrap();
            handle_connection_test!(
                stream,
                remote_addr,
                &dht,
                &server_state,
                &kad_firewall,
                &secure_ident,
                &transfer_runtime,
                hello_identity,
            )
            .await
            .unwrap();
        }
    });

    let mut stream = TcpStream::connect(peer_addr).await.unwrap();
    stream
        .write_all(&encode_hello_request(Ed2kHelloIdentity {
            user_hash: [0x41; 16],
            client_id: 0x2468_1357,
            tcp_port: 4662,
            udp_port: 4672,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        }))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;

    let modern_hashset_request = super::encode_hashset_request2(
        &requested_identifier,
        super::Ed2kHashsetRequestOptions {
            request_md4: true,
            request_aich: true,
        },
    )
    .unwrap();
    stream.write_all(&modern_hashset_request).await.unwrap();
    let modern_hashset_answer =
        read_until_opcode(&mut stream, OP_EMULEPROT, super::OP_HASHSETANSWER2).await;
    let returned = super::decode_hashset_answer2(&modern_hashset_answer[6..]).unwrap();
    assert_eq!(returned.file_identifier.file_hash, file_hash);
    assert_eq!(
        returned.file_identifier.aich_root,
        requested_identifier.aich_root
    );
    assert_eq!(returned.md4_hashset.unwrap().len(), 2);
    let returned_aich = returned
        .aich_hashset
        .expect("missing returned AICH hashset");
    assert_eq!(
        returned_aich.master_hash,
        requested_identifier.aich_root.unwrap()
    );
    assert_eq!(returned_aich.part_hashes.len(), 2);

    drop(stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_promotes_waiter_after_disconnect() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-disconnect",
        listener_test_identity(0x22, 0x1234_5678, 41001, 41000),
        [0x3D; 16],
        0x1122_3344,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued.txt", vec![0x51; 4096])
        .await;
    let server = runtime.spawn_listener_connections(2);

    let first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x31, 0x0102_0304, 4661, 4665),
        &file.file_hash,
    )
    .await;
    let mut second_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x32, 0x0506_0708, 4662, 4666),
        &file.file_hash,
        1,
    )
    .await;

    drop(first_stream);

    wait_for_upload_accept_timeout(&mut second_stream).await;
    drop(second_stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_promotes_waiter_after_cancel_transfer() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-cancel",
        listener_test_identity(0x23, 0x2233_4455, 41002, 41003),
        [0x3E; 16],
        0x5566_7788,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued.txt", vec![0x61; 4096])
        .await;
    let server = runtime.spawn_listener_connections(2);

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x41, 0x1111_1111, 4661, 4665),
        &file.file_hash,
    )
    .await;
    let mut second_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x42, 0x2222_2222, 4662, 4666),
        &file.file_hash,
        1,
    )
    .await;

    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);

    wait_for_upload_accept_timeout(&mut second_stream).await;
    drop(second_stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_refreshes_waiting_rank_before_promotion() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-refresh",
        listener_test_identity(0x51, 0x3141_5926, 41002, 41003),
        [0x4E; 16],
        0x2233_4455,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued.txt", vec![0x71; 4096])
        .await;
    let server = runtime.spawn_listener_connections(2);

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x61, 0x1111_2222, 4661, 4665),
        &file.file_hash,
    )
    .await;
    let mut second_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x62, 0x2222_3333, 4662, 4666),
        &file.file_hash,
        1,
    )
    .await;

    wait_for_queue_rank_timeout(&mut second_stream, 1).await;

    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);

    wait_for_upload_accept_timeout(&mut second_stream).await;
    drop(second_stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_reconnects_waiter_by_hello_identity() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-reconnect-hello",
        listener_test_identity(0x71, 0x4242_2424, 41002, 41003),
        [0x5E; 16],
        0x6677_8899,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let file = runtime
        .seed_verified_upload_file("queued.txt", vec![0x7B; 4096])
        .await;
    let server = runtime.spawn_listener_loop();

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x81, 0x1111_1111, 4661, 4665),
        &file.file_hash,
    )
    .await;

    let queued_identity = listener_test_identity(0x91, 0x3333_3333, 4662, 4666);
    let queued_stream =
        connect_peer_until_queue_rank(runtime.peer_addr, queued_identity, &file.file_hash, 1).await;
    drop(queued_stream);

    let mut reconnected_stream =
        connect_peer_until_queue_rank(runtime.peer_addr, queued_identity, &file.file_hash, 1).await;

    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);

    wait_for_upload_accept_timeout(&mut reconnected_stream).await;
    drop(reconnected_stream);
    server.abort();
}

#[tokio::test]
async fn listener_upload_queue_preserves_waiter_rank_across_file_switch() {
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-queue-file-switch",
        listener_test_identity(0x71, 0x4343_2525, 41002, 41003),
        [0x6E; 16],
        0x7788_99AA,
    )
    .await;
    runtime.use_one_slot_upload_queue().await;
    let first_file = runtime
        .seed_verified_upload_file("queued-one.txt", vec![0x7B; 4096])
        .await;
    let second_file = runtime
        .seed_verified_upload_file("queued-two.txt", vec![0x8C; 4096])
        .await;
    let server = runtime.spawn_listener_loop();

    let mut first_stream = connect_peer_until_upload_accepted(
        runtime.peer_addr,
        listener_test_identity(0x81, 0x1111_1111, 4661, 4665),
        &first_file.file_hash,
    )
    .await;
    let mut queued_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0x91, 0x3333_3333, 4662, 4666),
        &first_file.file_hash,
        1,
    )
    .await;
    let mut trailing_stream = connect_peer_until_queue_rank(
        runtime.peer_addr,
        listener_test_identity(0xA1, 0x4444_4444, 4663, 4667),
        &first_file.file_hash,
        2,
    )
    .await;

    request_upload_file(&mut queued_stream, &second_file.file_hash).await;
    wait_for_queue_rank(&mut queued_stream, 1).await;
    wait_for_queue_rank_timeout(&mut trailing_stream, 2).await;

    send_cancel_transfer(&mut first_stream).await;
    drop(first_stream);

    wait_for_upload_accept_timeout(&mut queued_stream).await;

    drop(queued_stream);
    drop(trailing_stream);
    server.abort();
}

#[tokio::test]
async fn listener_upload_peer_can_resume_partial_download_after_reconnect() {
    let payload = (0..32_768u32)
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-resume-reconnect",
        listener_test_identity(0xA1, 0x5151_0101, 41002, 41003),
        [0x6E; 16],
        0x99AA_5500,
    )
    .await;
    let file = runtime
        .seed_verified_upload_file("resume.bin", payload)
        .await;
    let server = runtime.spawn_listener_loop();

    let peer_identity = listener_test_identity(0xB1, 0x7777_0001, 4662, 4666);
    let first_end = (file.payload.len() as u64) / 2;
    let second_start = first_end;
    let second_end = file.payload.len() as u64;

    let mut first_stream =
        connect_peer_until_upload_accepted(runtime.peer_addr, peer_identity, &file.file_hash).await;
    request_upload_parts(&mut first_stream, &file.file_hash, &[(0, first_end)]).await;
    let first_bytes = read_upload_bytes(&mut first_stream, &file.file_hash, 0, first_end).await;
    assert_eq!(
        first_bytes,
        file.payload[0..usize::try_from(first_end).unwrap()].to_vec()
    );
    drop(first_stream);

    let mut resumed_stream =
        connect_peer_until_upload_accepted(runtime.peer_addr, peer_identity, &file.file_hash).await;
    request_upload_parts(
        &mut resumed_stream,
        &file.file_hash,
        &[(second_start, second_end)],
    )
    .await;
    let resumed_bytes = read_upload_bytes(
        &mut resumed_stream,
        &file.file_hash,
        second_start,
        second_end,
    )
    .await;
    assert_eq!(
        resumed_bytes,
        file.payload[usize::try_from(second_start).unwrap()..usize::try_from(second_end).unwrap()]
            .to_vec()
    );

    send_cancel_transfer(&mut resumed_stream).await;
    drop(resumed_stream);
    server.abort();
}
