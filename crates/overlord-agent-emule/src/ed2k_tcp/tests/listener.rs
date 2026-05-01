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
    let payload = vec![0x51; 4096];
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let root = unique_test_dir("ed2k-upload-listener-queue-disconnect");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    transfer_runtime
        .configure_upload_queue(Ed2kUploadQueueConfig {
            active_slots: 1,
            waiting_capacity: 8,
            waiting_timeout: Duration::from_secs(30),
            granted_timeout: Duration::from_secs(30),
            upload_timeout: Duration::from_secs(30),
        })
        .await;
    let job = new_transfer_job(file_hash, "queued.txt".to_string(), payload.len() as u64);
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
    let dht = DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x3D; 16]),
        udp_key: 0x1122_3344,
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
        user_hash: [0x22; 16],
        client_id: 0x1234_5678,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };

    let server = tokio::spawn({
        let dht = dht.clone();
        let transfer_runtime = Arc::clone(&transfer_runtime);
        let server_state = Arc::clone(&server_state);
        let kad_firewall = Arc::clone(&kad_firewall);
        let secure_ident = Arc::clone(&secure_ident);
        async move {
            let (first_stream, first_addr) = listener.accept().await.unwrap();
            let first = tokio::spawn({
                let dht = dht.clone();
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                async move {
                    handle_connection_test!(
                        first_stream,
                        first_addr,
                        &dht,
                        &server_state,
                        &kad_firewall,
                        &secure_ident,
                        &transfer_runtime,
                        hello_identity,
                    )
                    .await
                }
            });

            let (second_stream, second_addr) = listener.accept().await.unwrap();
            let second = tokio::spawn({
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                async move {
                    handle_connection_test!(
                        second_stream,
                        second_addr,
                        &dht,
                        &server_state,
                        &kad_firewall,
                        &secure_ident,
                        &transfer_runtime,
                        hello_identity,
                    )
                    .await
                }
            });

            first.await.unwrap().unwrap();
            second.await.unwrap().unwrap();
        }
    });

    let first_identity = Ed2kHelloIdentity {
        user_hash: [0x31; 16],
        client_id: 0x0102_0304,
        tcp_port: 4661,
        udp_port: 4665,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let mut first_stream = TcpStream::connect(peer_addr).await.unwrap();
    first_stream
        .write_all(&encode_hello_request(first_identity))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    first_stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;

    let second_identity = Ed2kHelloIdentity {
        user_hash: [0x32; 16],
        client_id: 0x0506_0708,
        tcp_port: 4662,
        udp_port: 4666,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let mut second_stream = TcpStream::connect(peer_addr).await.unwrap();
    second_stream
        .write_all(&encode_hello_request(second_identity))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut second_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    second_stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let queue_ranking =
        read_until_opcode(&mut second_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
    assert_eq!(u16::from_le_bytes([queue_ranking[6], queue_ranking[7]]), 1);

    drop(first_stream);

    let promoted = tokio::time::timeout(
        Duration::from_secs(3),
        read_until_opcode(
            &mut second_stream,
            OP_EDONKEYPROT,
            super::OP_ACCEPTUPLOADREQ,
        ),
    )
    .await
    .unwrap();
    assert_eq!(promoted.len(), 6);
    drop(second_stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_promotes_waiter_after_cancel_transfer() {
    let payload = vec![0x61; 4096];
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let root = unique_test_dir("ed2k-upload-listener-queue-cancel");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    transfer_runtime
        .configure_upload_queue(Ed2kUploadQueueConfig {
            active_slots: 1,
            waiting_capacity: 8,
            waiting_timeout: Duration::from_secs(30),
            granted_timeout: Duration::from_secs(30),
            upload_timeout: Duration::from_secs(30),
        })
        .await;
    let job = new_transfer_job(file_hash, "queued.txt".to_string(), payload.len() as u64);
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
    let dht = DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x3E; 16]),
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
        user_hash: [0x23; 16],
        client_id: 0x2233_4455,
        tcp_port: 41002,
        udp_port: 41003,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };

    let server = tokio::spawn({
        let dht = dht.clone();
        let transfer_runtime = Arc::clone(&transfer_runtime);
        let server_state = Arc::clone(&server_state);
        let kad_firewall = Arc::clone(&kad_firewall);
        let secure_ident = Arc::clone(&secure_ident);
        async move {
            let (first_stream, first_addr) = listener.accept().await.unwrap();
            let first = tokio::spawn({
                let dht = dht.clone();
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                async move {
                    handle_connection_test!(
                        first_stream,
                        first_addr,
                        &dht,
                        &server_state,
                        &kad_firewall,
                        &secure_ident,
                        &transfer_runtime,
                        hello_identity,
                    )
                    .await
                }
            });

            let (second_stream, second_addr) = listener.accept().await.unwrap();
            let second = tokio::spawn({
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                async move {
                    handle_connection_test!(
                        second_stream,
                        second_addr,
                        &dht,
                        &server_state,
                        &kad_firewall,
                        &secure_ident,
                        &transfer_runtime,
                        hello_identity,
                    )
                    .await
                }
            });

            first.await.unwrap().unwrap();
            second.await.unwrap().unwrap();
        }
    });

    let first_identity = Ed2kHelloIdentity {
        user_hash: [0x41; 16],
        client_id: 0x1111_1111,
        tcp_port: 4661,
        udp_port: 4665,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let mut first_stream = TcpStream::connect(peer_addr).await.unwrap();
    first_stream
        .write_all(&encode_hello_request(first_identity))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    first_stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;

    let second_identity = Ed2kHelloIdentity {
        user_hash: [0x42; 16],
        client_id: 0x2222_2222,
        tcp_port: 4662,
        udp_port: 4666,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let mut second_stream = TcpStream::connect(peer_addr).await.unwrap();
    second_stream
        .write_all(&encode_hello_request(second_identity))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut second_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    second_stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let queue_ranking =
        read_until_opcode(&mut second_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
    assert_eq!(u16::from_le_bytes([queue_ranking[6], queue_ranking[7]]), 1);

    first_stream
        .write_all(&encode_packet(
            OP_EDONKEYPROT,
            super::OP_CANCELTRANSFER,
            &[],
        ))
        .await
        .unwrap();
    drop(first_stream);

    let promoted = tokio::time::timeout(
        Duration::from_secs(3),
        read_until_opcode(
            &mut second_stream,
            OP_EDONKEYPROT,
            super::OP_ACCEPTUPLOADREQ,
        ),
    )
    .await
    .unwrap();
    assert_eq!(promoted.len(), 6);
    drop(second_stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_refreshes_waiting_rank_before_promotion() {
    let payload = vec![0x71; 4096];
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let root = unique_test_dir("ed2k-upload-listener-queue-refresh");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    transfer_runtime
        .configure_upload_queue(Ed2kUploadQueueConfig {
            active_slots: 1,
            waiting_capacity: 8,
            waiting_timeout: Duration::from_secs(30),
            granted_timeout: Duration::from_secs(30),
            upload_timeout: Duration::from_secs(30),
        })
        .await;
    let job = new_transfer_job(file_hash, "queued.txt".to_string(), payload.len() as u64);
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
    let dht = DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x4E; 16]),
        udp_key: 0x2233_4455,
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
        user_hash: [0x51; 16],
        client_id: 0x3141_5926,
        tcp_port: 41002,
        udp_port: 41003,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };

    let server = tokio::spawn({
        let dht = dht.clone();
        let transfer_runtime = Arc::clone(&transfer_runtime);
        let server_state = Arc::clone(&server_state);
        let kad_firewall = Arc::clone(&kad_firewall);
        let secure_ident = Arc::clone(&secure_ident);
        async move {
            let (first_stream, first_addr) = listener.accept().await.unwrap();
            let first = tokio::spawn({
                let dht = dht.clone();
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                async move {
                    handle_connection_test!(
                        first_stream,
                        first_addr,
                        &dht,
                        &server_state,
                        &kad_firewall,
                        &secure_ident,
                        &transfer_runtime,
                        hello_identity,
                    )
                    .await
                }
            });

            let (second_stream, second_addr) = listener.accept().await.unwrap();
            let second = tokio::spawn({
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                async move {
                    handle_connection_test!(
                        second_stream,
                        second_addr,
                        &dht,
                        &server_state,
                        &kad_firewall,
                        &secure_ident,
                        &transfer_runtime,
                        hello_identity,
                    )
                    .await
                }
            });

            first.await.unwrap().unwrap();
            second.await.unwrap().unwrap();
        }
    });

    let first_identity = Ed2kHelloIdentity {
        user_hash: [0x61; 16],
        client_id: 0x1111_2222,
        tcp_port: 4661,
        udp_port: 4665,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let mut first_stream = TcpStream::connect(peer_addr).await.unwrap();
    first_stream
        .write_all(&encode_hello_request(first_identity))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    first_stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;

    let second_identity = Ed2kHelloIdentity {
        user_hash: [0x62; 16],
        client_id: 0x2222_3333,
        tcp_port: 4662,
        udp_port: 4666,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let mut second_stream = TcpStream::connect(peer_addr).await.unwrap();
    second_stream
        .write_all(&encode_hello_request(second_identity))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut second_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    second_stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let first_rank =
        read_until_opcode(&mut second_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
    assert_eq!(u16::from_le_bytes([first_rank[6], first_rank[7]]), 1);

    let refreshed = tokio::time::timeout(
        Duration::from_secs(2),
        read_until_opcode(&mut second_stream, OP_EMULEPROT, super::OP_QUEUERANKING),
    )
    .await
    .unwrap();
    assert_eq!(u16::from_le_bytes([refreshed[6], refreshed[7]]), 1);

    first_stream
        .write_all(&encode_packet(
            OP_EDONKEYPROT,
            super::OP_CANCELTRANSFER,
            &[],
        ))
        .await
        .unwrap();
    drop(first_stream);

    let promoted = tokio::time::timeout(
        Duration::from_secs(3),
        read_until_opcode(
            &mut second_stream,
            OP_EDONKEYPROT,
            super::OP_ACCEPTUPLOADREQ,
        ),
    )
    .await
    .unwrap();
    assert_eq!(promoted.len(), 6);
    drop(second_stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_upload_queue_reconnects_waiter_by_hello_identity() {
    let payload = vec![0x7B; 4096];
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let root = unique_test_dir("ed2k-upload-listener-queue-reconnect-hello");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    transfer_runtime
        .configure_upload_queue(Ed2kUploadQueueConfig {
            active_slots: 1,
            waiting_capacity: 8,
            waiting_timeout: Duration::from_secs(30),
            granted_timeout: Duration::from_secs(30),
            upload_timeout: Duration::from_secs(30),
        })
        .await;
    let job = new_transfer_job(file_hash, "queued.txt".to_string(), payload.len() as u64);
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
    let dht = DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x5E; 16]),
        udp_key: 0x6677_8899,
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
        user_hash: [0x71; 16],
        client_id: 0x4242_2424,
        tcp_port: 41002,
        udp_port: 41003,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };

    let server = tokio::spawn({
        let dht = dht.clone();
        let transfer_runtime = Arc::clone(&transfer_runtime);
        let server_state = Arc::clone(&server_state);
        let kad_firewall = Arc::clone(&kad_firewall);
        let secure_ident = Arc::clone(&secure_ident);
        async move {
            loop {
                let (stream, addr) = listener.accept().await.unwrap();
                let dht = dht.clone();
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                tokio::spawn(async move {
                    let _ = handle_connection_test!(
                        stream,
                        addr,
                        &dht,
                        &server_state,
                        &kad_firewall,
                        &secure_ident,
                        &transfer_runtime,
                        hello_identity,
                    )
                    .await;
                });
            }
        }
    });

    let first_identity = Ed2kHelloIdentity {
        user_hash: [0x81; 16],
        client_id: 0x1111_1111,
        tcp_port: 4661,
        udp_port: 4665,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let mut first_stream = TcpStream::connect(peer_addr).await.unwrap();
    first_stream
        .write_all(&encode_hello_request(first_identity))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    first_stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;

    let queued_identity = Ed2kHelloIdentity {
        user_hash: [0x91; 16],
        client_id: 0x3333_3333,
        tcp_port: 4662,
        udp_port: 4666,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let mut queued_stream = TcpStream::connect(peer_addr).await.unwrap();
    queued_stream
        .write_all(&encode_hello_request(queued_identity))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut queued_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    queued_stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let queue_ranking =
        read_until_opcode(&mut queued_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
    assert_eq!(u16::from_le_bytes([queue_ranking[6], queue_ranking[7]]), 1);
    drop(queued_stream);

    let mut reconnected_stream = TcpStream::connect(peer_addr).await.unwrap();
    reconnected_stream
        .write_all(&encode_hello_request(queued_identity))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut reconnected_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    reconnected_stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let refreshed_rank = read_until_opcode(
        &mut reconnected_stream,
        OP_EMULEPROT,
        super::OP_QUEUERANKING,
    )
    .await;
    assert_eq!(
        u16::from_le_bytes([refreshed_rank[6], refreshed_rank[7]]),
        1
    );

    first_stream
        .write_all(&encode_packet(
            OP_EDONKEYPROT,
            super::OP_CANCELTRANSFER,
            &[],
        ))
        .await
        .unwrap();
    drop(first_stream);

    let promoted = tokio::time::timeout(
        Duration::from_secs(3),
        read_until_opcode(
            &mut reconnected_stream,
            OP_EDONKEYPROT,
            super::OP_ACCEPTUPLOADREQ,
        ),
    )
    .await
    .unwrap();
    assert_eq!(promoted.len(), 6);
    drop(reconnected_stream);
    server.abort();
}

#[tokio::test]
async fn listener_upload_queue_preserves_waiter_rank_across_file_switch() {
    let first_payload = vec![0x7B; 4096];
    let second_payload = vec![0x8C; 4096];
    let first_file_hash = Ed2kHash::from_bytes(Md4::digest(&first_payload).into());
    let second_file_hash = Ed2kHash::from_bytes(Md4::digest(&second_payload).into());
    let first_file_hash_hex = first_file_hash.to_string();
    let second_file_hash_hex = second_file_hash.to_string();
    let root = unique_test_dir("ed2k-upload-listener-queue-file-switch");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    transfer_runtime
        .configure_upload_queue(Ed2kUploadQueueConfig {
            active_slots: 1,
            waiting_capacity: 8,
            waiting_timeout: Duration::from_secs(30),
            granted_timeout: Duration::from_secs(30),
            upload_timeout: Duration::from_secs(30),
        })
        .await;

    let first_job = new_transfer_job(
        first_file_hash,
        "queued-one.txt".to_string(),
        first_payload.len() as u64,
    );
    transfer_runtime.ensure_job(&first_job).await.unwrap();
    transfer_runtime
        .store_md4_hashset(&first_file_hash_hex, Vec::new())
        .await
        .unwrap();
    transfer_runtime
        .store_piece_data(&first_file_hash_hex, 0, &first_payload)
        .await
        .unwrap();

    let second_job = new_transfer_job(
        second_file_hash,
        "queued-two.txt".to_string(),
        second_payload.len() as u64,
    );
    transfer_runtime.ensure_job(&second_job).await.unwrap();
    transfer_runtime
        .store_md4_hashset(&second_file_hash_hex, Vec::new())
        .await
        .unwrap();
    transfer_runtime
        .store_piece_data(&second_file_hash_hex, 0, &second_payload)
        .await
        .unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let dht = DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x6E; 16]),
        udp_key: 0x7788_99AA,
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
        user_hash: [0x71; 16],
        client_id: 0x4343_2525,
        tcp_port: 41002,
        udp_port: 41003,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };

    let server = tokio::spawn({
        let dht = dht.clone();
        let transfer_runtime = Arc::clone(&transfer_runtime);
        let server_state = Arc::clone(&server_state);
        let kad_firewall = Arc::clone(&kad_firewall);
        let secure_ident = Arc::clone(&secure_ident);
        async move {
            loop {
                let (stream, addr) = listener.accept().await.unwrap();
                let dht = dht.clone();
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                tokio::spawn(async move {
                    let _ = handle_connection_test!(
                        stream,
                        addr,
                        &dht,
                        &server_state,
                        &kad_firewall,
                        &secure_ident,
                        &transfer_runtime,
                        hello_identity,
                    )
                    .await;
                });
            }
        }
    });

    let first_identity = Ed2kHelloIdentity {
        user_hash: [0x81; 16],
        client_id: 0x1111_1111,
        tcp_port: 4661,
        udp_port: 4665,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let mut first_stream = TcpStream::connect(peer_addr).await.unwrap();
    first_stream
        .write_all(&encode_hello_request(first_identity))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    first_stream
        .write_all(&super::encode_start_upload_req(&first_file_hash))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;

    let queued_identity = Ed2kHelloIdentity {
        user_hash: [0x91; 16],
        client_id: 0x3333_3333,
        tcp_port: 4662,
        udp_port: 4666,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let mut queued_stream = TcpStream::connect(peer_addr).await.unwrap();
    queued_stream
        .write_all(&encode_hello_request(queued_identity))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut queued_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    queued_stream
        .write_all(&super::encode_start_upload_req(&first_file_hash))
        .await
        .unwrap();
    let first_rank =
        read_until_opcode(&mut queued_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
    assert_eq!(u16::from_le_bytes([first_rank[6], first_rank[7]]), 1);

    let trailing_identity = Ed2kHelloIdentity {
        user_hash: [0xA1; 16],
        client_id: 0x4444_4444,
        tcp_port: 4663,
        udp_port: 4667,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let mut trailing_stream = TcpStream::connect(peer_addr).await.unwrap();
    trailing_stream
        .write_all(&encode_hello_request(trailing_identity))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut trailing_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    trailing_stream
        .write_all(&super::encode_start_upload_req(&first_file_hash))
        .await
        .unwrap();
    let trailing_rank =
        read_until_opcode(&mut trailing_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
    assert_eq!(u16::from_le_bytes([trailing_rank[6], trailing_rank[7]]), 2);

    queued_stream
        .write_all(&super::encode_start_upload_req(&second_file_hash))
        .await
        .unwrap();
    let switched_rank =
        read_until_opcode(&mut queued_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
    assert_eq!(u16::from_le_bytes([switched_rank[6], switched_rank[7]]), 1);

    let refreshed_trailing_rank = tokio::time::timeout(
        Duration::from_secs(2),
        read_until_opcode(&mut trailing_stream, OP_EMULEPROT, super::OP_QUEUERANKING),
    )
    .await
    .unwrap();
    assert_eq!(
        u16::from_le_bytes([refreshed_trailing_rank[6], refreshed_trailing_rank[7]]),
        2
    );

    first_stream
        .write_all(&encode_packet(
            OP_EDONKEYPROT,
            super::OP_CANCELTRANSFER,
            &[],
        ))
        .await
        .unwrap();
    drop(first_stream);

    let promoted = tokio::time::timeout(
        Duration::from_secs(3),
        read_until_opcode(
            &mut queued_stream,
            OP_EDONKEYPROT,
            super::OP_ACCEPTUPLOADREQ,
        ),
    )
    .await
    .unwrap();
    assert_eq!(promoted.len(), 6);

    drop(queued_stream);
    drop(trailing_stream);
    server.abort();
}

#[tokio::test]
async fn listener_upload_peer_can_resume_partial_download_after_reconnect() {
    async fn read_upload_bytes(
        stream: &mut TcpStream,
        file_hash: &Ed2kHash,
        expected_start: u64,
        expected_end: u64,
    ) -> Vec<u8> {
        let mut reconstructed = Vec::new();
        let mut pending = None;
        while reconstructed.len() < usize::try_from(expected_end - expected_start).unwrap() {
            let packet = tokio::time::timeout(Duration::from_secs(5), read_packet(stream))
                .await
                .expect("timed out waiting for upload payload");
            match (packet[0], packet[5]) {
                (OP_EMULEPROT, super::OP_COMPRESSEDPART) => {
                    let (decoded_hash, start, advertised_len, fragment) =
                        super::decode_compressed_part_fragment(&packet[6..], false).unwrap();
                    assert_eq!(decoded_hash, *file_hash);
                    assert_eq!(start, expected_start);
                    let pending_stream =
                        pending.get_or_insert_with(|| super::PendingCompressedPart {
                            piece_index: 0,
                            start: expected_start,
                            end: expected_end,
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
                    let (decoded_hash, start, end, bytes) =
                        super::decode_sending_part_payload(&packet[6..], false).unwrap();
                    assert_eq!(decoded_hash, *file_hash);
                    assert_eq!(
                        start,
                        expected_start + u64::try_from(reconstructed.len()).unwrap()
                    );
                    assert_eq!(end, start + u64::try_from(bytes.len()).unwrap());
                    reconstructed.extend_from_slice(&bytes);
                }
                _ => {}
            }
        }
        reconstructed
    }

    let payload = (0..32_768u32)
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let root = unique_test_dir("ed2k-upload-listener-resume-reconnect");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let job = new_transfer_job(file_hash, "resume.bin".to_string(), payload.len() as u64);
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
    let dht = DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x6E; 16]),
        udp_key: 0x99AA_5500,
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
        user_hash: [0xA1; 16],
        client_id: 0x5151_0101,
        tcp_port: 41002,
        udp_port: 41003,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };

    let server = tokio::spawn({
        let dht = dht.clone();
        let transfer_runtime = Arc::clone(&transfer_runtime);
        let server_state = Arc::clone(&server_state);
        let kad_firewall = Arc::clone(&kad_firewall);
        let secure_ident = Arc::clone(&secure_ident);
        async move {
            loop {
                let (stream, addr) = listener.accept().await.unwrap();
                let dht = dht.clone();
                let transfer_runtime = Arc::clone(&transfer_runtime);
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                tokio::spawn(async move {
                    let _ = handle_connection_test!(
                        stream,
                        addr,
                        &dht,
                        &server_state,
                        &kad_firewall,
                        &secure_ident,
                        &transfer_runtime,
                        hello_identity,
                    )
                    .await;
                });
            }
        }
    });

    let peer_identity = Ed2kHelloIdentity {
        user_hash: [0xB1; 16],
        client_id: 0x7777_0001,
        tcp_port: 4662,
        udp_port: 4666,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let first_end = (payload.len() as u64) / 2;
    let second_start = first_end;
    let second_end = payload.len() as u64;

    let mut first_stream = TcpStream::connect(peer_addr).await.unwrap();
    first_stream
        .write_all(&encode_hello_request(peer_identity))
        .await
        .unwrap();
    let _ = read_until_opcode_timeout(
        &mut first_stream,
        OP_EDONKEYPROT,
        OP_HELLOANSWER,
        "first hello answer",
    )
    .await;
    first_stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let _ = read_until_opcode_timeout(
        &mut first_stream,
        OP_EDONKEYPROT,
        super::OP_ACCEPTUPLOADREQ,
        "first accept upload",
    )
    .await;
    first_stream
        .write_all(&super::encode_request_parts_batch(&file_hash, &[(0, first_end)]).unwrap())
        .await
        .unwrap();
    let first_bytes = read_upload_bytes(&mut first_stream, &file_hash, 0, first_end).await;
    assert_eq!(
        first_bytes,
        payload[0..usize::try_from(first_end).unwrap()].to_vec()
    );
    drop(first_stream);

    let mut resumed_stream = TcpStream::connect(peer_addr).await.unwrap();
    resumed_stream
        .write_all(&encode_hello_request(peer_identity))
        .await
        .unwrap();
    let _ = read_until_opcode_timeout(
        &mut resumed_stream,
        OP_EDONKEYPROT,
        OP_HELLOANSWER,
        "resumed hello answer",
    )
    .await;
    resumed_stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let _ = read_until_opcode_timeout(
        &mut resumed_stream,
        OP_EDONKEYPROT,
        super::OP_ACCEPTUPLOADREQ,
        "resumed accept upload",
    )
    .await;
    resumed_stream
        .write_all(
            &super::encode_request_parts_batch(&file_hash, &[(second_start, second_end)]).unwrap(),
        )
        .await
        .unwrap();

    let resumed_bytes =
        read_upload_bytes(&mut resumed_stream, &file_hash, second_start, second_end).await;
    assert_eq!(
        resumed_bytes,
        payload[usize::try_from(second_start).unwrap()..usize::try_from(second_end).unwrap()]
            .to_vec()
    );

    resumed_stream
        .write_all(&encode_packet(
            OP_EDONKEYPROT,
            super::OP_CANCELTRANSFER,
            &[],
        ))
        .await
        .unwrap();
    drop(resumed_stream);
    server.abort();
}
