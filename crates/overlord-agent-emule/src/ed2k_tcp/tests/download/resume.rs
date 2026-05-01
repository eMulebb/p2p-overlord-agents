use super::*;

#[tokio::test]
async fn small_file_download_resumes_partial_piece_after_reconnect() {
    let root = unique_test_dir("ed2k-small-file-download-resume-reconnect");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 32_768];
    let split = 8_192usize;
    let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let source_name = "resume-download.epub";
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            source_name.to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let peer_public_key = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );

        let (mut first_stream, _) = listener.accept().await.unwrap();
        let _hello = read_packet(&mut first_stream).await;
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
        first_stream.write_all(&hello_answer).await.unwrap();

        let _secure_ident_probe = read_packet(&mut first_stream).await;
        first_stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let _public_key = read_packet(&mut first_stream).await;
        let peer_public_key_packet = encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_public_key.public_key_payload().unwrap(),
        );
        first_stream
            .write_all(&peer_public_key_packet)
            .await
            .unwrap();

        let _signature = read_packet(&mut first_stream).await;
        first_stream
            .write_all(&encode_packet(
                OP_EMULEPROT,
                super::OP_SIGNATURE,
                &[0xAA; 49],
            ))
            .await
            .unwrap();

        let startup_request = read_packet(&mut first_stream).await;
        assert_startup_multipacket_ext2(
            startup_request[0],
            startup_request[5],
            &startup_request[6..],
            &file_hash,
            payload_for_server.len() as u64,
            false,
        );
        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload_for_server.len() as u64,
            source_name,
            false,
        );
        first_stream.write_all(&filename_answer).await.unwrap();

        let _start_upload = read_packet(&mut first_stream).await;
        first_stream
            .write_all(&encode_accept_upload_req())
            .await
            .unwrap();

        let first_request_parts = read_packet(&mut first_stream).await;
        assert_eq!(first_request_parts[5], super::OP_REQUESTPARTS);
        let (requested_hash, first_ranges) =
            decode_request_parts_payload(&first_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(first_ranges, vec![(0, payload_for_server.len() as u64)]);

        let first_fragment = encode_sending_part(
            &file_hash,
            0,
            split as u64,
            &payload_for_server[..split],
            false,
        )
        .unwrap();
        first_stream.write_all(&first_fragment).await.unwrap();
        drop(first_stream);

        let (mut resumed_stream, _) = listener.accept().await.unwrap();
        let _hello = read_packet(&mut resumed_stream).await;
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
        resumed_stream.write_all(&hello_answer).await.unwrap();

        let _secure_ident_probe = read_packet(&mut resumed_stream).await;
        resumed_stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let _public_key = read_packet(&mut resumed_stream).await;
        let peer_public_key_packet = encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_public_key.public_key_payload().unwrap(),
        );
        resumed_stream
            .write_all(&peer_public_key_packet)
            .await
            .unwrap();

        let _signature = read_packet(&mut resumed_stream).await;
        resumed_stream
            .write_all(&encode_packet(
                OP_EMULEPROT,
                super::OP_SIGNATURE,
                &[0xAA; 49],
            ))
            .await
            .unwrap();

        let startup_request = read_packet(&mut resumed_stream).await;
        assert_startup_multipacket_ext2(
            startup_request[0],
            startup_request[5],
            &startup_request[6..],
            &file_hash,
            payload_for_server.len() as u64,
            false,
        );
        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload_for_server.len() as u64,
            source_name,
            false,
        );
        resumed_stream.write_all(&filename_answer).await.unwrap();

        let _start_upload = read_packet(&mut resumed_stream).await;
        resumed_stream
            .write_all(&encode_accept_upload_req())
            .await
            .unwrap();

        let resumed_request_parts = read_packet(&mut resumed_stream).await;
        assert_eq!(resumed_request_parts[5], super::OP_REQUESTPARTS);
        let (requested_hash, resumed_ranges) =
            decode_request_parts_payload(&resumed_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(
            resumed_ranges,
            vec![(split as u64, payload_for_server.len() as u64)]
        );

        let resumed_fragment = encode_sending_part(
            &file_hash,
            split as u64,
            payload_for_server.len() as u64,
            &payload_for_server[split..],
            false,
        )
        .unwrap();
        resumed_stream.write_all(&resumed_fragment).await.unwrap();
    });

    let source = Ed2kFoundSource {
        file_hash,
        ip: Ipv4Addr::LOCALHOST,
        tcp_port: peer_addr.port(),
        client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
        low_id: false,
        obfuscated: false,
        obfuscation_options: None,
        user_hash: None,
        source_server: None,
    };
    let secure_ident = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    let hello_identity = Ed2kHelloIdentity {
        user_hash: [0x11; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };

    let first_result = download_file_from_peer_test!(
        Ipv4Addr::LOCALHOST,
        &source,
        hello_identity,
        &secure_ident,
        &transfer_runtime,
        source_name.to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(first_result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);

    let partial_manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(!partial_manifest.completed);
    assert_eq!(
        partial_manifest.pieces[0].state,
        crate::ed2k_transfer::Ed2kTransferState::Missing
    );
    assert_eq!(partial_manifest.pieces[0].bytes_written, split as u64);

    let resumed_result = download_file_from_peer_test!(
        Ipv4Addr::LOCALHOST,
        &source,
        hello_identity,
        &secure_ident,
        &transfer_runtime,
        source_name.to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(resumed_result, Ed2kPeerDownloadOutcome::Completed);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    server.await.unwrap();
}

#[tokio::test]
async fn small_file_download_ignores_malformed_range_and_releases_pending_piece() {
    let root = unique_test_dir("ed2k-small-file-malformed-range");
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
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let _hello = read_packet(&mut stream).await;
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

        let _secure_ident_probe = read_packet(&mut stream).await;
        stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let _public_key = read_packet(&mut stream).await;
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

        let _signature = read_packet(&mut stream).await;
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
            payload_for_server.len() as u64,
            false,
        );
        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload_for_server.len() as u64,
            "captured.epub",
            false,
        );
        stream.write_all(&filename_answer).await.unwrap();
        let _start_upload = read_packet(&mut stream).await;
        stream.write_all(&encode_accept_upload_req()).await.unwrap();

        let request_parts = read_packet(&mut stream).await;
        assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        let sending_part = encode_sending_part(
            &file_hash,
            1,
            payload_for_server.len() as u64 + 1,
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
        "captured.epub".to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await;

    assert_eq!(
        result.unwrap(),
        Ed2kPeerDownloadOutcome::AcceptedButIncomplete
    );
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(!manifest.completed);
    assert_eq!(
        manifest.pieces[0].state,
        crate::ed2k_transfer::Ed2kTransferState::Missing
    );
    server.await.unwrap();
}

#[tokio::test]
async fn small_file_download_releases_piece_after_out_of_order_multi_range_response() {
    let root = unique_test_dir("ed2k-small-file-out-of-order-window");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; (super::ED2K_EMBLOCK_SIZE as usize) * 4];
    let first_end = super::ED2K_EMBLOCK_SIZE;
    let second_end = super::ED2K_EMBLOCK_SIZE * 2;
    let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "window.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let _hello = read_packet(&mut stream).await;
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

        let _secure_ident_probe = read_packet(&mut stream).await;
        stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let _public_key = read_packet(&mut stream).await;
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

        let _signature = read_packet(&mut stream).await;
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
            payload_for_server.len() as u64,
            false,
        );
        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload_for_server.len() as u64,
            "window.epub",
            false,
        );
        stream.write_all(&filename_answer).await.unwrap();

        let _start_upload = read_packet(&mut stream).await;
        stream.write_all(&encode_accept_upload_req()).await.unwrap();

        let first_request_parts = read_packet(&mut stream).await;
        let (requested_hash, first_ranges) =
            decode_request_parts_payload(&first_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(first_ranges, vec![(0, first_end)]);
        let first_fragment = encode_sending_part(
            &file_hash,
            0,
            first_end,
            &payload_for_server[..usize::try_from(first_end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&first_fragment).await.unwrap();

        let second_request_parts = read_packet(&mut stream).await;
        let (requested_hash, second_ranges) =
            decode_request_parts_payload(&second_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(second_ranges, vec![(first_end, second_end)]);
        let second_fragment = encode_sending_part(
            &file_hash,
            first_end,
            second_end,
            &payload_for_server
                [usize::try_from(first_end).unwrap()..usize::try_from(second_end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&second_fragment).await.unwrap();

        let third_request_parts = read_packet(&mut stream).await;
        let (requested_hash, third_ranges) =
            decode_request_parts_payload(&third_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(
            third_ranges,
            vec![
                (second_end, second_end + super::ED2K_EMBLOCK_SIZE),
                (
                    second_end + super::ED2K_EMBLOCK_SIZE,
                    payload_for_server.len() as u64,
                ),
            ]
        );

        let (late_start, late_end) = third_ranges[1];
        let late_fragment = encode_sending_part(
            &file_hash,
            late_start,
            late_end,
            &payload_for_server
                [usize::try_from(late_start).unwrap()..usize::try_from(late_end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&late_fragment).await.unwrap();
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
        "window.epub".to_string(),
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
    assert_eq!(manifest.pieces[0].bytes_written, second_end);
    server.await.unwrap();
}

#[tokio::test]
async fn small_file_download_completes_after_out_of_order_multi_range_response() {
    let root = unique_test_dir("ed2k-small-file-out-of-order-window-complete");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x6C; (super::ED2K_EMBLOCK_SIZE as usize) * 4];
    let first_end = super::ED2K_EMBLOCK_SIZE;
    let second_end = super::ED2K_EMBLOCK_SIZE * 2;
    let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "window-complete.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let _hello = read_packet(&mut stream).await;
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

        let _secure_ident_probe = read_packet(&mut stream).await;
        stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let _public_key = read_packet(&mut stream).await;
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

        let _signature = read_packet(&mut stream).await;
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
            payload_for_server.len() as u64,
            false,
        );
        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload_for_server.len() as u64,
            "window-complete.epub",
            false,
        );
        stream.write_all(&filename_answer).await.unwrap();

        let _start_upload = read_packet(&mut stream).await;
        stream.write_all(&encode_accept_upload_req()).await.unwrap();

        let first_request_parts = read_packet(&mut stream).await;
        let (requested_hash, first_ranges) =
            decode_request_parts_payload(&first_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(first_ranges, vec![(0, first_end)]);
        let first_fragment = encode_sending_part(
            &file_hash,
            0,
            first_end,
            &payload_for_server[..usize::try_from(first_end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&first_fragment).await.unwrap();

        let second_request_parts = read_packet(&mut stream).await;
        let (requested_hash, second_ranges) =
            decode_request_parts_payload(&second_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(second_ranges, vec![(first_end, second_end)]);
        let second_fragment = encode_sending_part(
            &file_hash,
            first_end,
            second_end,
            &payload_for_server
                [usize::try_from(first_end).unwrap()..usize::try_from(second_end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&second_fragment).await.unwrap();

        let third_request_parts = read_packet(&mut stream).await;
        let (requested_hash, third_ranges) =
            decode_request_parts_payload(&third_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(
            third_ranges,
            vec![
                (second_end, second_end + super::ED2K_EMBLOCK_SIZE),
                (
                    second_end + super::ED2K_EMBLOCK_SIZE,
                    payload_for_server.len() as u64,
                ),
            ]
        );

        let (early_start, early_end) = third_ranges[0];
        let (late_start, late_end) = third_ranges[1];
        let late_fragment = encode_sending_part(
            &file_hash,
            late_start,
            late_end,
            &payload_for_server
                [usize::try_from(late_start).unwrap()..usize::try_from(late_end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&late_fragment).await.unwrap();

        let early_fragment = encode_sending_part(
            &file_hash,
            early_start,
            early_end,
            &payload_for_server
                [usize::try_from(early_start).unwrap()..usize::try_from(early_end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&early_fragment).await.unwrap();
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
        "window-complete.epub".to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    server.await.unwrap();
}

#[tokio::test]
async fn small_file_download_completes_after_out_of_order_multi_range_compressed_response() {
    let root = unique_test_dir("ed2k-small-file-out-of-order-window-compressed");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x37; (super::ED2K_EMBLOCK_SIZE as usize) * 4];
    let first_end = super::ED2K_EMBLOCK_SIZE;
    let second_end = super::ED2K_EMBLOCK_SIZE * 2;
    let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "window-complete-compressed.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let _hello = read_packet(&mut stream).await;
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

        let _secure_ident_probe = read_packet(&mut stream).await;
        stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let _public_key = read_packet(&mut stream).await;
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

        let _signature = read_packet(&mut stream).await;
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
            payload_for_server.len() as u64,
            false,
        );
        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload_for_server.len() as u64,
            "window-complete-compressed.epub",
            false,
        );
        stream.write_all(&filename_answer).await.unwrap();

        let _start_upload = read_packet(&mut stream).await;
        stream.write_all(&encode_accept_upload_req()).await.unwrap();

        let first_request_parts = read_packet(&mut stream).await;
        let (requested_hash, first_ranges) =
            decode_request_parts_payload(&first_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(first_ranges, vec![(0, first_end)]);
        let first_fragment = encode_sending_part(
            &file_hash,
            0,
            first_end,
            &payload_for_server[..usize::try_from(first_end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&first_fragment).await.unwrap();

        let second_request_parts = read_packet(&mut stream).await;
        let (requested_hash, second_ranges) =
            decode_request_parts_payload(&second_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(second_ranges, vec![(first_end, second_end)]);
        let second_fragment = encode_sending_part(
            &file_hash,
            first_end,
            second_end,
            &payload_for_server
                [usize::try_from(first_end).unwrap()..usize::try_from(second_end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&second_fragment).await.unwrap();

        let third_request_parts = read_packet(&mut stream).await;
        let (requested_hash, third_ranges) =
            decode_request_parts_payload(&third_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(
            third_ranges,
            vec![
                (second_end, second_end + super::ED2K_EMBLOCK_SIZE),
                (
                    second_end + super::ED2K_EMBLOCK_SIZE,
                    payload_for_server.len() as u64,
                ),
            ]
        );

        let (early_start, early_end) = third_ranges[0];
        let (late_start, late_end) = third_ranges[1];

        let mut late_encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        late_encoder
            .write_all(
                &payload_for_server
                    [usize::try_from(late_start).unwrap()..usize::try_from(late_end).unwrap()],
            )
            .unwrap();
        let late_compressed = late_encoder.finish().unwrap();
        let late_fragment = super::encode_compressed_part_fragment(
            &file_hash,
            late_start,
            late_compressed.len(),
            &late_compressed,
            false,
        )
        .unwrap();
        stream.write_all(&late_fragment).await.unwrap();

        let mut early_encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        early_encoder
            .write_all(
                &payload_for_server
                    [usize::try_from(early_start).unwrap()..usize::try_from(early_end).unwrap()],
            )
            .unwrap();
        let early_compressed = early_encoder.finish().unwrap();
        let early_fragment = super::encode_compressed_part_fragment(
            &file_hash,
            early_start,
            early_compressed.len(),
            &early_compressed,
            false,
        )
        .unwrap();
        stream.write_all(&early_fragment).await.unwrap();
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
        "window-complete-compressed.epub".to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    server.await.unwrap();
}
