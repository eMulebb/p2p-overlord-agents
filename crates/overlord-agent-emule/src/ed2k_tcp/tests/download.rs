use super::*;

#[tokio::test]
async fn small_file_download_waits_for_peer_signature_before_start_upload() {
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

    let root = unique_test_dir("ed2k-small-file-capture");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 2_409_452];
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
    let payload_for_server = payload.clone();
    let peer_public_key_for_server = Arc::clone(&peer_public_key);
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

        let peer_challenge =
            encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
        stream.write_all(&peer_challenge).await.unwrap();

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

        // Oracle-shaped sessions keep file startup traffic behind the full
        // secure-ident roundtrip, so no filename/upload request should
        // arrive before the peer signature closes the exchange.
        assert!(
            tokio::time::timeout(Duration::from_millis(150), read_packet(&mut stream))
                .await
                .is_err(),
            "startup requests must wait for peer OP_SIGNATURE"
        );

        let peer_signature = encode_packet(OP_EMULEPROT, super::OP_SIGNATURE, &[0xAA; 49]);
        stream.write_all(&peer_signature).await.unwrap();

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
        (180 * 1024) as u64,
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
async fn small_file_download_accepts_split_sending_part_frames() {
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

    let root = unique_test_dir("ed2k-small-file-split-sendingpart");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 180 * 1024];
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
    let payload_for_server = payload.clone();
    let peer_public_key_for_server = Arc::clone(&peer_public_key);
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
        let peer_challenge =
            encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
        stream.write_all(&peer_challenge).await.unwrap();

        let public_key = read_packet(&mut stream).await;
        assert_eq!(public_key[5], super::OP_PUBLICKEY);
        let peer_public_key_packet = encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_public_key_for_server.public_key_payload().unwrap(),
        );
        stream.write_all(&peer_public_key_packet).await.unwrap();

        let signature = read_packet(&mut stream).await;
        assert_eq!(signature[5], super::OP_SIGNATURE);
        let peer_signature = encode_packet(OP_EMULEPROT, super::OP_SIGNATURE, &[0xAA; 49]);
        stream.write_all(&peer_signature).await.unwrap();

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
            "captured.epub",
            false,
        );
        stream.write_all(&filename_answer).await.unwrap();

        let start_upload = read_packet(&mut stream).await;
        assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
        let accept = encode_accept_upload_req();
        stream.write_all(&accept).await.unwrap();

        let request_parts = read_packet(&mut stream).await;
        assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        let (requested_hash, ranges) =
            decode_request_parts_payload(&request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        let (start, end) = ranges[0];
        let midpoint = start + ((end - start) / 2);

        let first_fragment = encode_sending_part(
            &file_hash,
            start,
            midpoint,
            &payload_for_server
                [usize::try_from(start).unwrap()..usize::try_from(midpoint).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&first_fragment).await.unwrap();

        let second_fragment = encode_sending_part(
            &file_hash,
            midpoint,
            end,
            &payload_for_server[usize::try_from(midpoint).unwrap()..usize::try_from(end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&second_fragment).await.unwrap();
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
        (180 * 1024) as u64,
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
async fn hash_only_small_file_download_learns_metadata_from_startup_answer() {
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

    let root = unique_test_dir("ed2k-hash-only-small-file-download");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x41; 180 * 1024];
    let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let placeholder_name = format!("ed2k-{file_hash_hex}.bin");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_public_key = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    let payload_for_server = payload.clone();
    let peer_public_key_for_server = Arc::clone(&peer_public_key);
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
        let peer_challenge =
            encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
        stream.write_all(&peer_challenge).await.unwrap();

        let public_key = read_packet(&mut stream).await;
        assert_eq!(public_key[5], super::OP_PUBLICKEY);
        let peer_public_key_packet = encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_public_key_for_server.public_key_payload().unwrap(),
        );
        stream.write_all(&peer_public_key_packet).await.unwrap();

        let signature = read_packet(&mut stream).await;
        assert_eq!(signature[5], super::OP_SIGNATURE);
        let peer_signature = encode_packet(OP_EMULEPROT, super::OP_SIGNATURE, &[0xAA; 49]);
        stream.write_all(&peer_signature).await.unwrap();

        let startup_request = read_packet(&mut stream).await;
        assert_startup_multipacket_ext2(
            startup_request[0],
            startup_request[5],
            &startup_request[6..],
            &file_hash,
            0,
            false,
        );

        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload_for_server.len() as u64,
            "captured.epub",
            false,
        );
        stream.write_all(&filename_answer).await.unwrap();

        let start_upload = read_packet(&mut stream).await;
        assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
        let accept = encode_accept_upload_req();
        stream.write_all(&accept).await.unwrap();

        let request_parts = read_packet(&mut stream).await;
        assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        let (requested_hash, ranges) =
            decode_request_parts_payload(&request_parts[6..], false).unwrap();
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
    server.await.unwrap();
}

#[tokio::test]
async fn small_file_download_accepts_split_compressed_part_frames() {
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

    let root = unique_test_dir("ed2k-small-file-split-compressedpart");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 8 * 1024];
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
    let peer_public_key_for_server = Arc::clone(&peer_public_key);
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
        let peer_challenge =
            encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
        stream.write_all(&peer_challenge).await.unwrap();

        let public_key = read_packet(&mut stream).await;
        assert_eq!(public_key[5], super::OP_PUBLICKEY);
        let peer_public_key_packet = encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_public_key_for_server.public_key_payload().unwrap(),
        );
        stream.write_all(&peer_public_key_packet).await.unwrap();

        let signature = read_packet(&mut stream).await;
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
            false,
        );

        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload_for_server.len() as u64,
            "captured.epub",
            false,
        );
        stream.write_all(&filename_answer).await.unwrap();

        let start_upload = read_packet(&mut stream).await;
        assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
        stream.write_all(&encode_accept_upload_req()).await.unwrap();

        let request_parts = read_packet(&mut stream).await;
        assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        let (requested_hash, ranges) =
            decode_request_parts_payload(&request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(ranges, vec![(0, payload_for_server.len() as u64)]);

        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&payload_for_server).unwrap();
        let compressed = encoder.finish().unwrap();
        let split_at = (compressed.len() / 2).max(1);

        let first_fragment = super::encode_compressed_part_fragment(
            &file_hash,
            0,
            compressed.len(),
            &compressed[..split_at],
            false,
        )
        .unwrap();
        stream.write_all(&first_fragment).await.unwrap();

        let second_fragment = super::encode_compressed_part_fragment(
            &file_hash,
            0,
            compressed.len(),
            &compressed[split_at..],
            false,
        )
        .unwrap();
        stream.write_all(&second_fragment).await.unwrap();
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
    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    server.await.unwrap();
}

#[tokio::test]
async fn small_file_download_accepts_obfuscated_packed_startup_and_compressed_part_frames() {
    let root = unique_test_dir("ed2k-small-file-obfuscated-packed-compressedpart");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 8 * 1024];
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
    let peer_user_hash = [0x42; 16];
    let peer_public_key = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    let peer_public_key_for_server = Arc::clone(&peer_public_key);
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut transport = Ed2kTransport::accept(stream, peer_user_hash).await.unwrap();
        assert_eq!(transport.mode, Ed2kTransportMode::Obfuscated);

        let hello = transport.read_packet().await.unwrap().unwrap();
        assert_eq!(hello.protocol, OP_EDONKEYPROT);
        assert_eq!(hello.opcode, OP_HELLO);

        let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: peer_user_hash,
            client_id: 0x5912_0559,
            tcp_port: peer_addr.port(),
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        });
        transport.write_all(&hello_answer).await.unwrap();

        let secure_ident_probe = transport.read_packet().await.unwrap().unwrap();
        assert_eq!(secure_ident_probe.protocol, OP_EMULEPROT);
        assert_eq!(secure_ident_probe.opcode, OP_SECIDENTSTATE);

        let peer_challenge =
            encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
        transport.write_all(&peer_challenge).await.unwrap();

        let public_key = transport.read_packet().await.unwrap().unwrap();
        assert_eq!(public_key.protocol, OP_EMULEPROT);
        assert_eq!(public_key.opcode, super::OP_PUBLICKEY);

        let peer_public_key_packet = encode_packed_packet(
            super::OP_PUBLICKEY,
            &peer_public_key_for_server.public_key_payload().unwrap(),
        )
        .unwrap();
        transport.write_all(&peer_public_key_packet).await.unwrap();

        let signature = transport.read_packet().await.unwrap().unwrap();
        assert_eq!(signature.protocol, OP_EMULEPROT);
        assert_eq!(signature.opcode, super::OP_SIGNATURE);

        let peer_signature = encode_packed_packet(super::OP_SIGNATURE, &[0xAA; 49]).unwrap();
        transport.write_all(&peer_signature).await.unwrap();

        let startup_request = transport.read_packet().await.unwrap().unwrap();
        assert_startup_multipacket_ext2(
            startup_request.protocol,
            startup_request.opcode,
            &startup_request.payload,
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
        transport.write_all(&filename_answer).await.unwrap();

        let start_upload = transport.read_packet().await.unwrap().unwrap();
        assert_eq!(start_upload.protocol, OP_EDONKEYPROT);
        assert_eq!(start_upload.opcode, super::OP_STARTUPLOADREQ);
        transport
            .write_all(&encode_accept_upload_req())
            .await
            .unwrap();

        let request_parts = transport.read_packet().await.unwrap().unwrap();
        assert_eq!(request_parts.protocol, OP_EDONKEYPROT);
        assert_eq!(request_parts.opcode, super::OP_REQUESTPARTS);
        let (requested_hash, ranges) =
            decode_request_parts_payload(&request_parts.payload, false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(ranges, vec![(0, payload_for_server.len() as u64)]);

        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&payload_for_server).unwrap();
        let compressed = encoder.finish().unwrap();
        let split_at = (compressed.len() / 2).max(1);

        let first_fragment = super::encode_compressed_part_fragment(
            &file_hash,
            0,
            compressed.len(),
            &compressed[..split_at],
            false,
        )
        .unwrap();
        transport.write_all(&first_fragment).await.unwrap();

        let second_fragment = super::encode_compressed_part_fragment(
            &file_hash,
            0,
            compressed.len(),
            &compressed[split_at..],
            false,
        )
        .unwrap();
        transport.write_all(&second_fragment).await.unwrap();
    });

    let result = download_file_from_peer_test!(
        Ipv4Addr::LOCALHOST,
        &Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::LOCALHOST,
            tcp_port: peer_addr.port(),
            client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
            low_id: false,
            obfuscated: true,
            obfuscation_options: Some(super::EMULE_CRYPT_SUPPORTS | super::EMULE_CRYPT_REQUESTS,),
            user_hash: Some(peer_user_hash),
            source_server: None,
        },
        Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
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
    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    server.await.unwrap();
}

#[tokio::test]
async fn small_file_download_rejects_wrong_payload_and_keeps_manifest_incomplete() {
    async fn read_packet(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await?;
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await?;
        packet.extend_from_slice(&payload);
        Ok(packet)
    }

    let root = unique_test_dir("ed2k-small-file-bad-payload");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 32_768];
    let wrong_payload = vec![0x33; payload.len()];
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
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let Ok(hello) = read_packet(&mut stream).await else {
            return;
        };
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

        let Ok(_secure_ident_probe) = read_packet(&mut stream).await else {
            return;
        };
        stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let Ok(_public_key) = read_packet(&mut stream).await else {
            return;
        };
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

        let Ok(_signature) = read_packet(&mut stream).await else {
            return;
        };
        stream
            .write_all(&encode_packet(
                OP_EMULEPROT,
                super::OP_SIGNATURE,
                &[0xAA; 49],
            ))
            .await
            .unwrap();
        let Ok(startup_request) = read_packet(&mut stream).await else {
            return;
        };
        assert_startup_multipacket_ext2(
            startup_request[0],
            startup_request[5],
            &startup_request[6..],
            &file_hash,
            wrong_payload.len() as u64,
            false,
        );
        let startup_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            wrong_payload.len() as u64,
            "captured.epub",
            false,
        );
        stream.write_all(&startup_answer).await.unwrap();
        let Ok(_start_upload) = read_packet(&mut stream).await else {
            return;
        };
        stream.write_all(&encode_accept_upload_req()).await.unwrap();

        let Ok(request_parts) = read_packet(&mut stream).await else {
            return;
        };
        assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        let sending_part = encode_sending_part(
            &file_hash,
            0,
            wrong_payload.len() as u64,
            &wrong_payload,
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
async fn large_file_download_waits_for_secure_ident_before_hashset_and_upload() {
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

    let root = unique_test_dir("ed2k-large-file-secure-ident-order");
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
            "captured.iso".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();
    let source_root = unique_test_dir("ed2k-large-file-secure-ident-order-source");
    let source_runtime = Ed2kTransferRuntime::load_or_create(&source_root).unwrap();
    source_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "captured.iso".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();
    source_runtime
        .store_md4_hashset(&file_hash_hex, md4_hashset.clone())
        .await
        .unwrap();
    source_runtime
        .store_piece_data(&file_hash_hex, 0, &payload[..ED2K_PART_SIZE as usize])
        .await
        .unwrap();
    source_runtime
        .store_piece_data(&file_hash_hex, 1, &payload[ED2K_PART_SIZE as usize..])
        .await
        .unwrap();
    let source_aich = source_runtime
        .aich_hashset(&file_hash)
        .await
        .unwrap()
        .expect("missing source AICH hashset");
    let source_identifier = super::Ed2kFileIdentifier {
        file_hash,
        file_size: Some(payload.len() as u64),
        aich_root: Some(source_aich.master_hash),
    };

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

        let peer_challenge =
            encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
        stream.write_all(&peer_challenge).await.unwrap();

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

        let startup_answer = encode_startup_multipacket_ext2_answer_with_identifier(
            &source_identifier,
            "captured-fallback.iso",
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
        assert!(request_options.request_aich);

        let hashset_answer = super::encode_hashset_answer2(
            &source_identifier,
            Some(&md4_hashset),
            Some(&source_aich),
        )
        .unwrap();
        stream.write_all(&hashset_answer).await.unwrap();

        let start_upload = read_packet(&mut stream).await;
        assert_eq!(start_upload[0], OP_EDONKEYPROT);
        assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
        assert_eq!(&start_upload[6..22], &file_hash.0);

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

        let mut expected_start = 0u64;
        for (start, end) in ranges {
            assert_eq!(start, expected_start);
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
            expected_start = end;
        }
        while expected_start < payload_for_server.len() as u64 {
            let next_request_parts = read_packet(&mut stream).await;
            let next_request_uses_i64 = next_request_parts[5] == super::OP_REQUESTPARTS_I64;
            if next_request_uses_i64 {
                assert_eq!(next_request_parts[0], OP_EMULEPROT);
            } else {
                assert_eq!(next_request_parts[0], OP_EDONKEYPROT);
                assert_eq!(next_request_parts[5], super::OP_REQUESTPARTS);
            }
            let (next_requested_hash, next_ranges) =
                decode_request_parts_payload(&next_request_parts[6..], next_request_uses_i64)
                    .unwrap();
            assert_eq!(next_requested_hash, file_hash);
            assert!(!next_ranges.is_empty());
            for (start, end) in next_ranges {
                assert_eq!(start, expected_start);
                let start_index = usize::try_from(start).unwrap();
                let end_index = usize::try_from(end).unwrap();
                let sending_part = encode_sending_part(
                    &file_hash,
                    start,
                    end,
                    &payload_for_server[start_index..end_index],
                    next_request_uses_i64,
                )
                .unwrap();
                stream.write_all(&sending_part).await.unwrap();
                expected_start = end;
            }
        }
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
        "captured.iso".to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    assert!(manifest.aich_hashset_acquired);
    assert_eq!(manifest.aich_hashset.len(), 2);
    server.await.unwrap();
}

#[tokio::test]
async fn queue_only_peer_is_accepted_without_counting_as_failure() {
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

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
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

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
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

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
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

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

#[tokio::test]
async fn small_file_download_resumes_partial_piece_after_reconnect() {
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

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
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

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
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

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
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

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
    async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut packet = header.to_vec();
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        packet.extend_from_slice(&payload);
        packet
    }

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
