use super::*;

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
