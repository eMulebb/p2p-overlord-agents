use super::*;

pub(super) fn test_peer_secure_ident() -> Arc<Ed2kSecureIdent> {
    Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    )
}

pub(super) fn test_peer_hello(peer_addr: SocketAddr) -> Vec<u8> {
    encode_hello_answer(Ed2kHelloIdentity {
        user_hash: [0x42; 16],
        client_id: 0x5912_0559,
        tcp_port: peer_addr.port(),
        udp_port: 0,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    })
}

pub(super) async fn complete_plain_secure_ident_exchange(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    peer_secure_ident: &Ed2kSecureIdent,
) {
    let hello = read_packet(stream).await;
    assert_eq!(hello[0], OP_EDONKEYPROT);
    assert_eq!(hello[5], OP_HELLO);
    stream.write_all(&test_peer_hello(peer_addr)).await.unwrap();

    let secure_ident_probe = read_packet(stream).await;
    assert_eq!(secure_ident_probe[0], OP_EMULEPROT);
    assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);
    stream
        .write_all(&encode_secident_state(
            ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
            0x4436_EEAC,
        ))
        .await
        .unwrap();

    let public_key = read_packet(stream).await;
    assert_eq!(public_key[0], OP_EMULEPROT);
    assert_eq!(public_key[5], super::OP_PUBLICKEY);
    stream
        .write_all(&encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_secure_ident.public_key_payload().unwrap(),
        ))
        .await
        .unwrap();

    let signature = read_packet(stream).await;
    assert_eq!(signature[0], OP_EMULEPROT);
    assert_eq!(signature[5], super::OP_SIGNATURE);
    stream
        .write_all(&encode_packet(
            OP_EMULEPROT,
            super::OP_SIGNATURE,
            &[0xAA; 49],
        ))
        .await
        .unwrap();
}

pub(super) async fn answer_startup_metadata(
    stream: &mut TcpStream,
    file_hash: &Ed2kHash,
    file_size: u64,
    file_name: &str,
    include_file_status: bool,
) {
    answer_startup_metadata_with_expected_size(
        stream,
        file_hash,
        file_size,
        file_size,
        file_name,
        include_file_status,
    )
    .await;
}

pub(super) async fn answer_startup_metadata_with_expected_size(
    stream: &mut TcpStream,
    file_hash: &Ed2kHash,
    expected_request_size: u64,
    answer_file_size: u64,
    file_name: &str,
    include_file_status: bool,
) {
    let startup_request = read_packet(stream).await;
    assert_startup_multipacket_ext2(
        startup_request[0],
        startup_request[5],
        &startup_request[6..],
        file_hash,
        expected_request_size,
        false,
    );
    let filename_answer = encode_startup_multipacket_ext2_answer(
        file_hash,
        answer_file_size,
        file_name,
        include_file_status,
    );
    stream.write_all(&filename_answer).await.unwrap();
}

pub(super) async fn accept_upload_and_read_parts_request(
    stream: &mut TcpStream,
    use_i64: bool,
) -> (Ed2kHash, Vec<(u64, u64)>) {
    let start_upload = read_packet(stream).await;
    assert_eq!(start_upload[0], OP_EDONKEYPROT);
    assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
    stream.write_all(&encode_accept_upload_req()).await.unwrap();

    let request_parts = read_packet(stream).await;
    let expected_opcode = if use_i64 {
        super::OP_REQUESTPARTS_I64
    } else {
        OP_REQUESTPARTS
    };
    assert_eq!(request_parts[0], OP_EDONKEYPROT);
    assert_eq!(request_parts[5], expected_opcode);
    decode_request_parts_payload(&request_parts[6..], use_i64).unwrap()
}
