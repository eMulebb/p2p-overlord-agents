use super::*;

#[test]
fn firewall_check_udp_request_roundtrip() {
    let request = FirewallCheckUdpRequest {
        internal_udp_port: 41000,
        external_udp_port: 51000,
        sender_udp_key: 0x11223344,
    };

    let encoded = request.encode();
    let decoded = FirewallCheckUdpRequest::decode(&encoded).expect("decode");

    assert_eq!(decoded, request);
}

#[test]
fn secident_state_roundtrip_matches_wire_shape() {
    let packet = encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436EEAC);

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_SECIDENTSTATE);
    assert_eq!(
        decode_secident_state(&packet[6..]).unwrap(),
        (ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436EEAC)
    );
}

#[test]
fn queue_ranking_matches_emule_twelve_byte_payload_shape() {
    let packet = super::encode_queue_ranking(7);

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], super::OP_QUEUERANKING);
    assert_eq!(&packet[6..8], &7u16.to_le_bytes());
    assert_eq!(packet.len(), 18);
    assert!(packet[8..].iter().all(|byte| *byte == 0));
}

#[test]
fn public_key_payload_rejects_mismatched_length_prefix() {
    assert!(decode_public_key_payload(&[5, 1, 2, 3]).is_err());
}

#[test]
fn file_identifier_roundtrip_matches_stock_md4_plus_size_shape() {
    let identifier = super::Ed2kFileIdentifier {
        file_hash: Ed2kHash([0xAB; 16]),
        file_size: Some(9_728_000),
        aich_root: None,
    };
    let mut payload = Vec::new();
    identifier.encode_into(&mut payload);

    assert_eq!(payload[0], 0x03);
    assert_eq!(&payload[1..17], &[0xAB; 16]);
    assert_eq!(&payload[17..25], &9_728_000u64.to_le_bytes());

    let (decoded, remaining) = super::Ed2kFileIdentifier::decode(&payload).unwrap();
    assert_eq!(decoded, identifier);
    assert!(remaining.is_empty());
}

#[test]
fn file_identifier_from_manifest_includes_persisted_aich_root() {
    let file_hash = Ed2kHash([0x52; 16]);
    let job = new_transfer_job(file_hash, "captured.iso".to_string(), ED2K_PART_SIZE + 1);
    let mut manifest = Ed2kResumeManifest::new(&job);
    manifest.aich_root = Some(hex::encode([0x7E; 20]));

    let identifier = super::Ed2kFileIdentifier::from_manifest(&manifest).unwrap();
    assert_eq!(identifier.file_hash, file_hash);
    assert_eq!(identifier.file_size, Some(ED2K_PART_SIZE + 1));
    assert_eq!(identifier.aich_root, Some([0x7E; 20]));
}

#[test]
fn file_identifier_relaxed_match_tolerates_missing_optional_fields() {
    let strict = super::Ed2kFileIdentifier {
        file_hash: Ed2kHash([0x42; 16]),
        file_size: Some(1_234),
        aich_root: Some([0x7C; 20]),
    };
    let loose = super::Ed2kFileIdentifier {
        file_hash: strict.file_hash,
        file_size: None,
        aich_root: None,
    };

    assert!(strict.matches_relaxed(&loose));
    assert!(loose.matches_relaxed(&strict));
}

#[test]
fn file_identifier_rejects_reserved_descriptor_bits() {
    let mut payload = vec![0x08];
    payload.extend_from_slice(&[0x11; 16]);
    assert!(super::Ed2kFileIdentifier::decode(&payload).is_err());
}

#[test]
fn hashset_request2_roundtrip_preserves_file_identifier_and_request_bits() {
    let file_identifier = super::Ed2kFileIdentifier {
        file_hash: Ed2kHash([0x31; 16]),
        file_size: Some(ED2K_PART_SIZE + 1),
        aich_root: Some([0x7C; 20]),
    };
    let packet = super::encode_hashset_request2(
        &file_identifier,
        super::Ed2kHashsetRequestOptions {
            request_md4: true,
            request_aich: true,
        },
    )
    .unwrap();

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], super::OP_HASHSETREQUEST2);

    let (decoded_identifier, decoded_options) =
        super::decode_hashset_request2(&packet[6..]).unwrap();
    assert_eq!(decoded_identifier, file_identifier);
    assert!(decoded_options.request_md4);
    assert!(decoded_options.request_aich);
}

#[test]
fn hashset_answer2_roundtrip_preserves_modern_md4_and_aich_sections() {
    let file_identifier = super::Ed2kFileIdentifier {
        file_hash: Ed2kHash([0x44; 16]),
        file_size: Some(ED2K_PART_SIZE + 1),
        aich_root: Some([0x7D; 20]),
    };
    let md4_hashset = vec![[0x11; 16], [0x22; 16]];
    let aich_hashset = super::Ed2kAichHashset {
        master_hash: [0x7D; 20],
        part_hashes: vec![[0x55; 20], [0x66; 20]],
    };
    let packet =
        super::encode_hashset_answer2(&file_identifier, Some(&md4_hashset), Some(&aich_hashset))
            .unwrap();

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], super::OP_HASHSETANSWER2);

    let decoded = super::decode_hashset_answer2(&packet[6..]).unwrap();
    assert_eq!(decoded.file_identifier, file_identifier);
    assert_eq!(decoded.md4_hashset.unwrap(), md4_hashset);
    assert_eq!(decoded.aich_hashset.unwrap(), aich_hashset);
}

#[test]
fn hashset_answer2_rejects_mismatched_aich_section_root() {
    let file_identifier = super::Ed2kFileIdentifier {
        file_hash: Ed2kHash([0x44; 16]),
        file_size: Some(ED2K_PART_SIZE + 1),
        aich_root: Some([0x7D; 20]),
    };
    let packet = super::encode_hashset_answer2(
        &file_identifier,
        None,
        Some(&super::Ed2kAichHashset {
            master_hash: [0x6D; 20],
            part_hashes: vec![[0x55; 20], [0x66; 20]],
        }),
    )
    .unwrap();

    assert!(super::decode_hashset_answer2(&packet[6..]).is_err());
}

#[test]
fn request_filename_answer_uses_stock_u16_string_length_prefix() {
    let packet =
        super::encode_request_filename_answer(&Ed2kHash([0x55; 16]), "captured.epub").unwrap();

    assert_eq!(packet[0], OP_EDONKEYPROT);
    assert_eq!(packet[5], OP_REQFILENAMEANSWER);
    assert_eq!(&packet[6..22], &[0x55; 16]);
    assert_eq!(
        u16::from_le_bytes([packet[22], packet[23]]) as usize,
        "captured.epub".len()
    );
    assert_eq!(&packet[24..], b"captured.epub");
}

#[test]
fn compressed_part_fragment_roundtrip_preserves_header_shape() {
    let file_hash = Ed2kHash([0xAB; 16]);
    let start = 0u64;
    let bytes = vec![0x5A; 32_768];
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&bytes).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut payload = Vec::with_capacity(16 + 4 + 4 + compressed.len());
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&(u32::try_from(start).unwrap()).to_le_bytes());
    payload.extend_from_slice(&(u32::try_from(compressed.len()).unwrap()).to_le_bytes());
    payload.extend_from_slice(&compressed);

    let (decoded_hash, decoded_start, advertised_compressed_len, decoded_fragment) =
        super::decode_compressed_part_fragment(&payload, false).unwrap();
    assert_eq!(decoded_hash, file_hash);
    assert_eq!(decoded_start, start);
    assert_eq!(advertised_compressed_len, compressed.len());
    assert_eq!(decoded_fragment, compressed);
}

#[test]
fn compressed_part_fragments_inflate_across_multiple_packets() {
    let bytes = vec![0x5A; 32_768];
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&bytes).unwrap();
    let compressed = encoder.finish().unwrap();
    let split_at = compressed.len() / 2;
    let mut pending = super::PendingCompressedPart {
        piece_index: 0,
        start: 0,
        end: bytes.len() as u64,
        advertised_compressed_len: compressed.len(),
        compressed_received: 0,
        uncompressed_written: 0,
        inflater: flate2::Decompress::new(true),
    };

    let (first_bytes, first_finished) =
        super::inflate_compressed_part_fragment(&mut pending, &compressed[..split_at]).unwrap();
    let (second_bytes, second_finished) =
        super::inflate_compressed_part_fragment(&mut pending, &compressed[split_at..]).unwrap();

    assert!(!first_finished);
    assert!(second_finished);
    assert_eq!(pending.compressed_received, compressed.len());
    assert_eq!(pending.uncompressed_written, bytes.len() as u64);
    assert_eq!([first_bytes, second_bytes].concat(), bytes);
}

#[test]
fn packed_peer_payload_decodes_to_emule_protocol() {
    let payload = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let packed = encode_packed_packet(super::OP_PUBLICKEY, &payload).unwrap();
    let (protocol, decoded) =
        decode_peer_payload(super::OP_PACKEDPROT, packed[6..].to_vec()).unwrap();

    assert_eq!(protocol, OP_EMULEPROT);
    assert_eq!(decoded, payload);
}

#[test]
fn dump_send_phases_follow_oracle_labels() {
    assert_eq!(
        super::dump::canonical_ed2k_send_phase(
            "listener",
            "hello_reply",
            Some(OP_EDONKEYPROT),
            Some(OP_HELLOANSWER),
        )
        .as_ref(),
        "hello_answer"
    );
    assert_eq!(
        super::dump::canonical_ed2k_send_phase(
            "listener",
            "request_filename",
            Some(OP_EDONKEYPROT),
            Some(OP_REQFILENAMEANSWER),
        )
        .as_ref(),
        "filename_answer"
    );
    assert_eq!(
        super::dump::canonical_ed2k_send_phase(
            "listener",
            "set_req_file_id",
            Some(OP_EDONKEYPROT),
            Some(OP_FILESTATUS),
        )
        .as_ref(),
        "file_status"
    );
    assert_eq!(
        super::dump::canonical_ed2k_send_phase(
            "native_download",
            "hello",
            Some(OP_EDONKEYPROT),
            Some(OP_HELLO),
        )
        .as_ref(),
        "hello_request"
    );
    assert_eq!(
        super::dump::canonical_ed2k_send_phase(
            "native_download",
            "request_parts",
            Some(OP_EDONKEYPROT),
            Some(OP_REQUESTPARTS),
        )
        .as_ref(),
        "session"
    );
}

#[test]
fn dump_recv_phases_follow_oracle_labels() {
    assert_eq!(
        super::dump::canonical_ed2k_recv_phase(
            "listener",
            "custom",
            OP_EDONKEYPROT,
            OP_HELLOANSWER,
        )
        .as_ref(),
        "session"
    );
    assert_eq!(
        super::dump::canonical_ed2k_recv_phase(
            "udp_firewall_check",
            "session",
            OP_EDONKEYPROT,
            OP_HELLO,
        )
        .as_ref(),
        "hello_exchange"
    );
    assert_eq!(
        super::dump::canonical_ed2k_recv_phase(
            "udp_firewall_check",
            "session",
            OP_EMULEPROT,
            OP_FWCHECKUDPREQ,
        )
        .as_ref(),
        "fwcheck_request"
    );
}

#[test]
fn secure_ident_probe_requests_key_and_signature() {
    let mut state = Ed2kPeerSecureIdentState::default();
    let packet = begin_secure_ident_probe(&mut state);
    let (request_state, challenge) = decode_secident_state(&packet[6..]).unwrap();

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_SECIDENTSTATE);
    assert_eq!(request_state, ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED);
    assert_ne!(challenge, 0);
    assert_eq!(state.challenge_for, Some(challenge));
    assert!(state.requested_peer_key);
}

#[test]
fn secure_ident_signature_matches_oracle_message_shape() {
    let identity =
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap();
    let peer_public_key = RsaPublicKey::from(&RsaPrivateKey::new(&mut OsRng, 384).unwrap())
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    let challenge = 0x4436EEAC;

    let payload = identity
        .signature_payload(&peer_public_key, challenge)
        .unwrap();
    let signature = Signature::try_from(&payload[1..]).unwrap();
    let mut message = peer_public_key.clone();
    message.extend_from_slice(&challenge.to_le_bytes());

    assert_eq!(usize::from(payload[0]), payload.len() - 1);
    assert!(
        VerifyingKey::<Sha1>::new(RsaPublicKey::from(&identity.private_key))
            .verify(&message, &signature)
            .is_ok()
    );
}

#[test]
fn emule_packet_encoding_uses_standard_header() {
    let packet = encode_packet(OP_EMULEPROT, OP_FWCHECKUDPREQ, &[1, 2, 3, 4]);

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(
        u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]),
        5
    );
    assert_eq!(packet[5], OP_FWCHECKUDPREQ);
    assert_eq!(&packet[6..], &[1, 2, 3, 4]);
}

#[test]
fn hello_request_encoding_matches_ed2k_framing() {
    let packet = encode_hello_request(Ed2kHelloIdentity {
        user_hash: [0x11; 16],
        client_id: 0x521B_5895,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: u32::from_le_bytes([176, 123, 2, 239]),
        server_port: 4232,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    });

    assert_eq!(packet[0], OP_EDONKEYPROT);
    assert_eq!(packet[5], OP_HELLO);
    assert_eq!(packet[6], 16);
    assert_eq!(&packet[7..23], &[0x11; 16]);
    assert_eq!(u16::from_le_bytes([packet[27], packet[28]]), 41001);
    assert!(u32::from_le_bytes([packet[29], packet[30], packet[31], packet[32]]) >= 6);
    assert!(
        packet
            .windows(4)
            .any(|window| window == ((41000u32 << 16) | 41000u32).to_le_bytes())
    );
}

#[test]
fn hello_answer_advertises_emule_style_tags() {
    let packet = encode_hello_answer(Ed2kHelloIdentity {
        user_hash: [0x22; 16],
        client_id: 0x521B_5895,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: u32::from_le_bytes([176, 123, 2, 239]),
        server_port: 4232,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    });
    let expected_name_header = [
        ed2k_string_tag_type(HELLO_NICKNAME.len()),
        0x01,
        0x00,
        CT_NAME,
    ];
    let expected_u32_version_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_VERSION];
    let expected_udp_ports_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_UDPPORTS];
    let expected_misc1_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_MISCOPTIONS1];
    let expected_misc2_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_MISCOPTIONS2];
    let expected_emule_version_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_VERSION];

    assert_eq!(packet[0], OP_EDONKEYPROT);
    assert_eq!(packet[5], OP_HELLOANSWER);
    assert_eq!(&packet[6..22], &[0x22; 16]);
    assert_eq!(
        u32::from_le_bytes([packet[22], packet[23], packet[24], packet[25]]),
        0x521B_5895
    );
    assert_eq!(
        u32::from_le_bytes([packet[28], packet[29], packet[30], packet[31]]),
        6
    );
    assert!(
        packet
            .windows(expected_name_header.len())
            .any(|window| window == expected_name_header)
    );
    assert!(
        packet
            .windows(expected_u32_version_header.len())
            .any(|window| window == expected_u32_version_header)
    );
    assert!(
        packet
            .windows(expected_udp_ports_header.len())
            .any(|window| window == expected_udp_ports_header)
    );
    assert!(
        packet
            .windows(expected_misc1_header.len())
            .any(|window| window == expected_misc1_header)
    );
    assert!(
        packet
            .windows(expected_misc2_header.len())
            .any(|window| window == expected_misc2_header)
    );
    assert!(
        packet
            .windows(expected_emule_version_header.len())
            .any(|window| window == expected_emule_version_header)
    );
    assert!(
        packet
            .windows(HELLO_NICKNAME.len())
            .any(|window| window == HELLO_NICKNAME.as_bytes())
    );
    assert!(
        packet
            .windows(4)
            .any(|window| window == EDONKEY_VERSION.to_le_bytes())
    );
    assert!(
        packet
            .windows(4)
            .any(|window| window == ((41000u32 << 16) | 41000u32).to_le_bytes())
    );
    assert!(
        packet
            .windows(4)
            .any(|window| window == emule_misc_options1().to_le_bytes())
    );
    assert!(packet.windows(4).any(|window| {
        window == emule_misc_options2(emule_connect_options(true), false).to_le_bytes()
    }));
    assert!(
        packet
            .windows(4)
            .any(|window| window == emule_version_tag().to_le_bytes())
    );
    assert_eq!(
        u32::from_le_bytes([
            packet[packet.len() - 6],
            packet[packet.len() - 5],
            packet[packet.len() - 4],
            packet[packet.len() - 3]
        ]),
        u32::from_le_bytes([176, 123, 2, 239])
    );
    assert_eq!(
        u16::from_le_bytes([packet[packet.len() - 2], packet[packet.len() - 1]]),
        4232
    );
}

#[test]
fn hello_answer_matches_stock_072a_plaintext_sample() {
    let packet = encode_hello_answer(Ed2kHelloIdentity {
        user_hash: [
            0x73, 0xBE, 0xC5, 0x66, 0x14, 0x0E, 0x7E, 0x60, 0x83, 0xC4, 0x50, 0xC9, 0xAF, 0x02,
            0x6F, 0x83,
        ],
        client_id: 0x521B_5895,
        tcp_port: 46671,
        udp_port: 46673,
        server_ip: u32::from_le_bytes([176, 123, 2, 239]),
        server_port: 4232,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    });

    let expected = decode(
            "e3520000004c73bec566140e7e6083c450c9af026f8395581b524fb60600000015010001654d756c65030100113c000000030100f951b651b6030100fa16421334030100fe3a2c0000030100fb00200100b07b02ef8810",
        )
        .unwrap();

    assert_eq!(packet, expected);
}

#[test]
fn emule_info_request_uses_expected_protocol_and_tag_count() {
    let packet = encode_emule_info_request(41000);

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_EMULEINFO);
    assert_eq!(packet[6], EMULE_VERSION_SHORT);
    assert_eq!(packet[7], EMULE_PROTOCOL_VERSION);
    assert_eq!(
        u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]),
        7
    );
}

#[test]
fn emule_info_answer_uses_expected_protocol_and_tag_count() {
    let packet = encode_emule_info_answer(41000);

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_EMULEINFOANSWER);
    assert_eq!(packet[6], EMULE_VERSION_SHORT);
    assert_eq!(packet[7], EMULE_PROTOCOL_VERSION);
    assert_eq!(
        u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]),
        7
    );
}

#[test]
fn encoded_hello_request_is_detected_as_mule_hello() {
    let packet = encode_hello_request(Ed2kHelloIdentity {
        user_hash: [0x11; 16],
        client_id: 0x521B_5895,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: u32::from_le_bytes([176, 123, 2, 239]),
        server_port: 4232,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    });

    assert!(is_mule_hello(&packet[6..]).unwrap());
}

#[test]
fn oracle_server_callback_hello_is_detected_as_non_mule() {
    let payload = decode(
            "105d0e3efaf60e650d1f6f873e19326f635e67bc8236120200000097016553657276657289113c000000000000",
        )
        .unwrap();

    assert!(!is_mule_hello(&payload).unwrap());
}

#[test]
fn non_mule_hello_replies_with_emule_info_then_helloanswer() {
    let payload = decode(
            "105d0e3efaf60e650d1f6f873e19326f635e67bc8236120200000097016553657276657289113c000000000000",
        )
        .unwrap();
    let replies = build_hello_responses(
        &payload,
        Ed2kHelloIdentity {
            user_hash: [0x22; 16],
            client_id: 0x521B_5895,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: u32::from_le_bytes([176, 123, 2, 239]),
            server_port: 4232,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        },
    )
    .unwrap();

    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0][0], OP_EMULEPROT);
    assert_eq!(replies[0][5], OP_EMULEINFO);
    assert_eq!(replies[1][0], OP_EDONKEYPROT);
    assert_eq!(replies[1][5], OP_HELLOANSWER);
}

#[test]
fn connect_options_request_and_support_crypt_layer() {
    assert_eq!(
        emule_connect_options(true),
        EMULE_CRYPT_SUPPORTS | EMULE_CRYPT_REQUESTS
    );
}

#[test]
fn connect_options_disable_crypt_layer_when_obfuscation_is_off() {
    assert_eq!(emule_connect_options(false), 0);
}

#[tokio::test]
async fn enrich_hello_identity_sets_direct_udp_callback_for_low_id_with_verified_udp() {
    let server_state = Arc::new(RwLock::new(Ed2kServerState {
        endpoint: Some(SocketAddr::from((Ipv4Addr::new(185, 237, 185, 226), 31031))),
        client_id: Some(0x0000_1234),
        ..Ed2kServerState::default()
    }));
    let mut firewall = KadFirewallState::default();
    firewall.udp_open = true;
    firewall.udp_verified = true;
    let kad_firewall = Arc::new(Mutex::new(firewall));

    let identity = enrich_hello_identity(
        Ed2kHelloIdentity {
            user_hash: [0xAB; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        },
        &server_state,
        &kad_firewall,
    )
    .await;

    assert!(identity.direct_udp_callback);
    assert_eq!(identity.client_id, 0x0000_1234);
    assert_eq!(identity.server_ip, u32::from_le_bytes([185, 237, 185, 226]));
    assert_eq!(identity.server_port, 31031);
}

#[tokio::test]
async fn enrich_hello_identity_keeps_direct_udp_callback_off_for_high_id() {
    let server_state = Arc::new(RwLock::new(Ed2kServerState {
        endpoint: Some(SocketAddr::from((Ipv4Addr::new(185, 237, 185, 226), 31031))),
        client_id: Some(0x521B_5895),
        ..Ed2kServerState::default()
    }));
    let mut firewall = KadFirewallState::default();
    firewall.udp_open = true;
    firewall.udp_verified = true;
    let kad_firewall = Arc::new(Mutex::new(firewall));

    let identity = enrich_hello_identity(
        Ed2kHelloIdentity {
            user_hash: [0xCD; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        },
        &server_state,
        &kad_firewall,
    )
    .await;

    assert!(!identity.direct_udp_callback);
    assert_eq!(identity.client_id, 0x521B_5895);
}

#[test]
fn incoming_obfuscation_handshake_roundtrip_encrypts_followup_packets() {
    let user_hash = [0x44; 16];
    let random_key_part = [0x11, 0x22, 0x33, 0x44];
    let client_padding = [0xAA, 0xBB, 0xCC];
    let server_padding = [0x10, 0x20];

    let mut client_send =
        derive_obfuscation_key(user_hash, EMULE_TCP_CRYPT_MAGIC_REQUESTER, random_key_part);
    let mut client_receive =
        derive_obfuscation_key(user_hash, EMULE_TCP_CRYPT_MAGIC_SERVER, random_key_part);

    let mut encrypted_request_tail = Vec::new();
    encrypted_request_tail.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
    encrypted_request_tail.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    encrypted_request_tail.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    encrypted_request_tail.push(client_padding.len() as u8);
    encrypted_request_tail.extend_from_slice(&client_padding);
    client_send.apply(&mut encrypted_request_tail);

    let mut incoming_header = [0u8; 7];
    incoming_header.copy_from_slice(&encrypted_request_tail[..7]);
    let mut server_receive =
        derive_obfuscation_key(user_hash, EMULE_TCP_CRYPT_MAGIC_REQUESTER, random_key_part);
    let (padding_len, supported_methods, requested_method) =
        decode_incoming_obfuscation_header(&mut server_receive, incoming_header).unwrap();
    assert_eq!(padding_len, client_padding.len());
    assert_eq!(supported_methods, EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    assert_eq!(requested_method, EMULE_ENCRYPTION_METHOD_OBFUSCATION);

    let mut incoming_padding = encrypted_request_tail[7..].to_vec();
    server_receive.apply(&mut incoming_padding);
    assert_eq!(incoming_padding, client_padding);

    let mut server_send =
        derive_obfuscation_key(user_hash, EMULE_TCP_CRYPT_MAGIC_SERVER, random_key_part);
    let encrypted_response =
        encode_incoming_obfuscation_response(&mut server_send, &server_padding);

    let mut decrypted_response = encrypted_response.clone();
    client_receive.apply(&mut decrypted_response);
    assert_eq!(
        u32::from_le_bytes(decrypted_response[..4].try_into().unwrap()),
        EMULE_TCP_CRYPT_MAGIC_SYNC
    );
    assert_eq!(decrypted_response[4], EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    assert_eq!(usize::from(decrypted_response[5]), server_padding.len());
    assert_eq!(&decrypted_response[6..], &server_padding);

    let plaintext_packet = encode_packet(OP_EDONKEYPROT, OP_HELLOANSWER, &[1, 2, 3, 4]);
    let mut encrypted_packet = plaintext_packet.clone();
    client_send.apply(&mut encrypted_packet);
    server_receive.apply(&mut encrypted_packet);
    assert_eq!(encrypted_packet, plaintext_packet);

    let plaintext_reply = encode_packet(OP_EMULEPROT, OP_EMULEINFOANSWER, &[9, 8, 7]);
    let mut encrypted_reply = plaintext_reply.clone();
    server_send.apply(&mut encrypted_reply);
    client_receive.apply(&mut encrypted_reply);
    assert_eq!(encrypted_reply, plaintext_reply);
}

#[tokio::test]
async fn callback_connect_uses_plaintext_when_peer_has_no_crypt_metadata() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut packet = [0u8; 6];
        stream.read_exact(&mut packet).await.unwrap();
        packet
    });

    let mode = connect_callback_peer(
        Ipv4Addr::LOCALHOST,
        peer_addr,
        Ed2kHelloIdentity {
            user_hash: [0x55; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        },
        None,
        None,
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    let packet = server.await.unwrap();
    assert_eq!(mode, Ed2kPeerConnectMode::Plaintext);
    assert_eq!(packet[0], OP_EDONKEYPROT);
    assert_eq!(packet[5], OP_HELLO);
}

#[tokio::test]
async fn callback_connect_uses_obfuscation_when_peer_supports_crypt() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_user_hash = [0x66; 16];
    let expected_hello = encode_hello_request(Ed2kHelloIdentity {
        user_hash: [0x77; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    });
    let expected_hello_for_server = expected_hello.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut prefix = [0u8; 5];
        stream.read_exact(&mut prefix).await.unwrap();
        assert!(!matches!(
            prefix[0],
            OP_EDONKEYPROT | OP_EMULEPROT | super::OP_PACKEDPROT
        ));
        let random_key_part = [prefix[1], prefix[2], prefix[3], prefix[4]];

        let mut receive_cipher = derive_obfuscation_key(
            peer_user_hash,
            EMULE_TCP_CRYPT_MAGIC_REQUESTER,
            random_key_part,
        );
        let mut send_cipher = derive_obfuscation_key(
            peer_user_hash,
            EMULE_TCP_CRYPT_MAGIC_SERVER,
            random_key_part,
        );

        let mut encrypted_header = [0u8; 7];
        stream.read_exact(&mut encrypted_header).await.unwrap();
        let (padding_len, _, requested_method) =
            decode_incoming_obfuscation_header(&mut receive_cipher, encrypted_header).unwrap();
        assert_eq!(requested_method, EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        if padding_len > 0 {
            let mut encrypted_padding = vec![0u8; padding_len];
            stream.read_exact(&mut encrypted_padding).await.unwrap();
            receive_cipher.apply(&mut encrypted_padding);
        }

        let mut response = Vec::new();
        response.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
        response.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        response.push(0);
        send_cipher.apply(&mut response);
        stream.write_all(&response).await.unwrap();

        let mut encrypted_packet = vec![0u8; expected_hello_for_server.len()];
        stream.read_exact(&mut encrypted_packet).await.unwrap();
        receive_cipher.apply(&mut encrypted_packet);
        encrypted_packet
    });

    let mode = connect_callback_peer(
        Ipv4Addr::LOCALHOST,
        peer_addr,
        Ed2kHelloIdentity {
            user_hash: [0x77; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        },
        Some(peer_user_hash),
        Some(super::EMULE_CRYPT_SUPPORTS | super::EMULE_CRYPT_REQUESTS),
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    let packet = server.await.unwrap();
    assert_eq!(mode, Ed2kPeerConnectMode::Obfuscated);
    assert_eq!(packet, expected_hello);
}

#[tokio::test]
async fn callback_connect_stays_plaintext_when_local_obfuscation_is_disabled() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let expected_hello = encode_hello_request(Ed2kHelloIdentity {
        user_hash: [0x88; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    });
    let expected_hello_for_server = expected_hello.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut packet = vec![0u8; expected_hello_for_server.len()];
        stream.read_exact(&mut packet).await.unwrap();
        let reply = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [0xAA; 16],
            client_id: 0x521B_5895,
            tcp_port: 46671,
            udp_port: 46673,
            server_ip: u32::from_le_bytes([176, 123, 2, 239]),
            server_port: 4232,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });
        stream.write_all(&reply).await.unwrap();
        packet
    });

    let mode = connect_callback_peer(
        Ipv4Addr::LOCALHOST,
        peer_addr,
        Ed2kHelloIdentity {
            user_hash: [0x88; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        Some([0x99; 16]),
        Some(super::EMULE_CRYPT_SUPPORTS | super::EMULE_CRYPT_REQUESTS),
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    let packet = server.await.unwrap();
    assert_eq!(mode, Ed2kPeerConnectMode::Plaintext);
    assert_eq!(packet, expected_hello);
}

#[tokio::test]
async fn udp_firewall_check_request_completes_hello_exchange_before_request() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let helper_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, peer_addr) = listener.accept().await.unwrap();
        assert_eq!(peer_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        let hello = read_packet(&mut stream).await;
        assert_eq!(hello[0], OP_EDONKEYPROT);
        assert_eq!(hello[5], OP_HELLO);

        let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [0x10; 16],
            client_id: 0x521B_5895,
            tcp_port: 46671,
            udp_port: 46673,
            server_ip: u32::from_le_bytes([176, 123, 2, 239]),
            server_port: 4232,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });
        stream.write_all(&hello_answer).await.unwrap();

        let emule_info = encode_emule_info_request(46673);
        stream.write_all(&emule_info).await.unwrap();

        let mut saw_emule_info_answer = false;
        let mut saw_secure_ident_probe = false;
        let mut fwcheck = None;
        for _ in 0..3 {
            let packet = read_packet(&mut stream).await;
            match (packet[0], packet[5]) {
                (OP_EMULEPROT, OP_SECIDENTSTATE) => {
                    saw_secure_ident_probe = true;
                }
                (OP_EMULEPROT, OP_EMULEINFOANSWER) => {
                    saw_emule_info_answer = true;
                }
                (OP_EMULEPROT, OP_FWCHECKUDPREQ) => {
                    fwcheck = Some(packet);
                    break;
                }
                other => panic!("unexpected helper packet {:?}", other),
            }
        }
        assert!(saw_emule_info_answer || saw_secure_ident_probe);
        fwcheck.expect("expected OP_FWCHECKUDPREQ after hello exchange")
    });

    request_udp_firewall_check(
        None,
        Ipv4Addr::LOCALHOST,
        helper_addr,
        Ed2kHelloIdentity {
            user_hash: [0x77; 16],
            client_id: 0x1234_5678,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        FirewallCheckUdpRequest {
            internal_udp_port: 41000,
            external_udp_port: 41000,
            sender_udp_key: 0xAABB_CCDD,
        },
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    let fwcheck = server.await.unwrap();
    assert_eq!(&fwcheck[6..8], &41000u16.to_le_bytes());
    assert_eq!(&fwcheck[8..10], &41000u16.to_le_bytes());
    assert_eq!(&fwcheck[10..14], &0xAABB_CCDDu32.to_le_bytes());
}

#[tokio::test]
async fn udp_firewall_check_request_skips_silent_helper_before_request() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let helper_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, peer_addr) = listener.accept().await.unwrap();
        assert_eq!(peer_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await.unwrap();
        let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; packet_len - 1];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(header[0], OP_EDONKEYPROT);
        assert_eq!(header[5], OP_HELLO);

        let mut extra_header = [0u8; 6];
        let read_result = tokio::time::timeout(
            Duration::from_millis(500),
            stream.read_exact(&mut extra_header),
        )
        .await;
        match read_result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(_)) => {
                panic!(
                    "silent helper unexpectedly received opcode 0x{:02X}",
                    extra_header[5]
                );
            }
        }
    });

    let error = request_udp_firewall_check(
        None,
        Ipv4Addr::LOCALHOST,
        helper_addr,
        Ed2kHelloIdentity {
            user_hash: [0x77; 16],
            client_id: 0x1234_5678,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        FirewallCheckUdpRequest {
            internal_udp_port: 41000,
            external_udp_port: 41000,
            sender_udp_key: 0xAABB_CCDD,
        },
        Duration::from_millis(300),
    )
    .await
    .expect_err("silent helper must not receive firewall request");
    assert!(
        error
            .to_string()
            .contains("did not complete HELLO before OP_FWCHECKUDPREQ"),
        "{error:#}"
    );

    server.await.unwrap();
}
