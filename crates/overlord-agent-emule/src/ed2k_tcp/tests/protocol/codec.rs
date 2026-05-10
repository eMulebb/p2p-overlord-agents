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
fn queue_ranking_matches_emule_twelve_byte_payload_shape() {
    let packet = super::encode_queue_ranking(7);

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], super::OP_QUEUERANKING);
    assert_eq!(&packet[6..8], &7u16.to_le_bytes());
    assert_eq!(packet.len(), 18);
    assert!(packet[8..].iter().all(|byte| *byte == 0));
}

#[test]
fn public_ip_answer_uses_stock_four_byte_ipv4_payload() {
    let packet = encode_public_ip_answer(Ipv4Addr::new(203, 0, 113, 99));

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_PUBLICIP_ANSWER);
    assert_eq!(&packet[6..], &[203, 0, 113, 99]);
    assert_eq!(
        decode_public_ip_answer_payload(&packet[6..]).unwrap(),
        Ipv4Addr::new(203, 0, 113, 99)
    );
    assert!(decode_public_ip_answer_payload(&packet[6..9]).is_err());
}

#[test]
fn port_test_answer_matches_stock_edonkey_ack_shape() {
    let packet = encode_port_test_answer();

    assert_eq!(packet[0], OP_EDONKEYPROT);
    assert_eq!(packet[5], OP_PORTTEST);
    assert_eq!(&packet[6..], &[0x12]);
}

#[test]
fn file_description_decodes_stock_rating_and_long_string() {
    let mut payload = vec![4];
    payload.extend_from_slice(&5u32.to_le_bytes());
    payload.extend_from_slice(b"clean");

    let decoded = decode_file_description_payload(&payload).unwrap();

    assert_eq!(decoded.rating, 4);
    assert_eq!(decoded.comment, "clean");
    assert!(decode_file_description_payload(&payload[..4]).is_err());
}

#[test]
fn client_id_change_decodes_stock_two_u32_payload() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0x1122_3344u32.to_le_bytes());
    payload.extend_from_slice(&0x5566_7788u32.to_le_bytes());
    payload.extend_from_slice(&[0xAA, 0xBB]);

    let decoded = decode_client_id_change_payload(&payload).unwrap();

    assert_eq!(decoded.new_user_id, 0x1122_3344);
    assert_eq!(decoded.new_server_ip, 0x5566_7788);
    assert_eq!(decoded.trailing_len, 2);
    assert!(decode_client_id_change_payload(&payload[..7]).is_err());
}

#[test]
fn kad_callback_decodes_stock_buddy_forward_shape() {
    let buddy_check = [0x44; 16];
    let file_hash = Ed2kHash([0x45; 16]);
    let mut payload = Vec::new();
    payload.extend_from_slice(&buddy_check);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&u32::from_be_bytes([203, 0, 113, 77]).to_le_bytes());
    payload.extend_from_slice(&4662u16.to_le_bytes());
    payload.push(0xAA);

    let callback = decode_kad_callback_payload(&payload).unwrap();

    assert_eq!(callback.buddy_check, buddy_check);
    assert_eq!(callback.file_hash, file_hash);
    assert_eq!(callback.peer_ip, Ipv4Addr::new(203, 0, 113, 77));
    assert_eq!(callback.peer_tcp_port, 4662);
    assert_eq!(callback.trailing_len, 1);
    assert!(decode_kad_callback_payload(&payload[..37]).is_err());
}

#[test]
fn reask_callback_tcp_decodes_buddy_forwarded_udp_reask_shape() {
    let file_hash = Ed2kHash([0x46; 16]);
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from_be_bytes([198, 51, 100, 8]).to_le_bytes());
    payload.extend_from_slice(&4672u16.to_le_bytes());
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&9u16.to_le_bytes());

    let reask = decode_reask_callback_tcp_payload(&payload).unwrap();

    assert_eq!(reask.dest_ip, Ipv4Addr::new(198, 51, 100, 8));
    assert_eq!(reask.dest_port, 4672);
    assert_eq!(reask.file_hash, file_hash);
    assert_eq!(reask.extended_info_len, 2);
    assert!(decode_reask_callback_tcp_payload(&payload[..21]).is_err());
}

#[test]
fn chat_captcha_packets_decode_minimal_stock_shapes() {
    let request = decode_chat_captcha_request_payload(&[0, 0x42, 0x4D]).unwrap();
    assert_eq!(request.tag_count, 0);
    assert_eq!(request.data_len, 2);

    assert_eq!(decode_chat_captcha_result_payload(&[2]).unwrap(), 2);
    assert!(decode_chat_captcha_request_payload(&[]).is_err());
    assert!(decode_chat_captcha_result_payload(&[]).is_err());
}

#[test]
fn preview_packets_decode_stock_hash_and_frame_shape() {
    let file_hash = Ed2kHash([0x5E; 16]);
    let mut request_payload = file_hash.0.to_vec();
    request_payload.push(0xAA);
    let request = decode_preview_request_payload(&request_payload).unwrap();
    assert_eq!(request.file_hash, file_hash);
    assert_eq!(request.trailing_len, 1);

    let mut answer_payload = file_hash.0.to_vec();
    answer_payload.push(2);
    answer_payload.extend_from_slice(&3u32.to_le_bytes());
    answer_payload.extend_from_slice(b"one");
    answer_payload.extend_from_slice(&4u32.to_le_bytes());
    answer_payload.extend_from_slice(b"two!");
    let answer = decode_preview_answer_payload(&answer_payload).unwrap();

    assert_eq!(answer.file_hash, file_hash);
    assert_eq!(answer.frame_count, 2);
    assert_eq!(answer.frame_payload_bytes, 7);
    assert_eq!(answer.trailing_len, 0);
    assert!(decode_preview_request_payload(&request_payload[..15]).is_err());
    assert!(decode_preview_answer_payload(&answer_payload[..20]).is_err());
}

#[test]
fn aich_recovery_packets_decode_stock_shapes() {
    let file_hash = Ed2kHash([0x67; 16]);
    let master_hash = [0x68; 20];
    let mut request_payload = Vec::new();
    request_payload.extend_from_slice(&file_hash.0);
    request_payload.extend_from_slice(&3u16.to_le_bytes());
    request_payload.extend_from_slice(&master_hash);

    let request = decode_aich_recovery_request_payload(&request_payload).unwrap();
    assert_eq!(request.file_hash, file_hash);
    assert_eq!(request.part, 3);
    assert_eq!(request.master_hash, master_hash);

    let failure = encode_aich_recovery_failure_answer(&file_hash);
    assert_eq!(failure[0], OP_EMULEPROT);
    assert_eq!(failure[5], OP_AICHANSWER);
    let decoded_failure = decode_aich_recovery_answer_payload(&failure[6..]).unwrap();
    assert_eq!(decoded_failure.file_hash, file_hash);
    assert_eq!(decoded_failure.part, None);
    assert_eq!(decoded_failure.master_hash, None);
    assert_eq!(decoded_failure.recovery_payload_len, 0);

    let mut answer_payload = request_payload;
    answer_payload.extend_from_slice(b"recovery");
    let answer = decode_aich_recovery_answer_payload(&answer_payload).unwrap();
    assert_eq!(answer.file_hash, file_hash);
    assert_eq!(answer.part, Some(3));
    assert_eq!(answer.master_hash, Some(master_hash));
    assert_eq!(answer.recovery_payload_len, 8);
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
fn multipacket_ext2_source_request_matches_peer_source_exchange_version() {
    let file_identifier = super::Ed2kFileIdentifier {
        file_hash: Ed2kHash([0x37; 16]),
        file_size: Some(ED2K_PART_SIZE + 1),
        aich_root: None,
    };
    let job = new_transfer_job(
        file_identifier.file_hash,
        "captured.iso".to_string(),
        ED2K_PART_SIZE + 1,
    );
    let manifest = Ed2kResumeManifest::new(&job);

    let sx2 = super::encode_multipacket_ext2_request(
        &file_identifier,
        &manifest,
        PeerSourceExchangeRequest::V2,
    );
    assert_eq!(sx2[0], OP_EMULEPROT);
    assert_eq!(sx2[5], super::OP_MULTIPACKET_EXT2);
    assert!(sx2[6..].contains(&OP_REQUESTSOURCES2));

    let sx1 = super::encode_multipacket_ext2_request(
        &file_identifier,
        &manifest,
        PeerSourceExchangeRequest::V1,
    );
    assert!(sx1[6..].contains(&OP_REQUESTSOURCES));
    assert!(!sx1[6..].contains(&OP_REQUESTSOURCES2));

    let no_sx = super::encode_multipacket_ext2_request(
        &file_identifier,
        &manifest,
        PeerSourceExchangeRequest::None,
    );
    assert!(!no_sx[6..].contains(&OP_REQUESTSOURCES));
    assert!(!no_sx[6..].contains(&OP_REQUESTSOURCES2));
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
fn aich_file_hash_answer_carries_file_hash_then_sha1_root() {
    let file_hash = Ed2kHash([0x42; 16]);
    let aich_root = [0x7A; 20];
    let packet = encode_aich_file_hash_answer(&file_hash, aich_root);

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_AICHFILEHASHANS);
    let (decoded_hash, decoded_root) = decode_aich_file_hash_answer(&packet[6..]).unwrap();

    assert_eq!(decoded_hash, file_hash);
    assert_eq!(decoded_root, aich_root);
}

#[test]
fn legacy_multipacket_answer_uses_hash_prefixed_subpackets() {
    let file_hash = Ed2kHash([0x45; 16]);
    let aich_root = [0x6D; 20];

    let packet =
        encode_multipacket_answer(&file_hash, "legacy.avi", true, true, Some(aich_root)).unwrap();

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_MULTIPACKETANSWER);
    assert_eq!(&packet[6..22], &file_hash.0);
    let mut remaining = &packet[22..];
    assert_eq!(remaining[0], OP_REQFILENAMEANSWER);
    let name_len = usize::from(u16::from_le_bytes([remaining[1], remaining[2]]));
    assert_eq!(&remaining[3..3 + name_len], b"legacy.avi");
    remaining = &remaining[3 + name_len..];
    assert_eq!(remaining[0], OP_FILESTATUS);
    assert_eq!(&remaining[1..3], &0u16.to_le_bytes());
    remaining = &remaining[3..];
    assert_eq!(remaining[0], OP_AICHFILEHASHANS);
    assert_eq!(&remaining[1..21], &aich_root);
    assert_eq!(remaining.len(), 21);
}

#[test]
fn legacy_multipacket_request_uses_ext_envelope_for_sized_peer() {
    let file_hash = Ed2kHash([0x47; 16]);
    let job = new_transfer_job(
        file_hash,
        "legacy-download.avi".to_string(),
        ED2K_PART_SIZE + 1,
    );
    let manifest = Ed2kResumeManifest::new(&job);

    let packet = encode_multipacket_request(
        &file_hash,
        &manifest,
        true,
        PeerSourceExchangeRequest::V2,
        true,
    );

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_MULTIPACKET_EXT);
    assert_eq!(&packet[6..22], &file_hash.0);
    assert_eq!(
        u64::from_le_bytes(packet[22..30].try_into().unwrap()),
        ED2K_PART_SIZE + 1
    );
    assert!(packet[30..].contains(&OP_REQUESTFILENAME));
    assert!(packet[30..].contains(&OP_SETREQFILEID));
    assert!(packet[30..].contains(&OP_REQUESTSOURCES2));
    assert!(packet[30..].contains(&OP_AICHFILEHASHREQ));
}

#[test]
fn legacy_source_answer_v1_uses_peer_advertised_sx1_version() {
    let file_hash = Ed2kHash([0x58; 16]);
    let source = SourceExchangePeer {
        ip: [192, 0, 2, 44],
        tcp_port: 4662,
        server_ip: u32::from_le_bytes([203, 0, 113, 7]),
        server_port: 4242,
        user_hash: None,
        connect_options: 0,
    };

    let packet = encode_answer_sources(&file_hash, &[source]);

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_ANSWERSOURCES);
    let (decoded_hash, decoded_sources) = decode_answer_sources_payload(&packet[6..], 4).unwrap();

    assert_eq!(decoded_hash, file_hash);
    assert_eq!(decoded_sources, vec![source]);
}

#[test]
fn legacy_source_answer_rejects_v4_shape_from_v3_peer() {
    let file_hash = Ed2kHash([0x59; 16]);
    let source = SourceExchangePeer {
        ip: [198, 51, 100, 9],
        tcp_port: 4662,
        server_ip: u32::from_le_bytes([203, 0, 113, 8]),
        server_port: 4242,
        user_hash: Some([0x7B; 16]),
        connect_options: 0x03,
    };
    let mut payload = Vec::with_capacity(16 + 2 + 29);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(&u32::from_be_bytes(source.ip).to_le_bytes());
    payload.extend_from_slice(&source.tcp_port.to_le_bytes());
    payload.extend_from_slice(&source.server_ip.to_le_bytes());
    payload.extend_from_slice(&source.server_port.to_le_bytes());
    payload.extend_from_slice(&source.user_hash.unwrap());
    payload.push(source.connect_options);

    assert!(decode_answer_sources_payload(&payload, 3).is_err());
    let (decoded_hash, decoded_sources) = decode_answer_sources_payload(&payload, 4).unwrap();

    assert_eq!(decoded_hash, file_hash);
    assert_eq!(decoded_sources, vec![source]);
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
