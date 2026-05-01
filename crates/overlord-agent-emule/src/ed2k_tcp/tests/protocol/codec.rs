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
