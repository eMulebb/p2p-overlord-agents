use super::{
    CT_EMULE_MISCOPTIONS1, CT_EMULE_MISCOPTIONS2, CT_EMULE_UDPPORTS, CT_EMULE_VERSION, CT_NAME,
    CT_VERSION, DownloadSessionOptions, DownloadWindowLimits,
    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, EDONKEY_VERSION, EMULE_CRYPT_REQUESTS,
    EMULE_CRYPT_SUPPORTS, EMULE_ENCRYPTION_METHOD_OBFUSCATION, EMULE_PROTOCOL_VERSION,
    EMULE_TCP_CRYPT_MAGIC_REQUESTER, EMULE_TCP_CRYPT_MAGIC_SERVER, EMULE_TCP_CRYPT_MAGIC_SYNC,
    EMULE_VERSION_SHORT, Ed2kHelloIdentity, Ed2kPeerConnectMode, Ed2kPeerDownloadOptions,
    Ed2kPeerDownloadOutcome, Ed2kPeerSecureIdentState, Ed2kSecureIdent, Ed2kTransport,
    Ed2kTransportMode, FirewallCheckUdpRequest, HELLO_NICKNAME, OP_EDONKEYPROT, OP_EMULEINFO,
    OP_EMULEINFOANSWER, OP_EMULEPROT, OP_FILESTATUS, OP_FWCHECKUDPREQ, OP_HELLO, OP_HELLOANSWER,
    OP_REQFILENAMEANSWER, OP_REQUESTPARTS, OP_SECIDENTSTATE, TAGTYPE_UINT32,
    begin_secure_ident_probe, build_hello_responses, connect_callback_peer,
    decode_incoming_obfuscation_header, decode_peer_payload, decode_public_key_payload,
    decode_request_parts_payload, decode_secident_state, derive_obfuscation_key,
    download_file_from_peer, drive_download_session, ed2k_string_tag_type, emule_connect_options,
    emule_misc_options1, emule_misc_options2, emule_version_tag, encode_accept_upload_req,
    encode_emule_info_answer, encode_emule_info_request, encode_hello_answer, encode_hello_request,
    encode_incoming_obfuscation_response, encode_packed_packet, encode_packet,
    encode_secident_state, encode_sending_part, enrich_hello_identity, is_mule_hello,
    next_download_read_timeout, request_udp_firewall_check, select_download_window_limits,
};
use crate::{
    ed2k_server::{Ed2kFoundSource, Ed2kServerState},
    ed2k_transfer::{
        ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kTransferRuntime, Ed2kUploadQueueConfig,
        new_transfer_job,
    },
    kad_firewall::KadFirewallState,
    paths::unique_test_dir,
};
use flate2::Decompress;
use hex::decode;
use md4::{Digest, Md4};
use overlord_kad_dht::{DhtConfig, DhtNode};
use overlord_kad_proto::{Ed2kHash, NodeId};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::EncodePublicKey,
    rand_core::OsRng,
    signature::Verifier,
};
use sha1::Sha1;
use std::collections::VecDeque;
use std::io::{self, Write as _};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock},
};

macro_rules! download_file_from_peer_test {
    (
            $bind_ip:expr,
            $peer:expr,
            $hello_identity:expr,
            $secure_ident:expr,
            $transfer_runtime:expr,
            $canonical_name:expr,
            $file_size:expr,
            $timeout:expr $(,)?
        ) => {
        download_file_from_peer(Ed2kPeerDownloadOptions {
            bind_ip: $bind_ip,
            peer: $peer,
            hello_identity: $hello_identity,
            secure_ident: $secure_ident,
            transfer_runtime: $transfer_runtime,
            canonical_name: $canonical_name,
            file_size: $file_size,
            timeout: $timeout,
        })
    };
}

macro_rules! handle_connection_test {
    (
            $stream:expr,
            $peer_addr:expr,
            $dht:expr,
            $server_state:expr,
            $kad_firewall:expr,
            $secure_ident:expr,
            $transfer_runtime:expr,
            $hello_identity:expr $(,)?
        ) => {
        super::handle_connection(
            $stream,
            $peer_addr,
            super::Ed2kConnectionContext {
                dht: $dht,
                server_state: $server_state,
                kad_firewall: $kad_firewall,
                secure_ident: $secure_ident,
                transfer_runtime: $transfer_runtime,
                hello_identity: $hello_identity,
            },
        )
    };
}

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

fn assert_startup_multipacket_ext2(
    protocol: u8,
    opcode: u8,
    payload: &[u8],
    file_hash: &Ed2kHash,
    file_size: u64,
    expect_set_req_file_id: bool,
) {
    assert_eq!(protocol, OP_EMULEPROT);
    assert_eq!(opcode, super::OP_MULTIPACKET_EXT2);
    let (identifier, mut remaining) = super::Ed2kFileIdentifier::decode(payload).unwrap();
    assert_eq!(identifier.file_hash, *file_hash);
    assert_eq!(
        identifier.file_size,
        Some(file_size).filter(|size| *size != 0)
    );

    let mut saw_request_filename = false;
    let mut saw_request_sources2 = false;
    let mut saw_set_req_file_id = false;
    while let Some((&sub_opcode, rest)) = remaining.split_first() {
        remaining = rest;
        match sub_opcode {
            super::OP_REQUESTFILENAME => {
                remaining = super::skip_request_filename_ext_info(remaining, file_size).unwrap();
                saw_request_filename = true;
            }
            super::OP_SETREQFILEID => {
                saw_set_req_file_id = true;
            }
            super::OP_REQUESTSOURCES2 => {
                assert!(remaining.len() >= 3, "short OP_REQUESTSOURCES2 sub-payload");
                assert_eq!(
                    &remaining[..3],
                    &super::encode_request_sources2_subpayload()
                );
                remaining = &remaining[3..];
                saw_request_sources2 = true;
            }
            unexpected => panic!("unexpected startup sub-op 0x{unexpected:02X}"),
        }
    }

    assert!(saw_request_filename);
    assert!(saw_request_sources2);
    assert_eq!(saw_set_req_file_id, expect_set_req_file_id);
}

fn encode_startup_multipacket_ext2_answer_with_identifier(
    file_identifier: &super::Ed2kFileIdentifier,
    file_name: &str,
    include_file_status: bool,
) -> Vec<u8> {
    super::encode_multipacket_ext2_answer(file_identifier, file_name, true, include_file_status)
        .unwrap()
}

fn encode_startup_multipacket_ext2_answer(
    file_hash: &Ed2kHash,
    file_size: u64,
    file_name: &str,
    include_file_status: bool,
) -> Vec<u8> {
    encode_startup_multipacket_ext2_answer_with_identifier(
        &super::Ed2kFileIdentifier {
            file_hash: *file_hash,
            file_size: Some(file_size).filter(|size| *size != 0),
            aich_root: None,
        },
        file_name,
        include_file_status,
    )
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

    async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
        loop {
            let packet = read_packet(stream).await;
            if packet[0] == protocol && packet[5] == opcode {
                return packet;
            }
        }
    }

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
    let dht = DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x3C; 16]),
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
    let peer_identity = Ed2kHelloIdentity {
        user_hash: [0x77; 16],
        client_id: 0x8765_4321,
        tcp_port: 46671,
        udp_port: 46672,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    stream
        .write_all(&encode_hello_request(peer_identity))
        .await
        .unwrap();
    let _hello_answer = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;

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

    async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
        loop {
            let packet = read_packet(stream).await;
            if packet[0] == protocol && packet[5] == opcode {
                return packet;
            }
        }
    }

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
    let dht = DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x4D; 16]),
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
    stream
        .write_all(&encode_hello_request(peer_identity))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;

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

    async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
        loop {
            let packet = read_packet(stream).await;
            if packet[0] == protocol && packet[5] == opcode {
                return packet;
            }
        }
    }

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

    async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
        loop {
            let packet = read_packet(stream).await;
            if packet[0] == protocol && packet[5] == opcode {
                return packet;
            }
        }
    }

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

    async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
        loop {
            let packet = read_packet(stream).await;
            if packet[0] == protocol && packet[5] == opcode {
                return packet;
            }
        }
    }

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

    async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
        loop {
            let packet = read_packet(stream).await;
            if packet[0] == protocol && packet[5] == opcode {
                return packet;
            }
        }
    }

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

    async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
        loop {
            let packet = read_packet(stream).await;
            if packet[0] == protocol && packet[5] == opcode {
                return packet;
            }
        }
    }

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

    async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
        loop {
            let packet = read_packet(stream).await;
            if packet[0] == protocol && packet[5] == opcode {
                return packet;
            }
        }
    }

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

    async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
        loop {
            let packet = read_packet(stream).await;
            if packet[0] == protocol && packet[5] == opcode {
                return packet;
            }
        }
    }

    async fn read_until_opcode_timeout(
        stream: &mut TcpStream,
        protocol: u8,
        opcode: u8,
        context: &str,
    ) -> Vec<u8> {
        tokio::time::timeout(
            Duration::from_secs(5),
            read_until_opcode(stream, protocol, opcode),
        )
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {context}"))
    }

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

#[tokio::test]
async fn udp_firewall_check_request_completes_hello_exchange_before_request() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let helper_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
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
