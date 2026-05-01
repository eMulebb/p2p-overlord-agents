use super::{
    BackgroundServerSearchRequest, CT_EMULE_VERSION, CT_NAME, CT_SERVER_FLAGS, CT_VERSION,
    ConfiguredServerEntry, EDONKEY_VERSION, EMULE_ENCRYPTION_METHOD_OBFUSCATION,
    EMULE_TCP_CRYPT_MAGIC_REQUESTER, EMULE_TCP_CRYPT_MAGIC_SERVER, EMULE_TCP_CRYPT_MAGIC_SYNC,
    EMULE_UDP_CRYPT_MAGIC_SERVER_CLIENT, EMULE_UDP_CRYPT_MAGIC_SYNC_SERVER, EMULE_VERSION_MAJOR,
    EMULE_VERSION_MINOR, EMULE_VERSION_UPDATE, Ed2kFoundSource, Ed2kHash, Ed2kSearchFile,
    Ed2kServerState, FT_FILENAME, FT_FILESIZE, FT_FILETYPE, FT_SOURCES, HELLO_NICKNAME,
    OFFER_FILE_SAMPLE_HASH, OFFER_FILE_SAMPLE_NAME, OFFER_FILE_SAMPLE_SIZE, OP_EDONKEYPROT,
    OP_GETSERVERLIST, OP_GETSOURCES, OP_GETSOURCES_OBFU, OP_GLOBGETSOURCES2, OP_LOGINREQUEST,
    OP_OFFERFILES, OP_PACKEDPROT, ResolvedServerEntry, SERVER_OBFUSCATION_PRIME_BYTES,
    SERVER_OBFUSCATION_PUBLIC_KEY_LEN, SERVER_TCP_FLAG_COMPRESSION, SERVER_TCP_FLAG_LARGEFILES,
    SERVER_TCP_FLAG_TCPOBFUSCATION, SERVER_UDP_FLAG_EXT_GETSOURCES2,
    SERVER_UDP_FLAG_UDPOBFUSCATION, SOURCE_OBFUSCATION_USER_HASH_PRESENT, ST_DESCRIPTION,
    ST_SERVERNAME, ServerSession, TAG_SHORT_NAME_MASK, TAGTYPE_UINT32, biguint_to_fixed_be,
    decode_found_sources, decode_search_result_page, decode_search_results, decode_server_ident,
    decode_server_payload, decode_server_udp_datagram, derive_server_cipher,
    derive_server_udp_cipher, ed2k_string_tag_type, encode_login_request,
    encode_offer_files_payload, encode_packet, encode_search_request, encode_server_udp_datagram,
    encode_source_request, format_server_flags, ipv4_from_client_id,
    login_identity_for_server_transport, new_ed2k_server_search_channel,
    offer_files_catalog_fingerprint, search_keyword_via_background_session,
    search_source_via_background_session, server_capabilities, server_udp_endpoint,
    should_use_server_obfuscation, source_request_opcode, validate_found_sources,
};
use crate::{
    ed2k_tcp::{Ed2kHelloIdentity, emule_connect_options},
    ed2k_transfer::Ed2kSharedEntry,
};
use flate2::{Compression, write::ZlibEncoder};
use hex::decode;
use num_bigint::BigUint;
use std::{io::Write, net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::RwLock,
};
use tokio_util::sync::CancellationToken;

fn test_server(obfuscation_port_tcp: u16, udp_flags: u32) -> ResolvedServerEntry {
    ResolvedServerEntry {
        entry: ConfiguredServerEntry {
            host: "127.0.0.1".to_string(),
            port: 4661,
            name: Some("test".to_string()),
            description: None,
            udp_flags,
            udp_key: 0,
            udp_key_ip: 0,
            obfuscation_port_tcp,
            obfuscation_port_udp: 0,
        },
        ip: Ipv4Addr::LOCALHOST,
    }
}

fn test_udp_obfuscated_server() -> ResolvedServerEntry {
    ResolvedServerEntry {
        entry: ConfiguredServerEntry {
            host: "127.0.0.1".to_string(),
            port: 4661,
            name: Some("test".to_string()),
            description: None,
            udp_flags: SERVER_UDP_FLAG_UDPOBFUSCATION | SERVER_UDP_FLAG_EXT_GETSOURCES2,
            udp_key: 0x1122_3344,
            udp_key_ip: 0x5566_7788,
            obfuscation_port_tcp: 4661,
            obfuscation_port_udp: 4675,
        },
        ip: Ipv4Addr::LOCALHOST,
    }
}

#[test]
fn server_udp_endpoint_uses_obfuscation_port_when_keyed() {
    let server = test_udp_obfuscated_server();
    assert_eq!(server_udp_endpoint(&server).port(), 4675);

    let plain_server = test_server(0, SERVER_UDP_FLAG_EXT_GETSOURCES2);
    assert_eq!(server_udp_endpoint(&plain_server).port(), 4665);
}

#[test]
fn server_udp_obfuscation_round_trips_plain_payload() {
    let server = test_udp_obfuscated_server();
    let (endpoint, packet) = encode_server_udp_datagram(&server, OP_GLOBGETSOURCES2, b"abc");

    assert_eq!(endpoint.port(), 4675);
    assert_ne!(packet[0], OP_EDONKEYPROT);

    let random_key_part = 0x7788u16;
    let mut response = vec![0x01];
    response.extend_from_slice(&random_key_part.to_le_bytes());
    response.extend_from_slice(&EMULE_UDP_CRYPT_MAGIC_SYNC_SERVER.to_le_bytes());
    response.push(0);
    response.extend_from_slice(&[OP_EDONKEYPROT, OP_GLOBGETSOURCES2, b'a', b'b', b'c']);
    let mut cipher = derive_server_udp_cipher(
        server.entry.udp_key,
        random_key_part,
        EMULE_UDP_CRYPT_MAGIC_SERVER_CLIENT,
    );
    cipher.apply(&mut response[3..]);

    let decoded = decode_server_udp_datagram(&server, &response).expect("decrypt packet");
    assert_eq!(
        decoded,
        [OP_EDONKEYPROT, OP_GLOBGETSOURCES2, b'a', b'b', b'c']
    );
}

#[test]
fn login_request_matches_oracle_tag_shape() {
    let payload = encode_login_request(Ed2kHelloIdentity {
        user_hash: [0x11; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    });
    let nickname_tag_header = [
        ed2k_string_tag_type(HELLO_NICKNAME.len()),
        0x01,
        0x00,
        CT_NAME,
    ];
    let version_tag_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_VERSION];
    let server_flags_tag_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_SERVER_FLAGS];
    let emule_version_tag_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_VERSION];

    assert_eq!(&payload[..16], &[0x11; 16]);
    assert_eq!(u16::from_le_bytes([payload[20], payload[21]]), 41001);
    assert_eq!(
        u32::from_le_bytes([payload[22], payload[23], payload[24], payload[25]]),
        4
    );
    assert!(
        payload
            .windows(nickname_tag_header.len())
            .any(|window| window == nickname_tag_header)
    );
    assert!(
        payload
            .windows(version_tag_header.len())
            .any(|window| window == version_tag_header)
    );
    assert!(
        payload
            .windows(server_flags_tag_header.len())
            .any(|window| window == server_flags_tag_header)
    );
    assert!(
        payload
            .windows(emule_version_tag_header.len())
            .any(|window| window == emule_version_tag_header)
    );
    assert!(
        payload
            .windows(HELLO_NICKNAME.len())
            .any(|window| window == HELLO_NICKNAME.as_bytes())
    );
    assert!(
        payload
            .windows(4)
            .any(|window| window == EDONKEY_VERSION.to_le_bytes())
    );
    assert!(
        payload
            .windows(4)
            .any(|window| window == server_capabilities(emule_connect_options(true)).to_le_bytes())
    );
    let version =
        (EMULE_VERSION_MAJOR << 17) | (EMULE_VERSION_MINOR << 10) | (EMULE_VERSION_UPDATE << 7);
    assert!(
        payload
            .windows(4)
            .any(|window| window == version.to_le_bytes())
    );
}

#[test]
fn login_request_omits_crypt_flags_when_obfuscation_is_off() {
    let payload = encode_login_request(Ed2kHelloIdentity {
        user_hash: [0x22; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    });

    assert!(payload.windows(4).any(
            |window| window == server_capabilities(emule_connect_options(false)).to_le_bytes()
        ));
    assert_eq!(
        server_capabilities(emule_connect_options(false)) & 0x0E00,
        0
    );
}

#[test]
fn login_request_matches_stock_072a_plaintext_sample() {
    let packet = encode_packet(
        OP_LOGINREQUEST,
        &encode_login_request(Ed2kHelloIdentity {
            user_hash: [
                0x73, 0xBE, 0xC5, 0x66, 0x14, 0x0E, 0x7E, 0x60, 0x83, 0xC4, 0x50, 0xC9, 0xAF, 0x02,
                0x6F, 0x83,
            ],
            client_id: 0,
            tcp_port: 46671,
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        }),
        false,
    )
    .unwrap();

    let expected = decode(
            "e33c0000000173bec566140e7e6083c450c9af026f83000000004fb60400000015010001654d756c65030100113c0000000301002019010000030100fb00200100",
        )
        .unwrap();

    assert_eq!(packet, expected);
}

#[test]
fn login_request_matches_stock_072a_obfuscated_preference_sample() {
    let packet = encode_packet(
        OP_LOGINREQUEST,
        &encode_login_request(Ed2kHelloIdentity {
            user_hash: [
                0x73, 0xBE, 0xC5, 0x66, 0x14, 0x0E, 0x7E, 0x60, 0x83, 0xC4, 0x50, 0xC9, 0xAF, 0x02,
                0x6F, 0x83,
            ],
            client_id: 0,
            tcp_port: 46671,
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        }),
        false,
    )
    .unwrap();

    let expected = decode(
            "e33c0000000173bec566140e7e6083c450c9af026f83000000004fb60400000015010001654d756c65030100113c0000000301002019070000030100fb00200100",
        )
        .unwrap();

    assert_eq!(packet, expected);
}

#[test]
fn metadata_poor_server_defaults_to_plaintext_even_if_client_supports_crypt() {
    assert!(!should_use_server_obfuscation(
        emule_connect_options(true),
        &test_server(0, 0)
    ));
}

#[test]
fn server_obfuscation_requires_positive_server_metadata() {
    assert!(should_use_server_obfuscation(
        emule_connect_options(true),
        &test_server(4661, SERVER_UDP_FLAG_UDPOBFUSCATION)
    ));
}

#[test]
fn packet_encoder_uses_ed2k_framing() {
    let packet = encode_packet(OP_GETSERVERLIST, &[], false).unwrap();
    assert_eq!(packet[0], 0xE3);
    assert_eq!(
        u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]),
        1
    );
    assert_eq!(packet[5], OP_GETSERVERLIST);
}

#[test]
fn server_ident_parser_extracts_name_and_description() {
    let mut payload = vec![0u8; 22];
    payload.extend_from_slice(&2u32.to_le_bytes());
    payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 3));
    payload.push(ST_SERVERNAME);
    payload.extend_from_slice(b"test");
    payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 3));
    payload.push(ST_DESCRIPTION);
    payload.extend_from_slice(b"desc");

    let (name, description) = decode_server_ident(&payload).unwrap();

    assert_eq!(name.as_deref(), Some("test"));
    assert_eq!(description.as_deref(), Some("desc"));
}

#[test]
fn server_ident_parser_skips_non_short_named_tags() {
    let mut payload = vec![0u8; 22];
    payload.extend_from_slice(&2u32.to_le_bytes());
    payload.push(TAGTYPE_UINT32);
    payload.extend_from_slice(&4u16.to_le_bytes());
    payload.extend_from_slice(b"misc");
    payload.extend_from_slice(&7u32.to_le_bytes());
    payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 3));
    payload.push(ST_SERVERNAME);
    payload.extend_from_slice(b"test");

    let (name, description) = decode_server_ident(&payload).unwrap();

    assert_eq!(name.as_deref(), Some("test"));
    assert_eq!(description, None);
}

#[test]
fn server_state_reports_low_id_as_firewalled() {
    let mut state = Ed2kServerState::default();
    assert_eq!(state.tcp_firewalled(), None);
    state.client_id = Some(0x0000_1234);
    assert_eq!(state.tcp_firewalled(), Some(true));
    state.client_id = Some(0x7F00_0001);
    assert_eq!(state.tcp_firewalled(), Some(false));
}

#[test]
fn packed_server_payload_is_inflated() {
    let plain_payload = b"oracle-server-payload";
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plain_payload).unwrap();
    let packed_payload = encoder.finish().unwrap();

    let decoded = decode_server_payload(OP_PACKEDPROT, packed_payload).unwrap();

    assert_eq!(decoded, plain_payload);
}

#[test]
fn packet_encoder_uses_packed_framing_when_requested() {
    let packet = encode_packet(OP_GETSERVERLIST, &[], true).unwrap();
    assert_eq!(packet[0], OP_PACKEDPROT);
    let decoded = decode_server_payload(OP_PACKEDPROT, packet[6..].to_vec()).unwrap();
    assert!(decoded.is_empty());
    assert_eq!(packet[5], OP_GETSERVERLIST);
}

#[test]
fn server_flag_formatter_lists_known_capabilities() {
    let text = format_server_flags(SERVER_TCP_FLAG_COMPRESSION | SERVER_TCP_FLAG_LARGEFILES);
    assert!(text.contains("compression"));
    assert!(text.contains("large_files"));
}

#[test]
fn search_probe_encoding_matches_prefix_and_shape() {
    let payload = encode_search_request("ubuntu linux").unwrap();

    assert_eq!(payload[0], 1);
    assert_eq!(u16::from_le_bytes([payload[1], payload[2]]), 12);
    assert_eq!(&payload[3..15], b"ubuntu linux");
}

#[test]
fn search_probe_encoding_preserves_boolean_query_tree_shape() {
    let payload = encode_search_request("ubuntu OR linux").unwrap();

    assert_eq!(payload[0], 0);
    assert_eq!(payload[1], 0x01);
    assert_eq!(payload[2], 1);
    assert_eq!(u16::from_le_bytes([payload[3], payload[4]]), 6);
    assert_eq!(&payload[5..11], b"ubuntu");
    assert_eq!(payload[11], 1);
    assert_eq!(u16::from_le_bytes([payload[12], payload[13]]), 5);
    assert_eq!(&payload[14..19], b"linux");
}

#[test]
fn plaintext_server_sessions_preserve_crypt_capability_bits() {
    let identity = login_identity_for_server_transport(
        Ed2kHelloIdentity {
            user_hash: [0x33; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        },
        false,
    );

    assert_eq!(identity.connect_options, emule_connect_options(true));
}

#[test]
fn offer_files_payload_matches_oracle_search_session_sample() {
    let shared_catalog = vec![Ed2kSharedEntry {
        file_hash: hex::encode(OFFER_FILE_SAMPLE_HASH),
        canonical_name: OFFER_FILE_SAMPLE_NAME.to_string(),
        file_size: u64::from(OFFER_FILE_SAMPLE_SIZE),
        verified_complete: false,
        verified_ranges: Vec::new(),
        compatibility_hint: true,
        source_count_hint: Some(12),
        aich_root: None,
    }];
    let packet = encode_packet(
        OP_OFFERFILES,
        &encode_offer_files_payload(
            &shared_catalog,
            Some(0x521B_5895),
            46671,
            Some(SERVER_TCP_FLAG_COMPRESSION),
        ),
        false,
    )
    .unwrap();

    let expected = decode(
            "e34a00000015010000009f3c23db7651efbac9a837a8a0ae3ed9fbfbfbfbfbfb0300000082011e007562756e74752d6c696e75782d6f7261636c652d73616d706c652e69736f830200002000890304",
        )
        .unwrap();

    assert_eq!(packet, expected);
}

#[test]
fn offer_files_fingerprint_changes_when_shared_catalog_changes() {
    let base_catalog = vec![Ed2kSharedEntry {
        file_hash: hex::encode(OFFER_FILE_SAMPLE_HASH),
        canonical_name: OFFER_FILE_SAMPLE_NAME.to_string(),
        file_size: u64::from(OFFER_FILE_SAMPLE_SIZE),
        verified_complete: false,
        verified_ranges: Vec::new(),
        compatibility_hint: true,
        source_count_hint: Some(12),
        aich_root: None,
    }];
    let mut expanded_catalog = base_catalog.clone();
    expanded_catalog.push(Ed2kSharedEntry {
        file_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        canonical_name: "new-shared-file.bin".to_string(),
        file_size: 42_000,
        verified_complete: true,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
    });

    assert_ne!(
        offer_files_catalog_fingerprint(&base_catalog),
        offer_files_catalog_fingerprint(&expanded_catalog)
    );
}

#[test]
fn search_results_decoder_extracts_count_and_names() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&[0x11; 16]);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&4662u16.to_le_bytes());
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 9));
    payload.push(FT_FILENAME);
    payload.extend_from_slice(b"ubuntu.iso");
    payload.push(0x00);

    let summary = decode_search_results(&payload).unwrap();

    assert_eq!(summary.count, 1);
    assert_eq!(summary.sample_names, vec!["ubuntu.iso".to_string()]);
}

#[test]
fn search_results_decoder_extracts_size_type_and_sources() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&[0x22; 16]);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&4662u16.to_le_bytes());
    payload.extend_from_slice(&4u32.to_le_bytes());
    payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 9));
    payload.push(FT_FILENAME);
    payload.extend_from_slice(b"ubuntu.iso");
    payload.push(super::TAGTYPE_UINT64);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(FT_FILESIZE);
    payload.extend_from_slice(&4_294_967_300u64.to_le_bytes());
    payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 4));
    payload.push(FT_FILETYPE);
    payload.extend_from_slice(b"Video");
    payload.push(TAGTYPE_UINT32);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(FT_SOURCES);
    payload.extend_from_slice(&12u32.to_le_bytes());
    payload.push(0x01);

    let page = decode_search_result_page(&payload).unwrap();
    let files = page.files;

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].file_name.as_deref(), Some("ubuntu.iso"));
    assert_eq!(files[0].file_size, Some(4_294_967_300));
    assert_eq!(files[0].file_type.as_deref(), Some("Video"));
    assert_eq!(files[0].source_count, Some(12));
    assert!(page.more_results_available);
}

#[test]
fn search_results_decoder_rejects_invalid_more_marker() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.push(0x7F);

    let error = decode_search_result_page(&payload).unwrap_err().to_string();

    assert!(error.contains("More marker"));
}

#[test]
fn found_sources_decoder_extracts_plain_sources() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0xAA; 16]);
    payload.push(1);
    payload.extend_from_slice(&[10, 20, 30, 40]);
    payload.extend_from_slice(&4662u16.to_le_bytes());

    let sources = decode_found_sources(&payload, false).unwrap();
    let client_id = u32::from_le_bytes([10, 20, 30, 40]);

    assert_eq!(
        sources,
        vec![Ed2kFoundSource {
            file_hash: Ed2kHash([0xAA; 16]),
            ip: Ipv4Addr::new(10, 20, 30, 40),
            tcp_port: 4662,
            client_id,
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
        }]
    );
}

#[test]
fn found_sources_decoder_marks_low_id_sources_as_callback_only() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0xAB; 16]);
    payload.push(1);
    payload.extend_from_slice(&34254u32.to_le_bytes());
    payload.extend_from_slice(&4662u16.to_le_bytes());

    let sources = decode_found_sources(&payload, false).unwrap();
    let client_id = 34254u32;

    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].client_id, client_id);
    assert_eq!(sources[0].ip, ipv4_from_client_id(client_id));
    assert!(sources[0].low_id);
    assert!(!sources[0].is_direct_dialable());
}

#[test]
fn found_sources_decoder_extracts_obfuscated_sources_with_user_hash() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0xCC; 16]);
    payload.push(1);
    payload.extend_from_slice(&[10, 20, 30, 40]);
    payload.extend_from_slice(&4662u16.to_le_bytes());
    payload.push(SOURCE_OBFUSCATION_USER_HASH_PRESENT | 0x03);
    payload.extend_from_slice(&[0x61; 16]);

    let sources = decode_found_sources(&payload, true).unwrap();
    let client_id = u32::from_le_bytes([10, 20, 30, 40]);

    assert_eq!(
        sources,
        vec![Ed2kFoundSource {
            file_hash: Ed2kHash([0xCC; 16]),
            ip: Ipv4Addr::new(10, 20, 30, 40),
            tcp_port: 4662,
            client_id,
            low_id: false,
            obfuscated: true,
            obfuscation_options: Some(SOURCE_OBFUSCATION_USER_HASH_PRESENT | 0x03),
            user_hash: Some([0x61; 16]),
            source_server: None,
        }]
    );
}

#[test]
fn source_request_encoding_includes_u32_size_for_small_files() {
    let payload = encode_source_request(Ed2kHash([0xAB; 16]), 734_003_200);

    assert_eq!(&payload[..16], &[0xAB; 16]);
    assert_eq!(
        u32::from_le_bytes(payload[16..20].try_into().unwrap()),
        734_003_200
    );
    assert_eq!(payload.len(), 20);
}

#[test]
fn source_request_encoding_uses_hash_only_shape_when_size_is_unknown() {
    let payload = encode_source_request(Ed2kHash([0xEF; 16]), 0);

    assert_eq!(payload, vec![0xEF; 16]);
}

#[test]
fn source_request_encoding_uses_large_file_sentinel() {
    let payload = encode_source_request(Ed2kHash([0xCD; 16]), 4_294_967_301);

    assert_eq!(&payload[..16], &[0xCD; 16]);
    assert_eq!(u32::from_le_bytes(payload[16..20].try_into().unwrap()), 0);
    assert_eq!(
        u64::from_le_bytes(payload[20..28].try_into().unwrap()),
        4_294_967_301
    );
}

#[test]
fn source_request_opcode_uses_obfuscated_variant_when_supported() {
    assert_eq!(
        source_request_opcode(0x01, Some(SERVER_TCP_FLAG_TCPOBFUSCATION)),
        OP_GETSOURCES_OBFU
    );
    assert_eq!(
        source_request_opcode(0x00, Some(SERVER_TCP_FLAG_TCPOBFUSCATION)),
        OP_GETSOURCES
    );
    assert_eq!(source_request_opcode(0x01, Some(0)), OP_GETSOURCES);
}

#[test]
fn found_sources_validation_rejects_hash_mismatch() {
    let error = validate_found_sources(
        &[Ed2kFoundSource {
            file_hash: Ed2kHash([0xAA; 16]),
            ip: Ipv4Addr::new(1, 2, 3, 4),
            tcp_port: 4662,
            client_id: u32::from(Ipv4Addr::new(1, 2, 3, 4)),
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
        }],
        Ed2kHash([0xBB; 16]),
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("unexpected file hash"));
}

#[tokio::test]
async fn background_search_channel_round_trips_results() {
    let (handle, mut inbox) = new_ed2k_server_search_channel(1);
    let cancel = CancellationToken::new();
    let expected = Ed2kSearchFile {
        file_hash: Ed2kHash([0x44; 16]),
        file_name: Some("ubuntu.iso".to_string()),
        file_size: Some(123),
        file_type: Some("Doc".to_string()),
        source_count: Some(7),
    };
    let expected_for_task = expected.clone();

    let responder = tokio::spawn(async move {
        let request = inbox.receiver.recv().await.unwrap();
        match request {
            BackgroundServerSearchRequest::Keyword {
                query, response, ..
            } => {
                assert_eq!(query, "ubuntu linux");
                let _ = response.send(Ok(vec![expected_for_task]));
            }
            other => panic!("unexpected background request: {other:?}"),
        }
    });

    let results = search_keyword_via_background_session(
        &handle,
        "ubuntu linux",
        Duration::from_secs(1),
        &cancel,
    )
    .await
    .unwrap();

    assert_eq!(results, vec![expected]);
    responder.await.unwrap();
}

#[tokio::test]
async fn background_source_search_channel_round_trips_results() {
    let (handle, mut inbox) = new_ed2k_server_search_channel(1);
    let cancel = CancellationToken::new();
    let file_hash = Ed2kHash([0x51; 16]);
    let expected = Ed2kFoundSource {
        file_hash,
        ip: Ipv4Addr::new(10, 20, 30, 40),
        tcp_port: 4662,
        client_id: u32::from_le_bytes([10, 20, 30, 40]),
        low_id: false,
        obfuscated: true,
        obfuscation_options: Some(0x03),
        user_hash: Some([0x61; 16]),
        source_server: None,
    };
    let expected_for_task = expected.clone();

    let responder = tokio::spawn(async move {
        let request = inbox.receiver.recv().await.unwrap();
        match request {
            BackgroundServerSearchRequest::Source {
                file_hash: requested_hash,
                file_size,
                response,
                ..
            } => {
                assert_eq!(requested_hash, file_hash);
                assert_eq!(file_size, 42);
                let _ = response.send(Ok(vec![expected_for_task]));
            }
            other => panic!("unexpected background request: {other:?}"),
        }
    });

    let results = search_source_via_background_session(
        &handle,
        file_hash,
        42,
        Duration::from_secs(1),
        &cancel,
    )
    .await
    .unwrap();

    assert_eq!(results, vec![expected]);
    responder.await.unwrap();
}

#[tokio::test]
async fn server_obfuscation_handshake_encrypts_login_request() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let hello_identity = Ed2kHelloIdentity {
        user_hash: [0x11; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    };
    let expected_login = encode_packet(
        OP_LOGINREQUEST,
        &encode_login_request(hello_identity),
        false,
    )
    .unwrap();
    let expected_login_for_server = expected_login.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut handshake_prefix = [0u8; 1 + SERVER_OBFUSCATION_PUBLIC_KEY_LEN + 1];
        stream.read_exact(&mut handshake_prefix).await.unwrap();
        assert!(!matches!(
            handshake_prefix[0],
            OP_EDONKEYPROT | super::OP_EMULEPROT | super::OP_PACKEDPROT
        ));
        let client_padding_len =
            usize::from(handshake_prefix[1 + SERVER_OBFUSCATION_PUBLIC_KEY_LEN]);
        let mut client_padding = vec![0u8; client_padding_len];
        stream.read_exact(&mut client_padding).await.unwrap();

        let client_public =
            BigUint::from_bytes_be(&handshake_prefix[1..1 + SERVER_OBFUSCATION_PUBLIC_KEY_LEN]);
        let prime = BigUint::from_bytes_be(&SERVER_OBFUSCATION_PRIME_BYTES);
        let generator = BigUint::from(2u8);
        let server_secret = BigUint::from_bytes_be(&[0x42; 16]);
        let server_public = biguint_to_fixed_be(
            &generator.modpow(&server_secret, &prime),
            SERVER_OBFUSCATION_PUBLIC_KEY_LEN,
        )
        .unwrap();
        let shared_secret = biguint_to_fixed_be(
            &client_public.modpow(&server_secret, &prime),
            SERVER_OBFUSCATION_PUBLIC_KEY_LEN,
        )
        .unwrap();
        let mut send_cipher = derive_server_cipher(&shared_secret, EMULE_TCP_CRYPT_MAGIC_SERVER);
        let mut receive_cipher =
            derive_server_cipher(&shared_secret, EMULE_TCP_CRYPT_MAGIC_REQUESTER);

        let mut server_reply = Vec::with_capacity(SERVER_OBFUSCATION_PUBLIC_KEY_LEN + 10);
        server_reply.extend_from_slice(&server_public);
        let mut encrypted_reply = Vec::with_capacity(10);
        encrypted_reply.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
        encrypted_reply.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        encrypted_reply.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        encrypted_reply.push(3);
        encrypted_reply.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        send_cipher.apply(&mut encrypted_reply);
        server_reply.extend_from_slice(&encrypted_reply);
        stream.write_all(&server_reply).await.unwrap();

        let mut response_header = [0u8; 6];
        stream.read_exact(&mut response_header).await.unwrap();
        receive_cipher.apply(&mut response_header);
        assert_eq!(
            u32::from_le_bytes(response_header[..4].try_into().unwrap()),
            EMULE_TCP_CRYPT_MAGIC_SYNC
        );
        assert_eq!(response_header[4], EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        let response_padding_len = usize::from(response_header[5]);

        let mut encrypted_tail = vec![0u8; response_padding_len + expected_login_for_server.len()];
        stream.read_exact(&mut encrypted_tail).await.unwrap();
        receive_cipher.apply(&mut encrypted_tail);
        assert_eq!(
            &encrypted_tail[response_padding_len..],
            expected_login_for_server.as_slice()
        );
    });

    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let mut session = ServerSession::connect(
        Ipv4Addr::LOCALHOST,
        endpoint,
        state,
        "test",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    session
        .negotiate_obfuscation_and_send(&expected_login)
        .await
        .unwrap();

    server.await.unwrap();
}
