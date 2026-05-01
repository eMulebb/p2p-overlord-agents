use super::*;

#[test]
fn kad_hello_metadata_parses_misc_bits_and_source_uport() {
    let metadata = parse_kad_hello_metadata(&[
        Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
        Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x07)),
    ]);

    assert_eq!(metadata.hello_source_udp_port, Some(41000));
    assert!(metadata.udp_firewalled);
    assert!(metadata.tcp_firewalled);
    assert!(metadata.requests_hello_res_ack);
}

#[test]
fn kad_hello_response_tags_encode_expected_misc_bits() {
    let tags = build_kad_hello_response_tags(41000, true, false, true);

    assert_eq!(
        tags,
        vec![
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
            Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05)),
        ]
    );
}

#[test]
fn kad_hello_request_tags_prefer_misc_options_when_ack_is_requested() {
    let tags = build_kad_hello_request_tags(41000, true, false, false, true);

    assert_eq!(
        tags,
        vec![Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x04))]
    );
}

#[test]
fn kad_hello_request_tags_advertise_source_uport_for_verified_open_udp() {
    let tags = build_kad_hello_request_tags(41000, true, false, false, false);

    assert_eq!(
        tags,
        vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))]
    );
}

#[test]
fn kad_hello_request_tags_can_be_empty_before_udp_state_is_verified() {
    let tags = build_kad_hello_request_tags(41000, false, false, false, false);

    assert!(tags.is_empty());
}

#[test]
fn hello_response_ack_requires_sender_verify_key() {
    assert!(!should_request_hello_response_ack(8, false, None));
    assert!(should_request_hello_response_ack(
        8,
        false,
        Some(0x1122_3344)
    ));
    assert!(!should_request_hello_response_ack(
        8,
        true,
        Some(0x1122_3344)
    ));
    assert!(!should_request_hello_response_ack(
        7,
        false,
        Some(0x1122_3344)
    ));
}

#[test]
fn kad_source_results_preserve_obfuscation_and_user_hash_metadata() {
    let source = kad_source_result_to_ed2k_found_source(SourceResult {
        file_hash: Ed2kHash::from_bytes([0x44; 16]),
        source_id: Ed2kHash::from_bytes([0x55; 16]),
        ip: Ipv4Addr::new(127, 0, 0, 2),
        tcp_port: 4662,
        udp_port: 4672,
        obfuscation_options: Some(0x03),
    });

    assert!(source.obfuscated);
    assert_eq!(source.obfuscation_options, Some(0x03));
    assert_eq!(source.user_hash, Some([0x55; 16]));
    assert_eq!(source.ip, Ipv4Addr::new(127, 0, 0, 2));
}

#[tokio::test]
async fn bound_ed2k_listener_is_treated_as_tcp_open() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ed2k_server_state = Arc::new(RwLock::new(Ed2kServerState::default()));

    assert!(!current_tcp_firewalled(&listener, &ed2k_server_state).await);
}

#[tokio::test]
async fn low_id_server_verdict_marks_tcp_as_firewalled() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ed2k_server_state = Arc::new(RwLock::new(Ed2kServerState {
        client_id: Some(0x0000_2222),
        ..Ed2kServerState::default()
    }));

    assert!(current_tcp_firewalled(&listener, &ed2k_server_state).await);
}

#[tokio::test]
async fn hello_response_uses_oracle_hello_shape() {
    let dht = DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x33; 16]),
        udp_key: 0x1122_3344,
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ed2k_server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));

    let hello = build_hello_response(&dht, &listener, &ed2k_server_state, &kad_firewall, true)
        .await
        .unwrap();

    assert_eq!(hello.node_id, dht.own_id());
    assert!(hello.tags.iter().any(|tag| matches!(
        (&tag.name, &tag.value),
        (TagName::Short(name), TagValue::U16(_))
            if *name == tag_name::SOURCEUPORT
    )));
}

#[tokio::test]
async fn hello_request_uses_oracle_hello_shape() {
    let dht = DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x44; 16]),
        udp_key: 0x5566_7788,
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ed2k_server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));

    let hello = build_hello_request(&dht, &listener, &ed2k_server_state, &kad_firewall, true)
        .await
        .unwrap();

    assert_eq!(hello.node_id, dht.own_id());
    assert!(hello.tags.iter().any(|tag| matches!(
        (&tag.name, &tag.value),
        (TagName::Short(name), TagValue::U8(bits))
            if *name == tag_name::KADMISCOPTIONS && (*bits & 0x04) != 0
    )));
}
