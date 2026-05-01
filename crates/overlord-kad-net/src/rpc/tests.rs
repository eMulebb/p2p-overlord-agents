use super::*;
use crate::obfuscation::ObfuscationLayer;
use crate::transport::MockTransport;
use overlord_kad_proto::constants::opcode;
use overlord_kad_proto::{KadPacket, NodeId};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

fn make_local_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn make_peer_addr() -> SocketAddr {
    "127.0.0.1:9999".parse().unwrap()
}

fn make_rpc(config: RpcConfig) -> RpcManager {
    let transport = MockTransport::new(make_local_addr());
    let obfuscation = ObfuscationLayer::new(overlord_kad_proto::NodeId::ZERO, 0, false);
    RpcManager::new(transport, obfuscation, config)
}

fn make_rpc_with_transport(transport: MockTransport) -> RpcManager {
    let obfuscation = ObfuscationLayer::new(overlord_kad_proto::NodeId::ZERO, 0, false);
    RpcManager::new(transport, obfuscation, RpcConfig::default())
}

fn make_rpc_with_shared_transport(
    transport: Arc<MockTransport>,
    obfuscation: ObfuscationLayer,
) -> RpcManager {
    RpcManager::new(transport, obfuscation, RpcConfig::default())
}

#[tokio::test]
async fn test_request_response() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let ping = KadPacket::Ping;

    // In a background task: wait a bit, then inject a PONG from peer
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let pong = KadPacket::Pong(overlord_kad_proto::Pong { udp_port: 9999 });
        let encoded = pong.encode().unwrap();
        let _ = inject_tx.send((encoded, peer_addr)).await;
    });

    let result = rpc
        .request(peer_addr, &ping, opcode::PONG, Duration::from_secs(5))
        .await;

    assert!(result.is_ok(), "expected Ok, got {:?}", result);
    assert!(matches!(
        result.unwrap(),
        KadPacket::Pong(overlord_kad_proto::Pong { udp_port: 9999 })
    ));
}

#[tokio::test]
async fn test_request_timeout() {
    let rpc = make_rpc(RpcConfig {
        max_outbound_pps: 0,
        ..Default::default()
    });
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let ping = KadPacket::Ping;

    // No response injected — should time out
    let result = rpc
        .request(peer_addr, &ping, opcode::PONG, Duration::from_millis(100))
        .await;

    assert!(matches!(result, Err(NetError::Timeout { .. })));
}

#[tokio::test]
async fn test_unsolicited_request_broadcast() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();

    // Inject a HelloReq (requests are broadcast as unsolicited traffic).
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let hello = KadPacket::HelloReq(overlord_kad_proto::HelloReq {
            node_id: NodeId::from_bytes([0x44; 16]),
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        });
        let encoded = hello.encode().unwrap();
        let _ = inject_tx.send((encoded, peer_addr)).await;
    });

    let received = tokio::time::timeout(Duration::from_secs(2), subscriber.recv()).await;
    assert!(received.is_ok(), "timed out waiting for broadcast");
    let received = received.unwrap().unwrap();
    assert!(matches!(received.packet, KadPacket::HelloReq(_)));
    assert_eq!(received.from, peer_addr);
    assert!(!received.was_obfuscated);
    assert_eq!(received.sender_verify_key, None);
    assert!(!received.receiver_verify_key_valid);
}

#[tokio::test]
async fn test_tracked_hello_response_is_broadcast_without_pending_request() {
    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let inject_tx = transport.injector();
    let obfuscation = ObfuscationLayer::new(NodeId::from_bytes([0xAA; 16]), 0x1234_5678, true);
    let rpc = make_rpc_with_shared_transport(Arc::clone(&transport), obfuscation);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let peer_id = NodeId::from_bytes([0x44; 16]);
    rpc.send(
        peer_addr,
        &KadPacket::HelloReq(overlord_kad_proto::HelloReq {
            node_id: NodeId::from_bytes([0x55; 16]),
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        }),
    )
    .await
    .unwrap();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let hello = KadPacket::HelloRes(overlord_kad_proto::HelloRes {
            node_id: peer_id,
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        });
        let encoded = hello.encode().unwrap();
        let _ = inject_tx.send((encoded, peer_addr)).await;
    });

    let received = tokio::time::timeout(Duration::from_secs(2), subscriber.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(received.packet, KadPacket::HelloRes(_)));
    assert_eq!(received.from, peer_addr);
}

#[tokio::test]
async fn test_plaintext_hello_response_stays_plaintext_without_obfuscation() {
    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_shared_transport(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::from_bytes([0xAA; 16]), 0x1234_5678, false),
    );
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    rpc.send(
        peer_addr,
        &KadPacket::HelloReq(overlord_kad_proto::HelloReq {
            node_id: NodeId::from_bytes([0x55; 16]),
            tcp_port: 4662,
            version: overlord_kad_proto::KAD_VERSION,
            tags: Vec::new(),
        }),
    )
    .await
    .unwrap();

    let hello = KadPacket::HelloRes(overlord_kad_proto::HelloRes {
        node_id: NodeId::from_bytes([0x44; 16]),
        tcp_port: 4662,
        version: overlord_kad_proto::KAD_VERSION,
        tags: Vec::new(),
    });
    let encoded = hello.encode().unwrap();
    let _ = inject_tx.send((encoded, peer_addr)).await;

    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(received.packet, KadPacket::HelloRes(_)));
    assert!(!received.was_obfuscated);
    assert_eq!(received.sender_verify_key, None);
    assert!(!received.receiver_verify_key_valid);
}

#[tokio::test]
async fn test_untracked_response_is_dropped() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let hello = KadPacket::HelloRes(overlord_kad_proto::HelloRes {
            node_id: NodeId::from_bytes([0x44; 16]),
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        });
        let encoded = hello.encode().unwrap();
        let _ = inject_tx.send((encoded, peer_addr)).await;
    });

    let received = tokio::time::timeout(Duration::from_millis(200), subscriber.recv()).await;
    assert!(
        received.is_err(),
        "unexpectedly received untracked response"
    );
}

#[tokio::test]
async fn test_rate_limiter() {
    let rpc = make_rpc(RpcConfig {
        max_outbound_pps: 1000,
        ..Default::default()
    });
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let ping = KadPacket::Ping;

    // Send 5 packets rapidly — all should succeed with high PPS limit
    for _ in 0..5 {
        let result = rpc.send(peer_addr, &ping).await;
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn test_flood_blocking() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = RpcManager::new(
        transport,
        ObfuscationLayer::new(overlord_kad_proto::NodeId::ZERO, 0, false),
        RpcConfig {
            max_inbound_per_ip: 20,
            flood_window: Duration::from_secs(1),
            broadcast_capacity: 256,
            ..Default::default()
        },
    );
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr: SocketAddr = "1.2.3.4:9999".parse().unwrap();
    let pong = KadPacket::Pong(overlord_kad_proto::Pong { udp_port: 9999 });
    let encoded = pong.encode().unwrap();

    // Inject 100 packets — untracked responses should be dropped.
    let total = 100usize;
    for _ in 0..total {
        let _ = inject_tx.send((encoded.clone(), peer_addr)).await;
    }

    // Collect what we get within a short window
    let mut received_count = 0usize;
    let collect_timeout = Duration::from_millis(200);
    let deadline = tokio::time::Instant::now() + collect_timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, subscriber.recv()).await {
            Ok(Ok(_)) => received_count += 1,
            _ => break,
        }
    }

    assert!(
        received_count == 0,
        "received {} packets, expected no unsolicited tracked responses",
        received_count
    );
}

#[tokio::test]
async fn test_search_res_uses_higher_flood_budget() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = RpcManager::new(
        transport,
        ObfuscationLayer::new(overlord_kad_proto::NodeId::ZERO, 0, false),
        RpcConfig {
            max_inbound_per_ip: 20,
            max_inbound_search_res_per_ip: 64,
            flood_window: Duration::from_secs(1),
            broadcast_capacity: 256,
            ..Default::default()
        },
    );
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr: SocketAddr = "1.2.3.4:9999".parse().unwrap();
    let packet = KadPacket::SearchRes(overlord_kad_proto::SearchRes {
        sender_id: NodeId::from_bytes([0x44; 16]),
        target: NodeId::from_bytes([0x55; 16]),
        results: Vec::new(),
    });
    let encoded = packet.encode().unwrap();

    for _ in 0..40usize {
        let _ = inject_tx.send((encoded.clone(), peer_addr)).await;
    }

    let mut received_count = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, subscriber.recv()).await {
            Ok(Ok(_)) => received_count += 1,
            _ => break,
        }
    }

    assert!(
        received_count >= 40,
        "received {} SEARCH_RES packets, expected all 40 to pass",
        received_count
    );
}

#[tokio::test]
async fn test_massive_flood_invokes_handler_and_counts_tracker_actions() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let massive_flood_hits = Arc::new(AtomicU64::new(0));
    let massive_flood_hits_for_handler = Arc::clone(&massive_flood_hits);
    let rpc = RpcManager::new(
        transport,
        ObfuscationLayer::new(overlord_kad_proto::NodeId::ZERO, 0, false),
        RpcConfig {
            request_tracking_window: Duration::from_secs(60),
            massive_flood_handler: Some(Arc::new(move |_| {
                massive_flood_hits_for_handler.fetch_add(1, AtomicOrdering::Relaxed);
            })),
            ..Default::default()
        },
    );
    let _handle = rpc.start();

    let peer_addr: SocketAddr = "1.2.3.4:9999".parse().unwrap();
    let hello = KadPacket::HelloReq(overlord_kad_proto::HelloReq {
        node_id: NodeId::from_bytes([0x44; 16]),
        tcp_port: 4662,
        version: 8,
        tags: Vec::new(),
    });
    let encoded = hello.encode().unwrap();

    for _ in 0..13usize {
        let _ = inject_tx.send((encoded.clone(), peer_addr)).await;
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let snapshot = rpc.observability();
    let hello_bucket = snapshot
        .tracker_buckets
        .iter()
        .find(|bucket| bucket.bucket == "hello_req")
        .expect("hello bucket present");
    assert_eq!(hello_bucket.accepted_requests, 3);
    assert_eq!(hello_bucket.tracker_drops, 9);
    assert_eq!(hello_bucket.tracker_massive_drops, 1);
    assert_eq!(massive_flood_hits.load(AtomicOrdering::Relaxed), 1);
}

#[tokio::test]
async fn test_unrequested_response_is_counted_and_dropped() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let pong = KadPacket::Pong(overlord_kad_proto::Pong { udp_port: 9999 });
    let encoded = pong.encode().unwrap();
    let _ = inject_tx.send((encoded, peer_addr)).await;

    let received = tokio::time::timeout(Duration::from_millis(100), subscriber.recv()).await;
    assert!(received.is_err(), "unexpectedly accepted unrequested pong");

    let snapshot = rpc.observability();
    let pong_stats = snapshot
        .response_opcodes
        .iter()
        .find(|opcode| opcode.opcode == "KADEMLIA2_PONG")
        .expect("pong counters present");
    assert_eq!(pong_stats.dropped_unrequested, 1);
    assert_eq!(pong_stats.matched_pending, 0);
    assert_eq!(pong_stats.matched_tracked, 0);
}

#[tokio::test]
async fn test_tracked_response_without_pending_request_is_broadcast_and_counted() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    rpc.send(
        peer_addr,
        &KadPacket::HelloReq(overlord_kad_proto::HelloReq {
            node_id: NodeId::from_bytes([0x55; 16]),
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        }),
    )
    .await
    .unwrap();

    let hello_res = KadPacket::HelloRes(overlord_kad_proto::HelloRes {
        node_id: NodeId::from_bytes([0x44; 16]),
        tcp_port: 4662,
        version: 8,
        tags: Vec::new(),
    });
    let encoded = hello_res.encode().unwrap();
    let _ = inject_tx.send((encoded, peer_addr)).await;

    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(received.packet, KadPacket::HelloRes(_)));

    let snapshot = rpc.observability();
    let hello_res_stats = snapshot
        .response_opcodes
        .iter()
        .find(|opcode| opcode.opcode == "KADEMLIA2_HELLO_RES")
        .expect("hello response counters present");
    assert_eq!(hello_res_stats.matched_tracked, 1);
    assert_eq!(hello_res_stats.dropped_unrequested, 0);
}

#[tokio::test]
async fn test_observability_tracks_outbound_work_classes() {
    let transport = MockTransport::new(make_local_addr());
    let rpc = make_rpc_with_transport(transport);
    let peer_addr = make_peer_addr();

    rpc.send_with_class(peer_addr, &KadPacket::Ping, RpcWorkClass::Harvest)
        .await
        .unwrap();
    rpc.send_with_class(peer_addr, &KadPacket::Ping, RpcWorkClass::Publish)
        .await
        .unwrap();

    let snapshot = rpc.observability();
    assert_eq!(
        snapshot.global_max_outbound_pps,
        RpcConfig::default().max_outbound_pps
    );
    assert_eq!(snapshot.work_classes.len(), 4);

    let harvest = snapshot
        .work_classes
        .iter()
        .find(|work_class| work_class.class == RpcWorkClass::Harvest)
        .expect("harvest class present");
    assert_eq!(harvest.sent_packets, 1);
    assert!(harvest.last_sent_at.is_some());

    let publish = snapshot
        .work_classes
        .iter()
        .find(|work_class| work_class.class == RpcWorkClass::Publish)
        .expect("publish class present");
    assert_eq!(publish.sent_packets, 1);
    assert!(publish.last_sent_at.is_some());
}

#[tokio::test]
async fn test_hello_request_registers_identity_and_version_for_obfuscated_reply() {
    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let inject_tx = transport.injector();
    let obfuscation = ObfuscationLayer::new(NodeId::from_bytes([0xAA; 16]), 0x1234_5678, true);
    let rpc = make_rpc_with_shared_transport(Arc::clone(&transport), obfuscation);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let peer_id = NodeId::from_bytes([0x44; 16]);
    let hello = KadPacket::HelloReq(overlord_kad_proto::HelloReq {
        node_id: peer_id,
        tcp_port: 4662,
        version: 8,
        tags: Vec::new(),
    });
    let encoded_hello = hello.encode().unwrap();
    let _ = inject_tx.send((encoded_hello, peer_addr)).await;

    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(received.packet, KadPacket::HelloReq(_)));

    let search = KadPacket::SearchKeyReq(overlord_kad_proto::SearchKeyReq {
        target: NodeId::from_bytes([0x55; 16]),
        start_position: 0,
        restrictive_payload: Vec::new(),
    });
    rpc.send(peer_addr, &search).await.unwrap();

    let outgoing = transport.drain_outgoing();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].0, peer_addr);
    assert_ne!(outgoing[0].1[0], overlord_kad_proto::OP_KADEMLIAHEADER);
}

#[tokio::test]
async fn test_obfuscated_hello_response_keeps_node_id_for_future_requests() {
    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let inject_tx = transport.injector();
    let local_node_id = NodeId::from_bytes([0xAA; 16]);
    let local_udp_key = 0x1234_5678;
    let rpc = make_rpc_with_shared_transport(
        Arc::clone(&transport),
        ObfuscationLayer::new(local_node_id, local_udp_key, true),
    );
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let peer_node_id = NodeId::from_bytes([0x44; 16]);
    let peer_udp_key = 0x5566_7788;
    let peer_obfuscation = ObfuscationLayer::new(peer_node_id, peer_udp_key, true);
    let local_addr = make_local_addr();
    peer_obfuscation.register_peer_identity(local_addr, local_node_id);
    peer_obfuscation.register_peer_version(local_addr, 8);
    let local_ip = match local_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!(),
    };
    let peer_ip = match peer_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!(),
    };
    peer_obfuscation.register_peer_key(local_addr, rpc.verify_key_for_ip(peer_ip));

    rpc.send(
        peer_addr,
        &KadPacket::HelloReq(overlord_kad_proto::HelloReq {
            node_id: local_node_id,
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        }),
    )
    .await
    .unwrap();
    transport.drain_outgoing();

    let hello_res = KadPacket::HelloRes(overlord_kad_proto::HelloRes {
        node_id: peer_node_id,
        tcp_port: 4662,
        version: 8,
        tags: Vec::new(),
    });
    let encoded_hello_res = hello_res.encode().unwrap();
    let encrypted_hello_res =
        peer_obfuscation.encrypt(local_addr, opcode::HELLO_RES, &encoded_hello_res);
    let _ = inject_tx.send((encrypted_hello_res, peer_addr)).await;

    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(received.packet, KadPacket::HelloRes(_)));
    assert!(received.was_obfuscated);
    assert_eq!(
        received.sender_verify_key,
        Some(peer_obfuscation.verify_key_for_ip(local_ip))
    );

    let search = KadPacket::SearchKeyReq(overlord_kad_proto::SearchKeyReq {
        target: NodeId::from_bytes([0x55; 16]),
        start_position: 0,
        restrictive_payload: Vec::new(),
    });
    rpc.send(peer_addr, &search).await.unwrap();

    let outgoing = transport.drain_outgoing();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].0, peer_addr);
    assert_ne!(outgoing[0].1[0] & 0x03, 0x02);
    assert_ne!(outgoing[0].1[0], overlord_kad_proto::OP_KADEMLIAHEADER);
}

#[tokio::test]
async fn test_lookup_search_response_does_not_teach_receiver_verify_key() {
    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let inject_tx = transport.injector();
    let local_node_id = NodeId::from_bytes([0xAA; 16]);
    let rpc = make_rpc_with_shared_transport(
        Arc::clone(&transport),
        ObfuscationLayer::new(local_node_id, 0x1234_5678, true),
    );
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let peer_node_id = NodeId::from_bytes([0x44; 16]);
    let peer_obfuscation = ObfuscationLayer::new(peer_node_id, 0x5566_7788, true);
    let local_addr = make_local_addr();
    let peer_ip = match peer_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!(),
    };
    peer_obfuscation.register_peer_identity(local_addr, local_node_id);
    peer_obfuscation.register_peer_version(local_addr, 8);
    peer_obfuscation.register_peer_key(local_addr, rpc.verify_key_for_ip(peer_ip));

    let search_res = KadPacket::SearchRes(overlord_kad_proto::SearchRes {
        sender_id: peer_node_id,
        target: NodeId::from_bytes([0x55; 16]),
        results: Vec::new(),
    });
    let encrypted_search_res = peer_obfuscation.encrypt(
        local_addr,
        opcode::SEARCH_RES,
        &search_res.encode().unwrap(),
    );
    let _ = inject_tx.send((encrypted_search_res, peer_addr)).await;

    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(received.packet, KadPacket::SearchRes(_)));
    assert_eq!(
        received.sender_verify_key,
        Some(peer_obfuscation.verify_key_for_ip(match local_addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(_) => unreachable!(),
        }))
    );

    rpc.send(
        peer_addr,
        &KadPacket::Firewalled2Req(overlord_kad_proto::Firewalled2Req {
            tcp_port: 4662,
            user_hash: overlord_kad_proto::Ed2kHash::ZERO,
            connect_options: 0,
        }),
    )
    .await
    .unwrap();

    let outgoing = transport.drain_outgoing();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].0, peer_addr);
    assert_ne!(outgoing[0].1[0] & 0x03, 0x02);
    assert_ne!(outgoing[0].1[0], overlord_kad_proto::OP_KADEMLIAHEADER);
}

#[tokio::test]
async fn test_plaintext_hello_request_send_keeps_raw_wire_shape() {
    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let rpc = make_rpc_with_shared_transport(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::from_bytes([0xAA; 16]), 0x1234_5678, false),
    );

    let peer_addr = make_peer_addr();
    rpc.send(
        peer_addr,
        &KadPacket::HelloReq(overlord_kad_proto::HelloReq {
            node_id: NodeId::from_bytes([0x55; 16]),
            tcp_port: 4662,
            version: overlord_kad_proto::KAD_VERSION,
            tags: Vec::new(),
        }),
    )
    .await
    .unwrap();

    let outgoing = transport.drain_outgoing();
    assert_eq!(outgoing.len(), 1);
    let (_, wire) = &outgoing[0];
    assert_eq!(wire[0], overlord_kad_proto::constants::OP_KADEMLIAHEADER);
    assert_eq!(wire[1], opcode::HELLO_REQ);
}
