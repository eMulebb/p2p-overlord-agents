use super::*;

pub(super) async fn test_dht() -> DhtNode {
    DhtNode::new(DhtConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        node_id: NodeId::from_bytes([0x3C; 16]),
        udp_key: 0x1122_3344,
        ..DhtConfig::default()
    })
    .await
    .unwrap()
}

pub(super) fn listener_hello_identity() -> Ed2kHelloIdentity {
    Ed2kHelloIdentity {
        user_hash: [0x22; 16],
        client_id: 0x1234_5678,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    }
}

pub(super) fn peer_hello_identity() -> Ed2kHelloIdentity {
    Ed2kHelloIdentity {
        user_hash: [0x77; 16],
        client_id: 0x8765_4321,
        tcp_port: 46671,
        udp_port: 46672,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    }
}

pub(super) fn listener_secure_ident() -> Arc<Ed2kSecureIdent> {
    test_peer_secure_ident()
}

pub(super) fn spawn_single_listener_connection(
    listener: TcpListener,
    dht: DhtNode,
    server_state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    secure_ident: Arc<Ed2kSecureIdent>,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    hello_identity: Ed2kHelloIdentity,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
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
    })
}

pub(super) async fn connect_peer_and_exchange_hello(
    peer_addr: SocketAddr,
    peer_identity: Ed2kHelloIdentity,
) -> TcpStream {
    let mut stream = TcpStream::connect(peer_addr).await.unwrap();
    stream
        .write_all(&encode_hello_request(peer_identity))
        .await
        .unwrap();
    let _hello_answer = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    stream
}
