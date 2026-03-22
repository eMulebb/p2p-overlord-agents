use crate::error::NetError;
use crate::obfuscation::{DecryptResult, ObfuscationLayer};
use crate::rate_limit::RateLimiter;
use crate::tracker::PacketTracker;
use crate::transport::Transport;
use overlord_kad_proto::{KadPacket, constants::opcode};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, oneshot};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Configuration for RpcManager.
pub struct RpcConfig {
    /// Max outbound packets per second. 0 = unlimited.
    pub max_outbound_pps: u32,
    /// Max inbound packets per IP per second before flood-blocking.
    pub max_inbound_per_ip: u32,
    /// Duration for flood-tracking window.
    pub flood_window: Duration,
    /// Capacity of the unsolicited broadcast channel.
    pub broadcast_capacity: usize,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            max_outbound_pps: 50,
            max_inbound_per_ip: 20,
            flood_window: Duration::from_secs(1),
            broadcast_capacity: 256,
        }
    }
}

struct PendingEntry {
    remote_addr: SocketAddr,
    request_opcode: u8,
    expected_opcode: u8,
    tx: oneshot::Sender<KadPacket>,
    created_at: std::time::Instant,
}

struct RpcInner {
    transport: Arc<dyn Transport>,
    obfuscation: ObfuscationLayer,
    rate_limiter: RateLimiter,
    tracker: Mutex<PacketTracker>,
    pending: Mutex<HashMap<u64, PendingEntry>>,
    next_id: AtomicU64,
    unsolicited_tx: broadcast::Sender<(KadPacket, SocketAddr)>,
}

pub struct RpcManager {
    inner: Arc<RpcInner>,
}

impl Clone for RpcManager {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl RpcManager {
    /// Create a new RpcManager. Call `start()` to begin receiving.
    pub fn new(
        transport: impl Transport,
        obfuscation: ObfuscationLayer,
        config: RpcConfig,
    ) -> Self {
        let (unsolicited_tx, _) = broadcast::channel(config.broadcast_capacity);
        let inner = Arc::new(RpcInner {
            transport: Arc::new(transport),
            obfuscation,
            rate_limiter: RateLimiter::new(config.max_outbound_pps),
            tracker: Mutex::new(PacketTracker::new(
                config.max_inbound_per_ip,
                config.flood_window,
            )),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            unsolicited_tx,
        });
        Self { inner }
    }

    /// Start the background receive loop. Returns the JoinHandle.
    /// The handle will run until the transport is closed or an unrecoverable error occurs.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            loop {
                match inner.transport.recv_raw().await {
                    Ok((data, from)) => {
                        // 1. Flood check
                        let allowed = inner.tracker.lock().unwrap().record_and_check(from.ip());
                        if !allowed {
                            warn!("flood-blocking {}", from.ip());
                            continue;
                        }

                        // 2. Obfuscation decrypt
                        let DecryptResult {
                            data: plain,
                            was_obfuscated,
                            sender_verify_key,
                        } = inner.obfuscation.decrypt(from, &data);
                        if let Some(sender_verify_key) = sender_verify_key {
                            inner.obfuscation.register_peer_key(from, sender_verify_key);
                        }
                        debug!("packet from {} was_obfuscated={}", from, was_obfuscated);

                        // 3. Parse packet
                        let packet = match KadPacket::decode(&plain) {
                            Ok(p) => p,
                            Err(e) => {
                                debug!("failed to decode packet from {}: {}", from, e);
                                continue;
                            }
                        };

                        if let Some(peer_id) = peer_identity_from_packet(&packet) {
                            inner.obfuscation.register_peer_identity(from, peer_id);
                        }

                        let response_opcode = packet.opcode();

                        // 4. Try to match a pending request
                        let matched = {
                            let mut pending = inner.pending.lock().unwrap();
                            // Find oldest matching entry
                            let match_id = pending
                                .iter()
                                .filter(|(_, e)| {
                                    e.remote_addr == from && e.expected_opcode == response_opcode
                                })
                                .min_by_key(|(_, e)| e.created_at)
                                .map(|(id, _)| *id);

                            if let Some(id) = match_id {
                                let entry = pending.remove(&id).unwrap();
                                let age_ms = entry.created_at.elapsed().as_millis();
                                debug!(
                                    "matched pending response: opcode=0x{:02X} from={}",
                                    response_opcode, from
                                );
                                if is_publish_opcode(entry.request_opcode)
                                    || is_publish_opcode(response_opcode)
                                {
                                    info!(
                                        "kad publish pending match pending_id={} request_opcode={} response_opcode={} from={} age_ms={}",
                                        id,
                                        opcode_name(entry.request_opcode),
                                        opcode_name(response_opcode),
                                        from,
                                        age_ms,
                                    );
                                }
                                let _ = entry.tx.send(packet.clone());
                                Some((id, age_ms, entry.request_opcode))
                            } else {
                                None
                            }
                        };

                        if is_publish_opcode(response_opcode) {
                            info!(
                                "kad publish recv opcode={} from={} matched_pending={} matched_pending_id={} matched_age_ms={} matched_request_opcode={} obfuscated={} sender_verify_key={}",
                                opcode_name(response_opcode),
                                from,
                                matched.is_some(),
                                matched.map(|(id, _, _)| id).unwrap_or_default(),
                                matched.map(|(_, age_ms, _)| age_ms).unwrap_or_default(),
                                matched
                                    .map(|(_, _, request_opcode)| opcode_name(request_opcode))
                                    .unwrap_or("-"),
                                was_obfuscated,
                                sender_verify_key.unwrap_or_default(),
                            );
                        }

                        // 5. If unmatched: broadcast
                        if matched.is_none() {
                            debug!(
                                "unsolicited packet: opcode=0x{:02X} from={}",
                                response_opcode, from
                            );
                            let _ = inner.unsolicited_tx.send((packet, from));
                        }
                    }
                    Err(e) => {
                        if matches!(&e, NetError::Io(io_err) if io_err.raw_os_error() == Some(10054))
                        {
                            debug!(
                                "ignoring transient Windows UDP reset while receiving: {}",
                                e
                            );
                        } else {
                            error!("transport recv error: {}", e);
                        }
                        // For IO errors, log and continue. For ChannelClosed, stop.
                        if matches!(e, NetError::ChannelClosed) {
                            break;
                        }
                    }
                }
            }
        })
    }

    /// Send a packet to addr and wait for a response matching expected_opcode.
    /// Respects the rate limiter.
    pub async fn request(
        &self,
        addr: SocketAddr,
        packet: &KadPacket,
        expected_opcode: u8,
        timeout_duration: Duration,
    ) -> Result<KadPacket, NetError> {
        let (tx, rx) = oneshot::channel();
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);

        {
            let mut pending = self.inner.pending.lock().unwrap();
            pending.insert(
                id,
                PendingEntry {
                    remote_addr: addr,
                    request_opcode: packet.opcode(),
                    expected_opcode,
                    tx,
                    created_at: std::time::Instant::now(),
                },
            );
        }

        if is_publish_opcode(packet.opcode()) || is_publish_opcode(expected_opcode) {
            info!(
                "kad publish pending add pending_id={} request_opcode={} expected_opcode={} to={} timeout_ms={}",
                id,
                opcode_name(packet.opcode()),
                opcode_name(expected_opcode),
                addr,
                timeout_duration.as_millis(),
            );
        }

        // Send the packet
        if let Err(e) = self.send(addr, packet).await {
            // Remove the pending entry since we failed to send
            self.inner.pending.lock().unwrap().remove(&id);
            return Err(e);
        }

        // Await response with timeout
        match timeout(timeout_duration, rx).await {
            Ok(Ok(pkt)) => {
                // Entry already removed by recv loop
                Ok(pkt)
            }
            Ok(Err(_)) => {
                // oneshot sender dropped — channel closed
                self.inner.pending.lock().unwrap().remove(&id);
                Err(NetError::ChannelClosed)
            }
            Err(_) => {
                // Timeout
                let elapsed_ms = self
                    .inner
                    .pending
                    .lock()
                    .unwrap()
                    .remove(&id)
                    .map(|entry| entry.created_at.elapsed().as_millis())
                    .unwrap_or_default();
                if is_publish_opcode(packet.opcode()) || is_publish_opcode(expected_opcode) {
                    info!(
                        "kad publish pending timeout pending_id={} request_opcode={} expected_opcode={} to={} age_ms={}",
                        id,
                        opcode_name(packet.opcode()),
                        opcode_name(expected_opcode),
                        addr,
                        elapsed_ms,
                    );
                }
                let secs = timeout_duration.as_secs();
                Err(NetError::Timeout { addr, secs })
            }
        }
    }

    /// Send a packet without waiting for a response.
    /// Respects the rate limiter.
    pub async fn send(&self, addr: SocketAddr, packet: &KadPacket) -> Result<(), NetError> {
        self.inner.rate_limiter.acquire().await;
        let encoded = packet.encode()?;
        let outbound = self.inner.obfuscation.inspect_outbound(addr);
        let wire = self
            .inner
            .obfuscation
            .encrypt(addr, packet.opcode(), &encoded);
        if is_publish_opcode(packet.opcode()) {
            let crypt_target = outbound
                .peer_node_id
                .map(|node_id| node_id.to_string())
                .unwrap_or_else(|| "-".to_string());
            info!(
                "kad publish send opcode={} to={} payload_len={} wire_len={} mode={} receiver_verify_key={} sender_verify_key={} crypt_target={}",
                opcode_name(packet.opcode()),
                addr,
                encoded.len(),
                wire.len(),
                outbound.mode.as_str(),
                outbound.receiver_verify_key.unwrap_or_default(),
                outbound.sender_verify_key.unwrap_or_default(),
                crypt_target,
            );
        }
        self.inner.transport.send_raw(addr, &wire).await
    }

    /// Subscribe to unsolicited incoming packets (HELLOs, PINGs, search requests, etc.)
    /// Packets that match a pending request are NOT broadcast here.
    pub fn subscribe(&self) -> broadcast::Receiver<(KadPacket, SocketAddr)> {
        self.inner.unsolicited_tx.subscribe()
    }

    /// Local UDP bind address.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        self.inner.transport.local_addr().map_err(NetError::Io)
    }

    /// Register a peer's announced receiver verify key for obfuscated replies.
    pub fn register_peer_key(&self, addr: SocketAddr, key: u32) {
        self.inner.obfuscation.register_peer_key(addr, key);
    }

    /// Derive the verify key we should announce to a specific IPv4 peer.
    #[must_use]
    pub fn verify_key_for_ip(&self, ip: Ipv4Addr) -> u32 {
        self.inner.obfuscation.verify_key_for_ip(ip)
    }

    /// Register a peer's Kad node ID for NodeID-based request obfuscation.
    pub fn register_peer_identity(&self, addr: SocketAddr, node_id: overlord_kad_proto::NodeId) {
        self.inner.obfuscation.register_peer_identity(addr, node_id);
    }
}

fn is_publish_opcode(opcode_value: u8) -> bool {
    matches!(
        opcode_value,
        opcode::PUBLISH_KEY_REQ
            | opcode::PUBLISH_SOURCE_REQ
            | opcode::PUBLISH_NOTES_REQ
            | opcode::PUBLISH_RES
            | opcode::PUBLISH_RES_ACK
    )
}

fn opcode_name(opcode_value: u8) -> &'static str {
    match opcode_value {
        opcode::PUBLISH_KEY_REQ => "KADEMLIA2_PUBLISH_KEY_REQ",
        opcode::PUBLISH_SOURCE_REQ => "KADEMLIA2_PUBLISH_SOURCE_REQ",
        opcode::PUBLISH_NOTES_REQ => "KADEMLIA2_PUBLISH_NOTES_REQ",
        opcode::PUBLISH_RES => "KADEMLIA2_PUBLISH_RES",
        opcode::PUBLISH_RES_ACK => "KADEMLIA2_PUBLISH_RES_ACK",
        _ => "UNKNOWN",
    }
}

fn peer_identity_from_packet(packet: &KadPacket) -> Option<overlord_kad_proto::NodeId> {
    match packet {
        KadPacket::BootstrapRes(res) => Some(res.sender_id),
        KadPacket::HelloReq(req) => Some(req.node_id),
        KadPacket::HelloRes(res) => Some(res.node_id),
        KadPacket::SearchRes(res) => Some(res.sender_id),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obfuscation::ObfuscationLayer;
    use crate::transport::MockTransport;
    use overlord_kad_proto::constants::opcode;
    use overlord_kad_proto::{KadPacket, NodeId};

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
            let pong = KadPacket::Pong;
            let encoded = pong.encode().unwrap();
            let _ = inject_tx.send((encoded, peer_addr)).await;
        });

        let result = rpc
            .request(peer_addr, &ping, opcode::PONG, Duration::from_secs(5))
            .await;

        assert!(result.is_ok(), "expected Ok, got {:?}", result);
        assert!(matches!(result.unwrap(), KadPacket::Pong));
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
    async fn test_unsolicited_broadcast() {
        let transport = MockTransport::new(make_local_addr());
        let inject_tx = transport.injector();
        let rpc = make_rpc_with_transport(transport);
        let mut subscriber = rpc.subscribe();
        let _handle = rpc.start();

        let peer_addr = make_peer_addr();

        // Inject a HelloResAck (no pending request for it)
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let hello = KadPacket::HelloResAck(overlord_kad_proto::HelloResAck {
                node_id: NodeId::from_bytes([0x44; 16]),
                tags: Vec::new(),
            });
            let encoded = hello.encode().unwrap();
            let _ = inject_tx.send((encoded, peer_addr)).await;
        });

        let received = tokio::time::timeout(Duration::from_secs(2), subscriber.recv()).await;
        assert!(received.is_ok(), "timed out waiting for broadcast");
        let (pkt, addr) = received.unwrap().unwrap();
        assert!(matches!(pkt, KadPacket::HelloResAck(_)));
        assert_eq!(addr, peer_addr);
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
        let pong = KadPacket::Pong;
        let encoded = pong.encode().unwrap();

        // Inject 100 packets — only first 20 should be broadcast
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

        // Should receive at most max_inbound_per_ip (20) packets from that IP
        assert!(
            received_count <= 20,
            "received {} packets, expected at most 20",
            received_count
        );
    }
}
