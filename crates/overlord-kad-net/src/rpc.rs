//! Kad RPC manager and runtime observability surface.
//!
//! `RpcManager` is the stateful boundary where raw datagrams become typed Kad
//! packets, obfuscation state is updated, pending requests are matched, and the
//! oracle-shaped packet tracker decides whether unsolicited traffic should be
//! accepted or dropped.

mod config;
mod observability;
mod packet_info;

pub use config::{MassiveFloodHandler, RpcClassBudgetConfig, RpcConfig, RpcWorkClass};
use observability::RpcObservabilityState;
pub use observability::{
    RpcObservabilitySnapshot, RpcResponseOpcodeSnapshot, RpcTrackerBucketSnapshot,
    RpcWorkClassSnapshot,
};
use packet_info::{
    hex_prefix, inbound_transport_mode, inspect_inbound_packet, is_publish_opcode,
    is_tracked_response_opcode, opcode_name, outbound_transport_reason,
    should_learn_sender_verify_key, should_log_unsolicited_opcode,
    tracked_request_opcode_for_response,
};

use crate::error::NetError;
use crate::obfuscation::{DecryptResult, ObfuscationLayer};
use crate::rate_limit::RateLimiter;
use crate::tracker::{
    OutboundRequestTracker, PacketTracker, PacketTrackerAction, PacketTrackerBucket,
    PacketTrackerKey,
};
use crate::transport::Transport;
use crate::wire_dump::{KadUdpDumpSummary, dump_kad_udp_packet};
use overlord_kad_proto::KadPacket;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, oneshot};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

struct PendingEntry {
    remote_addr: SocketAddr,
    request_opcode: u8,
    expected_opcode: u8,
    tx: oneshot::Sender<KadPacket>,
    created_at: std::time::Instant,
}

/// Unsolicited Kad packet plus the transport metadata the oracle uses for
/// HELLO verification and reply shaping.
#[derive(Debug, Clone)]
pub struct ReceivedKadPacket {
    /// Decoded Kad payload.
    pub packet: KadPacket,
    /// Remote endpoint that sent the packet.
    pub from: SocketAddr,
    /// Whether the packet arrived through Kad UDP obfuscation.
    pub was_obfuscated: bool,
    /// Sender verify key recovered from the encrypted trailer, when present.
    pub sender_verify_key: Option<u32>,
    /// Whether the sender proved our receiver verify key instead of using
    /// NodeID-mode request obfuscation.
    pub receiver_verify_key_valid: bool,
}

struct RpcInner {
    transport: Arc<dyn Transport>,
    obfuscation: ObfuscationLayer,
    global_rate_limiter: RateLimiter,
    interactive_rate_limiter: RateLimiter,
    harvest_rate_limiter: RateLimiter,
    maintenance_rate_limiter: RateLimiter,
    publish_rate_limiter: RateLimiter,
    max_outbound_pps: u32,
    class_budgets: RpcClassBudgetConfig,
    tracker: Mutex<PacketTracker>,
    outbound_tracker: Mutex<OutboundRequestTracker>,
    pending: Mutex<HashMap<u64, PendingEntry>>,
    next_id: AtomicU64,
    unsolicited_tx: broadcast::Sender<ReceivedKadPacket>,
    observability: Mutex<RpcObservabilityState>,
    massive_flood_handler: Option<MassiveFloodHandler>,
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
            global_rate_limiter: RateLimiter::new(config.max_outbound_pps),
            interactive_rate_limiter: RateLimiter::new(
                config
                    .class_budgets
                    .max_outbound_pps_for(RpcWorkClass::Interactive),
            ),
            harvest_rate_limiter: RateLimiter::new(
                config
                    .class_budgets
                    .max_outbound_pps_for(RpcWorkClass::Harvest),
            ),
            maintenance_rate_limiter: RateLimiter::new(
                config
                    .class_budgets
                    .max_outbound_pps_for(RpcWorkClass::Maintenance),
            ),
            publish_rate_limiter: RateLimiter::new(
                config
                    .class_budgets
                    .max_outbound_pps_for(RpcWorkClass::Publish),
            ),
            max_outbound_pps: config.max_outbound_pps,
            class_budgets: config.class_budgets,
            tracker: Mutex::new(PacketTracker::new(
                config.max_inbound_per_ip,
                config.max_inbound_search_res_per_ip,
                config.flood_window,
                config.request_tracking_window,
            )),
            outbound_tracker: Mutex::new(OutboundRequestTracker::new(Duration::from_secs(180))),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            unsolicited_tx,
            observability: Mutex::new(RpcObservabilityState::default()),
            massive_flood_handler: config.massive_flood_handler,
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
                        // 1. Obfuscation decrypt
                        let DecryptResult {
                            data: plain,
                            was_obfuscated,
                            sender_verify_key,
                            receiver_verify_key_valid,
                        } = inner.obfuscation.decrypt(from, &data);
                        debug!("packet from {} was_obfuscated={}", from, was_obfuscated);

                        // 3. Parse packet
                        let packet = match KadPacket::decode(&plain) {
                            Ok(p) => p,
                            Err(e) => {
                                inner.observability.lock().unwrap().record_decode_failure();
                                dump_kad_udp_packet(
                                    "recv",
                                    from,
                                    &data,
                                    &plain,
                                    KadUdpDumpSummary {
                                        protocol: plain.first().copied().unwrap_or_default(),
                                        opcode: plain.get(1).copied(),
                                        opcode_name: None,
                                        raw_obfuscated: was_obfuscated,
                                        transport_mode: Some(inbound_transport_mode(
                                            was_obfuscated,
                                            receiver_verify_key_valid,
                                        )),
                                        requested_obfuscation: None,
                                        receiver_verify_key: None,
                                        sender_verify_key,
                                        receiver_verify_key_valid: Some(receiver_verify_key_valid),
                                        tracked_request_opcode: None,
                                        drop_reason: Some("decode_failed"),
                                        tracker_bucket: None,
                                        tracker_action: None,
                                        tracker_observed_packets: None,
                                        tracker_max_packets: None,
                                    },
                                );
                                info!(
                                    "kad recv decode-failed from={} obfuscated={} raw_len={} plain_len={} raw_prefix={} plain_prefix={} error={}",
                                    from,
                                    was_obfuscated,
                                    data.len(),
                                    plain.len(),
                                    hex_prefix(&data, 16),
                                    hex_prefix(&plain, 16),
                                    e,
                                );
                                debug!("failed to decode packet from {}: {}", from, e);
                                continue;
                            }
                        };

                        let response_opcode = packet.opcode();
                        let inbound = inspect_inbound_packet(&packet);

                        if let Some(peer_id) = inbound.peer_id {
                            inner.obfuscation.register_peer_identity(from, peer_id);
                        }
                        if let Some(kad_version) = inbound.kad_version {
                            inner.obfuscation.register_peer_version(from, kad_version);
                        }
                        if should_learn_sender_verify_key(response_opcode)
                            && let Some(sender_verify_key) = sender_verify_key
                        {
                            inner.obfuscation.register_peer_key(from, sender_verify_key);
                        }

                        debug!(
                            "kad recv opcode={} from={} obfuscated={} receiver_key_valid={} sender_verify_key={} bucket={} peer_id={} peer_version={}",
                            opcode_name(response_opcode),
                            from,
                            was_obfuscated,
                            receiver_verify_key_valid,
                            sender_verify_key.unwrap_or_default(),
                            inbound
                                .tracker_bucket
                                .map(PacketTrackerBucket::label)
                                .unwrap_or("-"),
                            inbound
                                .peer_id
                                .map(|peer_id| peer_id.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                            inbound
                                .kad_version
                                .map_or_else(|| "-".to_string(), |version| version.to_string()),
                        );

                        if let Some(bucket) = inbound.tracker_bucket {
                            let decision =
                                inner
                                    .tracker
                                    .lock()
                                    .unwrap()
                                    .record_and_check(PacketTrackerKey {
                                        ip: from.ip(),
                                        bucket,
                                    });
                            inner
                                .observability
                                .lock()
                                .unwrap()
                                .record_tracker_action(bucket, decision.action);
                            if !decision.allowed {
                                let drop_reason = match decision.action {
                                    PacketTrackerAction::Allow => None,
                                    PacketTrackerAction::Drop => Some("tracker_drop"),
                                    PacketTrackerAction::MassiveDrop => {
                                        Some("tracker_massive_drop")
                                    }
                                };
                                dump_kad_udp_packet(
                                    "recv",
                                    from,
                                    &data,
                                    &plain,
                                    KadUdpDumpSummary {
                                        protocol: plain.first().copied().unwrap_or_default(),
                                        opcode: Some(response_opcode),
                                        opcode_name: Some(opcode_name(response_opcode)),
                                        raw_obfuscated: was_obfuscated,
                                        transport_mode: Some(inbound_transport_mode(
                                            was_obfuscated,
                                            receiver_verify_key_valid,
                                        )),
                                        requested_obfuscation: None,
                                        receiver_verify_key: None,
                                        sender_verify_key,
                                        receiver_verify_key_valid: Some(receiver_verify_key_valid),
                                        tracked_request_opcode: None,
                                        drop_reason,
                                        tracker_bucket: Some(bucket.label()),
                                        tracker_action: Some(decision.action.label()),
                                        tracker_observed_packets: Some(decision.observed_packets),
                                        tracker_max_packets: Some(decision.max_packets),
                                    },
                                );
                                warn!(
                                    "tracker-dropping {} opcode={} bucket={} action={} observed_packets={} max_packets={} window_ms={}",
                                    from.ip(),
                                    opcode_name(response_opcode),
                                    bucket.label(),
                                    decision.action.label(),
                                    decision.observed_packets,
                                    decision.max_packets,
                                    decision.window.as_millis(),
                                );
                                if matches!(decision.action, PacketTrackerAction::MassiveDrop)
                                    && let Some(handler) = &inner.massive_flood_handler
                                {
                                    handler(from);
                                }
                                continue;
                            }
                        }

                        // 4. Try to match a pending request
                        let matched = {
                            let mut pending = inner.pending.lock().unwrap();
                            // Prefer the exact endpoint first, then fall back to
                            // the oracle's IP-based response matching when the
                            // source port changes underneath a still-valid reply.
                            let exact_match_id = pending
                                .iter()
                                .filter(|(_, e)| {
                                    e.remote_addr == from && e.expected_opcode == response_opcode
                                })
                                .min_by_key(|(_, e)| e.created_at)
                                .map(|(id, _)| *id);

                            let ip_only_match_id = exact_match_id.or_else(|| {
                                pending
                                    .iter()
                                    .filter(|(_, e)| {
                                        e.remote_addr.ip() == from.ip()
                                            && e.expected_opcode == response_opcode
                                    })
                                    .min_by_key(|(_, e)| e.created_at)
                                    .map(|(id, _)| *id)
                            });

                            if let Some(id) = ip_only_match_id {
                                let entry = pending.remove(&id).unwrap();
                                let age_ms = entry.created_at.elapsed().as_millis();
                                let matched_by_ip_only = entry.remote_addr != from;
                                debug!(
                                    "matched pending response: opcode=0x{:02X} from={}",
                                    response_opcode, from
                                );
                                if is_publish_opcode(entry.request_opcode)
                                    || is_publish_opcode(response_opcode)
                                {
                                    debug!(
                                        "kad publish pending match pending_id={} request_opcode={} response_opcode={} from={} age_ms={}",
                                        id,
                                        opcode_name(entry.request_opcode),
                                        opcode_name(response_opcode),
                                        from,
                                        age_ms,
                                    );
                                }
                                let _ = entry.tx.send(packet.clone());
                                Some((id, age_ms, entry.request_opcode, matched_by_ip_only))
                            } else {
                                None
                            }
                        };

                        let tracked_request_opcode = tracked_request_opcode_for_response(
                            &inner.outbound_tracker,
                            from.ip(),
                            response_opcode,
                        );
                        let dump_request_opcode = matched
                            .map(|(_, _, request_opcode, _)| request_opcode)
                            .or(tracked_request_opcode);

                        let mut dump_summary = KadUdpDumpSummary {
                            protocol: plain.first().copied().unwrap_or_default(),
                            opcode: Some(response_opcode),
                            opcode_name: Some(opcode_name(response_opcode)),
                            raw_obfuscated: was_obfuscated,
                            transport_mode: Some(inbound_transport_mode(
                                was_obfuscated,
                                receiver_verify_key_valid,
                            )),
                            requested_obfuscation: None,
                            receiver_verify_key: None,
                            sender_verify_key,
                            receiver_verify_key_valid: Some(receiver_verify_key_valid),
                            tracked_request_opcode: dump_request_opcode.map(opcode_name),
                            drop_reason: None,
                            tracker_bucket: inbound.tracker_bucket.map(PacketTrackerBucket::label),
                            tracker_action: inbound.tracker_bucket.map(|_| "allow"),
                            tracker_observed_packets: None,
                            tracker_max_packets: None,
                        };

                        if is_publish_opcode(response_opcode) {
                            debug!(
                                "kad publish recv opcode={} from={} matched_pending={} matched_pending_id={} matched_age_ms={} matched_request_opcode={} matched_by_ip_only={} tracked_by_ip={} tracked_request_opcode={} obfuscated={} sender_verify_key={}",
                                opcode_name(response_opcode),
                                from,
                                matched.is_some(),
                                matched.map(|(id, _, _, _)| id).unwrap_or_default(),
                                matched.map(|(_, age_ms, _, _)| age_ms).unwrap_or_default(),
                                matched
                                    .map(|(_, _, request_opcode, _)| opcode_name(request_opcode))
                                    .unwrap_or("-"),
                                matched
                                    .map(|(_, _, _, matched_by_ip_only)| matched_by_ip_only)
                                    .unwrap_or(false),
                                tracked_request_opcode.is_some(),
                                tracked_request_opcode.map(opcode_name).unwrap_or("-"),
                                was_obfuscated,
                                sender_verify_key.unwrap_or_default(),
                            );
                        }

                        // 5. If unmatched: broadcast
                        if matched.is_none() {
                            if is_tracked_response_opcode(response_opcode)
                                && tracked_request_opcode.is_none()
                            {
                                inner
                                    .observability
                                    .lock()
                                    .unwrap()
                                    .record_response_dropped_unrequested(response_opcode);
                                dump_summary.drop_reason = Some("unrequested_response");
                                dump_kad_udp_packet("recv", from, &data, &plain, dump_summary);
                                debug!(
                                    "kad recv dropping-unrequested-response opcode={} from={} obfuscated={} sender_verify_key={}",
                                    opcode_name(response_opcode),
                                    from,
                                    was_obfuscated,
                                    sender_verify_key.unwrap_or_default(),
                                );
                                continue;
                            }
                            if is_tracked_response_opcode(response_opcode) {
                                inner
                                    .observability
                                    .lock()
                                    .unwrap()
                                    .record_response_matched_tracked(response_opcode);
                            } else {
                                inner
                                    .observability
                                    .lock()
                                    .unwrap()
                                    .record_response_accepted_unsolicited(response_opcode);
                            }
                            dump_kad_udp_packet("recv", from, &data, &plain, dump_summary);
                            if should_log_unsolicited_opcode(response_opcode) {
                                debug!(
                                    "kad recv unsolicited opcode={} from={} obfuscated={} sender_verify_key={} tracked_request_opcode={}",
                                    opcode_name(response_opcode),
                                    from,
                                    was_obfuscated,
                                    sender_verify_key.unwrap_or_default(),
                                    tracked_request_opcode.map(opcode_name).unwrap_or("-"),
                                );
                            }
                            debug!(
                                "unsolicited packet: opcode=0x{:02X} from={}",
                                response_opcode, from
                            );
                            let _ = inner.unsolicited_tx.send(ReceivedKadPacket {
                                packet,
                                from,
                                was_obfuscated,
                                sender_verify_key,
                                receiver_verify_key_valid,
                            });
                        } else {
                            inner
                                .observability
                                .lock()
                                .unwrap()
                                .record_response_matched_pending(response_opcode);
                            dump_kad_udp_packet("recv", from, &data, &plain, dump_summary);
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
        self.request_with_class(
            addr,
            packet,
            expected_opcode,
            timeout_duration,
            RpcWorkClass::Interactive,
        )
        .await
    }

    /// Send a packet to addr and wait for a response matching expected_opcode.
    /// Respects both the global safety cap and the selected work-class budget.
    pub async fn request_with_class(
        &self,
        addr: SocketAddr,
        packet: &KadPacket,
        expected_opcode: u8,
        timeout_duration: Duration,
        work_class: RpcWorkClass,
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
            debug!(
                "kad publish pending add pending_id={} request_opcode={} expected_opcode={} to={} timeout_ms={}",
                id,
                opcode_name(packet.opcode()),
                opcode_name(expected_opcode),
                addr,
                timeout_duration.as_millis(),
            );
        }

        // Send the packet
        if let Err(e) = self.send_with_class(addr, packet, work_class).await {
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
                    debug!(
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
        self.send_with_class(addr, packet, RpcWorkClass::Interactive)
            .await
    }

    /// Send a packet without waiting for a response.
    /// Respects both the global safety cap and the selected work-class budget.
    pub async fn send_with_class(
        &self,
        addr: SocketAddr,
        packet: &KadPacket,
        work_class: RpcWorkClass,
    ) -> Result<(), NetError> {
        let budget_started = std::time::Instant::now();
        self.rate_limiter_for_class(work_class).acquire().await;
        self.inner.global_rate_limiter.acquire().await;
        let wait_millis = budget_started.elapsed().as_millis() as u64;
        self.inner
            .observability
            .lock()
            .unwrap()
            .record_work_class_send(work_class, wait_millis);
        let encoded = packet.encode()?;
        let outbound = self
            .inner
            .obfuscation
            .inspect_outbound(addr, packet.opcode());
        debug!(
            "kad send opcode={} to={} mode={} reason={} peer_version={} receiver_verify_key={} sender_verify_key={} peer_node_id={}",
            opcode_name(packet.opcode()),
            addr,
            outbound.mode.as_str(),
            outbound_transport_reason(packet.opcode(), outbound),
            outbound
                .peer_kad_version
                .map_or_else(|| "-".to_string(), |version| version.to_string()),
            outbound.receiver_verify_key.unwrap_or_default(),
            outbound.sender_verify_key.unwrap_or_default(),
            outbound
                .peer_node_id
                .map(|node_id| node_id.to_string())
                .unwrap_or_else(|| "-".to_string()),
        );
        let wire = self
            .inner
            .obfuscation
            .encrypt(addr, packet.opcode(), &encoded);
        self.inner
            .outbound_tracker
            .lock()
            .unwrap()
            .record(addr.ip(), packet.opcode());
        if is_publish_opcode(packet.opcode()) {
            let crypt_target = outbound
                .peer_node_id
                .map(|node_id| node_id.to_string())
                .unwrap_or_else(|| "-".to_string());
            debug!(
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
        dump_kad_udp_packet(
            "send",
            addr,
            &wire,
            &encoded,
            KadUdpDumpSummary {
                protocol: encoded.first().copied().unwrap_or_default(),
                opcode: Some(packet.opcode()),
                opcode_name: Some(opcode_name(packet.opcode())),
                raw_obfuscated: !matches!(
                    outbound.mode,
                    crate::obfuscation::OutboundKadEncryptionMode::Plaintext
                ),
                transport_mode: Some(outbound.mode.as_str()),
                requested_obfuscation: Some(!matches!(
                    outbound.mode,
                    crate::obfuscation::OutboundKadEncryptionMode::Plaintext
                )),
                receiver_verify_key: outbound.receiver_verify_key,
                sender_verify_key: outbound.sender_verify_key,
                receiver_verify_key_valid: None,
                tracked_request_opcode: None,
                drop_reason: None,
                tracker_bucket: None,
                tracker_action: None,
                tracker_observed_packets: None,
                tracker_max_packets: None,
            },
        );
        self.inner.transport.send_raw(addr, &wire).await
    }

    /// Subscribe to unsolicited incoming packets (HELLOs, PINGs, search requests, etc.)
    /// Packets that match a pending request are NOT broadcast here.
    pub fn subscribe(&self) -> broadcast::Receiver<ReceivedKadPacket> {
        self.inner.unsolicited_tx.subscribe()
    }

    /// Local UDP bind address.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        self.inner.transport.local_addr().map_err(NetError::Io)
    }

    /// Snapshot the current tracker and response-handling counters.
    #[must_use]
    pub fn observability(&self) -> RpcObservabilitySnapshot {
        self.inner
            .observability
            .lock()
            .unwrap()
            .snapshot(self.inner.max_outbound_pps, self.inner.class_budgets)
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

    fn rate_limiter_for_class(&self, work_class: RpcWorkClass) -> &RateLimiter {
        match work_class {
            RpcWorkClass::Interactive => &self.inner.interactive_rate_limiter,
            RpcWorkClass::Harvest => &self.inner.harvest_rate_limiter,
            RpcWorkClass::Maintenance => &self.inner.maintenance_rate_limiter,
            RpcWorkClass::Publish => &self.inner.publish_rate_limiter,
        }
    }

    /// Return the latest receiver verify key learned for the peer IP behind this endpoint.
    #[must_use]
    pub fn known_peer_key(&self, addr: SocketAddr) -> Option<u32> {
        self.inner.obfuscation.receiver_verify_key_for_addr(addr)
    }

    /// Register a peer's Kad node ID for request-obfuscation fallback when no
    /// receiver verify key is known yet.
    pub fn register_peer_identity(&self, addr: SocketAddr, node_id: overlord_kad_proto::NodeId) {
        self.inner.obfuscation.register_peer_identity(addr, node_id);
    }

    /// Register the peer Kad version so outbound transport shape can match the oracle gates.
    pub fn register_peer_version(&self, addr: SocketAddr, kad_version: u8) {
        self.inner
            .obfuscation
            .register_peer_version(addr, kad_version);
    }
}

#[cfg(test)]
mod tests;
