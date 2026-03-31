use overlord_kad_net::RpcManager;
use overlord_kad_proto::{
    Ed2kHash, KadPacket, NodeId, Tag,
    constants::{
        ALPHA, K, KADEMLIA_FIND_NODE, KADEMLIA_FIND_VALUE, KADEMLIA_STORE, SEARCHTOLERANCE,
    },
    opcode,
    packet::{ContactEntry, Req, SearchKeyReq, SearchNotesReq, SearchSourceReq},
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, trace, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateState {
    Pending,
    Inflight,
    Responded,
    Failed,
}

#[derive(Debug, Clone)]
pub struct TraversalContact {
    pub id: NodeId,
    pub addr: SocketAddr,
    pub version: u8,
}

#[derive(Debug, Clone)]
pub struct TraversalCandidate {
    pub contact: TraversalContact,
    pub state: CandidateState,
    pub distance: NodeId, // XOR distance to target
}

#[derive(Debug, Clone)]
pub enum TraversalKind {
    /// Pure node lookup — just find close nodes.
    FindNode,
    /// Store lookup — publish preparation should request the store fanout like the oracle.
    Store,
    /// Keyword search — after traversal, send SearchKeyReq to close nodes.
    Keyword { request: SearchKeyReq },
    /// Source search — after traversal, send the provided SearchSourceReq to close nodes.
    Source { request: SearchSourceReq },
    /// Notes search — after traversal, send SearchNotesReq to close nodes.
    Notes { size: u64 },
}

pub struct TraversalConfig {
    pub target: NodeId,
    pub search_kind: TraversalKind,
    pub timeout: Duration,
    pub query_timeout: Duration, // per-node query timeout
    pub phase2_fanout: usize,
    pub cancel: CancellationToken,
    /// Optional streaming hook for phase-2 SEARCH_RES entries.
    ///
    /// We keep `search_entries` in the final `TraversalResult` for callers that still
    /// want the collected batch, but the node/API path now consumes results
    /// incrementally from this channel as packets arrive.
    pub result_tx: Option<mpsc::Sender<(Ed2kHash, Vec<Tag>)>>,
}

pub struct TraversalResult {
    /// K closest nodes that responded.
    pub closest: Vec<TraversalContact>,
    /// Raw SEARCH_RES entries collected for non-streaming callers.
    ///
    /// Stream-based search APIs consume results directly from `result_tx`, so
    /// they intentionally leave this buffer empty to avoid duplicating every
    /// inbound result page in memory.
    pub search_entries: Vec<(Ed2kHash, Vec<overlord_kad_proto::Tag>)>,
}

fn traversal_closest_limit(search_kind: &TraversalKind, phase2_fanout: usize) -> usize {
    match search_kind {
        TraversalKind::Store => phase2_fanout.max(K),
        _ => K,
    }
}

/// Immutable inputs for the traversal phase-2 search pass.
struct SearchPhaseConfig<'a> {
    responded: &'a [TraversalContact],
    kind: TraversalKind,
    target: NodeId,
    query_timeout: Duration,
    deadline: Instant,
    phase2_fanout: usize,
    /// Timestamp of the last traversal `RES` response.
    ///
    /// eMule only starts `StorePacket()` once the lookup has been idle for a
    /// few seconds, so phase 2 needs this to mirror the oracle's jump-start
    /// gate instead of burst-sending immediately.
    last_lookup_response_at: Option<Instant>,
    /// Oracle-style idle grace before jump-start emits the first search packet.
    jumpstart_idle_grace: Duration,
    /// Oracle-style periodic tick for walking one closest responder at a time.
    jumpstart_tick: Duration,
    cancel: &'a CancellationToken,
    result_tx: Option<mpsc::Sender<(Ed2kHash, Vec<Tag>)>>,
}

/// eMule checks stalled searches once per second.
const SEARCH_JUMPSTART_TICK: Duration = Duration::from_secs(1);
/// eMule only jump-starts once the last lookup response is at least 3 seconds old.
const SEARCH_JUMPSTART_IDLE_GRACE: Duration = Duration::from_secs(3);

pub async fn run_traversal(
    rpc: &RpcManager,
    initial_candidates: Vec<TraversalContact>,
    config: TraversalConfig,
) -> TraversalResult {
    let TraversalConfig {
        target,
        search_kind,
        timeout,
        query_timeout,
        phase2_fanout,
        cancel,
        result_tx,
    } = config;
    let deadline = Instant::now() + timeout;
    let closest_limit = traversal_closest_limit(&search_kind, phase2_fanout);

    // Determine the count byte for Req based on search kind.
    let req_count = match search_kind {
        TraversalKind::FindNode => KADEMLIA_FIND_NODE,
        TraversalKind::Store => KADEMLIA_STORE,
        _ => KADEMLIA_FIND_VALUE,
    };

    // ── Phase 1: Req/Res traversal to find K closest nodes ──────────────────

    let mut candidates: Vec<TraversalCandidate> = initial_candidates
        .into_iter()
        .map(|c| {
            let distance = target.distance(&c.id);
            TraversalCandidate {
                contact: c,
                state: CandidateState::Pending,
                distance,
            }
        })
        .collect();
    candidates.sort_by(|a, b| a.distance.cmp(&b.distance));
    candidates.dedup_by(|a, b| a.contact.id == b.contact.id);

    let mut seen: HashSet<NodeId> = candidates.iter().map(|c| c.contact.id).collect();

    let mut join_set: JoinSet<(NodeId, Result<KadPacket, overlord_kad_net::NetError>)> =
        JoinSet::new();
    let mut last_lookup_response_at = None;

    loop {
        if cancel.is_cancelled() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;

        // Launch ALPHA Req queries for closest pending candidates
        let inflight_count = candidates
            .iter()
            .filter(|c| c.state == CandidateState::Inflight)
            .count();
        let to_launch = ALPHA.saturating_sub(inflight_count);

        let pending_closest: Vec<usize> = candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| c.state == CandidateState::Pending)
            .take(to_launch)
            .map(|(i, _)| i)
            .collect();

        for idx in pending_closest {
            candidates[idx].state = CandidateState::Inflight;
            let contact = candidates[idx].contact.clone();
            register_traversal_identity(rpc, &contact);
            let rpc = rpc.clone();
            let query_timeout = query_timeout.min(remaining);

            join_set.spawn(async move {
                let packet = KadPacket::Req(Req {
                    count: req_count,
                    target,
                    recipient_id: contact.id,
                });
                let result = rpc
                    .request(contact.addr, &packet, opcode::RES, query_timeout)
                    .await;
                (contact.id, result)
            });
        }

        if join_set.is_empty() {
            break;
        }

        let next = tokio::select! {
            _ = cancel.cancelled() => break,
            next = tokio::time::timeout(remaining, join_set.join_next()) => next,
        };

        let result = match next {
            Ok(Some(Ok(r))) => r,
            Ok(Some(Err(e))) => {
                warn!("traversal task panicked: {}", e);
                continue;
            }
            Ok(None) | Err(_) => break,
        };

        let (contact_id, query_result) = result;

        let candidate_idx = candidates.iter().position(|c| c.contact.id == contact_id);

        match query_result {
            Err(e) => {
                trace!("query failed for {}: {}", contact_id, e);
                if let Some(idx) = candidate_idx {
                    candidates[idx].state = CandidateState::Failed;
                }
            }
            Ok(KadPacket::Res(res)) => {
                last_lookup_response_at = Some(Instant::now());
                if let Some(idx) = candidate_idx {
                    candidates[idx].state = CandidateState::Responded;
                }
                let sanitized = match sanitize_res_contacts(
                    &res.contacts,
                    candidates
                        .get(candidate_idx.unwrap_or(usize::MAX))
                        .map(|c| c.contact.addr)
                        .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
                    req_count as usize,
                ) {
                    Some(contacts) => contacts,
                    None => {
                        trace!(
                            "dropping RES from {} because it exceeds requested contact count",
                            contact_id
                        );
                        continue;
                    }
                };
                for entry in sanitized {
                    if seen.contains(&entry.node_id) {
                        continue;
                    }
                    if entry.ip == 0 || entry.udp_port == 0 {
                        continue;
                    }
                    seen.insert(entry.node_id);
                    let addr = SocketAddr::new(IpAddr::V4(entry.ip_addr()), entry.udp_port);
                    let distance = target.distance(&entry.node_id);
                    let c = TraversalCandidate {
                        contact: TraversalContact {
                            id: entry.node_id,
                            addr,
                            version: entry.version,
                        },
                        state: CandidateState::Pending,
                        distance,
                    };
                    let pos = candidates.partition_point(|x| x.distance < distance);
                    candidates.insert(pos, c);
                }
            }
            Ok(other) => {
                trace!(
                    "unexpected packet during traversal from {}: {:?}",
                    contact_id,
                    other.opcode()
                );
                if let Some(idx) = candidate_idx {
                    candidates[idx].state = CandidateState::Failed;
                }
            }
        }

        if matches!(search_kind, TraversalKind::FindNode) && find_node_lookup_converged(&candidates)
        {
            break;
        }

        // Termination: the responder window this traversal cares about is done.
        let closest_goal_done = candidates
            .iter()
            .take(closest_limit)
            .all(|c| matches!(c.state, CandidateState::Responded | CandidateState::Failed));
        let any_inflight = candidates
            .iter()
            .any(|c| c.state == CandidateState::Inflight);

        if closest_goal_done && !any_inflight {
            break;
        }
    }

    join_set.abort_all();

    let responded: Vec<TraversalContact> = candidates
        .iter()
        .filter(|c| c.state == CandidateState::Responded)
        .map(|c| c.contact.clone())
        .collect();
    let closest: Vec<TraversalContact> = responded.iter().take(closest_limit).cloned().collect();

    let responded_count = candidates
        .iter()
        .filter(|c| c.state == CandidateState::Responded)
        .count();
    let failed_count = candidates
        .iter()
        .filter(|c| c.state == CandidateState::Failed)
        .count();
    info!(
        "traversal phase1 done: {} responded, {} failed, {} total candidates, {} in closest set",
        responded_count,
        failed_count,
        candidates.len(),
        closest.len()
    );

    // ── Phase 2: Send search packets to close nodes ──────────────────────────

    let search_entries = match search_kind {
        TraversalKind::FindNode => vec![],
        TraversalKind::Store => vec![],
        kind => {
            run_search_phase(
                rpc,
                SearchPhaseConfig {
                    responded: &responded,
                    kind,
                    target,
                    query_timeout,
                    deadline,
                    phase2_fanout,
                    last_lookup_response_at,
                    jumpstart_idle_grace: SEARCH_JUMPSTART_IDLE_GRACE,
                    jumpstart_tick: SEARCH_JUMPSTART_TICK,
                    cancel: &cancel,
                    result_tx,
                },
            )
            .await
        }
    };

    TraversalResult {
        closest,
        search_entries,
    }
}

/// Send search packets to the selected responding nodes and collect results.
async fn run_search_phase(
    rpc: &RpcManager,
    config: SearchPhaseConfig<'_>,
) -> Vec<(Ed2kHash, Vec<overlord_kad_proto::Tag>)> {
    let SearchPhaseConfig {
        responded,
        kind,
        target,
        query_timeout,
        deadline,
        phase2_fanout,
        last_lookup_response_at,
        jumpstart_idle_grace,
        jumpstart_tick,
        cancel,
        result_tx,
    } = config;
    if cancel.is_cancelled() {
        return vec![];
    }
    let now = Instant::now();
    if now >= deadline {
        return vec![];
    }
    let remaining = deadline - now;
    let qt = query_timeout.min(remaining);
    let phase_deadline = Instant::now() + qt;

    let send_to = select_phase2_contacts(responded, target, phase2_fanout);

    info!(
        "traversal phase2: walking search packets across {} nodes, qt={:.1}s",
        send_to.len(),
        qt.as_secs_f32()
    );

    let mut unsolicited = rpc.subscribe();
    let mut queried_addrs = HashSet::new();
    let mut pending_contacts = send_to.into_iter().collect::<VecDeque<_>>();
    let mut search_entries = Vec::new();
    let should_collect_search_entries = result_tx.is_none();
    let result_tx = result_tx;
    let mut next_emit_at = compute_initial_jumpstart_emit_at(
        last_lookup_response_at,
        Instant::now(),
        jumpstart_idle_grace,
    );

    loop {
        if cancel.is_cancelled() {
            break;
        }
        let now = Instant::now();
        if now >= phase_deadline {
            break;
        }
        let receive_until = if pending_contacts.is_empty() {
            phase_deadline
        } else {
            next_emit_at.min(phase_deadline)
        };
        collect_search_results_until(
            &mut unsolicited,
            cancel,
            receive_until,
            target,
            &queried_addrs,
            &result_tx,
            should_collect_search_entries,
            &mut search_entries,
        )
        .await;

        let now = Instant::now();
        if now >= phase_deadline {
            break;
        }
        if pending_contacts.is_empty() || now < next_emit_at {
            continue;
        }

        let Some(contact) = pending_contacts.pop_front() else {
            continue;
        };
        register_traversal_identity(rpc, contact);
        let packet = match kind {
            TraversalKind::Keyword { ref request } => KadPacket::SearchKeyReq(request.clone()),
            TraversalKind::Source { ref request } => KadPacket::SearchSourceReq(request.clone()),
            TraversalKind::Notes { size } => {
                KadPacket::SearchNotesReq(SearchNotesReq { target, size })
            }
            TraversalKind::FindNode => unreachable!(),
            TraversalKind::Store => unreachable!(),
        };

        info!(
            "traversal phase2: jump-start send to {} remaining_contacts={}",
            contact.addr,
            pending_contacts.len()
        );
        if let Err(err) = rpc.send(contact.addr, &packet).await {
            trace!("search phase send failed for {}: {}", contact.id, err);
        }
        queried_addrs.insert(contact.addr);
        next_emit_at = Instant::now() + jumpstart_tick;
    }

    info!(
        "traversal phase2 done: {} total search entries collected",
        search_entries.len()
    );

    search_entries
}

/// Compute when the next phase-2 search packet is allowed to be emitted.
fn compute_initial_jumpstart_emit_at(
    last_lookup_response_at: Option<Instant>,
    now: Instant,
    jumpstart_idle_grace: Duration,
) -> Instant {
    let Some(last_lookup_response_at) = last_lookup_response_at else {
        return now;
    };
    let stalled_at = last_lookup_response_at + jumpstart_idle_grace;
    stalled_at.max(now)
}

/// Drain unsolicited packets until the next jump-start emit slot or overall deadline.
#[allow(clippy::too_many_arguments)]
async fn collect_search_results_until(
    unsolicited: &mut tokio::sync::broadcast::Receiver<overlord_kad_net::ReceivedKadPacket>,
    cancel: &CancellationToken,
    receive_until: Instant,
    target: NodeId,
    queried_addrs: &HashSet<SocketAddr>,
    result_tx: &Option<mpsc::Sender<(Ed2kHash, Vec<Tag>)>>,
    collect_search_entries: bool,
    search_entries: &mut Vec<(Ed2kHash, Vec<Tag>)>,
) {
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let now = Instant::now();
        if now >= receive_until {
            break;
        }
        let remaining = receive_until - now;
        match tokio::select! {
            _ = cancel.cancelled() => break,
            result = tokio::time::timeout(remaining, unsolicited.recv()) => result,
        } {
            Ok(Ok(overlord_kad_net::ReceivedKadPacket {
                packet: KadPacket::SearchRes(sr),
                from,
                ..
            })) => {
                if !queried_addrs.contains(&from) {
                    trace!("ignoring SEARCH_RES from unqueried sender {}", from);
                    continue;
                }
                if sr.keyword_id != target {
                    trace!(
                        "ignoring SEARCH_RES from {} for mismatched target {}",
                        from, sr.keyword_id
                    );
                    continue;
                }

                info!(
                    "search phase got SearchRes: {} results from sender {}",
                    sr.results.len(),
                    sr.sender_id
                );
                for entry in sr.results {
                    if let Some(tx) = result_tx.as_ref() {
                        let _ = tx.send((entry.hash, entry.tags.clone())).await;
                    }
                    if collect_search_entries {
                        search_entries.push((entry.hash, entry.tags));
                    }
                }
            }
            Ok(Ok(overlord_kad_net::ReceivedKadPacket {
                packet: other,
                from,
                ..
            })) => {
                if queried_addrs.contains(&from) {
                    trace!(
                        "search phase unexpected packet opcode=0x{:02X} from {}",
                        other.opcode(),
                        from
                    );
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped))) => {
                warn!(
                    "search phase broadcast receiver lagged; skipped {} packets",
                    skipped
                );
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            Err(_) => break,
        }
    }
}

/// Register traversal contact metadata with the RPC layer before sending.
///
/// Traversal frequently queries freshly discovered contacts before they are persisted in the
/// routing table, so the traversal itself must seed the RPC obfuscation cache with their Kad IDs.
fn register_traversal_identity(rpc: &RpcManager, contact: &TraversalContact) {
    if contact.id != NodeId::ZERO {
        rpc.register_peer_identity(contact.addr, contact.id);
    }
    rpc.register_peer_version(contact.addr, contact.version);
}

fn select_phase2_contacts(
    responded: &[TraversalContact],
    target: NodeId,
    phase2_fanout: usize,
) -> Vec<&TraversalContact> {
    // eMule stops phase 2 at the closest tolerated responders. We keep the
    // configurable ceiling for tests or explicit tightening, but never exceed
    // the oracle's closest-K contact window.
    let oracle_ceiling = phase2_fanout.min(K);
    responded
        .iter()
        .filter(|contact| passes_search_tolerance(target, contact))
        .take(oracle_ceiling)
        .collect()
}

/// Returns true once a pure node lookup has already locked in its closest `K` responders.
fn find_node_lookup_converged(candidates: &[TraversalCandidate]) -> bool {
    let closest_responded = candidates
        .iter()
        .filter(|candidate| candidate.state == CandidateState::Responded)
        .take(K)
        .collect::<Vec<_>>();
    let Some(threshold) = closest_responded.last().map(|candidate| candidate.distance) else {
        return false;
    };
    if closest_responded.len() < K {
        return false;
    }

    !candidates.iter().any(|candidate| {
        matches!(
            candidate.state,
            CandidateState::Pending | CandidateState::Inflight
        ) && candidate.distance <= threshold
    })
}

fn sanitize_res_contacts(
    contacts: &[ContactEntry],
    responder_addr: SocketAddr,
    max_contacts: usize,
) -> Option<Vec<ContactEntry>> {
    if contacts.len() > max_contacts {
        return None;
    }

    let mut seen_ips = HashSet::new();
    let mut prefix_counts = HashMap::<u32, usize>::new();

    if let IpAddr::V4(ip) = responder_addr.ip() {
        seen_ips.insert(ip);
        *prefix_counts.entry(ipv4_prefix_24(ip)).or_insert(0) += 1;
    }

    let mut sanitized = Vec::with_capacity(contacts.len());
    for entry in contacts {
        if entry.ip == 0 || entry.udp_port == 0 {
            continue;
        }

        let ip = entry.ip_addr();
        if !seen_ips.insert(ip) {
            continue;
        }

        // eMule rejects overly clustered RES answers by capping each /24 to two
        // contacts in one response and by treating the responder IP as already seen.
        // Reference: srchybrid/kademlia/kademlia/Search.cpp ProcessResponse.
        let prefix = ipv4_prefix_24(ip);
        let count = prefix_counts.entry(prefix).or_insert(0);
        if *count >= 2 {
            continue;
        }
        *count += 1;
        sanitized.push(entry.clone());
    }

    Some(sanitized)
}

fn passes_search_tolerance(target: NodeId, contact: &TraversalContact) -> bool {
    match contact.addr.ip() {
        IpAddr::V4(ip) if is_lan_ip(ip) => true,
        IpAddr::V4(_) => distance_high32(target.distance(&contact.id)) <= SEARCHTOLERANCE,
        IpAddr::V6(_) => false,
    }
}

fn distance_high32(distance: NodeId) -> u32 {
    // eMule compares SEARCHTOLERANCE against CUInt128::Get32BitChunk(0), and
    // our NodeId bytes are stored in the same little-endian-per-u32 chunk order
    // that goes on the wire. So the first chunk needs little-endian decoding.
    u32::from_le_bytes([distance.0[0], distance.0[1], distance.0[2], distance.0[3]])
}

fn is_lan_ip(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

fn ipv4_prefix_24(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets()) & 0xFFFF_FF00
}

#[cfg(test)]
mod tests {
    use super::*;
    use overlord_kad_net::MockTransport;
    use overlord_kad_net::{ObfuscationLayer, RpcConfig};
    use overlord_kad_proto::constants::OP_KADEMLIAHEADER;
    use overlord_kad_proto::{Ed2kHash, packet::SearchRes};
    use overlord_kad_proto::{KadPacket, NodeId};
    use std::sync::Arc;

    #[test]
    fn test_traversal_kind_clone() {
        let k = TraversalKind::FindNode;
        let _ = k;
        let k2 = TraversalKind::Keyword {
            request: SearchKeyReq {
                target: NodeId::from_bytes([0x11; 16]),
                start_position: 5,
                restrictive_payload: Vec::new(),
            },
        };
        let _ = k2;
    }

    #[test]
    fn test_candidate_sorting() {
        let target = NodeId::ZERO;
        let mut candidates = [
            TraversalCandidate {
                contact: TraversalContact {
                    id: NodeId::from_bytes([0xFF; 16]),
                    addr: "127.0.0.1:1".parse().unwrap(),
                    version: 9,
                },
                state: CandidateState::Pending,
                distance: target.distance(&NodeId::from_bytes([0xFF; 16])),
            },
            TraversalCandidate {
                contact: TraversalContact {
                    id: NodeId::from_bytes([0x01; 16]),
                    addr: "127.0.0.1:2".parse().unwrap(),
                    version: 9,
                },
                state: CandidateState::Pending,
                distance: target.distance(&NodeId::from_bytes([0x01; 16])),
            },
        ];
        candidates.sort_by(|a, b| a.distance.cmp(&b.distance));
        // 0x01... is closer to ZERO than 0xFF...
        assert_eq!(candidates[0].contact.id, NodeId::from_bytes([0x01; 16]));
    }

    #[test]
    fn test_traversal_closest_limit_keeps_store_fanout_above_oracle_k() {
        assert_eq!(traversal_closest_limit(&TraversalKind::Store, 20), 20);
        assert_eq!(traversal_closest_limit(&TraversalKind::Store, 4), K);
    }

    #[test]
    fn test_traversal_closest_limit_caps_non_store_walks_at_oracle_k() {
        assert_eq!(traversal_closest_limit(&TraversalKind::FindNode, 20), K);
        assert_eq!(
            traversal_closest_limit(
                &TraversalKind::Keyword {
                    request: SearchKeyReq {
                        target: NodeId::ZERO,
                        start_position: 0,
                        restrictive_payload: Vec::new(),
                    },
                },
                20,
            ),
            K
        );
    }

    #[test]
    fn test_sanitize_res_contacts_rejects_overlarge_reply() {
        let contacts = vec![
            ContactEntry {
                node_id: NodeId::from_bytes([1; 16]),
                ip: 0x01020304,
                udp_port: 4672,
                tcp_port: 4662,
                version: 9,
            };
            3
        ];
        assert!(sanitize_res_contacts(&contacts, "2.3.4.5:4672".parse().unwrap(), 2).is_none());
    }

    #[test]
    fn test_sanitize_res_contacts_filters_duplicate_ip_and_overpopulated_prefix() {
        let contacts = vec![
            ContactEntry {
                node_id: NodeId::from_bytes([1; 16]),
                ip: 0x01020304,
                udp_port: 4672,
                tcp_port: 4662,
                version: 9,
            },
            ContactEntry {
                node_id: NodeId::from_bytes([2; 16]),
                ip: 0x01020304,
                udp_port: 4673,
                tcp_port: 4663,
                version: 9,
            },
            ContactEntry {
                node_id: NodeId::from_bytes([3; 16]),
                ip: 0x01020355,
                udp_port: 4674,
                tcp_port: 4664,
                version: 9,
            },
            ContactEntry {
                node_id: NodeId::from_bytes([4; 16]),
                ip: 0x01020399,
                udp_port: 4675,
                tcp_port: 4665,
                version: 9,
            },
        ];

        let sanitized = sanitize_res_contacts(&contacts, "1.2.3.1:4672".parse().unwrap(), 10)
            .expect("sanitized");
        assert_eq!(sanitized.len(), 1);
        assert_eq!(sanitized[0].ip_addr(), Ipv4Addr::new(1, 2, 3, 4));
    }

    #[test]
    fn test_passes_search_tolerance_with_lan_exemption() {
        let target = NodeId::ZERO;
        let contact = TraversalContact {
            id: NodeId::from_bytes([0xFF; 16]),
            addr: "192.168.1.10:4672".parse().unwrap(),
            version: 9,
        };
        assert!(passes_search_tolerance(target, &contact));
    }

    #[test]
    fn test_passes_search_tolerance_rejects_far_contact() {
        let target = NodeId::ZERO;
        let contact = TraversalContact {
            id: NodeId::from_bytes([0xFF; 16]),
            addr: "8.8.8.8:4672".parse().unwrap(),
            version: 9,
        };
        assert!(!passes_search_tolerance(target, &contact));
    }

    #[test]
    fn test_find_node_lookup_converged_ignores_farther_unfinished_candidates() {
        let mut candidates = (0u8..K as u8)
            .map(|n| TraversalCandidate {
                contact: TraversalContact {
                    id: NodeId::from_bytes([n; 16]),
                    addr: format!("127.0.0.1:{}", 4600 + u16::from(n))
                        .parse()
                        .unwrap(),
                    version: 9,
                },
                state: CandidateState::Responded,
                distance: NodeId::from_bytes([n; 16]),
            })
            .collect::<Vec<_>>();
        candidates.push(TraversalCandidate {
            contact: TraversalContact {
                id: NodeId::from_bytes([0xFF; 16]),
                addr: "127.0.0.1:4700".parse().unwrap(),
                version: 9,
            },
            state: CandidateState::Pending,
            distance: NodeId::from_bytes([0xFF; 16]),
        });

        assert!(find_node_lookup_converged(&candidates));
    }

    #[test]
    fn test_find_node_lookup_converged_waits_for_unfinished_closer_candidate() {
        let mut candidates = (1u8..=K as u8)
            .map(|n| TraversalCandidate {
                contact: TraversalContact {
                    id: NodeId::from_bytes([n; 16]),
                    addr: format!("127.0.0.1:{}", 4600 + u16::from(n))
                        .parse()
                        .unwrap(),
                    version: 9,
                },
                state: CandidateState::Responded,
                distance: NodeId::from_bytes([n; 16]),
            })
            .collect::<Vec<_>>();
        candidates.push(TraversalCandidate {
            contact: TraversalContact {
                id: NodeId::from_bytes([0; 16]),
                addr: "127.0.0.1:4701".parse().unwrap(),
                version: 9,
            },
            state: CandidateState::Inflight,
            distance: NodeId::from_bytes([0; 16]),
        });

        assert!(!find_node_lookup_converged(&candidates));
    }

    #[test]
    fn test_select_phase2_contacts_caps_fanout_at_oracle_k() {
        let target = NodeId::ZERO;
        let responded: Vec<TraversalContact> = (1u8..=20)
            .map(|n| TraversalContact {
                id: NodeId::from_bytes([0, 0, 0, 0, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                addr: format!("192.168.1.{}:4672", n).parse().unwrap(),
                version: 9,
            })
            .collect();

        let selected = select_phase2_contacts(&responded, target, 15);
        assert_eq!(selected.len(), K);
    }

    #[test]
    fn test_select_phase2_contacts_respects_fanout_ceiling() {
        let target = NodeId::ZERO;
        let responded: Vec<TraversalContact> = (1u8..=5)
            .map(|n| TraversalContact {
                id: NodeId::from_bytes([0, 0, 0, 0, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                addr: format!("192.168.1.{}:4672", n).parse().unwrap(),
                version: 9,
            })
            .collect();

        let selected = select_phase2_contacts(&responded, target, 3);
        assert_eq!(selected.len(), 3);
    }

    #[tokio::test]
    async fn test_run_search_phase_collects_multiple_search_res_packets() {
        let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
        let injector = transport.injector();
        let rpc = RpcManager::new(
            Arc::clone(&transport),
            ObfuscationLayer::new(NodeId::ZERO, 0, false),
            RpcConfig::default(),
        );
        let _handle = rpc.start();

        let target = NodeId::from_bytes([0x22; 16]);
        let contact = TraversalContact {
            id: NodeId::from_bytes([0x11; 16]),
            addr: "192.168.1.10:4672".parse().unwrap(),
            version: 9,
        };
        let (result_tx, mut result_rx) = mpsc::channel(8);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let first = KadPacket::SearchRes(SearchRes {
                sender_id: contact.id,
                keyword_id: target,
                results: vec![overlord_kad_proto::packet::SearchResultEntry {
                    hash: Ed2kHash::from_bytes([1; 16]),
                    tags: vec![],
                }],
            });
            injector
                .send((first.encode().unwrap(), contact.addr))
                .await
                .unwrap();

            tokio::time::sleep(Duration::from_millis(10)).await;
            let second = KadPacket::SearchRes(SearchRes {
                sender_id: contact.id,
                keyword_id: target,
                results: vec![overlord_kad_proto::packet::SearchResultEntry {
                    hash: Ed2kHash::from_bytes([2; 16]),
                    tags: vec![],
                }],
            });
            injector
                .send((second.encode().unwrap(), contact.addr))
                .await
                .unwrap();
        });

        let search_entries = run_search_phase(
            &rpc,
            SearchPhaseConfig {
                responded: &[contact],
                kind: TraversalKind::Keyword {
                    request: SearchKeyReq {
                        target,
                        start_position: 0,
                        restrictive_payload: Vec::new(),
                    },
                },
                target,
                query_timeout: Duration::from_millis(100),
                deadline: Instant::now() + Duration::from_millis(300),
                phase2_fanout: 10,
                last_lookup_response_at: None,
                jumpstart_idle_grace: Duration::ZERO,
                jumpstart_tick: Duration::from_millis(10),
                cancel: &CancellationToken::new(),
                result_tx: Some(result_tx),
            },
        )
        .await;

        assert!(
            search_entries.is_empty(),
            "streaming searches should not duplicate raw SEARCH_RES storage"
        );
        let streamed_first = result_rx.recv().await.expect("first streamed result");
        let streamed_second = result_rx.recv().await.expect("second streamed result");
        assert_eq!(streamed_first.0, Ed2kHash::from_bytes([1; 16]));
        assert_eq!(streamed_second.0, Ed2kHash::from_bytes([2; 16]));
    }

    #[tokio::test]
    async fn test_run_search_phase_replays_plain_keyword_request_shape() {
        let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
        let rpc = RpcManager::new(
            Arc::clone(&transport),
            ObfuscationLayer::new(NodeId::ZERO, 0, false),
            RpcConfig::default(),
        );
        let _handle = rpc.start();

        let target = NodeId::from_bytes([0x44; 16]);
        let contact = TraversalContact {
            id: NodeId::from_bytes([0x12; 16]),
            addr: "192.168.1.20:4672".parse().unwrap(),
            version: 9,
        };

        let _ = run_search_phase(
            &rpc,
            SearchPhaseConfig {
                responded: std::slice::from_ref(&contact),
                kind: TraversalKind::Keyword {
                    request: SearchKeyReq {
                        target,
                        start_position: 0,
                        restrictive_payload: Vec::new(),
                    },
                },
                target,
                query_timeout: Duration::from_millis(20),
                deadline: Instant::now() + Duration::from_millis(50),
                phase2_fanout: 1,
                last_lookup_response_at: None,
                jumpstart_idle_grace: Duration::ZERO,
                jumpstart_tick: Duration::from_millis(10),
                cancel: &CancellationToken::new(),
                result_tx: None,
            },
        )
        .await;

        let outgoing = transport.drain_outgoing();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].0, contact.addr);
        let packet = KadPacket::decode(&outgoing[0].1).unwrap();
        let KadPacket::SearchKeyReq(request) = packet else {
            panic!("expected SearchKeyReq");
        };
        assert_eq!(request.target, target);
        assert_eq!(request.start_position, 0);
        assert!(request.restrictive_payload.is_empty());
    }

    #[tokio::test]
    async fn test_run_search_phase_replays_restrictive_keyword_payload() {
        let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
        let rpc = RpcManager::new(
            Arc::clone(&transport),
            ObfuscationLayer::new(NodeId::ZERO, 0, false),
            RpcConfig::default(),
        );
        let _handle = rpc.start();

        let target = NodeId::from_bytes([0x55; 16]);
        let contact = TraversalContact {
            id: NodeId::from_bytes([0x13; 16]),
            addr: "192.168.1.21:4672".parse().unwrap(),
            version: 9,
        };
        let restrictive_request = SearchKeyReq {
            target,
            start_position: 0x8000,
            restrictive_payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let _ = run_search_phase(
            &rpc,
            SearchPhaseConfig {
                responded: std::slice::from_ref(&contact),
                kind: TraversalKind::Keyword {
                    request: restrictive_request.clone(),
                },
                target,
                query_timeout: Duration::from_millis(20),
                deadline: Instant::now() + Duration::from_millis(50),
                phase2_fanout: 1,
                last_lookup_response_at: None,
                jumpstart_idle_grace: Duration::ZERO,
                jumpstart_tick: Duration::from_millis(10),
                cancel: &CancellationToken::new(),
                result_tx: None,
            },
        )
        .await;

        let outgoing = transport.drain_outgoing();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].0, contact.addr);
        let packet = KadPacket::decode(&outgoing[0].1).unwrap();
        let KadPacket::SearchKeyReq(request) = packet else {
            panic!("expected SearchKeyReq");
        };
        assert_eq!(request, restrictive_request);
    }

    #[tokio::test]
    async fn test_run_search_phase_replays_source_request_shape() {
        let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
        let rpc = RpcManager::new(
            Arc::clone(&transport),
            ObfuscationLayer::new(NodeId::ZERO, 0, false),
            RpcConfig::default(),
        );
        let _handle = rpc.start();

        let target = NodeId::from_bytes([0x77; 16]);
        let contact = TraversalContact {
            id: NodeId::from_bytes([0x14; 16]),
            addr: "192.168.1.22:4672".parse().unwrap(),
            version: 9,
        };
        let source_request = SearchSourceReq {
            target,
            start_position: 0x1234,
            size: 123_456,
        };

        let _ = run_search_phase(
            &rpc,
            SearchPhaseConfig {
                responded: std::slice::from_ref(&contact),
                kind: TraversalKind::Source {
                    request: source_request.clone(),
                },
                target,
                query_timeout: Duration::from_millis(20),
                deadline: Instant::now() + Duration::from_millis(50),
                phase2_fanout: 1,
                last_lookup_response_at: None,
                jumpstart_idle_grace: Duration::ZERO,
                jumpstart_tick: Duration::from_millis(10),
                cancel: &CancellationToken::new(),
                result_tx: None,
            },
        )
        .await;

        let outgoing = transport.drain_outgoing();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].0, contact.addr);
        let packet = KadPacket::decode(&outgoing[0].1).unwrap();
        let KadPacket::SearchSourceReq(request) = packet else {
            panic!("expected SearchSourceReq");
        };
        assert_eq!(request, source_request);
    }

    #[tokio::test]
    async fn test_run_search_phase_walks_one_contact_per_jumpstart_tick() {
        let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
        let rpc = RpcManager::new(
            Arc::clone(&transport),
            ObfuscationLayer::new(NodeId::ZERO, 0, false),
            RpcConfig::default(),
        );
        let _handle = rpc.start();

        let target = NodeId::from_bytes([0x66; 16]);
        let contacts = vec![
            TraversalContact {
                id: NodeId::from_bytes([0x21; 16]),
                addr: "192.168.1.31:4672".parse().unwrap(),
                version: 9,
            },
            TraversalContact {
                id: NodeId::from_bytes([0x22; 16]),
                addr: "192.168.1.32:4672".parse().unwrap(),
                version: 9,
            },
        ];
        let first_addr = contacts[0].addr;
        let second_addr = contacts[1].addr;
        let test_contacts = contacts.clone();

        let run = tokio::spawn({
            let rpc = rpc.clone();
            async move {
                run_search_phase(
                    &rpc,
                    SearchPhaseConfig {
                        responded: &test_contacts,
                        kind: TraversalKind::Keyword {
                            request: SearchKeyReq {
                                target,
                                start_position: 0,
                                restrictive_payload: Vec::new(),
                            },
                        },
                        target,
                        query_timeout: Duration::from_millis(160),
                        deadline: Instant::now() + Duration::from_millis(220),
                        phase2_fanout: 2,
                        last_lookup_response_at: Some(Instant::now()),
                        jumpstart_idle_grace: Duration::from_millis(15),
                        jumpstart_tick: Duration::from_millis(50),
                        cancel: &CancellationToken::new(),
                        result_tx: None,
                    },
                )
                .await
            }
        });

        tokio::time::sleep(Duration::from_millis(35)).await;
        let first_wave = transport.drain_outgoing();
        assert_eq!(first_wave.len(), 1);
        assert_eq!(first_wave[0].0, first_addr);

        tokio::time::sleep(Duration::from_millis(60)).await;
        let second_wave = transport.drain_outgoing();
        assert_eq!(second_wave.len(), 1);
        assert_eq!(second_wave[0].0, second_addr);

        run.await.unwrap();
    }

    #[tokio::test]
    async fn test_run_traversal_obfuscates_phase1_queries_for_fresh_contacts() {
        let transport = Arc::new(MockTransport::new("127.0.0.1:0".parse().unwrap()));
        let injector = transport.injector();
        let rpc = RpcManager::new(
            Arc::clone(&transport),
            ObfuscationLayer::new(NodeId::from_bytes([0x10; 16]), 0x1122_3344, true),
            RpcConfig::default(),
        );
        let _handle = rpc.start();

        let target = NodeId::from_bytes([0x44; 16]);
        let contact = TraversalContact {
            id: NodeId::from_bytes([0x12; 16]),
            addr: "127.0.0.1:4672".parse().unwrap(),
            version: 9,
        };
        let reply_addr = contact.addr;

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let packet = KadPacket::Res(overlord_kad_proto::packet::Res {
                target,
                contacts: Vec::new(),
            });
            injector
                .send((packet.encode().unwrap(), reply_addr))
                .await
                .unwrap();
        });

        let result = run_traversal(
            &rpc,
            vec![contact.clone()],
            TraversalConfig {
                target,
                search_kind: TraversalKind::FindNode,
                timeout: Duration::from_secs(1),
                query_timeout: Duration::from_millis(200),
                phase2_fanout: 1,
                cancel: CancellationToken::new(),
                result_tx: None,
            },
        )
        .await;

        let outgoing = transport.drain_outgoing();
        assert!(!outgoing.is_empty(), "expected traversal to send a query");
        assert_eq!(outgoing[0].0, contact.addr);
        assert_ne!(
            outgoing[0].1[0], OP_KADEMLIAHEADER,
            "phase1 query should already be obfuscated for a known Kad ID"
        );
        assert_eq!(result.closest.len(), 1);
        assert_eq!(result.closest[0].id, contact.id);
    }
}
