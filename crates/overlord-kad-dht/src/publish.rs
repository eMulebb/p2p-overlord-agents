use crate::error::DhtError;
use crate::traversal::{TraversalConfig, TraversalContact, TraversalKind, run_traversal};
use overlord_kad_net::RpcManager;
use overlord_kad_proto::constants::STORE_TIMEOUT_SECS;
use overlord_kad_proto::{
    Ed2kHash, KadPacket, NodeId, Tag,
    constants::K,
    opcode,
    packet::{PublishEntry, PublishKeyReq, PublishNotesReq, PublishSourceReq},
};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const PUBLISH_TIMEOUT: Duration = Duration::from_secs(STORE_TIMEOUT_SECS);
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const PUBLISH_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Summarizes the outcome of a Kad publish fanout over the closest contacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PublishAttemptStats {
    pub closest_contacts_considered: u32,
    pub attempted_contacts: u32,
    pub acked_contacts: u32,
    pub timed_out_contacts: u32,
}

impl PublishAttemptStats {
    #[must_use]
    pub fn failed_contacts(self) -> u32 {
        self.attempted_contacts.saturating_sub(self.acked_contacts)
    }
}

/// Captures one in-flight publish RPC so the caller can log and aggregate the
/// result after the concurrent fanout completes.
#[derive(Debug, Clone)]
struct PublishAttempt {
    rank: u32,
    total: u32,
    contact: TraversalContact,
}

/// Send the publish RPC to all selected contacts concurrently so the live wire
/// shape matches the oracle's bursty publish fanout instead of serial timeout
/// chains.
async fn execute_publish_fanout(
    rpc: &RpcManager,
    contacts: &[TraversalContact],
    packet: &KadPacket,
) -> Vec<(
    PublishAttempt,
    Result<KadPacket, overlord_kad_net::NetError>,
)> {
    let mut join_set = JoinSet::new();
    let total = contacts.len() as u32;

    for (index, contact) in contacts.iter().cloned().enumerate() {
        let rpc = rpc.clone();
        let packet = packet.clone();
        let attempt = PublishAttempt {
            rank: index as u32 + 1,
            total,
            contact,
        };
        join_set.spawn(async move {
            let result = rpc
                .request(
                    attempt.contact.addr,
                    &packet,
                    opcode::PUBLISH_RES,
                    PUBLISH_RESPONSE_TIMEOUT,
                )
                .await;
            (attempt, result)
        });
    }

    let mut results = Vec::with_capacity(contacts.len());
    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok(result) => results.push(result),
            Err(error) => {
                tracing::warn!("publish request task failed to join: {error}");
            }
        }
    }

    results
}

/// Publish a keyword→file mapping.
/// Returns the number of nodes that acknowledged.
pub async fn publish_keyword(
    rpc: &RpcManager,
    routing_table: &tokio::sync::Mutex<overlord_kad_routing::RoutingTable>,
    keyword_hash: NodeId,
    file_hash: Ed2kHash,
    tags: Vec<Tag>,
) -> Result<PublishAttemptStats, DhtError> {
    let target = keyword_hash;
    let initial = get_initial(routing_table, &target).await;

    let traversal = run_traversal(
        rpc,
        initial,
        TraversalConfig {
            target,
            search_kind: TraversalKind::Store,
            timeout: PUBLISH_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout: K,
            cancel: CancellationToken::new(),
            result_tx: None,
        },
    )
    .await;

    if traversal.closest.is_empty() {
        return Err(DhtError::PublishFailed);
    }

    let entry = PublishEntry {
        hash: file_hash,
        tags,
    };
    let packet = KadPacket::PublishKeyReq(PublishKeyReq {
        target,
        entries: vec![entry],
    });

    let publish_contacts: Vec<_> = traversal.closest.iter().take(K).cloned().collect();
    let mut stats = PublishAttemptStats {
        closest_contacts_considered: traversal.closest.len() as u32,
        attempted_contacts: publish_contacts.len() as u32,
        ..PublishAttemptStats::default()
    };
    for contact in &publish_contacts {
        register_publish_contact(rpc, contact);
    }
    for (index, contact) in publish_contacts.iter().enumerate() {
        tracing::info!(
            "kad publish contact family=keyword step=send rank={}/{} contact_addr={} contact_id={} contact_version={} target={} file_hash={}",
            index + 1,
            stats.attempted_contacts,
            contact.addr,
            contact.id,
            contact.version,
            target,
            file_hash,
        );
    }
    for (attempt, result) in execute_publish_fanout(rpc, &publish_contacts, &packet).await {
        match result {
            Ok(KadPacket::PublishRes(response)) => {
                stats.acked_contacts += 1;
                tracing::info!(
                    "kad publish contact family=keyword step=ack rank={}/{} contact_addr={} contact_id={} response_target={} response_load={}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    response.target,
                    response.load,
                );
            }
            Ok(other) => {
                stats.acked_contacts += 1;
                tracing::info!(
                    "kad publish contact family=keyword step=ack rank={}/{} contact_addr={} contact_id={} response_opcode=0x{:02X}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    other.opcode(),
                );
            }
            Err(e) => {
                if matches!(e, overlord_kad_net::NetError::Timeout { .. }) {
                    stats.timed_out_contacts += 1;
                }
                tracing::info!(
                    "kad publish contact family=keyword step=fail rank={}/{} contact_addr={} contact_id={} error={}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    e,
                );
                tracing::debug!(
                    "publish_keyword ack failed from {}: {}",
                    attempt.contact.addr,
                    e
                );
            }
        }
    }

    Ok(stats)
}

/// Publish source availability for a file.
pub async fn publish_source(
    rpc: &RpcManager,
    routing_table: &tokio::sync::Mutex<overlord_kad_routing::RoutingTable>,
    publisher_id: NodeId,
    file_hash: Ed2kHash,
    tags: Vec<Tag>,
) -> Result<PublishAttemptStats, DhtError> {
    let target = NodeId::from_bytes(file_hash.0);
    let initial = get_initial(routing_table, &target).await;

    let traversal = run_traversal(
        rpc,
        initial,
        TraversalConfig {
            target,
            search_kind: TraversalKind::Store,
            timeout: PUBLISH_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout: K,
            cancel: CancellationToken::new(),
            result_tx: None,
        },
    )
    .await;

    if traversal.closest.is_empty() {
        return Err(DhtError::PublishFailed);
    }

    let packet = KadPacket::PublishSourceReq(PublishSourceReq {
        target,
        publisher_id,
        tags,
    });

    let publish_contacts: Vec<_> = traversal.closest.iter().take(K).cloned().collect();
    let mut stats = PublishAttemptStats {
        closest_contacts_considered: traversal.closest.len() as u32,
        attempted_contacts: publish_contacts.len() as u32,
        ..PublishAttemptStats::default()
    };
    for contact in &publish_contacts {
        register_publish_contact(rpc, contact);
    }
    for (index, contact) in publish_contacts.iter().enumerate() {
        tracing::info!(
            "kad publish contact family=source step=send rank={}/{} contact_addr={} contact_id={} contact_version={} target={} file_hash={} publisher_id={}",
            index + 1,
            stats.attempted_contacts,
            contact.addr,
            contact.id,
            contact.version,
            target,
            file_hash,
            publisher_id,
        );
    }
    for (attempt, result) in execute_publish_fanout(rpc, &publish_contacts, &packet).await {
        match result {
            Ok(KadPacket::PublishRes(response)) => {
                stats.acked_contacts += 1;
                tracing::info!(
                    "kad publish contact family=source step=ack rank={}/{} contact_addr={} contact_id={} response_target={} response_load={}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    response.target,
                    response.load,
                );
            }
            Ok(other) => {
                stats.acked_contacts += 1;
                tracing::info!(
                    "kad publish contact family=source step=ack rank={}/{} contact_addr={} contact_id={} response_opcode=0x{:02X}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    other.opcode(),
                );
            }
            Err(e) => {
                if matches!(e, overlord_kad_net::NetError::Timeout { .. }) {
                    stats.timed_out_contacts += 1;
                }
                tracing::info!(
                    "kad publish contact family=source step=fail rank={}/{} contact_addr={} contact_id={} error={}",
                    attempt.rank,
                    attempt.total,
                    attempt.contact.addr,
                    attempt.contact.id,
                    e,
                );
                tracing::debug!(
                    "publish_source ack failed from {}: {}",
                    attempt.contact.addr,
                    e
                );
            }
        }
    }

    Ok(stats)
}

/// Publish a note/rating for a file.
pub async fn publish_notes(
    rpc: &RpcManager,
    routing_table: &tokio::sync::Mutex<overlord_kad_routing::RoutingTable>,
    file_hash: Ed2kHash,
    note_hash: Ed2kHash,
    tags: Vec<Tag>,
) -> Result<usize, DhtError> {
    let target = NodeId::from_bytes(file_hash.0);
    let initial = get_initial(routing_table, &target).await;

    let traversal = run_traversal(
        rpc,
        initial,
        TraversalConfig {
            target,
            search_kind: TraversalKind::Store,
            timeout: PUBLISH_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout: K,
            cancel: CancellationToken::new(),
            result_tx: None,
        },
    )
    .await;

    if traversal.closest.is_empty() {
        return Err(DhtError::PublishFailed);
    }

    let packet = KadPacket::PublishNotesReq(PublishNotesReq {
        target,
        note_hash,
        tags,
    });

    let publish_contacts: Vec<_> = traversal.closest.iter().take(K).cloned().collect();
    for contact in &publish_contacts {
        register_publish_contact(rpc, contact);
    }

    let mut acks = 0usize;
    for (attempt, result) in execute_publish_fanout(rpc, &publish_contacts, &packet).await {
        match result {
            Ok(_) => acks += 1,
            Err(e) => tracing::debug!(
                "publish_notes ack failed from {}: {}",
                attempt.contact.addr,
                e
            ),
        }
    }

    Ok(acks)
}

async fn get_initial(
    routing_table: &tokio::sync::Mutex<overlord_kad_routing::RoutingTable>,
    target: &NodeId,
) -> Vec<TraversalContact> {
    let rt = routing_table.lock().await;
    rt.get_closest(target, K)
        .into_iter()
        .map(|c| TraversalContact {
            id: c.id,
            addr: SocketAddr::new(IpAddr::V4(c.ip), c.udp_port),
            version: c.kad_version,
        })
        .collect()
}

/// Register publish-target contact identity before sending the publish request.
///
/// Publish fanout works on traversal results directly, so these contacts may not have reached the
/// routing table yet even though their Kad IDs are already known.
fn register_publish_contact(rpc: &RpcManager, contact: &TraversalContact) {
    if contact.id != NodeId::ZERO {
        rpc.register_peer_identity(contact.addr, contact.id);
    }
    rpc.register_peer_version(contact.addr, contact.version);
}
