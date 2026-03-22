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

    let mut stats = PublishAttemptStats {
        closest_contacts_considered: traversal.closest.len() as u32,
        attempted_contacts: traversal.closest.iter().take(K).count() as u32,
        ..PublishAttemptStats::default()
    };
    for (index, contact) in traversal.closest.iter().take(K).enumerate() {
        register_publish_contact(rpc, contact);
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
        match rpc
            .request(
                contact.addr,
                &packet,
                opcode::PUBLISH_RES,
                PUBLISH_RESPONSE_TIMEOUT,
            )
            .await
        {
            Ok(KadPacket::PublishRes(response)) => {
                stats.acked_contacts += 1;
                tracing::info!(
                    "kad publish contact family=keyword step=ack rank={}/{} contact_addr={} contact_id={} response_target={} response_load={}",
                    index + 1,
                    stats.attempted_contacts,
                    contact.addr,
                    contact.id,
                    response.target,
                    response.load,
                );
            }
            Ok(other) => {
                stats.acked_contacts += 1;
                tracing::info!(
                    "kad publish contact family=keyword step=ack rank={}/{} contact_addr={} contact_id={} response_opcode=0x{:02X}",
                    index + 1,
                    stats.attempted_contacts,
                    contact.addr,
                    contact.id,
                    other.opcode(),
                );
            }
            Err(e) => {
                if matches!(e, overlord_kad_net::NetError::Timeout { .. }) {
                    stats.timed_out_contacts += 1;
                }
                tracing::info!(
                    "kad publish contact family=keyword step=fail rank={}/{} contact_addr={} contact_id={} error={}",
                    index + 1,
                    stats.attempted_contacts,
                    contact.addr,
                    contact.id,
                    e,
                );
                tracing::debug!("publish_keyword ack failed from {}: {}", contact.addr, e);
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

    let mut stats = PublishAttemptStats {
        closest_contacts_considered: traversal.closest.len() as u32,
        attempted_contacts: traversal.closest.iter().take(K).count() as u32,
        ..PublishAttemptStats::default()
    };
    for (index, contact) in traversal.closest.iter().take(K).enumerate() {
        register_publish_contact(rpc, contact);
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
        match rpc
            .request(
                contact.addr,
                &packet,
                opcode::PUBLISH_RES,
                PUBLISH_RESPONSE_TIMEOUT,
            )
            .await
        {
            Ok(KadPacket::PublishRes(response)) => {
                stats.acked_contacts += 1;
                tracing::info!(
                    "kad publish contact family=source step=ack rank={}/{} contact_addr={} contact_id={} response_target={} response_load={}",
                    index + 1,
                    stats.attempted_contacts,
                    contact.addr,
                    contact.id,
                    response.target,
                    response.load,
                );
            }
            Ok(other) => {
                stats.acked_contacts += 1;
                tracing::info!(
                    "kad publish contact family=source step=ack rank={}/{} contact_addr={} contact_id={} response_opcode=0x{:02X}",
                    index + 1,
                    stats.attempted_contacts,
                    contact.addr,
                    contact.id,
                    other.opcode(),
                );
            }
            Err(e) => {
                if matches!(e, overlord_kad_net::NetError::Timeout { .. }) {
                    stats.timed_out_contacts += 1;
                }
                tracing::info!(
                    "kad publish contact family=source step=fail rank={}/{} contact_addr={} contact_id={} error={}",
                    index + 1,
                    stats.attempted_contacts,
                    contact.addr,
                    contact.id,
                    e,
                );
                tracing::debug!("publish_source ack failed from {}: {}", contact.addr, e);
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

    let mut acks = 0usize;
    for contact in traversal.closest.iter().take(K) {
        register_publish_contact(rpc, contact);
        match rpc
            .request(
                contact.addr,
                &packet,
                opcode::PUBLISH_RES,
                PUBLISH_RESPONSE_TIMEOUT,
            )
            .await
        {
            Ok(_) => acks += 1,
            Err(e) => tracing::debug!("publish_notes ack failed from {}: {}", contact.addr, e),
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
}
