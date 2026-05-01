use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use overlord_kad_dht::DhtNode;
use overlord_kad_proto::{KadUdpKey, NodeId, Tag, TagName, TagValue, tag_name};
use overlord_kad_routing::Contact;
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tracing::debug;

use crate::{ed2k_server::Ed2kServerState, kad_firewall::KadFirewallState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct KadHelloPeerMetadata {
    pub(super) hello_source_udp_port: Option<u16>,
    pub(super) udp_firewalled: bool,
    pub(super) tcp_firewalled: bool,
    pub(super) requests_hello_res_ack: bool,
}

fn read_u16_tag_value(value: &TagValue) -> Option<u16> {
    match value {
        TagValue::U16(port) => Some(*port),
        TagValue::U32(port) => u16::try_from(*port).ok(),
        TagValue::U8(port) => Some(u16::from(*port)),
        TagValue::UInt(port) => u16::try_from(*port).ok(),
        _ => None,
    }
}

fn read_u8_tag_value(value: &TagValue) -> Option<u8> {
    match value {
        TagValue::U8(bits) => Some(*bits),
        TagValue::U16(bits) => u8::try_from(*bits).ok(),
        TagValue::U32(bits) => u8::try_from(*bits).ok(),
        TagValue::UInt(bits) => u8::try_from(*bits).ok(),
        _ => None,
    }
}

pub(super) fn parse_kad_hello_metadata(tags: &[Tag]) -> KadHelloPeerMetadata {
    let mut metadata = KadHelloPeerMetadata::default();

    for tag in tags {
        match &tag.name {
            TagName::Short(name) if *name == tag_name::SOURCEUPORT => {
                metadata.hello_source_udp_port =
                    read_u16_tag_value(&tag.value).filter(|port| *port != 0);
            }
            TagName::Short(name) if *name == tag_name::KADMISCOPTIONS => {
                let Some(bits) = read_u8_tag_value(&tag.value) else {
                    continue;
                };
                metadata.udp_firewalled = (bits & 0x01) != 0;
                metadata.tcp_firewalled = (bits & 0x02) != 0;
                metadata.requests_hello_res_ack = (bits & 0x04) != 0;
            }
            _ => {}
        }
    }

    metadata
}

pub(super) async fn current_tcp_firewalled(
    ed2k_listener: &TcpListener,
    ed2k_server_state: &Arc<RwLock<Ed2kServerState>>,
) -> bool {
    if let Some(tcp_firewalled) = ed2k_server_state.read().await.tcp_firewalled() {
        return tcp_firewalled;
    }

    // Before the first ED2K server verdict arrives, a bound listener is still the
    // best local fallback signal we have.
    ed2k_listener
        .local_addr()
        .map(|addr| addr.port() == 0)
        .unwrap_or(true)
}

pub(super) fn build_kad_hello_response_tags(
    kad_udp_port: u16,
    udp_firewalled: bool,
    tcp_firewalled: bool,
    request_ack: bool,
) -> Vec<Tag> {
    let mut tags = vec![Tag::new_short(
        tag_name::SOURCEUPORT,
        TagValue::U16(kad_udp_port),
    )];
    let misc_options =
        u8::from(udp_firewalled) | (u8::from(tcp_firewalled) << 1) | (u8::from(request_ack) << 2);
    tags.push(Tag::new_short(
        tag_name::KADMISCOPTIONS,
        TagValue::U8(misc_options),
    ));
    tags
}

pub(super) fn build_kad_hello_request_tags(
    kad_udp_port: u16,
    can_advertise_source_udp_port: bool,
    udp_firewalled: bool,
    tcp_firewalled: bool,
    request_ack: bool,
) -> Vec<Tag> {
    // The matched oracle HELLO_REQ traffic in the live parity run emitted a
    // narrower tag shape than HELLO_RES: it sent either SOURCEUPORT or
    // KADMISCOPTIONS here, but not both in the same request.
    if request_ack || udp_firewalled || tcp_firewalled {
        let misc_options = u8::from(udp_firewalled)
            | (u8::from(tcp_firewalled) << 1)
            | (u8::from(request_ack) << 2);
        return vec![Tag::new_short(
            tag_name::KADMISCOPTIONS,
            TagValue::U8(misc_options),
        )];
    }

    if can_advertise_source_udp_port {
        return vec![Tag::new_short(
            tag_name::SOURCEUPORT,
            TagValue::U16(kad_udp_port),
        )];
    }

    Vec::new()
}

pub(super) fn should_request_hello_response_ack(
    peer_version: u8,
    receiver_verify_key_valid: bool,
    sender_verify_key: Option<u32>,
) -> bool {
    peer_version >= 8 && !receiver_verify_key_valid && sender_verify_key.is_some()
}

pub(super) async fn build_hello_response(
    dht: &DhtNode,
    ed2k_listener: &TcpListener,
    ed2k_server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    request_ack: bool,
) -> Result<overlord_kad_proto::HelloRes> {
    let bind_addr = dht.bind_addr()?;
    let tcp_port = ed2k_listener
        .local_addr()
        .context("failed to read eD2k listener address while building hello")?
        .port();
    let firewall = kad_firewall.lock().await;

    Ok(overlord_kad_proto::HelloRes {
        node_id: dht.own_id(),
        tcp_port,
        version: overlord_kad_proto::KAD_VERSION,
        tags: build_kad_hello_response_tags(
            bind_addr.port(),
            firewall.udp_verified && !firewall.udp_open,
            current_tcp_firewalled(ed2k_listener, ed2k_server_state).await,
            request_ack,
        ),
    })
}

pub(super) async fn build_hello_request(
    dht: &DhtNode,
    ed2k_listener: &TcpListener,
    ed2k_server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    request_ack: bool,
) -> Result<overlord_kad_proto::HelloReq> {
    let bind_addr = dht.bind_addr()?;
    let tcp_port = ed2k_listener
        .local_addr()
        .context("failed to read eD2k listener address while building hello request")?
        .port();
    let firewall = kad_firewall.lock().await;

    Ok(overlord_kad_proto::HelloReq {
        node_id: dht.own_id(),
        tcp_port,
        version: overlord_kad_proto::KAD_VERSION,
        tags: build_kad_hello_request_tags(
            bind_addr.port(),
            firewall.udp_verified && firewall.udp_open,
            firewall.udp_verified && !firewall.udp_open,
            current_tcp_firewalled(ed2k_listener, ed2k_server_state).await,
            request_ack,
        ),
    })
}

pub(super) async fn add_contact_from_hello(
    dht: &DhtNode,
    from: SocketAddr,
    node_id: NodeId,
    tcp_port: u16,
    version: u8,
    udp_key: Option<u32>,
    tags: &[Tag],
) -> Option<KadHelloPeerMetadata> {
    let mut metadata = parse_kad_hello_metadata(tags);
    if version < 8 {
        metadata.requests_hello_res_ack = false;
    }

    let std::net::IpAddr::V4(ip) = from.ip() else {
        return Some(metadata);
    };

    let mut contact = Contact::new(
        node_id,
        ip,
        metadata.hello_source_udp_port.unwrap_or(from.port()),
        tcp_port,
        version,
    );
    let routed_udp_port = contact.udp_port;
    contact.hello_source_udp_port = metadata.hello_source_udp_port;
    contact.udp_firewalled = metadata.udp_firewalled;
    contact.tcp_firewalled = metadata.tcp_firewalled;
    contact.requests_hello_res_ack = metadata.requests_hello_res_ack;
    if let Some(udp_key) = udp_key {
        contact.udp_key = KadUdpKey::new(udp_key);
    }

    if metadata.udp_firewalled {
        debug!(
            "skipping UDP-firewalled hello contact node_id={} from={} routed_udp_port={} source_uport={:?} tcp_firewalled={} requests_ack={}",
            node_id,
            from,
            routed_udp_port,
            metadata.hello_source_udp_port,
            metadata.tcp_firewalled,
            metadata.requests_hello_res_ack
        );
        return Some(metadata);
    }

    match dht.add_contact(contact).await {
        Ok(()) => {
            debug!(
                "accepted hello contact node_id={} from={} routed_udp_port={} source_uport={:?} tcp_firewalled={} requests_ack={}",
                node_id,
                from,
                routed_udp_port,
                metadata.hello_source_udp_port,
                metadata.tcp_firewalled,
                metadata.requests_hello_res_ack
            );
        }
        Err(error) => {
            debug!("failed to add hello contact from {from}: {error}");
        }
    }

    Some(metadata)
}
