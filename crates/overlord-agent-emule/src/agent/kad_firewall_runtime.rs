use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::Utc;
use overlord_agent_nat::{NatManager, NatStatus, TransportProtocol};
use overlord_kad_dht::DhtNode;
use overlord_kad_proto::{Ed2kHash, KadPacket, KadUdpKey, constants::opcode};
use overlord_kad_routing::{Contact, ContactType};
use rand::seq::SliceRandom;
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tracing::{debug, info, warn};

use super::{
    FIREWALLED_TCP_PROBE_TIMEOUT_SECS, KAD_EXTERNAL_PORT_DISCOVERY_MAX_ATTEMPTS,
    KAD_EXTERNAL_PORT_DISCOVERY_QUERY_TIMEOUT_SECS, KAD_FIREWALLED_RESPONSE_TIMEOUT_SECS,
    kad_runtime::current_tcp_firewalled,
};
use crate::{
    ed2k_server::Ed2kServerState,
    ed2k_tcp::{
        Ed2kHelloIdentity, emule_connect_options, enrich_hello_identity, send_kad_firewall_tcp_ack,
    },
    kad_firewall::{ExternalPortDiscoveryOutcome, FirewalledResponseOutcome, KadFirewallState},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ActiveUdpFirewallPorts {
    pub(super) internal: u16,
    pub(super) external: u16,
}

impl ActiveUdpFirewallPorts {
    pub(super) fn expected_ports(self) -> Vec<u16> {
        let mut ports = vec![self.internal];
        if self.external != 0 && self.external != self.internal {
            ports.push(self.external);
        }
        ports
    }
}

fn nat_external_udp_port(status: &NatStatus) -> Option<u16> {
    status
        .mappings
        .iter()
        .find(|mapping| mapping.name == "kad" && mapping.protocol == TransportProtocol::Udp)
        .map(|mapping| mapping.external_addr.port())
}

async fn discover_external_kad_udp_port(
    dht: &DhtNode,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
) -> u16 {
    let bind_ip = match dht.bind_addr() {
        Ok(bind_addr) => match bind_addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return 0,
        },
        Err(_) => return 0,
    };

    {
        let mut firewall = kad_firewall.lock().await;
        firewall.begin_external_port_discovery(Utc::now());
    }

    let mut contacts = dht
        .routing_contacts()
        .await
        .into_iter()
        .filter(|contact| {
            contact.kad_version >= 6 && contact.udp_port != 0 && contact.ip != bind_ip
        })
        .collect::<Vec<_>>();
    contacts.shuffle(&mut rand::thread_rng());

    for contact in contacts
        .into_iter()
        .take(KAD_EXTERNAL_PORT_DISCOVERY_MAX_ATTEMPTS)
    {
        let needs_discovery = {
            let firewall = kad_firewall.lock().await;
            firewall.needs_external_port_discovery()
        };
        if !needs_discovery {
            break;
        }

        let addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.udp_port);
        match dht
            .request_packet(
                addr,
                &KadPacket::Ping,
                opcode::PONG,
                Duration::from_secs(KAD_EXTERNAL_PORT_DISCOVERY_QUERY_TIMEOUT_SECS),
            )
            .await
        {
            Ok(KadPacket::Pong(pong)) => {
                let outcome = {
                    let mut firewall = kad_firewall.lock().await;
                    firewall.record_external_port_candidate(addr.ip(), pong.udp_port, Utc::now())
                };
                match outcome {
                    ExternalPortDiscoveryOutcome::Recorded => {
                        debug!(
                            "kad external UDP port candidate reporter={} reported_port={}",
                            addr, pong.udp_port
                        );
                    }
                    ExternalPortDiscoveryOutcome::Resolved(port) => {
                        info!(
                            "resolved external Kad UDP port reporter={} external_port={}",
                            addr, port
                        );
                    }
                    ExternalPortDiscoveryOutcome::Unreliable => {
                        warn!(
                            "external Kad UDP port discovery became unreliable after reporter={} reported_port={}",
                            addr, pong.udp_port
                        );
                    }
                    ExternalPortDiscoveryOutcome::Ignored => {}
                }
            }
            Ok(other) => {
                debug!(
                    "unexpected Kad packet while probing external UDP port from {addr}: {other:?}"
                );
            }
            Err(error) => {
                debug!("failed Kad external UDP port probe against {addr}: {error}");
            }
        }
    }

    let mut firewall = kad_firewall.lock().await;
    firewall.finish_external_port_discovery(Utc::now());
    firewall.external_udp_port_for_request()
}

pub(super) async fn active_udp_firewall_ports(
    dht: &DhtNode,
    nat: &NatManager,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    internal_udp_port: u16,
) -> ActiveUdpFirewallPorts {
    let status = nat.status().await;
    if let Some(external_udp_port) = nat_external_udp_port(&status) {
        return ActiveUdpFirewallPorts {
            internal: internal_udp_port,
            external: external_udp_port,
        };
    }

    let external_udp_port = discover_external_kad_udp_port(dht, kad_firewall).await;
    ActiveUdpFirewallPorts {
        internal: internal_udp_port,
        external: external_udp_port,
    }
}

pub(super) async fn select_udp_firewall_helpers(
    dht: &DhtNode,
    helper_count: usize,
) -> Result<Vec<Contact>> {
    let local_ip = dht.bind_addr()?.ip();
    let mut contacts = dht
        .routing_contacts()
        .await
        .into_iter()
        .filter(|contact| {
            contact.kad_version >= 6
                && contact.tcp_port != 0
                && contact.udp_port != 0
                && contact.contact_type != ContactType::Dead
                && IpAddr::V4(contact.ip) != local_ip
        })
        .collect::<Vec<_>>();
    contacts.shuffle(&mut rand::thread_rng());
    contacts.sort_by_key(|contact| std::cmp::Reverse(score_udp_firewall_helper(contact)));

    let mut selected = Vec::with_capacity(helper_count);
    let mut seen_ips = std::collections::HashSet::new();
    for contact in contacts {
        if seen_ips.insert(contact.ip) {
            selected.push(contact);
            if selected.len() >= helper_count {
                break;
            }
        }
    }
    Ok(selected)
}

fn score_udp_firewall_helper(contact: &Contact) -> (u8, u8, u8, u8, u8, u8) {
    (
        u8::from(contact.contact_type == ContactType::Active),
        u8::from(contact.verified),
        u8::from(!contact.tcp_firewalled),
        u8::from(!contact.udp_firewalled),
        u8::from(contact.udp_key != KadUdpKey::ZERO),
        contact.kad_version,
    )
}

async fn tcp_firewall_probe(addr: SocketAddr, timeout: Duration) -> Result<()> {
    let stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .with_context(|| format!("timed out connecting to TCP firewall probe target {addr}"))??;
    stream
        .set_nodelay(true)
        .with_context(|| format!("failed to enable TCP_NODELAY for probe target {addr}"))?;
    Ok(())
}

async fn send_firewalled_response(dht: &DhtNode, from: SocketAddr) -> Result<()> {
    let IpAddr::V4(ip) = from.ip() else {
        return Ok(());
    };
    dht.send_packet(
        from,
        &KadPacket::FirewalledRes(overlord_kad_proto::FirewalledRes {
            ip: u32::from_be_bytes(ip.octets()),
        }),
    )
    .await?;
    Ok(())
}

pub(super) fn spawn_firewalled_response(dht: DhtNode, from: SocketAddr, tcp_port: u16) {
    tokio::spawn(async move {
        let IpAddr::V4(ip) = from.ip() else {
            return;
        };
        let _ = send_firewalled_response(&dht, from).await;

        let target = SocketAddr::new(IpAddr::V4(ip), tcp_port);
        if tcp_firewall_probe(
            target,
            Duration::from_secs(FIREWALLED_TCP_PROBE_TIMEOUT_SECS),
        )
        .await
        .is_err()
        {
            return;
        }

        let _ = dht.send_packet(from, &KadPacket::FirewalledAckRes).await;
    });
}

pub(super) fn spawn_modern_firewalled_response(
    context: KadFirewalledCheckContext,
    bind_ip: Ipv4Addr,
    from: SocketAddr,
    tcp_port: u16,
    peer_user_hash: [u8; 16],
    peer_connect_options: u8,
) {
    tokio::spawn(async move {
        let IpAddr::V4(ip) = from.ip() else {
            return;
        };
        let KadFirewalledCheckContext {
            dht,
            kad_firewall,
            ed2k_listener,
            ed2k_server_state,
            ed2k_user_hash,
            ed2k_obfuscation_enabled,
        } = context;

        let _ = send_firewalled_response(&dht, from).await;

        let local_tcp_port = match ed2k_listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(error) => {
                debug!("failed to read local eD2k TCP port for Kad firewall ACK: {error}");
                return;
            }
        };
        let local_udp_port = match dht.bind_addr() {
            Ok(addr) => addr.port(),
            Err(error) => {
                debug!("failed to read local Kad UDP port for Kad firewall ACK: {error}");
                return;
            }
        };
        let hello_identity = enrich_hello_identity(
            Ed2kHelloIdentity {
                user_hash: ed2k_user_hash.0,
                client_id: 0,
                tcp_port: local_tcp_port,
                udp_port: local_udp_port,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(ed2k_obfuscation_enabled),
                direct_udp_callback: false,
            },
            &ed2k_server_state,
            &kad_firewall,
        )
        .await;
        let peer_addr = SocketAddr::new(IpAddr::V4(ip), tcp_port);

        match send_kad_firewall_tcp_ack(
            bind_ip,
            peer_addr,
            hello_identity,
            peer_user_hash,
            peer_connect_options,
            Duration::from_secs(FIREWALLED_TCP_PROBE_TIMEOUT_SECS),
        )
        .await
        {
            Ok(mode) => debug!(
                "sent Kad TCP firewall ACK to={} transport={}",
                peer_addr,
                mode.as_str()
            ),
            Err(error) => debug!("failed to send Kad TCP firewall ACK to {peer_addr}: {error}"),
        }
    });
}

/// Mirror the oracle's HELLO-triggered Kad TCP firewall/IP recheck.
///
/// When the local runtime still looks TCP-firewalled, eMule emits up to four
/// `KADEMLIA_FIREWALLED2_REQ` probes after successful HELLO exchanges. Each
/// matching `KADEMLIA_FIREWALLED_RES` reports the externally observed IP and
/// advances the bounded recheck loop.
pub(super) struct KadFirewalledCheckContext {
    pub(super) dht: DhtNode,
    pub(super) kad_firewall: Arc<Mutex<KadFirewallState>>,
    pub(super) ed2k_listener: Arc<TcpListener>,
    pub(super) ed2k_server_state: Arc<RwLock<Ed2kServerState>>,
    pub(super) ed2k_user_hash: Ed2kHash,
    pub(super) ed2k_obfuscation_enabled: bool,
}

pub(super) fn spawn_kad_firewalled_check(
    context: KadFirewalledCheckContext,
    from: SocketAddr,
    peer_version: u8,
) {
    tokio::spawn(async move {
        let KadFirewalledCheckContext {
            dht,
            kad_firewall,
            ed2k_listener,
            ed2k_server_state,
            ed2k_user_hash,
            ed2k_obfuscation_enabled,
        } = context;
        let started_at = Utc::now();
        let tcp_firewalled = current_tcp_firewalled(&ed2k_listener, &ed2k_server_state).await;
        if !tcp_firewalled {
            let mut firewall = kad_firewall.lock().await;
            firewall.refresh_tcp_recheck(false, started_at);
            return;
        }

        let IpAddr::V4(_) = from.ip() else {
            return;
        };

        {
            let mut firewall = kad_firewall.lock().await;
            firewall.refresh_tcp_recheck(true, started_at);
            if !firewall.try_begin_tcp_firewall_probe(from.ip(), started_at) {
                return;
            }
        }

        let tcp_port = match ed2k_listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(error) => {
                let mut firewall = kad_firewall.lock().await;
                firewall.record_tcp_firewall_probe_failed(
                    from.ip(),
                    &format!("failed to read local eD2k TCP port: {error}"),
                );
                return;
            }
        };

        let request = if peer_version > 6 {
            KadPacket::Firewalled2Req(overlord_kad_proto::Firewalled2Req {
                tcp_port,
                user_hash: ed2k_user_hash,
                connect_options: emule_connect_options(ed2k_obfuscation_enabled),
            })
        } else {
            KadPacket::FirewalledReq(overlord_kad_proto::FirewalledReq { tcp_port })
        };

        debug!(
            "sending Kad firewalled check to={} peer_version={} request_opcode={}",
            from,
            peer_version,
            if peer_version > 6 {
                "KADEMLIA_FIREWALLED2_REQ"
            } else {
                "KADEMLIA_FIREWALLED_REQ"
            }
        );

        match dht
            .request_packet(
                from,
                &request,
                opcode::FIREWALLED_RES,
                Duration::from_secs(KAD_FIREWALLED_RESPONSE_TIMEOUT_SECS),
            )
            .await
        {
            Ok(KadPacket::FirewalledRes(response)) => {
                let reported_ip = IpAddr::V4(Ipv4Addr::from(response.ip));
                let outcome = {
                    let mut firewall = kad_firewall.lock().await;
                    firewall.record_firewalled_response(from.ip(), reported_ip, Utc::now())
                };
                match outcome {
                    FirewalledResponseOutcome::Recorded => {
                        info!(
                            "kad firewalled check recorded helper={} reported_ip={}",
                            from, reported_ip
                        );
                    }
                    FirewalledResponseOutcome::Completed => {
                        info!(
                            "kad firewalled check completed helper={} reported_ip={}",
                            from, reported_ip
                        );
                    }
                    FirewalledResponseOutcome::Ignored => {
                        debug!(
                            "ignored unmatched Kad firewalled response helper={} reported_ip={}",
                            from, reported_ip
                        );
                    }
                }
            }
            Ok(other) => {
                let mut firewall = kad_firewall.lock().await;
                firewall.record_tcp_firewall_probe_failed(
                    from.ip(),
                    &format!("unexpected Kad firewalled response {other:?}"),
                );
            }
            Err(error) => {
                let mut firewall = kad_firewall.lock().await;
                firewall.record_tcp_firewall_probe_failed(from.ip(), &error.to_string());
                debug!("Kad firewalled check failed for {}: {}", from, error);
            }
        }
    });
}
