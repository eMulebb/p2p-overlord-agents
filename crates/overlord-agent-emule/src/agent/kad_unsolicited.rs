use std::{net::IpAddr, sync::Arc};

use anyhow::Result;
use chrono::Utc;
use overlord_agent_common::{KadHarvestObservability, SnoopObservation};
use overlord_kad_dht::{DhtNode, ReceivedKadPacket};
use overlord_kad_proto::{Ed2kHash, KadPacket, constants::K, packet::ContactEntry};
use overlord_kad_routing::Contact;
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tracing::{debug, info, warn};

use super::{
    LOCAL_SEARCH_RESPONSE_LIMIT,
    kad_firewall_runtime::{
        KadFirewalledCheckContext, spawn_firewalled_response, spawn_kad_firewalled_check,
        spawn_modern_firewalled_response,
    },
    kad_runtime::{
        add_contact_from_hello, build_hello_response, should_request_hello_response_ack,
    },
    snoop::{
        build_keyword_snoop_entry, build_notes_snoop_entry, build_source_snoop_entry,
        record_snoop_entry,
    },
};
use crate::{
    ed2k_server::Ed2kServerState,
    kad_firewall::{FirewallUdpPacketOutcome, KadFirewallState},
    kad_store::KadLocalStore,
    snoop_queue::SnoopQueue,
};

pub(super) struct UnsolicitedPacketContext<'a> {
    pub(super) snoop_queue: &'a Arc<Mutex<SnoopQueue>>,
    pub(super) observed_snoop_events: &'a Arc<Mutex<Vec<SnoopObservation>>>,
    pub(super) local_store: &'a Arc<Mutex<KadLocalStore>>,
    pub(super) harvest_observability: &'a Arc<Mutex<KadHarvestObservability>>,
    pub(super) kad_firewall: &'a Arc<Mutex<KadFirewallState>>,
    pub(super) ed2k_listener: &'a Arc<TcpListener>,
    pub(super) ed2k_server_state: &'a Arc<RwLock<Ed2kServerState>>,
    pub(super) ed2k_user_hash: Ed2kHash,
    pub(super) bind_ip: std::net::Ipv4Addr,
    pub(super) ed2k_obfuscation_enabled: bool,
}

pub(super) async fn handle_unsolicited_packet(
    dht: &DhtNode,
    context: UnsolicitedPacketContext<'_>,
    received: ReceivedKadPacket,
) -> Result<()> {
    let ReceivedKadPacket {
        packet,
        from,
        sender_verify_key,
        receiver_verify_key_valid,
        ..
    } = received;

    match packet {
        KadPacket::Ping => {
            dht.send_packet(
                from,
                &KadPacket::Pong(overlord_kad_proto::Pong {
                    udp_port: from.port(),
                }),
            )
            .await?
        }
        KadPacket::FirewalledReq(req) => {
            spawn_firewalled_response(dht.clone(), from, req.tcp_port);
        }
        KadPacket::Firewalled2Req(req) => {
            spawn_modern_firewalled_response(
                KadFirewalledCheckContext {
                    dht: dht.clone(),
                    kad_firewall: Arc::clone(context.kad_firewall),
                    ed2k_listener: Arc::clone(context.ed2k_listener),
                    ed2k_server_state: Arc::clone(context.ed2k_server_state),
                    ed2k_user_hash: context.ed2k_user_hash,
                    ed2k_obfuscation_enabled: context.ed2k_obfuscation_enabled,
                },
                context.bind_ip,
                from,
                req.tcp_port,
                req.user_hash.0,
                req.connect_options,
            );
        }
        KadPacket::FirewallUdp(packet) => {
            let outcome = {
                let mut firewall = context.kad_firewall.lock().await;
                firewall.record_firewall_udp_packet(
                    from.ip(),
                    packet.error_code,
                    packet.udp_port,
                    Utc::now(),
                )
            };
            match outcome {
                FirewallUdpPacketOutcome::Open(summary) => {
                    info!(
                        "kad udp firewall-check open helpers_selected={} helpers_requested={} helpers_succeeded={} helpers_failed={} elapsed_ms={}",
                        summary.helpers_selected,
                        summary.helpers_requested,
                        summary.helpers_succeeded,
                        summary.helpers_failed,
                        (summary.completed_at - summary.started_at).num_milliseconds()
                    );
                }
                FirewallUdpPacketOutcome::Recorded => {
                    debug!(
                        "recorded kad firewall UDP packet from={} error_code={} reported_port={}",
                        from, packet.error_code, packet.udp_port
                    );
                }
                FirewallUdpPacketOutcome::Ignored => {}
            }
        }
        KadPacket::FindBuddyReq(req) => {
            debug!(
                "ignoring Kad find-buddy request from={} buddy_id={} tcp_port={} until buddy runtime is implemented",
                from, req.buddy_id, req.tcp_port
            );
        }
        KadPacket::FindBuddyRes(res) => {
            debug!(
                "ignoring unsolicited Kad find-buddy response from={} buddy_id={} tcp_port={} connect_options={:?}",
                from, res.buddy_id, res.tcp_port, res.connect_options
            );
        }
        KadPacket::CallbackReq(req) => {
            debug!(
                "ignoring Kad callback request from={} buddy_id={} file_hash={} tcp_port={} until buddy runtime is implemented",
                from, req.buddy_id, req.file_hash, req.tcp_port
            );
        }
        KadPacket::HelloReq(req) => {
            if let Some(udp_key) = sender_verify_key {
                dht.register_peer_key(from, udp_key);
            }
            let peer_metadata = add_contact_from_hello(
                dht,
                from,
                req.node_id,
                req.tcp_port,
                req.version,
                sender_verify_key,
                &req.tags,
            )
            .await;
            let request_ack = should_request_hello_response_ack(
                req.version,
                receiver_verify_key_valid,
                sender_verify_key,
            );
            let hello_res = build_hello_response(
                dht,
                context.ed2k_listener,
                context.ed2k_server_state,
                context.kad_firewall,
                request_ack,
            )
            .await?;
            let peer_metadata = peer_metadata.unwrap_or_default();
            debug!(
                "sending Kad hello response to={} request_ack={} receiver_key_valid={} peer_udp_firewalled={} peer_tcp_firewalled={} peer_requests_ack={}",
                from,
                request_ack,
                receiver_verify_key_valid,
                peer_metadata.udp_firewalled,
                peer_metadata.tcp_firewalled,
                peer_metadata.requests_hello_res_ack
            );
            if req.version >= 8 && !receiver_verify_key_valid && sender_verify_key.is_none() {
                debug!(
                    "skipping HELLO_RES ACK request to={} because sender verify key is unavailable",
                    from
                );
            }
            let _ = dht.send_packet(from, &KadPacket::HelloRes(hello_res)).await;
            spawn_kad_firewalled_check(
                KadFirewalledCheckContext {
                    dht: dht.clone(),
                    kad_firewall: Arc::clone(context.kad_firewall),
                    ed2k_listener: Arc::clone(context.ed2k_listener),
                    ed2k_server_state: Arc::clone(context.ed2k_server_state),
                    ed2k_user_hash: context.ed2k_user_hash,
                    ed2k_obfuscation_enabled: context.ed2k_obfuscation_enabled,
                },
                from,
                req.version,
            );
        }
        KadPacket::HelloRes(res) => {
            if let Some(udp_key) = sender_verify_key {
                dht.register_peer_key(from, udp_key);
            }
            let peer_metadata = add_contact_from_hello(
                dht,
                from,
                res.node_id,
                res.tcp_port,
                res.version,
                sender_verify_key,
                &res.tags,
            )
            .await
            .unwrap_or_default();
            if peer_metadata.requests_hello_res_ack {
                if sender_verify_key.is_none() {
                    warn!(
                        "peer requested HELLO_RES_ACK without a UDP key from={}",
                        from
                    );
                } else {
                    debug!(
                        "sending Kad hello response ACK to={} peer_udp_firewalled={} peer_tcp_firewalled={}",
                        from, peer_metadata.udp_firewalled, peer_metadata.tcp_firewalled
                    );
                    let _ = dht
                        .send_packet(
                            from,
                            &KadPacket::HelloResAck(overlord_kad_proto::HelloResAck {
                                node_id: dht.own_id(),
                                tags: Vec::new(),
                            }),
                        )
                        .await;
                }
            }
            spawn_kad_firewalled_check(
                KadFirewalledCheckContext {
                    dht: dht.clone(),
                    kad_firewall: Arc::clone(context.kad_firewall),
                    ed2k_listener: Arc::clone(context.ed2k_listener),
                    ed2k_server_state: Arc::clone(context.ed2k_server_state),
                    ed2k_user_hash: context.ed2k_user_hash,
                    ed2k_obfuscation_enabled: context.ed2k_obfuscation_enabled,
                },
                from,
                res.version,
            );
        }
        KadPacket::HelloResAck(_ack) => {}
        KadPacket::BootstrapReq => {
            let bind_addr = dht.bind_addr()?;
            let contacts = dht
                .closest_contacts(&dht.own_id(), K)
                .await
                .into_iter()
                .map(contact_to_entry)
                .collect();
            dht.send_packet(
                from,
                &KadPacket::BootstrapRes(overlord_kad_proto::BootstrapRes {
                    sender_id: dht.own_id(),
                    sender_tcp_port: bind_addr.port(),
                    sender_version: overlord_kad_proto::KAD_VERSION,
                    contacts,
                }),
            )
            .await?;
        }
        KadPacket::Req(req) => {
            let contacts = dht
                .closest_contacts(&req.target, req.count as usize)
                .await
                .into_iter()
                .map(contact_to_entry)
                .collect();
            dht.send_packet(
                from,
                &KadPacket::Res(overlord_kad_proto::Res {
                    target: req.target,
                    contacts,
                }),
            )
            .await?;
        }
        KadPacket::SearchKeyReq(req) => {
            let observed_at = Utc::now();
            record_snoop_entry(
                context.snoop_queue,
                context.observed_snoop_events,
                context.harvest_observability,
                from,
                build_keyword_snoop_entry(&req, observed_at),
            )
            .await;
            let response = {
                let mut store = context.local_store.lock().await;
                // Restrictive keyword searches carry opaque payloads which we
                // do not parse yet, so only non-restrictive queries are served
                // from the local store in v1.
                store.keyword_search_response(
                    dht.own_id(),
                    &req,
                    LOCAL_SEARCH_RESPONSE_LIMIT,
                    observed_at,
                )
            };
            if let Some(response) = response {
                let _ = dht.send_packet(from, &KadPacket::SearchRes(response)).await;
            }
        }
        KadPacket::SearchSourceReq(req) => {
            let observed_at = Utc::now();
            record_snoop_entry(
                context.snoop_queue,
                context.observed_snoop_events,
                context.harvest_observability,
                from,
                build_source_snoop_entry(&req, observed_at),
            )
            .await;
            let response = {
                let mut store = context.local_store.lock().await;
                store.source_search_response(
                    dht.own_id(),
                    &req,
                    LOCAL_SEARCH_RESPONSE_LIMIT,
                    observed_at,
                )
            };
            if let Some(response) = response {
                let _ = dht.send_packet(from, &KadPacket::SearchRes(response)).await;
            }
        }
        KadPacket::SearchNotesReq(req) => {
            let observed_at = Utc::now();
            record_snoop_entry(
                context.snoop_queue,
                context.observed_snoop_events,
                context.harvest_observability,
                from,
                build_notes_snoop_entry(&req, observed_at),
            )
            .await;
            let response = {
                let mut store = context.local_store.lock().await;
                store.notes_search_response(
                    dht.own_id(),
                    &req,
                    LOCAL_SEARCH_RESPONSE_LIMIT,
                    observed_at,
                )
            };
            if let Some(response) = response {
                let _ = dht.send_packet(from, &KadPacket::SearchRes(response)).await;
            }
        }
        KadPacket::PublishKeyReq(req) => {
            let observed_at = Utc::now();
            {
                let mut store = context.local_store.lock().await;
                store.record_keyword_publish_batch(req.target, &req.entries, observed_at);
            }
            let _ = dht
                .send_packet(
                    from,
                    &KadPacket::PublishRes(overlord_kad_proto::PublishRes {
                        target: req.target,
                        load: 0,
                        options: None,
                    }),
                )
                .await;
        }
        KadPacket::PublishSourceReq(req) => {
            let accepted = if let IpAddr::V4(ip) = from.ip() {
                let mut store = context.local_store.lock().await;
                store.record_source_publish(
                    req.target,
                    req.publisher_id,
                    ip,
                    from.port(),
                    &req.tags,
                    Utc::now(),
                )
            } else {
                false
            };
            if accepted {
                let _ = dht
                    .send_packet(
                        from,
                        &KadPacket::PublishRes(overlord_kad_proto::PublishRes {
                            target: req.target,
                            load: 0,
                            options: None,
                        }),
                    )
                    .await;
            } else {
                debug!(
                    "rejecting Kad source publish from={} target={} publisher_id={} without stock source marker",
                    from, req.target, req.publisher_id
                );
            }
        }
        KadPacket::PublishNotesReq(req) => {
            {
                let mut store = context.local_store.lock().await;
                store.record_notes_publish(req.target, req.publisher_id, &req.tags, Utc::now());
            }
            let _ = dht
                .send_packet(
                    from,
                    &KadPacket::PublishRes(overlord_kad_proto::PublishRes {
                        target: req.target,
                        load: 0,
                        options: None,
                    }),
                )
                .await;
        }
        _ => {}
    }
    Ok(())
}

fn contact_to_entry(contact: Contact) -> ContactEntry {
    ContactEntry {
        node_id: contact.id,
        ip: u32::from_be_bytes(contact.ip.octets()),
        udp_port: contact.udp_port,
        tcp_port: contact.tcp_port,
        version: contact.kad_version,
    }
}
