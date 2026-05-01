use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use overlord_kad_dht::RpcWorkClass;
use overlord_kad_proto::KadPacket;
use rand::seq::SliceRandom;
use tracing::{debug, info, warn};

use crate::config::EmuleAgentConfig;

use super::kad_runtime::build_hello_request;
use super::lifecycle::{persist_nodes_dat_for, random_routing_refresh_target};
use super::{AgentNetworkRuntime, OverlordAgentEmule};

impl OverlordAgentEmule {
    pub(super) async fn spawn_routing_refresh_task(
        &self,
        runtime: &AgentNetworkRuntime,
        config: &EmuleAgentConfig,
    ) {
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let state_paths = self.state_paths.clone();
        let routing_refresh_interval =
            Duration::from_secs(config.p2p.kad.routing_refresh_interval_secs.max(1));
        let nodes_dat_refresh_interval =
            Duration::from_secs(config.p2p.kad.nodes_dat_refresh_interval_secs.max(1));
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let mut last_nodes_dat_persist = Instant::now();
            let mut last_persisted_contact_count = dht.routing_contacts().await.len();
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(routing_refresh_interval).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }

                let target = random_routing_refresh_target();
                let started_at = Instant::now();
                let contacts_before = dht.routing_contacts().await.len();
                match dht
                    .lookup_nodes_with_class(&target, RpcWorkClass::Maintenance)
                    .await
                {
                    Ok(closest) => {
                        let contacts_after = dht.routing_contacts().await.len();
                        info!(
                            "kad routing refresh target={} closest={} contacts_before={} contacts_after={} elapsed_ms={}",
                            target,
                            closest.len(),
                            contacts_before,
                            contacts_after,
                            started_at.elapsed().as_millis()
                        );

                        let snapshot_due =
                            last_nodes_dat_persist.elapsed() >= nodes_dat_refresh_interval;
                        if contacts_after != last_persisted_contact_count || snapshot_due {
                            if let Err(error) = persist_nodes_dat_for(&dht, &state_paths).await {
                                warn!("failed to persist nodes.dat after routing refresh: {error}");
                            } else {
                                last_nodes_dat_persist = Instant::now();
                                last_persisted_contact_count = contacts_after;
                            }
                        }
                    }
                    Err(error) => debug!("kad routing refresh failed target={target}: {error}"),
                }
            }
        }));
    }

    pub(super) async fn spawn_kad_hello_intro_task(
        &self,
        runtime: &AgentNetworkRuntime,
        config: &EmuleAgentConfig,
    ) {
        let dht = runtime.dht.clone();
        let ed2k_listener = Arc::clone(&runtime.ed2k_listener);
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let kad_firewall = Arc::clone(&runtime.kad_firewall);
        let shutdown = Arc::clone(&runtime.shutdown);
        let hello_intro_interval_secs = config.p2p.kad.hello_intro_interval_secs;
        let hello_intro_fanout = config.p2p.kad.hello_intro_fanout;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let mut introduced = std::collections::HashSet::new();
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(hello_intro_interval_secs.max(1))).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }

                let local_ip = match dht.bind_addr() {
                    Ok(bind_addr) => bind_addr.ip(),
                    Err(error) => {
                        debug!("kad hello intro skipped: failed to resolve bind addr: {error}");
                        continue;
                    }
                };
                let mut contacts = dht
                    .routing_contacts()
                    .await
                    .into_iter()
                    .filter_map(|contact| {
                        let addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.udp_port);
                        (contact.udp_port != 0
                            && contact.kad_version >= 6
                            && IpAddr::V4(contact.ip) != local_ip
                            && !introduced.contains(&addr))
                        .then_some((contact, addr))
                    })
                    .collect::<Vec<_>>();
                contacts.shuffle(&mut rand::thread_rng());

                for (contact, addr) in contacts.into_iter().take(hello_intro_fanout.max(1)) {
                    // eMule requests HELLO_RES_ACK from HELLO_RES, not from proactive HELLO_REQ.
                    let request_ack = false;
                    let hello = match build_hello_request(
                        &dht,
                        &ed2k_listener,
                        &ed2k_server_state,
                        &kad_firewall,
                        request_ack,
                    )
                    .await
                    {
                        Ok(hello) => hello,
                        Err(error) => {
                            debug!("failed to build Kad hello request for {addr}: {error}");
                            continue;
                        }
                    };
                    debug!(
                        "sending Kad hello request to={} contact_id={} contact_version={} request_ack={}",
                        addr, contact.id, contact.kad_version, request_ack
                    );
                    if let Err(error) = dht
                        .send_packet_with_class(
                            addr,
                            &KadPacket::HelloReq(hello),
                            RpcWorkClass::Maintenance,
                        )
                        .await
                    {
                        debug!("failed to send Kad hello request to {addr}: {error}");
                        continue;
                    }
                    introduced.insert(addr);
                }
            }
        }));
    }
}
