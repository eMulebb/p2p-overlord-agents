use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use chrono::Utc;
use tracing::{debug, info, warn};

use crate::config::EmuleAgentConfig;
use crate::ed2k_tcp::{FirewallCheckUdpRequest, enrich_hello_identity, request_udp_firewall_check};

use super::ed2k_runtime::ed2k_hello_identity_from_config;
use super::kad_firewall_runtime::{active_udp_firewall_ports, select_udp_firewall_helpers};
use super::{AgentNetworkRuntime, OverlordAgentEmule, UDP_FIREWALL_HELPER_CANDIDATE_MULTIPLIER};

impl OverlordAgentEmule {
    pub(super) async fn spawn_udp_firewall_check_task(
        &self,
        runtime: &AgentNetworkRuntime,
        config: &EmuleAgentConfig,
    ) {
        let dht = runtime.dht.clone();
        let nat = Arc::clone(&runtime.nat);
        let shutdown = Arc::clone(&runtime.shutdown);
        let kad_firewall = Arc::clone(&runtime.kad_firewall);
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let ed2k_secure_ident = Arc::clone(&runtime.ed2k_secure_ident);
        let udp_firewall_check_enabled = config.p2p.kad.udp_firewall_check_enabled;
        let udp_firewall_recheck_interval =
            Duration::from_secs(config.p2p.kad.udp_firewall_recheck_interval_secs.max(1));
        let udp_firewall_check_timeout =
            Duration::from_secs(config.p2p.kad.udp_firewall_check_timeout_secs.max(1));
        let udp_firewall_check_contact_count = config.p2p.kad.udp_firewall_check_contact_count;
        let ed2k_user_hash = self.ed2k_user_hash;
        let ed2k_hello_identity = ed2k_hello_identity_from_config(config, ed2k_user_hash);
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            if !udp_firewall_check_enabled {
                return;
            }

            while !shutdown.load(Ordering::Relaxed) {
                if !dht.is_bootstrapped() {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    continue;
                }

                let bind_addr = match dht.bind_addr() {
                    Ok(bind_addr) => bind_addr,
                    Err(error) => {
                        debug!("kad firewall-check skipped: failed to resolve bind addr: {error}");
                        continue;
                    }
                };
                let helper_hello_identity = enrich_hello_identity(
                    ed2k_hello_identity,
                    &ed2k_server_state,
                    &kad_firewall,
                )
                .await;
                if helper_hello_identity.client_id == 0
                    || helper_hello_identity.server_ip == 0
                    || helper_hello_identity.server_port == 0
                {
                    debug!(
                        "kad firewall-check skipped: ED2K helper hello not ready client_id={} server_ip={} server_port={}",
                        helper_hello_identity.client_id,
                        Ipv4Addr::from(helper_hello_identity.server_ip.to_le_bytes()),
                        helper_hello_identity.server_port
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                let helper_contacts = match select_udp_firewall_helpers(
                    &dht,
                    udp_firewall_check_contact_count
                        .saturating_mul(UDP_FIREWALL_HELPER_CANDIDATE_MULTIPLIER),
                )
                .await
                {
                    Ok(contacts) => contacts,
                    Err(error) => {
                        debug!("kad firewall-check helper selection failed: {error}");
                        continue;
                    }
                };
                if helper_contacts.is_empty() {
                    debug!("kad firewall-check skipped: no helper contacts available");
                    continue;
                }

                let bind_ip = match bind_addr.ip() {
                    IpAddr::V4(ip) => ip,
                    IpAddr::V6(_) => {
                        debug!("kad firewall-check skipped: IPv6 bind addr is not supported");
                        continue;
                    }
                };
                let active_ports =
                    active_udp_firewall_ports(&dht, &nat, &kad_firewall, bind_addr.port()).await;
                let expected_ports = active_ports.expected_ports();
                let started_at = Utc::now();
                {
                    let mut firewall = kad_firewall.lock().await;
                    if !firewall.begin_udp_check(
                        helper_contacts.iter().map(|contact| IpAddr::V4(contact.ip)),
                        expected_ports.iter().copied(),
                        started_at,
                    ) {
                        continue;
                    }
                }

                let internal_udp_port = active_ports.internal;
                let external_udp_port = active_ports.external;
                info!(
                    "starting kad udp firewall-check target_helpers={} candidate_helpers={} internal_port={} external_port={}",
                    udp_firewall_check_contact_count,
                    helper_contacts.len(),
                    internal_udp_port,
                    external_udp_port
                );
                debug!(
                    "kad udp firewall-check helper hello client_id={} server_ip={} server_port={} direct_udp_callback={}",
                    helper_hello_identity.client_id,
                    Ipv4Addr::from(helper_hello_identity.server_ip.to_le_bytes()),
                    helper_hello_identity.server_port,
                    helper_hello_identity.direct_udp_callback
                );

                let mut request_tasks = Vec::with_capacity(helper_contacts.len());
                for contact in helper_contacts {
                    let helper_addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.tcp_port);
                    let helper_ip = IpAddr::V4(contact.ip);
                    let request = FirewallCheckUdpRequest {
                        internal_udp_port,
                        external_udp_port,
                        sender_udp_key: dht.verify_key_for_ip(contact.ip),
                    };
                    let secure_ident = Arc::clone(&ed2k_secure_ident);
                    let helper_dht = dht.clone();
                    request_tasks.push(tokio::spawn(async move {
                        let result = request_udp_firewall_check(
                            Some(helper_dht),
                            bind_ip,
                            helper_addr,
                            helper_hello_identity,
                            secure_ident,
                            request,
                            udp_firewall_check_timeout,
                        )
                        .await;
                        (helper_ip, helper_addr, result)
                    }));
                }

                for task in request_tasks {
                    match task.await {
                        Ok((_helper_ip, helper_addr, Ok(()))) => {
                            debug!("sent OP_FWCHECKUDPREQ to helper {helper_addr}");
                        }
                        Ok((helper_ip, helper_addr, Err(error))) => {
                            let mut firewall = kad_firewall.lock().await;
                            firewall.record_helper_request_failed(helper_ip, &error.to_string());
                            debug!("failed to send OP_FWCHECKUDPREQ to helper {helper_addr}: {error}");
                        }
                        Err(error) => {
                            debug!("UDP firewall-check helper task failed: {error}");
                        }
                    }
                }

                tokio::time::sleep(udp_firewall_check_timeout).await;
                let summary = {
                    let mut firewall = kad_firewall.lock().await;
                    firewall.finish_udp_check(Utc::now())
                };
                if let Some(summary) = summary {
                    if summary.open {
                        info!(
                            "kad udp firewall-check completed open helpers_selected={} helpers_requested={} helpers_succeeded={} helpers_failed={} elapsed_ms={}",
                            summary.helpers_selected,
                            summary.helpers_requested,
                            summary.helpers_succeeded,
                            summary.helpers_failed,
                            (summary.completed_at - summary.started_at).num_milliseconds()
                        );
                    } else {
                        warn!(
                            "kad udp firewall-check completed firewalled helpers_selected={} helpers_requested={} helpers_succeeded={} helpers_failed={} elapsed_ms={}",
                            summary.helpers_selected,
                            summary.helpers_requested,
                            summary.helpers_succeeded,
                            summary.helpers_failed,
                            (summary.completed_at - summary.started_at).num_milliseconds()
                        );
                    }
                }
                tokio::time::sleep(udp_firewall_recheck_interval).await;
            }
        }));
    }
}
