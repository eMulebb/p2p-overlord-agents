use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use overlord_agent_nat::{
    MappingExposure, MappingSpec, NatManagerBuilder, TransportProtocol,
    built_in_upnp_port_mapping_providers, default_upnp_backend_order, detect_interfaces,
};
use overlord_kad_dht::{DhtConfig, RpcClassBudgetConfig};
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock, Semaphore},
};
use tracing::info;

use crate::config::{Ed2kUploadQueuePolicyConfig, EmuleAgentConfig};
use crate::ed2k_server::{Ed2kServerState, new_ed2k_server_search_channel};
use crate::ed2k_tcp::Ed2kSecureIdent;
use crate::ed2k_transfer::{Ed2kTransferRuntime, Ed2kUploadQueueConfig};
use crate::kad_firewall::KadFirewallState;

use super::lifecycle::{
    load_or_create_node_id, load_or_create_udp_key, read_optional_bytes, resolved_socket_addr,
};
use super::networking::p2p_interface_reconcile_target;
use super::publish::synthetic_popular_hashes;
use super::{
    AgentNetworkRuntime, ED2K_BACKGROUND_SEARCH_QUEUE_CAPACITY, OverlordAgentEmule,
    PASSIVE_REPLAY_CONCURRENCY,
};

impl OverlordAgentEmule {
    pub(super) fn ed2k_upload_queue_config(
        config: &Ed2kUploadQueuePolicyConfig,
    ) -> Ed2kUploadQueueConfig {
        Ed2kUploadQueueConfig {
            active_slots: config.active_slots,
            waiting_capacity: config.waiting_capacity,
            waiting_timeout: Duration::from_secs(config.waiting_timeout_secs),
            granted_timeout: Duration::from_secs(config.granted_timeout_secs),
            upload_timeout: Duration::from_secs(config.upload_timeout_secs),
        }
    }

    pub(super) fn nat_mappings_from_config(
        config: &EmuleAgentConfig,
        bind_ip: Option<&str>,
    ) -> Result<Vec<MappingSpec>> {
        let kad_addr = resolved_socket_addr(config.p2p.kad.listen_port, bind_ip)
            .context("invalid p2p.kad.listen_port for NAT mapping")?;
        let ed2k_addr = resolved_socket_addr(config.p2p.ed2k.listen_port, bind_ip)
            .context("invalid p2p.ed2k.listen_port for NAT mapping")?;

        Ok(vec![
            MappingSpec {
                name: "kad".to_string(),
                local_addr: kad_addr,
                protocol: TransportProtocol::Udp,
                exposure: MappingExposure::Required,
                preferred_external_port: None,
            },
            MappingSpec {
                name: "ed2k".to_string(),
                local_addr: ed2k_addr,
                protocol: TransportProtocol::Tcp,
                exposure: MappingExposure::Preferred,
                preferred_external_port: None,
            },
        ])
    }

    pub(super) async fn reconcile_runtime(&self) -> Result<()> {
        let config = self.config.read().await.clone();
        let interfaces = detect_interfaces().unwrap_or_default();
        let binding = Self::resolve_p2p_selection_state(&config, &interfaces, None, false, false);
        {
            let mut selection_state = self.p2p_selection_state.write().await;
            *selection_state = binding.clone();
        }

        if !binding.selection_confirmed {
            self.stop_runtime().await?;
            return Ok(());
        }

        let Some(bind_ip) = binding.bind_ip.clone() else {
            self.stop_runtime().await?;
            return Ok(());
        };

        self.stop_runtime().await?;
        match self.build_runtime(&config, &bind_ip).await {
            Ok(runtime) => {
                let dht_task = runtime.dht.start();
                runtime.tasks.lock().await.push(dht_task);
                runtime.nat.start().await?;
                self.spawn_background_tasks(&runtime, &config).await;
                *self.runtime.lock().await = Some(runtime);
                let mut selection_state = self.p2p_selection_state.write().await;
                selection_state.state = overlord_agent_nat::InterfaceSelectionState::Applied;
                selection_state.ready = true;
                selection_state.last_error = None;
            }
            Err(error) => {
                let mut selection_state = self.p2p_selection_state.write().await;
                selection_state.state = overlord_agent_nat::InterfaceSelectionState::Error;
                selection_state.last_error = Some(error.to_string());
            }
        }

        Ok(())
    }

    pub(super) async fn reconcile_p2p_runtime_if_interface_moved(&self) -> Result<()> {
        let config = self.config.read().await.clone();
        if !config.p2p.selection_confirmed {
            return Ok(());
        }
        if config
            .p2p
            .bind_ip
            .as_deref()
            .is_some_and(|bind_ip| !bind_ip.trim().is_empty())
        {
            return Ok(());
        }

        let Some(bind_iface) = config
            .p2p
            .bind_iface
            .as_deref()
            .filter(|bind_iface| !bind_iface.trim().is_empty())
        else {
            return Ok(());
        };
        let Some(runtime_bind_ip) = self
            .runtime
            .lock()
            .await
            .as_ref()
            .map(|runtime| runtime.bind_ip)
        else {
            return Ok(());
        };

        let interfaces = detect_interfaces().unwrap_or_default();
        let Some(next_bind_ip) =
            p2p_interface_reconcile_target(&config, &interfaces, runtime_bind_ip)
        else {
            return Ok(());
        };

        info!(
            "p2p bind interface resolved to a new IPv4 address; reconciling runtime bind_iface={} old_bind_ip={} new_bind_ip={}",
            bind_iface, runtime_bind_ip, next_bind_ip
        );
        self.reconcile_runtime().await
    }

    pub(super) async fn stop_runtime(&self) -> Result<()> {
        self.cancel_active_searches().await;
        if let Some(runtime) = self.runtime.lock().await.take() {
            runtime.shutdown.store(true, Ordering::SeqCst);
            let tasks = {
                let mut tasks = runtime.tasks.lock().await;
                std::mem::take(&mut *tasks)
            };
            for task in tasks {
                task.abort();
            }
            runtime.nat.stop().await?;
        }
        Ok(())
    }

    pub(super) async fn cancel_active_searches(&self) {
        let handles = {
            let mut active = self.active_searches.lock().await;
            active.drain().map(|(_, handle)| handle).collect::<Vec<_>>()
        };
        for handle in handles {
            handle.cancel.cancel();
        }
    }

    pub(super) async fn build_runtime(
        &self,
        config: &EmuleAgentConfig,
        bind_ip: &str,
    ) -> Result<AgentNetworkRuntime> {
        let bind_ipv4 = bind_ip
            .parse::<Ipv4Addr>()
            .with_context(|| format!("bind_ip is not a valid IPv4 address: {bind_ip}"))?;
        let node_id = load_or_create_node_id(&self.state_paths.node_id_path)?;
        let udp_key = load_or_create_udp_key(&self.state_paths.udp_key_path)?;
        let ed2k_secure_ident =
            Ed2kSecureIdent::load_or_create(&self.state_paths.ed2k_secure_ident_path)?;
        let bind_addr = resolved_socket_addr(config.p2p.kad.listen_port, Some(bind_ip))
            .context("invalid p2p.kad.listen_port")?;
        let ed2k_bind_addr = resolved_socket_addr(config.p2p.ed2k.listen_port, Some(bind_ip))
            .context("invalid p2p.ed2k.listen_port")?;
        let nodes_dat = read_optional_bytes(&self.state_paths.nodes_dat_path)?;
        let nodes_text = (!config.p2p.kad.bootstrap_nodes.is_empty())
            .then(|| config.p2p.kad.bootstrap_nodes.join("\n"));

        let dht = overlord_kad_dht::DhtNode::new(DhtConfig {
            bind_addr,
            node_id,
            max_routing_table_size: 12_000,
            bootstrap_min_routing_contacts: config.p2p.kad.bootstrap_min_routing_contacts,
            max_concurrent_searches: 5,
            search_timeout: Duration::from_secs(config.p2p.kad.search_timeout_secs),
            store_timeout: Duration::from_secs(config.p2p.kad.store_timeout_secs),
            republish_interval: Duration::from_secs(config.p2p.kad.republish_interval_secs),
            publish_contact_fanout: config.p2p.kad.publish_contact_fanout,
            max_outbound_pps: config.p2p.kad.max_outbound_pps,
            class_budgets: RpcClassBudgetConfig {
                interactive_max_outbound_pps: config.p2p.kad.interactive_max_outbound_pps,
                harvest_max_outbound_pps: config.p2p.kad.harvest_max_outbound_pps,
                maintenance_max_outbound_pps: config.p2p.kad.maintenance_max_outbound_pps,
                publish_max_outbound_pps: config.p2p.kad.publish_max_outbound_pps,
            },
            search_phase2_fanout: config.p2p.kad.search_phase2_fanout,
            keyword_result_cap: config.p2p.kad.keyword_result_cap,
            source_result_cap: config.p2p.kad.source_result_cap,
            notes_result_cap: config.p2p.kad.notes_result_cap,
            obfuscation_enabled: config.p2p.kad.obfuscation_enabled,
            udp_key,
            nodes_dat,
            nodes_text,
        })
        .await?;

        let nat_config = overlord_agent_nat::NatConfig {
            enabled: config.nat.p2p.enabled,
            backend_order: if config.nat.p2p.backend_order.is_empty() {
                default_upnp_backend_order()
            } else {
                config.nat.p2p.backend_order.clone()
            },
            bind_ip: Some(bind_ip.to_string()),
            igd_ip: config.nat.p2p.igd_ip.clone(),
            minissdpd_socket: config.nat.p2p.minissdpd_socket.clone(),
            ssdp_local_port: config.nat.p2p.ssdp_local_port,
            discovery_timeout_secs: config.nat.p2p.discovery_timeout_secs,
            lease_duration_secs: config.nat.p2p.lease_duration_secs,
            renew_margin_secs: config.nat.p2p.renew_margin_secs,
            external_ip_override: config.nat.p2p.external_ip_override.clone(),
        };

        let nat = Arc::new(
            NatManagerBuilder::new(nat_config)
                .with_mappings(Self::nat_mappings_from_config(config, Some(bind_ip))?)
                .with_providers(built_in_upnp_port_mapping_providers())
                .build(),
        );
        let ed2k_listener =
            Arc::new(TcpListener::bind(ed2k_bind_addr).await.with_context(|| {
                format!("failed to bind eD2k TCP listener on {ed2k_bind_addr}")
            })?);
        let (ed2k_server_search, ed2k_server_search_inbox) =
            new_ed2k_server_search_channel(ED2K_BACKGROUND_SEARCH_QUEUE_CAPACITY);
        let ed2k_transfer = Arc::new(Ed2kTransferRuntime::load_or_create_with_upload_queue(
            &self.state_paths.ed2k_transfer_root,
            Self::ed2k_upload_queue_config(&config.p2p.ed2k.upload_queue),
        )?);
        ed2k_transfer
            .replace_catalog_hints(&synthetic_popular_hashes())
            .await;
        let ed2k_shared_catalog = ed2k_transfer.shared_catalog();

        Ok(AgentNetworkRuntime {
            bind_ip: bind_ipv4,
            dht,
            ed2k_listener,
            ed2k_shared_catalog,
            ed2k_transfer,
            ed2k_server_search,
            ed2k_server_search_inbox: Arc::new(Mutex::new(Some(ed2k_server_search_inbox))),
            ed2k_server_state: Arc::new(RwLock::new(Ed2kServerState::default())),
            ed2k_secure_ident: Arc::new(ed2k_secure_ident),
            nat,
            kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
            tasks: Arc::new(Mutex::new(Vec::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            passive_result_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            passive_replay_gate: Arc::new(Semaphore::new(PASSIVE_REPLAY_CONCURRENCY)),
        })
    }
}
