use std::sync::Arc;

use tracing::warn;

use crate::config::EmuleAgentConfig;
use crate::ed2k_server::{Ed2kServerLoopOptions, run_ed2k_server_loop};
use crate::ed2k_tcp::{
    Ed2kHelloIdentity, Ed2kListenerOptions, emule_connect_options, run_ed2k_listener,
};

use super::{AgentNetworkRuntime, OverlordAgentEmule};

impl OverlordAgentEmule {
    pub(super) async fn spawn_ed2k_background_tasks(
        &self,
        runtime: &AgentNetworkRuntime,
        config: &EmuleAgentConfig,
    ) {
        let dht = runtime.dht.clone();
        let ed2k_listener = Arc::clone(&runtime.ed2k_listener);
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let kad_firewall = Arc::clone(&runtime.kad_firewall);
        let ed2k_secure_ident = Arc::clone(&runtime.ed2k_secure_ident);
        let ed2k_transfer = Arc::clone(&runtime.ed2k_transfer);
        let shutdown = Arc::clone(&runtime.shutdown);
        let ed2k_user_hash = self.ed2k_user_hash;
        let ed2k_hello_identity = Ed2kHelloIdentity {
            user_hash: ed2k_user_hash,
            client_id: 0,
            tcp_port: config.p2p.ed2k.listen_port,
            udp_port: config.p2p.kad.listen_port,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(config.p2p.ed2k.obfuscation_enabled),
            direct_udp_callback: false,
        };
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            run_ed2k_listener(Ed2kListenerOptions {
                listener: ed2k_listener,
                dht,
                server_state: ed2k_server_state,
                kad_firewall,
                secure_ident: ed2k_secure_ident,
                transfer_runtime: ed2k_transfer,
                hello_identity: ed2k_hello_identity,
                shutdown,
            })
            .await;
        }));

        let bind_ip = runtime.bind_ip;
        let nat = Arc::clone(&runtime.nat);
        let shutdown = Arc::clone(&runtime.shutdown);
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let ed2k_shared_catalog = Arc::clone(&runtime.ed2k_shared_catalog);
        let ed2k_server_search_inbox = runtime.ed2k_server_search_inbox.lock().await.take();
        let kad_firewall = Arc::clone(&runtime.kad_firewall);
        let ed2k_server_config = config.p2p.ed2k.clone();
        let ed2k_user_hash = self.ed2k_user_hash;
        let ed2k_hello_identity = Ed2kHelloIdentity {
            user_hash: ed2k_user_hash,
            client_id: 0,
            tcp_port: config.p2p.ed2k.listen_port,
            udp_port: config.p2p.kad.listen_port,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(config.p2p.ed2k.obfuscation_enabled),
            direct_udp_callback: false,
        };
        if let Some(ed2k_server_search_inbox) = ed2k_server_search_inbox {
            runtime.tasks.lock().await.push(tokio::spawn(async move {
                run_ed2k_server_loop(Ed2kServerLoopOptions {
                    bind_ip,
                    nat,
                    config: ed2k_server_config,
                    hello_identity: ed2k_hello_identity,
                    shared_catalog: ed2k_shared_catalog,
                    state: ed2k_server_state,
                    search_inbox: ed2k_server_search_inbox,
                    kad_firewall,
                    shutdown,
                })
                .await;
            }));
        } else {
            warn!("ED2K server loop inbox was already taken; skipping ED2K server loop spawn");
        }
    }
}
