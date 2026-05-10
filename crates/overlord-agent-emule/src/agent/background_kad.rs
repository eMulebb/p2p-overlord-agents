use std::sync::{Arc, atomic::Ordering};

use overlord_kad_proto::Ed2kHash;
use tracing::debug;

use crate::config::EmuleAgentConfig;

use super::kad_unsolicited::{UnsolicitedPacketContext, handle_unsolicited_packet};
use super::{AgentNetworkRuntime, OverlordAgentEmule};

impl OverlordAgentEmule {
    pub(super) async fn spawn_unsolicited_packet_task(
        &self,
        runtime: &AgentNetworkRuntime,
        config: &EmuleAgentConfig,
    ) {
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let snoop_queue = Arc::clone(&self.snoop_queue);
        let observed_snoop_events = Arc::clone(&self.observed_snoop_events);
        let local_store = Arc::clone(&self.local_store);
        let harvest_observability = Arc::clone(&self.harvest_observability);
        let kad_firewall = Arc::clone(&runtime.kad_firewall);
        let ed2k_listener = Arc::clone(&runtime.ed2k_listener);
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let ed2k_user_hash = self.ed2k_user_hash;
        let bind_ip = runtime.bind_ip;
        let ed2k_obfuscation_enabled = config.p2p.ed2k.obfuscation_enabled;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let mut packets = dht.subscribe_packets();
            while !shutdown.load(Ordering::Relaxed) {
                match packets.recv().await {
                    Ok(received) => {
                        if let Err(error) = handle_unsolicited_packet(
                            &dht,
                            UnsolicitedPacketContext {
                                snoop_queue: &snoop_queue,
                                observed_snoop_events: &observed_snoop_events,
                                local_store: &local_store,
                                harvest_observability: &harvest_observability,
                                kad_firewall: &kad_firewall,
                                ed2k_listener: &ed2k_listener,
                                ed2k_server_state: &ed2k_server_state,
                                ed2k_user_hash: Ed2kHash::from_bytes(ed2k_user_hash),
                                bind_ip,
                                ed2k_obfuscation_enabled,
                            },
                            received,
                        )
                        .await
                        {
                            debug!("unsolicited packet handling failed: {error}");
                        }
                    }
                    Err(error) => {
                        debug!("packet subscription closed: {error}");
                        break;
                    }
                }
            }
        }));
    }
}
