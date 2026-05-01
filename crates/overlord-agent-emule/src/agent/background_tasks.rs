use crate::config::EmuleAgentConfig;

use super::{AgentNetworkRuntime, OverlordAgentEmule};

impl OverlordAgentEmule {
    pub(super) async fn spawn_background_tasks(
        &self,
        runtime: &AgentNetworkRuntime,
        config: &EmuleAgentConfig,
    ) {
        self.spawn_routing_refresh_task(runtime, config).await;
        self.spawn_bootstrap_publish_task(runtime, config).await;
        self.spawn_unsolicited_packet_task(runtime, config).await;
        self.spawn_ed2k_background_tasks(runtime, config).await;
        self.spawn_udp_firewall_check_task(runtime, config).await;
        self.spawn_kad_hello_intro_task(runtime, config).await;
        self.spawn_passive_replay_tasks(runtime, config).await;
        self.spawn_snoop_flush_task(runtime).await;
        self.spawn_periodic_publish_tasks(runtime, config).await;
    }
}
