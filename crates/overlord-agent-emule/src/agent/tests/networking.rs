use super::*;

#[test]
fn empty_networking_config_prefers_miniupnpc_only() {
    assert_eq!(
        empty_networking_config().nat.p2p.backend_order,
        vec![UPNP_MINIUPNPC_BACKEND.to_string()]
    );
}

#[test]
fn apply_networking_config_preserves_explicit_backend_order() {
    let mut config = EmuleAgentConfig::default();
    let mut desired = empty_networking_config();
    desired.nat.p2p.backend_order = vec![UPNP_RUPNP_BACKEND.to_string()];

    apply_networking_config(&mut config, &desired);

    assert_eq!(
        config.nat.p2p.backend_order,
        vec![UPNP_RUPNP_BACKEND.to_string()]
    );
}

#[test]
fn restart_required_only_for_control_endpoint_changes() {
    let old = empty_networking_config();

    let mut nat_only = old.clone();
    nat_only.nat.p2p.enabled = true;
    nat_only.nat.p2p.backend_order = vec![UPNP_RUPNP_BACKEND.to_string()];
    assert!(!OverlordAgentEmule::restart_required_for_networking_change(
        &old, &nat_only
    ));

    let mut control_bind_ip = old.clone();
    control_bind_ip.control.bind_ip = Some("127.0.0.1".to_string());
    control_bind_ip.control.selection_confirmed = true;
    assert!(OverlordAgentEmule::restart_required_for_networking_change(
        &old,
        &control_bind_ip
    ));

    let mut control_port = old.clone();
    control_port.control.listen_port = 14_001;
    assert!(OverlordAgentEmule::restart_required_for_networking_change(
        &old,
        &control_port
    ));

    let mut p2p_port = old.clone();
    p2p_port.p2p.kad.listen_port = 41_999;
    assert!(!OverlordAgentEmule::restart_required_for_networking_change(
        &old, &p2p_port
    ));
}

#[test]
fn p2p_interface_reconcile_target_tracks_interface_ip_changes() {
    let mut config = EmuleAgentConfig::default();
    config.p2p.selection_confirmed = true;
    config.p2p.bind_iface = Some("hide.me".to_string());
    config.p2p.bind_ip = None;
    let interfaces = vec![AgentInterface {
        name: "hide.me".to_string(),
        description: None,
        is_loopback: false,
        is_vpn_candidate: true,
        has_default_route: false,
        addresses: vec![overlord_agent_nat::AgentInterfaceAddress {
            family: InterfaceAddressFamily::Ipv4,
            address: "10.46.87.221".to_string(),
        }],
    }];

    assert_eq!(
        p2p_interface_reconcile_target(&config, &interfaces, "10.46.102.186".parse().unwrap()),
        Some("10.46.87.221".parse().unwrap())
    );
    assert_eq!(
        p2p_interface_reconcile_target(&config, &interfaces, "10.46.87.221".parse().unwrap()),
        None
    );
}

#[test]
fn p2p_interface_reconcile_target_respects_explicit_bind_ip() {
    let mut config = EmuleAgentConfig::default();
    config.p2p.selection_confirmed = true;
    config.p2p.bind_iface = Some("hide.me".to_string());
    config.p2p.bind_ip = Some("10.46.102.186".to_string());
    let interfaces = vec![AgentInterface {
        name: "hide.me".to_string(),
        description: None,
        is_loopback: false,
        is_vpn_candidate: true,
        has_default_route: false,
        addresses: vec![overlord_agent_nat::AgentInterfaceAddress {
            family: InterfaceAddressFamily::Ipv4,
            address: "10.46.87.221".to_string(),
        }],
    }];

    assert_eq!(
        p2p_interface_reconcile_target(&config, &interfaces, "10.46.102.186".parse().unwrap()),
        None
    );
}
