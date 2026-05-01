use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result};
use overlord_kad_dht::{
    DhtNode,
    bootstrap::{BootstrapContact, encode_nodes_dat},
};
use overlord_kad_proto::NodeId;
use uuid::Uuid;

use crate::config::EmuleAgentConfig;

#[derive(Clone)]
pub(super) struct AgentStatePaths {
    pub(super) node_id_path: PathBuf,
    pub(super) udp_key_path: PathBuf,
    pub(super) ed2k_user_hash_path: PathBuf,
    pub(super) ed2k_secure_ident_path: PathBuf,
    pub(super) ed2k_transfer_root: PathBuf,
    pub(super) nodes_dat_path: PathBuf,
    pub(super) networking_config_path: PathBuf,
}

impl AgentStatePaths {
    pub(super) fn from_config(config: &EmuleAgentConfig) -> Self {
        let state_dir = PathBuf::from(&config.agent.state_dir);
        let nodes_dat_path = if config.p2p.kad.nodes_dat_path.trim().is_empty() {
            state_dir.join("overlord-kad.nodes.dat")
        } else {
            PathBuf::from(&config.p2p.kad.nodes_dat_path)
        };
        Self {
            node_id_path: state_dir.join("overlord-kad.node-id"),
            udp_key_path: state_dir.join("overlord-kad.udp-key"),
            ed2k_user_hash_path: state_dir.join("overlord-ed2k.user-hash.bin"),
            ed2k_secure_ident_path: state_dir.join("overlord-ed2k.secident.pkcs8.der"),
            ed2k_transfer_root: state_dir.join("overlord-ed2k-transfer"),
            nodes_dat_path,
            networking_config_path: state_dir.join("overlord-agent.networking.json"),
        }
    }
}

pub(super) fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}

pub(super) fn read_optional_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(fs::read(path).with_context(|| {
        format!("failed to read {}", path.display())
    })?))
}

pub(super) fn resolved_socket_addr(listen_port: u16, bind_ip: Option<&str>) -> Result<SocketAddr> {
    let ip = match bind_ip {
        Some(bind_ip) => bind_ip
            .parse::<IpAddr>()
            .with_context(|| format!("invalid bind ip {bind_ip}"))?,
        None => IpAddr::from([0, 0, 0, 0]),
    };
    Ok(SocketAddr::new(ip, listen_port))
}

pub(super) fn load_or_create_indexer_id(path: &str) -> Result<Uuid> {
    let path = Path::new(path);
    if path.exists() {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        return Uuid::parse_str(contents.trim())
            .with_context(|| format!("invalid uuid in {}", path.display()));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let generated = Uuid::new_v4();
    fs::write(path, generated.to_string())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(generated)
}

pub(super) fn load_or_create_node_id(path: &Path) -> Result<NodeId> {
    if path.exists() {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        return NodeId::from_str(contents.trim())
            .with_context(|| format!("invalid node id in {}", path.display()));
    }
    let node_id = NodeId::from_bytes(rand::random());
    fs::write(path, node_id.to_string())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(node_id)
}

pub(super) fn load_or_create_udp_key(path: &Path) -> Result<u32> {
    if path.exists() {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        return contents
            .trim()
            .parse::<u32>()
            .with_context(|| format!("invalid udp key in {}", path.display()));
    }
    let udp_key: u32 = rand::random();
    fs::write(path, udp_key.to_string())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(udp_key)
}

/// Generate a random Kad target so background refreshes gradually cover the wider keyspace.
pub(super) fn random_routing_refresh_target() -> NodeId {
    NodeId::from_bytes(rand::random())
}

pub(super) async fn persist_nodes_dat_for(
    dht: &DhtNode,
    state_paths: &AgentStatePaths,
) -> Result<()> {
    let contacts = dht
        .routing_contacts()
        .await
        .into_iter()
        .map(|contact| {
            let addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.udp_port);
            let udp_key = dht.known_peer_key(addr).unwrap_or(contact.udp_key);
            BootstrapContact {
                node_id: contact.id,
                ip: contact.ip,
                udp_port: contact.udp_port,
                tcp_port: contact.tcp_port,
                version: contact.kad_version,
                udp_key,
            }
        })
        .collect::<Vec<_>>();
    let bytes = encode_nodes_dat(&contacts)?;
    fs::write(&state_paths.nodes_dat_path, bytes)
        .with_context(|| format!("failed to write {}", state_paths.nodes_dat_path.display()))?;
    Ok(())
}
