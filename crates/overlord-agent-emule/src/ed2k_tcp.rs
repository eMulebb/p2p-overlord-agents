//! Minimal eD2k TCP support required for Kad firewall verification.
//!
//! The full eD2k peer protocol is out of scope for the current agent, but the
//! Kad oracle uses one specific eD2k TCP message, `OP_FWCHECKUDPREQ`, to ask a
//! helper peer to send `KADEMLIA2_FIREWALLUDP` probes back to our UDP socket.
//! This module implements just enough framing to send and receive that request.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, warn};

use overlord_kad_dht::DhtNode;
use overlord_kad_proto::{FirewallUdp, KadPacket};

const OP_EMULEPROT: u8 = 0xC5;
const OP_EDONKEYPROT: u8 = 0xE3;
const OP_HELLO: u8 = 0x01;
const OP_FWCHECKUDPREQ: u8 = 0xA7;
const TCP_PACKET_HEADER_LEN: usize = 6;

/// One decoded eD2k TCP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmuleTcpPacket {
    /// Protocol marker byte.
    pub protocol: u8,
    /// Packet opcode.
    pub opcode: u8,
    /// Packet payload without the framing header.
    pub payload: Vec<u8>,
}

/// Payload of `OP_FWCHECKUDPREQ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallCheckUdpRequest {
    /// UDP port the requester is listening on locally.
    pub internal_udp_port: u16,
    /// UDP port observed/mapped externally for the requester.
    pub external_udp_port: u16,
    /// Per-helper Kad UDP verify key used to obfuscate the helper's reply.
    pub sender_udp_key: u32,
}

impl FirewallCheckUdpRequest {
    fn encode(self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..2].copy_from_slice(&self.internal_udp_port.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.external_udp_port.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.sender_udp_key.to_le_bytes());
        bytes
    }

    fn decode(payload: &[u8]) -> Result<Self> {
        if payload.len() != 8 {
            anyhow::bail!("invalid OP_FWCHECKUDPREQ payload size {}", payload.len());
        }
        Ok(Self {
            internal_udp_port: u16::from_le_bytes([payload[0], payload[1]]),
            external_udp_port: u16::from_le_bytes([payload[2], payload[3]]),
            sender_udp_key: u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]),
        })
    }
}

/// Minimal identity announced during the helper TCP hello handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed2kHelloIdentity {
    /// Stable 16-byte user hash / client hash.
    pub user_hash: [u8; 16],
    /// TCP port advertised in the hello packet.
    pub tcp_port: u16,
}

/// Send one `OP_FWCHECKUDPREQ` to a helper peer over eD2k TCP.
pub async fn request_udp_firewall_check(
    helper_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    request: FirewallCheckUdpRequest,
    timeout: Duration,
) -> Result<()> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(helper_addr))
        .await
        .with_context(|| format!("timed out connecting to eD2k helper {helper_addr}"))??;
    stream
        .set_nodelay(true)
        .with_context(|| format!("failed to enable TCP_NODELAY for helper {helper_addr}"))?;
    let hello_packet = encode_minimal_hello(hello_identity);
    tokio::time::timeout(timeout, stream.write_all(&hello_packet))
        .await
        .with_context(|| format!("timed out sending OP_HELLO to {helper_addr}"))??;
    let _ = tokio::time::timeout(Duration::from_millis(500), read_packet(&mut stream)).await;
    let payload = request.encode();
    let packet = encode_packet(OP_EMULEPROT, OP_FWCHECKUDPREQ, &payload);
    tokio::time::timeout(timeout, stream.write_all(&packet))
        .await
        .with_context(|| format!("timed out sending OP_FWCHECKUDPREQ to {helper_addr}"))??;
    Ok(())
}

fn encode_minimal_hello(identity: Ed2kHelloIdentity) -> Vec<u8> {
    let mut payload = Vec::with_capacity(33);
    // OP_HELLO starts with an explicit user-hash length byte.
    payload.push(16);
    payload.extend_from_slice(&identity.user_hash);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&identity.tcp_port.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    encode_packet(OP_EDONKEYPROT, OP_HELLO, &payload)
}

/// Run the minimal eD2k TCP listener needed for inbound firewall-check requests.
pub async fn run_ed2k_listener(
    listener: Arc<TcpListener>,
    dht: DhtNode,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                if let Err(error) = handle_connection(stream, peer_addr, &dht).await {
                    debug!("eD2k connection handling failed from {peer_addr}: {error}");
                }
            }
            Err(error) if is_transient_accept_error(&error) => {
                debug!("ignoring transient eD2k accept failure: {error}");
            }
            Err(error) => {
                warn!("eD2k listener accept failed: {error}");
                break;
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    dht: &DhtNode,
) -> Result<()> {
    let packet = read_packet(&mut stream)
        .await
        .with_context(|| format!("failed to read eD2k packet from {peer_addr}"))?;
    let Some(packet) = packet else {
        return Ok(());
    };
    if packet.protocol != OP_EMULEPROT || packet.opcode != OP_FWCHECKUDPREQ {
        return Ok(());
    }

    let request = FirewallCheckUdpRequest::decode(&packet.payload)?;
    reply_with_firewall_udp(dht, peer_addr.ip(), request).await
}

async fn reply_with_firewall_udp(
    dht: &DhtNode,
    peer_ip: IpAddr,
    request: FirewallCheckUdpRequest,
) -> Result<()> {
    let ports = if request.external_udp_port != 0
        && request.external_udp_port != request.internal_udp_port
    {
        vec![request.internal_udp_port, request.external_udp_port]
    } else {
        vec![request.internal_udp_port]
    };

    let error_code = match peer_ip {
        IpAddr::V4(ip) => {
            if dht
                .routing_contacts()
                .await
                .iter()
                .any(|contact| contact.ip == ip)
            {
                1u8
            } else {
                0u8
            }
        }
        IpAddr::V6(_) => 1,
    };

    for port in ports.into_iter().filter(|port| *port != 0) {
        let target = SocketAddr::new(peer_ip, port);
        if request.sender_udp_key != 0 {
            dht.register_peer_key(target, request.sender_udp_key);
        }
        dht.send_packet(
            target,
            &KadPacket::FirewallUdp(FirewallUdp {
                error_code,
                udp_port: port,
            }),
        )
        .await
        .with_context(|| format!("failed to send KADEMLIA2_FIREWALLUDP to {target}"))?;
    }
    Ok(())
}

fn encode_packet(protocol: u8, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(TCP_PACKET_HEADER_LEN + payload.len());
    bytes.push(protocol);
    bytes.extend_from_slice(
        &(u32::try_from(payload.len() + 1).expect("payload too large")).to_le_bytes(),
    );
    bytes.push(opcode);
    bytes.extend_from_slice(payload);
    bytes
}

async fn read_packet(stream: &mut TcpStream) -> Result<Option<EmuleTcpPacket>> {
    let mut header = [0u8; TCP_PACKET_HEADER_LEN];
    match stream.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }

    let protocol = header[0];
    let packet_length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
    let opcode = header[5];
    if packet_length == 0 {
        anyhow::bail!("invalid eD2k packet length 0");
    }

    let payload_len = usize::try_from(packet_length - 1).context("packet length overflow")?;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;

    Ok(Some(EmuleTcpPacket {
        protocol,
        opcode,
        payload,
    }))
}

fn is_transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::{
        Ed2kHelloIdentity, FirewallCheckUdpRequest, OP_EDONKEYPROT, OP_EMULEPROT, OP_FWCHECKUDPREQ,
        OP_HELLO, encode_minimal_hello, encode_packet,
    };

    #[test]
    fn firewall_check_udp_request_roundtrip() {
        let request = FirewallCheckUdpRequest {
            internal_udp_port: 41000,
            external_udp_port: 51000,
            sender_udp_key: 0x11223344,
        };

        let encoded = request.encode();
        let decoded = FirewallCheckUdpRequest::decode(&encoded).expect("decode");

        assert_eq!(decoded, request);
    }

    #[test]
    fn emule_packet_encoding_uses_standard_header() {
        let packet = encode_packet(OP_EMULEPROT, OP_FWCHECKUDPREQ, &[1, 2, 3, 4]);

        assert_eq!(packet[0], OP_EMULEPROT);
        assert_eq!(
            u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]),
            5
        );
        assert_eq!(packet[5], OP_FWCHECKUDPREQ);
        assert_eq!(&packet[6..], &[1, 2, 3, 4]);
    }

    #[test]
    fn minimal_hello_encoding_matches_ed2k_framing() {
        let packet = encode_minimal_hello(Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            tcp_port: 41001,
        });

        assert_eq!(packet[0], OP_EDONKEYPROT);
        assert_eq!(
            u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]),
            34
        );
        assert_eq!(packet[5], OP_HELLO);
        assert_eq!(packet[6], 16);
        assert_eq!(&packet[7..23], &[0x11; 16]);
        assert_eq!(u16::from_le_bytes([packet[27], packet[28]]), 41001);
    }
}
