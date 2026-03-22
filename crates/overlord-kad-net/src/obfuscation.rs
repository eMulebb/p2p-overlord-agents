use md5::compute as md5_compute;
use overlord_kad_proto::NodeId;
use overlord_kad_proto::constants::{OP_KADEMLIAHEADER, OP_KADEMLIAPACKEDPROT};
use rand::Rng;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;

/// Kad UDP obfuscation sync constant used by the oracle `EncryptedDatagramSocket`.
const MAGICVALUE_UDP_SYNC_CLIENT: u32 = 0x395F_2EC1;

/// Marker value used when the packet is encrypted with the receiver verify key.
const KAD_MARKER_RECEIVER_KEY: u8 = 0x02;

/// Padding is disabled in the oracle UDP path today, but the parser still
/// accepts it so we keep the same shape here.
const UDP_PADDING_LEN: u8 = 0;

#[derive(Debug, Clone, Default)]
struct PeerCryptoState {
    /// Latest sender verify key learned from an obfuscated packet sent by this
    /// peer to us. This is the key the oracle reuses for reply packets.
    receiver_verify_key: Option<u32>,
    /// Target node ID used for NodeID-based request obfuscation.
    node_id: Option<NodeId>,
}

/// Result of attempting to decrypt an incoming packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptResult {
    /// Decrypted Kad payload, or the original buffer when no obfuscation was used.
    pub data: Vec<u8>,
    /// Whether the packet was successfully parsed as obfuscated Kad UDP.
    pub was_obfuscated: bool,
    /// Sender verify key recovered from the encrypted trailer.
    pub sender_verify_key: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KadKeyMode {
    NodeId,
    ReceiverVerifyKey,
}

/// Outbound Kad UDP encryption mode chosen for a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundKadEncryptionMode {
    /// No Kad UDP obfuscation will be applied.
    Plaintext,
    /// NodeID-based Kad obfuscation will be used.
    NodeId,
    /// Receiver verify-key Kad obfuscation will be used.
    ReceiverVerifyKey,
}

impl OutboundKadEncryptionMode {
    /// Stable string form used by wire-observability logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::NodeId => "node_id",
            Self::ReceiverVerifyKey => "receiver_verify_key",
        }
    }
}

/// Snapshot of the peer crypto context used to decide outbound Kad UDP transport shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundKadEncryptionInfo {
    /// Final encryption mode the runtime will use for this destination.
    pub mode: OutboundKadEncryptionMode,
    /// Known Kad node ID for the peer, when available.
    pub peer_node_id: Option<NodeId>,
    /// Latest receiver verify key learned from this peer, when available.
    pub receiver_verify_key: Option<u32>,
    /// Verify key this node would announce to the destination peer.
    pub sender_verify_key: Option<u32>,
}

fn rc4(key: &[u8], data: &mut [u8]) {
    if key.is_empty() || data.is_empty() {
        return;
    }
    let klen = key.len();
    let mut s = [0u8; 256];
    for (i, value) in s.iter_mut().enumerate() {
        *value = i as u8;
    }
    let mut j = 0usize;
    for i in 0..256usize {
        j = (j + s[i] as usize + key[i % klen] as usize) & 0xFF;
        s.swap(i, j);
    }
    let mut i = 0usize;
    let mut j = 0usize;
    for byte in data.iter_mut() {
        i = (i + 1) & 0xFF;
        j = (j + s[i] as usize) & 0xFF;
        s.swap(i, j);
        *byte ^= s[(s[i] as usize + s[j] as usize) & 0xFF];
    }
}

fn md5_key_material(bytes: &[u8]) -> [u8; 16] {
    md5_compute(bytes).0
}

fn derive_kad_request_key(node_id: NodeId, random_key_part: u16) -> [u8; 16] {
    let mut key_data = [0u8; 18];
    key_data[..16].copy_from_slice(&node_id.0);
    key_data[16..18].copy_from_slice(&random_key_part.to_le_bytes());
    md5_key_material(&key_data)
}

fn derive_kad_receiver_key(receiver_verify_key: u32, random_key_part: u16) -> [u8; 16] {
    let mut key_data = [0u8; 6];
    key_data[..4].copy_from_slice(&receiver_verify_key.to_le_bytes());
    key_data[4..6].copy_from_slice(&random_key_part.to_le_bytes());
    md5_key_material(&key_data)
}

fn derive_udp_verify_key(our_udp_key: u32, target_ip: Ipv4Addr) -> u32 {
    // eMule hashes the native in-memory bytes of:
    //   (<our Kad UDP key> << 32) | sockAddr.sin_addr.s_addr
    // On little-endian Windows, `sin_addr.s_addr` is already stored with the
    // IPv4 octets in network order in memory, so the hashed 8-byte buffer is:
    //   <ipv4 octets as seen on the wire><our_udp_key little-endian>
    let mut key_data = [0u8; 8];
    key_data[..4].copy_from_slice(&target_ip.octets());
    key_data[4..8].copy_from_slice(&our_udp_key.to_le_bytes());
    let digest = md5_key_material(&key_data);
    let folded = u32::from_le_bytes(digest[0..4].try_into().unwrap())
        ^ u32::from_le_bytes(digest[4..8].try_into().unwrap())
        ^ u32::from_le_bytes(digest[8..12].try_into().unwrap())
        ^ u32::from_le_bytes(digest[12..16].try_into().unwrap());
    (folded % 0xFFFF_FFFE) + 1
}

fn marker_try_order(marker: u8) -> [KadKeyMode; 2] {
    match marker & 0x03 {
        0x02 => [KadKeyMode::ReceiverVerifyKey, KadKeyMode::NodeId],
        _ => [KadKeyMode::NodeId, KadKeyMode::ReceiverVerifyKey],
    }
}

fn is_plain_protocol_marker(byte: u8) -> bool {
    matches!(byte, 0xE3 | 0xE4 | 0xE5 | 0xA3 | 0xC5 | 0xD4)
}

fn select_marker(mode: KadKeyMode) -> u8 {
    let mut rng = rand::thread_rng();
    loop {
        let mut marker: u8 = rng.r#gen();
        marker &= !0x03;
        if matches!(mode, KadKeyMode::ReceiverVerifyKey) {
            marker |= KAD_MARKER_RECEIVER_KEY;
        }
        if !is_plain_protocol_marker(marker) {
            return marker;
        }
    }
}

/// Oracle-shaped Kad UDP obfuscation layer.
///
/// This mirrors the Kad branch of eMule/aMule `EncryptedDatagramSocket`:
/// whenever we know the peer Kad ID we keep preferring NodeID-based
/// obfuscation, and only fall back to the receiver verify key when the Kad ID
/// is unavailable.
pub struct ObfuscationLayer {
    our_node_id: NodeId,
    our_udp_key: u32,
    enabled: bool,
    peers: Mutex<HashMap<SocketAddr, PeerCryptoState>>,
}

impl ObfuscationLayer {
    pub fn new(our_node_id: NodeId, our_udp_key: u32, enabled: bool) -> Self {
        Self {
            our_node_id,
            our_udp_key,
            enabled,
            peers: Mutex::new(HashMap::new()),
        }
    }

    /// Register a peer node ID so outbound requests can use NodeID-based Kad obfuscation.
    pub fn register_peer_identity(&self, addr: SocketAddr, node_id: NodeId) {
        let mut guard = self.peers.lock().unwrap();
        guard.entry(addr).or_default().node_id = Some(node_id);
    }

    /// Register the latest sender verify key learned from an obfuscated packet.
    ///
    /// The oracle stores this as the peer's `CKadUDPKey` value bound to our own
    /// public IP and reuses it for reply packets.
    pub fn register_peer_key(&self, addr: SocketAddr, key: u32) {
        let mut guard = self.peers.lock().unwrap();
        guard.entry(addr).or_default().receiver_verify_key = Some(key);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Our locally generated Kad UDP anti-spoofing seed.
    pub fn our_udp_key(&self) -> u32 {
        self.our_udp_key
    }

    /// Derive the verify key we would announce to a specific IPv4 peer.
    pub fn verify_key_for_ip(&self, ip: Ipv4Addr) -> u32 {
        derive_udp_verify_key(self.our_udp_key, ip)
    }

    /// Describe the outbound Kad UDP transport shape currently selected for a peer.
    #[must_use]
    pub fn inspect_outbound(&self, addr: SocketAddr) -> OutboundKadEncryptionInfo {
        let peer = self
            .peers
            .lock()
            .unwrap()
            .get(&addr)
            .cloned()
            .unwrap_or_default();
        let mode = if !self.enabled {
            OutboundKadEncryptionMode::Plaintext
        } else if peer.node_id.is_some() {
            OutboundKadEncryptionMode::NodeId
        } else if peer.receiver_verify_key.is_some() {
            OutboundKadEncryptionMode::ReceiverVerifyKey
        } else {
            OutboundKadEncryptionMode::Plaintext
        };
        let sender_verify_key = match (mode, addr.ip()) {
            (OutboundKadEncryptionMode::Plaintext, _) => None,
            (_, IpAddr::V4(ip)) => Some(self.verify_key_for_ip(ip)),
            (_, IpAddr::V6(_)) => None,
        };

        OutboundKadEncryptionInfo {
            mode,
            peer_node_id: peer.node_id,
            receiver_verify_key: peer.receiver_verify_key,
            sender_verify_key,
        }
    }

    /// Encrypt a Kad packet for sending to `addr`.
    ///
    /// The caller still passes the opcode for tracing/call-site symmetry, but
    /// the oracle selection rule is identity-driven rather than opcode-driven:
    /// use the peer Kad ID when we know it, otherwise fall back to the receiver
    /// verify key.
    pub fn encrypt(&self, addr: SocketAddr, _opcode: u8, plaintext: &[u8]) -> Vec<u8> {
        let outbound = self.inspect_outbound(addr);
        if matches!(outbound.mode, OutboundKadEncryptionMode::Plaintext) {
            return plaintext.to_vec();
        }

        let peer = self
            .peers
            .lock()
            .unwrap()
            .get(&addr)
            .cloned()
            .unwrap_or_default();
        let preferred_mode = match outbound.mode {
            OutboundKadEncryptionMode::Plaintext => None,
            OutboundKadEncryptionMode::NodeId => Some(KadKeyMode::NodeId),
            OutboundKadEncryptionMode::ReceiverVerifyKey => Some(KadKeyMode::ReceiverVerifyKey),
        };

        let Some(mode) = preferred_mode else {
            return plaintext.to_vec();
        };

        let random_key_part: u16 = rand::thread_rng().r#gen();
        let rc4_key = match mode {
            KadKeyMode::NodeId => derive_kad_request_key(peer.node_id.unwrap(), random_key_part),
            KadKeyMode::ReceiverVerifyKey => {
                derive_kad_receiver_key(peer.receiver_verify_key.unwrap(), random_key_part)
            }
        };

        let sender_verify_key = match addr.ip() {
            IpAddr::V4(ip) => self.verify_key_for_ip(ip),
            IpAddr::V6(_) => return plaintext.to_vec(),
        };

        let mut encrypted_tail = Vec::with_capacity(13 + plaintext.len());
        encrypted_tail.extend_from_slice(&MAGICVALUE_UDP_SYNC_CLIENT.to_le_bytes());
        encrypted_tail.push(UDP_PADDING_LEN);
        encrypted_tail
            .extend_from_slice(&peer.receiver_verify_key.unwrap_or_default().to_le_bytes());
        encrypted_tail.extend_from_slice(&sender_verify_key.to_le_bytes());
        encrypted_tail.extend_from_slice(plaintext);
        rc4(&rc4_key, &mut encrypted_tail);

        let mut result = Vec::with_capacity(3 + encrypted_tail.len());
        result.push(select_marker(mode));
        result.extend_from_slice(&random_key_part.to_le_bytes());
        result.extend_from_slice(&encrypted_tail);
        result
    }

    /// Attempt to decrypt an incoming Kad packet.
    pub fn decrypt(&self, from: SocketAddr, buf: &[u8]) -> DecryptResult {
        if buf.len() < 3 {
            return DecryptResult {
                data: buf.to_vec(),
                was_obfuscated: false,
                sender_verify_key: None,
            };
        }

        if matches!(buf[0], OP_KADEMLIAHEADER | OP_KADEMLIAPACKEDPROT) {
            return DecryptResult {
                data: buf.to_vec(),
                was_obfuscated: false,
                sender_verify_key: None,
            };
        }

        let random_key_part = u16::from_le_bytes([buf[1], buf[2]]);
        let remote_ip = match from.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                return DecryptResult {
                    data: buf.to_vec(),
                    was_obfuscated: false,
                    sender_verify_key: None,
                };
            }
        };

        for mode in marker_try_order(buf[0]) {
            let rc4_key = match mode {
                KadKeyMode::NodeId => derive_kad_request_key(self.our_node_id, random_key_part),
                KadKeyMode::ReceiverVerifyKey => {
                    derive_kad_receiver_key(self.verify_key_for_ip(remote_ip), random_key_part)
                }
            };

            let mut decrypted = buf[3..].to_vec();
            rc4(&rc4_key, &mut decrypted);
            if decrypted.len() < 13 {
                continue;
            }

            let magic = u32::from_le_bytes(decrypted[0..4].try_into().unwrap());
            if magic != MAGICVALUE_UDP_SYNC_CLIENT {
                continue;
            }

            let padding_len = usize::from(decrypted[4] & 0x0F);
            let payload_offset = 5 + padding_len + 8;
            if decrypted.len() <= payload_offset {
                continue;
            }

            let sender_verify_key = u32::from_le_bytes(
                decrypted[5 + padding_len + 4..5 + padding_len + 8]
                    .try_into()
                    .unwrap(),
            );
            let payload = decrypted.split_off(payload_offset);
            if payload.first().copied() != Some(OP_KADEMLIAHEADER)
                && payload.first().copied() != Some(OP_KADEMLIAPACKEDPROT)
            {
                continue;
            }

            return DecryptResult {
                data: payload,
                was_obfuscated: true,
                sender_verify_key: Some(sender_verify_key),
            };
        }

        DecryptResult {
            data: buf.to_vec(),
            was_obfuscated: false,
            sender_verify_key: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use overlord_kad_proto::opcode;

    fn sender_addr() -> SocketAddr {
        "1.2.3.4:4672".parse().unwrap()
    }

    fn receiver_addr() -> SocketAddr {
        "5.6.7.8:4672".parse().unwrap()
    }

    #[test]
    fn test_verify_key_derivation_is_stable_and_non_zero() {
        let layer = ObfuscationLayer::new(NodeId::from_bytes([0x11; 16]), 0xCAFE_BABE, true);
        let ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
        assert_eq!(layer.verify_key_for_ip(ip), layer.verify_key_for_ip(ip));
        assert_ne!(layer.verify_key_for_ip(ip), 0);
    }

    #[test]
    fn test_verify_key_derivation_matches_emule_memory_layout() {
        let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let our_udp_key: u32 = 0xA1B2_C3D4;

        let mut emule_key_data = [0u8; 8];
        emule_key_data[..4].copy_from_slice(&[1, 2, 3, 4]);
        emule_key_data[4..8].copy_from_slice(&our_udp_key.to_le_bytes());
        let digest = md5_key_material(&emule_key_data);
        let expected = (u32::from_le_bytes(digest[0..4].try_into().unwrap())
            ^ u32::from_le_bytes(digest[4..8].try_into().unwrap())
            ^ u32::from_le_bytes(digest[8..12].try_into().unwrap())
            ^ u32::from_le_bytes(digest[12..16].try_into().unwrap()))
            % 0xFFFF_FFFE
            + 1;

        assert_eq!(derive_udp_verify_key(our_udp_key, ip), expected);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_with_node_id_mode() {
        let sender = ObfuscationLayer::new(NodeId::from_bytes([0x11; 16]), 0x1234_5678, true);
        let receiver = ObfuscationLayer::new(NodeId::from_bytes([0x22; 16]), 0x8765_4321, true);
        sender.register_peer_identity(receiver_addr(), receiver.our_node_id);

        let plaintext = vec![OP_KADEMLIAHEADER, opcode::SEARCH_KEY_REQ, 0xAA, 0xBB];
        let encrypted = sender.encrypt(receiver_addr(), opcode::SEARCH_KEY_REQ, &plaintext);
        assert_ne!(encrypted, plaintext);
        assert_ne!(encrypted[0], OP_KADEMLIAHEADER);

        let decrypted = receiver.decrypt(sender_addr(), &encrypted);
        assert!(decrypted.was_obfuscated);
        assert_eq!(decrypted.data, plaintext);
        assert_eq!(
            decrypted.sender_verify_key,
            Some(sender.verify_key_for_ip(match receiver_addr().ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => unreachable!(),
            }))
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_with_receiver_key_mode() {
        let sender = ObfuscationLayer::new(NodeId::from_bytes([0x33; 16]), 0x1020_3040, true);
        let receiver = ObfuscationLayer::new(NodeId::from_bytes([0x44; 16]), 0x5566_7788, true);
        let sender_ip = match sender_addr().ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => unreachable!(),
        };
        sender.register_peer_key(receiver_addr(), receiver.verify_key_for_ip(sender_ip));

        let plaintext = vec![OP_KADEMLIAHEADER, opcode::PONG, 0x01, 0x02];
        let encrypted = sender.encrypt(receiver_addr(), opcode::PONG, &plaintext);
        assert_ne!(encrypted, plaintext);
        assert_eq!(encrypted[0] & 0x03, KAD_MARKER_RECEIVER_KEY);

        let decrypted = receiver.decrypt(sender_addr(), &encrypted);
        assert!(decrypted.was_obfuscated);
        assert_eq!(decrypted.data, plaintext);
    }

    #[test]
    fn test_node_id_mode_is_preferred_over_receiver_key_even_for_response_opcodes() {
        let sender = ObfuscationLayer::new(NodeId::from_bytes([0x55; 16]), 0xAABB_CCDD, true);
        let receiver = ObfuscationLayer::new(NodeId::from_bytes([0x66; 16]), 0x1122_3344, true);
        let sender_ip = match sender_addr().ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => unreachable!(),
        };

        sender.register_peer_identity(receiver_addr(), receiver.our_node_id);
        sender.register_peer_key(receiver_addr(), receiver.verify_key_for_ip(sender_ip));

        let plaintext = vec![OP_KADEMLIAHEADER, opcode::PUBLISH_RES, 0xAA, 0x55];
        let encrypted = sender.encrypt(receiver_addr(), opcode::PUBLISH_RES, &plaintext);

        // eMule keeps preferring the Kad ID path when it knows both values.
        assert_eq!(encrypted[0] & 0x03, 0);

        let decrypted = receiver.decrypt(sender_addr(), &encrypted);
        assert!(decrypted.was_obfuscated);
        assert_eq!(decrypted.data, plaintext);
    }

    #[test]
    fn test_decrypt_plaintext_unchanged() {
        let layer = ObfuscationLayer::new(NodeId::from_bytes([0x11; 16]), 0xABCD_1234, true);
        let plain = vec![OP_KADEMLIAHEADER, opcode::PING, 0x00, 0x00];
        let decrypted = layer.decrypt(sender_addr(), &plain);
        assert!(!decrypted.was_obfuscated);
        assert_eq!(decrypted.data, plain);
        assert_eq!(decrypted.sender_verify_key, None);
    }

    #[test]
    fn test_disabled_encrypt_returns_plaintext() {
        let layer = ObfuscationLayer::new(NodeId::from_bytes([0x11; 16]), 0xDEAD_BEEF, false);
        let plaintext = vec![OP_KADEMLIAHEADER, opcode::PING];
        assert_eq!(
            layer.encrypt(receiver_addr(), opcode::PING, &plaintext),
            plaintext
        );
    }
}
