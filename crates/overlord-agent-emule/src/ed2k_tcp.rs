//! Minimal eD2k TCP support required for Kad firewall verification and TCP hello parity.
//!
//! The full eD2k peer protocol is still out of scope for the current agent, but
//! the Kad oracle exposes a real eD2k TCP surface during startup instead of a
//! one-packet firewall helper stub. To stay wire-compatible with that bootstrap
//! path, this module now implements a small stateful subset:
//! - outbound `OP_HELLO` followed by `OP_FWCHECKUDPREQ` for UDP firewall checks
//! - inbound basic eMule TCP obfuscation handshake
//! - inbound `OP_HELLO` / `OP_HELLOANSWER` framing
//! - inbound `OP_EMULEINFO` / `OP_EMULEINFOANSWER` framing
//! - inbound `OP_FWCHECKUDPREQ`
//!
//! The listener intentionally does not claim full eD2k file-transfer support;
//! it only keeps enough of the oracle's hello-capability shape to avoid looking
//! like a dead-end TCP port to real peers.

use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use md5::compute as md5_compute;
use rand::Rng;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
};
use tracing::{debug, warn};

use overlord_kad_dht::DhtNode;
use overlord_kad_proto::{FirewallUdp, KadPacket};

const OP_EMULEPROT: u8 = 0xC5;
const OP_EDONKEYPROT: u8 = 0xE3;
const OP_PACKEDPROT: u8 = 0xD4;
const OP_HELLO: u8 = 0x01;
const OP_HELLOANSWER: u8 = 0x4C;
const OP_EMULEINFO: u8 = 0x01;
const OP_EMULEINFOANSWER: u8 = 0x02;
const OP_FWCHECKUDPREQ: u8 = 0xA7;
const TCP_PACKET_HEADER_LEN: usize = 6;
const ED2K_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

const EMULE_PROTOCOL_VERSION: u8 = 0x01;
const EDONKEY_VERSION: u32 = 0x3C;
const EMULE_VERSION_MAJOR: u32 = 0;
const EMULE_VERSION_MINOR: u32 = 60;
const EMULE_VERSION_UPDATE: u32 = 3;
const EMULE_VERSION_SHORT: u8 = EMULE_VERSION_MINOR as u8;

const TAGTYPE_STRING: u8 = 0x02;
const TAGTYPE_UINT32: u8 = 0x03;
const TAGTYPE_STR1: u8 = 0x11;

const CT_NAME: u8 = 0x01;
const CT_VERSION: u8 = 0x11;
const CT_EMULE_UDPPORTS: u8 = 0xF9;
const CT_EMULE_MISCOPTIONS1: u8 = 0xFA;
const CT_EMULE_VERSION: u8 = 0xFB;
const CT_EMULE_MISCOPTIONS2: u8 = 0xFE;

const ET_COMPRESSION: u8 = 0x20;
const ET_UDPPORT: u8 = 0x21;
const ET_UDPVER: u8 = 0x22;
const ET_SOURCEEXCHANGE: u8 = 0x23;
const ET_COMMENTS: u8 = 0x24;
const ET_EXTENDEDREQUEST: u8 = 0x25;
const ET_FEATURES: u8 = 0x27;

const EMULE_CRYPT_SUPPORTS: u8 = 0x01;
const EMULE_CRYPT_REQUESTS: u8 = 0x02;
const EMULE_CRYPT_REQUIRES: u8 = 0x04;
const EMULE_ENCRYPTION_METHOD_OBFUSCATION: u8 = 0x00;
const EMULE_TCP_CRYPT_MAGIC_REQUESTER: u8 = 34;
const EMULE_TCP_CRYPT_MAGIC_SERVER: u8 = 203;
const EMULE_TCP_CRYPT_MAGIC_SYNC: u32 = 0x835E_6FC4;
const EMULE_TCP_CRYPT_DISCARD_LEN: usize = 1024;

const HELLO_NICKNAME: &str = "overlord-agent";

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
    /// UDP port advertised in the hello packet.
    pub udp_port: u16,
    /// Local eD2k connect-option bits mirrored from the oracle hello path.
    pub connect_options: u8,
}

#[derive(Debug)]
struct Rc4KeyStream {
    s: [u8; 256],
    i: usize,
    j: usize,
}

impl Rc4KeyStream {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (index, value) in s.iter_mut().enumerate() {
            *value = index as u8;
        }
        let mut j = 0usize;
        for i in 0..256usize {
            j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xFF;
            s.swap(i, j);
        }
        let mut stream = Self { s, i: 0, j: 0 };
        let mut discard = [0u8; EMULE_TCP_CRYPT_DISCARD_LEN];
        stream.apply(&mut discard);
        stream
    }

    fn apply(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            self.i = (self.i + 1) & 0xFF;
            self.j = (self.j + self.s[self.i] as usize) & 0xFF;
            self.s.swap(self.i, self.j);
            *byte ^= self.s[(self.s[self.i] as usize + self.s[self.j] as usize) & 0xFF];
        }
    }
}

#[derive(Debug)]
struct Ed2kTransport {
    stream: TcpStream,
    prefetched: VecDeque<u8>,
    receive_cipher: Option<Rc4KeyStream>,
    send_cipher: Option<Rc4KeyStream>,
    mode: Ed2kTransportMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ed2kTransportMode {
    Plaintext,
    Obfuscated,
}

impl Ed2kTransportMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Obfuscated => "obfuscated",
        }
    }
}

/// Result of the agent's active eD2k peer connect path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ed2kPeerConnectMode {
    /// A plaintext eD2k TCP session was opened.
    Plaintext,
    /// An obfuscated eD2k TCP session was opened.
    Obfuscated,
}

impl Ed2kPeerConnectMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Obfuscated => "obfuscated",
        }
    }
}

/// Send one `OP_FWCHECKUDPREQ` to a helper peer over eD2k TCP.
pub async fn request_udp_firewall_check(
    helper_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    request: FirewallCheckUdpRequest,
    timeout: Duration,
) -> Result<()> {
    let stream = tokio::time::timeout(timeout, TcpStream::connect(helper_addr))
        .await
        .with_context(|| format!("timed out connecting to eD2k helper {helper_addr}"))??;
    stream
        .set_nodelay(true)
        .with_context(|| format!("failed to enable TCP_NODELAY for helper {helper_addr}"))?;
    let mut transport = Ed2kTransport {
        stream,
        prefetched: VecDeque::new(),
        receive_cipher: None,
        send_cipher: None,
        mode: Ed2kTransportMode::Plaintext,
    };
    let hello_packet = encode_hello_request(hello_identity);
    tokio::time::timeout(timeout, transport.write_all(&hello_packet))
        .await
        .with_context(|| format!("timed out sending OP_HELLO to {helper_addr}"))??;
    let _ = tokio::time::timeout(Duration::from_millis(500), transport.read_packet()).await;
    let payload = request.encode();
    let packet = encode_packet(OP_EMULEPROT, OP_FWCHECKUDPREQ, &payload);
    tokio::time::timeout(timeout, transport.write_all(&packet))
        .await
        .with_context(|| format!("timed out sending OP_FWCHECKUDPREQ to {helper_addr}"))??;
    Ok(())
}

/// Mirror the oracle's active peer callback path by opening an outgoing eD2k
/// client connection and immediately sending `OP_HELLO`.
pub(crate) async fn connect_callback_peer(
    bind_ip: Ipv4Addr,
    peer_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    peer_user_hash: Option<[u8; 16]>,
    peer_connect_options: Option<u8>,
    timeout: Duration,
) -> Result<Ed2kPeerConnectMode> {
    let mut transport = Ed2kTransport::connect_outgoing(
        bind_ip,
        peer_addr,
        hello_identity.connect_options,
        peer_user_hash,
        peer_connect_options,
        timeout,
    )
    .await?;
    let mode = match transport.mode {
        Ed2kTransportMode::Plaintext => Ed2kPeerConnectMode::Plaintext,
        Ed2kTransportMode::Obfuscated => Ed2kPeerConnectMode::Obfuscated,
    };

    let hello_packet = encode_hello_request(hello_identity);
    tokio::time::timeout(timeout, transport.write_all(&hello_packet))
        .await
        .with_context(|| format!("timed out sending OP_HELLO to callback peer {peer_addr}"))??;

    loop {
        let packet =
            match tokio::time::timeout(ED2K_CONNECTION_IDLE_TIMEOUT, transport.read_packet()).await
            {
                Ok(Ok(packet)) => packet,
                Ok(Err(error)) if is_connection_shutdown_error(&error) => return Ok(mode),
                Ok(Err(error)) => {
                    return Err(error)
                        .with_context(|| format!("failed to read eD2k packet from {peer_addr}"));
                }
                Err(_) => return Ok(mode),
            };
        let Some(packet) = packet else {
            return Ok(mode);
        };
        match (packet.protocol, packet.opcode) {
            (OP_EDONKEYPROT, OP_HELLO) => {
                let reply = encode_hello_answer(hello_identity);
                transport
                    .write_all(&reply)
                    .await
                    .with_context(|| format!("failed to send OP_HELLOANSWER to {peer_addr}"))?;
            }
            (OP_EDONKEYPROT, OP_HELLOANSWER)
            | (OP_EMULEPROT, OP_EMULEINFOANSWER)
            | (OP_EMULEPROT, OP_EMULEINFO) => {
                if packet.opcode == OP_EMULEINFO {
                    let reply = encode_emule_info_answer(hello_identity.udp_port);
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send OP_EMULEINFOANSWER to {peer_addr}")
                    })?;
                }
                return Ok(mode);
            }
            _ => return Ok(mode),
        }
    }
}

impl Ed2kTransport {
    async fn connect_outgoing(
        bind_ip: Ipv4Addr,
        peer_addr: SocketAddr,
        local_connect_options: u8,
        peer_user_hash: Option<[u8; 16]>,
        peer_connect_options: Option<u8>,
        timeout: Duration,
    ) -> Result<Self> {
        let socket = match peer_addr {
            SocketAddr::V4(_) => {
                TcpSocket::new_v4().context("failed to create outgoing eD2k TCP socket")?
            }
            SocketAddr::V6(_) => {
                anyhow::bail!("IPv6 callback peer connections are not supported yet: {peer_addr}")
            }
        };
        socket
            .bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
            .with_context(|| format!("failed to bind outgoing eD2k socket to {bind_ip}"))?;
        let mut stream = tokio::time::timeout(timeout, socket.connect(peer_addr))
            .await
            .with_context(|| format!("timed out connecting to eD2k peer {peer_addr}"))??;
        stream
            .set_nodelay(true)
            .with_context(|| format!("failed to enable TCP_NODELAY for peer {peer_addr}"))?;

        if should_enable_outgoing_obfuscation(
            local_connect_options,
            peer_user_hash,
            peer_connect_options,
        )? {
            let peer_user_hash = peer_user_hash.expect("validated above");
            let (receive_cipher, send_cipher) = tokio::time::timeout(
                timeout,
                negotiate_outgoing_obfuscation_handshake(&mut stream, peer_user_hash),
            )
            .await
            .with_context(|| {
                format!("timed out negotiating eD2k obfuscation with peer {peer_addr}")
            })??;
            return Ok(Self {
                stream,
                prefetched: VecDeque::new(),
                receive_cipher: Some(receive_cipher),
                send_cipher: Some(send_cipher),
                mode: Ed2kTransportMode::Obfuscated,
            });
        }

        Ok(Self {
            stream,
            prefetched: VecDeque::new(),
            receive_cipher: None,
            send_cipher: None,
            mode: Ed2kTransportMode::Plaintext,
        })
    }

    async fn accept(mut stream: TcpStream, local_user_hash: [u8; 16]) -> Result<Self> {
        let mut first_byte = [0u8; 1];
        match stream.read_exact(&mut first_byte).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(Self {
                    stream,
                    prefetched: VecDeque::new(),
                    receive_cipher: None,
                    send_cipher: None,
                    mode: Ed2kTransportMode::Plaintext,
                });
            }
            Err(error) => return Err(error.into()),
        }

        if is_plain_ed2k_protocol_marker(first_byte[0]) {
            let mut prefetched = VecDeque::with_capacity(1);
            prefetched.push_back(first_byte[0]);
            return Ok(Self {
                stream,
                prefetched,
                receive_cipher: None,
                send_cipher: None,
                mode: Ed2kTransportMode::Plaintext,
            });
        }

        let (receive_cipher, send_cipher) =
            accept_incoming_obfuscation_handshake(&mut stream, local_user_hash, first_byte[0])
                .await?;
        Ok(Self {
            stream,
            prefetched: VecDeque::new(),
            receive_cipher: Some(receive_cipher),
            send_cipher: Some(send_cipher),
            mode: Ed2kTransportMode::Obfuscated,
        })
    }

    async fn read_packet(&mut self) -> Result<Option<EmuleTcpPacket>> {
        let Some(protocol) = self.read_u8().await? else {
            return Ok(None);
        };

        let mut header_rest = [0u8; TCP_PACKET_HEADER_LEN - 1];
        self.read_exact(&mut header_rest).await?;
        let packet_length = u32::from_le_bytes([
            header_rest[0],
            header_rest[1],
            header_rest[2],
            header_rest[3],
        ]);
        let opcode = header_rest[4];
        if packet_length == 0 {
            anyhow::bail!("invalid eD2k packet length 0");
        }

        let payload_len = usize::try_from(packet_length - 1).context("packet length overflow")?;
        let mut payload = vec![0u8; payload_len];
        self.read_exact(&mut payload).await?;
        Ok(Some(EmuleTcpPacket {
            protocol,
            opcode,
            payload,
        }))
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        if let Some(cipher) = self.send_cipher.as_mut() {
            let mut encrypted = bytes.to_vec();
            cipher.apply(&mut encrypted);
            self.stream.write_all(&encrypted).await?;
        } else {
            self.stream.write_all(bytes).await?;
        }
        Ok(())
    }

    async fn read_u8(&mut self) -> Result<Option<u8>> {
        if let Some(byte) = self.prefetched.pop_front() {
            return Ok(Some(byte));
        }
        let mut byte = [0u8; 1];
        match self.stream.read_exact(&mut byte).await {
            Ok(_) => {
                if let Some(cipher) = self.receive_cipher.as_mut() {
                    cipher.apply(&mut byte);
                }
                Ok(Some(byte[0]))
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn read_exact(&mut self, bytes: &mut [u8]) -> Result<()> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            if let Some(byte) = self.prefetched.pop_front() {
                bytes[offset] = byte;
                offset += 1;
            } else {
                break;
            }
        }
        if offset < bytes.len() {
            self.stream.read_exact(&mut bytes[offset..]).await?;
            if let Some(cipher) = self.receive_cipher.as_mut() {
                cipher.apply(&mut bytes[offset..]);
            }
        }
        Ok(())
    }
}

/// Return the eMule TCP/Kad connect-option bits mirrored from the oracle
/// `GetMyConnectOptions(true, false)` path, minus the direct-callback flag.
#[must_use]
pub const fn emule_connect_options(obfuscation_enabled: bool) -> u8 {
    if obfuscation_enabled {
        EMULE_CRYPT_SUPPORTS | EMULE_CRYPT_REQUESTS
    } else {
        0
    }
}

fn encode_hello_request(identity: Ed2kHelloIdentity) -> Vec<u8> {
    let mut payload = Vec::with_capacity(96);
    payload.push(16);
    payload.extend_from_slice(&encode_hello_type_payload(identity));
    encode_packet(OP_EDONKEYPROT, OP_HELLO, &payload)
}

fn encode_hello_type_payload(identity: Ed2kHelloIdentity) -> Vec<u8> {
    let mut payload = Vec::with_capacity(96);
    payload.extend_from_slice(&identity.user_hash);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&identity.tcp_port.to_le_bytes());
    append_emule_hello_tags(&mut payload, identity);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload
}

fn encode_ed2k_short_tag_header(payload: &mut Vec<u8>, type_byte: u8, name: u8) {
    payload.push(type_byte);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(name);
}

fn push_ed2k_u32_tag(payload: &mut Vec<u8>, name: u8, value: u32) {
    encode_ed2k_short_tag_header(payload, TAGTYPE_UINT32, name);
    payload.extend_from_slice(&value.to_le_bytes());
}

fn push_ed2k_string_tag(payload: &mut Vec<u8>, name: u8, value: &str) {
    let value_bytes = value.as_bytes();
    let type_byte = if (1..=16).contains(&value_bytes.len()) {
        TAGTYPE_STR1 + u8::try_from(value_bytes.len() - 1).expect("string tag length fits in u8")
    } else {
        TAGTYPE_STRING
    };
    encode_ed2k_short_tag_header(payload, type_byte, name);
    if type_byte == TAGTYPE_STRING {
        payload.extend_from_slice(
            &u16::try_from(value_bytes.len())
                .expect("string tag length fits in u16")
                .to_le_bytes(),
        );
    }
    payload.extend_from_slice(value_bytes);
}

fn emule_misc_options1() -> u32 {
    let supports_aich = 1u32;
    let supports_unicode = 1u32;
    let udp_version = 4u32;
    let data_compression_version = 1u32;
    let secure_ident_version = 0u32;
    let source_exchange_version = 4u32;
    let extended_requests_version = 2u32;
    let comments_version = 1u32;
    let peer_cache = 1u32;
    let no_view_shared_files = 1u32;
    let multipacket = 1u32;
    let preview_supported = 0u32;
    (supports_aich << 29)
        | (supports_unicode << 28)
        | (udp_version << 24)
        | (data_compression_version << 20)
        | (secure_ident_version << 16)
        | (source_exchange_version << 12)
        | (extended_requests_version << 8)
        | (comments_version << 4)
        | (peer_cache << 3)
        | (no_view_shared_files << 2)
        | (multipacket << 1)
        | preview_supported
}

fn emule_misc_options2(connect_options: u8) -> u32 {
    let supports_file_identifiers = 1u32;
    let direct_udp_callback = 0u32;
    let supports_captcha = 1u32;
    let supports_source_exchange2 = 1u32;
    let requires_crypt_layer = 0u32;
    let requests_crypt_layer = u32::from((connect_options & EMULE_CRYPT_REQUESTS) != 0);
    let supports_crypt_layer = u32::from((connect_options & EMULE_CRYPT_SUPPORTS) != 0);
    let ext_multipacket = 1u32;
    let supports_large_files = 1u32;
    let kad_version = u32::from(overlord_kad_proto::KAD_VERSION);
    (supports_file_identifiers << 13)
        | (direct_udp_callback << 12)
        | (supports_captcha << 11)
        | (supports_source_exchange2 << 10)
        | (requires_crypt_layer << 9)
        | (requests_crypt_layer << 8)
        | (supports_crypt_layer << 7)
        | (ext_multipacket << 5)
        | (supports_large_files << 4)
        | kad_version
}

fn emule_version_tag() -> u32 {
    (EMULE_VERSION_MAJOR << 17) | (EMULE_VERSION_MINOR << 10) | (EMULE_VERSION_UPDATE << 7)
}

fn append_emule_hello_tags(payload: &mut Vec<u8>, identity: Ed2kHelloIdentity) {
    payload.extend_from_slice(&6u32.to_le_bytes());
    push_ed2k_string_tag(payload, CT_NAME, HELLO_NICKNAME);
    push_ed2k_u32_tag(payload, CT_VERSION, EDONKEY_VERSION);
    // The agent only exposes one UDP surface today, so advertise the Kad port
    // in both halves until a separate eD2k UDP listener exists.
    push_ed2k_u32_tag(
        payload,
        CT_EMULE_UDPPORTS,
        (u32::from(identity.udp_port) << 16) | u32::from(identity.udp_port),
    );
    push_ed2k_u32_tag(payload, CT_EMULE_MISCOPTIONS1, emule_misc_options1());
    push_ed2k_u32_tag(
        payload,
        CT_EMULE_MISCOPTIONS2,
        emule_misc_options2(identity.connect_options),
    );
    push_ed2k_u32_tag(payload, CT_EMULE_VERSION, emule_version_tag());
}

fn encode_hello_answer(identity: Ed2kHelloIdentity) -> Vec<u8> {
    encode_packet(
        OP_EDONKEYPROT,
        OP_HELLOANSWER,
        &encode_hello_type_payload(identity),
    )
}

fn encode_emule_info_answer(kad_udp_port: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(48);
    payload.push(EMULE_VERSION_SHORT);
    payload.push(EMULE_PROTOCOL_VERSION);
    payload.extend_from_slice(&7u32.to_le_bytes());
    push_ed2k_u32_tag(&mut payload, ET_COMPRESSION, 1);
    push_ed2k_u32_tag(&mut payload, ET_UDPVER, 4);
    push_ed2k_u32_tag(&mut payload, ET_UDPPORT, u32::from(kad_udp_port));
    push_ed2k_u32_tag(&mut payload, ET_SOURCEEXCHANGE, 3);
    push_ed2k_u32_tag(&mut payload, ET_COMMENTS, 1);
    push_ed2k_u32_tag(&mut payload, ET_EXTENDEDREQUEST, 2);
    push_ed2k_u32_tag(&mut payload, ET_FEATURES, 0);
    encode_packet(OP_EMULEPROT, OP_EMULEINFOANSWER, &payload)
}

/// Run the minimal eD2k TCP listener needed for inbound hello parity and firewall checks.
pub async fn run_ed2k_listener(
    listener: Arc<TcpListener>,
    dht: DhtNode,
    hello_identity: Ed2kHelloIdentity,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                if let Err(error) = handle_connection(stream, peer_addr, &dht, hello_identity).await
                {
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
    stream: TcpStream,
    peer_addr: SocketAddr,
    dht: &DhtNode,
    hello_identity: Ed2kHelloIdentity,
) -> Result<()> {
    let kad_udp_port = dht
        .bind_addr()
        .context("failed to resolve Kad bind address for eD2k hello response")?
        .port();
    let response_identity = Ed2kHelloIdentity {
        udp_port: kad_udp_port,
        ..hello_identity
    };
    let mut transport = tokio::time::timeout(
        ED2K_CONNECTION_IDLE_TIMEOUT,
        Ed2kTransport::accept(stream, hello_identity.user_hash),
    )
    .await
    .context("timed out waiting for initial eD2k peer bytes")??;
    transport
        .stream
        .set_nodelay(true)
        .with_context(|| format!("failed to enable TCP_NODELAY for inbound peer {peer_addr}"))?;
    debug!(
        "accepted eD2k TCP peer from {peer_addr} transport={}",
        transport.mode.as_str()
    );

    loop {
        let packet =
            match tokio::time::timeout(ED2K_CONNECTION_IDLE_TIMEOUT, transport.read_packet()).await
            {
                Ok(packet) => packet
                    .with_context(|| format!("failed to read eD2k packet from {peer_addr}"))?,
                Err(_) => return Ok(()),
            };
        let Some(packet) = packet else {
            return Ok(());
        };

        match (packet.protocol, packet.opcode) {
            (OP_EDONKEYPROT, OP_HELLO) => {
                debug!(
                    "received eD2k OP_HELLO from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
                let reply = encode_hello_answer(response_identity);
                transport
                    .write_all(&reply)
                    .await
                    .with_context(|| format!("failed to send OP_HELLOANSWER to {peer_addr}"))?;
            }
            (OP_EDONKEYPROT, OP_HELLOANSWER) => {
                debug!(
                    "received eD2k OP_HELLOANSWER from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
            }
            (OP_EMULEPROT, OP_EMULEINFO) => {
                debug!(
                    "received eMule OP_EMULEINFO from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
                let reply = encode_emule_info_answer(kad_udp_port);
                transport
                    .write_all(&reply)
                    .await
                    .with_context(|| format!("failed to send OP_EMULEINFOANSWER to {peer_addr}"))?;
            }
            (OP_EMULEPROT, OP_EMULEINFOANSWER) => {
                debug!(
                    "received eMule OP_EMULEINFOANSWER from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
            }
            (OP_EMULEPROT, OP_FWCHECKUDPREQ) => {
                debug!(
                    "received eMule OP_FWCHECKUDPREQ from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
                let request = FirewallCheckUdpRequest::decode(&packet.payload)?;
                reply_with_firewall_udp(dht, peer_addr.ip(), request).await?;
            }
            _ => {
                debug!(
                    "closing eD2k connection from {peer_addr}: unsupported protocol=0x{:02X} opcode=0x{:02X}",
                    packet.protocol, packet.opcode
                );
                return Ok(());
            }
        }
    }
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

fn is_plain_ed2k_protocol_marker(marker: u8) -> bool {
    matches!(marker, OP_EDONKEYPROT | OP_PACKEDPROT | OP_EMULEPROT)
}

fn derive_obfuscation_key(
    user_hash: [u8; 16],
    magic: u8,
    random_key_part: [u8; 4],
) -> Rc4KeyStream {
    let mut key_material = [0u8; 21];
    key_material[..16].copy_from_slice(&user_hash);
    key_material[16] = magic;
    key_material[17..].copy_from_slice(&random_key_part);
    Rc4KeyStream::new(&md5_compute(key_material).0)
}

fn should_enable_outgoing_obfuscation(
    local_connect_options: u8,
    peer_user_hash: Option<[u8; 16]>,
    peer_connect_options: Option<u8>,
) -> Result<bool> {
    let Some(connect_options) = peer_connect_options else {
        return Ok(false);
    };
    let local_supports_crypt_layer = local_connect_options & EMULE_CRYPT_SUPPORTS != 0;
    let supports_crypt_layer = connect_options & EMULE_CRYPT_SUPPORTS != 0;
    let requests_crypt_layer = connect_options & EMULE_CRYPT_REQUESTS != 0;
    let requires_crypt_layer = connect_options & EMULE_CRYPT_REQUIRES != 0;

    if requires_crypt_layer && !local_supports_crypt_layer {
        anyhow::bail!("peer requires eD2k TCP obfuscation but local obfuscation is disabled");
    }

    if requires_crypt_layer && (!supports_crypt_layer || peer_user_hash.is_none()) {
        anyhow::bail!(
            "peer requires eD2k TCP obfuscation without advertising usable support metadata"
        );
    }

    Ok(local_supports_crypt_layer
        && supports_crypt_layer
        && peer_user_hash.is_some()
        && (requests_crypt_layer || local_connect_options & EMULE_CRYPT_REQUESTS != 0))
}

fn random_non_protocol_marker() -> u8 {
    loop {
        let marker = rand::random::<u8>();
        if !is_plain_ed2k_protocol_marker(marker) {
            return marker;
        }
    }
}

async fn negotiate_outgoing_obfuscation_handshake(
    stream: &mut TcpStream,
    peer_user_hash: [u8; 16],
) -> Result<(Rc4KeyStream, Rc4KeyStream)> {
    let random_key_part = rand::random::<u32>().to_le_bytes();
    let mut send_cipher = derive_obfuscation_key(
        peer_user_hash,
        EMULE_TCP_CRYPT_MAGIC_REQUESTER,
        random_key_part,
    );
    let mut receive_cipher = derive_obfuscation_key(
        peer_user_hash,
        EMULE_TCP_CRYPT_MAGIC_SERVER,
        random_key_part,
    );

    let request_padding_len = rand::thread_rng().gen_range(0..=15usize);
    let mut request = Vec::with_capacity(12 + request_padding_len);
    request.push(random_non_protocol_marker());
    request.extend_from_slice(&random_key_part);

    let mut encrypted_tail = Vec::with_capacity(7 + request_padding_len);
    encrypted_tail.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
    encrypted_tail.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    encrypted_tail.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    encrypted_tail.push(u8::try_from(request_padding_len).expect("padding length fits in u8"));
    let mut request_padding = vec![0u8; request_padding_len];
    rand::thread_rng().fill(&mut request_padding[..]);
    encrypted_tail.extend_from_slice(&request_padding);
    send_cipher.apply(&mut encrypted_tail);
    request.extend_from_slice(&encrypted_tail);
    stream.write_all(&request).await?;

    let mut encrypted_header = [0u8; 6];
    stream.read_exact(&mut encrypted_header).await?;
    receive_cipher.apply(&mut encrypted_header);
    let magic = u32::from_le_bytes(encrypted_header[..4].try_into().unwrap());
    if magic != EMULE_TCP_CRYPT_MAGIC_SYNC {
        anyhow::bail!("invalid obfuscated eD2k TCP response magic 0x{magic:08X}");
    }
    if encrypted_header[4] != EMULE_ENCRYPTION_METHOD_OBFUSCATION {
        anyhow::bail!(
            "peer selected unsupported eD2k TCP encryption method 0x{:02X}",
            encrypted_header[4]
        );
    }
    let padding_len = usize::from(encrypted_header[5]);
    if padding_len > 0 {
        let mut encrypted_padding = vec![0u8; padding_len];
        stream.read_exact(&mut encrypted_padding).await?;
        receive_cipher.apply(&mut encrypted_padding);
    }
    Ok((receive_cipher, send_cipher))
}

fn decode_incoming_obfuscation_header(
    receive_cipher: &mut Rc4KeyStream,
    encrypted_header: [u8; 7],
) -> Result<(usize, u8, u8)> {
    let mut decrypted = encrypted_header;
    receive_cipher.apply(&mut decrypted);
    let magic = u32::from_le_bytes(decrypted[..4].try_into().unwrap());
    if magic != EMULE_TCP_CRYPT_MAGIC_SYNC {
        anyhow::bail!("invalid obfuscated eD2k TCP magic 0x{magic:08X}");
    }
    Ok((usize::from(decrypted[6]), decrypted[4], decrypted[5]))
}

fn encode_incoming_obfuscation_response(send_cipher: &mut Rc4KeyStream, padding: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(6 + padding.len());
    response.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
    response.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
    response.push(u8::try_from(padding.len()).expect("padding length fits in u8"));
    response.extend_from_slice(padding);
    send_cipher.apply(&mut response);
    response
}

async fn accept_incoming_obfuscation_handshake(
    stream: &mut TcpStream,
    local_user_hash: [u8; 16],
    first_marker: u8,
) -> Result<(Rc4KeyStream, Rc4KeyStream)> {
    if is_plain_ed2k_protocol_marker(first_marker) {
        anyhow::bail!("plaintext marker 0x{first_marker:02X} cannot start obfuscated handshake");
    }

    let mut random_key_part = [0u8; 4];
    stream.read_exact(&mut random_key_part).await?;
    let mut receive_cipher = derive_obfuscation_key(
        local_user_hash,
        EMULE_TCP_CRYPT_MAGIC_REQUESTER,
        random_key_part,
    );
    let mut send_cipher = derive_obfuscation_key(
        local_user_hash,
        EMULE_TCP_CRYPT_MAGIC_SERVER,
        random_key_part,
    );

    let mut encrypted_header = [0u8; 7];
    stream.read_exact(&mut encrypted_header).await?;
    let (padding_len, supported_methods, requested_method) =
        decode_incoming_obfuscation_header(&mut receive_cipher, encrypted_header)?;
    if requested_method != EMULE_ENCRYPTION_METHOD_OBFUSCATION {
        debug!(
            "peer requested unsupported eD2k TCP encryption method 0x{requested_method:02X}; falling back to obfuscation"
        );
    }
    if supported_methods != EMULE_ENCRYPTION_METHOD_OBFUSCATION {
        debug!(
            "peer advertised unexpected eD2k TCP encryption support mask 0x{supported_methods:02X}"
        );
    }

    if padding_len > 0 {
        let mut ignored_padding = vec![0u8; padding_len];
        stream.read_exact(&mut ignored_padding).await?;
        receive_cipher.apply(&mut ignored_padding);
    }

    let response_padding_len = rand::thread_rng().gen_range(0..=15usize);
    let mut response_padding = vec![0u8; response_padding_len];
    rand::thread_rng().fill(&mut response_padding[..]);
    let response = encode_incoming_obfuscation_response(&mut send_cipher, &response_padding);
    stream.write_all(&response).await?;
    Ok((receive_cipher, send_cipher))
}

fn is_transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset | io::ErrorKind::TimedOut
    )
}

fn is_connection_shutdown_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some_and(|io_error| {
            matches!(
                io_error.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CT_EMULE_MISCOPTIONS1, CT_EMULE_MISCOPTIONS2, CT_EMULE_UDPPORTS, CT_EMULE_VERSION, CT_NAME,
        CT_VERSION, EDONKEY_VERSION, EMULE_CRYPT_REQUESTS, EMULE_CRYPT_SUPPORTS,
        EMULE_ENCRYPTION_METHOD_OBFUSCATION, EMULE_PROTOCOL_VERSION,
        EMULE_TCP_CRYPT_MAGIC_REQUESTER, EMULE_TCP_CRYPT_MAGIC_SERVER, EMULE_TCP_CRYPT_MAGIC_SYNC,
        EMULE_VERSION_SHORT, Ed2kHelloIdentity, Ed2kPeerConnectMode, FirewallCheckUdpRequest,
        HELLO_NICKNAME, OP_EDONKEYPROT, OP_EMULEINFOANSWER, OP_EMULEPROT, OP_FWCHECKUDPREQ,
        OP_HELLO, OP_HELLOANSWER, TAGTYPE_STR1, TAGTYPE_UINT32, connect_callback_peer,
        decode_incoming_obfuscation_header, derive_obfuscation_key, emule_connect_options,
        emule_misc_options1, emule_misc_options2, emule_version_tag, encode_emule_info_answer,
        encode_hello_answer, encode_hello_request, encode_incoming_obfuscation_response,
        encode_packet,
    };
    use std::{net::Ipv4Addr, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
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
    fn hello_request_encoding_matches_ed2k_framing() {
        let packet = encode_hello_request(Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            tcp_port: 41001,
            udp_port: 41000,
            connect_options: emule_connect_options(true),
        });

        assert_eq!(packet[0], OP_EDONKEYPROT);
        assert_eq!(packet[5], OP_HELLO);
        assert_eq!(packet[6], 16);
        assert_eq!(&packet[7..23], &[0x11; 16]);
        assert_eq!(u16::from_le_bytes([packet[27], packet[28]]), 41001);
        assert!(u32::from_le_bytes([packet[29], packet[30], packet[31], packet[32]]) >= 6);
        assert!(
            packet
                .windows(4)
                .any(|window| window == ((41000u32 << 16) | 41000u32).to_le_bytes())
        );
    }

    #[test]
    fn hello_answer_advertises_emule_style_tags() {
        let packet = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [0x22; 16],
            tcp_port: 41001,
            udp_port: 41000,
            connect_options: emule_connect_options(true),
        });
        let expected_name_header = [
            TAGTYPE_STR1 + u8::try_from(HELLO_NICKNAME.len() - 1).unwrap(),
            0x01,
            0x00,
            CT_NAME,
        ];
        let expected_u32_version_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_VERSION];
        let expected_udp_ports_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_UDPPORTS];
        let expected_misc1_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_MISCOPTIONS1];
        let expected_misc2_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_MISCOPTIONS2];
        let expected_emule_version_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_VERSION];

        assert_eq!(packet[0], OP_EDONKEYPROT);
        assert_eq!(packet[5], OP_HELLOANSWER);
        assert_eq!(&packet[6..22], &[0x22; 16]);
        assert_eq!(
            u32::from_le_bytes([packet[28], packet[29], packet[30], packet[31]]),
            6
        );
        assert!(
            packet
                .windows(expected_name_header.len())
                .any(|window| window == expected_name_header)
        );
        assert!(
            packet
                .windows(expected_u32_version_header.len())
                .any(|window| window == expected_u32_version_header)
        );
        assert!(
            packet
                .windows(expected_udp_ports_header.len())
                .any(|window| window == expected_udp_ports_header)
        );
        assert!(
            packet
                .windows(expected_misc1_header.len())
                .any(|window| window == expected_misc1_header)
        );
        assert!(
            packet
                .windows(expected_misc2_header.len())
                .any(|window| window == expected_misc2_header)
        );
        assert!(
            packet
                .windows(expected_emule_version_header.len())
                .any(|window| window == expected_emule_version_header)
        );
        assert!(
            packet
                .windows(HELLO_NICKNAME.len())
                .any(|window| window == HELLO_NICKNAME.as_bytes())
        );
        assert!(
            packet
                .windows(4)
                .any(|window| window == EDONKEY_VERSION.to_le_bytes())
        );
        assert!(
            packet
                .windows(4)
                .any(|window| window == ((41000u32 << 16) | 41000u32).to_le_bytes())
        );
        assert!(
            packet
                .windows(4)
                .any(|window| window == emule_misc_options1().to_le_bytes())
        );
        assert!(packet.windows(4).any(|window| {
            window == emule_misc_options2(emule_connect_options(true)).to_le_bytes()
        }));
        assert!(
            packet
                .windows(4)
                .any(|window| window == emule_version_tag().to_le_bytes())
        );
    }

    #[test]
    fn emule_info_answer_uses_expected_protocol_and_tag_count() {
        let packet = encode_emule_info_answer(41000);

        assert_eq!(packet[0], OP_EMULEPROT);
        assert_eq!(packet[5], OP_EMULEINFOANSWER);
        assert_eq!(packet[6], EMULE_VERSION_SHORT);
        assert_eq!(packet[7], EMULE_PROTOCOL_VERSION);
        assert_eq!(
            u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]),
            7
        );
    }

    #[test]
    fn connect_options_request_and_support_crypt_layer() {
        assert_eq!(
            emule_connect_options(true),
            EMULE_CRYPT_SUPPORTS | EMULE_CRYPT_REQUESTS
        );
    }

    #[test]
    fn connect_options_disable_crypt_layer_when_obfuscation_is_off() {
        assert_eq!(emule_connect_options(false), 0);
    }

    #[test]
    fn incoming_obfuscation_handshake_roundtrip_encrypts_followup_packets() {
        let user_hash = [0x44; 16];
        let random_key_part = [0x11, 0x22, 0x33, 0x44];
        let client_padding = [0xAA, 0xBB, 0xCC];
        let server_padding = [0x10, 0x20];

        let mut client_send =
            derive_obfuscation_key(user_hash, EMULE_TCP_CRYPT_MAGIC_REQUESTER, random_key_part);
        let mut client_receive =
            derive_obfuscation_key(user_hash, EMULE_TCP_CRYPT_MAGIC_SERVER, random_key_part);

        let mut encrypted_request_tail = Vec::new();
        encrypted_request_tail.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
        encrypted_request_tail.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        encrypted_request_tail.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        encrypted_request_tail.push(client_padding.len() as u8);
        encrypted_request_tail.extend_from_slice(&client_padding);
        client_send.apply(&mut encrypted_request_tail);

        let mut incoming_header = [0u8; 7];
        incoming_header.copy_from_slice(&encrypted_request_tail[..7]);
        let mut server_receive =
            derive_obfuscation_key(user_hash, EMULE_TCP_CRYPT_MAGIC_REQUESTER, random_key_part);
        let (padding_len, supported_methods, requested_method) =
            decode_incoming_obfuscation_header(&mut server_receive, incoming_header).unwrap();
        assert_eq!(padding_len, client_padding.len());
        assert_eq!(supported_methods, EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        assert_eq!(requested_method, EMULE_ENCRYPTION_METHOD_OBFUSCATION);

        let mut incoming_padding = encrypted_request_tail[7..].to_vec();
        server_receive.apply(&mut incoming_padding);
        assert_eq!(incoming_padding, client_padding);

        let mut server_send =
            derive_obfuscation_key(user_hash, EMULE_TCP_CRYPT_MAGIC_SERVER, random_key_part);
        let encrypted_response =
            encode_incoming_obfuscation_response(&mut server_send, &server_padding);

        let mut decrypted_response = encrypted_response.clone();
        client_receive.apply(&mut decrypted_response);
        assert_eq!(
            u32::from_le_bytes(decrypted_response[..4].try_into().unwrap()),
            EMULE_TCP_CRYPT_MAGIC_SYNC
        );
        assert_eq!(decrypted_response[4], EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        assert_eq!(usize::from(decrypted_response[5]), server_padding.len());
        assert_eq!(&decrypted_response[6..], &server_padding);

        let plaintext_packet = encode_packet(OP_EDONKEYPROT, OP_HELLOANSWER, &[1, 2, 3, 4]);
        let mut encrypted_packet = plaintext_packet.clone();
        client_send.apply(&mut encrypted_packet);
        server_receive.apply(&mut encrypted_packet);
        assert_eq!(encrypted_packet, plaintext_packet);

        let plaintext_reply = encode_packet(OP_EMULEPROT, OP_EMULEINFOANSWER, &[9, 8, 7]);
        let mut encrypted_reply = plaintext_reply.clone();
        server_send.apply(&mut encrypted_reply);
        client_receive.apply(&mut encrypted_reply);
        assert_eq!(encrypted_reply, plaintext_reply);
    }

    #[tokio::test]
    async fn callback_connect_uses_plaintext_when_peer_has_no_crypt_metadata() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut packet = [0u8; 6];
            stream.read_exact(&mut packet).await.unwrap();
            packet
        });

        let mode = connect_callback_peer(
            Ipv4Addr::LOCALHOST,
            peer_addr,
            Ed2kHelloIdentity {
                user_hash: [0x55; 16],
                tcp_port: 41001,
                udp_port: 41000,
                connect_options: emule_connect_options(true),
            },
            None,
            None,
            Duration::from_secs(3),
        )
        .await
        .unwrap();

        let packet = server.await.unwrap();
        assert_eq!(mode, Ed2kPeerConnectMode::Plaintext);
        assert_eq!(packet[0], OP_EDONKEYPROT);
        assert_eq!(packet[5], OP_HELLO);
    }

    #[tokio::test]
    async fn callback_connect_uses_obfuscation_when_peer_supports_crypt() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let peer_user_hash = [0x66; 16];
        let expected_hello = encode_hello_request(Ed2kHelloIdentity {
            user_hash: [0x77; 16],
            tcp_port: 41001,
            udp_port: 41000,
            connect_options: emule_connect_options(true),
        });
        let expected_hello_for_server = expected_hello.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut prefix = [0u8; 5];
            stream.read_exact(&mut prefix).await.unwrap();
            assert!(!matches!(
                prefix[0],
                OP_EDONKEYPROT | OP_EMULEPROT | super::OP_PACKEDPROT
            ));
            let random_key_part = [prefix[1], prefix[2], prefix[3], prefix[4]];

            let mut receive_cipher = derive_obfuscation_key(
                peer_user_hash,
                EMULE_TCP_CRYPT_MAGIC_REQUESTER,
                random_key_part,
            );
            let mut send_cipher = derive_obfuscation_key(
                peer_user_hash,
                EMULE_TCP_CRYPT_MAGIC_SERVER,
                random_key_part,
            );

            let mut encrypted_header = [0u8; 7];
            stream.read_exact(&mut encrypted_header).await.unwrap();
            let (padding_len, _, requested_method) =
                decode_incoming_obfuscation_header(&mut receive_cipher, encrypted_header).unwrap();
            assert_eq!(requested_method, EMULE_ENCRYPTION_METHOD_OBFUSCATION);
            if padding_len > 0 {
                let mut encrypted_padding = vec![0u8; padding_len];
                stream.read_exact(&mut encrypted_padding).await.unwrap();
                receive_cipher.apply(&mut encrypted_padding);
            }

            let mut response = Vec::new();
            response.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
            response.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
            response.push(0);
            send_cipher.apply(&mut response);
            stream.write_all(&response).await.unwrap();

            let mut encrypted_packet = vec![0u8; expected_hello_for_server.len()];
            stream.read_exact(&mut encrypted_packet).await.unwrap();
            receive_cipher.apply(&mut encrypted_packet);
            encrypted_packet
        });

        let mode = connect_callback_peer(
            Ipv4Addr::LOCALHOST,
            peer_addr,
            Ed2kHelloIdentity {
                user_hash: [0x77; 16],
                tcp_port: 41001,
                udp_port: 41000,
                connect_options: emule_connect_options(true),
            },
            Some(peer_user_hash),
            Some(super::EMULE_CRYPT_SUPPORTS | super::EMULE_CRYPT_REQUESTS),
            Duration::from_secs(3),
        )
        .await
        .unwrap();

        let packet = server.await.unwrap();
        assert_eq!(mode, Ed2kPeerConnectMode::Obfuscated);
        assert_eq!(packet, expected_hello);
    }

    #[tokio::test]
    async fn callback_connect_stays_plaintext_when_local_obfuscation_is_disabled() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let expected_hello = encode_hello_request(Ed2kHelloIdentity {
            user_hash: [0x88; 16],
            tcp_port: 41001,
            udp_port: 41000,
            connect_options: emule_connect_options(false),
        });
        let expected_hello_for_server = expected_hello.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut packet = vec![0u8; expected_hello_for_server.len()];
            stream.read_exact(&mut packet).await.unwrap();
            let reply = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0xAA; 16],
                tcp_port: 46671,
                udp_port: 46673,
                connect_options: emule_connect_options(false),
            });
            stream.write_all(&reply).await.unwrap();
            packet
        });

        let mode = connect_callback_peer(
            Ipv4Addr::LOCALHOST,
            peer_addr,
            Ed2kHelloIdentity {
                user_hash: [0x88; 16],
                tcp_port: 41001,
                udp_port: 41000,
                connect_options: emule_connect_options(false),
            },
            Some([0x99; 16]),
            Some(super::EMULE_CRYPT_SUPPORTS | super::EMULE_CRYPT_REQUESTS),
            Duration::from_secs(3),
        )
        .await
        .unwrap();

        let packet = server.await.unwrap();
        assert_eq!(mode, Ed2kPeerConnectMode::Plaintext);
        assert_eq!(packet, expected_hello);
    }
}
