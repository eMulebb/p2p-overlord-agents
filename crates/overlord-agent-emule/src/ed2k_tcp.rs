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
    fs, io,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::SecondsFormat;
use md5::compute as md5_compute;
use rand::Rng;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    rand_core::OsRng,
    signature::{RandomizedSigner, SignatureEncoding},
};
use serde::Serialize;
use sha1::Sha1;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::{Mutex, RwLock},
};
use tracing::{debug, warn};

use crate::ed2k_server::Ed2kServerState;
use crate::kad_firewall::KadFirewallState;
use overlord_kad_dht::DhtNode;
use overlord_kad_proto::{FirewallUdp, KadPacket};

const OP_EMULEPROT: u8 = 0xC5;
const OP_EDONKEYPROT: u8 = 0xE3;
const OP_PACKEDPROT: u8 = 0xD4;
const OP_HELLO: u8 = 0x01;
const OP_HELLOANSWER: u8 = 0x4C;
const OP_EMULEINFO: u8 = 0x01;
const OP_EMULEINFOANSWER: u8 = 0x02;
const OP_PUBLICKEY: u8 = 0x85;
const OP_SIGNATURE: u8 = 0x86;
const OP_SECIDENTSTATE: u8 = 0x87;
const OP_FWCHECKUDPREQ: u8 = 0xA7;
const TCP_PACKET_HEADER_LEN: usize = 6;
const ED2K_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const FIREWALL_HELPER_POST_REQUEST_KEEPALIVE_SECS: u64 = 10;

const EMULE_PROTOCOL_VERSION: u8 = 0x01;
const EDONKEY_VERSION: u32 = 0x3C;
const EMULE_VERSION_MAJOR: u32 = 0;
const EMULE_VERSION_MINOR: u32 = 60;
const EMULE_VERSION_UPDATE: u32 = 3;
const EMULE_VERSION_SHORT: u8 = EMULE_VERSION_MINOR as u8;
const EMULE_SECURE_IDENT_VERSION: u32 = 3;
const EMULE_INFO_FEATURES: u32 = 3;
const EMULE_ADVERTISED_KAD_VERSION: u32 = 10;

const TAGTYPE_STRING: u8 = 0x02;
const TAGTYPE_UINT32: u8 = 0x03;
const TAGTYPE_FLOAT32: u8 = 0x04;
const TAGTYPE_BOOL: u8 = 0x05;
const TAGTYPE_BOOLARRAY: u8 = 0x06;
const TAGTYPE_BLOB: u8 = 0x07;
const TAGTYPE_UINT16: u8 = 0x08;
const TAGTYPE_UINT8: u8 = 0x09;
const TAGTYPE_UINT64: u8 = 0x0B;
const TAGTYPE_STR1: u8 = 0x11;
const TAG_SHORT_NAME_MASK: u8 = 0x80;

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
const ED2K_SECURE_IDENT_KEY_BITS: usize = 384;
const ED2K_SECURE_IDENT_SIGNATURE_NEEDED: u8 = 1;
const ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED: u8 = 2;

const HELLO_NICKNAME: &str = "https://emule-project.net";

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
    /// Server-assigned HighID or LowID when known.
    pub client_id: u32,
    /// TCP port advertised in the hello packet.
    pub tcp_port: u16,
    /// UDP port advertised in the hello packet.
    pub udp_port: u16,
    /// Current ED2K server IPv4 address in the oracle hello trailer format.
    pub server_ip: u32,
    /// Current ED2K server TCP port in the oracle hello trailer format.
    pub server_port: u16,
    /// Local eD2k connect-option bits mirrored from the oracle hello path.
    pub connect_options: u8,
    /// Whether the node currently advertises direct UDP callback support.
    pub direct_udp_callback: bool,
}

/// Persistent RSA identity used for the eMule secure-ident side channel.
#[derive(Debug)]
pub struct Ed2kSecureIdent {
    private_key: RsaPrivateKey,
    public_key_der: Vec<u8>,
}

impl Ed2kSecureIdent {
    /// Load the oracle-compatible ED2K secure-ident keypair from disk or create it on first use.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes =
                fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
            let private_key = RsaPrivateKey::from_pkcs8_der(&bytes).with_context(|| {
                format!("invalid PKCS#8 ED2K secure-ident key at {}", path.display())
            })?;
            return Self::from_private_key(private_key);
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let private_key = RsaPrivateKey::new(&mut OsRng, ED2K_SECURE_IDENT_KEY_BITS)
            .context("failed to generate ED2K secure-ident RSA keypair")?;
        let encoded = private_key
            .to_pkcs8_der()
            .context("failed to encode ED2K secure-ident private key")?;
        fs::write(path, encoded.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?;
        Self::from_private_key(private_key)
    }

    fn from_private_key(private_key: RsaPrivateKey) -> Result<Self> {
        let public_key_der = RsaPublicKey::from(&private_key)
            .to_public_key_der()
            .context("failed to encode ED2K secure-ident public key")?
            .as_bytes()
            .to_vec();
        Ok(Self {
            private_key,
            public_key_der,
        })
    }

    fn public_key_payload(&self) -> Result<Vec<u8>> {
        let key_len = u8::try_from(self.public_key_der.len())
            .context("ED2K secure-ident public key exceeds u8 length")?;
        let mut payload = Vec::with_capacity(1 + self.public_key_der.len());
        payload.push(key_len);
        payload.extend_from_slice(&self.public_key_der);
        Ok(payload)
    }

    fn signature_payload(&self, peer_public_key: &[u8], challenge: u32) -> Result<Vec<u8>> {
        let mut message = Vec::with_capacity(peer_public_key.len() + 4);
        message.extend_from_slice(peer_public_key);
        message.extend_from_slice(&challenge.to_le_bytes());

        let signing_key = SigningKey::<Sha1>::new(self.private_key.clone());
        let signature = signing_key.sign_with_rng(&mut OsRng, &message);
        let signature_bytes = signature.to_bytes();
        let sig_len = u8::try_from(signature_bytes.len())
            .context("ED2K secure-ident signature exceeds u8 length")?;
        let mut payload = Vec::with_capacity(1 + signature_bytes.len());
        payload.push(sig_len);
        payload.extend_from_slice(signature_bytes.as_ref());
        Ok(payload)
    }
}

#[derive(Debug, Default)]
struct Ed2kPeerSecureIdentState {
    peer_public_key: Option<Vec<u8>>,
    peer_challenge_from: Option<u32>,
    challenge_for: Option<u32>,
    pending_signature: bool,
    requested_peer_key: bool,
}

/// Immutable session metadata shared by one outgoing TCP helper exchange.
#[derive(Clone, Copy)]
struct FirewallHelperContext<'a> {
    helper_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    kad_udp_port: u16,
    secure_ident: &'a Ed2kSecureIdent,
    dht: Option<&'a DhtNode>,
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

#[derive(Debug, Serialize)]
struct Ed2kTcpDumpRecord<'a> {
    schema: &'static str,
    ts_utc: String,
    flow: &'static str,
    phase: &'a str,
    direction: &'a str,
    remote_addr: String,
    transport_mode: &'a str,
    protocol: Option<&'static str>,
    protocol_marker: Option<u8>,
    opcode: Option<u8>,
    opcode_name: Option<&'static str>,
    raw_len: Option<usize>,
    raw_hex: Option<String>,
    payload_len: Option<usize>,
    payload_hex: Option<String>,
    note: Option<String>,
}

fn ed2k_tcp_dump_file() -> &'static StdMutex<Option<fs::File>> {
    static DUMP_FILE: OnceLock<StdMutex<Option<fs::File>>> = OnceLock::new();
    DUMP_FILE.get_or_init(|| {
        let file = std::env::var("OVERLORD_LOG_DIR")
            .ok()
            .map(std::path::PathBuf::from)
            .and_then(|dir| {
                fs::create_dir_all(&dir).ok()?;
                let path = dir.join(format!(
                    "agent-ed2k-tcp-dump-{}.jsonl",
                    chrono::Utc::now().format("%Y.%m.%d-%H.%M.%S")
                ));
                fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .ok()
            });
        StdMutex::new(file)
    })
}

fn ed2k_protocol_name(protocol: u8) -> &'static str {
    match protocol {
        OP_EDONKEYPROT => "ed2k",
        OP_EMULEPROT => "emule",
        OP_PACKEDPROT => "packed",
        _ => "unknown",
    }
}

fn ed2k_opcode_name(protocol: u8, opcode: u8) -> &'static str {
    match (protocol, opcode) {
        (OP_EDONKEYPROT, OP_HELLO) => "OP_HELLO",
        (OP_EDONKEYPROT, OP_HELLOANSWER) => "OP_HELLOANSWER",
        (OP_EMULEPROT, OP_EMULEINFO) => "OP_EMULEINFO",
        (OP_EMULEPROT, OP_EMULEINFOANSWER) => "OP_EMULEINFOANSWER",
        (OP_EMULEPROT, OP_PUBLICKEY) => "OP_PUBLICKEY",
        (OP_EMULEPROT, OP_SIGNATURE) => "OP_SIGNATURE",
        (OP_EMULEPROT, OP_SECIDENTSTATE) => "OP_SECIDENTSTATE",
        (OP_EMULEPROT, OP_FWCHECKUDPREQ) => "OP_FWCHECKUDPREQ",
        _ => "UNKNOWN",
    }
}

fn dump_ed2k_tcp_record(record: &Ed2kTcpDumpRecord<'_>) {
    let Ok(line) = serde_json::to_string(record) else {
        return;
    };
    let Ok(mut guard) = ed2k_tcp_dump_file().lock() else {
        return;
    };
    let Some(file) = guard.as_mut() else {
        return;
    };
    let _ = writeln!(file, "{line}");
}

fn dump_ed2k_tcp_meta(
    flow: &'static str,
    remote_addr: SocketAddr,
    transport_mode: Option<Ed2kTransportMode>,
    phase: &str,
    note: impl Into<String>,
) {
    let record = Ed2kTcpDumpRecord {
        schema: "ed2k_tcp_helper_v1",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        flow,
        phase,
        direction: "meta",
        remote_addr: remote_addr.to_string(),
        transport_mode: transport_mode.map_or("unknown", Ed2kTransportMode::as_str),
        protocol: None,
        protocol_marker: None,
        opcode: None,
        opcode_name: None,
        raw_len: None,
        raw_hex: None,
        payload_len: None,
        payload_hex: None,
        note: Some(note.into()),
    };
    dump_ed2k_tcp_record(&record);
}

fn dump_ed2k_tcp_send(
    flow: &'static str,
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    bytes: &[u8],
) {
    let protocol = bytes.first().copied();
    let opcode = bytes.get(5).copied();
    let payload = if bytes.len() > TCP_PACKET_HEADER_LEN {
        Some(&bytes[TCP_PACKET_HEADER_LEN..])
    } else {
        None
    };
    let record = Ed2kTcpDumpRecord {
        schema: "ed2k_tcp_helper_v1",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        flow,
        phase,
        direction: "send",
        remote_addr: remote_addr.to_string(),
        transport_mode: transport_mode.as_str(),
        protocol: protocol.map(ed2k_protocol_name),
        protocol_marker: protocol,
        opcode,
        opcode_name: protocol.zip(opcode).map(|(p, o)| ed2k_opcode_name(p, o)),
        raw_len: Some(bytes.len()),
        raw_hex: Some(hex::encode(bytes)),
        payload_len: payload.map(<[u8]>::len),
        payload_hex: payload.map(hex::encode),
        note: None,
    };
    dump_ed2k_tcp_record(&record);
}

fn dump_ed2k_tcp_recv(
    flow: &'static str,
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    packet: &EmuleTcpPacket,
) {
    let record = Ed2kTcpDumpRecord {
        schema: "ed2k_tcp_helper_v1",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        flow,
        phase,
        direction: "recv",
        remote_addr: remote_addr.to_string(),
        transport_mode: transport_mode.as_str(),
        protocol: Some(ed2k_protocol_name(packet.protocol)),
        protocol_marker: Some(packet.protocol),
        opcode: Some(packet.opcode),
        opcode_name: Some(ed2k_opcode_name(packet.protocol, packet.opcode)),
        raw_len: Some(TCP_PACKET_HEADER_LEN + packet.payload.len()),
        raw_hex: Some(hex::encode(encode_packet(
            packet.protocol,
            packet.opcode,
            &packet.payload,
        ))),
        payload_len: Some(packet.payload.len()),
        payload_hex: Some(hex::encode(&packet.payload)),
        note: None,
    };
    dump_ed2k_tcp_record(&record);
}

fn dump_ed2k_tcp_helper_meta(
    remote_addr: SocketAddr,
    transport_mode: Option<Ed2kTransportMode>,
    phase: &str,
    note: impl Into<String>,
) {
    dump_ed2k_tcp_meta(
        "udp_firewall_check",
        remote_addr,
        transport_mode,
        phase,
        note,
    );
}

fn dump_ed2k_tcp_helper_send(
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    bytes: &[u8],
) {
    dump_ed2k_tcp_send(
        "udp_firewall_check",
        remote_addr,
        transport_mode,
        phase,
        bytes,
    );
}

fn dump_ed2k_tcp_helper_recv(
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    packet: &EmuleTcpPacket,
) {
    dump_ed2k_tcp_recv(
        "udp_firewall_check",
        remote_addr,
        transport_mode,
        phase,
        packet,
    );
}

fn dump_ed2k_tcp_listener_meta(
    remote_addr: SocketAddr,
    transport_mode: Option<Ed2kTransportMode>,
    phase: &str,
    note: impl Into<String>,
) {
    dump_ed2k_tcp_meta("listener", remote_addr, transport_mode, phase, note);
}

fn dump_ed2k_tcp_listener_send(
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    bytes: &[u8],
) {
    dump_ed2k_tcp_send("listener", remote_addr, transport_mode, phase, bytes);
}

fn dump_ed2k_tcp_listener_recv(
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    packet: &EmuleTcpPacket,
) {
    dump_ed2k_tcp_recv("listener", remote_addr, transport_mode, phase, packet);
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

async fn drive_firewall_helper_hello_exchange(
    transport: &mut Ed2kTransport,
    context: FirewallHelperContext<'_>,
    peer_secure_ident: &mut Ed2kPeerSecureIdentState,
    timeout: Duration,
) -> Result<bool> {
    let mut hello_completed = false;
    let hello_packet = encode_hello_request(context.hello_identity);
    dump_ed2k_tcp_helper_send(
        context.helper_addr,
        transport.mode,
        "hello_request",
        &hello_packet,
    );
    tokio::time::timeout(timeout, transport.write_all(&hello_packet))
        .await
        .with_context(|| format!("timed out sending OP_HELLO to {}", context.helper_addr))??;

    // The oracle only advances the dedicated UDP firewall-check flow once the
    // HELLO side channel actually answered. Keep this bounded, but do not fall
    // through to OP_FWCHECKUDPREQ after a short silent timeout.
    let exchange_deadline = tokio::time::Instant::now() + timeout.min(Duration::from_secs(3));
    while tokio::time::Instant::now() < exchange_deadline {
        let remaining = exchange_deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = match tokio::time::timeout(remaining, transport.read_packet()).await {
            Ok(Ok(Some(packet))) => packet,
            Ok(Ok(None)) => {
                dump_ed2k_tcp_helper_meta(
                    context.helper_addr,
                    Some(transport.mode),
                    "hello_exchange_closed",
                    "connection closed before helper hello exchange completed",
                );
                break;
            }
            Ok(Err(error)) if is_connection_shutdown_error(&error) => break,
            Ok(Err(error)) => {
                dump_ed2k_tcp_helper_meta(
                    context.helper_addr,
                    Some(transport.mode),
                    "hello_exchange_error",
                    error.to_string(),
                );
                return Err(error).with_context(|| {
                    format!("failed to read eD2k packet from {}", context.helper_addr)
                });
            }
            Err(_) => break,
        };
        let packet_completed_hello = helper_packet_completes_hello(&packet);
        if !handle_firewall_helper_packet(
            transport,
            context,
            peer_secure_ident,
            "hello_exchange",
            packet,
        )
        .await?
        {
            break;
        }
        hello_completed |= packet_completed_hello;
        if hello_completed {
            break;
        }
    }

    Ok(hello_completed)
}

fn helper_packet_completes_hello(packet: &EmuleTcpPacket) -> bool {
    matches!(
        (packet.protocol, packet.opcode),
        (OP_EDONKEYPROT, OP_HELLO) | (OP_EDONKEYPROT, OP_HELLOANSWER)
    )
}

async fn handle_firewall_helper_packet(
    transport: &mut Ed2kTransport,
    context: FirewallHelperContext<'_>,
    peer_secure_ident: &mut Ed2kPeerSecureIdentState,
    phase: &str,
    packet: EmuleTcpPacket,
) -> Result<bool> {
    dump_ed2k_tcp_helper_recv(context.helper_addr, transport.mode, phase, &packet);

    match (packet.protocol, packet.opcode) {
        (OP_EDONKEYPROT, OP_HELLO) => {
            let is_mule_hello = is_mule_hello(&packet.payload)?;
            let reply = encode_hello_answer(context.hello_identity);
            dump_ed2k_tcp_helper_send(context.helper_addr, transport.mode, "hello_answer", &reply);
            transport.write_all(&reply).await.with_context(|| {
                format!("failed to send OP_HELLOANSWER to {}", context.helper_addr)
            })?;
            if is_mule_hello && !peer_secure_ident.requested_peer_key {
                let request = begin_secure_ident_probe(peer_secure_ident);
                dump_ed2k_tcp_helper_send(
                    context.helper_addr,
                    transport.mode,
                    "secure_ident_probe",
                    &request,
                );
                transport.write_all(&request).await.with_context(|| {
                    format!("failed to send OP_SECIDENTSTATE to {}", context.helper_addr)
                })?;
            }
        }
        (OP_EDONKEYPROT, OP_HELLOANSWER) => {
            // Oracle behavior: a mule-style HELLOANSWER already satisfies the
            // "both info packets received" gate, so the helper immediately
            // starts secure-ident before it sends OP_FWCHECKUDPREQ.
            let is_mule_hello = is_mule_hello_answer(&packet.payload)?;
            if is_mule_hello && !peer_secure_ident.requested_peer_key {
                let request = begin_secure_ident_probe(peer_secure_ident);
                dump_ed2k_tcp_helper_send(
                    context.helper_addr,
                    transport.mode,
                    "secure_ident_probe",
                    &request,
                );
                transport.write_all(&request).await.with_context(|| {
                    format!("failed to send OP_SECIDENTSTATE to {}", context.helper_addr)
                })?;
            }
        }
        (OP_EMULEPROT, OP_EMULEINFO) => {
            let reply = encode_emule_info_answer(context.kad_udp_port);
            dump_ed2k_tcp_helper_send(
                context.helper_addr,
                transport.mode,
                "emule_info_answer",
                &reply,
            );
            transport.write_all(&reply).await.with_context(|| {
                format!(
                    "failed to send OP_EMULEINFOANSWER to {}",
                    context.helper_addr
                )
            })?;
        }
        (OP_EMULEPROT, OP_EMULEINFOANSWER) => {}
        (OP_EMULEPROT, OP_SECIDENTSTATE) => {
            let (state, challenge) = decode_secident_state(&packet.payload)?;
            peer_secure_ident.peer_challenge_from = Some(challenge);
            if state != 0 {
                peer_secure_ident.pending_signature = true;
            }
            if state == ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED {
                let public_key = encode_packet(
                    OP_EMULEPROT,
                    OP_PUBLICKEY,
                    &context.secure_ident.public_key_payload()?,
                );
                dump_ed2k_tcp_helper_send(
                    context.helper_addr,
                    transport.mode,
                    "public_key",
                    &public_key,
                );
                transport.write_all(&public_key).await.with_context(|| {
                    format!("failed to send OP_PUBLICKEY to {}", context.helper_addr)
                })?;
            }
            if !try_send_secure_ident_signature(
                transport,
                context.helper_addr,
                context.secure_ident,
                peer_secure_ident,
            )
            .await?
                && state == ED2K_SECURE_IDENT_SIGNATURE_NEEDED
                && !peer_secure_ident.requested_peer_key
            {
                let challenge_for = random_nonzero_u32();
                peer_secure_ident.challenge_for = Some(challenge_for);
                peer_secure_ident.pending_signature = true;
                peer_secure_ident.requested_peer_key = true;
                let request = encode_secident_state(
                    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                    challenge_for,
                );
                dump_ed2k_tcp_helper_send(
                    context.helper_addr,
                    transport.mode,
                    "secure_ident_probe",
                    &request,
                );
                transport.write_all(&request).await.with_context(|| {
                    format!(
                        "failed to send fallback OP_SECIDENTSTATE to {}",
                        context.helper_addr
                    )
                })?;
            }
        }
        (OP_EMULEPROT, OP_PUBLICKEY) => {
            peer_secure_ident.peer_public_key = Some(decode_public_key_payload(&packet.payload)?);
            let _ = try_send_secure_ident_signature(
                transport,
                context.helper_addr,
                context.secure_ident,
                peer_secure_ident,
            )
            .await?;
        }
        (OP_EMULEPROT, OP_SIGNATURE) => {}
        (OP_EMULEPROT, OP_FWCHECKUDPREQ) => {
            // Oracle peers can ask us for their UDP firewall check on any
            // established client TCP session, including the same helper session
            // we opened first. Mirror that bidirectional behavior here.
            if let Some(dht) = context.dht {
                let request = FirewallCheckUdpRequest::decode(&packet.payload)?;
                dump_ed2k_tcp_helper_meta(
                    context.helper_addr,
                    Some(transport.mode),
                    "peer_fwcheck_request",
                    format!(
                        "internal_udp_port={} external_udp_port={} sender_udp_key={}",
                        request.internal_udp_port,
                        request.external_udp_port,
                        request.sender_udp_key
                    ),
                );
                reply_with_firewall_udp(dht, context.helper_addr.ip(), request).await?;
                return Ok(true);
            }
            return Ok(false);
        }
        _ => return Ok(false),
    }

    Ok(true)
}

/// Send one `OP_FWCHECKUDPREQ` to a helper peer over eD2k TCP.
pub async fn request_udp_firewall_check(
    dht: Option<DhtNode>,
    bind_ip: Ipv4Addr,
    helper_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    secure_ident: Arc<Ed2kSecureIdent>,
    request: FirewallCheckUdpRequest,
    timeout: Duration,
) -> Result<()> {
    let mut transport = match Ed2kTransport::connect_outgoing(
        bind_ip,
        helper_addr,
        hello_identity.connect_options,
        None,
        None,
        timeout,
    )
    .await
    {
        Ok(transport) => transport,
        Err(error) => {
            dump_ed2k_tcp_helper_meta(helper_addr, None, "connect_error", error.to_string());
            return Err(error);
        }
    };
    dump_ed2k_tcp_helper_meta(
        helper_addr,
        Some(transport.mode),
        "connect_ok",
        format!(
            "client_id={} server_ip={} server_port={} direct_udp_callback={}",
            hello_identity.client_id,
            Ipv4Addr::from(hello_identity.server_ip.to_le_bytes()),
            hello_identity.server_port,
            hello_identity.direct_udp_callback
        ),
    );
    let helper_context = FirewallHelperContext {
        helper_addr,
        hello_identity,
        kad_udp_port: hello_identity.udp_port,
        secure_ident: &secure_ident,
        dht: dht.as_ref(),
    };
    let mut peer_secure_ident = Ed2kPeerSecureIdentState::default();
    let hello_completed = drive_firewall_helper_hello_exchange(
        &mut transport,
        helper_context,
        &mut peer_secure_ident,
        timeout,
    )
    .await?;
    if !hello_completed {
        dump_ed2k_tcp_helper_meta(
            helper_addr,
            Some(transport.mode),
            "hello_exchange_incomplete",
            "helper never completed HELLO before firewall request",
        );
        anyhow::bail!("helper {helper_addr} did not complete HELLO before OP_FWCHECKUDPREQ");
    }
    let payload = request.encode();
    let packet = encode_packet(OP_EMULEPROT, OP_FWCHECKUDPREQ, &payload);
    dump_ed2k_tcp_helper_send(helper_addr, transport.mode, "fwcheck_request", &packet);
    tokio::time::timeout(timeout, transport.write_all(&packet))
        .await
        .with_context(|| format!("timed out sending OP_FWCHECKUDPREQ to {helper_addr}"))??;

    // Keep the helper TCP session around briefly so peers that finish their
    // hello side channel after receiving the request do not see an immediate
    // disconnect before scheduling the UDP callback.
    let post_fwcheck_deadline = tokio::time::Instant::now()
        + timeout.min(Duration::from_secs(
            FIREWALL_HELPER_POST_REQUEST_KEEPALIVE_SECS,
        ));
    while tokio::time::Instant::now() < post_fwcheck_deadline {
        let remaining =
            post_fwcheck_deadline.saturating_duration_since(tokio::time::Instant::now());
        let packet = match tokio::time::timeout(remaining, transport.read_packet()).await {
            Ok(Ok(Some(packet))) => packet,
            Ok(Ok(None)) => {
                dump_ed2k_tcp_helper_meta(
                    helper_addr,
                    Some(transport.mode),
                    "post_fwcheck_closed",
                    "connection closed after firewall request",
                );
                break;
            }
            Ok(Err(error)) if is_connection_shutdown_error(&error) => break,
            Ok(Err(error)) => {
                dump_ed2k_tcp_helper_meta(
                    helper_addr,
                    Some(transport.mode),
                    "post_fwcheck_error",
                    error.to_string(),
                );
                break;
            }
            Err(_) => break,
        };
        if !handle_firewall_helper_packet(
            &mut transport,
            helper_context,
            &mut peer_secure_ident,
            "post_fwcheck",
            packet,
        )
        .await?
        {
            break;
        }
    }
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
                for reply in build_hello_responses(&packet.payload, hello_identity)? {
                    transport
                        .write_all(&reply)
                        .await
                        .with_context(|| format!("failed to reply to OP_HELLO from {peer_addr}"))?;
                }
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
    payload.extend_from_slice(&identity.client_id.to_le_bytes());
    payload.extend_from_slice(&identity.tcp_port.to_le_bytes());
    append_emule_hello_tags(&mut payload, identity);
    payload.extend_from_slice(&identity.server_ip.to_le_bytes());
    payload.extend_from_slice(&identity.server_port.to_le_bytes());
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
    let secure_ident_version = EMULE_SECURE_IDENT_VERSION;
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

fn emule_misc_options2(connect_options: u8, direct_udp_callback: bool) -> u32 {
    let supports_file_identifiers = 1u32;
    let direct_udp_callback = u32::from(direct_udp_callback);
    let supports_captcha = 1u32;
    let supports_source_exchange2 = 1u32;
    let requires_crypt_layer = 0u32;
    let requests_crypt_layer = u32::from((connect_options & EMULE_CRYPT_REQUESTS) != 0);
    let supports_crypt_layer = u32::from((connect_options & EMULE_CRYPT_SUPPORTS) != 0);
    let ext_multipacket = 1u32;
    let supports_large_files = 1u32;
    let kad_version = EMULE_ADVERTISED_KAD_VERSION;
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
        emule_misc_options2(identity.connect_options, identity.direct_udp_callback),
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

fn encode_emule_info_payload(kad_udp_port: u16) -> Vec<u8> {
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
    push_ed2k_u32_tag(&mut payload, ET_FEATURES, EMULE_INFO_FEATURES);
    payload
}

fn encode_emule_info_request(kad_udp_port: u16) -> Vec<u8> {
    encode_packet(
        OP_EMULEPROT,
        OP_EMULEINFO,
        &encode_emule_info_payload(kad_udp_port),
    )
}

fn encode_emule_info_answer(kad_udp_port: u16) -> Vec<u8> {
    encode_packet(
        OP_EMULEPROT,
        OP_EMULEINFOANSWER,
        &encode_emule_info_payload(kad_udp_port),
    )
}

fn decode_hello_tag(mut bytes: &[u8]) -> Result<(Option<u8>, &[u8])> {
    if bytes.len() < 2 {
        anyhow::bail!("short eD2k hello tag header");
    }
    let type_byte = bytes[0];
    let short_name = (type_byte & TAG_SHORT_NAME_MASK) != 0;
    let base_type = type_byte & !TAG_SHORT_NAME_MASK;
    bytes = &bytes[1..];

    let tag_name = if short_name {
        let name = bytes[0];
        bytes = &bytes[1..];
        Some(name)
    } else {
        if bytes.len() < 2 {
            anyhow::bail!("short eD2k hello long-name length");
        }
        let name_len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        bytes = &bytes[2..];
        if bytes.len() < name_len {
            anyhow::bail!("short eD2k hello long-name bytes");
        }
        let name = if name_len == 1 { Some(bytes[0]) } else { None };
        bytes = &bytes[name_len..];
        name
    };

    let remaining = match base_type {
        TAGTYPE_STRING => {
            if bytes.len() < 2 {
                anyhow::bail!("short eD2k hello string tag length");
            }
            let len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            if bytes.len() < 2 + len {
                anyhow::bail!("short eD2k hello string tag value");
            }
            &bytes[2 + len..]
        }
        TAGTYPE_STR1..=0x20 => {
            let len = usize::from(base_type - TAGTYPE_STR1 + 1);
            if bytes.len() < len {
                anyhow::bail!("short eD2k hello compact string tag value");
            }
            &bytes[len..]
        }
        TAGTYPE_UINT32 | TAGTYPE_FLOAT32 => {
            if bytes.len() < 4 {
                anyhow::bail!("short eD2k hello 32-bit tag value");
            }
            &bytes[4..]
        }
        TAGTYPE_UINT64 => {
            if bytes.len() < 8 {
                anyhow::bail!("short eD2k hello uint64 tag value");
            }
            &bytes[8..]
        }
        TAGTYPE_UINT16 => {
            if bytes.len() < 2 {
                anyhow::bail!("short eD2k hello uint16 tag value");
            }
            &bytes[2..]
        }
        TAGTYPE_UINT8 | TAGTYPE_BOOL => {
            if bytes.is_empty() {
                anyhow::bail!("short eD2k hello uint8/bool tag value");
            }
            &bytes[1..]
        }
        TAGTYPE_BOOLARRAY => {
            if bytes.len() < 2 {
                anyhow::bail!("short eD2k hello bool-array tag length");
            }
            let bit_len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            let byte_len = (bit_len / 8).saturating_add(1);
            if bytes.len() < 2 + byte_len {
                anyhow::bail!("short eD2k hello bool-array tag value");
            }
            &bytes[2 + byte_len..]
        }
        TAGTYPE_BLOB => {
            if bytes.len() < 4 {
                anyhow::bail!("short eD2k hello blob tag length");
            }
            let blob_len = usize::try_from(u32::from_le_bytes(bytes[..4].try_into().unwrap()))
                .context("eD2k hello blob length overflow")?;
            if bytes.len() < 4 + blob_len {
                anyhow::bail!("short eD2k hello blob tag value");
            }
            &bytes[4 + blob_len..]
        }
        0x01 => {
            if bytes.len() < 16 {
                anyhow::bail!("short eD2k hello hash tag value");
            }
            &bytes[16..]
        }
        _ => anyhow::bail!("unsupported eD2k hello tag type 0x{base_type:02X}"),
    };

    Ok((tag_name, remaining))
}

fn is_mule_hello_type_payload(payload: &[u8]) -> Result<bool> {
    if payload.len() < 16 + 4 + 2 + 4 {
        anyhow::bail!("short eD2k hello-type payload");
    }
    let mut cursor = &payload[16 + 4 + 2..];
    let tag_count = usize::try_from(u32::from_le_bytes(cursor[..4].try_into().unwrap()))
        .context("eD2k hello tag count overflow")?;
    cursor = &cursor[4..];

    for _ in 0..tag_count {
        let (tag_name, rest) = decode_hello_tag(cursor)?;
        if tag_name == Some(CT_EMULE_VERSION) {
            return Ok(true);
        }
        cursor = rest;
    }

    Ok(false)
}

fn is_mule_hello(payload: &[u8]) -> Result<bool> {
    if payload.len() < 1 + 16 + 4 + 2 + 4 {
        anyhow::bail!("short eD2k OP_HELLO payload");
    }
    is_mule_hello_type_payload(&payload[1..])
}

fn is_mule_hello_answer(payload: &[u8]) -> Result<bool> {
    is_mule_hello_type_payload(payload)
}

fn build_hello_responses(
    incoming_payload: &[u8],
    response_identity: Ed2kHelloIdentity,
) -> Result<Vec<Vec<u8>>> {
    let is_mule_hello = is_mule_hello(incoming_payload)?;
    let mut replies = Vec::with_capacity(2);
    if !is_mule_hello {
        replies.push(encode_emule_info_request(response_identity.udp_port));
    }
    replies.push(encode_hello_answer(response_identity));
    Ok(replies)
}

fn encode_secident_state(state: u8, challenge: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(5);
    payload.push(state);
    payload.extend_from_slice(&challenge.to_le_bytes());
    encode_packet(OP_EMULEPROT, OP_SECIDENTSTATE, &payload)
}

fn decode_secident_state(payload: &[u8]) -> Result<(u8, u32)> {
    if payload.len() != 5 {
        anyhow::bail!("invalid OP_SECIDENTSTATE payload size {}", payload.len());
    }
    Ok((
        payload[0],
        u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]),
    ))
}

fn decode_public_key_payload(payload: &[u8]) -> Result<Vec<u8>> {
    let Some((&key_len, key_bytes)) = payload.split_first() else {
        anyhow::bail!("empty OP_PUBLICKEY payload");
    };
    if usize::from(key_len) != key_bytes.len() {
        anyhow::bail!(
            "invalid OP_PUBLICKEY length prefix {} for payload size {}",
            key_len,
            key_bytes.len()
        );
    }
    Ok(key_bytes.to_vec())
}

pub(crate) fn apply_server_state(
    mut identity: Ed2kHelloIdentity,
    state: &Ed2kServerState,
) -> Ed2kHelloIdentity {
    if let Some(client_id) = state.client_id {
        identity.client_id = client_id;
    }
    if let Some(SocketAddr::V4(endpoint)) = state.endpoint {
        identity.server_ip = u32::from_le_bytes(endpoint.ip().octets());
        identity.server_port = endpoint.port();
    }
    identity
}

/// Apply the current ED2K server and Kad firewall runtime state to an
/// outbound or listener hello identity.
pub(crate) async fn enrich_hello_identity(
    identity: Ed2kHelloIdentity,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
) -> Ed2kHelloIdentity {
    let mut identity = {
        let state = server_state.read().await;
        apply_server_state(identity, &state)
    };
    let firewall = kad_firewall.lock().await;
    identity.direct_udp_callback = identity.client_id != 0
        && identity.client_id < 0x0100_0000
        && firewall.udp_verified
        && firewall.udp_open;
    identity
}

/// Run the minimal eD2k TCP listener needed for inbound hello parity and firewall checks.
pub async fn run_ed2k_listener(
    listener: Arc<TcpListener>,
    dht: DhtNode,
    server_state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    secure_ident: Arc<Ed2kSecureIdent>,
    hello_identity: Ed2kHelloIdentity,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                if let Err(error) = handle_connection(
                    stream,
                    peer_addr,
                    &dht,
                    &server_state,
                    &kad_firewall,
                    &secure_ident,
                    hello_identity,
                )
                .await
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
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    secure_ident: &Arc<Ed2kSecureIdent>,
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
    let response_identity =
        enrich_hello_identity(response_identity, server_state, kad_firewall).await;
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
    dump_ed2k_tcp_listener_meta(
        peer_addr,
        Some(transport.mode),
        "accept",
        format!("udp_port={kad_udp_port}"),
    );
    let mut peer_secure_ident = Ed2kPeerSecureIdentState::default();

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
        dump_ed2k_tcp_listener_recv(peer_addr, transport.mode, "session", &packet);

        match (packet.protocol, packet.opcode) {
            (OP_EDONKEYPROT, OP_HELLO) => {
                let is_mule_hello = is_mule_hello(&packet.payload)?;
                debug!(
                    "received eD2k OP_HELLO from {peer_addr} transport={} mule_hello={is_mule_hello}",
                    transport.mode.as_str(),
                );
                for reply in build_hello_responses(&packet.payload, response_identity)? {
                    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "hello_reply", &reply);
                    transport
                        .write_all(&reply)
                        .await
                        .with_context(|| format!("failed to reply to OP_HELLO from {peer_addr}"))?;
                }
                if is_mule_hello && !peer_secure_ident.requested_peer_key {
                    let request = begin_secure_ident_probe(&mut peer_secure_ident);
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "secure_ident_probe",
                        &request,
                    );
                    transport.write_all(&request).await.with_context(|| {
                        format!("failed to send OP_SECIDENTSTATE to {peer_addr}")
                    })?;
                }
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
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "emule_info_answer", &reply);
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
            (OP_EMULEPROT, OP_SECIDENTSTATE) => {
                let (state, challenge) = decode_secident_state(&packet.payload)?;
                debug!(
                    "received eMule OP_SECIDENTSTATE from {peer_addr} transport={} state={} challenge={challenge}",
                    transport.mode.as_str(),
                    state
                );
                peer_secure_ident.peer_challenge_from = Some(challenge);
                if state != 0 {
                    peer_secure_ident.pending_signature = true;
                }
                if state == ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED {
                    let public_key = encode_packet(
                        OP_EMULEPROT,
                        OP_PUBLICKEY,
                        &secure_ident.public_key_payload()?,
                    );
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "public_key",
                        &public_key,
                    );
                    transport
                        .write_all(&public_key)
                        .await
                        .with_context(|| format!("failed to send OP_PUBLICKEY to {peer_addr}"))?;
                }
                if !try_send_secure_ident_signature(
                    &mut transport,
                    peer_addr,
                    secure_ident,
                    &mut peer_secure_ident,
                )
                .await?
                    && state == ED2K_SECURE_IDENT_SIGNATURE_NEEDED
                    && !peer_secure_ident.requested_peer_key
                {
                    let challenge_for = random_nonzero_u32();
                    peer_secure_ident.challenge_for = Some(challenge_for);
                    peer_secure_ident.pending_signature = true;
                    peer_secure_ident.requested_peer_key = true;
                    let request = encode_secident_state(
                        ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                        challenge_for,
                    );
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "secure_ident_probe",
                        &request,
                    );
                    transport.write_all(&request).await.with_context(|| {
                        format!("failed to send fallback OP_SECIDENTSTATE to {peer_addr}")
                    })?;
                }
            }
            (OP_EMULEPROT, OP_PUBLICKEY) => {
                peer_secure_ident.peer_public_key =
                    Some(decode_public_key_payload(&packet.payload)?);
                debug!(
                    "received eMule OP_PUBLICKEY from {peer_addr} transport={} key_len={}",
                    transport.mode.as_str(),
                    peer_secure_ident
                        .peer_public_key
                        .as_ref()
                        .map_or(0, Vec::len)
                );
                let _ = try_send_secure_ident_signature(
                    &mut transport,
                    peer_addr,
                    secure_ident,
                    &mut peer_secure_ident,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_SIGNATURE) => {
                debug!(
                    "received eMule OP_SIGNATURE from {peer_addr} transport={} payload_len={}",
                    transport.mode.as_str(),
                    packet.payload.len()
                );
            }
            (OP_EMULEPROT, OP_FWCHECKUDPREQ) => {
                debug!(
                    "received eMule OP_FWCHECKUDPREQ from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
                let request = FirewallCheckUdpRequest::decode(&packet.payload)?;
                dump_ed2k_tcp_listener_meta(
                    peer_addr,
                    Some(transport.mode),
                    "fwcheck_request",
                    format!(
                        "internal_udp_port={} external_udp_port={} sender_udp_key={}",
                        request.internal_udp_port,
                        request.external_udp_port,
                        request.sender_udp_key
                    ),
                );
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

fn random_nonzero_u32() -> u32 {
    loop {
        let value: u32 = rand::random();
        if value != 0 {
            return value;
        }
    }
}

fn begin_secure_ident_probe(peer_state: &mut Ed2kPeerSecureIdentState) -> Vec<u8> {
    let challenge_for = random_nonzero_u32();
    peer_state.challenge_for = Some(challenge_for);
    peer_state.requested_peer_key = true;
    encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, challenge_for)
}

async fn try_send_secure_ident_signature(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    secure_ident: &Ed2kSecureIdent,
    peer_state: &mut Ed2kPeerSecureIdentState,
) -> Result<bool> {
    let Some(peer_public_key) = peer_state.peer_public_key.as_deref() else {
        return Ok(false);
    };
    let Some(challenge) = peer_state.peer_challenge_from else {
        return Ok(false);
    };
    if !peer_state.pending_signature {
        return Ok(false);
    }
    let signature = encode_packet(
        OP_EMULEPROT,
        OP_SIGNATURE,
        &secure_ident.signature_payload(peer_public_key, challenge)?,
    );
    transport
        .write_all(&signature)
        .await
        .with_context(|| format!("failed to send OP_SIGNATURE to {peer_addr}"))?;
    peer_state.pending_signature = false;
    Ok(true)
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
        CT_VERSION, ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, EDONKEY_VERSION,
        EMULE_CRYPT_REQUESTS, EMULE_CRYPT_SUPPORTS, EMULE_ENCRYPTION_METHOD_OBFUSCATION,
        EMULE_PROTOCOL_VERSION, EMULE_TCP_CRYPT_MAGIC_REQUESTER, EMULE_TCP_CRYPT_MAGIC_SERVER,
        EMULE_TCP_CRYPT_MAGIC_SYNC, EMULE_VERSION_SHORT, Ed2kHelloIdentity, Ed2kPeerConnectMode,
        Ed2kPeerSecureIdentState, Ed2kSecureIdent, FirewallCheckUdpRequest, HELLO_NICKNAME,
        OP_EDONKEYPROT, OP_EMULEINFO, OP_EMULEINFOANSWER, OP_EMULEPROT, OP_FWCHECKUDPREQ, OP_HELLO,
        OP_HELLOANSWER, OP_SECIDENTSTATE, TAGTYPE_STRING, TAGTYPE_UINT32, begin_secure_ident_probe,
        build_hello_responses, connect_callback_peer, decode_incoming_obfuscation_header,
        decode_public_key_payload, decode_secident_state, derive_obfuscation_key,
        emule_connect_options, emule_misc_options1, emule_misc_options2, emule_version_tag,
        encode_emule_info_answer, encode_emule_info_request, encode_hello_answer,
        encode_hello_request, encode_incoming_obfuscation_response, encode_packet,
        encode_secident_state, enrich_hello_identity, is_mule_hello, request_udp_firewall_check,
    };
    use crate::{ed2k_server::Ed2kServerState, kad_firewall::KadFirewallState};
    use hex::decode;
    use rsa::{
        RsaPrivateKey, RsaPublicKey,
        pkcs1v15::{Signature, VerifyingKey},
        pkcs8::EncodePublicKey,
        rand_core::OsRng,
        signature::Verifier,
    };
    use sha1::Sha1;
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{Mutex, RwLock},
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
    fn secident_state_roundtrip_matches_wire_shape() {
        let packet = encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436EEAC);

        assert_eq!(packet[0], OP_EMULEPROT);
        assert_eq!(packet[5], OP_SECIDENTSTATE);
        assert_eq!(
            decode_secident_state(&packet[6..]).unwrap(),
            (ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436EEAC)
        );
    }

    #[test]
    fn public_key_payload_rejects_mismatched_length_prefix() {
        assert!(decode_public_key_payload(&[5, 1, 2, 3]).is_err());
    }

    #[test]
    fn secure_ident_probe_requests_key_and_signature() {
        let mut state = Ed2kPeerSecureIdentState::default();
        let packet = begin_secure_ident_probe(&mut state);
        let (request_state, challenge) = decode_secident_state(&packet[6..]).unwrap();

        assert_eq!(packet[0], OP_EMULEPROT);
        assert_eq!(packet[5], OP_SECIDENTSTATE);
        assert_eq!(request_state, ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED);
        assert_ne!(challenge, 0);
        assert_eq!(state.challenge_for, Some(challenge));
        assert!(state.requested_peer_key);
    }

    #[test]
    fn secure_ident_signature_matches_oracle_message_shape() {
        let identity =
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap();
        let peer_public_key = RsaPublicKey::from(&RsaPrivateKey::new(&mut OsRng, 384).unwrap())
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let challenge = 0x4436EEAC;

        let payload = identity
            .signature_payload(&peer_public_key, challenge)
            .unwrap();
        let signature = Signature::try_from(&payload[1..]).unwrap();
        let mut message = peer_public_key.clone();
        message.extend_from_slice(&challenge.to_le_bytes());

        assert_eq!(usize::from(payload[0]), payload.len() - 1);
        assert!(
            VerifyingKey::<Sha1>::new(RsaPublicKey::from(&identity.private_key))
                .verify(&message, &signature)
                .is_ok()
        );
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
            client_id: 0x521B_5895,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: u32::from_le_bytes([176, 123, 2, 239]),
            server_port: 4232,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
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
            client_id: 0x521B_5895,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: u32::from_le_bytes([176, 123, 2, 239]),
            server_port: 4232,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        });
        let expected_name_header = [TAGTYPE_STRING, 0x01, 0x00, CT_NAME];
        let expected_u32_version_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_VERSION];
        let expected_udp_ports_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_UDPPORTS];
        let expected_misc1_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_MISCOPTIONS1];
        let expected_misc2_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_MISCOPTIONS2];
        let expected_emule_version_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_VERSION];

        assert_eq!(packet[0], OP_EDONKEYPROT);
        assert_eq!(packet[5], OP_HELLOANSWER);
        assert_eq!(&packet[6..22], &[0x22; 16]);
        assert_eq!(
            u32::from_le_bytes([packet[22], packet[23], packet[24], packet[25]]),
            0x521B_5895
        );
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
            window == emule_misc_options2(emule_connect_options(true), false).to_le_bytes()
        }));
        assert!(
            packet
                .windows(4)
                .any(|window| window == emule_version_tag().to_le_bytes())
        );
        assert_eq!(
            u32::from_le_bytes([
                packet[packet.len() - 6],
                packet[packet.len() - 5],
                packet[packet.len() - 4],
                packet[packet.len() - 3]
            ]),
            u32::from_le_bytes([176, 123, 2, 239])
        );
        assert_eq!(
            u16::from_le_bytes([packet[packet.len() - 2], packet[packet.len() - 1]]),
            4232
        );
    }

    #[test]
    fn hello_answer_matches_oracle_plaintext_sample() {
        let packet = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [
                0x73, 0xBE, 0xC5, 0x66, 0x14, 0x0E, 0x7E, 0x60, 0x83, 0xC4, 0x50, 0xC9, 0xAF, 0x02,
                0x6F, 0x83,
            ],
            client_id: 0x521B_5895,
            tcp_port: 46671,
            udp_port: 46673,
            server_ip: u32::from_le_bytes([176, 123, 2, 239]),
            server_port: 4232,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });

        let expected = decode(
            "e3680000004c73bec566140e7e6083c450c9af026f8395581b524fb60600000002010001190068747470733a2f2f656d756c652d70726f6a6563742e6e6574030100113c000000030100f951b651b6030100fa1e421334030100fe3a2c0000030100fb80f10000b07b02ef8810",
        )
        .unwrap();

        assert_eq!(packet, expected);
    }

    #[test]
    fn emule_info_request_uses_expected_protocol_and_tag_count() {
        let packet = encode_emule_info_request(41000);

        assert_eq!(packet[0], OP_EMULEPROT);
        assert_eq!(packet[5], OP_EMULEINFO);
        assert_eq!(packet[6], EMULE_VERSION_SHORT);
        assert_eq!(packet[7], EMULE_PROTOCOL_VERSION);
        assert_eq!(
            u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]),
            7
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
    fn encoded_hello_request_is_detected_as_mule_hello() {
        let packet = encode_hello_request(Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0x521B_5895,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: u32::from_le_bytes([176, 123, 2, 239]),
            server_port: 4232,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        });

        assert!(is_mule_hello(&packet[6..]).unwrap());
    }

    #[test]
    fn oracle_server_callback_hello_is_detected_as_non_mule() {
        let payload = decode(
            "105d0e3efaf60e650d1f6f873e19326f635e67bc8236120200000097016553657276657289113c000000000000",
        )
        .unwrap();

        assert!(!is_mule_hello(&payload).unwrap());
    }

    #[test]
    fn non_mule_hello_replies_with_emule_info_then_helloanswer() {
        let payload = decode(
            "105d0e3efaf60e650d1f6f873e19326f635e67bc8236120200000097016553657276657289113c000000000000",
        )
        .unwrap();
        let replies = build_hello_responses(
            &payload,
            Ed2kHelloIdentity {
                user_hash: [0x22; 16],
                client_id: 0x521B_5895,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: u32::from_le_bytes([176, 123, 2, 239]),
                server_port: 4232,
                connect_options: emule_connect_options(true),
                direct_udp_callback: false,
            },
        )
        .unwrap();

        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0][0], OP_EMULEPROT);
        assert_eq!(replies[0][5], OP_EMULEINFO);
        assert_eq!(replies[1][0], OP_EDONKEYPROT);
        assert_eq!(replies[1][5], OP_HELLOANSWER);
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

    #[tokio::test]
    async fn enrich_hello_identity_sets_direct_udp_callback_for_low_id_with_verified_udp() {
        let server_state = Arc::new(RwLock::new(Ed2kServerState {
            endpoint: Some(SocketAddr::from((Ipv4Addr::new(185, 237, 185, 226), 31031))),
            client_id: Some(0x0000_1234),
            ..Ed2kServerState::default()
        }));
        let mut firewall = KadFirewallState::default();
        firewall.udp_open = true;
        firewall.udp_verified = true;
        let kad_firewall = Arc::new(Mutex::new(firewall));

        let identity = enrich_hello_identity(
            Ed2kHelloIdentity {
                user_hash: [0xAB; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(true),
                direct_udp_callback: false,
            },
            &server_state,
            &kad_firewall,
        )
        .await;

        assert!(identity.direct_udp_callback);
        assert_eq!(identity.client_id, 0x0000_1234);
        assert_eq!(identity.server_ip, u32::from_le_bytes([185, 237, 185, 226]));
        assert_eq!(identity.server_port, 31031);
    }

    #[tokio::test]
    async fn enrich_hello_identity_keeps_direct_udp_callback_off_for_high_id() {
        let server_state = Arc::new(RwLock::new(Ed2kServerState {
            endpoint: Some(SocketAddr::from((Ipv4Addr::new(185, 237, 185, 226), 31031))),
            client_id: Some(0x521B_5895),
            ..Ed2kServerState::default()
        }));
        let mut firewall = KadFirewallState::default();
        firewall.udp_open = true;
        firewall.udp_verified = true;
        let kad_firewall = Arc::new(Mutex::new(firewall));

        let identity = enrich_hello_identity(
            Ed2kHelloIdentity {
                user_hash: [0xCD; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(true),
                direct_udp_callback: false,
            },
            &server_state,
            &kad_firewall,
        )
        .await;

        assert!(!identity.direct_udp_callback);
        assert_eq!(identity.client_id, 0x521B_5895);
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
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(true),
                direct_udp_callback: false,
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
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
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
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(true),
                direct_udp_callback: false,
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
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });
        let expected_hello_for_server = expected_hello.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut packet = vec![0u8; expected_hello_for_server.len()];
            stream.read_exact(&mut packet).await.unwrap();
            let reply = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0xAA; 16],
                client_id: 0x521B_5895,
                tcp_port: 46671,
                udp_port: 46673,
                server_ip: u32::from_le_bytes([176, 123, 2, 239]),
                server_port: 4232,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&reply).await.unwrap();
            packet
        });

        let mode = connect_callback_peer(
            Ipv4Addr::LOCALHOST,
            peer_addr,
            Ed2kHelloIdentity {
                user_hash: [0x88; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
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

    #[tokio::test]
    async fn udp_firewall_check_request_completes_hello_exchange_before_request() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let helper_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            async fn read_packet(stream: &mut TcpStream) -> Vec<u8> {
                let mut header = [0u8; 6];
                stream.read_exact(&mut header).await.unwrap();
                let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
                let mut packet = header.to_vec();
                let mut payload = vec![0u8; packet_len - 1];
                stream.read_exact(&mut payload).await.unwrap();
                packet.extend_from_slice(&payload);
                packet
            }

            let (mut stream, peer_addr) = listener.accept().await.unwrap();
            assert_eq!(peer_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

            let hello = read_packet(&mut stream).await;
            assert_eq!(hello[0], OP_EDONKEYPROT);
            assert_eq!(hello[5], OP_HELLO);

            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x10; 16],
                client_id: 0x521B_5895,
                tcp_port: 46671,
                udp_port: 46673,
                server_ip: u32::from_le_bytes([176, 123, 2, 239]),
                server_port: 4232,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&hello_answer).await.unwrap();

            let emule_info = encode_emule_info_request(46673);
            stream.write_all(&emule_info).await.unwrap();

            let mut saw_emule_info_answer = false;
            let mut saw_secure_ident_probe = false;
            let mut fwcheck = None;
            for _ in 0..3 {
                let packet = read_packet(&mut stream).await;
                match (packet[0], packet[5]) {
                    (OP_EMULEPROT, OP_SECIDENTSTATE) => {
                        saw_secure_ident_probe = true;
                    }
                    (OP_EMULEPROT, OP_EMULEINFOANSWER) => {
                        saw_emule_info_answer = true;
                    }
                    (OP_EMULEPROT, OP_FWCHECKUDPREQ) => {
                        fwcheck = Some(packet);
                        break;
                    }
                    other => panic!("unexpected helper packet {:?}", other),
                }
            }
            assert!(saw_emule_info_answer || saw_secure_ident_probe);
            fwcheck.expect("expected OP_FWCHECKUDPREQ after hello exchange")
        });

        request_udp_firewall_check(
            None,
            Ipv4Addr::LOCALHOST,
            helper_addr,
            Ed2kHelloIdentity {
                user_hash: [0x77; 16],
                client_id: 0x1234_5678,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            FirewallCheckUdpRequest {
                internal_udp_port: 41000,
                external_udp_port: 41000,
                sender_udp_key: 0xAABB_CCDD,
            },
            Duration::from_secs(3),
        )
        .await
        .unwrap();

        let fwcheck = server.await.unwrap();
        assert_eq!(&fwcheck[6..8], &41000u16.to_le_bytes());
        assert_eq!(&fwcheck[8..10], &41000u16.to_le_bytes());
        assert_eq!(&fwcheck[10..14], &0xAABB_CCDDu32.to_le_bytes());
    }

    #[tokio::test]
    async fn udp_firewall_check_request_skips_silent_helper_before_request() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let helper_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, peer_addr) = listener.accept().await.unwrap();
            assert_eq!(peer_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

            let mut header = [0u8; 6];
            stream.read_exact(&mut header).await.unwrap();
            let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
            let mut payload = vec![0u8; packet_len - 1];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(header[0], OP_EDONKEYPROT);
            assert_eq!(header[5], OP_HELLO);

            let mut extra_header = [0u8; 6];
            let read_result = tokio::time::timeout(
                Duration::from_millis(500),
                stream.read_exact(&mut extra_header),
            )
            .await;
            match read_result {
                Err(_) => {}
                Ok(Err(_)) => {}
                Ok(Ok(_)) => {
                    panic!(
                        "silent helper unexpectedly received opcode 0x{:02X}",
                        extra_header[5]
                    );
                }
            }
        });

        let error = request_udp_firewall_check(
            None,
            Ipv4Addr::LOCALHOST,
            helper_addr,
            Ed2kHelloIdentity {
                user_hash: [0x77; 16],
                client_id: 0x1234_5678,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            FirewallCheckUdpRequest {
                internal_udp_port: 41000,
                external_udp_port: 41000,
                sender_udp_key: 0xAABB_CCDD,
            },
            Duration::from_millis(300),
        )
        .await
        .expect_err("silent helper must not receive firewall request");
        assert!(
            error
                .to_string()
                .contains("did not complete HELLO before OP_FWCHECKUDPREQ"),
            "{error:#}"
        );

        server.await.unwrap();
    }
}
