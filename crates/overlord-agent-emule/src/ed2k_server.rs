//! Minimal eD2k server session support used to obtain oracle-style HighID/LowID
//! feedback and keep the agent visible on the ED2K side of the network.
//!
//! This intentionally does not implement the full server feature set yet. The
//! current scope mirrors the parts of the oracle's `ServerConnect` and
//! `ServerSocket` flow that matter for parity today:
//! - connect from the VPN-bound interface to one configured ED2K server
//! - send an oracle-shaped `OP_LOGINREQUEST`
//! - process `OP_IDCHANGE`, `OP_SERVERSTATUS`, and a few informational replies
//! - keep the TCP session alive with empty `OP_OFFERFILES` packets

use std::{
    io,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use flate2::read::ZlibDecoder;
use md5::compute as md5_compute;
use num_bigint::BigUint;
use rand::{Rng, RngCore};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream, lookup_host},
    sync::RwLock,
};
use tracing::{debug, info, warn};

use overlord_agent_nat::NatManager;

use crate::{
    config::Ed2kConfig,
    ed2k_tcp::{Ed2kHelloIdentity, apply_server_state, connect_callback_peer},
};

const OP_EDONKEYPROT: u8 = 0xE3;
const OP_EMULEPROT: u8 = 0xC5;
const OP_LOGINREQUEST: u8 = 0x01;
const OP_REJECT: u8 = 0x05;
const OP_GETSERVERLIST: u8 = 0x14;
const OP_OFFERFILES: u8 = 0x15;
const OP_SEARCHREQUEST: u8 = 0x16;
const OP_SERVERLIST: u8 = 0x32;
const OP_SEARCHRESULT: u8 = 0x33;
const OP_SERVERSTATUS: u8 = 0x34;
const OP_CALLBACKREQUESTED: u8 = 0x35;
const OP_CALLBACK_FAIL: u8 = 0x36;
const OP_SERVERMESSAGE: u8 = 0x38;
const OP_IDCHANGE: u8 = 0x40;
const OP_SERVERIDENT: u8 = 0x41;
const OP_PACKEDPROT: u8 = 0xD4;
const TCP_PACKET_HEADER_LEN: usize = 6;
const MAX_SERVER_DECOMPRESSED_PACKET_LEN: usize = 250_000;

const EDONKEY_VERSION: u32 = 0x3C;
const EMULE_VERSION_MAJOR: u32 = 0;
const EMULE_VERSION_MINOR: u32 = 60;
const EMULE_VERSION_UPDATE: u32 = 3;
const HELLO_NICKNAME: &str = "https://emule-project.net";

const TAGTYPE_HASH: u8 = 0x01;
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
const CT_SERVER_FLAGS: u8 = 0x20;
const CT_EMULE_VERSION: u8 = 0xFB;

const SRVCAP_ZLIB: u32 = 0x0001;
const SRVCAP_NEWTAGS: u32 = 0x0008;
const SRVCAP_UNICODE: u32 = 0x0010;
const SRVCAP_LARGEFILES: u32 = 0x0100;
const SRVCAP_SUPPORTCRYPT: u32 = 0x0200;
const SRVCAP_REQUESTCRYPT: u32 = 0x0400;
const SRVCAP_REQUIRECRYPT: u32 = 0x0800;

const SERVER_TCP_FLAG_COMPRESSION: u32 = 0x0000_0001;
const SERVER_TCP_FLAG_NEWTAGS: u32 = 0x0000_0008;
const SERVER_TCP_FLAG_UNICODE: u32 = 0x0000_0010;
const SERVER_TCP_FLAG_RELATEDSEARCH: u32 = 0x0000_0040;
const SERVER_TCP_FLAG_TYPETAGINTEGER: u32 = 0x0000_0080;
const SERVER_TCP_FLAG_LARGEFILES: u32 = 0x0000_0100;
const SERVER_TCP_FLAG_TCPOBFUSCATION: u32 = 0x0000_0400;

const ST_SERVERNAME: u8 = 0x01;
const ST_DESCRIPTION: u8 = 0x0B;
const FT_FILENAME: u8 = 0x01;

const EMULE_TCP_CRYPT_MAGIC_REQUESTER: u8 = 34;
const EMULE_TCP_CRYPT_MAGIC_SERVER: u8 = 203;
const EMULE_TCP_CRYPT_MAGIC_SYNC: u32 = 0x835E_6FC4;
const EMULE_TCP_CRYPT_DISCARD_LEN: usize = 1024;
const EMULE_ENCRYPTION_METHOD_OBFUSCATION: u8 = 0x00;
const SERVER_OBFUSCATION_PUBLIC_KEY_LEN: usize = 96;
const SERVER_OBFUSCATION_RANDOM_EXPONENT_LEN: usize = 16;
const SERVER_OBFUSCATION_MAX_PADDING_LEN: usize = 15;
const SERVER_OBFUSCATION_PRIME_BYTES: [u8; SERVER_OBFUSCATION_PUBLIC_KEY_LEN] = [
    0xF2, 0xBF, 0x52, 0xC5, 0x5F, 0x58, 0x7A, 0xDD, 0x53, 0x71, 0xA9, 0x36, 0xE8, 0x86, 0xEB, 0x3C,
    0x62, 0x17, 0xA3, 0x3E, 0xC3, 0x4C, 0xB4, 0x0D, 0xC7, 0x3A, 0x41, 0xA6, 0x43, 0xAF, 0xFC, 0xE7,
    0x21, 0xFC, 0x28, 0x63, 0x66, 0x53, 0x5B, 0xDB, 0xCE, 0x25, 0x9F, 0x22, 0x86, 0xDA, 0x4A, 0x91,
    0xB2, 0x07, 0xCB, 0xAA, 0x52, 0x55, 0xD4, 0xF6, 0x1C, 0xCE, 0xAE, 0xD4, 0x5A, 0xD5, 0xE0, 0x74,
    0x7D, 0xF7, 0x78, 0x18, 0x28, 0x10, 0x5F, 0x34, 0x0F, 0x76, 0x23, 0x87, 0xF8, 0x8B, 0x28, 0x91,
    0x42, 0xFB, 0x42, 0x68, 0x8F, 0x05, 0x15, 0x0F, 0x54, 0x8B, 0x5F, 0x43, 0x6A, 0xF7, 0x0D, 0xF3,
];

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

/// Live ED2K server session view used by the agent to decide whether TCP is
/// still effectively firewalled from the network's point of view.
#[derive(Debug, Clone, Default)]
pub struct Ed2kServerState {
    /// Currently connected server endpoint, if any.
    pub endpoint: Option<SocketAddr>,
    /// Server-assigned client ID from `OP_IDCHANGE`.
    pub client_id: Option<u32>,
    /// Last reported TCP capability flags from the server.
    pub server_flags: Option<u32>,
    /// Last reported server user count.
    pub server_users: Option<u32>,
    /// Last reported server file count.
    pub server_files: Option<u32>,
    /// Last advertised server name, when known.
    pub server_name: Option<String>,
    /// Last advertised server description, when known.
    pub server_description: Option<String>,
    /// Whether the current session is established.
    pub connected: bool,
}

impl Ed2kServerState {
    /// Returns whether the oracle-style HighID/LowID result says TCP is firewalled.
    #[must_use]
    pub fn tcp_firewalled(&self) -> Option<bool> {
        self.client_id.map(is_low_id)
    }
}

#[derive(Debug)]
struct Ed2kPacket {
    opcode: u8,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct ServerSession {
    stream: TcpStream,
    endpoint: SocketAddr,
    state: Arc<RwLock<Ed2kServerState>>,
    last_tx: Instant,
    receive_cipher: Option<Rc4KeyStream>,
    send_cipher: Option<Rc4KeyStream>,
    probe_search_sent: bool,
}

#[derive(Clone)]
struct ServerSessionContext {
    bind_ip: Ipv4Addr,
    nat: Arc<NatManager>,
    hello_identity: Ed2kHelloIdentity,
    probe_search_term: Option<String>,
    state: Arc<RwLock<Ed2kServerState>>,
    keepalive_interval: Duration,
    connect_timeout: Duration,
    shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CallbackRequest {
    peer_addr: SocketAddr,
    connect_options: Option<u8>,
    user_hash: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SearchResultSummary {
    count: u32,
    sample_names: Vec<String>,
}

/// Returns whether the agent should start an ED2K server session with TCP
/// obfuscation.
///
/// The oracle only chooses an obfuscated server TCP connect when it has
/// positive server metadata such as `ST_TCPPORTOBFUSCATION` and the related
/// capability flags. Our current agent config only accepts raw `host:port`
/// endpoints, so those `server.met` hints are absent. To stay aligned with the
/// oracle's behavior in that metadata-poor case, the agent starts with a
/// plaintext server session instead of guessing an obfuscated path.
fn should_use_server_obfuscation(
    connect_options: u8,
    has_server_obfuscation_metadata: bool,
) -> bool {
    connect_options != 0 && has_server_obfuscation_metadata
}

impl ServerSession {
    async fn connect(
        bind_ip: Ipv4Addr,
        endpoint: SocketAddr,
        state: Arc<RwLock<Ed2kServerState>>,
        timeout: Duration,
    ) -> Result<Self> {
        let socket = TcpSocket::new_v4().context("failed to create ED2K server TCP socket")?;
        socket
            .bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
            .with_context(|| format!("failed to bind ED2K server socket to {bind_ip}"))?;
        let stream = tokio::time::timeout(timeout, socket.connect(endpoint))
            .await
            .with_context(|| format!("timed out connecting to ED2K server {endpoint}"))??;
        stream
            .set_nodelay(true)
            .with_context(|| format!("failed to enable TCP_NODELAY for ED2K server {endpoint}"))?;
        Ok(Self {
            stream,
            endpoint,
            state,
            last_tx: Instant::now(),
            receive_cipher: None,
            send_cipher: None,
            probe_search_sent: false,
        })
    }

    async fn send_packet(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        let mut packet = encode_packet(opcode, payload);
        if let Some(cipher) = self.send_cipher.as_mut() {
            cipher.apply(&mut packet);
        }
        self.stream.write_all(&packet).await.with_context(|| {
            format!("failed to send opcode=0x{opcode:02X} to {}", self.endpoint)
        })?;
        self.last_tx = Instant::now();
        Ok(())
    }

    async fn negotiate_obfuscation_and_send(&mut self, first_packet: &[u8]) -> Result<()> {
        let prime = BigUint::from_bytes_be(&SERVER_OBFUSCATION_PRIME_BYTES);
        let generator = BigUint::from(2u8);
        let secret = random_nonzero_biguint(SERVER_OBFUSCATION_RANDOM_EXPONENT_LEN);
        let public = generator.modpow(&secret, &prime);
        let public_bytes = biguint_to_fixed_be(&public, SERVER_OBFUSCATION_PUBLIC_KEY_LEN)?;

        let mut request = Vec::with_capacity(1 + SERVER_OBFUSCATION_PUBLIC_KEY_LEN + 16);
        request.push(random_non_protocol_marker());
        request.extend_from_slice(&public_bytes);
        let initial_padding_len =
            rand::thread_rng().gen_range(0..=SERVER_OBFUSCATION_MAX_PADDING_LEN);
        request.push(u8::try_from(initial_padding_len).expect("padding length fits in u8"));
        let mut initial_padding = vec![0u8; initial_padding_len];
        rand::thread_rng().fill_bytes(&mut initial_padding);
        request.extend_from_slice(&initial_padding);
        self.stream.write_all(&request).await.with_context(|| {
            format!(
                "failed to send ED2K server obfuscation request to {}",
                self.endpoint
            )
        })?;

        let mut remote_public_bytes = [0u8; SERVER_OBFUSCATION_PUBLIC_KEY_LEN];
        self.stream
            .read_exact(&mut remote_public_bytes)
            .await
            .with_context(|| {
                format!(
                    "failed to read ED2K server obfuscation DH answer from {}",
                    self.endpoint
                )
            })?;
        let remote_public = BigUint::from_bytes_be(&remote_public_bytes);
        let shared_secret = remote_public.modpow(&secret, &prime);
        let shared_secret_bytes =
            biguint_to_fixed_be(&shared_secret, SERVER_OBFUSCATION_PUBLIC_KEY_LEN)?;
        let mut send_cipher =
            derive_server_cipher(&shared_secret_bytes, EMULE_TCP_CRYPT_MAGIC_REQUESTER);
        let mut receive_cipher =
            derive_server_cipher(&shared_secret_bytes, EMULE_TCP_CRYPT_MAGIC_SERVER);

        let mut encrypted_header = [0u8; 7];
        self.stream
            .read_exact(&mut encrypted_header)
            .await
            .with_context(|| {
                format!(
                    "failed to read ED2K server obfuscation header from {}",
                    self.endpoint
                )
            })?;
        receive_cipher.apply(&mut encrypted_header);
        let magic = u32::from_le_bytes(encrypted_header[..4].try_into().unwrap());
        if magic != EMULE_TCP_CRYPT_MAGIC_SYNC {
            anyhow::bail!(
                "unexpected ED2K server obfuscation magic 0x{magic:08X} from {}",
                self.endpoint
            );
        }
        let server_preferred = encrypted_header[5];
        if server_preferred != EMULE_ENCRYPTION_METHOD_OBFUSCATION {
            debug!(
                "ED2K server {} preferred unsupported obfuscation method {}",
                self.endpoint, server_preferred
            );
        }
        let server_padding_len = usize::from(encrypted_header[6]);
        if server_padding_len > SERVER_OBFUSCATION_MAX_PADDING_LEN {
            debug!(
                "ED2K server {} sent {} obfuscation padding bytes",
                self.endpoint, server_padding_len
            );
        }
        if server_padding_len > 0 {
            let mut encrypted_padding = vec![0u8; server_padding_len];
            self.stream
                .read_exact(&mut encrypted_padding)
                .await
                .with_context(|| {
                    format!(
                        "failed to read ED2K server obfuscation padding from {}",
                        self.endpoint
                    )
                })?;
            receive_cipher.apply(&mut encrypted_padding);
        }

        let response_padding_len =
            rand::thread_rng().gen_range(0..=SERVER_OBFUSCATION_MAX_PADDING_LEN);
        let mut response = Vec::with_capacity(6 + response_padding_len + first_packet.len());
        response.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
        response.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        response.push(u8::try_from(response_padding_len).expect("padding length fits in u8"));
        let mut response_padding = vec![0u8; response_padding_len];
        rand::thread_rng().fill_bytes(&mut response_padding);
        response.extend_from_slice(&response_padding);
        response.extend_from_slice(first_packet);
        send_cipher.apply(&mut response);
        self.stream.write_all(&response).await.with_context(|| {
            format!(
                "failed to send ED2K server obfuscation response to {}",
                self.endpoint
            )
        })?;

        self.receive_cipher = Some(receive_cipher);
        self.send_cipher = Some(send_cipher);
        self.last_tx = Instant::now();
        Ok(())
    }

    async fn read_packet(&mut self) -> Result<Option<Ed2kPacket>> {
        let mut header = [0u8; TCP_PACKET_HEADER_LEN];
        match self.stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        if let Some(cipher) = self.receive_cipher.as_mut() {
            cipher.apply(&mut header);
        }

        if !matches!(header[0], OP_EDONKEYPROT | OP_PACKEDPROT) {
            anyhow::bail!(
                "unsupported ED2K server protocol 0x{:02X} from {}",
                header[0],
                self.endpoint
            );
        }

        let packet_length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
        if packet_length == 0 {
            anyhow::bail!("invalid ED2K server packet length 0");
        }
        let payload_len =
            usize::try_from(packet_length - 1).context("server packet length overflow")?;
        let mut payload = vec![0u8; payload_len];
        self.stream.read_exact(&mut payload).await?;
        if let Some(cipher) = self.receive_cipher.as_mut() {
            cipher.apply(&mut payload);
        }
        let payload = decode_server_payload(header[0], payload).with_context(|| {
            format!("failed to decode ED2K server packet from {}", self.endpoint)
        })?;
        Ok(Some(Ed2kPacket {
            opcode: header[5],
            payload,
        }))
    }
}

/// Runs the minimal oracle-shaped ED2K server session loop for the configured endpoints.
pub async fn run_ed2k_server_loop(
    bind_ip: Ipv4Addr,
    nat: Arc<NatManager>,
    config: Ed2kConfig,
    hello_identity: Ed2kHelloIdentity,
    state: Arc<RwLock<Ed2kServerState>>,
    shutdown: Arc<AtomicBool>,
) {
    let reconnect_delay = Duration::from_secs(config.reconnect_interval_secs.max(1));
    let session_context = ServerSessionContext {
        bind_ip,
        nat,
        hello_identity,
        probe_search_term: config.probe_search_term.clone(),
        state: Arc::clone(&state),
        keepalive_interval: Duration::from_secs(config.keepalive_secs.max(1)),
        connect_timeout: Duration::from_secs(config.connect_timeout_secs.max(1)),
        shutdown: Arc::clone(&shutdown),
    };

    if config.server_endpoints.is_empty() {
        info!("ED2K server session disabled: no p2p.ed2k.server_endpoints configured");
        return;
    }

    while !shutdown.load(Ordering::Relaxed) {
        let mut attempted_any = false;
        for endpoint_text in &config.server_endpoints {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            attempted_any = true;
            match resolve_server_endpoint(endpoint_text).await {
                Ok(endpoint) => {
                    if let Err(error) = run_one_server_session(endpoint, &session_context).await {
                        clear_server_connection_state(&state).await;
                        warn!("ED2K server session ended for {endpoint}: {error}");
                    }
                }
                Err(error) => {
                    warn!("failed to resolve ED2K server endpoint {endpoint_text}: {error}");
                }
            }

            if !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(reconnect_delay).await;
            }
        }

        if !attempted_any && !shutdown.load(Ordering::Relaxed) {
            tokio::time::sleep(reconnect_delay).await;
        }
    }
}

async fn run_one_server_session(
    endpoint: SocketAddr,
    context: &ServerSessionContext,
) -> Result<()> {
    let mut session = ServerSession::connect(
        context.bind_ip,
        endpoint,
        Arc::clone(&context.state),
        context.connect_timeout,
    )
    .await?;
    {
        let mut guard = context.state.write().await;
        guard.endpoint = Some(endpoint);
        guard.connected = false;
        guard.client_id = None;
        guard.server_flags = None;
    }

    let nat_status = context.nat.status().await;
    let observed_external_ip = nat_status.observed_external_addresses.first().cloned();
    let login_payload = encode_login_request(context.hello_identity);
    let has_server_obfuscation_metadata = false;
    let use_server_obfuscation = should_use_server_obfuscation(
        context.hello_identity.connect_options,
        has_server_obfuscation_metadata,
    );
    info!(
        "connected to ED2K server {} bind_ip={} observed_external_ip={} transport={} connect_options={} server_obfuscation_metadata={}",
        endpoint,
        context.bind_ip,
        observed_external_ip.as_deref().unwrap_or("unknown"),
        if use_server_obfuscation {
            "obfuscated"
        } else {
            "plaintext"
        },
        format_connect_options(context.hello_identity.connect_options),
        has_server_obfuscation_metadata
    );
    if use_server_obfuscation {
        session
            .negotiate_obfuscation_and_send(&encode_packet(OP_LOGINREQUEST, &login_payload))
            .await?;
    } else {
        session.send_packet(OP_LOGINREQUEST, &login_payload).await?;
    }

    loop {
        if context.shutdown.load(Ordering::Relaxed) {
            clear_server_connection_state(&context.state).await;
            return Ok(());
        }

        tokio::select! {
            packet = session.read_packet() => {
                let Some(packet) = packet? else {
                    anyhow::bail!("ED2K server {} closed the connection", endpoint);
                };
                handle_server_packet(&mut session, packet, context).await?;
            }
            _ = tokio::time::sleep(context.keepalive_interval) => {
                if session.last_tx.elapsed() >= context.keepalive_interval {
                    session.send_packet(OP_OFFERFILES, &0u32.to_le_bytes()).await?;
                    debug!("sent ED2K server keepalive to {}", endpoint);
                }
            }
        }
    }
}

async fn handle_server_packet(
    session: &mut ServerSession,
    packet: Ed2kPacket,
    context: &ServerSessionContext,
) -> Result<()> {
    match packet.opcode {
        OP_SERVERMESSAGE => {
            if let Some(message) = decode_ed2k_string(&packet.payload)? {
                info!("ED2K server message from {}: {}", session.endpoint, message);
            }
        }
        OP_IDCHANGE => {
            if packet.payload.len() < 4 {
                anyhow::bail!("short OP_IDCHANGE payload from {}", session.endpoint);
            }
            let client_id = u32::from_le_bytes(packet.payload[..4].try_into().unwrap());
            let server_flags = (packet.payload.len() >= 8)
                .then(|| u32::from_le_bytes(packet.payload[4..8].try_into().unwrap()));
            let reported_client_ip = (packet.payload.len() >= 16).then(|| {
                Ipv4Addr::from(u32::from_le_bytes(
                    packet.payload[12..16].try_into().unwrap(),
                ))
            });
            {
                let mut guard = session.state.write().await;
                guard.connected = true;
                guard.client_id = Some(client_id);
                guard.server_flags = server_flags;
            }
            info!(
                "ED2K server assigned client_id={} high_id={} server_flags={} reported_client_ip={}",
                client_id,
                !is_low_id(client_id),
                format_server_flags(server_flags.unwrap_or_default()),
                reported_client_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            session.send_packet(OP_GETSERVERLIST, &[]).await?;
            if !session.probe_search_sent
                && let Some(term) = context.probe_search_term.as_deref()
            {
                let search_payload = encode_search_request(term)?;
                if !search_payload.is_empty() {
                    session
                        .send_packet(OP_SEARCHREQUEST, &search_payload)
                        .await?;
                    session.probe_search_sent = true;
                    info!(
                        "sent ED2K server search probe term={term:?} endpoint={}",
                        session.endpoint
                    );
                }
            }
        }
        OP_SEARCHRESULT => {
            let summary = decode_search_results(&packet.payload)?;
            info!(
                "ED2K search results from {}: count={} sample_names={}",
                session.endpoint,
                summary.count,
                if summary.sample_names.is_empty() {
                    "-".to_string()
                } else {
                    summary.sample_names.join(" | ")
                }
            );
        }
        OP_SERVERSTATUS => {
            if packet.payload.len() >= 8 {
                let users = u32::from_le_bytes(packet.payload[..4].try_into().unwrap());
                let files = u32::from_le_bytes(packet.payload[4..8].try_into().unwrap());
                {
                    let mut guard = session.state.write().await;
                    guard.server_users = Some(users);
                    guard.server_files = Some(files);
                }
                info!(
                    "ED2K server status from {}: users={} files={}",
                    session.endpoint, users, files
                );
            }
        }
        OP_SERVERIDENT => {
            let (name, description) = decode_server_ident(&packet.payload)?;
            {
                let mut guard = session.state.write().await;
                if let Some(name) = &name {
                    guard.server_name = Some(name.clone());
                }
                if let Some(description) = &description {
                    guard.server_description = Some(description.clone());
                }
            }
            debug!(
                "ED2K server ident from {}: name={} description={}",
                session.endpoint,
                name.as_deref().unwrap_or("-"),
                description.as_deref().unwrap_or("-")
            );
        }
        OP_SERVERLIST => {
            let count = packet.payload.first().copied().unwrap_or_default();
            debug!(
                "ED2K server {} returned {} server list entries",
                session.endpoint, count
            );
        }
        OP_CALLBACKREQUESTED => {
            if let Some(callback) = decode_callback_request(&packet.payload)? {
                info!(
                    "ED2K server requested callback from peer {} transport_hint={} payload_len={}",
                    callback.peer_addr,
                    callback
                        .connect_options
                        .map(format_connect_options)
                        .unwrap_or_else(|| "plaintext".to_string()),
                    packet.payload.len()
                );
                let bind_ip = context.bind_ip;
                let hello_identity = {
                    let state = context.state.read().await;
                    apply_server_state(context.hello_identity, &state)
                };
                let connect_timeout = context.connect_timeout;
                tokio::spawn(async move {
                    match connect_callback_peer(
                        bind_ip,
                        callback.peer_addr,
                        hello_identity,
                        callback.user_hash,
                        callback.connect_options,
                        connect_timeout,
                    )
                    .await
                    {
                        Ok(mode) => {
                            info!(
                                "ED2K callback peer connect completed peer={} transport={}",
                                callback.peer_addr,
                                mode.as_str()
                            );
                        }
                        Err(error) => {
                            debug!(
                                "ED2K callback peer connect failed peer={}: {error}",
                                callback.peer_addr
                            );
                        }
                    }
                });
            }
        }
        OP_CALLBACK_FAIL => {
            debug!(
                "ED2K server callback failed notification from {}",
                session.endpoint
            );
        }
        OP_REJECT => {
            anyhow::bail!("ED2K server {} rejected the last command", session.endpoint);
        }
        opcode => {
            debug!(
                "ignoring unsupported ED2K server opcode=0x{:02X} from {} payload_len={}",
                opcode,
                session.endpoint,
                packet.payload.len()
            );
        }
    }
    Ok(())
}

fn decode_callback_request(payload: &[u8]) -> Result<Option<CallbackRequest>> {
    if payload.len() < 6 {
        return Ok(None);
    }
    let ip = Ipv4Addr::from(u32::from_le_bytes(payload[..4].try_into().unwrap()));
    let port = u16::from_le_bytes(payload[4..6].try_into().unwrap());
    let connect_options = payload.get(6).copied();
    let user_hash = (payload.len() >= 23).then(|| {
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&payload[7..23]);
        hash
    });
    Ok(Some(CallbackRequest {
        peer_addr: SocketAddr::new(IpAddr::V4(ip), port),
        connect_options,
        user_hash,
    }))
}

async fn clear_server_connection_state(state: &Arc<RwLock<Ed2kServerState>>) {
    let mut guard = state.write().await;
    guard.connected = false;
    guard.endpoint = None;
    guard.client_id = None;
    guard.server_flags = None;
}

async fn resolve_server_endpoint(endpoint_text: &str) -> Result<SocketAddr> {
    if let Ok(endpoint) = endpoint_text.parse::<SocketAddr>() {
        return Ok(endpoint);
    }
    lookup_host(endpoint_text)
        .await
        .with_context(|| format!("failed to resolve {endpoint_text}"))?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| anyhow::anyhow!("no IPv4 address resolved for {endpoint_text}"))
}

fn encode_login_request(identity: Ed2kHelloIdentity) -> Vec<u8> {
    let mut payload = Vec::with_capacity(96);
    payload.extend_from_slice(&identity.user_hash);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&identity.tcp_port.to_le_bytes());
    payload.extend_from_slice(&4u32.to_le_bytes());
    push_string_tag(&mut payload, CT_NAME, HELLO_NICKNAME);
    push_u32_tag(&mut payload, CT_VERSION, EDONKEY_VERSION);
    push_u32_tag(
        &mut payload,
        CT_SERVER_FLAGS,
        server_capabilities(identity.connect_options),
    );
    push_u32_tag(&mut payload, CT_EMULE_VERSION, emule_version_tag());
    payload
}

fn encode_search_request(term: &str) -> Result<Vec<u8>> {
    let terms: Vec<&str> = term
        .split_whitespace()
        .filter(|term| !term.is_empty())
        .collect();
    if terms.is_empty() {
        return Ok(Vec::new());
    }

    let mut payload = Vec::new();
    encode_search_terms(&mut payload, &terms)?;
    Ok(payload)
}

fn encode_search_terms(payload: &mut Vec<u8>, terms: &[&str]) -> Result<()> {
    let Some((first, rest)) = terms.split_first() else {
        return Ok(());
    };
    if rest.is_empty() {
        encode_search_string_param(payload, first)?;
        return Ok(());
    }

    payload.push(0);
    payload.push(0x00);
    encode_search_string_param(payload, first)?;
    encode_search_terms(payload, rest)?;
    Ok(())
}

fn encode_search_string_param(payload: &mut Vec<u8>, value: &str) -> Result<()> {
    let value_bytes = value.as_bytes();
    let value_len = u16::try_from(value_bytes.len()).context("ED2K search term is too long")?;
    payload.push(1);
    payload.extend_from_slice(&value_len.to_le_bytes());
    payload.extend_from_slice(value_bytes);
    Ok(())
}

fn server_capabilities(connect_options: u8) -> u32 {
    let mut flags = SRVCAP_ZLIB | SRVCAP_NEWTAGS | SRVCAP_LARGEFILES | SRVCAP_UNICODE;
    if connect_options & 0x01 != 0 {
        flags |= SRVCAP_SUPPORTCRYPT;
    }
    if connect_options & 0x02 != 0 {
        flags |= SRVCAP_REQUESTCRYPT;
    }
    if connect_options & 0x04 != 0 {
        flags |= SRVCAP_REQUIRECRYPT;
    }
    flags
}

fn emule_version_tag() -> u32 {
    (EMULE_VERSION_MAJOR << 17) | (EMULE_VERSION_MINOR << 10) | (EMULE_VERSION_UPDATE << 7)
}

fn push_u32_tag(payload: &mut Vec<u8>, name: u8, value: u32) {
    payload.push(TAGTYPE_UINT32);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(name);
    payload.extend_from_slice(&value.to_le_bytes());
}

fn push_string_tag(payload: &mut Vec<u8>, name: u8, value: &str) {
    let value_bytes = value.as_bytes();
    let type_byte = if (1..=16).contains(&value_bytes.len()) {
        TAGTYPE_STR1 + u8::try_from(value_bytes.len() - 1).expect("string tag length fits in u8")
    } else {
        TAGTYPE_STRING
    };
    payload.push(type_byte);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(name);
    if type_byte == TAGTYPE_STRING {
        payload.extend_from_slice(
            &u16::try_from(value_bytes.len())
                .expect("string tag length fits in u16")
                .to_le_bytes(),
        );
    }
    payload.extend_from_slice(value_bytes);
}

fn encode_packet(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(TCP_PACKET_HEADER_LEN + payload.len());
    bytes.push(OP_EDONKEYPROT);
    bytes.extend_from_slice(
        &(u32::try_from(payload.len() + 1).expect("payload too large")).to_le_bytes(),
    );
    bytes.push(opcode);
    bytes.extend_from_slice(payload);
    bytes
}

fn random_nonzero_biguint(byte_len: usize) -> BigUint {
    let mut bytes = vec![0u8; byte_len];
    rand::thread_rng().fill_bytes(&mut bytes);
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[byte_len - 1] = 1;
    }
    BigUint::from_bytes_be(&bytes)
}

fn biguint_to_fixed_be(value: &BigUint, byte_len: usize) -> Result<Vec<u8>> {
    let bytes = value.to_bytes_be();
    if bytes.len() > byte_len {
        anyhow::bail!(
            "big integer requires {} bytes, expected at most {}",
            bytes.len(),
            byte_len
        );
    }
    let mut fixed = vec![0u8; byte_len];
    fixed[byte_len - bytes.len()..].copy_from_slice(&bytes);
    Ok(fixed)
}

fn derive_server_cipher(shared_secret: &[u8], magic: u8) -> Rc4KeyStream {
    let mut key_material = Vec::with_capacity(shared_secret.len() + 1);
    key_material.extend_from_slice(shared_secret);
    key_material.push(magic);
    Rc4KeyStream::new(&md5_compute(key_material).0)
}

fn random_non_protocol_marker() -> u8 {
    loop {
        let mut marker = [0u8; 1];
        rand::thread_rng().fill_bytes(&mut marker);
        let marker = marker[0];
        if !matches!(marker, OP_EDONKEYPROT | OP_EMULEPROT | OP_PACKEDPROT) {
            return marker;
        }
    }
}

fn decode_server_payload(protocol: u8, payload: Vec<u8>) -> Result<Vec<u8>> {
    if protocol != OP_PACKEDPROT {
        return Ok(payload);
    }

    let mut decoder = ZlibDecoder::new(payload.as_slice());
    let mut decoded = Vec::with_capacity(
        payload
            .len()
            .saturating_mul(10)
            .saturating_add(300)
            .min(MAX_SERVER_DECOMPRESSED_PACKET_LEN),
    );
    let mut chunk = [0u8; 4096];
    loop {
        let read = decoder.read(&mut chunk).context("zlib inflate failed")?;
        if read == 0 {
            break;
        }
        if decoded.len().saturating_add(read) > MAX_SERVER_DECOMPRESSED_PACKET_LEN {
            anyhow::bail!(
                "decompressed ED2K server packet exceeded {} bytes",
                MAX_SERVER_DECOMPRESSED_PACKET_LEN
            );
        }
        decoded.extend_from_slice(&chunk[..read]);
    }
    Ok(decoded)
}

fn decode_ed2k_string(payload: &[u8]) -> Result<Option<String>> {
    if payload.len() < 2 {
        return Ok(None);
    }
    let len = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
    if payload.len() < len + 2 {
        anyhow::bail!("short ED2K string payload");
    }
    Ok(Some(
        String::from_utf8_lossy(&payload[2..2 + len]).into_owned(),
    ))
}

fn decode_server_ident(payload: &[u8]) -> Result<(Option<String>, Option<String>)> {
    if payload.len() < 26 {
        return Ok((None, None));
    }
    let tag_count = u32::from_le_bytes(payload[22..26].try_into().unwrap());
    let mut cursor = &payload[26..];
    let mut name = None;
    let mut description = None;
    for _ in 0..tag_count {
        let (tag_name, tag_value, rest) = decode_tag(cursor)?;
        cursor = rest;
        match tag_name {
            Some(ST_SERVERNAME) => name = tag_value,
            Some(ST_DESCRIPTION) => description = tag_value,
            _ => {}
        }
    }
    Ok((name, description))
}

fn decode_search_results(payload: &[u8]) -> Result<SearchResultSummary> {
    if payload.len() < 4 {
        anyhow::bail!("short ED2K search results payload");
    }
    let count = u32::from_le_bytes(payload[..4].try_into().unwrap());
    let mut cursor = &payload[4..];
    let mut sample_names = Vec::new();

    for _ in 0..count {
        if cursor.len() < 26 {
            anyhow::bail!("short ED2K search result entry");
        }
        cursor = &cursor[22..];
        let tag_count = u32::from_le_bytes(cursor[..4].try_into().unwrap());
        cursor = &cursor[4..];
        let mut name = None;
        for _ in 0..tag_count {
            let (tag_name, tag_value, rest) = decode_tag(cursor)?;
            cursor = rest;
            if tag_name == Some(FT_FILENAME) && name.is_none() {
                name = tag_value;
            }
        }
        if let Some(name) = name
            && sample_names.len() < 3
        {
            sample_names.push(name);
        }
    }

    Ok(SearchResultSummary {
        count,
        sample_names,
    })
}

fn decode_tag(mut bytes: &[u8]) -> Result<(Option<u8>, Option<String>, &[u8])> {
    if bytes.len() < 2 {
        anyhow::bail!("short ED2K tag header");
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
            anyhow::bail!("short ED2K long-name length");
        }
        let name_len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        bytes = &bytes[2..];
        if bytes.len() < name_len {
            anyhow::bail!("short ED2K long-name bytes");
        }
        let name = if name_len == 1 { Some(bytes[0]) } else { None };
        bytes = &bytes[name_len..];
        name
    };

    let string_value = match base_type {
        TAGTYPE_STRING => {
            if bytes.len() < 2 {
                anyhow::bail!("short ED2K string tag length");
            }
            let len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            bytes = &bytes[2..];
            if bytes.len() < len {
                anyhow::bail!("short ED2K string tag value");
            }
            let value = String::from_utf8_lossy(&bytes[..len]).into_owned();
            bytes = &bytes[len..];
            Some(value)
        }
        TAGTYPE_STR1..=0x20 => {
            let len = usize::from(base_type - TAGTYPE_STR1 + 1);
            if bytes.len() < len {
                anyhow::bail!("short ED2K compact string tag value");
            }
            let value = String::from_utf8_lossy(&bytes[..len]).into_owned();
            bytes = &bytes[len..];
            Some(value)
        }
        TAGTYPE_UINT32 => {
            if bytes.len() < 4 {
                anyhow::bail!("short ED2K uint32 tag value");
            }
            bytes = &bytes[4..];
            None
        }
        TAGTYPE_UINT64 => {
            if bytes.len() < 8 {
                anyhow::bail!("short ED2K uint64 tag value");
            }
            bytes = &bytes[8..];
            None
        }
        TAGTYPE_UINT16 => {
            if bytes.len() < 2 {
                anyhow::bail!("short ED2K uint16 tag value");
            }
            bytes = &bytes[2..];
            None
        }
        TAGTYPE_UINT8 | TAGTYPE_BOOL => {
            if bytes.is_empty() {
                anyhow::bail!("short ED2K uint8/bool tag value");
            }
            bytes = &bytes[1..];
            None
        }
        TAGTYPE_FLOAT32 => {
            if bytes.len() < 4 {
                anyhow::bail!("short ED2K float32 tag value");
            }
            bytes = &bytes[4..];
            None
        }
        TAGTYPE_HASH => {
            if bytes.len() < 16 {
                anyhow::bail!("short ED2K hash tag value");
            }
            bytes = &bytes[16..];
            None
        }
        TAGTYPE_BOOLARRAY => {
            if bytes.len() < 2 {
                anyhow::bail!("short ED2K bool-array tag length");
            }
            let bit_len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            bytes = &bytes[2..];
            let byte_len = (bit_len / 8).saturating_add(1);
            if bytes.len() < byte_len {
                anyhow::bail!("short ED2K bool-array tag value");
            }
            bytes = &bytes[byte_len..];
            None
        }
        TAGTYPE_BLOB => {
            if bytes.len() < 4 {
                anyhow::bail!("short ED2K blob tag length");
            }
            let blob_len = usize::try_from(u32::from_le_bytes(bytes[..4].try_into().unwrap()))
                .context("ED2K blob tag length overflow")?;
            bytes = &bytes[4..];
            if bytes.len() < blob_len {
                anyhow::bail!("short ED2K blob tag value");
            }
            bytes = &bytes[blob_len..];
            None
        }
        _ => anyhow::bail!("unsupported ED2K tag type 0x{base_type:02X}"),
    };

    Ok((tag_name, string_value, bytes))
}

fn format_server_flags(flags: u32) -> String {
    let mut enabled = Vec::new();
    if flags & SERVER_TCP_FLAG_COMPRESSION != 0 {
        enabled.push("compression");
    }
    if flags & SERVER_TCP_FLAG_NEWTAGS != 0 {
        enabled.push("newtags");
    }
    if flags & SERVER_TCP_FLAG_UNICODE != 0 {
        enabled.push("unicode");
    }
    if flags & SERVER_TCP_FLAG_RELATEDSEARCH != 0 {
        enabled.push("related_search");
    }
    if flags & SERVER_TCP_FLAG_TYPETAGINTEGER != 0 {
        enabled.push("int_tags");
    }
    if flags & SERVER_TCP_FLAG_LARGEFILES != 0 {
        enabled.push("large_files");
    }
    if flags & SERVER_TCP_FLAG_TCPOBFUSCATION != 0 {
        enabled.push("tcp_obfuscation");
    }
    if enabled.is_empty() {
        format!("0x{flags:08X}")
    } else {
        format!("0x{flags:08X} [{}]", enabled.join(","))
    }
}

fn format_connect_options(connect_options: u8) -> String {
    let mut parts = Vec::new();
    if connect_options & 0x01 != 0 {
        parts.push("supports_crypt");
    }
    if connect_options & 0x02 != 0 {
        parts.push("requests_crypt");
    }
    if connect_options & 0x04 != 0 {
        parts.push("requires_crypt");
    }
    if parts.is_empty() {
        return format!("0x{connect_options:02X}");
    }
    format!("0x{connect_options:02X} ({})", parts.join("|"))
}

fn is_low_id(client_id: u32) -> bool {
    client_id < 0x0100_0000
}

#[cfg(test)]
mod tests {
    use super::{
        CT_EMULE_VERSION, CT_NAME, CT_SERVER_FLAGS, CT_VERSION, EDONKEY_VERSION,
        EMULE_ENCRYPTION_METHOD_OBFUSCATION, EMULE_TCP_CRYPT_MAGIC_REQUESTER,
        EMULE_TCP_CRYPT_MAGIC_SERVER, EMULE_TCP_CRYPT_MAGIC_SYNC, EMULE_VERSION_MAJOR,
        EMULE_VERSION_MINOR, EMULE_VERSION_UPDATE, Ed2kServerState, FT_FILENAME, HELLO_NICKNAME,
        OP_EDONKEYPROT, OP_GETSERVERLIST, OP_LOGINREQUEST, OP_PACKEDPROT,
        SERVER_OBFUSCATION_PRIME_BYTES, SERVER_OBFUSCATION_PUBLIC_KEY_LEN,
        SERVER_TCP_FLAG_COMPRESSION, SERVER_TCP_FLAG_LARGEFILES, ST_DESCRIPTION, ST_SERVERNAME,
        ServerSession, TAG_SHORT_NAME_MASK, TAGTYPE_UINT32, biguint_to_fixed_be,
        decode_search_results, decode_server_ident, decode_server_payload, derive_server_cipher,
        encode_login_request, encode_packet, encode_search_request, format_server_flags,
        server_capabilities, should_use_server_obfuscation,
    };
    use crate::ed2k_tcp::{Ed2kHelloIdentity, emule_connect_options};
    use flate2::{Compression, write::ZlibEncoder};
    use hex::decode;
    use num_bigint::BigUint;
    use std::{io::Write, net::Ipv4Addr, sync::Arc, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::RwLock,
    };

    #[test]
    fn login_request_matches_oracle_tag_shape() {
        let payload = encode_login_request(Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
        });
        let nickname_tag_header = [super::TAGTYPE_STRING, 0x01, 0x00, CT_NAME];
        let version_tag_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_VERSION];
        let server_flags_tag_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_SERVER_FLAGS];
        let emule_version_tag_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_VERSION];

        assert_eq!(&payload[..16], &[0x11; 16]);
        assert_eq!(u16::from_le_bytes([payload[20], payload[21]]), 41001);
        assert_eq!(
            u32::from_le_bytes([payload[22], payload[23], payload[24], payload[25]]),
            4
        );
        assert!(
            payload
                .windows(nickname_tag_header.len())
                .any(|window| window == nickname_tag_header)
        );
        assert!(
            payload
                .windows(version_tag_header.len())
                .any(|window| window == version_tag_header)
        );
        assert!(
            payload
                .windows(server_flags_tag_header.len())
                .any(|window| window == server_flags_tag_header)
        );
        assert!(
            payload
                .windows(emule_version_tag_header.len())
                .any(|window| window == emule_version_tag_header)
        );
        assert!(
            payload
                .windows(HELLO_NICKNAME.len())
                .any(|window| window == HELLO_NICKNAME.as_bytes())
        );
        assert!(
            payload
                .windows(4)
                .any(|window| window == EDONKEY_VERSION.to_le_bytes())
        );
        assert!(
            payload
                .windows(4)
                .any(|window| window
                    == server_capabilities(emule_connect_options(true)).to_le_bytes())
        );
        let version =
            (EMULE_VERSION_MAJOR << 17) | (EMULE_VERSION_MINOR << 10) | (EMULE_VERSION_UPDATE << 7);
        assert!(
            payload
                .windows(4)
                .any(|window| window == version.to_le_bytes())
        );
    }

    #[test]
    fn login_request_omits_crypt_flags_when_obfuscation_is_off() {
        let payload = encode_login_request(Ed2kHelloIdentity {
            user_hash: [0x22; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
        });

        assert!(payload.windows(4).any(
            |window| window == server_capabilities(emule_connect_options(false)).to_le_bytes()
        ));
        assert_eq!(
            server_capabilities(emule_connect_options(false)) & 0x0E00,
            0
        );
    }

    #[test]
    fn login_request_matches_oracle_plaintext_sample() {
        let packet = encode_packet(
            OP_LOGINREQUEST,
            &encode_login_request(Ed2kHelloIdentity {
                user_hash: [
                    0x73, 0xBE, 0xC5, 0x66, 0x14, 0x0E, 0x7E, 0x60, 0x83, 0xC4, 0x50, 0xC9, 0xAF,
                    0x02, 0x6F, 0x83,
                ],
                client_id: 0,
                tcp_port: 46671,
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
            }),
        );

        let expected = decode(
            "e3520000000173bec566140e7e6083c450c9af026f83000000004fb60400000002010001190068747470733a2f2f656d756c652d70726f6a6563742e6e6574030100113c0000000301002019010000030100fb80f10000",
        )
        .unwrap();

        assert_eq!(packet, expected);
    }

    #[test]
    fn login_request_matches_oracle_obfuscated_preference_sample() {
        let packet = encode_packet(
            OP_LOGINREQUEST,
            &encode_login_request(Ed2kHelloIdentity {
                user_hash: [
                    0x73, 0xBE, 0xC5, 0x66, 0x14, 0x0E, 0x7E, 0x60, 0x83, 0xC4, 0x50, 0xC9, 0xAF,
                    0x02, 0x6F, 0x83,
                ],
                client_id: 0,
                tcp_port: 46671,
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(true),
            }),
        );

        let expected = decode(
            "e3520000000173bec566140e7e6083c450c9af026f83000000004fb60400000002010001190068747470733a2f2f656d756c652d70726f6a6563742e6e6574030100113c0000000301002019070000030100fb80f10000",
        )
        .unwrap();

        assert_eq!(packet, expected);
    }

    #[test]
    fn metadata_poor_server_defaults_to_plaintext_even_if_client_supports_crypt() {
        assert!(!should_use_server_obfuscation(
            emule_connect_options(true),
            false
        ));
    }

    #[test]
    fn server_obfuscation_requires_positive_server_metadata() {
        assert!(should_use_server_obfuscation(
            emule_connect_options(true),
            true
        ));
    }

    #[test]
    fn packet_encoder_uses_ed2k_framing() {
        let packet = encode_packet(OP_GETSERVERLIST, &[]);
        assert_eq!(packet[0], 0xE3);
        assert_eq!(
            u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]),
            1
        );
        assert_eq!(packet[5], OP_GETSERVERLIST);
    }

    #[test]
    fn server_ident_parser_extracts_name_and_description() {
        let mut payload = vec![0u8; 22];
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 3));
        payload.push(ST_SERVERNAME);
        payload.extend_from_slice(b"test");
        payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 3));
        payload.push(ST_DESCRIPTION);
        payload.extend_from_slice(b"desc");

        let (name, description) = decode_server_ident(&payload).unwrap();

        assert_eq!(name.as_deref(), Some("test"));
        assert_eq!(description.as_deref(), Some("desc"));
    }

    #[test]
    fn server_ident_parser_skips_non_short_named_tags() {
        let mut payload = vec![0u8; 22];
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.push(TAGTYPE_UINT32);
        payload.extend_from_slice(&4u16.to_le_bytes());
        payload.extend_from_slice(b"misc");
        payload.extend_from_slice(&7u32.to_le_bytes());
        payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 3));
        payload.push(ST_SERVERNAME);
        payload.extend_from_slice(b"test");

        let (name, description) = decode_server_ident(&payload).unwrap();

        assert_eq!(name.as_deref(), Some("test"));
        assert_eq!(description, None);
    }

    #[test]
    fn server_state_reports_low_id_as_firewalled() {
        let mut state = Ed2kServerState::default();
        assert_eq!(state.tcp_firewalled(), None);
        state.client_id = Some(0x0000_1234);
        assert_eq!(state.tcp_firewalled(), Some(true));
        state.client_id = Some(0x7F00_0001);
        assert_eq!(state.tcp_firewalled(), Some(false));
    }

    #[test]
    fn packed_server_payload_is_inflated() {
        let plain_payload = b"oracle-server-payload";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain_payload).unwrap();
        let packed_payload = encoder.finish().unwrap();

        let decoded = decode_server_payload(OP_PACKEDPROT, packed_payload).unwrap();

        assert_eq!(decoded, plain_payload);
    }

    #[test]
    fn server_flag_formatter_lists_known_capabilities() {
        let text = format_server_flags(SERVER_TCP_FLAG_COMPRESSION | SERVER_TCP_FLAG_LARGEFILES);
        assert!(text.contains("compression"));
        assert!(text.contains("large_files"));
    }

    #[test]
    fn search_probe_encoding_matches_prefix_and_shape() {
        let payload = encode_search_request("ubuntu linux").unwrap();

        assert_eq!(payload[0], 0);
        assert_eq!(payload[1], 0);
        assert_eq!(payload[2], 1);
        assert_eq!(u16::from_le_bytes([payload[3], payload[4]]), 6);
        assert_eq!(&payload[5..11], b"ubuntu");
        assert_eq!(payload[11], 1);
        assert_eq!(u16::from_le_bytes([payload[12], payload[13]]), 5);
        assert_eq!(&payload[14..19], b"linux");
    }

    #[test]
    fn search_results_decoder_extracts_count_and_names() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&[0x11; 16]);
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&4662u16.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 9));
        payload.push(FT_FILENAME);
        payload.extend_from_slice(b"ubuntu.iso");

        let summary = decode_search_results(&payload).unwrap();

        assert_eq!(summary.count, 1);
        assert_eq!(summary.sample_names, vec!["ubuntu.iso".to_string()]);
    }

    #[tokio::test]
    async fn server_obfuscation_handshake_encrypts_login_request() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let hello_identity = Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
        };
        let expected_login = encode_packet(OP_LOGINREQUEST, &encode_login_request(hello_identity));
        let expected_login_for_server = expected_login.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut handshake_prefix = [0u8; 1 + SERVER_OBFUSCATION_PUBLIC_KEY_LEN + 1];
            stream.read_exact(&mut handshake_prefix).await.unwrap();
            assert!(!matches!(
                handshake_prefix[0],
                OP_EDONKEYPROT | super::OP_EMULEPROT | super::OP_PACKEDPROT
            ));
            let client_padding_len =
                usize::from(handshake_prefix[1 + SERVER_OBFUSCATION_PUBLIC_KEY_LEN]);
            let mut client_padding = vec![0u8; client_padding_len];
            stream.read_exact(&mut client_padding).await.unwrap();

            let client_public =
                BigUint::from_bytes_be(&handshake_prefix[1..1 + SERVER_OBFUSCATION_PUBLIC_KEY_LEN]);
            let prime = BigUint::from_bytes_be(&SERVER_OBFUSCATION_PRIME_BYTES);
            let generator = BigUint::from(2u8);
            let server_secret = BigUint::from_bytes_be(&[0x42; 16]);
            let server_public = biguint_to_fixed_be(
                &generator.modpow(&server_secret, &prime),
                SERVER_OBFUSCATION_PUBLIC_KEY_LEN,
            )
            .unwrap();
            let shared_secret = biguint_to_fixed_be(
                &client_public.modpow(&server_secret, &prime),
                SERVER_OBFUSCATION_PUBLIC_KEY_LEN,
            )
            .unwrap();
            let mut send_cipher =
                derive_server_cipher(&shared_secret, EMULE_TCP_CRYPT_MAGIC_SERVER);
            let mut receive_cipher =
                derive_server_cipher(&shared_secret, EMULE_TCP_CRYPT_MAGIC_REQUESTER);

            let mut server_reply = Vec::with_capacity(SERVER_OBFUSCATION_PUBLIC_KEY_LEN + 10);
            server_reply.extend_from_slice(&server_public);
            let mut encrypted_reply = Vec::with_capacity(10);
            encrypted_reply.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
            encrypted_reply.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
            encrypted_reply.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
            encrypted_reply.push(3);
            encrypted_reply.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
            send_cipher.apply(&mut encrypted_reply);
            server_reply.extend_from_slice(&encrypted_reply);
            stream.write_all(&server_reply).await.unwrap();

            let mut response_header = [0u8; 6];
            stream.read_exact(&mut response_header).await.unwrap();
            receive_cipher.apply(&mut response_header);
            assert_eq!(
                u32::from_le_bytes(response_header[..4].try_into().unwrap()),
                EMULE_TCP_CRYPT_MAGIC_SYNC
            );
            assert_eq!(response_header[4], EMULE_ENCRYPTION_METHOD_OBFUSCATION);
            let response_padding_len = usize::from(response_header[5]);

            let mut encrypted_tail =
                vec![0u8; response_padding_len + expected_login_for_server.len()];
            stream.read_exact(&mut encrypted_tail).await.unwrap();
            receive_cipher.apply(&mut encrypted_tail);
            assert_eq!(
                &encrypted_tail[response_padding_len..],
                expected_login_for_server.as_slice()
            );
        });

        let state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let mut session =
            ServerSession::connect(Ipv4Addr::LOCALHOST, endpoint, state, Duration::from_secs(5))
                .await
                .unwrap();
        session
            .negotiate_obfuscation_and_send(&expected_login)
            .await
            .unwrap();

        server.await.unwrap();
    }
}
