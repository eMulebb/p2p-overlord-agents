//! Minimal eD2k server session support used to obtain oracle-style HighID/LowID
//! feedback and keep the agent visible on the ED2K side of the network.
//!
//! This intentionally does not implement the full server feature set yet. The
//! current scope mirrors the parts of the oracle's `ServerConnect` and
//! `ServerSocket` flow that matter for parity today:
//! - connect from the VPN-bound interface to one configured ED2K server
//! - send an oracle-shaped `OP_LOGINREQUEST`
//! - advertise a minimal oracle-shaped shared-file catalog during the connected
//!   transition so the server sees a credible `OP_OFFERFILES`
//! - process `OP_IDCHANGE`, `OP_SERVERSTATUS`, and a few informational replies
//! - execute keyword searches with oracle-style query trees and `More` paging
//! - execute server source searches through the same long-lived TCP session
//! - keep the TCP session alive with empty `OP_OFFERFILES` packets

use std::{
    fs, io,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use chrono::SecondsFormat;
use flate2::read::ZlibDecoder;
use flate2::{Compression, write::ZlibEncoder};
use md5::compute as md5_compute;
use num_bigint::BigUint;
use rand::{Rng, RngCore};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream, UdpSocket, lookup_host},
    sync::{Mutex, RwLock, mpsc, oneshot},
    time::Instant as TokioInstant,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use overlord_agent_nat::NatManager;
use overlord_kad_proto::Ed2kHash;

use crate::{
    config::{Ed2kConfig, Ed2kServerEntry},
    ed2k_tcp::{Ed2kHelloIdentity, connect_callback_peer, enrich_hello_identity},
    ed2k_transfer::{Ed2kSharedCatalog, Ed2kSharedEntry},
    kad_firewall::KadFirewallState,
};

const OP_EDONKEYPROT: u8 = 0xE3;
const OP_EMULEPROT: u8 = 0xC5;
const OP_LOGINREQUEST: u8 = 0x01;
const OP_REJECT: u8 = 0x05;
const OP_GETSERVERLIST: u8 = 0x14;
const OP_OFFERFILES: u8 = 0x15;
const OP_SEARCHREQUEST: u8 = 0x16;
const OP_GETSOURCES: u8 = 0x19;
const OP_CALLBACKREQUEST: u8 = 0x1C;
const OP_GETSOURCES_OBFU: u8 = 0x23;
const OP_QUERY_MORE_RESULT: u8 = 0x21;
const OP_GLOBSEARCHREQ3: u8 = 0x90;
const OP_GLOBSEARCHREQ2: u8 = 0x92;
const OP_GLOBGETSOURCES2: u8 = 0x94;
const OP_GLOBSERVSTATREQ: u8 = 0x96;
const OP_GLOBSERVSTATRES: u8 = 0x97;
const OP_GLOBSEARCHREQ: u8 = 0x98;
const OP_GLOBSEARCHRES: u8 = 0x99;
const OP_GLOBGETSOURCES: u8 = 0x9A;
const OP_GLOBFOUNDSOURCES: u8 = 0x9B;
const OP_SERVERLIST: u8 = 0x32;
const OP_SEARCHRESULT: u8 = 0x33;
const OP_SERVERSTATUS: u8 = 0x34;
const OP_CALLBACKREQUESTED: u8 = 0x35;
const OP_CALLBACK_FAIL: u8 = 0x36;
const OP_SERVERMESSAGE: u8 = 0x38;
const OP_IDCHANGE: u8 = 0x40;
const OP_SERVERIDENT: u8 = 0x41;
const OP_FOUNDSOURCES: u8 = 0x42;
const OP_FOUNDSOURCES_OBFU: u8 = 0x44;
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
const CT_SERVER_UDPSEARCH_FLAGS: u8 = 0x0E;
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
const SRVCAP_UDP_NEWTAGS_LARGEFILES: u32 = 0x0001;

const SERVER_TCP_FLAG_COMPRESSION: u32 = 0x0000_0001;
const SERVER_TCP_FLAG_NEWTAGS: u32 = 0x0000_0008;
const SERVER_TCP_FLAG_UNICODE: u32 = 0x0000_0010;
const SERVER_TCP_FLAG_RELATEDSEARCH: u32 = 0x0000_0040;
const SERVER_TCP_FLAG_TYPETAGINTEGER: u32 = 0x0000_0080;
const SERVER_TCP_FLAG_LARGEFILES: u32 = 0x0000_0100;
const SERVER_TCP_FLAG_TCPOBFUSCATION: u32 = 0x0000_0400;
const SERVER_UDP_FLAG_EXT_GETSOURCES: u32 = 0x0000_0001;
const SERVER_UDP_FLAG_EXT_GETFILES: u32 = 0x0000_0002;
const SERVER_UDP_FLAG_EXT_GETSOURCES2: u32 = 0x0000_0020;
const SERVER_UDP_FLAG_LARGEFILES: u32 = 0x0000_0100;
const SERVER_UDP_FLAG_UDPOBFUSCATION: u32 = 0x0000_0200;
const SERVER_UDP_FLAG_TCPOBFUSCATION: u32 = 0x0000_0400;

const ST_SERVERNAME: u8 = 0x01;
const ST_DESCRIPTION: u8 = 0x0B;
const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
const FT_FILETYPE: u8 = 0x03;
const FT_SOURCES: u8 = 0x15;
const FT_FILESIZE_HI: u8 = 0x3A;
const ED2K_FILETYPE_PROGRAM: u8 = 0x04;
const ED2K_FILETYPE_DOCUMENT: u8 = 0x05;
const ED2K_FILETYPE_ARCHIVE: u8 = 0x06;
const ED2K_FILETYPE_AUDIO: u8 = 0x07;
const ED2K_FILETYPE_VIDEO: u8 = 0x08;

const OFFER_FILE_COMPLETE_SENTINEL_CLIENT_ID: u32 = 0xFBFB_FBFB;
const OFFER_FILE_COMPLETE_SENTINEL_CLIENT_PORT: u16 = 0xFBFB;
const OFFER_FILE_SAMPLE_HASH: [u8; 16] = [
    0x9F, 0x3C, 0x23, 0xDB, 0x76, 0x51, 0xEF, 0xBA, 0xC9, 0xA8, 0x37, 0xA8, 0xA0, 0xAE, 0x3E, 0xD9,
];
const OFFER_FILE_SAMPLE_NAME: &str = "ubuntu-linux-oracle-sample.iso";
const OFFER_FILE_SAMPLE_SIZE: u32 = 0x0020_0000;
const OFFER_FILE_SEARCH_SETTLE_DELAY: Duration = Duration::from_millis(80);
static NEXT_SERVER_SESSION_TRACE_ID: AtomicU64 = AtomicU64::new(1);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerSessionPhase {
    Connecting,
    AwaitingIdChange,
    Connected,
    OfferFilesSent,
    SearchActive,
    AwaitingMore,
    Completed,
}

impl ServerSessionPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::AwaitingIdChange => "awaiting_idchange",
            Self::Connected => "connected",
            Self::OfferFilesSent => "offer_files_sent",
            Self::SearchActive => "search_active",
            Self::AwaitingMore => "awaiting_more",
            Self::Completed => "completed",
        }
    }
}

#[derive(Debug)]
struct ServerSession {
    stream: TcpStream,
    endpoint: SocketAddr,
    state: Arc<RwLock<Ed2kServerState>>,
    trace_id: u64,
    trace_role: &'static str,
    last_tx: Instant,
    receive_cipher: Option<Rc4KeyStream>,
    send_cipher: Option<Rc4KeyStream>,
    login_accepted: bool,
    probe_search_sent: bool,
    offer_files_sent: bool,
    offer_files_sent_at: Option<Instant>,
    assigned_client_id: Option<u32>,
    server_flags: Option<u32>,
    server_list_requested: bool,
    phase: ServerSessionPhase,
}

#[derive(Clone)]
struct ServerSessionContext {
    bind_ip: Ipv4Addr,
    nat: Arc<NatManager>,
    hello_identity: Ed2kHelloIdentity,
    probe_search_term: Option<String>,
    shared_catalog: Ed2kSharedCatalog,
    state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    keepalive_interval: Duration,
    connect_timeout: Duration,
    rotation_interval: Option<Duration>,
    shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfiguredServerEntry {
    host: String,
    port: u16,
    name: Option<String>,
    description: Option<String>,
    udp_flags: u32,
    udp_key: u32,
    udp_key_ip: u32,
    obfuscation_port_tcp: u16,
    obfuscation_port_udp: u16,
}

impl ConfiguredServerEntry {
    fn from_endpoint_text(endpoint_text: &str) -> Result<Self> {
        let endpoint = endpoint_text
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid ED2K server endpoint {endpoint_text}"))?;
        Ok(Self {
            host: endpoint.ip().to_string(),
            port: endpoint.port(),
            name: None,
            description: None,
            udp_flags: 0,
            udp_key: 0,
            udp_key_ip: 0,
            obfuscation_port_tcp: 0,
            obfuscation_port_udp: 0,
        })
    }

    fn from_metadata(entry: &Ed2kServerEntry) -> Result<Self> {
        if entry.host.trim().is_empty() || entry.port == 0 {
            anyhow::bail!("ED2K server entry requires a non-empty host and non-zero port");
        }
        Ok(Self {
            host: entry.host.clone(),
            port: entry.port,
            name: entry.name.clone(),
            description: entry.description.clone(),
            udp_flags: entry.udp_flags,
            udp_key: entry.udp_key,
            udp_key_ip: entry.udp_key_ip,
            obfuscation_port_tcp: entry.obfuscation_port_tcp,
            obfuscation_port_udp: entry.obfuscation_port_udp,
        })
    }

    fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or("-")
    }

    fn base_endpoint_text(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn supports_obfuscation_tcp(&self) -> bool {
        self.obfuscation_port_tcp != 0
            && (self.udp_flags & (SERVER_UDP_FLAG_UDPOBFUSCATION | SERVER_UDP_FLAG_TCPOBFUSCATION))
                != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedServerEntry {
    entry: ConfiguredServerEntry,
    ip: Ipv4Addr,
}

impl ResolvedServerEntry {
    fn base_endpoint(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.ip), self.entry.port)
    }

    fn transport_endpoint(&self, use_obfuscation: bool) -> SocketAddr {
        let chosen_port = if use_obfuscation && self.entry.obfuscation_port_tcp != 0 {
            self.entry.obfuscation_port_tcp
        } else {
            self.entry.port
        };
        SocketAddr::new(IpAddr::V4(self.ip), chosen_port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CallbackRequest {
    peer_addr: SocketAddr,
    connect_options: Option<u8>,
    user_hash: Option<[u8; 16]>,
}

#[derive(Debug)]
struct ServerUdpPacket {
    opcode: u8,
    payload: Vec<u8>,
    from: SocketAddr,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SearchResultSummary {
    count: u32,
    sample_names: Vec<String>,
}

/// One decoded ED2K server search result entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kSearchFile {
    /// File hash reported by the ED2K server.
    pub file_hash: Ed2kHash,
    /// File name tag, when present.
    pub file_name: Option<String>,
    /// File size tag, when present.
    pub file_size: Option<u64>,
    /// ED2K file-type tag, when present.
    pub file_type: Option<String>,
    /// Server-reported source availability, when present.
    pub source_count: Option<u32>,
}

/// One decoded ED2K server source-search entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kFoundSource {
    /// File hash referenced by the source reply.
    pub file_hash: Ed2kHash,
    /// Source IPv4 address reported by the ED2K server when the source is a
    /// direct-dial HighID peer. For LowID peers this is the server-reported
    /// client-id rendered as IPv4, which is not directly dialable.
    pub ip: Ipv4Addr,
    /// Source TCP port reported by the ED2K server.
    pub tcp_port: u16,
    /// Raw client-id token reported by the ED2K server.
    pub client_id: u32,
    /// Whether the server source entry refers to a LowID peer that requires a
    /// callback path instead of direct TCP dialing.
    pub low_id: bool,
    /// Whether the server used the obfuscated `OP_FOUNDSOURCES_OBFU` family.
    pub obfuscated: bool,
    /// Optional per-source obfuscation settings byte from the oracle wire shape.
    pub obfuscation_options: Option<u8>,
    /// Optional user hash present when the source advertises it in the obfuscated shape.
    pub user_hash: Option<[u8; 16]>,
    /// ED2K server endpoint that reported this source, when known.
    pub source_server: Option<SocketAddr>,
}

impl Ed2kFoundSource {
    /// Returns `true` when this source can be dialed directly over TCP.
    #[must_use]
    pub fn is_direct_dialable(&self) -> bool {
        !self.low_id
    }
}

type BackgroundKeywordSearchResponse = std::result::Result<Vec<Ed2kSearchFile>, String>;
type BackgroundSourceSearchResponse = std::result::Result<Vec<Ed2kFoundSource>, String>;
type BackgroundCallbackRequestResponse = std::result::Result<(), String>;

/// Handle used by active jobs to execute a keyword search through the
/// long-lived ED2K background session.
#[derive(Clone)]
pub struct Ed2kServerSearchHandle {
    sender: mpsc::Sender<BackgroundServerSearchRequest>,
}

/// Inbox owned by the long-lived ED2K background server task.
pub struct Ed2kServerSearchInbox {
    receiver: mpsc::Receiver<BackgroundServerSearchRequest>,
}

#[derive(Debug)]
enum BackgroundServerSearchRequest {
    Keyword {
        query: String,
        timeout: Duration,
        response: oneshot::Sender<BackgroundKeywordSearchResponse>,
    },
    Source {
        file_hash: Ed2kHash,
        file_size: u64,
        timeout: Duration,
        response: oneshot::Sender<BackgroundSourceSearchResponse>,
    },
    Callback {
        client_id: u32,
        response: oneshot::Sender<BackgroundCallbackRequestResponse>,
    },
}

#[derive(Debug)]
enum PendingBackgroundServerSearch {
    Keyword {
        query: String,
        deadline: TokioInstant,
        results: Vec<Ed2kSearchFile>,
        page_count: u32,
        response: oneshot::Sender<BackgroundKeywordSearchResponse>,
    },
    Source {
        file_hash: Ed2kHash,
        deadline: TokioInstant,
        response: oneshot::Sender<BackgroundSourceSearchResponse>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SearchResultPage {
    files: Vec<Ed2kSearchFile>,
    more_results_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SearchExprNode {
    Term(String),
    And(Box<SearchExprNode>, Box<SearchExprNode>),
    Or(Box<SearchExprNode>, Box<SearchExprNode>),
    Not(Box<SearchExprNode>, Box<SearchExprNode>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SearchToken {
    Term(String),
    And,
    Or,
    Not,
    OpenParen,
    CloseParen,
}

#[derive(Debug, Serialize)]
struct Ed2kServerDumpRecord<'a> {
    schema: &'static str,
    source: &'static str,
    ts_utc: String,
    event_seq: u64,
    trace_id: u64,
    trace_key: String,
    state_id: String,
    state_label: &'a str,
    role: &'a str,
    phase: &'a str,
    direction: &'a str,
    endpoint: String,
    transport: &'a str,
    opcode: Option<String>,
    opcode_name: Option<&'static str>,
    payload_len: Option<usize>,
    payload_hex: Option<String>,
    note: Option<String>,
}

fn next_ed2k_server_dump_event_seq() -> u64 {
    static NEXT_EVENT_SEQ: AtomicU64 = AtomicU64::new(1);
    NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed)
}

fn ed2k_server_trace_key(session: &ServerSession) -> String {
    format!(
        "server:{}:{}:{}",
        session.trace_role, session.trace_id, session.endpoint
    )
}

fn ed2k_server_state_id(session: &ServerSession) -> String {
    format!("server.{}.{}", session.trace_role, session.phase.as_str())
}

/// Creates a bounded request channel for background-session ED2K server searches.
#[must_use]
pub fn new_ed2k_server_search_channel(
    capacity: usize,
) -> (Ed2kServerSearchHandle, Ed2kServerSearchInbox) {
    let (sender, receiver) = mpsc::channel(capacity.max(1));
    (
        Ed2kServerSearchHandle { sender },
        Ed2kServerSearchInbox { receiver },
    )
}

/// Requests a keyword search on the already-connected ED2K background session.
///
/// This keeps active jobs on the same server TCP session shape as the oracle
/// whenever that long-lived session is healthy.
pub async fn search_keyword_via_background_session(
    handle: &Ed2kServerSearchHandle,
    query: &str,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<Ed2kSearchFile>> {
    let (response, receive_response) = oneshot::channel();
    handle
        .sender
        .send(BackgroundServerSearchRequest::Keyword {
            query: query.to_string(),
            timeout,
            response,
        })
        .await
        .context("ED2K background search channel is closed")?;

    tokio::select! {
        _ = cancel.cancelled() => Ok(Vec::new()),
        result = tokio::time::timeout(timeout, receive_response) => {
            let response = result
                .with_context(|| format!("timed out waiting for ED2K background search response after {timeout:?}"))?
                .context("ED2K background search responder dropped")?;
            response.map_err(anyhow::Error::msg)
        }
    }
}

/// Requests a source search on the already-connected ED2K background session.
///
/// This keeps active source lookups on the same server TCP session shape as the
/// oracle whenever that long-lived session is healthy.
pub async fn search_source_via_background_session(
    handle: &Ed2kServerSearchHandle,
    file_hash: Ed2kHash,
    file_size: u64,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<Ed2kFoundSource>> {
    let (response, receive_response) = oneshot::channel();
    handle
        .sender
        .send(BackgroundServerSearchRequest::Source {
            file_hash,
            file_size,
            timeout,
            response,
        })
        .await
        .context("ED2K background search channel is closed")?;

    tokio::select! {
        _ = cancel.cancelled() => Ok(Vec::new()),
        result = tokio::time::timeout(timeout, receive_response) => {
            let response = result
                .with_context(|| format!("timed out waiting for ED2K background source response after {timeout:?}"))?
                .context("ED2K background source responder dropped")?;
            response.map_err(anyhow::Error::msg)
        }
    }
}

/// Requests an ED2K server callback for a LowID peer on the current
/// background server session.
pub async fn request_callback_via_background_session(
    handle: &Ed2kServerSearchHandle,
    client_id: u32,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<()> {
    let (response, receive_response) = oneshot::channel();
    handle
        .sender
        .send(BackgroundServerSearchRequest::Callback {
            client_id,
            response,
        })
        .await
        .context("ED2K background callback channel is closed")?;

    tokio::select! {
        _ = cancel.cancelled() => Ok(()),
        result = tokio::time::timeout(timeout, receive_response) => {
            let response = result
                .with_context(|| format!("timed out waiting for ED2K background callback response after {timeout:?}"))?
                .context("ED2K background callback responder dropped")?;
            response.map_err(anyhow::Error::msg)
        }
    }
}

/// Requests an ED2K server callback for a LowID peer on one explicit server.
///
/// This keeps callback routing aligned with the server that reported the
/// callback-only source whenever that provenance is available.
#[allow(clippy::too_many_arguments)]
pub async fn request_callback_on_server(
    bind_ip: Ipv4Addr,
    config: &Ed2kConfig,
    hello_identity: Ed2kHelloIdentity,
    shared_catalog: &[Ed2kSharedEntry],
    server_endpoint: SocketAddr,
    client_id: u32,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<()> {
    let resolved_server = resolve_callback_server_entry(config, server_endpoint).await?;
    let use_server_obfuscation =
        should_use_server_obfuscation(hello_identity.connect_options, &resolved_server);
    let login_identity =
        login_identity_for_server_transport(hello_identity, use_server_obfuscation);
    let transport_endpoint = resolved_server.transport_endpoint(use_server_obfuscation);
    let mut session = ServerSession::connect(
        bind_ip,
        transport_endpoint,
        Arc::new(RwLock::new(Ed2kServerState::default())),
        "active_callback",
        timeout,
    )
    .await?;
    let login_payload = encode_login_request(login_identity);
    if use_server_obfuscation {
        let login_request = encode_packet(OP_LOGINREQUEST, &login_payload, false)?;
        session
            .negotiate_obfuscation_and_send(&login_request)
            .await?;
    } else {
        session.send_packet(OP_LOGINREQUEST, &login_payload).await?;
    }
    session.set_phase(
        ServerSessionPhase::AwaitingIdChange,
        "login request sent; awaiting OP_IDCHANGE for callback request",
    );
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        let packet = tokio::time::timeout(timeout, session.read_packet())
            .await
            .with_context(|| {
                format!("timed out waiting for ED2K callback-ready login on {transport_endpoint}")
            })??;
        let Some(packet) = packet else {
            anyhow::bail!("ED2K server {transport_endpoint} closed before callback dispatch");
        };
        match packet.opcode {
            OP_IDCHANGE => {
                if packet.payload.len() < 4 {
                    anyhow::bail!("short OP_IDCHANGE payload from {transport_endpoint}");
                }
                session.assigned_client_id =
                    Some(u32::from_le_bytes(packet.payload[..4].try_into().unwrap()));
                session.server_flags = (packet.payload.len() >= 8)
                    .then(|| u32::from_le_bytes(packet.payload[4..8].try_into().unwrap()));
                send_connected_server_startup(
                    &mut session,
                    &Arc::new(RwLock::new(shared_catalog.to_vec())),
                    hello_identity.tcp_port,
                )
                .await?;
                wait_for_offer_files_settle(&mut session).await;
                session.set_phase(
                    ServerSessionPhase::SearchActive,
                    format!("dispatching callback request client_id={client_id}"),
                );
                session
                    .send_packet(OP_CALLBACKREQUEST, &client_id.to_le_bytes())
                    .await?;
                info!(
                    "sent ED2K targeted callback request client_id={} endpoint={} trace_id={} transport={}",
                    client_id,
                    session.endpoint,
                    session.trace_id,
                    if use_server_obfuscation {
                        "obfuscated"
                    } else {
                        "plaintext"
                    }
                );
                session.set_phase(
                    ServerSessionPhase::Completed,
                    format!("completed callback request client_id={client_id}"),
                );
                return Ok(());
            }
            OP_REJECT => {
                anyhow::bail!("ED2K server {transport_endpoint} rejected the callback request");
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum DecodedTagValue {
    String(String),
    Unsigned(u64),
    Bool(bool),
    Float32(f32),
    Hash([u8; 16]),
    Blob(Vec<u8>),
    BoolArray(Vec<u8>),
}

/// Returns whether the agent should start an ED2K server session with TCP
/// obfuscation.
///
/// The oracle only chooses an obfuscated server TCP connect when the server
/// advertises the needed metadata, primarily `ST_TCPPORTOBFUSCATION` plus the
/// UDP capability bits which signal TCP obfuscation support.
fn should_use_server_obfuscation(connect_options: u8, server: &ResolvedServerEntry) -> bool {
    connect_options != 0 && server.entry.supports_obfuscation_tcp()
}

fn ed2k_server_dump_file() -> &'static StdMutex<Option<fs::File>> {
    static DUMP_FILE: OnceLock<StdMutex<Option<fs::File>>> = OnceLock::new();
    DUMP_FILE.get_or_init(|| {
        let file = std::env::var("OVERLORD_LOG_DIR")
            .ok()
            .map(std::path::PathBuf::from)
            .and_then(|dir| {
                fs::create_dir_all(&dir).ok()?;
                let path = dir.join(format!(
                    "agent-ed2k-server-dump-{}.jsonl",
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

fn dump_ed2k_server_record(record: &Ed2kServerDumpRecord<'_>) {
    let Ok(line) = serde_json::to_string(record) else {
        return;
    };
    let Ok(mut guard) = ed2k_server_dump_file().lock() else {
        return;
    };
    let Some(file) = guard.as_mut() else {
        return;
    };
    let _ = std::io::Write::write_all(file, line.as_bytes());
    let _ = std::io::Write::write_all(file, b"\n");
}

fn dump_ed2k_server_meta(session: &ServerSession, note: impl Into<String>) {
    let record = Ed2kServerDumpRecord {
        schema: "ed2k_server_session_v1",
        source: "agent",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: next_ed2k_server_dump_event_seq(),
        trace_id: session.trace_id,
        trace_key: ed2k_server_trace_key(session),
        state_id: ed2k_server_state_id(session),
        state_label: session.phase.as_str(),
        role: session.trace_role,
        phase: session.phase.as_str(),
        direction: "meta",
        endpoint: session.endpoint.to_string(),
        transport: if session.send_cipher.is_some() {
            "obfuscated"
        } else {
            "plaintext"
        },
        opcode: None,
        opcode_name: None,
        payload_len: None,
        payload_hex: None,
        note: Some(note.into()),
    };
    dump_ed2k_server_record(&record);
}

fn dump_ed2k_server_packet(
    session: &ServerSession,
    direction: &'static str,
    opcode: u8,
    payload: &[u8],
) {
    let record = Ed2kServerDumpRecord {
        schema: "ed2k_server_session_v1",
        source: "agent",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: next_ed2k_server_dump_event_seq(),
        trace_id: session.trace_id,
        trace_key: ed2k_server_trace_key(session),
        state_id: ed2k_server_state_id(session),
        state_label: session.phase.as_str(),
        role: session.trace_role,
        phase: session.phase.as_str(),
        direction,
        endpoint: session.endpoint.to_string(),
        transport: if session.send_cipher.is_some() {
            "obfuscated"
        } else {
            "plaintext"
        },
        opcode: Some(format!("0x{opcode:02X}")),
        opcode_name: Some(server_opcode_name(opcode)),
        payload_len: Some(payload.len()),
        payload_hex: Some(hex::encode(payload)),
        note: None,
    };
    dump_ed2k_server_record(&record);
}

fn server_opcode_name(opcode: u8) -> &'static str {
    match opcode {
        OP_LOGINREQUEST => "OP_LOGINREQUEST",
        OP_GETSERVERLIST => "OP_GETSERVERLIST",
        OP_OFFERFILES => "OP_OFFERFILES",
        OP_SEARCHREQUEST => "OP_SEARCHREQUEST",
        OP_GETSOURCES => "OP_GETSOURCES",
        OP_GETSOURCES_OBFU => "OP_GETSOURCES_OBFU",
        OP_QUERY_MORE_RESULT => "OP_QUERY_MORE_RESULT",
        OP_SERVERLIST => "OP_SERVERLIST",
        OP_SEARCHRESULT => "OP_SEARCHRESULT",
        OP_SERVERSTATUS => "OP_SERVERSTATUS",
        OP_CALLBACKREQUESTED => "OP_CALLBACKREQUESTED",
        OP_CALLBACK_FAIL => "OP_CALLBACK_FAIL",
        OP_SERVERMESSAGE => "OP_SERVERMESSAGE",
        OP_IDCHANGE => "OP_IDCHANGE",
        OP_SERVERIDENT => "OP_SERVERIDENT",
        OP_FOUNDSOURCES => "OP_FOUNDSOURCES",
        OP_FOUNDSOURCES_OBFU => "OP_FOUNDSOURCES_OBFU",
        OP_REJECT => "OP_REJECT",
        _ => "UNKNOWN",
    }
}

impl ServerSession {
    async fn connect(
        bind_ip: Ipv4Addr,
        endpoint: SocketAddr,
        state: Arc<RwLock<Ed2kServerState>>,
        trace_role: &'static str,
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
        let trace_id = NEXT_SERVER_SESSION_TRACE_ID.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            stream,
            endpoint,
            state,
            trace_id,
            trace_role,
            last_tx: Instant::now(),
            receive_cipher: None,
            send_cipher: None,
            login_accepted: false,
            probe_search_sent: false,
            offer_files_sent: false,
            offer_files_sent_at: None,
            assigned_client_id: None,
            server_flags: None,
            server_list_requested: false,
            phase: ServerSessionPhase::Connecting,
        })
    }

    fn set_phase(&mut self, phase: ServerSessionPhase, note: impl Into<String>) {
        self.phase = phase;
        dump_ed2k_server_meta(self, note);
    }

    async fn send_packet(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        let use_compression = self.server_supports_compression();
        let mut packet = encode_packet(opcode, payload, use_compression)?;
        debug!(
            "ED2K trace id={} role={} phase={} dir=tx endpoint={} opcode=0x{:02X} payload_len={} wire_len={} compressed={}",
            self.trace_id,
            self.trace_role,
            self.phase.as_str(),
            self.endpoint,
            opcode,
            payload.len(),
            packet.len(),
            use_compression
        );
        dump_ed2k_server_packet(self, "tx", opcode, payload);
        if let Some(cipher) = self.send_cipher.as_mut() {
            cipher.apply(&mut packet);
        }
        self.stream.write_all(&packet).await.with_context(|| {
            format!("failed to send opcode=0x{opcode:02X} to {}", self.endpoint)
        })?;
        self.last_tx = Instant::now();
        Ok(())
    }

    fn server_supports_compression(&self) -> bool {
        self.server_flags.unwrap_or_default() & SERVER_TCP_FLAG_COMPRESSION != 0
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
        dump_ed2k_server_meta(self, "server obfuscation negotiated");
        Ok(())
    }

    async fn read_packet(&mut self) -> Result<Option<Ed2kPacket>> {
        let mut header = [0u8; TCP_PACKET_HEADER_LEN];
        match self.stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                debug!(
                    "ED2K trace id={} role={} phase={} dir=rx endpoint={} eof=true",
                    self.trace_id,
                    self.trace_role,
                    self.phase.as_str(),
                    self.endpoint
                );
                dump_ed2k_server_meta(self, "server socket reached eof");
                return Ok(None);
            }
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
        debug!(
            "ED2K trace id={} role={} phase={} dir=rx endpoint={} prot=0x{:02X} opcode=0x{:02X} payload_len={}",
            self.trace_id,
            self.trace_role,
            self.phase.as_str(),
            self.endpoint,
            header[0],
            header[5],
            payload.len()
        );
        dump_ed2k_server_packet(self, "rx", header[5], &payload);
        Ok(Some(Ed2kPacket {
            opcode: header[5],
            payload,
        }))
    }
}

/// Runs the minimal oracle-shaped ED2K server session loop for the configured endpoints.
#[allow(clippy::too_many_arguments)]
pub async fn run_ed2k_server_loop(
    bind_ip: Ipv4Addr,
    nat: Arc<NatManager>,
    config: Ed2kConfig,
    hello_identity: Ed2kHelloIdentity,
    shared_catalog: Ed2kSharedCatalog,
    state: Arc<RwLock<Ed2kServerState>>,
    mut search_inbox: Ed2kServerSearchInbox,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    shutdown: Arc<AtomicBool>,
) {
    let reconnect_delay = Duration::from_secs(config.reconnect_interval_secs.max(1));
    let session_context = ServerSessionContext {
        bind_ip,
        nat,
        hello_identity,
        probe_search_term: config.probe_search_term.clone(),
        shared_catalog,
        state: Arc::clone(&state),
        kad_firewall,
        keepalive_interval: Duration::from_secs(config.keepalive_secs.max(1)),
        connect_timeout: Duration::from_secs(config.connect_timeout_secs.max(1)),
        rotation_interval: (config.session_rotation_secs > 0)
            .then(|| Duration::from_secs(config.session_rotation_secs)),
        shutdown: Arc::clone(&shutdown),
    };

    let configured_servers = match configured_server_entries(&config) {
        Ok(entries) => entries,
        Err(error) => {
            warn!("ED2K server session disabled: invalid server configuration: {error}");
            return;
        }
    };
    if configured_servers.is_empty() {
        info!(
            "ED2K server session disabled: no p2p.ed2k.server_entries or p2p.ed2k.server_endpoints configured"
        );
        return;
    }

    while !shutdown.load(Ordering::Relaxed) {
        let mut attempted_any = false;
        for configured_server in &configured_servers {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            attempted_any = true;
            match resolve_server_entry(configured_server).await {
                Ok(server) => {
                    if let Err(error) =
                        run_one_server_session(&server, &session_context, &mut search_inbox).await
                    {
                        clear_server_connection_state(&state).await;
                        warn!(
                            "ED2K server session ended for {} name={}: {error}",
                            server.base_endpoint(),
                            server.entry.display_name()
                        );
                    }
                }
                Err(error) => {
                    warn!(
                        "failed to resolve ED2K server endpoint {} name={}: {error}",
                        configured_server.base_endpoint_text(),
                        configured_server.display_name()
                    );
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
    server: &ResolvedServerEntry,
    context: &ServerSessionContext,
    search_inbox: &mut Ed2kServerSearchInbox,
) -> Result<()> {
    let use_server_obfuscation =
        should_use_server_obfuscation(context.hello_identity.connect_options, server);
    let login_identity =
        login_identity_for_server_transport(context.hello_identity, use_server_obfuscation);
    let transport_endpoint = server.transport_endpoint(use_server_obfuscation);
    let mut session = ServerSession::connect(
        context.bind_ip,
        transport_endpoint,
        Arc::clone(&context.state),
        "background",
        context.connect_timeout,
    )
    .await?;
    let server_udp_socket = match bind_server_udp_socket(context.bind_ip).await {
        Ok(socket) => {
            info!(
                "bound ED2K server UDP helper local={} remote={} trace_id={}",
                socket.local_addr()?,
                server_udp_endpoint(server),
                session.trace_id
            );
            Some(socket)
        }
        Err(error) => {
            warn!(
                "failed to bind ED2K server UDP helper for {}: {error}",
                server.base_endpoint()
            );
            None
        }
    };
    {
        let mut guard = context.state.write().await;
        guard.endpoint = Some(server.base_endpoint());
        guard.connected = false;
        guard.client_id = None;
        guard.server_flags = None;
    }

    let nat_status = context.nat.status().await;
    let observed_external_ip = nat_status.observed_external_addresses.first().cloned();
    let login_payload = encode_login_request(login_identity);
    info!(
        "connected to ED2K server {} name={} trace_id={} role=background bind_ip={} observed_external_ip={} transport={} connect_options={} supports_obf_tcp={} obf_port={} udp_flags=0x{:08X} udp_key_present={} chosen_port={}",
        server.base_endpoint(),
        server.entry.display_name(),
        session.trace_id,
        context.bind_ip,
        observed_external_ip.as_deref().unwrap_or("unknown"),
        if use_server_obfuscation {
            "obfuscated"
        } else {
            "plaintext"
        },
        format_connect_options(login_identity.connect_options),
        server.entry.supports_obfuscation_tcp(),
        server.entry.obfuscation_port_tcp,
        server.entry.udp_flags,
        server.entry.udp_key != 0,
        transport_endpoint.port(),
    );
    if use_server_obfuscation {
        let login_request = encode_packet(OP_LOGINREQUEST, &login_payload, false)?;
        session
            .negotiate_obfuscation_and_send(&login_request)
            .await?;
    } else {
        session.send_packet(OP_LOGINREQUEST, &login_payload).await?;
    }
    session.set_phase(
        ServerSessionPhase::AwaitingIdChange,
        "login request sent; awaiting OP_IDCHANGE",
    );

    let rotation_deadline = context
        .rotation_interval
        .map(|interval| TokioInstant::now() + interval);
    let mut queued_background_search = None;
    let mut pending_background_search = None;

    loop {
        if context.shutdown.load(Ordering::Relaxed) {
            fail_background_search_request(
                &mut queued_background_search,
                "ED2K background session is shutting down before search dispatch",
            );
            fail_pending_background_search(
                &mut pending_background_search,
                "ED2K background session is shutting down before search completion",
            );
            clear_server_connection_state(&context.state).await;
            return Ok(());
        }

        tokio::select! {
            _ = async {
                if let Some(deadline) = rotation_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                fail_background_search_request(
                    &mut queued_background_search,
                    "ED2K background session rotated before search dispatch",
                );
                fail_pending_background_search(
                    &mut pending_background_search,
                    "ED2K background session rotated before search completion",
                );
                info!(
                    "rotating ED2K server session from {} after {:?}",
                    server.base_endpoint(),
                    context.rotation_interval.expect("rotation interval is set"),
                );
                clear_server_connection_state(&context.state).await;
                return Ok(());
            }
            request = search_inbox.receiver.recv(), if queued_background_search.is_none() && pending_background_search.is_none() => {
                if let Some(request) = request {
                    if session.login_accepted {
                        match start_background_server_search(
                            &mut session,
                            server,
                            server_udp_socket.as_ref(),
                            context.hello_identity.connect_options,
                            request,
                        )
                        .await
                        {
                            Ok(pending) => pending_background_search = pending,
                            Err(error) => warn!("failed to start ED2K background server search on {}: {error}", server.base_endpoint()),
                        }
                    } else {
                        match &request {
                            BackgroundServerSearchRequest::Keyword { query, .. } => info!(
                                "queued ED2K background keyword search query={query:?} endpoint={} trace_id={} awaiting login",
                                session.endpoint,
                                session.trace_id
                            ),
                            BackgroundServerSearchRequest::Source { file_hash, .. } => info!(
                                "queued ED2K background source search file_hash={} endpoint={} trace_id={} awaiting login",
                                file_hash,
                                session.endpoint,
                                session.trace_id
                            ),
                            BackgroundServerSearchRequest::Callback { client_id, .. } => info!(
                                "queued ED2K background callback request client_id={} endpoint={} trace_id={} awaiting login",
                                client_id,
                                session.endpoint,
                                session.trace_id
                            ),
                        }
                        queued_background_search = Some(request);
                    }
                }
            }
            _ = async {
                if let Some(pending) = pending_background_search.as_ref() {
                    let deadline = match pending {
                        PendingBackgroundServerSearch::Keyword { deadline, .. }
                        | PendingBackgroundServerSearch::Source { deadline, .. } => *deadline,
                    };
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if pending_background_search.is_some() => {
                let timeout_error = match pending_background_search.as_ref() {
                    Some(PendingBackgroundServerSearch::Keyword { .. }) => {
                        "ED2K background session search timed out waiting for OP_SEARCHRESULT"
                    }
                    Some(PendingBackgroundServerSearch::Source { .. }) => {
                        "ED2K background session search timed out waiting for OP_FOUNDSOURCES"
                    }
                    None => unreachable!("pending background search timeout without search"),
                };
                fail_pending_background_search(&mut pending_background_search, timeout_error);
            }
            packet = session.read_packet() => {
                let Some(packet) = packet? else {
                    let closed_error = format!(
                        "ED2K server {} closed the connection",
                        server.base_endpoint()
                    );
                    fail_background_search_request(
                        &mut queued_background_search,
                        &format!("{closed_error} before search dispatch"),
                    );
                    fail_pending_background_search(
                        &mut pending_background_search,
                        &format!("{closed_error} before search completion"),
                    );
                    anyhow::bail!(
                        "{closed_error}"
                    );
                };
                if let Some(pending) = pending_background_search.take() {
                    match (packet.opcode, pending) {
                        (OP_SEARCHRESULT, PendingBackgroundServerSearch::Keyword {
                            query,
                            deadline,
                            mut results,
                            mut page_count,
                            response,
                        }) => {
                            let page = decode_search_result_page(&packet.payload)?;
                            log_search_result_page(session.endpoint, &page.files);
                            page_count += 1;
                            results.extend(page.files);
                            if page.more_results_available {
                                session.set_phase(
                                    ServerSessionPhase::AwaitingMore,
                                    format!(
                                        "received background search page {} query={query:?}; requesting more",
                                        page_count
                                    ),
                                );
                                session.send_packet(OP_QUERY_MORE_RESULT, &[]).await?;
                                pending_background_search = Some(PendingBackgroundServerSearch::Keyword {
                                    query,
                                    deadline,
                                    results,
                                    page_count,
                                    response,
                                });
                                continue;
                            }
                            session.set_phase(
                                ServerSessionPhase::Completed,
                                format!(
                                    "completed background keyword search query={query:?} pages={page_count} results={}",
                                    results.len()
                                ),
                            );
                            info!(
                                "completed ED2K background keyword search query={:?} endpoint={} trace_id={} result_count={} pages={}",
                                query,
                                session.endpoint,
                                session.trace_id,
                                results.len(),
                                page_count
                            );
                            let _ = response.send(Ok(results));
                            continue;
                        }
                        (OP_FOUNDSOURCES | OP_FOUNDSOURCES_OBFU, PendingBackgroundServerSearch::Source {
                            file_hash,
                            response,
                            ..
                        }) => {
                            let results = annotate_found_sources_server(
                                decode_found_sources(
                                    &packet.payload,
                                    packet.opcode == OP_FOUNDSOURCES_OBFU,
                                )?,
                                session.endpoint,
                            );
                            validate_found_sources(&results, file_hash)?;
                            session.set_phase(
                                ServerSessionPhase::Completed,
                                format!(
                                    "completed background source search file_hash={} sources={}",
                                    file_hash,
                                    results.len()
                                ),
                            );
                            info!(
                                "completed ED2K background source search file_hash={} endpoint={} trace_id={} source_count={} obfuscated={}",
                                file_hash,
                                session.endpoint,
                                session.trace_id,
                                results.len(),
                                packet.opcode == OP_FOUNDSOURCES_OBFU
                            );
                            let _ = response.send(Ok(results));
                            continue;
                        }
                        (_, pending) => {
                            pending_background_search = Some(pending);
                        }
                    }
                }
                handle_server_packet(
                    &mut session,
                    packet,
                    context,
                    queued_background_search.is_none() && pending_background_search.is_none(),
                )
                .await?;
                if session.login_accepted
                    && pending_background_search.is_none()
                    && let Some(request) = queued_background_search.take()
                {
                    match start_background_server_search(
                        &mut session,
                        server,
                        server_udp_socket.as_ref(),
                        context.hello_identity.connect_options,
                        request,
                    )
                    .await
                    {
                        Ok(pending) => pending_background_search = pending,
                        Err(error) => warn!("failed to start ED2K background server search on {}: {error}", server.base_endpoint()),
                    }
                }
            }
            udp_packet = async {
                if let Some(socket) = server_udp_socket.as_ref() {
                    read_server_udp_packet(socket).await
                } else {
                    std::future::pending::<Result<Option<ServerUdpPacket>>>().await
                }
            } => {
                if let Some(packet) = udp_packet? {
                    handle_background_udp_packet(
                        server,
                        &packet,
                        &mut pending_background_search,
                        &context.state,
                    )?;
                }
            }
            _ = tokio::time::sleep(context.keepalive_interval) => {
                if session.last_tx.elapsed() >= context.keepalive_interval {
                    session.send_packet(OP_OFFERFILES, &0u32.to_le_bytes()).await?;
                    debug!("sent ED2K server keepalive to {}", server.base_endpoint());
                }
                if let Some(socket) = server_udp_socket.as_ref()
                    && let Err(error) = send_server_udp_status_request(socket, server).await
                {
                    warn!(
                        "failed to send ED2K server UDP status request to {}: {error}",
                        server.base_endpoint()
                    );
                }
            }
        }
    }
}

/// Executes a one-shot ED2K keyword search against the configured servers.
///
/// This is a staging path used by active `SearchJob`s before the fuller ED2K
/// server connection pool exists. The function prefers the currently connected
/// background server when one is available, caps how many configured servers it
/// will probe, and returns the first non-empty result page it receives.
#[allow(clippy::too_many_arguments)]
pub async fn search_keyword_servers(
    bind_ip: Ipv4Addr,
    config: &Ed2kConfig,
    hello_identity: Ed2kHelloIdentity,
    shared_catalog: &[Ed2kSharedEntry],
    preferred_endpoint: Option<SocketAddr>,
    max_attempts: usize,
    query: &str,
    cancel: &CancellationToken,
) -> Result<Vec<Ed2kSearchFile>> {
    let mut configured_servers = configured_server_entries(config)?;
    if configured_servers.is_empty() {
        anyhow::bail!("ED2K keyword search requires at least one configured server");
    }
    if let Some(preferred_endpoint) = preferred_endpoint
        && let Some(index) = configured_servers.iter().position(|entry| {
            entry.host == preferred_endpoint.ip().to_string()
                && entry.port == preferred_endpoint.port()
        })
    {
        let preferred = configured_servers.remove(index);
        configured_servers.insert(0, preferred);
    }

    let search_payload = encode_search_request(query)?;
    if search_payload.is_empty() {
        return Ok(Vec::new());
    }

    let idle_timeout = Duration::from_secs(config.connect_timeout_secs.max(5));
    let mut last_error = None;

    for (attempt_index, configured_server) in configured_servers
        .into_iter()
        .take(max_attempts.max(1))
        .enumerate()
    {
        if cancel.is_cancelled() {
            return Ok(Vec::new());
        }

        let resolved_server = match resolve_server_entry(&configured_server).await {
            Ok(server) => server,
            Err(error) => {
                warn!(
                    "failed to resolve ED2K search server {} name={}: {error}",
                    configured_server.base_endpoint_text(),
                    configured_server.display_name()
                );
                last_error = Some(error);
                continue;
            }
        };
        info!(
            "ED2K keyword search attempt={}/{} endpoint={} name={}",
            attempt_index + 1,
            max_attempts.max(1),
            resolved_server.base_endpoint(),
            resolved_server.entry.display_name()
        );

        match search_keyword_on_server(
            bind_ip,
            &resolved_server,
            hello_identity,
            shared_catalog,
            &search_payload,
            idle_timeout,
            cancel,
        )
        .await
        {
            Ok(results) if !results.is_empty() => return Ok(results),
            Ok(_) => continue,
            Err(error) => {
                warn!(
                    "ED2K keyword search failed for {} name={}: {error}",
                    resolved_server.base_endpoint(),
                    resolved_server.entry.display_name()
                );
                last_error = Some(error);
            }
        }
    }

    if let Some(error) = last_error {
        return Err(error);
    }

    Ok(Vec::new())
}

/// Executes a one-shot ED2K server source search for one file hash and size.
///
/// The ED2K server protocol uses `OP_GETSOURCES`/`OP_FOUNDSOURCES` rather than
/// the generic search-query tree used for keyword searches, so this path stays
/// separate from `search_keyword_servers`.
#[allow(clippy::too_many_arguments)]
pub async fn search_source_servers(
    bind_ip: Ipv4Addr,
    config: &Ed2kConfig,
    hello_identity: Ed2kHelloIdentity,
    shared_catalog: &[Ed2kSharedEntry],
    preferred_endpoint: Option<SocketAddr>,
    max_attempts: usize,
    file_hash: Ed2kHash,
    _file_size: u64,
    cancel: &CancellationToken,
) -> Result<Vec<Ed2kFoundSource>> {
    let mut configured_servers = configured_server_entries(config)?;
    if configured_servers.is_empty() {
        anyhow::bail!("ED2K source search requires at least one configured server");
    }
    if let Some(preferred_endpoint) = preferred_endpoint
        && let Some(index) = configured_servers.iter().position(|entry| {
            entry.host == preferred_endpoint.ip().to_string()
                && entry.port == preferred_endpoint.port()
        })
    {
        let preferred = configured_servers.remove(index);
        configured_servers.insert(0, preferred);
    }

    let idle_timeout = Duration::from_secs(config.connect_timeout_secs.max(5));
    let mut last_error = None;
    let mut aggregated_results: Vec<Ed2kFoundSource> = Vec::new();

    for (attempt_index, configured_server) in configured_servers
        .into_iter()
        .take(max_attempts.max(1))
        .enumerate()
    {
        if cancel.is_cancelled() {
            return Ok(Vec::new());
        }
        let resolved_server = match resolve_server_entry(&configured_server).await {
            Ok(server) => server,
            Err(error) => {
                warn!(
                    "failed to resolve ED2K source-search server {} name={}: {error}",
                    configured_server.base_endpoint_text(),
                    configured_server.display_name()
                );
                last_error = Some(error);
                continue;
            }
        };
        info!(
            "ED2K source search attempt={}/{} endpoint={} name={} file_hash={}",
            attempt_index + 1,
            max_attempts.max(1),
            resolved_server.base_endpoint(),
            resolved_server.entry.display_name(),
            file_hash
        );
        match search_sources_on_server(
            bind_ip,
            &resolved_server,
            hello_identity,
            shared_catalog,
            file_hash,
            _file_size,
            idle_timeout,
            cancel,
        )
        .await
        {
            Ok(results) if !results.is_empty() => {
                merge_found_sources(&mut aggregated_results, results);
            }
            Ok(_) => continue,
            Err(error) => {
                warn!(
                    "ED2K source search failed for {} name={}: {error}",
                    resolved_server.base_endpoint(),
                    resolved_server.entry.display_name()
                );
                last_error = Some(error);
            }
        }
    }

    if !aggregated_results.is_empty() {
        return Ok(aggregated_results);
    }

    if let Some(error) = last_error {
        return Err(error);
    }
    Ok(Vec::new())
}

async fn search_keyword_on_server(
    bind_ip: Ipv4Addr,
    server: &ResolvedServerEntry,
    hello_identity: Ed2kHelloIdentity,
    shared_catalog: &[Ed2kSharedEntry],
    search_payload: &[u8],
    idle_timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<Ed2kSearchFile>> {
    let use_server_obfuscation =
        should_use_server_obfuscation(hello_identity.connect_options, server);
    let login_identity =
        login_identity_for_server_transport(hello_identity, use_server_obfuscation);
    let transport_endpoint = server.transport_endpoint(use_server_obfuscation);
    let mut session = ServerSession::connect(
        bind_ip,
        transport_endpoint,
        Arc::new(RwLock::new(Ed2kServerState::default())),
        "active_search",
        idle_timeout,
    )
    .await?;
    info!(
        "ED2K active search session connected trace_id={} endpoint={} transport={} query_len={}",
        session.trace_id,
        transport_endpoint,
        if use_server_obfuscation {
            "obfuscated"
        } else {
            "plaintext"
        },
        search_payload.len()
    );
    let login_request = encode_packet(
        OP_LOGINREQUEST,
        &encode_login_request(login_identity),
        false,
    )?;
    if use_server_obfuscation {
        session
            .negotiate_obfuscation_and_send(&login_request)
            .await
            .with_context(|| {
                format!(
                    "failed to negotiate ED2K server obfuscation with {}",
                    transport_endpoint
                )
            })?;
    } else {
        session
            .stream
            .write_all(&login_request)
            .await
            .with_context(|| {
                format!("failed to send ED2K server login request to {transport_endpoint}")
            })?;
    }
    session.last_tx = Instant::now();
    session.set_phase(
        ServerSessionPhase::AwaitingIdChange,
        "login request sent; awaiting OP_IDCHANGE",
    );

    let mut results = Vec::new();
    let mut page_count = 0u32;

    loop {
        if cancel.is_cancelled() {
            return Ok(Vec::new());
        }

        let packet = tokio::time::timeout(idle_timeout, session.read_packet())
            .await
            .with_context(|| {
                format!("timed out waiting for ED2K server search reply from {transport_endpoint}")
            })??;
        let Some(packet) = packet else {
            break;
        };

        match packet.opcode {
            OP_IDCHANGE => {
                if packet.payload.len() < 4 {
                    anyhow::bail!("short OP_IDCHANGE payload from {transport_endpoint}");
                }
                session.assigned_client_id =
                    Some(u32::from_le_bytes(packet.payload[..4].try_into().unwrap()));
                session.server_flags = (packet.payload.len() >= 8)
                    .then(|| u32::from_le_bytes(packet.payload[4..8].try_into().unwrap()));
                let active_catalog = Arc::new(RwLock::new(shared_catalog.to_vec()));
                send_connected_server_startup(
                    &mut session,
                    &active_catalog,
                    hello_identity.tcp_port,
                )
                .await?;
                wait_for_offer_files_settle(&session).await;
                session.set_phase(
                    ServerSessionPhase::SearchActive,
                    "dispatching active keyword search request",
                );
                session
                    .send_packet(OP_SEARCHREQUEST, search_payload)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to send ED2K keyword search request to {transport_endpoint}"
                        )
                    })?;
            }
            OP_SEARCHRESULT => {
                let page = decode_search_result_page(&packet.payload)?;
                page_count += 1;
                results.extend(page.files);
                if page.more_results_available {
                    session.set_phase(
                        ServerSessionPhase::AwaitingMore,
                        format!("received active result page {page_count}; requesting more"),
                    );
                    session.send_packet(OP_QUERY_MORE_RESULT, &[]).await?;
                } else {
                    session.set_phase(
                        ServerSessionPhase::Completed,
                        format!(
                            "completed active keyword search pages={page_count} results={}",
                            results.len()
                        ),
                    );
                    break;
                }
            }
            OP_REJECT => {
                anyhow::bail!("ED2K server {transport_endpoint} rejected the search session");
            }
            _ => {}
        }
    }

    Ok(results)
}

#[allow(clippy::too_many_arguments)]
async fn search_sources_on_server(
    bind_ip: Ipv4Addr,
    server: &ResolvedServerEntry,
    hello_identity: Ed2kHelloIdentity,
    shared_catalog: &[Ed2kSharedEntry],
    file_hash: Ed2kHash,
    file_size: u64,
    idle_timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<Ed2kFoundSource>> {
    let use_server_obfuscation =
        should_use_server_obfuscation(hello_identity.connect_options, server);
    let login_identity =
        login_identity_for_server_transport(hello_identity, use_server_obfuscation);
    let transport_endpoint = server.transport_endpoint(use_server_obfuscation);
    let mut session = ServerSession::connect(
        bind_ip,
        transport_endpoint,
        Arc::new(RwLock::new(Ed2kServerState::default())),
        "active_sources",
        idle_timeout,
    )
    .await?;
    let login_request = encode_packet(
        OP_LOGINREQUEST,
        &encode_login_request(login_identity),
        false,
    )?;
    if use_server_obfuscation {
        session
            .negotiate_obfuscation_and_send(&login_request)
            .await
            .with_context(|| {
                format!(
                    "failed to negotiate ED2K server obfuscation with {}",
                    transport_endpoint
                )
            })?;
    } else {
        session
            .send_packet(OP_LOGINREQUEST, &encode_login_request(login_identity))
            .await?;
    }
    session.last_tx = Instant::now();
    session.set_phase(
        ServerSessionPhase::AwaitingIdChange,
        "login request sent; awaiting OP_IDCHANGE for source search",
    );
    let active_catalog = Arc::new(RwLock::new(shared_catalog.to_vec()));

    loop {
        if cancel.is_cancelled() {
            return Ok(Vec::new());
        }
        let packet = tokio::time::timeout(idle_timeout, session.read_packet())
            .await
            .with_context(|| {
                format!(
                    "timed out waiting for ED2K server source-search reply from {transport_endpoint}"
                )
            })??;
        let Some(packet) = packet else {
            break;
        };
        match packet.opcode {
            OP_IDCHANGE => {
                if packet.payload.len() < 4 {
                    anyhow::bail!("short OP_IDCHANGE payload from {transport_endpoint}");
                }
                session.assigned_client_id =
                    Some(u32::from_le_bytes(packet.payload[..4].try_into().unwrap()));
                session.server_flags = (packet.payload.len() >= 8)
                    .then(|| u32::from_le_bytes(packet.payload[4..8].try_into().unwrap()));
                send_connected_server_startup(
                    &mut session,
                    &active_catalog,
                    hello_identity.tcp_port,
                )
                .await?;
                session.set_phase(
                    ServerSessionPhase::SearchActive,
                    format!("dispatching source search file_hash={file_hash}"),
                );
                let source_request = encode_source_request(file_hash, file_size);
                let opcode = source_request_opcode(
                    login_identity.connect_options,
                    session.server_flags,
                    use_server_obfuscation,
                );
                session.send_packet(opcode, &source_request).await?;
            }
            OP_FOUNDSOURCES | OP_FOUNDSOURCES_OBFU => {
                let results = annotate_found_sources_server(
                    decode_found_sources(&packet.payload, packet.opcode == OP_FOUNDSOURCES_OBFU)?,
                    server.base_endpoint(),
                );
                validate_found_sources(&results, file_hash)?;
                session.set_phase(
                    ServerSessionPhase::Completed,
                    format!(
                        "completed source search file_hash={} sources={}",
                        file_hash,
                        results.len()
                    ),
                );
                return Ok(results);
            }
            OP_REJECT => {
                anyhow::bail!(
                    "ED2K server {transport_endpoint} rejected the source-search session"
                );
            }
            _ => {}
        }
    }

    Ok(Vec::new())
}

async fn maybe_send_probe_search(
    session: &mut ServerSession,
    context: &ServerSessionContext,
) -> Result<()> {
    if !session.login_accepted || session.probe_search_sent {
        return Ok(());
    }
    let Some(term) = context.probe_search_term.as_deref() else {
        return Ok(());
    };
    let search_payload = encode_search_request(term)?;
    if search_payload.is_empty() {
        return Ok(());
    }
    wait_for_offer_files_settle(session).await;
    session.set_phase(
        ServerSessionPhase::SearchActive,
        format!("dispatching probe keyword search term={term:?}"),
    );
    session
        .send_packet(OP_SEARCHREQUEST, &search_payload)
        .await?;
    session.probe_search_sent = true;
    info!(
        "sent ED2K server search probe term={term:?} endpoint={}",
        session.endpoint
    );
    Ok(())
}

async fn handle_server_packet(
    session: &mut ServerSession,
    packet: Ed2kPacket,
    context: &ServerSessionContext,
    allow_probe_search: bool,
) -> Result<()> {
    match packet.opcode {
        OP_IDCHANGE => {
            if packet.payload.len() < 4 {
                anyhow::bail!("short OP_IDCHANGE payload from {}", session.endpoint);
            }
            let client_id = u32::from_le_bytes(packet.payload[..4].try_into().unwrap());
            let server_flags = (packet.payload.len() >= 8)
                .then(|| u32::from_le_bytes(packet.payload[4..8].try_into().unwrap()));
            let reported_client_ip = (packet.payload.len() >= 16).then(|| {
                ipv4_from_client_id(u32::from_le_bytes(
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
            session.assigned_client_id = Some(client_id);
            session.server_flags = server_flags;
            session.login_accepted = true;
            send_connected_server_startup(
                session,
                &context.shared_catalog,
                context.hello_identity.tcp_port,
            )
            .await?;
            if allow_probe_search {
                maybe_send_probe_search(session, context).await?;
            }
        }
        OP_SEARCHRESULT => {
            let page = decode_search_result_page(&packet.payload)?;
            log_search_result_page(session.endpoint, &page.files);
            if page.more_results_available {
                session.set_phase(
                    ServerSessionPhase::AwaitingMore,
                    "probe search reported more results; requesting another page",
                );
                session.send_packet(OP_QUERY_MORE_RESULT, &[]).await?;
            } else if session.probe_search_sent {
                session.set_phase(
                    ServerSessionPhase::Completed,
                    "probe search completed without additional pages",
                );
            }
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
            if allow_probe_search {
                maybe_send_probe_search(session, context).await?;
            }
        }
        OP_SERVERLIST => {
            let count = packet.payload.first().copied().unwrap_or_default();
            debug!(
                "ED2K server {} returned {} server list entries",
                session.endpoint, count
            );
            if allow_probe_search {
                maybe_send_probe_search(session, context).await?;
            }
        }
        OP_SERVERMESSAGE => {
            if let Some(message) = decode_ed2k_string(&packet.payload)? {
                info!("ED2K server message from {}: {}", session.endpoint, message);
            }
            if allow_probe_search {
                maybe_send_probe_search(session, context).await?;
            }
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
                let hello_identity = enrich_hello_identity(
                    context.hello_identity,
                    &context.state,
                    &context.kad_firewall,
                )
                .await;
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

fn handle_background_udp_packet(
    server: &ResolvedServerEntry,
    packet: &ServerUdpPacket,
    pending_background_search: &mut Option<PendingBackgroundServerSearch>,
    state: &Arc<RwLock<Ed2kServerState>>,
) -> Result<()> {
    if packet.from.ip() != IpAddr::V4(server.ip) {
        return Ok(());
    }
    match packet.opcode {
        OP_GLOBSEARCHRES => {
            let Some(PendingBackgroundServerSearch::Keyword {
                query,
                mut results,
                response,
                ..
            }) = pending_background_search.take()
            else {
                return Ok(());
            };
            for page in decode_udp_search_result_pages(&packet.payload)? {
                log_search_result_page(server.base_endpoint(), &page.files);
                results.extend(page.files);
            }
            info!(
                "completed ED2K background UDP keyword search query={:?} endpoint={} source=udp result_count={}",
                query,
                server.base_endpoint(),
                results.len()
            );
            let _ = response.send(Ok(results));
        }
        OP_GLOBFOUNDSOURCES => {
            let Some(PendingBackgroundServerSearch::Source {
                file_hash,
                response,
                ..
            }) = pending_background_search.take()
            else {
                return Ok(());
            };
            let mut aggregated_results = Vec::new();
            for results in decode_udp_found_source_sets(&packet.payload)? {
                validate_found_sources(&results, file_hash)?;
                merge_found_sources(&mut aggregated_results, results);
            }
            info!(
                "completed ED2K background UDP source search file_hash={} endpoint={} source=udp source_count={}",
                file_hash,
                server.base_endpoint(),
                aggregated_results.len()
            );
            let _ = response.send(Ok(aggregated_results));
        }
        OP_GLOBSERVSTATRES => {
            if packet.payload.len() >= 8 {
                let users = u32::from_le_bytes(packet.payload[..4].try_into().unwrap());
                let files = u32::from_le_bytes(packet.payload[4..8].try_into().unwrap());
                if let Ok(mut guard) = state.try_write() {
                    guard.server_users = Some(users);
                    guard.server_files = Some(files);
                }
                debug!(
                    "ED2K server UDP status from {} users={} files={}",
                    packet.from, users, files
                );
            }
        }
        _ => {}
    }
    Ok(())
}

fn fail_background_search_request(
    request: &mut Option<BackgroundServerSearchRequest>,
    error: &str,
) {
    if let Some(request) = request.take() {
        match request {
            BackgroundServerSearchRequest::Keyword { response, .. } => {
                let _ = response.send(Err(error.to_string()));
            }
            BackgroundServerSearchRequest::Source { response, .. } => {
                let _ = response.send(Err(error.to_string()));
            }
            BackgroundServerSearchRequest::Callback { response, .. } => {
                let _ = response.send(Err(error.to_string()));
            }
        }
    }
}

fn fail_pending_background_search(
    request: &mut Option<PendingBackgroundServerSearch>,
    error: &str,
) {
    if let Some(request) = request.take() {
        match request {
            PendingBackgroundServerSearch::Keyword { response, .. } => {
                let _ = response.send(Err(error.to_string()));
            }
            PendingBackgroundServerSearch::Source { response, .. } => {
                let _ = response.send(Err(error.to_string()));
            }
        }
    }
}

async fn start_background_server_search(
    session: &mut ServerSession,
    server: &ResolvedServerEntry,
    server_udp_socket: Option<&UdpSocket>,
    connect_options: u8,
    request: BackgroundServerSearchRequest,
) -> Result<Option<PendingBackgroundServerSearch>> {
    match request {
        BackgroundServerSearchRequest::Keyword {
            query,
            timeout,
            response,
        } => {
            let search_payload = encode_search_request(&query)?;
            if search_payload.is_empty() {
                let _ = response.send(Ok(Vec::new()));
                anyhow::bail!("ED2K background keyword search payload was unexpectedly empty");
            }
            wait_for_offer_files_settle(session).await;
            session.set_phase(
                ServerSessionPhase::SearchActive,
                format!("dispatching background keyword search query={query:?}"),
            );
            session
                .send_packet(OP_SEARCHREQUEST, &search_payload)
                .await?;
            if let Some(socket) = server_udp_socket
                && let Err(error) = send_udp_keyword_search(socket, server, &search_payload).await
            {
                warn!(
                    "failed to send ED2K background UDP keyword search query={:?} endpoint={}: {error}",
                    query,
                    server.base_endpoint()
                );
            }
            info!(
                "sent ED2K background keyword search query={:?} endpoint={} trace_id={} role={}",
                query, session.endpoint, session.trace_id, session.trace_role
            );
            Ok(Some(PendingBackgroundServerSearch::Keyword {
                query,
                deadline: TokioInstant::now() + timeout,
                results: Vec::new(),
                page_count: 0,
                response,
            }))
        }
        BackgroundServerSearchRequest::Source {
            file_hash,
            file_size,
            timeout,
            response,
        } => {
            wait_for_offer_files_settle(session).await;
            session.set_phase(
                ServerSessionPhase::SearchActive,
                format!("dispatching background source search file_hash={file_hash}"),
            );
            let source_request = encode_source_request(file_hash, file_size);
            let opcode = source_request_opcode(
                connect_options,
                session.server_flags,
                session.send_cipher.is_some(),
            );
            session.send_packet(opcode, &source_request).await?;
            if let Some(socket) = server_udp_socket
                && let Err(error) =
                    send_udp_source_search(socket, server, file_hash, file_size).await
            {
                warn!(
                    "failed to send ED2K background UDP source search file_hash={} endpoint={}: {error}",
                    file_hash,
                    server.base_endpoint()
                );
            }
            info!(
                "sent ED2K background source search file_hash={} endpoint={} trace_id={} role={} opcode=0x{:02X}",
                file_hash, session.endpoint, session.trace_id, session.trace_role, opcode
            );
            Ok(Some(PendingBackgroundServerSearch::Source {
                file_hash,
                deadline: TokioInstant::now() + timeout,
                response,
            }))
        }
        BackgroundServerSearchRequest::Callback {
            client_id,
            response,
        } => {
            wait_for_offer_files_settle(session).await;
            session.set_phase(
                ServerSessionPhase::SearchActive,
                format!("dispatching background callback request client_id={client_id}"),
            );
            session
                .send_packet(OP_CALLBACKREQUEST, &client_id.to_le_bytes())
                .await?;
            info!(
                "sent ED2K background callback request client_id={} endpoint={} trace_id={} role={}",
                client_id, session.endpoint, session.trace_id, session.trace_role
            );
            let _ = response.send(Ok(()));
            Ok(None)
        }
    }
}

fn log_search_result_page(endpoint: SocketAddr, results: &[Ed2kSearchFile]) {
    let sample_hits = results
        .iter()
        .take(5)
        .map(|file| {
            let file_name = file.file_name.as_deref().unwrap_or("-");
            let file_size = file
                .file_size
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string());
            format!("{file_name} [hash={} size={}]", file.file_hash, file_size)
        })
        .collect::<Vec<_>>();
    info!(
        "ED2K search results from {}: count={} sample_hits={}",
        endpoint,
        results.len(),
        if sample_hits.is_empty() {
            "-".to_string()
        } else {
            sample_hits.join(" | ")
        }
    );
}

fn decode_callback_request(payload: &[u8]) -> Result<Option<CallbackRequest>> {
    if payload.len() < 6 {
        return Ok(None);
    }
    let ip = ipv4_from_client_id(u32::from_le_bytes(payload[..4].try_into().unwrap()));
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

fn decode_udp_found_source_sets(payload: &[u8]) -> Result<Vec<Vec<Ed2kFoundSource>>> {
    let mut cursor = payload;
    let mut sets = Vec::new();
    while !cursor.is_empty() {
        let (sources, rest) = decode_found_sources_from(cursor, false)?;
        sets.push(sources);
        cursor = rest;
    }
    Ok(sets)
}

fn decode_found_sources(payload: &[u8], obfuscated: bool) -> Result<Vec<Ed2kFoundSource>> {
    let (results, rest) = decode_found_sources_from(payload, obfuscated)?;
    if !rest.is_empty() {
        anyhow::bail!(
            "unexpected ED2K found-sources trailing data len={}",
            rest.len()
        );
    }
    Ok(results)
}

fn annotate_found_sources_server(
    mut results: Vec<Ed2kFoundSource>,
    server_endpoint: SocketAddr,
) -> Vec<Ed2kFoundSource> {
    for source in &mut results {
        source.source_server = Some(server_endpoint);
    }
    results
}

fn ipv4_from_client_id(client_id: u32) -> Ipv4Addr {
    Ipv4Addr::from(client_id.to_le_bytes())
}

fn validate_found_sources(results: &[Ed2kFoundSource], expected_file_hash: Ed2kHash) -> Result<()> {
    for source in results {
        if source.file_hash != expected_file_hash {
            anyhow::bail!(
                "ED2K found-sources reply referenced unexpected file hash {} expected {}",
                source.file_hash,
                expected_file_hash
            );
        }
    }
    Ok(())
}

fn merge_found_sources(
    aggregated_results: &mut Vec<Ed2kFoundSource>,
    new_results: Vec<Ed2kFoundSource>,
) {
    for source in new_results {
        if let Some(existing) = aggregated_results.iter_mut().find(|existing| {
            existing.ip == source.ip
                && existing.tcp_port == source.tcp_port
                && existing.obfuscation_options == source.obfuscation_options
                && existing.user_hash == source.user_hash
        }) {
            if existing.source_server.is_none() && source.source_server.is_some() {
                existing.source_server = source.source_server;
            }
            continue;
        }
        aggregated_results.push(source);
    }
}

async fn resolve_callback_server_entry(
    config: &Ed2kConfig,
    server_endpoint: SocketAddr,
) -> Result<ResolvedServerEntry> {
    let endpoint_v4 = match server_endpoint {
        SocketAddr::V4(endpoint) => endpoint,
        SocketAddr::V6(_) => {
            anyhow::bail!("ED2K callback server endpoint must be IPv4, got {server_endpoint}")
        }
    };

    for configured_server in configured_server_entries(config)? {
        let resolved_server = resolve_server_entry(&configured_server).await?;
        if resolved_server.base_endpoint() == SocketAddr::V4(endpoint_v4) {
            return Ok(resolved_server);
        }
    }

    Ok(ResolvedServerEntry {
        entry: ConfiguredServerEntry::from_endpoint_text(&server_endpoint.to_string())?,
        ip: *endpoint_v4.ip(),
    })
}

async fn clear_server_connection_state(state: &Arc<RwLock<Ed2kServerState>>) {
    let mut guard = state.write().await;
    guard.connected = false;
    guard.endpoint = None;
    guard.client_id = None;
    guard.server_flags = None;
}

fn configured_server_entries(config: &Ed2kConfig) -> Result<Vec<ConfiguredServerEntry>> {
    if !config.server_entries.is_empty() {
        return config
            .server_entries
            .iter()
            .map(ConfiguredServerEntry::from_metadata)
            .collect();
    }

    config
        .server_endpoints
        .iter()
        .map(|endpoint_text| ConfiguredServerEntry::from_endpoint_text(endpoint_text))
        .collect()
}

async fn resolve_server_entry(entry: &ConfiguredServerEntry) -> Result<ResolvedServerEntry> {
    let lookup = format!("{}:{}", entry.host, entry.port);
    let ip = if let Ok(parsed_ip) = entry.host.parse::<Ipv4Addr>() {
        parsed_ip
    } else {
        lookup_host(&lookup)
            .await
            .with_context(|| format!("failed to resolve {lookup}"))?
            .find_map(|endpoint| match endpoint {
                SocketAddr::V4(endpoint) => Some(*endpoint.ip()),
                SocketAddr::V6(_) => None,
            })
            .ok_or_else(|| anyhow::anyhow!("no IPv4 address resolved for {lookup}"))?
    };
    Ok(ResolvedServerEntry {
        entry: entry.clone(),
        ip,
    })
}

async fn bind_server_udp_socket(bind_ip: Ipv4Addr) -> Result<UdpSocket> {
    UdpSocket::bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
        .await
        .with_context(|| format!("failed to bind ED2K server UDP helper on {bind_ip}:0"))
}

fn server_udp_endpoint(server: &ResolvedServerEntry) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(server.ip),
        if server.entry.port <= u16::MAX - 4 {
            server.entry.port + 4
        } else {
            server.entry.port
        },
    )
}

async fn send_server_udp_packet(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
    opcode: u8,
    payload: &[u8],
) -> Result<()> {
    let mut packet = Vec::with_capacity(2 + payload.len());
    packet.push(OP_EDONKEYPROT);
    packet.push(opcode);
    packet.extend_from_slice(payload);
    socket
        .send_to(&packet, server_udp_endpoint(server))
        .await
        .with_context(|| {
            format!(
                "failed to send ED2K server UDP opcode=0x{opcode:02X} to {}",
                server_udp_endpoint(server)
            )
        })?;
    Ok(())
}

async fn send_server_udp_status_request(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
) -> Result<()> {
    send_server_udp_packet(socket, server, OP_GLOBSERVSTATREQ, &[]).await
}

async fn send_udp_keyword_search(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
    search_payload: &[u8],
) -> Result<()> {
    let (opcode, payload) = encode_udp_search_request(server, search_payload);
    send_server_udp_packet(socket, server, opcode, &payload).await
}

async fn send_udp_source_search(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
    file_hash: Ed2kHash,
    file_size: u64,
) -> Result<()> {
    let (opcode, payload) = encode_udp_source_request(server, file_hash, file_size);
    send_server_udp_packet(socket, server, opcode, &payload).await
}

async fn read_server_udp_packet(socket: &UdpSocket) -> Result<Option<ServerUdpPacket>> {
    let mut buffer = vec![0u8; 65_535];
    let (len, from) = socket
        .recv_from(&mut buffer)
        .await
        .context("failed to receive ED2K server UDP datagram")?;
    if len < 2 {
        return Ok(None);
    }
    if buffer[0] != OP_EDONKEYPROT {
        return Ok(None);
    }
    Ok(Some(ServerUdpPacket {
        opcode: buffer[1],
        payload: buffer[2..len].to_vec(),
        from,
    }))
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
    let Some(expression) = parse_search_expression(term)? else {
        return Ok(Vec::new());
    };

    let mut payload = Vec::new();
    if let Some(joined_terms) = flatten_and_terms(&expression) {
        encode_search_string_param(&mut payload, &joined_terms.join(" "))?;
    } else {
        encode_search_expression(&mut payload, &expression)?;
    }
    Ok(payload)
}

fn login_identity_for_server_transport(
    mut identity: Ed2kHelloIdentity,
    use_server_obfuscation: bool,
) -> Ed2kHelloIdentity {
    if !use_server_obfuscation {
        identity.connect_options = 0;
    }
    identity
}

fn encode_offer_files_payload(
    shared_catalog: &[Ed2kSharedEntry],
    client_id: Option<u32>,
    tcp_port: u16,
    server_flags: Option<u32>,
) -> Vec<u8> {
    let (advertised_client_id, advertised_client_port) =
        advertised_client_endpoint_for_offer_file(client_id, tcp_port, server_flags);
    let offered_files = offered_files_catalog(shared_catalog);
    let mut payload = Vec::with_capacity(80 * offered_files.len());
    payload.extend_from_slice(
        &u32::try_from(offered_files.len())
            .expect("offered file count fits in u32")
            .to_le_bytes(),
    );
    for (file_hash, file_name, file_size, file_type) in offered_files {
        payload.extend_from_slice(&file_hash);
        payload.extend_from_slice(&advertised_client_id.to_le_bytes());
        payload.extend_from_slice(&advertised_client_port.to_le_bytes());
        payload.extend_from_slice(&3u32.to_le_bytes());
        push_short_string_tag(&mut payload, FT_FILENAME, &file_name);
        push_short_u32_tag(&mut payload, FT_FILESIZE, file_size);
        push_short_u8_tag(&mut payload, FT_FILETYPE, file_type);
    }
    payload
}

fn advertised_client_endpoint_for_offer_file(
    client_id: Option<u32>,
    tcp_port: u16,
    server_flags: Option<u32>,
) -> (u32, u16) {
    if server_flags.unwrap_or_default() & SERVER_TCP_FLAG_COMPRESSION != 0 {
        return (
            OFFER_FILE_COMPLETE_SENTINEL_CLIENT_ID,
            OFFER_FILE_COMPLETE_SENTINEL_CLIENT_PORT,
        );
    }
    match client_id {
        Some(client_id) if !is_low_id(client_id) => (client_id, tcp_port),
        _ => (0, 0),
    }
}

fn encode_search_string_param(payload: &mut Vec<u8>, value: &str) -> Result<()> {
    let value_bytes = value.as_bytes();
    let value_len = u16::try_from(value_bytes.len()).context("ED2K search term is too long")?;
    payload.push(1);
    payload.extend_from_slice(&value_len.to_le_bytes());
    payload.extend_from_slice(value_bytes);
    Ok(())
}

/// Encode the oracle-shaped ED2K local-server source request payload.
///
/// Modern eMule sends the file hash plus file size in the TCP local-server
/// source-request path. Large files use the `0` sentinel followed by a `u64`.
fn encode_source_request(file_hash: Ed2kHash, file_size: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(28);
    payload.extend_from_slice(&file_hash.0);
    if file_size > u64::from(u32::MAX) {
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&file_size.to_le_bytes());
    } else {
        payload.extend_from_slice(&(file_size as u32).to_le_bytes());
    }
    payload
}

fn encode_udp_search_request(server: &ResolvedServerEntry, search_payload: &[u8]) -> (u8, Vec<u8>) {
    if server.entry.udp_flags & SERVER_UDP_FLAG_EXT_GETFILES != 0
        && server.entry.udp_flags & SERVER_UDP_FLAG_LARGEFILES != 0
    {
        let mut payload = Vec::with_capacity(search_payload.len() + 11);
        payload.extend_from_slice(&1u32.to_le_bytes());
        push_u32_tag(
            &mut payload,
            CT_SERVER_UDPSEARCH_FLAGS,
            SRVCAP_UDP_NEWTAGS_LARGEFILES,
        );
        payload.extend_from_slice(search_payload);
        (OP_GLOBSEARCHREQ3, payload)
    } else if server.entry.udp_flags & SERVER_UDP_FLAG_EXT_GETFILES != 0 {
        (OP_GLOBSEARCHREQ2, search_payload.to_vec())
    } else {
        (OP_GLOBSEARCHREQ, search_payload.to_vec())
    }
}

fn encode_udp_source_request(
    server: &ResolvedServerEntry,
    file_hash: Ed2kHash,
    file_size: u64,
) -> (u8, Vec<u8>) {
    if server.entry.udp_flags & SERVER_UDP_FLAG_EXT_GETSOURCES2 != 0 {
        (
            OP_GLOBGETSOURCES2,
            encode_source_request(file_hash, file_size),
        )
    } else {
        let _supports_legacy_getsources =
            server.entry.udp_flags & SERVER_UDP_FLAG_EXT_GETSOURCES != 0;
        (OP_GLOBGETSOURCES, file_hash.0.to_vec())
    }
}

fn source_request_opcode(
    connect_options: u8,
    server_flags: Option<u32>,
    use_obfuscated_transport: bool,
) -> u8 {
    if connect_options != 0
        && use_obfuscated_transport
        && server_flags.unwrap_or_default() & SERVER_TCP_FLAG_TCPOBFUSCATION != 0
    {
        OP_GETSOURCES_OBFU
    } else {
        OP_GETSOURCES
    }
}

fn offered_files_catalog(shared_catalog: &[Ed2kSharedEntry]) -> Vec<([u8; 16], String, u32, u8)> {
    let mut offered_files = shared_catalog
        .iter()
        .filter_map(popular_hash_offer_file)
        .take(200)
        .collect::<Vec<_>>();
    if offered_files.is_empty() {
        offered_files.push((
            OFFER_FILE_SAMPLE_HASH,
            OFFER_FILE_SAMPLE_NAME.to_string(),
            OFFER_FILE_SAMPLE_SIZE,
            ED2K_FILETYPE_PROGRAM,
        ));
    }
    offered_files
}

fn popular_hash_offer_file(hash: &Ed2kSharedEntry) -> Option<([u8; 16], String, u32, u8)> {
    let file_hash = hash.parsed_hash().ok()?;
    let file_size = u32::try_from(hash.file_size).unwrap_or(u32::MAX);
    Some((
        file_hash.0,
        hash.canonical_name.clone(),
        file_size,
        ed2k_offer_file_type(&hash.canonical_name),
    ))
}

fn ed2k_offer_file_type(file_name: &str) -> u8 {
    match file_name
        .rsplit('.')
        .next()
        .map(|extension| extension.to_ascii_lowercase())
        .as_deref()
    {
        Some("avi" | "mp4" | "mkv" | "mov" | "wmv" | "mpeg" | "mpg") => ED2K_FILETYPE_VIDEO,
        Some("mp3" | "flac" | "ogg" | "wav" | "aac" | "m4a") => ED2K_FILETYPE_AUDIO,
        Some("zip" | "rar" | "7z" | "tar" | "gz" | "bz2") => ED2K_FILETYPE_ARCHIVE,
        Some("pdf" | "doc" | "docx" | "txt" | "rtf" | "epub") => ED2K_FILETYPE_DOCUMENT,
        _ => ED2K_FILETYPE_PROGRAM,
    }
}

fn encode_search_expression(payload: &mut Vec<u8>, expression: &SearchExprNode) -> Result<()> {
    match expression {
        SearchExprNode::Term(value) => encode_search_string_param(payload, value),
        SearchExprNode::And(left, right) => {
            payload.push(0);
            payload.push(0x00);
            encode_search_expression(payload, left)?;
            encode_search_expression(payload, right)
        }
        SearchExprNode::Or(left, right) => {
            payload.push(0);
            payload.push(0x01);
            encode_search_expression(payload, left)?;
            encode_search_expression(payload, right)
        }
        SearchExprNode::Not(left, right) => {
            payload.push(0);
            payload.push(0x02);
            encode_search_expression(payload, left)?;
            encode_search_expression(payload, right)
        }
    }
}

fn flatten_and_terms(expression: &SearchExprNode) -> Option<Vec<String>> {
    let mut terms = Vec::new();
    if collect_flat_and_terms(expression, &mut terms) {
        Some(terms)
    } else {
        None
    }
}

fn collect_flat_and_terms(expression: &SearchExprNode, terms: &mut Vec<String>) -> bool {
    match expression {
        SearchExprNode::Term(value) => {
            terms.push(value.clone());
            true
        }
        SearchExprNode::And(left, right) => {
            collect_flat_and_terms(left, terms) && collect_flat_and_terms(right, terms)
        }
        SearchExprNode::Or(_, _) | SearchExprNode::Not(_, _) => false,
    }
}

fn parse_search_expression(input: &str) -> Result<Option<SearchExprNode>> {
    let tokens = tokenize_search_expression(input)?;
    if tokens.is_empty() {
        return Ok(None);
    }
    let mut parser = SearchExpressionParser::new(tokens);
    let expression = parser.parse_expression(1)?;
    if parser.peek().is_some() {
        anyhow::bail!("unexpected trailing ED2K search tokens");
    }
    Ok(Some(expression))
}

fn tokenize_search_expression(input: &str) -> Result<Vec<SearchToken>> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.peek().copied() {
        match ch {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(SearchToken::OpenParen);
            }
            ')' => {
                chars.next();
                tokens.push(SearchToken::CloseParen);
            }
            '"' => {
                chars.next();
                let mut phrase = String::new();
                let mut closed = false;
                for next in chars.by_ref() {
                    if next == '"' {
                        closed = true;
                        break;
                    }
                    phrase.push(next);
                }
                if !closed {
                    anyhow::bail!("unterminated quoted ED2K search phrase");
                }
                let phrase = phrase.trim();
                if !phrase.is_empty() {
                    tokens.push(SearchToken::Term(phrase.to_string()));
                }
            }
            _ => {
                let mut word = String::new();
                while let Some(next) = chars.peek().copied() {
                    if next.is_whitespace() || matches!(next, '(' | ')' | '"') {
                        break;
                    }
                    word.push(next);
                    chars.next();
                }
                if word.is_empty() {
                    continue;
                }
                let uppercase = word.to_ascii_uppercase();
                match uppercase.as_str() {
                    "AND" => tokens.push(SearchToken::And),
                    "OR" => tokens.push(SearchToken::Or),
                    "NOT" => tokens.push(SearchToken::Not),
                    _ => tokens.push(SearchToken::Term(word)),
                }
            }
        }
    }
    Ok(tokens)
}

struct SearchExpressionParser {
    tokens: Vec<SearchToken>,
    position: usize,
}

impl SearchExpressionParser {
    fn new(tokens: Vec<SearchToken>) -> Self {
        Self {
            tokens,
            position: 0,
        }
    }

    fn peek(&self) -> Option<&SearchToken> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<SearchToken> {
        let token = self.tokens.get(self.position).cloned()?;
        self.position += 1;
        Some(token)
    }

    fn parse_expression(&mut self, min_precedence: u8) -> Result<SearchExprNode> {
        let mut lhs = self.parse_primary()?;
        while let Some((operator, precedence, implicit)) = self.peek_binary_operator() {
            if precedence < min_precedence {
                break;
            }
            if !implicit {
                let _ = self.next();
            }
            let rhs = self.parse_expression(precedence + 1)?;
            lhs = match operator {
                SearchBinaryOperator::And => SearchExprNode::And(Box::new(lhs), Box::new(rhs)),
                SearchBinaryOperator::Or => SearchExprNode::Or(Box::new(lhs), Box::new(rhs)),
                SearchBinaryOperator::Not => SearchExprNode::Not(Box::new(lhs), Box::new(rhs)),
            };
        }
        Ok(lhs)
    }

    fn parse_primary(&mut self) -> Result<SearchExprNode> {
        match self.next() {
            Some(SearchToken::Term(value)) => Ok(SearchExprNode::Term(value)),
            Some(SearchToken::OpenParen) => {
                let expression = self.parse_expression(1)?;
                match self.next() {
                    Some(SearchToken::CloseParen) => Ok(expression),
                    _ => anyhow::bail!("missing closing parenthesis in ED2K search expression"),
                }
            }
            Some(
                SearchToken::And | SearchToken::Or | SearchToken::Not | SearchToken::CloseParen,
            )
            | None => anyhow::bail!("invalid ED2K search expression"),
        }
    }

    fn peek_binary_operator(&self) -> Option<(SearchBinaryOperator, u8, bool)> {
        match self.peek() {
            Some(SearchToken::And) => Some((SearchBinaryOperator::And, 1, false)),
            Some(SearchToken::Or) => Some((SearchBinaryOperator::Or, 2, false)),
            Some(SearchToken::Not) => Some((SearchBinaryOperator::Not, 3, false)),
            Some(SearchToken::Term(_) | SearchToken::OpenParen) => {
                Some((SearchBinaryOperator::And, 1, true))
            }
            Some(SearchToken::CloseParen) | None => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchBinaryOperator {
    And,
    Or,
    Not,
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

fn push_short_u32_tag(payload: &mut Vec<u8>, name: u8, value: u32) {
    payload.push(TAG_SHORT_NAME_MASK | TAGTYPE_UINT32);
    payload.push(name);
    payload.extend_from_slice(&value.to_le_bytes());
}

fn push_short_u8_tag(payload: &mut Vec<u8>, name: u8, value: u8) {
    payload.push(TAG_SHORT_NAME_MASK | TAGTYPE_UINT8);
    payload.push(name);
    payload.push(value);
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

fn push_short_string_tag(payload: &mut Vec<u8>, name: u8, value: &str) {
    let value_bytes = value.as_bytes();
    let type_byte = if (1..=16).contains(&value_bytes.len()) {
        TAGTYPE_STR1 + u8::try_from(value_bytes.len() - 1).expect("string tag length fits in u8")
    } else {
        TAGTYPE_STRING
    };
    payload.push(TAG_SHORT_NAME_MASK | type_byte);
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

fn encode_packet(opcode: u8, payload: &[u8], use_compression: bool) -> Result<Vec<u8>> {
    let protocol = if use_compression {
        OP_PACKEDPROT
    } else {
        OP_EDONKEYPROT
    };
    let encoded_payload = if use_compression {
        encode_packed_payload(payload)?
    } else {
        payload.to_vec()
    };
    let mut bytes = Vec::with_capacity(TCP_PACKET_HEADER_LEN + encoded_payload.len());
    bytes.push(protocol);
    bytes.extend_from_slice(
        &(u32::try_from(encoded_payload.len() + 1).context("payload too large")?).to_le_bytes(),
    );
    bytes.push(opcode);
    bytes.extend_from_slice(&encoded_payload);
    Ok(bytes)
}

fn encode_packed_payload(payload: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(payload)
        .context("failed to deflate ED2K server payload")?;
    encoder
        .finish()
        .context("failed to finalize ED2K server payload compression")
}

async fn send_offer_files_advertisement(
    session: &mut ServerSession,
    shared_catalog: &Ed2kSharedCatalog,
    tcp_port: u16,
) -> Result<()> {
    if session.offer_files_sent {
        return Ok(());
    }
    let shared_catalog = shared_catalog.read().await.clone();
    let payload = encode_offer_files_payload(
        &shared_catalog,
        session.assigned_client_id,
        tcp_port,
        session.server_flags,
    );
    session.send_packet(OP_OFFERFILES, &payload).await?;
    session.offer_files_sent = true;
    session.offer_files_sent_at = Some(Instant::now());
    session.set_phase(
        ServerSessionPhase::OfferFilesSent,
        format!(
            "sent offer-files advertisement entries={}",
            offered_files_catalog(&shared_catalog).len()
        ),
    );
    debug!(
        "sent ED2K offer-files advertisement to {}",
        session.endpoint
    );
    Ok(())
}

async fn send_connected_server_startup(
    session: &mut ServerSession,
    shared_catalog: &Ed2kSharedCatalog,
    tcp_port: u16,
) -> Result<()> {
    session.set_phase(
        ServerSessionPhase::Connected,
        "server session accepted after OP_IDCHANGE",
    );
    send_offer_files_advertisement(session, shared_catalog, tcp_port).await?;
    send_server_list_request(session).await?;
    Ok(())
}

async fn send_server_list_request(session: &mut ServerSession) -> Result<()> {
    if session.server_list_requested {
        return Ok(());
    }
    session.send_packet(OP_GETSERVERLIST, &[]).await?;
    session.server_list_requested = true;
    dump_ed2k_server_meta(session, "requested server list after connected transition");
    Ok(())
}

async fn wait_for_offer_files_settle(session: &ServerSession) {
    let Some(sent_at) = session.offer_files_sent_at else {
        return;
    };
    let elapsed = sent_at.elapsed();
    if elapsed < OFFER_FILE_SEARCH_SETTLE_DELAY {
        tokio::time::sleep(OFFER_FILE_SEARCH_SETTLE_DELAY - elapsed).await;
    }
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

#[cfg(test)]
fn decode_search_results(payload: &[u8]) -> Result<SearchResultSummary> {
    let page = decode_search_result_page(payload)?;
    let sample_names = page
        .files
        .iter()
        .filter_map(|file| file.file_name.clone())
        .take(3)
        .collect::<Vec<_>>();
    Ok(SearchResultSummary {
        count: u32::try_from(page.files.len()).expect("search result count fits in u32"),
        sample_names,
    })
}

fn decode_search_result_page(payload: &[u8]) -> Result<SearchResultPage> {
    let (page, rest) = decode_search_result_page_from(payload)?;
    if !rest.is_empty() {
        anyhow::bail!(
            "unexpected ED2K search trailing data len={} after result page",
            rest.len()
        );
    }
    Ok(page)
}

fn decode_udp_search_result_pages(payload: &[u8]) -> Result<Vec<SearchResultPage>> {
    let mut cursor = payload;
    let mut pages = Vec::new();
    while !cursor.is_empty() {
        let (page, rest) = decode_search_result_page_from(cursor)?;
        pages.push(page);
        cursor = rest;
    }
    Ok(pages)
}

fn decode_search_result_page_from(payload: &[u8]) -> Result<(SearchResultPage, &[u8])> {
    if payload.len() < 4 {
        anyhow::bail!("short ED2K search results payload");
    }
    let count = u32::from_le_bytes(payload[..4].try_into().unwrap());
    let mut cursor = &payload[4..];
    let mut files = Vec::with_capacity(count as usize);

    for _ in 0..count {
        if cursor.len() < 26 {
            anyhow::bail!("short ED2K search result entry");
        }
        let file_hash = Ed2kHash(cursor[..16].try_into().unwrap());
        cursor = &cursor[16..];
        cursor = &cursor[4..];
        cursor = &cursor[2..];
        let tag_count = u32::from_le_bytes(cursor[..4].try_into().unwrap());
        cursor = &cursor[4..];
        let mut name = None;
        let mut size = None;
        let mut size_hi = None;
        let mut file_type = None;
        let mut source_count = None;
        for _ in 0..tag_count {
            let (tag_name, tag_value, rest) = decode_tag_value(cursor)?;
            cursor = rest;
            match (tag_name, tag_value) {
                (Some(FT_FILENAME), Some(DecodedTagValue::String(value))) if name.is_none() => {
                    name = Some(value);
                }
                (Some(FT_FILESIZE), Some(DecodedTagValue::Unsigned(value))) => {
                    size = Some(value);
                }
                (Some(FT_FILESIZE_HI), Some(DecodedTagValue::Unsigned(value))) => {
                    size_hi = Some(value);
                }
                (Some(FT_FILETYPE), Some(DecodedTagValue::String(value)))
                    if file_type.is_none() =>
                {
                    file_type = Some(value);
                }
                (Some(FT_SOURCES), Some(DecodedTagValue::Unsigned(value))) => {
                    source_count =
                        Some(u32::try_from(value).context("ED2K source count overflow")?);
                }
                _ => {}
            }
        }
        let file_size = match (size, size_hi) {
            (Some(value), Some(upper)) if value <= u32::MAX as u64 && upper != 0 => {
                Some((upper << 32) | value)
            }
            (Some(value), _) => Some(value),
            (None, Some(upper)) => Some(upper << 32),
            (None, None) => None,
        };
        files.push(Ed2kSearchFile {
            file_hash,
            file_name: name,
            file_size,
            file_type,
            source_count,
        });
    }

    let (more_results_available, rest) = match cursor {
        [] => (false, &[][..]),
        [marker @ (0x00 | 0x01)] => (*marker != 0, &[][..]),
        [marker @ (0x00 | 0x01), rest @ ..] if udp_chain_matches(rest, OP_GLOBSEARCHRES) => {
            (*marker != 0, &rest[2..])
        }
        rest if udp_chain_matches(rest, OP_GLOBSEARCHRES) => (false, &rest[2..]),
        [marker] => anyhow::bail!("invalid ED2K search More marker 0x{marker:02X}"),
        _ => anyhow::bail!(
            "unexpected ED2K search trailing data len={} after result page",
            cursor.len()
        ),
    };

    Ok((
        SearchResultPage {
            files,
            more_results_available,
        },
        rest,
    ))
}

fn decode_found_sources_from(
    payload: &[u8],
    obfuscated: bool,
) -> Result<(Vec<Ed2kFoundSource>, &[u8])> {
    if payload.len() < 17 {
        anyhow::bail!("short ED2K found-sources payload");
    }
    let file_hash = Ed2kHash(payload[..16].try_into().unwrap());
    let count = usize::from(payload[16]);
    let mut cursor = &payload[17..];
    let mut results = Vec::with_capacity(count);
    for _ in 0..count {
        if cursor.len() < 6 {
            anyhow::bail!("short ED2K found-sources entry");
        }
        let client_id = u32::from_le_bytes(cursor[..4].try_into().unwrap());
        let ip = ipv4_from_client_id(client_id);
        let tcp_port = u16::from_le_bytes(cursor[4..6].try_into().unwrap());
        let low_id = is_low_id(client_id);
        cursor = &cursor[6..];
        let mut obfuscation_options = None;
        let mut user_hash = None;
        if obfuscated {
            if cursor.is_empty() {
                anyhow::bail!("short ED2K obfuscated source options");
            }
            let options = cursor[0];
            cursor = &cursor[1..];
            obfuscation_options = Some(options);
            if options & 0x08 != 0 {
                if cursor.len() < 16 {
                    anyhow::bail!("short ED2K obfuscated source user hash");
                }
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&cursor[..16]);
                cursor = &cursor[16..];
                user_hash = Some(hash);
            }
        }
        results.push(Ed2kFoundSource {
            file_hash,
            ip,
            tcp_port,
            client_id,
            low_id,
            obfuscated,
            obfuscation_options,
            user_hash,
            source_server: None,
        });
    }

    let rest = if udp_chain_matches(cursor, OP_GLOBFOUNDSOURCES) {
        &cursor[2..]
    } else {
        cursor
    };
    Ok((results, rest))
}

fn udp_chain_matches(payload: &[u8], opcode: u8) -> bool {
    payload.len() >= 2 && payload[0] == OP_EDONKEYPROT && payload[1] == opcode
}

fn decode_tag(bytes: &[u8]) -> Result<(Option<u8>, Option<String>, &[u8])> {
    let (tag_name, tag_value, rest) = decode_tag_value(bytes)?;
    let string_value = match tag_value {
        Some(DecodedTagValue::String(value)) => Some(value),
        _ => None,
    };
    Ok((tag_name, string_value, rest))
}

fn decode_tag_value(mut bytes: &[u8]) -> Result<(Option<u8>, Option<DecodedTagValue>, &[u8])> {
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

    let decoded_value = match base_type {
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
            Some(DecodedTagValue::String(value))
        }
        TAGTYPE_STR1..=0x20 => {
            let len = usize::from(base_type - TAGTYPE_STR1 + 1);
            if bytes.len() < len {
                anyhow::bail!("short ED2K compact string tag value");
            }
            let value = String::from_utf8_lossy(&bytes[..len]).into_owned();
            bytes = &bytes[len..];
            Some(DecodedTagValue::String(value))
        }
        TAGTYPE_UINT32 => {
            if bytes.len() < 4 {
                anyhow::bail!("short ED2K uint32 tag value");
            }
            let value = u32::from_le_bytes(bytes[..4].try_into().unwrap());
            bytes = &bytes[4..];
            Some(DecodedTagValue::Unsigned(u64::from(value)))
        }
        TAGTYPE_UINT64 => {
            if bytes.len() < 8 {
                anyhow::bail!("short ED2K uint64 tag value");
            }
            let value = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            bytes = &bytes[8..];
            Some(DecodedTagValue::Unsigned(value))
        }
        TAGTYPE_UINT16 => {
            if bytes.len() < 2 {
                anyhow::bail!("short ED2K uint16 tag value");
            }
            let value = u16::from_le_bytes(bytes[..2].try_into().unwrap());
            bytes = &bytes[2..];
            Some(DecodedTagValue::Unsigned(u64::from(value)))
        }
        TAGTYPE_UINT8 | TAGTYPE_BOOL => {
            if bytes.is_empty() {
                anyhow::bail!("short ED2K uint8/bool tag value");
            }
            let value = bytes[0];
            bytes = &bytes[1..];
            if base_type == TAGTYPE_BOOL {
                Some(DecodedTagValue::Bool(value != 0))
            } else {
                Some(DecodedTagValue::Unsigned(u64::from(value)))
            }
        }
        TAGTYPE_FLOAT32 => {
            if bytes.len() < 4 {
                anyhow::bail!("short ED2K float32 tag value");
            }
            let value = f32::from_le_bytes(bytes[..4].try_into().unwrap());
            bytes = &bytes[4..];
            Some(DecodedTagValue::Float32(value))
        }
        TAGTYPE_HASH => {
            if bytes.len() < 16 {
                anyhow::bail!("short ED2K hash tag value");
            }
            let value: [u8; 16] = bytes[..16].try_into().unwrap();
            bytes = &bytes[16..];
            Some(DecodedTagValue::Hash(value))
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
            let value = bytes[..byte_len].to_vec();
            bytes = &bytes[byte_len..];
            Some(DecodedTagValue::BoolArray(value))
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
            let value = bytes[..blob_len].to_vec();
            bytes = &bytes[blob_len..];
            Some(DecodedTagValue::Blob(value))
        }
        _ => anyhow::bail!("unsupported ED2K tag type 0x{base_type:02X}"),
    };

    Ok((tag_name, decoded_value, bytes))
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
        BackgroundServerSearchRequest, CT_EMULE_VERSION, CT_NAME, CT_SERVER_FLAGS, CT_VERSION,
        ConfiguredServerEntry, EDONKEY_VERSION, EMULE_ENCRYPTION_METHOD_OBFUSCATION,
        EMULE_TCP_CRYPT_MAGIC_REQUESTER, EMULE_TCP_CRYPT_MAGIC_SERVER, EMULE_TCP_CRYPT_MAGIC_SYNC,
        EMULE_VERSION_MAJOR, EMULE_VERSION_MINOR, EMULE_VERSION_UPDATE, Ed2kFoundSource, Ed2kHash,
        Ed2kSearchFile, Ed2kServerState, FT_FILENAME, FT_FILESIZE, FT_FILETYPE, FT_SOURCES,
        HELLO_NICKNAME, OFFER_FILE_SAMPLE_HASH, OFFER_FILE_SAMPLE_NAME, OFFER_FILE_SAMPLE_SIZE,
        OP_EDONKEYPROT, OP_GETSERVERLIST, OP_GETSOURCES, OP_GETSOURCES_OBFU, OP_LOGINREQUEST,
        OP_OFFERFILES, OP_PACKEDPROT, ResolvedServerEntry, SERVER_OBFUSCATION_PRIME_BYTES,
        SERVER_OBFUSCATION_PUBLIC_KEY_LEN, SERVER_TCP_FLAG_COMPRESSION, SERVER_TCP_FLAG_LARGEFILES,
        SERVER_TCP_FLAG_TCPOBFUSCATION, SERVER_UDP_FLAG_UDPOBFUSCATION, ST_DESCRIPTION,
        ST_SERVERNAME, ServerSession, TAG_SHORT_NAME_MASK, TAGTYPE_UINT32, biguint_to_fixed_be,
        decode_found_sources, decode_search_result_page, decode_search_results,
        decode_server_ident, decode_server_payload, derive_server_cipher, encode_login_request,
        encode_offer_files_payload, encode_packet, encode_search_request, encode_source_request,
        format_server_flags, ipv4_from_client_id, login_identity_for_server_transport,
        new_ed2k_server_search_channel, search_keyword_via_background_session,
        search_source_via_background_session, server_capabilities, should_use_server_obfuscation,
        source_request_opcode, validate_found_sources,
    };
    use crate::{
        ed2k_tcp::{Ed2kHelloIdentity, emule_connect_options},
        ed2k_transfer::Ed2kSharedEntry,
    };
    use flate2::{Compression, write::ZlibEncoder};
    use hex::decode;
    use num_bigint::BigUint;
    use std::{io::Write, net::Ipv4Addr, sync::Arc, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::RwLock,
    };
    use tokio_util::sync::CancellationToken;

    fn test_server(obfuscation_port_tcp: u16, udp_flags: u32) -> ResolvedServerEntry {
        ResolvedServerEntry {
            entry: ConfiguredServerEntry {
                host: "127.0.0.1".to_string(),
                port: 4661,
                name: Some("test".to_string()),
                description: None,
                udp_flags,
                udp_key: 0,
                udp_key_ip: 0,
                obfuscation_port_tcp,
                obfuscation_port_udp: 0,
            },
            ip: Ipv4Addr::LOCALHOST,
        }
    }

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
            direct_udp_callback: false,
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
            direct_udp_callback: false,
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
                direct_udp_callback: false,
            }),
            false,
        )
        .unwrap();

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
                direct_udp_callback: false,
            }),
            false,
        )
        .unwrap();

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
            &test_server(0, 0)
        ));
    }

    #[test]
    fn server_obfuscation_requires_positive_server_metadata() {
        assert!(should_use_server_obfuscation(
            emule_connect_options(true),
            &test_server(4661, SERVER_UDP_FLAG_UDPOBFUSCATION)
        ));
    }

    #[test]
    fn packet_encoder_uses_ed2k_framing() {
        let packet = encode_packet(OP_GETSERVERLIST, &[], false).unwrap();
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
    fn packet_encoder_uses_packed_framing_when_requested() {
        let packet = encode_packet(OP_GETSERVERLIST, &[], true).unwrap();
        assert_eq!(packet[0], OP_PACKEDPROT);
        let decoded = decode_server_payload(OP_PACKEDPROT, packet[6..].to_vec()).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(packet[5], OP_GETSERVERLIST);
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

        assert_eq!(payload[0], 1);
        assert_eq!(u16::from_le_bytes([payload[1], payload[2]]), 12);
        assert_eq!(&payload[3..15], b"ubuntu linux");
    }

    #[test]
    fn search_probe_encoding_preserves_boolean_query_tree_shape() {
        let payload = encode_search_request("ubuntu OR linux").unwrap();

        assert_eq!(payload[0], 0);
        assert_eq!(payload[1], 0x01);
        assert_eq!(payload[2], 1);
        assert_eq!(u16::from_le_bytes([payload[3], payload[4]]), 6);
        assert_eq!(&payload[5..11], b"ubuntu");
        assert_eq!(payload[11], 1);
        assert_eq!(u16::from_le_bytes([payload[12], payload[13]]), 5);
        assert_eq!(&payload[14..19], b"linux");
    }

    #[test]
    fn plaintext_server_sessions_clear_crypt_capability_bits() {
        let identity = login_identity_for_server_transport(
            Ed2kHelloIdentity {
                user_hash: [0x33; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(true),
                direct_udp_callback: false,
            },
            false,
        );

        assert_eq!(identity.connect_options, 0);
    }

    #[test]
    fn offer_files_payload_matches_oracle_search_session_sample() {
        let shared_catalog = vec![Ed2kSharedEntry {
            file_hash: hex::encode(OFFER_FILE_SAMPLE_HASH),
            canonical_name: OFFER_FILE_SAMPLE_NAME.to_string(),
            file_size: u64::from(OFFER_FILE_SAMPLE_SIZE),
            verified_complete: false,
            verified_ranges: Vec::new(),
            compatibility_hint: true,
            source_count_hint: Some(12),
        }];
        let packet = encode_packet(
            OP_OFFERFILES,
            &encode_offer_files_payload(
                &shared_catalog,
                Some(0x521B_5895),
                46671,
                Some(SERVER_TCP_FLAG_COMPRESSION),
            ),
            false,
        )
        .unwrap();

        let expected = decode(
            "e34a00000015010000009f3c23db7651efbac9a837a8a0ae3ed9fbfbfbfbfbfb0300000082011e007562756e74752d6c696e75782d6f7261636c652d73616d706c652e69736f830200002000890304",
        )
        .unwrap();

        assert_eq!(packet, expected);
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
        payload.push(0x00);

        let summary = decode_search_results(&payload).unwrap();

        assert_eq!(summary.count, 1);
        assert_eq!(summary.sample_names, vec!["ubuntu.iso".to_string()]);
    }

    #[test]
    fn search_results_decoder_extracts_size_type_and_sources() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&[0x22; 16]);
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&4662u16.to_le_bytes());
        payload.extend_from_slice(&4u32.to_le_bytes());
        payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 9));
        payload.push(FT_FILENAME);
        payload.extend_from_slice(b"ubuntu.iso");
        payload.push(super::TAGTYPE_UINT64);
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.push(FT_FILESIZE);
        payload.extend_from_slice(&4_294_967_300u64.to_le_bytes());
        payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 4));
        payload.push(FT_FILETYPE);
        payload.extend_from_slice(b"Video");
        payload.push(TAGTYPE_UINT32);
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.push(FT_SOURCES);
        payload.extend_from_slice(&12u32.to_le_bytes());
        payload.push(0x01);

        let page = decode_search_result_page(&payload).unwrap();
        let files = page.files;

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_name.as_deref(), Some("ubuntu.iso"));
        assert_eq!(files[0].file_size, Some(4_294_967_300));
        assert_eq!(files[0].file_type.as_deref(), Some("Video"));
        assert_eq!(files[0].source_count, Some(12));
        assert!(page.more_results_available);
    }

    #[test]
    fn search_results_decoder_rejects_invalid_more_marker() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.push(0x7F);

        let error = decode_search_result_page(&payload).unwrap_err().to_string();

        assert!(error.contains("More marker"));
    }

    #[test]
    fn found_sources_decoder_extracts_plain_sources() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0xAA; 16]);
        payload.push(1);
        payload.extend_from_slice(&[10, 20, 30, 40]);
        payload.extend_from_slice(&4662u16.to_le_bytes());

        let sources = decode_found_sources(&payload, false).unwrap();
        let client_id = u32::from_le_bytes([10, 20, 30, 40]);

        assert_eq!(
            sources,
            vec![Ed2kFoundSource {
                file_hash: Ed2kHash([0xAA; 16]),
                ip: Ipv4Addr::new(10, 20, 30, 40),
                tcp_port: 4662,
                client_id,
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            }]
        );
    }

    #[test]
    fn found_sources_decoder_marks_low_id_sources_as_callback_only() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0xAB; 16]);
        payload.push(1);
        payload.extend_from_slice(&34254u32.to_le_bytes());
        payload.extend_from_slice(&4662u16.to_le_bytes());

        let sources = decode_found_sources(&payload, false).unwrap();
        let client_id = 34254u32;

        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].client_id, client_id);
        assert_eq!(sources[0].ip, ipv4_from_client_id(client_id));
        assert!(sources[0].low_id);
        assert!(!sources[0].is_direct_dialable());
    }

    #[test]
    fn source_request_encoding_includes_u32_size_for_small_files() {
        let payload = encode_source_request(Ed2kHash([0xAB; 16]), 734_003_200);

        assert_eq!(&payload[..16], &[0xAB; 16]);
        assert_eq!(
            u32::from_le_bytes(payload[16..20].try_into().unwrap()),
            734_003_200
        );
        assert_eq!(payload.len(), 20);
    }

    #[test]
    fn source_request_encoding_uses_large_file_sentinel() {
        let payload = encode_source_request(Ed2kHash([0xCD; 16]), 4_294_967_301);

        assert_eq!(&payload[..16], &[0xCD; 16]);
        assert_eq!(u32::from_le_bytes(payload[16..20].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_le_bytes(payload[20..28].try_into().unwrap()),
            4_294_967_301
        );
    }

    #[test]
    fn source_request_opcode_uses_obfuscated_variant_when_supported() {
        assert_eq!(
            source_request_opcode(0x01, Some(SERVER_TCP_FLAG_TCPOBFUSCATION), true),
            OP_GETSOURCES_OBFU
        );
        assert_eq!(
            source_request_opcode(0x00, Some(SERVER_TCP_FLAG_TCPOBFUSCATION), true),
            OP_GETSOURCES
        );
        assert_eq!(
            source_request_opcode(0x01, Some(SERVER_TCP_FLAG_TCPOBFUSCATION), false),
            OP_GETSOURCES
        );
    }

    #[test]
    fn found_sources_validation_rejects_hash_mismatch() {
        let error = validate_found_sources(
            &[Ed2kFoundSource {
                file_hash: Ed2kHash([0xAA; 16]),
                ip: Ipv4Addr::new(1, 2, 3, 4),
                tcp_port: 4662,
                client_id: u32::from(Ipv4Addr::new(1, 2, 3, 4)),
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            }],
            Ed2kHash([0xBB; 16]),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unexpected file hash"));
    }

    #[tokio::test]
    async fn background_search_channel_round_trips_results() {
        let (handle, mut inbox) = new_ed2k_server_search_channel(1);
        let cancel = CancellationToken::new();
        let expected = Ed2kSearchFile {
            file_hash: Ed2kHash([0x44; 16]),
            file_name: Some("ubuntu.iso".to_string()),
            file_size: Some(123),
            file_type: Some("Doc".to_string()),
            source_count: Some(7),
        };
        let expected_for_task = expected.clone();

        let responder = tokio::spawn(async move {
            let request = inbox.receiver.recv().await.unwrap();
            match request {
                BackgroundServerSearchRequest::Keyword {
                    query, response, ..
                } => {
                    assert_eq!(query, "ubuntu linux");
                    let _ = response.send(Ok(vec![expected_for_task]));
                }
                other => panic!("unexpected background request: {other:?}"),
            }
        });

        let results = search_keyword_via_background_session(
            &handle,
            "ubuntu linux",
            Duration::from_secs(1),
            &cancel,
        )
        .await
        .unwrap();

        assert_eq!(results, vec![expected]);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn background_source_search_channel_round_trips_results() {
        let (handle, mut inbox) = new_ed2k_server_search_channel(1);
        let cancel = CancellationToken::new();
        let file_hash = Ed2kHash([0x51; 16]);
        let expected = Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::new(10, 20, 30, 40),
            tcp_port: 4662,
            client_id: u32::from_le_bytes([10, 20, 30, 40]),
            low_id: false,
            obfuscated: true,
            obfuscation_options: Some(0x03),
            user_hash: Some([0x61; 16]),
            source_server: None,
        };
        let expected_for_task = expected.clone();

        let responder = tokio::spawn(async move {
            let request = inbox.receiver.recv().await.unwrap();
            match request {
                BackgroundServerSearchRequest::Source {
                    file_hash: requested_hash,
                    file_size,
                    response,
                    ..
                } => {
                    assert_eq!(requested_hash, file_hash);
                    assert_eq!(file_size, 42);
                    let _ = response.send(Ok(vec![expected_for_task]));
                }
                other => panic!("unexpected background request: {other:?}"),
            }
        });

        let results = search_source_via_background_session(
            &handle,
            file_hash,
            42,
            Duration::from_secs(1),
            &cancel,
        )
        .await
        .unwrap();

        assert_eq!(results, vec![expected]);
        responder.await.unwrap();
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
            direct_udp_callback: false,
        };
        let expected_login = encode_packet(
            OP_LOGINREQUEST,
            &encode_login_request(hello_identity),
            false,
        )
        .unwrap();
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
        let mut session = ServerSession::connect(
            Ipv4Addr::LOCALHOST,
            endpoint,
            state,
            "test",
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        session
            .negotiate_obfuscation_and_send(&expected_login)
            .await
            .unwrap();

        server.await.unwrap();
    }
}
