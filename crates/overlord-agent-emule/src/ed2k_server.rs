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
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use num_bigint::BigUint;
use rand::{Rng, RngCore};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream, UdpSocket},
    sync::{Mutex, RwLock},
    time::Instant as TokioInstant,
};
use tracing::{debug, info, warn};

use overlord_agent_nat::NatManager;
use overlord_kad_proto::Ed2kHash;

use crate::{
    config::Ed2kConfig,
    ed2k_tcp::{Ed2kHelloIdentity, connect_callback_peer, enrich_hello_identity},
    ed2k_transfer::{Ed2kSharedCatalog, Ed2kSharedEntry},
    kad_firewall::KadFirewallState,
};

mod active_callback;
mod active_keyword;
mod active_source;
mod background;
mod diagnostics;
mod flags;
mod obfuscation;
mod packet_codec;
mod result_decoder;
mod search_expr;
mod server_entry;
mod tag_codec;
mod udp;
pub use active_callback::{Ed2kCallbackRequestOptions, request_callback_on_server};
pub use active_keyword::{Ed2kKeywordSearchOptions, search_keyword_servers};
pub use active_source::{
    Ed2kSourceSearchOptions, Ed2kUdpSourceSearchOptions, search_source_servers,
    search_source_udp_servers,
};
use background::{
    BackgroundServerSearchRequest, PendingBackgroundServerSearch, fail_background_search_request,
    fail_pending_background_search, handle_background_udp_packet, log_search_result_page,
    start_background_server_search,
};
pub use background::{
    Ed2kServerSearchHandle, Ed2kServerSearchInbox, new_ed2k_server_search_channel,
    request_callback_via_background_session, search_keyword_via_background_session,
    search_source_via_background_session,
};
use diagnostics::{dump_ed2k_server_meta, dump_ed2k_server_packet};
use flags::{format_connect_options, format_server_flags, is_low_id};
use obfuscation::{
    Rc4KeyStream, biguint_to_fixed_be, derive_server_cipher, random_non_protocol_marker,
    random_nonzero_biguint, should_use_server_obfuscation,
};
use packet_codec::{decode_server_payload, encode_packet};
use result_decoder::{
    decode_found_sources, decode_search_result_page, decode_udp_found_source_sets,
    decode_udp_search_result_pages,
};
use search_expr::encode_search_request;
use server_entry::{
    ResolvedServerEntry, configured_server_entries, resolve_callback_server_entry,
    resolve_server_entry,
};
use tag_codec::{
    decode_ed2k_string, decode_tag, push_short_string_tag, push_short_u8_tag, push_short_u32_tag,
    push_string_tag, push_u32_tag,
};
use udp::{decode_server_udp_datagram, encode_server_udp_datagram, server_udp_endpoint};

#[cfg(test)]
use server_entry::ConfiguredServerEntry;

#[cfg(test)]
use result_decoder::decode_search_results;

#[cfg(test)]
use tag_codec::ed2k_string_tag_type;

#[cfg(test)]
use udp::derive_server_udp_cipher;

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
const EMULE_VERSION_MINOR: u32 = 72;
const EMULE_VERSION_UPDATE: u32 = 0;
// Stock eMule reads the nick from preferences. Until the agent grows an
// operator-configurable nick surface, keep a neutral stock-like default
// instead of the earlier project URL identity.
const HELLO_NICKNAME: &str = "eMule";

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
const SOURCE_OBFUSCATION_USER_HASH_PRESENT: u8 = 0x80;
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
const EMULE_UDP_CRYPT_HEADER_LEN: usize = 8;
const EMULE_UDP_CRYPT_MAGIC_SYNC_SERVER: u32 = 0x13EF_24D5;
const EMULE_UDP_CRYPT_MAGIC_CLIENT_SERVER: u8 = 0x6B;
const EMULE_UDP_CRYPT_MAGIC_SERVER_CLIENT: u8 = 0xA5;
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
    offer_files_catalog_fingerprint: Option<u64>,
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
            offer_files_catalog_fingerprint: None,
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

/// Inputs for the long-lived ED2K server session loop.
pub struct Ed2kServerLoopOptions {
    pub bind_ip: Ipv4Addr,
    pub nat: Arc<NatManager>,
    pub config: Ed2kConfig,
    pub hello_identity: Ed2kHelloIdentity,
    pub shared_catalog: Ed2kSharedCatalog,
    pub state: Arc<RwLock<Ed2kServerState>>,
    pub search_inbox: Ed2kServerSearchInbox,
    pub kad_firewall: Arc<Mutex<KadFirewallState>>,
    pub shutdown: Arc<AtomicBool>,
}

/// Runs the minimal oracle-shaped ED2K server session loop for the configured endpoints.
pub async fn run_ed2k_server_loop(options: Ed2kServerLoopOptions) {
    let Ed2kServerLoopOptions {
        bind_ip,
        nat,
        config,
        hello_identity,
        shared_catalog,
        state,
        mut search_inbox,
        kad_firewall,
        shutdown,
    } = options;
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
            }, if queued_background_search.is_none() && pending_background_search.is_none() => {
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
                    read_server_udp_packet(socket, server).await
                } else {
                    std::future::pending::<Result<Option<ServerUdpPacket>>>().await
                }
            } => {
                match udp_packet {
                    Ok(Some(packet)) => {
                        handle_background_udp_packet(
                            server,
                            &packet,
                            &mut pending_background_search,
                            &context.state,
                        )?;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!(
                            "ignoring ED2K server UDP helper receive failure for {}: {error}",
                            server.base_endpoint()
                        );
                    }
                }
            }
            _ = tokio::time::sleep(context.keepalive_interval) => {
                if session.last_tx.elapsed() >= context.keepalive_interval {
                    send_offer_files_advertisement(
                        &mut session,
                        &context.shared_catalog,
                        context.hello_identity.tcp_port,
                    )
                    .await?;
                    if session.last_tx.elapsed() >= context.keepalive_interval {
                        session.send_packet(OP_OFFERFILES, &0u32.to_le_bytes()).await?;
                        debug!("sent ED2K server keepalive to {}", server.base_endpoint());
                    }
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

async fn clear_server_connection_state(state: &Arc<RwLock<Ed2kServerState>>) {
    let mut guard = state.write().await;
    guard.connected = false;
    guard.endpoint = None;
    guard.client_id = None;
    guard.server_flags = None;
}

async fn bind_server_udp_socket(bind_ip: Ipv4Addr) -> Result<UdpSocket> {
    UdpSocket::bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
        .await
        .with_context(|| format!("failed to bind ED2K server UDP helper on {bind_ip}:0"))
}

async fn send_server_udp_packet(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
    opcode: u8,
    payload: &[u8],
) -> Result<()> {
    let (endpoint, packet) = encode_server_udp_datagram(server, opcode, payload);
    socket.send_to(&packet, endpoint).await.with_context(|| {
        format!(
            "failed to send ED2K server UDP opcode=0x{opcode:02X} to {}",
            endpoint
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

async fn read_server_udp_packet(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
) -> Result<Option<ServerUdpPacket>> {
    let mut buffer = vec![0u8; 65_535];
    let (len, from) = socket
        .recv_from(&mut buffer)
        .await
        .context("failed to receive ED2K server UDP datagram")?;
    let Some(packet) = decode_server_udp_datagram(server, &buffer[..len]) else {
        return Ok(None);
    };
    if packet.len() < 2 || packet[0] != OP_EDONKEYPROT {
        return Ok(None);
    }
    Ok(Some(ServerUdpPacket {
        opcode: packet[1],
        payload: packet[2..].to_vec(),
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

fn login_identity_for_server_transport(
    identity: Ed2kHelloIdentity,
    use_server_obfuscation: bool,
) -> Ed2kHelloIdentity {
    let _ = use_server_obfuscation;
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

/// Encode the ED2K local-server source request payload.
///
/// Modern eMule sends the file hash plus file size in the TCP local-server
/// source-request path. Large files use the `0` sentinel followed by a `u64`.
/// When the caller does not yet know the file size, fall back to the legacy
/// hash-only payload so hash-only live probes can still acquire sources.
fn encode_source_request(file_hash: Ed2kHash, file_size: u64) -> Vec<u8> {
    if file_size == 0 {
        return file_hash.0.to_vec();
    }
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

fn source_request_opcode(connect_options: u8, server_flags: Option<u32>) -> u8 {
    // A source-search session may still need the obfuscated reply family even
    // when the TCP session itself stayed plaintext because the configured
    // server entry lacked an obfuscation port. Once OP_IDCHANGE confirms the
    // server supports TCP obfuscation, prefer the obfuscated found-sources
    // shape so peer user-hash metadata is preserved.
    if connect_options != 0
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

fn offer_files_catalog_fingerprint(shared_catalog: &[Ed2kSharedEntry]) -> u64 {
    let mut hasher = DefaultHasher::new();
    offered_files_catalog(shared_catalog).hash(&mut hasher);
    hasher.finish()
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

async fn send_offer_files_advertisement(
    session: &mut ServerSession,
    shared_catalog: &Ed2kSharedCatalog,
    tcp_port: u16,
) -> Result<()> {
    let shared_catalog = shared_catalog.read().await.clone();
    let catalog_fingerprint = offer_files_catalog_fingerprint(&shared_catalog);
    if session.offer_files_sent
        && session.offer_files_catalog_fingerprint == Some(catalog_fingerprint)
    {
        return Ok(());
    }
    let payload = encode_offer_files_payload(
        &shared_catalog,
        session.assigned_client_id,
        tcp_port,
        session.server_flags,
    );
    let was_sent = session.offer_files_sent;
    session.send_packet(OP_OFFERFILES, &payload).await?;
    session.offer_files_sent = true;
    session.offer_files_sent_at = Some(Instant::now());
    session.offer_files_catalog_fingerprint = Some(catalog_fingerprint);
    session.set_phase(
        ServerSessionPhase::OfferFilesSent,
        format!(
            "{} offer-files advertisement entries={}",
            if was_sent { "refreshed" } else { "sent" },
            offered_files_catalog(&shared_catalog).len()
        ),
    );
    debug!(
        "{} ED2K offer-files advertisement to {}",
        if was_sent { "refreshed" } else { "sent" },
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
mod tests;
