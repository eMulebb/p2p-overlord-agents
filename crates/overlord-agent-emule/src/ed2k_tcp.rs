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
//! The listener intentionally does not claim full eD2k file-transfer support,
//! but it now serves the verified upload subset that peers expect once they
//! choose us as a source:
//! - filename, file-status, and hashset answers for known files
//! - upload-intent acknowledgement
//! - range serving with eMule-style part fragmentation and optional compression

use std::{
    io,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock},
};
use tracing::{debug, info, warn};

use crate::ed2k_server::Ed2kServerState;
#[cfg(test)]
use crate::ed2k_transfer::ED2K_EMBLOCK_SIZE;
use crate::ed2k_transfer::{
    Ed2kAichHashset, Ed2kResumeManifest, Ed2kSharedEntry, Ed2kTransferRuntime,
    Ed2kUploadPeerIdentity, Ed2kUploadSessionHandle, Ed2kUploadSessionStatus, decode_aich_hash_hex,
};
use crate::kad_firewall::KadFirewallState;
use overlord_kad_dht::DhtNode;
use overlord_kad_proto::{Ed2kHash, FirewallUdp, KadPacket};

mod codec;
mod download;
mod dump;
mod firewall_helper;
mod hello;
mod identity;
mod obfuscation;
mod transport;
use codec::{
    build_upload_part_packets, decode_aich_file_hash_answer, decode_compressed_part_fragment,
    decode_file_hash_payload, decode_file_status_payload, decode_hashset_answer,
    decode_hashset_answer2, decode_hashset_request2, decode_peer_payload,
    decode_request_filename_answer, decode_request_filename_answer_body,
    decode_request_parts_payload, decode_request_sources_payload, decode_sending_part_payload,
    encode_accept_upload_req, encode_aich_file_hash_request, encode_answer_sources_empty,
    encode_answer_sources2_empty, encode_file_req_ans_nofil, encode_file_status_complete,
    encode_hashset_answer, encode_hashset_answer2, encode_hashset_request, encode_hashset_request2,
    encode_multipacket_ext2_answer, encode_multipacket_ext2_request, encode_packet,
    encode_queue_ranking, encode_request_filename, encode_request_filename_answer,
    encode_request_parts_batch, encode_request_sources2, encode_set_req_file_id,
    encode_start_upload_req, inflate_compressed_part_fragment, skip_file_status_body,
    skip_request_filename_ext_info,
};
#[cfg(test)]
use codec::{
    encode_compressed_part_fragment, encode_packed_packet, encode_request_sources2_subpayload,
    encode_sending_part,
};
use download::{DownloadSessionOptions, PendingCompressedPart, drive_download_session};
#[cfg(test)]
use download::{DownloadWindowLimits, next_download_read_timeout, select_download_window_limits};
pub(crate) use download::{
    Ed2kPeerDownloadOptions, Ed2kPeerDownloadOutcome, download_file_from_peer,
};
pub(crate) use dump::dump_ed2k_tcp_download_meta;
use dump::{
    dump_ed2k_tcp_download_recv, dump_ed2k_tcp_download_send, dump_ed2k_tcp_listener_meta,
    dump_ed2k_tcp_listener_recv, dump_ed2k_tcp_listener_send,
};
pub use firewall_helper::request_udp_firewall_check;
pub(crate) use firewall_helper::{
    connect_callback_peer, emule_connect_options, is_connection_shutdown_error,
};
use hello::{
    DecodedHelloIdentity, build_hello_responses, decode_hello_profile, encode_emule_info_answer,
    encode_hello_answer, encode_hello_request, is_mule_hello, is_mule_hello_answer,
};
#[cfg(test)]
use hello::{
    ed2k_string_tag_type, emule_misc_options1, emule_misc_options2, emule_version_tag,
    encode_emule_info_request,
};
pub use identity::Ed2kSecureIdent;
use identity::{
    Ed2kPeerSecureIdentState, begin_secure_ident_probe, decode_public_key_payload,
    decode_secident_state, encode_secident_state, random_nonzero_u32,
    try_send_secure_ident_signature,
};
use obfuscation::{
    Rc4KeyStream, accept_incoming_obfuscation_handshake, is_plain_ed2k_protocol_marker,
    negotiate_outgoing_obfuscation_handshake, should_enable_outgoing_obfuscation,
};
#[cfg(test)]
use obfuscation::{
    decode_incoming_obfuscation_header, derive_obfuscation_key,
    encode_incoming_obfuscation_response,
};
pub use transport::EmuleTcpPacket;
use transport::{Ed2kTransport, Ed2kTransportMode};

const OP_EMULEPROT: u8 = 0xC5;
const OP_EDONKEYPROT: u8 = 0xE3;
const OP_PACKEDPROT: u8 = 0xD4;
const OP_HELLO: u8 = 0x01;
const OP_HELLOANSWER: u8 = 0x4C;
const OP_COMPRESSEDPART: u8 = 0x40;
const OP_SENDINGPART: u8 = 0x46;
const OP_REQUESTPARTS: u8 = 0x47;
const OP_FILEREQANSNOFIL: u8 = 0x48;
const OP_SETREQFILEID: u8 = 0x4F;
const OP_FILESTATUS: u8 = 0x50;
const OP_HASHSETREQUEST: u8 = 0x51;
const OP_HASHSETANSWER: u8 = 0x52;
const OP_STARTUPLOADREQ: u8 = 0x54;
const OP_ACCEPTUPLOADREQ: u8 = 0x55;
const OP_CANCELTRANSFER: u8 = 0x56;
const OP_REQUESTFILENAME: u8 = 0x58;
const OP_REQFILENAMEANSWER: u8 = 0x59;
const OP_QUEUERANKING: u8 = 0x60;
const OP_FILEDESC: u8 = 0x61;
const OP_REQUESTSOURCES: u8 = 0x81;
const OP_ANSWERSOURCES: u8 = 0x82;
const OP_REQUESTSOURCES2: u8 = 0x83;
const OP_ANSWERSOURCES2: u8 = 0x84;
const OP_AICHFILEHASHANS: u8 = 0x9D;
const OP_AICHFILEHASHREQ: u8 = 0x9E;
const OP_COMPRESSEDPART_I64: u8 = 0xA1;
const OP_SENDINGPART_I64: u8 = 0xA2;
const OP_REQUESTPARTS_I64: u8 = 0xA3;
const OP_MULTIPACKET_EXT2: u8 = 0xA9;
const OP_MULTIPACKETANSWER_EXT2: u8 = 0xB0;
const OP_HASHSETREQUEST2: u8 = 0xB1;
const OP_HASHSETANSWER2: u8 = 0xB2;
const OP_EMULEINFO: u8 = 0x01;
const OP_EMULEINFOANSWER: u8 = 0x02;
const OP_PUBLICKEY: u8 = 0x85;
const OP_SIGNATURE: u8 = 0x86;
const OP_SECIDENTSTATE: u8 = 0x87;
const OP_FWCHECKUDPREQ: u8 = 0xA7;
const TCP_PACKET_HEADER_LEN: usize = 6;
const MAX_PEER_DECOMPRESSED_PACKET_LEN: usize = 50_000;
const ED2K_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const ED2K_UPLOAD_QUEUE_POLL_INTERVAL: Duration = Duration::from_millis(500);
#[cfg(not(test))]
const ED2K_UPLOAD_QUEUE_REFRESH_INTERVAL: Duration = Duration::from_secs(10);
#[cfg(test)]
const ED2K_UPLOAD_QUEUE_REFRESH_INTERVAL: Duration = Duration::from_millis(200);
const FIREWALL_HELPER_POST_REQUEST_KEEPALIVE_SECS: u64 = 10;
const ED2K_UPLOAD_PACKET_SPLIT_THRESHOLD: usize = 13_000;
const ED2K_UPLOAD_PACKET_FRAGMENT_LEN: usize = 10_240;

const EMULE_PROTOCOL_VERSION: u8 = 0x01;
const EDONKEY_VERSION: u32 = 0x3C;
const EMULE_VERSION_MAJOR: u32 = 0;
const EMULE_VERSION_MINOR: u32 = 72;
const EMULE_VERSION_UPDATE: u32 = 0;
const EMULE_VERSION_SHORT: u8 = EMULE_VERSION_MINOR as u8;
const EMULE_SECURE_IDENT_VERSION: u32 = 3;
const EMULE_INFO_FEATURES: u32 = 3;
const EMULE_ADVERTISED_KAD_VERSION: u32 = 10;
const ED2K_SOURCE_EXCHANGE2_VERSION: u8 = 4;

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

// Stock eMule reads the nick from preferences. Until the agent grows an
// operator-configurable nick surface, keep a neutral stock-like default
// instead of the earlier project URL identity.
const HELLO_NICKNAME: &str = "eMule";

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ed2kFileIdentifier {
    file_hash: Ed2kHash,
    file_size: Option<u64>,
    aich_root: Option<[u8; 20]>,
}

impl Ed2kFileIdentifier {
    const INCLUDE_MD4: u8 = 1 << 0;
    const INCLUDE_SIZE: u8 = 1 << 1;
    const INCLUDE_AICH: u8 = 1 << 2;
    const RESERVED_BITS: u8 = 0xF8;

    fn from_manifest(manifest: &Ed2kResumeManifest) -> Result<Self> {
        Ok(Self {
            file_hash: Ed2kHash::from_str(&manifest.file_hash)
                .with_context(|| format!("invalid manifest file hash {}", manifest.file_hash))?,
            file_size: Some(manifest.file_size).filter(|file_size| *file_size != 0),
            aich_root: manifest
                .aich_root
                .as_deref()
                .map(decode_aich_hash_hex)
                .transpose()?,
        })
    }

    fn from_shared_entry(shared: &Ed2kSharedEntry) -> Result<Self> {
        Ok(Self {
            file_hash: shared.parsed_hash()?,
            file_size: Some(shared.file_size).filter(|file_size| *file_size != 0),
            aich_root: shared
                .aich_root
                .as_deref()
                .map(decode_aich_hash_hex)
                .transpose()?,
        })
    }

    fn encode_into(&self, payload: &mut Vec<u8>) {
        let mut descriptor = Self::INCLUDE_MD4;
        if self.file_size.is_some() {
            descriptor |= Self::INCLUDE_SIZE;
        }
        if self.aich_root.is_some() {
            descriptor |= Self::INCLUDE_AICH;
        }
        payload.push(descriptor);
        payload.extend_from_slice(&self.file_hash.0);
        if let Some(file_size) = self.file_size {
            payload.extend_from_slice(&file_size.to_le_bytes());
        }
        if let Some(aich_root) = self.aich_root {
            payload.extend_from_slice(&aich_root);
        }
    }

    fn decode(payload: &[u8]) -> Result<(Self, &[u8])> {
        let Some((&descriptor, mut rest)) = payload.split_first() else {
            anyhow::bail!("short ED2K FileIdentifier descriptor");
        };
        if descriptor & Self::RESERVED_BITS != 0 {
            anyhow::bail!("unsupported ED2K FileIdentifier descriptor 0x{descriptor:02X}");
        }
        if descriptor & Self::INCLUDE_MD4 == 0 {
            anyhow::bail!("ED2K FileIdentifier missing mandatory MD4 hash");
        }
        if rest.len() < 16 {
            anyhow::bail!("short ED2K FileIdentifier MD4 hash");
        }
        let file_hash = Ed2kHash::from_bytes(rest[..16].try_into().unwrap());
        rest = &rest[16..];

        let file_size = if descriptor & Self::INCLUDE_SIZE != 0 {
            if rest.len() < 8 {
                anyhow::bail!("short ED2K FileIdentifier size");
            }
            let value = u64::from_le_bytes(rest[..8].try_into().unwrap());
            rest = &rest[8..];
            Some(value).filter(|file_size| *file_size != 0)
        } else {
            None
        };

        let aich_root = if descriptor & Self::INCLUDE_AICH != 0 {
            if rest.len() < 20 {
                anyhow::bail!("short ED2K FileIdentifier AICH root");
            }
            let mut root = [0u8; 20];
            root.copy_from_slice(&rest[..20]);
            rest = &rest[20..];
            Some(root)
        } else {
            None
        };

        Ok((
            Self {
                file_hash,
                file_size,
                aich_root,
            },
            rest,
        ))
    }

    fn matches_relaxed(&self, other: &Self) -> bool {
        self.file_hash == other.file_hash
            && match (self.file_size, other.file_size) {
                (Some(left), Some(right)) => left == right,
                _ => true,
            }
            && match (self.aich_root, other.aich_root) {
                (Some(left), Some(right)) => left == right,
                _ => true,
            }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ed2kHashsetRequestOptions {
    request_md4: bool,
    request_aich: bool,
}

impl Ed2kHashsetRequestOptions {
    const REQUEST_MD4: u8 = 1 << 0;
    const REQUEST_AICH: u8 = 1 << 1;

    fn encode(self) -> u8 {
        (if self.request_md4 {
            Self::REQUEST_MD4
        } else {
            0
        }) | (if self.request_aich {
            Self::REQUEST_AICH
        } else {
            0
        })
    }

    const fn decode(options: u8) -> Self {
        Self {
            request_md4: options & Self::REQUEST_MD4 != 0,
            request_aich: options & Self::REQUEST_AICH != 0,
        }
    }

    const fn has_known_request(self) -> bool {
        self.request_md4 || self.request_aich
    }
}

type Ed2kMd4Hashset = Vec<[u8; 16]>;
type Ed2kMd4HashsetDecode<'a> = (Ed2kHash, Ed2kMd4Hashset, &'a [u8]);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ed2kHashsetAnswer2 {
    file_identifier: Ed2kFileIdentifier,
    md4_hashset: Option<Ed2kMd4Hashset>,
    aich_hashset: Option<Ed2kAichHashset>,
}

struct EncodedUploadPartPacket {
    phase: &'static str,
    packet: Vec<u8>,
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

/// Inputs for the long-lived ED2K TCP listener task.
pub struct Ed2kListenerOptions {
    pub listener: Arc<TcpListener>,
    pub dht: DhtNode,
    pub server_state: Arc<RwLock<Ed2kServerState>>,
    pub kad_firewall: Arc<Mutex<KadFirewallState>>,
    pub secure_ident: Arc<Ed2kSecureIdent>,
    pub transfer_runtime: Arc<Ed2kTransferRuntime>,
    pub hello_identity: Ed2kHelloIdentity,
    pub shutdown: Arc<AtomicBool>,
}

/// Run the minimal eD2k TCP listener needed for inbound hello parity and firewall checks.
pub async fn run_ed2k_listener(options: Ed2kListenerOptions) {
    let Ed2kListenerOptions {
        listener,
        dht,
        server_state,
        kad_firewall,
        secure_ident,
        transfer_runtime,
        hello_identity,
        shutdown,
    } = options;
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let dht = dht.clone();
                let server_state = Arc::clone(&server_state);
                let kad_firewall = Arc::clone(&kad_firewall);
                let secure_ident = Arc::clone(&secure_ident);
                let transfer_runtime = Arc::clone(&transfer_runtime);
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(
                        stream,
                        peer_addr,
                        Ed2kConnectionContext {
                            dht: &dht,
                            server_state: &server_state,
                            kad_firewall: &kad_firewall,
                            secure_ident: &secure_ident,
                            transfer_runtime: &transfer_runtime,
                            hello_identity,
                        },
                    )
                    .await
                    {
                        debug!("eD2k connection handling failed from {peer_addr}: {error}");
                    }
                });
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

struct Ed2kConnectionContext<'a> {
    dht: &'a DhtNode,
    server_state: &'a Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &'a Arc<Mutex<KadFirewallState>>,
    secure_ident: &'a Arc<Ed2kSecureIdent>,
    transfer_runtime: &'a Arc<Ed2kTransferRuntime>,
    hello_identity: Ed2kHelloIdentity,
}

async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    context: Ed2kConnectionContext<'_>,
) -> Result<()> {
    let Ed2kConnectionContext {
        dht,
        server_state,
        kad_firewall,
        secure_ident,
        transfer_runtime,
        hello_identity,
    } = context;
    let local_addr = stream.local_addr().with_context(|| {
        format!("failed to resolve local eD2k listener address for {peer_addr}")
    })?;
    dump_ed2k_tcp_listener_meta(
        peer_addr,
        None,
        "tcp_accept",
        format!("local_addr={local_addr}"),
    );
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
    let mut transport = match tokio::time::timeout(
        ED2K_CONNECTION_IDLE_TIMEOUT,
        Ed2kTransport::accept(stream, hello_identity.user_hash),
    )
    .await
    {
        Ok(Ok(transport)) => transport,
        Ok(Err(error)) => {
            dump_ed2k_tcp_listener_meta(
                peer_addr,
                None,
                "accept_failed",
                format!("local_addr={local_addr} error={error:#}"),
            );
            return Err(error).with_context(|| {
                format!("failed to accept inbound eD2k peer transport from {peer_addr}")
            });
        }
        Err(_) => {
            dump_ed2k_tcp_listener_meta(
                peer_addr,
                None,
                "accept_timeout",
                format!(
                    "local_addr={local_addr} idle_timeout_secs={}",
                    ED2K_CONNECTION_IDLE_TIMEOUT.as_secs()
                ),
            );
            anyhow::bail!("timed out waiting for initial eD2k peer bytes");
        }
    };
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
    let mut requested_file_hash: Option<Ed2kHash> = None;
    let mut peer_upload_identity = upload_peer_identity_from_socket(peer_addr);
    let mut upload_session: Option<Ed2kUploadSessionHandle> = None;
    let mut upload_session_file_hash: Option<Ed2kHash> = None;
    let mut upload_granted_sent = false;
    let mut last_queue_rank = None;
    let mut last_queue_rank_sent_at = None;

    let result = loop {
        let read_timeout = if upload_session.is_some() {
            ED2K_UPLOAD_QUEUE_POLL_INTERVAL
        } else {
            ED2K_CONNECTION_IDLE_TIMEOUT
        };
        let packet = match tokio::time::timeout(read_timeout, transport.read_packet()).await {
            Ok(packet) => {
                packet.with_context(|| format!("failed to read eD2k packet from {peer_addr}"))?
            }
            Err(_) => {
                let Some(upload_session_handle) = upload_session.as_ref() else {
                    break Ok(());
                };
                match transfer_runtime
                    .poll_upload_session(upload_session_handle, true)
                    .await
                {
                    Ed2kUploadSessionStatus::Granted => {
                        if !upload_granted_sent {
                            let reply = encode_accept_upload_req();
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "accept_upload",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send OP_ACCEPTUPLOADREQ to {peer_addr}")
                            })?;
                            upload_granted_sent = true;
                            last_queue_rank = None;
                            last_queue_rank_sent_at = None;
                        }
                        continue;
                    }
                    Ed2kUploadSessionStatus::Waiting { rank } => {
                        let now = tokio::time::Instant::now();
                        let should_refresh = last_queue_rank != Some(rank)
                            || last_queue_rank_sent_at.is_none_or(|sent_at| {
                                now.duration_since(sent_at) >= ED2K_UPLOAD_QUEUE_REFRESH_INTERVAL
                            });
                        if should_refresh {
                            let reply = encode_queue_ranking(rank);
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "queue_ranking",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send OP_QUEUERANKING to {peer_addr}")
                            })?;
                            last_queue_rank = Some(rank);
                            last_queue_rank_sent_at = Some(now);
                        }
                        continue;
                    }
                    Ed2kUploadSessionStatus::Stale => break Ok(()),
                }
            }
        };
        let Some(packet) = packet else {
            break Ok(());
        };
        dump_ed2k_tcp_listener_recv(peer_addr, transport.mode, "session", &packet);

        match (packet.protocol, packet.opcode) {
            (OP_EDONKEYPROT, OP_HELLO) => {
                let hello_profile = decode_hello_profile(&packet.payload)?;
                peer_upload_identity =
                    upload_peer_identity_from_hello(peer_addr, &hello_profile.identity);
                debug!(
                    "received eD2k OP_HELLO from {peer_addr} transport={} mule_hello={}",
                    transport.mode.as_str(),
                    hello_profile.is_mule_hello,
                );
                for reply in build_hello_responses(&packet.payload, response_identity)? {
                    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "hello_reply", &reply);
                    transport
                        .write_all(&reply)
                        .await
                        .with_context(|| format!("failed to reply to OP_HELLO from {peer_addr}"))?;
                }
                if hello_profile.is_mule_hello && !peer_secure_ident.requested_peer_key {
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
                if let Some(callback_intent) = transfer_runtime
                    .claim_callback_intent(hello_profile.identity.client_id)
                    .await
                {
                    let file_hash =
                        Ed2kHash::from_str(&callback_intent.file_hash).with_context(|| {
                            format!(
                                "invalid callback file hash {} for client_id={}",
                                callback_intent.file_hash, callback_intent.client_id
                            )
                        })?;
                    info!(
                        "claimed inbound ED2K callback download file_hash={} client_id={} peer={peer_addr}",
                        callback_intent.file_hash, callback_intent.client_id
                    );
                    match drive_download_session(DownloadSessionOptions {
                        transport: &mut transport,
                        peer_addr,
                        hello_identity: response_identity,
                        secure_ident: secure_ident.as_ref(),
                        transfer_runtime,
                        file_hash,
                        file_hash_hex: &callback_intent.file_hash,
                        timeout: ED2K_CONNECTION_IDLE_TIMEOUT,
                        send_initial_requests: true,
                        initial_hello_complete: true,
                        initial_secure_ident_started: true,
                    })
                    .await?
                    {
                        Ed2kPeerDownloadOutcome::Completed => break Ok(()),
                        Ed2kPeerDownloadOutcome::AcceptedButIncomplete => break Ok(()),
                    }
                }
            }
            (OP_EDONKEYPROT, OP_HELLOANSWER) => {
                debug!(
                    "received eD2k OP_HELLOANSWER from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
            }
            (OP_EMULEPROT, OP_MULTIPACKET_EXT2) => {
                let (requested_identifier, mut remaining) =
                    Ed2kFileIdentifier::decode(&packet.payload)?;
                let requested = requested_identifier.file_hash;
                requested_file_hash = Some(requested);
                let Some(shared) = transfer_runtime.local_entry(&requested).await? else {
                    let reply = encode_file_req_ans_nofil(&requested);
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "multipacket_ext2_nofil",
                        &reply,
                    );
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send OP_FILEREQANSNOFIL to {peer_addr}")
                    })?;
                    continue;
                };
                let shared_identifier = Ed2kFileIdentifier::from_shared_entry(&shared)?;
                if !shared_identifier.matches_relaxed(&requested_identifier) {
                    let reply = encode_file_req_ans_nofil(&requested);
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "multipacket_ext2_mismatch",
                        &reply,
                    );
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send OP_FILEREQANSNOFIL to {peer_addr}")
                    })?;
                    continue;
                }

                let mut include_filename_answer = false;
                let mut include_file_status = false;
                while let Some((&sub_opcode, rest)) = remaining.split_first() {
                    remaining = rest;
                    match sub_opcode {
                        OP_REQUESTFILENAME => {
                            remaining =
                                skip_request_filename_ext_info(remaining, shared.file_size)?;
                            include_filename_answer = true;
                        }
                        OP_SETREQFILEID => {
                            include_file_status = true;
                        }
                        OP_REQUESTSOURCES => {
                            let reply = encode_answer_sources_empty(&requested);
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "answer_sources",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send source exchange reply to {peer_addr}")
                            })?;
                        }
                        OP_REQUESTSOURCES2 => {
                            if remaining.len() < 3 {
                                anyhow::bail!(
                                    "short OP_REQUESTSOURCES2 sub-payload in OP_MULTIPACKET_EXT2"
                                );
                            }
                            let requested_version = remaining[0];
                            remaining = &remaining[3..];
                            let reply = encode_answer_sources2_empty(
                                &requested,
                                requested_version.max(ED2K_SOURCE_EXCHANGE2_VERSION),
                            );
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "answer_sources",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send source exchange reply to {peer_addr}")
                            })?;
                        }
                        OP_AICHFILEHASHREQ => {}
                        _ => {
                            anyhow::bail!(
                                "unsupported OP_MULTIPACKET_EXT2 sub-op 0x{sub_opcode:02X}"
                            );
                        }
                    }
                }

                if include_filename_answer || include_file_status {
                    let reply = encode_multipacket_ext2_answer(
                        &shared_identifier,
                        &shared.canonical_name,
                        include_filename_answer,
                        include_file_status,
                    )?;
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "multipacket_ext2_answer",
                        &reply,
                    );
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send OP_MULTIPACKETANSWER_EXT2 to {peer_addr}")
                    })?;
                }
            }
            (OP_EDONKEYPROT, OP_REQUESTFILENAME) => {
                let requested = decode_file_hash_payload(&packet.payload)?;
                let reply = if let Some(shared) = transfer_runtime.local_entry(&requested).await? {
                    requested_file_hash = Some(requested);
                    encode_request_filename_answer(&requested, &shared.canonical_name)?
                } else {
                    encode_file_req_ans_nofil(&requested)
                };
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "request_filename", &reply);
                transport.write_all(&reply).await.with_context(|| {
                    format!("failed to send OP_REQFILENAMEANSWER to {peer_addr}")
                })?;
            }
            (OP_EDONKEYPROT, OP_SETREQFILEID) => {
                let requested = decode_file_hash_payload(&packet.payload)?;
                requested_file_hash = Some(requested);
                let reply = if transfer_runtime.local_entry(&requested).await?.is_some() {
                    encode_file_status_complete(&requested)
                } else {
                    encode_file_req_ans_nofil(&requested)
                };
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "set_req_file_id", &reply);
                transport.write_all(&reply).await.with_context(|| {
                    format!("failed to send OP_SETREQFILEID response to {peer_addr}")
                })?;
            }
            (OP_EDONKEYPROT, OP_STARTUPLOADREQ) => {
                let requested = decode_file_hash_payload(&packet.payload)?;
                requested_file_hash = Some(requested);
                let reply = if transfer_runtime.local_entry(&requested).await?.is_some() {
                    let status = if upload_session_file_hash == Some(requested) {
                        match upload_session.as_ref() {
                            Some(upload_session_handle) => {
                                transfer_runtime
                                    .poll_upload_session(upload_session_handle, true)
                                    .await
                            }
                            None => Ed2kUploadSessionStatus::Stale,
                        }
                    } else {
                        let (session_handle, status) = transfer_runtime
                            .begin_upload_session(peer_upload_identity.clone(), &requested)
                            .await;
                        upload_session = Some(session_handle);
                        upload_session_file_hash = Some(requested);
                        status
                    };
                    match status {
                        Ed2kUploadSessionStatus::Granted => {
                            upload_granted_sent = true;
                            last_queue_rank = None;
                            last_queue_rank_sent_at = None;
                            encode_accept_upload_req()
                        }
                        Ed2kUploadSessionStatus::Waiting { rank } => {
                            upload_granted_sent = false;
                            last_queue_rank = Some(rank);
                            last_queue_rank_sent_at = Some(tokio::time::Instant::now());
                            encode_queue_ranking(rank)
                        }
                        Ed2kUploadSessionStatus::Stale => {
                            upload_granted_sent = false;
                            last_queue_rank = Some(1);
                            last_queue_rank_sent_at = Some(tokio::time::Instant::now());
                            encode_queue_ranking(1)
                        }
                    }
                } else {
                    encode_file_req_ans_nofil(&requested)
                };
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "start_upload", &reply);
                transport.write_all(&reply).await.with_context(|| {
                    format!("failed to send OP_STARTUPLOADREQ response to {peer_addr}")
                })?;
            }
            (OP_EDONKEYPROT, OP_CANCELTRANSFER) => {
                if let Some(upload_session_handle) = upload_session.as_ref() {
                    transfer_runtime
                        .release_upload_session(upload_session_handle)
                        .await;
                }
                upload_session = None;
                break Ok(());
            }
            (OP_EDONKEYPROT, OP_HASHSETREQUEST) => {
                let requested = decode_file_hash_payload(&packet.payload)?;
                let reply = if transfer_runtime.local_entry(&requested).await?.is_some() {
                    if let Some(hashset) = transfer_runtime.md4_hashset(&requested).await? {
                        encode_hashset_answer(&requested, &hashset)?
                    } else {
                        encode_file_req_ans_nofil(&requested)
                    }
                } else {
                    encode_file_req_ans_nofil(&requested)
                };
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "hashset_request", &reply);
                transport
                    .write_all(&reply)
                    .await
                    .with_context(|| format!("failed to send OP_HASHSETANSWER to {peer_addr}"))?;
            }
            (OP_EMULEPROT, OP_HASHSETREQUEST2) => {
                let (requested_identifier, request_options) =
                    decode_hashset_request2(&packet.payload)?;
                let requested = requested_identifier.file_hash;
                requested_file_hash = Some(requested);
                if !request_options.has_known_request() {
                    continue;
                }
                let reply = if let Some(shared) = transfer_runtime.local_entry(&requested).await? {
                    let shared_identifier = Ed2kFileIdentifier::from_shared_entry(&shared)?;
                    if !shared_identifier.matches_relaxed(&requested_identifier) {
                        encode_file_req_ans_nofil(&requested)
                    } else {
                        let md4_hashset = if request_options.request_md4 {
                            transfer_runtime.md4_hashset(&requested).await?
                        } else {
                            None
                        };
                        let aich_hashset = if request_options.request_aich {
                            transfer_runtime.aich_hashset(&requested).await?
                        } else {
                            None
                        };
                        encode_hashset_answer2(
                            &shared_identifier,
                            md4_hashset.as_deref(),
                            aich_hashset.as_ref(),
                        )?
                    }
                } else {
                    encode_file_req_ans_nofil(&requested)
                };
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "hashset_request", &reply);
                transport
                    .write_all(&reply)
                    .await
                    .with_context(|| format!("failed to send OP_HASHSETANSWER2 to {peer_addr}"))?;
            }
            (OP_EMULEPROT, OP_REQUESTSOURCES) | (OP_EMULEPROT, OP_REQUESTSOURCES2) => {
                let (requested, requested_version) =
                    decode_request_sources_payload(packet.opcode, &packet.payload)?;
                requested_file_hash = Some(requested);
                if transfer_runtime.local_entry(&requested).await?.is_some() {
                    let reply = if packet.opcode == OP_REQUESTSOURCES2 {
                        encode_answer_sources2_empty(
                            &requested,
                            requested_version.max(ED2K_SOURCE_EXCHANGE2_VERSION),
                        )
                    } else {
                        encode_answer_sources_empty(&requested)
                    };
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "answer_sources",
                        &reply,
                    );
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send source exchange reply to {peer_addr}")
                    })?;
                }
            }
            (OP_EMULEPROT, OP_AICHFILEHASHREQ) => {
                let requested = decode_file_hash_payload(&packet.payload)?;
                requested_file_hash = Some(requested);
                if transfer_runtime.local_entry(&requested).await?.is_some() {
                    // Keep the legacy AICH probe from tearing down the upload
                    // session even when we do not currently expose an AICH tree.
                }
            }
            (OP_EDONKEYPROT, OP_REQUESTPARTS) | (OP_EMULEPROT, OP_REQUESTPARTS_I64) => {
                let is_i64 = packet.opcode == OP_REQUESTPARTS_I64;
                let (requested, ranges) = decode_request_parts_payload(&packet.payload, is_i64)?;
                requested_file_hash = Some(requested);
                let Some(shared) = transfer_runtime.local_entry(&requested).await? else {
                    let reply = encode_file_req_ans_nofil(&requested);
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "request_parts_nofil",
                        &reply,
                    );
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send OP_FILEREQANSNOFIL to {peer_addr}")
                    })?;
                    continue;
                };

                if upload_session_file_hash != Some(requested) {
                    let (session_handle, status) = transfer_runtime
                        .begin_upload_session(peer_upload_identity.clone(), &requested)
                        .await;
                    upload_session = Some(session_handle);
                    upload_session_file_hash = Some(requested);
                    upload_granted_sent = false;
                    match status {
                        Ed2kUploadSessionStatus::Granted => {
                            let reply = encode_accept_upload_req();
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "accept_upload",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send OP_ACCEPTUPLOADREQ to {peer_addr}")
                            })?;
                            upload_granted_sent = true;
                            last_queue_rank = None;
                            last_queue_rank_sent_at = None;
                        }
                        Ed2kUploadSessionStatus::Waiting { rank } => {
                            let reply = encode_queue_ranking(rank);
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "queue_ranking",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send OP_QUEUERANKING to {peer_addr}")
                            })?;
                            last_queue_rank = Some(rank);
                            last_queue_rank_sent_at = Some(tokio::time::Instant::now());
                            continue;
                        }
                        Ed2kUploadSessionStatus::Stale => continue,
                    }
                }

                let Some(upload_session_handle) = upload_session.as_ref() else {
                    continue;
                };
                match transfer_runtime
                    .note_upload_request_parts(upload_session_handle)
                    .await
                {
                    Ed2kUploadSessionStatus::Granted => {
                        if !upload_granted_sent {
                            let reply = encode_accept_upload_req();
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "accept_upload",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send OP_ACCEPTUPLOADREQ to {peer_addr}")
                            })?;
                            upload_granted_sent = true;
                        }
                        last_queue_rank = None;
                        last_queue_rank_sent_at = None;
                    }
                    Ed2kUploadSessionStatus::Waiting { rank } => {
                        let reply = encode_queue_ranking(rank);
                        dump_ed2k_tcp_listener_send(
                            peer_addr,
                            transport.mode,
                            "queue_ranking",
                            &reply,
                        );
                        transport.write_all(&reply).await.with_context(|| {
                            format!("failed to send OP_QUEUERANKING to {peer_addr}")
                        })?;
                        last_queue_rank = Some(rank);
                        last_queue_rank_sent_at = Some(tokio::time::Instant::now());
                        continue;
                    }
                    Ed2kUploadSessionStatus::Stale => break Ok(()),
                }
                for (start, end) in ranges {
                    let Some(bytes) = transfer_runtime
                        .read_verified_range(&requested, start, end)
                        .await?
                    else {
                        continue;
                    };
                    for reply in build_upload_part_packets(
                        &requested,
                        &shared.canonical_name,
                        start,
                        end,
                        &bytes,
                        is_i64,
                    )? {
                        dump_ed2k_tcp_listener_send(
                            peer_addr,
                            transport.mode,
                            reply.phase,
                            &reply.packet,
                        );
                        transport.write_all(&reply.packet).await.with_context(|| {
                            format!("failed to send ED2K upload payload to {peer_addr}")
                        })?;
                    }
                }
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
                if let Some(requested_file_hash) = requested_file_hash {
                    debug!(
                        "closing eD2k connection from {peer_addr}: unsupported protocol=0x{:02X} opcode=0x{:02X} requested_file_hash={requested_file_hash}",
                        packet.protocol, packet.opcode
                    );
                    break Ok(());
                }
                debug!(
                    "closing eD2k connection from {peer_addr}: unsupported protocol=0x{:02X} opcode=0x{:02X}",
                    packet.protocol, packet.opcode
                );
                break Ok(());
            }
        }
    };

    if let Some(upload_session_handle) = upload_session.as_ref() {
        transfer_runtime
            .release_upload_session(upload_session_handle)
            .await;
    }
    result
}

fn upload_peer_identity_from_socket(peer_addr: SocketAddr) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        ip: peer_addr.ip(),
        tcp_port: peer_addr.port(),
        user_hash: None,
        client_id: None,
    }
}

fn upload_peer_identity_from_hello(
    peer_addr: SocketAddr,
    remote_hello: &DecodedHelloIdentity,
) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        ip: peer_addr.ip(),
        tcp_port: if remote_hello.tcp_port == 0 {
            peer_addr.port()
        } else {
            remote_hello.tcp_port
        },
        user_hash: Some(remote_hello.user_hash),
        client_id: Some(remote_hello.client_id),
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

fn is_transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests;
