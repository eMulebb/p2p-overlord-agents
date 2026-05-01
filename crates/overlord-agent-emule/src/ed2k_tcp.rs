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
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use flate2::Decompress;
use md5::compute as md5_compute;
use rand::Rng;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::{Mutex, RwLock},
};
use tracing::{debug, info, warn};

use crate::ed2k_server::{Ed2kFoundSource, Ed2kServerState};
use crate::ed2k_transfer::{
    ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE, Ed2kAichHashset, Ed2kResumeManifest, Ed2kSharedEntry,
    Ed2kSourceHint, Ed2kTransferRuntime, Ed2kUploadPeerIdentity, Ed2kUploadSessionHandle,
    Ed2kUploadSessionStatus, decode_aich_hash_hex, expected_piece_length, new_transfer_job,
};
use crate::kad_firewall::KadFirewallState;
use overlord_kad_dht::DhtNode;
use overlord_kad_proto::{Ed2kHash, FirewallUdp, KadPacket};

mod codec;
mod dump;
mod hello;
mod identity;
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
pub(crate) use dump::dump_ed2k_tcp_download_meta;
use dump::{
    dump_ed2k_tcp_download_recv, dump_ed2k_tcp_download_send, dump_ed2k_tcp_helper_meta,
    dump_ed2k_tcp_helper_recv, dump_ed2k_tcp_helper_send, dump_ed2k_tcp_listener_meta,
    dump_ed2k_tcp_listener_recv, dump_ed2k_tcp_listener_send,
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

/// Outcome of one outbound ED2K peer download attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ed2kPeerDownloadOutcome {
    /// The peer contributed enough data for the manifest to complete.
    Completed,
    /// The peer accepted the session and looked valid, but the transfer did not
    /// complete before the peer closed or the attempt timed out.
    AcceptedButIncomplete,
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

/// Incremental inflate state for one pending compressed part stream.
///
/// Real eMule peers can split one compressed block across multiple
/// `OP_COMPRESSEDPART` frames. The per-packet header repeats the block start
/// and the total compressed stream length, while the payload only carries one
/// fragment of the zlib stream.
struct PendingCompressedPart {
    piece_index: u32,
    start: u64,
    end: u64,
    advertised_compressed_len: usize,
    compressed_received: usize,
    uncompressed_written: u64,
    inflater: Decompress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActiveDownloadPiece {
    piece_index: u32,
    next_offset: u64,
    piece_end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingPartRequest {
    piece_index: u32,
    start: u64,
    end: u64,
    queued: bool,
    received_end: u64,
    response_bytes: Vec<u8>,
}

impl PendingPartRequest {
    fn new(piece_index: u32, start: u64, end: u64) -> Self {
        Self {
            piece_index,
            start,
            end,
            queued: false,
            received_end: start,
            response_bytes: Vec::new(),
        }
    }

    fn matches_uncompressed_fragment(&self, start: u64, end: u64) -> bool {
        self.queued && self.received_end == start && end >= start && end <= self.end
    }

    fn buffer_response_bytes(&mut self, start: u64, end: u64, bytes: &[u8]) -> Result<()> {
        let data_len = u64::try_from(bytes.len()).context("response block exceeds u64 length")?;
        let expected_end = start.saturating_add(data_len);
        if start != self.received_end || end != expected_end || end > self.end {
            anyhow::bail!(
                "unexpected response range {start}..{end} for pending block {}..{} received_end={}",
                self.start,
                self.end,
                self.received_end
            );
        }
        self.response_bytes.extend_from_slice(bytes);
        self.received_end = end;
        Ok(())
    }

    fn is_ready(&self) -> bool {
        self.received_end == self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DownloadWindowLimits {
    max_pending_blocks: usize,
    min_pending_blocks: usize,
}

struct DownloadRequestWindowState<'a> {
    transfer_runtime: &'a Ed2kTransferRuntime,
    file_hash: &'a Ed2kHash,
    file_hash_hex: &'a str,
    file_size: u64,
    manifest: &'a Ed2kResumeManifest,
    active_piece_request: &'a mut Option<ActiveDownloadPiece>,
    pending_part_requests: &'a mut Vec<PendingPartRequest>,
    upload_accepted_at: tokio::time::Instant,
    completed_block_count: usize,
    session_payload_down: u64,
    part_response_grace: Duration,
}

struct EncodedUploadPartPacket {
    phase: &'static str,
    packet: Vec<u8>,
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
pub(crate) enum Ed2kTransportMode {
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

/// Executes a minimal outbound native ED2K download session against one peer.
///
/// A successful public-peer oracle capture showed a startup sequence that
/// public peers accept more readily than our earlier minimal flow:
///
/// `OP_HELLO -> OP_HELLOANSWER -> secure-ident -> OP_REQUESTFILENAME ->
/// OP_SETREQFILEID -> OP_HASHSETREQUEST2/ANSWER2 -> OP_STARTUPLOADREQ ->
/// OP_ACCEPTUPLOADREQ -> OP_REQUESTPARTS`
///
/// Public peers that the oracle downloaded from were closing on our earlier
/// startup sequence, so the downloader now follows the observed file-startup
/// shape instead of the more speculative minimal flow.
///
/// Some real peers still acknowledge upload intent before they return a
/// hashset. The downloader keeps the captured hashset-first path as the
/// default, but falls back to `OP_STARTUPLOADREQ` after a short stall so
/// queue-oriented peers are not discarded prematurely.
/// Inputs for one outbound native ED2K peer download attempt.
pub(crate) struct Ed2kPeerDownloadOptions<'a> {
    pub bind_ip: Ipv4Addr,
    pub peer: &'a Ed2kFoundSource,
    pub hello_identity: Ed2kHelloIdentity,
    pub secure_ident: &'a Arc<Ed2kSecureIdent>,
    pub transfer_runtime: &'a Ed2kTransferRuntime,
    pub canonical_name: String,
    pub file_size: u64,
    pub timeout: Duration,
}

pub(crate) async fn download_file_from_peer(
    options: Ed2kPeerDownloadOptions<'_>,
) -> Result<Ed2kPeerDownloadOutcome> {
    let Ed2kPeerDownloadOptions {
        bind_ip,
        peer,
        hello_identity,
        secure_ident,
        transfer_runtime,
        canonical_name,
        file_size,
        timeout,
    } = options;
    let file_hash = peer.file_hash;
    let file_hash_hex = file_hash.to_string();
    let job = new_transfer_job(file_hash, canonical_name, file_size);
    transfer_runtime.ensure_job(&job).await?;
    transfer_runtime
        .remember_source(
            &file_hash_hex,
            Ed2kSourceHint {
                ip: peer.ip.to_string(),
                tcp_port: peer.tcp_port,
                user_hash: peer.user_hash.map(hex::encode),
            },
        )
        .await?;

    let peer_addr = SocketAddr::new(IpAddr::V4(peer.ip), peer.tcp_port);
    dump_ed2k_tcp_download_meta(
        peer_addr,
        None,
        "connect_start",
        format!(
            "file_hash={file_hash_hex} file_size={file_size} client_id={} obfuscated={} has_user_hash={}",
            peer.client_id,
            peer.obfuscated,
            peer.user_hash.is_some()
        ),
    );
    async {
        let mut transport = Ed2kTransport::connect_outgoing(
            bind_ip,
            peer_addr,
            hello_identity.connect_options,
            peer.user_hash,
            peer.obfuscation_options,
            timeout,
        )
        .await?;
        dump_ed2k_tcp_download_meta(
            peer_addr,
            Some(transport.mode),
            "connect_ready",
            format!("file_hash={file_hash_hex}"),
        );
        let hello = encode_hello_request(hello_identity);
        dump_ed2k_tcp_download_send(peer_addr, transport.mode, "hello", &hello);
        transport
            .write_all(&hello)
            .await
            .with_context(|| format!("failed to send OP_HELLO to {peer_addr}"))?;
        let session_result = drive_download_session(DownloadSessionOptions {
            transport: &mut transport,
            peer_addr,
            hello_identity,
            secure_ident: secure_ident.as_ref(),
            transfer_runtime,
            file_hash,
            file_hash_hex: &file_hash_hex,
            timeout,
            send_initial_requests: true,
            initial_hello_complete: false,
            initial_secure_ident_started: false,
        })
        .await;
        match &session_result {
            Ok(Ed2kPeerDownloadOutcome::Completed) => dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport.mode),
                "complete",
                format!("file_hash={file_hash_hex}"),
            ),
            Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete) => dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport.mode),
                "accepted_incomplete",
                format!("file_hash={file_hash_hex}"),
            ),
            Err(error) => dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport.mode),
                "error",
                format!("file_hash={file_hash_hex} error={error}"),
            ),
        }
        session_result
    }
    .await
}

struct DownloadSessionOptions<'a> {
    transport: &'a mut Ed2kTransport,
    peer_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    secure_ident: &'a Ed2kSecureIdent,
    transfer_runtime: &'a Ed2kTransferRuntime,
    file_hash: Ed2kHash,
    file_hash_hex: &'a str,
    timeout: Duration,
    send_initial_requests: bool,
    initial_hello_complete: bool,
    initial_secure_ident_started: bool,
}

async fn drive_download_session(
    options: DownloadSessionOptions<'_>,
) -> Result<Ed2kPeerDownloadOutcome> {
    let DownloadSessionOptions {
        transport,
        peer_addr,
        hello_identity,
        secure_ident,
        transfer_runtime,
        file_hash,
        file_hash_hex,
        timeout,
        send_initial_requests,
        initial_hello_complete,
        initial_secure_ident_started,
    } = options;
    const HASHSET_STALL_UPLOAD_FALLBACK: Duration = Duration::from_millis(500);
    const QUEUE_RANK_GRACE: Duration = Duration::from_secs(20);
    const PART_RESPONSE_GRACE: Duration = Duration::from_secs(20);
    // eMule keeps a pending block scheduler that is broader than one live wire
    // request. We mirror that with one claimed piece, a queued-vs-unqueued
    // block list, and wire packets that carry up to three queued ranges.
    let mut pending_part_requests: Vec<PendingPartRequest> = Vec::new();
    let mut pending_compressed_parts: Vec<PendingCompressedPart> = Vec::new();
    let mut manifest = transfer_runtime.manifest(file_hash_hex).await?;
    let mut request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
    let mut peer_secure_ident = Ed2kPeerSecureIdentState::default();
    let mut hello_complete = initial_hello_complete;
    let mut secure_ident_started = initial_secure_ident_started;
    let mut remote_supports_file_identifiers = false;
    let mut startup_file_requests_sent = false;
    let mut startup_file_response_received = false;
    let mut source_request_sent = false;
    let mut aich_file_hash_requested = false;
    let mut hashset_requested = false;
    let mut hashset_requested_at = None;
    let mut upload_requested = false;
    let mut upload_accepted = false;
    let mut upload_accepted_at = None;
    let mut part_response_deadline = None;
    let mut queued_until = None;
    let mut active_piece_request: Option<ActiveDownloadPiece> = None;
    let mut completed_block_count = 0usize;
    let mut session_payload_down = 0u64;

    let session_result = async {
        loop {
            if manifest.completed {
                return Ok(Ed2kPeerDownloadOutcome::Completed);
            }

            let waiting_for_peer_secure_ident = secure_ident_started
                && (peer_secure_ident.peer_challenge_from.is_none()
                    || peer_secure_ident.pending_signature
                    || (peer_secure_ident.requested_peer_key
                        && peer_secure_ident.peer_public_key.is_none())
                    || (peer_secure_ident.challenge_for.is_some()
                        && !peer_secure_ident.peer_signature_received));

            if send_initial_requests && hello_complete && !secure_ident_started {
                let secure_ident_probe = begin_secure_ident_probe(&mut peer_secure_ident);
                dump_ed2k_tcp_download_send(
                    peer_addr,
                    transport.mode,
                    "secure_ident_probe",
                    &secure_ident_probe,
                );
                transport
                    .write_all(&secure_ident_probe)
                    .await
                    .with_context(|| format!("failed to send OP_SECIDENTSTATE to {peer_addr}"))?;
                secure_ident_started = true;
            }

            if send_initial_requests
                && hello_complete
                && !startup_file_requests_sent
                && !waiting_for_peer_secure_ident
            {
                if remote_supports_file_identifiers {
                    let multipacket_ext2 =
                        encode_multipacket_ext2_request(&request_file_identifier, &manifest);
                    dump_ed2k_tcp_download_send(
                        peer_addr,
                        transport.mode,
                        "multipacket_ext2_request",
                        &multipacket_ext2,
                    );
                    transport
                        .write_all(&multipacket_ext2)
                        .await
                        .with_context(|| {
                            format!("failed to send OP_MULTIPACKET_EXT2 to {peer_addr}")
                        })?;
                    source_request_sent = true;
                    aich_file_hash_requested = true;
                } else {
                    let request_filename = encode_request_filename(&file_hash, &manifest);
                    dump_ed2k_tcp_download_send(
                        peer_addr,
                        transport.mode,
                        "request_filename",
                        &request_filename,
                    );
                    transport
                        .write_all(&request_filename)
                        .await
                        .with_context(|| {
                            format!("failed to send OP_REQUESTFILENAME to {peer_addr}")
                        })?;

                    if manifest.file_size > ED2K_PART_SIZE {
                        let set_req_file_id = encode_set_req_file_id(&file_hash);
                        dump_ed2k_tcp_download_send(
                            peer_addr,
                            transport.mode,
                            "set_req_file_id",
                            &set_req_file_id,
                        );
                        transport
                            .write_all(&set_req_file_id)
                            .await
                            .with_context(|| {
                                format!("failed to send OP_SETREQFILEID to {peer_addr}")
                            })?;
                    }
                }
                startup_file_requests_sent = true;
            }

            if send_initial_requests
                && hello_complete
                && !source_request_sent
                && !waiting_for_peer_secure_ident
                && !remote_supports_file_identifiers
            {
                let source_request = encode_request_sources2(&file_hash);
                dump_ed2k_tcp_download_send(
                    peer_addr,
                    transport.mode,
                    "request_sources2",
                    &source_request,
                );
                transport
                    .write_all(&source_request)
                    .await
                    .with_context(|| {
                        format!("failed to send OP_REQUESTSOURCES2 to {peer_addr}")
                    })?;
                source_request_sent = true;
            }

            if send_initial_requests
                && hello_complete
                && !aich_file_hash_requested
                && !waiting_for_peer_secure_ident
                && !remote_supports_file_identifiers
            {
                let aich_file_hash_request = encode_aich_file_hash_request(&file_hash);
                dump_ed2k_tcp_download_send(
                    peer_addr,
                    transport.mode,
                    "aich_file_hash_request",
                    &aich_file_hash_request,
                );
                transport
                    .write_all(&aich_file_hash_request)
                    .await
                    .with_context(|| {
                        format!("failed to send OP_AICHFILEHASHREQ to {peer_addr}")
                    })?;
                aich_file_hash_requested = true;
            }

            if send_initial_requests
                && hello_complete
                && manifest.file_size != 0
                && !manifest.md4_hashset_acquired
                && !hashset_requested
                && !waiting_for_peer_secure_ident
                && startup_file_response_received
            {
                if manifest.file_size <= ED2K_PART_SIZE {
                    manifest = transfer_runtime
                        .store_md4_hashset(file_hash_hex, Vec::new())
                        .await?;
                } else {
                    let hashset_request = if remote_supports_file_identifiers {
                        encode_hashset_request2(
                            &request_file_identifier,
                            Ed2kHashsetRequestOptions {
                                request_md4: true,
                                request_aich: manifest.file_size > ED2K_PART_SIZE
                                    && request_file_identifier.aich_root.is_some(),
                            },
                        )?
                    } else {
                        encode_hashset_request(&file_hash)
                    };
                    dump_ed2k_tcp_download_send(
                        peer_addr,
                        transport.mode,
                        "hashset_request",
                        &hashset_request,
                    );
                    transport
                        .write_all(&hashset_request)
                        .await
                        .with_context(|| {
                            if remote_supports_file_identifiers {
                                format!("failed to send OP_HASHSETREQUEST2 to {peer_addr}")
                            } else {
                                format!("failed to send OP_HASHSETREQUEST to {peer_addr}")
                            }
                        })?;
                    hashset_requested = true;
                    hashset_requested_at = Some(tokio::time::Instant::now());
                }
            }

            let hashset_request_stalled = hashset_requested_at
                .is_some_and(|requested_at| requested_at.elapsed() >= HASHSET_STALL_UPLOAD_FALLBACK);
            if send_initial_requests
                && hello_complete
                && manifest.file_size != 0
                && (manifest.md4_hashset_acquired || hashset_request_stalled)
                && !upload_requested
                && !waiting_for_peer_secure_ident
                && startup_file_response_received
            {
                if hashset_request_stalled && !manifest.md4_hashset_acquired {
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "upload_request_hashset_fallback",
                        format!("file_hash={file_hash_hex}"),
                    );
                }
                let start_upload = encode_start_upload_req(&file_hash);
                dump_ed2k_tcp_download_send(
                    peer_addr,
                    transport.mode,
                    "start_upload",
                    &start_upload,
                );
                transport
                    .write_all(&start_upload)
                    .await
                    .with_context(|| format!("failed to send OP_STARTUPLOADREQ to {peer_addr}"))?;
                upload_requested = true;
            }

            if manifest.md4_hashset_acquired
                && upload_accepted
                && let Some(next_deadline) = pump_download_request_window(
                    transport,
                    peer_addr,
                    DownloadRequestWindowState {
                        transfer_runtime,
                        file_hash: &file_hash,
                        file_hash_hex,
                        file_size: manifest.file_size,
                        manifest: &manifest,
                        active_piece_request: &mut active_piece_request,
                        pending_part_requests: &mut pending_part_requests,
                        upload_accepted_at: upload_accepted_at
                            .unwrap_or_else(tokio::time::Instant::now),
                        completed_block_count,
                        session_payload_down,
                        part_response_grace: PART_RESPONSE_GRACE,
                    },
                )
                .await?
            {
                part_response_deadline = Some(next_deadline);
            }

            let fallback_poll_delay = if send_initial_requests
                && hello_complete
                && hashset_requested
                && !manifest.md4_hashset_acquired
                && !upload_requested
                && !waiting_for_peer_secure_ident
            {
                hashset_requested_at.map(|requested_at| {
                    HASHSET_STALL_UPLOAD_FALLBACK.saturating_sub(requested_at.elapsed())
                })
            } else {
                None
            };
            let now = tokio::time::Instant::now();
            let read_timeout = next_download_read_timeout(
                now,
                timeout,
                fallback_poll_delay,
                queued_until,
                part_response_deadline,
            );
            let packet = match tokio::time::timeout(read_timeout, transport.read_packet()).await {
                Ok(Ok(Some(packet))) => packet,
                Ok(Ok(None)) => {
                    if hello_complete {
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            Some(transport.mode),
                            "peer_closed_incomplete",
                            format!("file_hash={file_hash_hex}"),
                        );
                        return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                    }
                    anyhow::bail!("peer {peer_addr} closed ED2K download session");
                }
                Ok(Err(error)) => {
                    if hello_complete && is_connection_shutdown_error(&error) {
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            Some(transport.mode),
                            "peer_shutdown_incomplete",
                            format!("file_hash={file_hash_hex}"),
                        );
                        return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                    }
                    return Err(error)
                        .with_context(|| format!("failed to read eD2k packet from {peer_addr}"));
                }
                Err(_) => {
                    if fallback_poll_delay.is_some() {
                        continue;
                    }
                    if queued_until.is_some_and(|deadline| tokio::time::Instant::now() < deadline) {
                        continue;
                    }
                    if !pending_part_requests.iter().any(|request| request.queued) {
                        part_response_deadline = None;
                    }
                    if part_response_deadline
                        .is_some_and(|deadline| tokio::time::Instant::now() < deadline)
                    {
                        continue;
                    }
                    if hello_complete {
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            Some(transport.mode),
                            "peer_timeout_incomplete",
                            format!("file_hash={file_hash_hex}"),
                        );
                        return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                    }
                    anyhow::bail!("timed out waiting for ED2K peer packet from {peer_addr}");
                }
            };
            dump_ed2k_tcp_download_recv(peer_addr, transport.mode, "session", &packet);

            match (packet.protocol, packet.opcode) {
                (OP_EDONKEYPROT, OP_HELLO) => {
                    let hello_profile = decode_hello_profile(&packet.payload)?;
                    for reply in build_hello_responses(&packet.payload, hello_identity)? {
                        dump_ed2k_tcp_download_send(peer_addr, transport.mode, "hello_reply", &reply);
                        transport.write_all(&reply).await.with_context(|| {
                            format!("failed to reply to OP_HELLO during download with {peer_addr}")
                        })?;
                    }
                    hello_complete = true;
                    remote_supports_file_identifiers = hello_profile.supports_file_identifiers;
                    if hello_profile.is_mule_hello && !peer_secure_ident.requested_peer_key {
                        let secure_ident_probe = begin_secure_ident_probe(&mut peer_secure_ident);
                        dump_ed2k_tcp_download_send(
                            peer_addr,
                            transport.mode,
                            "secure_ident_probe",
                            &secure_ident_probe,
                        );
                        transport
                            .write_all(&secure_ident_probe)
                            .await
                            .with_context(|| {
                                format!("failed to send OP_SECIDENTSTATE to {peer_addr}")
                            })?;
                        secure_ident_started = true;
                    }
                }
                (OP_EDONKEYPROT, OP_HELLOANSWER) => {
                    let hello_profile = decode_hello_profile(&packet.payload)?;
                    hello_complete = true;
                    remote_supports_file_identifiers = hello_profile.supports_file_identifiers;
                    if send_initial_requests
                        && hello_profile.is_mule_hello
                        && !peer_secure_ident.requested_peer_key
                    {
                        let secure_ident_probe = begin_secure_ident_probe(&mut peer_secure_ident);
                        dump_ed2k_tcp_download_send(
                            peer_addr,
                            transport.mode,
                            "secure_ident_probe",
                            &secure_ident_probe,
                        );
                        transport
                            .write_all(&secure_ident_probe)
                            .await
                            .with_context(|| {
                                format!("failed to send OP_SECIDENTSTATE to {peer_addr}")
                            })?;
                        secure_ident_started = true;
                    }
                }
                (OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ) => {
                    upload_accepted = true;
                    upload_accepted_at.get_or_insert_with(tokio::time::Instant::now);
                    queued_until = None;
                }
                (OP_EMULEPROT, OP_EMULEINFO) => {
                    transport
                        .write_all(&encode_emule_info_answer(hello_identity.udp_port))
                        .await
                        .with_context(|| {
                            format!("failed to send OP_EMULEINFOANSWER to {peer_addr}")
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
                            &secure_ident.public_key_payload()?,
                        );
                        dump_ed2k_tcp_download_send(
                            peer_addr,
                            transport.mode,
                            "public_key",
                            &public_key,
                        );
                        transport.write_all(&public_key).await.with_context(|| {
                            format!("failed to send OP_PUBLICKEY to {peer_addr}")
                        })?;
                    }
                    if !try_send_secure_ident_signature(
                        transport,
                        peer_addr,
                        secure_ident,
                        &mut peer_secure_ident,
                    )
                    .await?
                        && state == ED2K_SECURE_IDENT_SIGNATURE_NEEDED
                        && !peer_secure_ident.requested_peer_key
                    {
                        let secure_ident_probe = begin_secure_ident_probe(&mut peer_secure_ident);
                        dump_ed2k_tcp_download_send(
                            peer_addr,
                            transport.mode,
                            "secure_ident_probe",
                            &secure_ident_probe,
                        );
                        transport
                            .write_all(&secure_ident_probe)
                            .await
                            .with_context(|| {
                                format!("failed to send fallback OP_SECIDENTSTATE to {peer_addr}")
                            })?;
                        secure_ident_started = true;
                    }
                }
                (OP_EMULEPROT, OP_PUBLICKEY) => {
                    peer_secure_ident.peer_public_key =
                        Some(decode_public_key_payload(&packet.payload)?);
                    let _ = try_send_secure_ident_signature(
                        transport,
                        peer_addr,
                        secure_ident,
                        &mut peer_secure_ident,
                    )
                    .await?;
                }
                (OP_EMULEPROT, OP_SIGNATURE) => {
                    peer_secure_ident.peer_signature_received = true;
                }
                (OP_EDONKEYPROT, OP_HASHSETANSWER) => {
                    let (returned_hash, hashset) = decode_hashset_answer(&packet.payload)?;
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "peer {peer_addr} returned hashset for unexpected file {}",
                            returned_hash
                        );
                    }
                    manifest = transfer_runtime
                        .store_md4_hashset(file_hash_hex, hashset)
                        .await?;
                }
                (OP_EMULEPROT, OP_HASHSETANSWER2) => {
                    let hashset_answer = decode_hashset_answer2(&packet.payload)?;
                    if !request_file_identifier
                        .matches_relaxed(&hashset_answer.file_identifier)
                    {
                        anyhow::bail!(
                            "peer {peer_addr} returned OP_HASHSETANSWER2 for unexpected file {}",
                            hashset_answer.file_identifier.file_hash
                        );
                    }
                    reconcile_download_manifest_metadata(
                        transfer_runtime,
                        file_hash_hex,
                        &mut manifest,
                        &mut request_file_identifier,
                        &hashset_answer.file_identifier,
                        None,
                    )
                    .await?;
                    if let Some(hashset) = hashset_answer.md4_hashset {
                        manifest = transfer_runtime
                            .store_md4_hashset(file_hash_hex, hashset)
                            .await?;
                    }
                    if let Some(hashset) = hashset_answer.aich_hashset {
                        manifest = transfer_runtime
                            .store_aich_hashset(file_hash_hex, hashset)
                            .await?;
                        request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
                    }
                }
                (OP_EDONKEYPROT, OP_REQFILENAMEANSWER) => {
                    let (returned_hash, returned_file_name) =
                        decode_request_filename_answer(&packet.payload)?;
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "OP_REQFILENAMEANSWER hash mismatch {} expected {}",
                            returned_hash,
                            file_hash
                        );
                    }
                    manifest = transfer_runtime
                        .reconcile_job_metadata(
                            file_hash_hex,
                            Some(returned_file_name.as_str()),
                            None,
                        )
                        .await?;
                    request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
                    startup_file_response_received = true;
                }
                (OP_EDONKEYPROT, OP_FILESTATUS) => {
                    let (returned_hash, _part_count) = decode_file_status_payload(&packet.payload)?;
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "peer {peer_addr} returned file status for unexpected file {}",
                            returned_hash
                        );
                    }
                    startup_file_response_received = true;
                }
                (OP_EMULEPROT, OP_MULTIPACKETANSWER_EXT2) => {
                    let (returned_identifier, mut remaining) =
                        Ed2kFileIdentifier::decode(&packet.payload)?;
                    if !request_file_identifier.matches_relaxed(&returned_identifier) {
                        anyhow::bail!(
                            "peer {peer_addr} returned OP_MULTIPACKETANSWER_EXT2 for unexpected file {}",
                            returned_identifier.file_hash
                        );
                    }
                    let mut returned_file_name = None;
                    while let Some((&sub_opcode, rest)) = remaining.split_first() {
                        remaining = rest;
                        match sub_opcode {
                            OP_REQFILENAMEANSWER => {
                                let (file_name, rest) =
                                    decode_request_filename_answer_body(remaining)?;
                                remaining = rest;
                                returned_file_name = Some(file_name);
                            }
                            OP_FILESTATUS => {
                                let (_part_count, rest) = skip_file_status_body(remaining)?;
                                remaining = rest;
                            }
                            _ => {
                                anyhow::bail!(
                                    "unsupported OP_MULTIPACKETANSWER_EXT2 sub-op 0x{sub_opcode:02X}"
                                );
                            }
                        }
                    }
                    reconcile_download_manifest_metadata(
                        transfer_runtime,
                        file_hash_hex,
                        &mut manifest,
                        &mut request_file_identifier,
                        &returned_identifier,
                        returned_file_name.as_deref(),
                    )
                    .await?;
                    startup_file_response_received = true;
                }
                (OP_EMULEPROT, OP_AICHFILEHASHANS) => {
                    let returned_hash = decode_aich_file_hash_answer(&packet.payload)?;
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "peer {peer_addr} returned AICH file hash for unexpected file {}",
                            returned_hash
                        );
                    }
                }
                (OP_EDONKEYPROT, OP_SETREQFILEID) => {
                    // Non-oracle peers sometimes echo the file id again instead of
                    // the expected file-status payload. Stay tolerant, but do not
                    // treat it as the startup gate that oracle-like peers rely on.
                }
                (OP_EMULEPROT, OP_ANSWERSOURCES) | (OP_EMULEPROT, OP_ANSWERSOURCES2) => {
                    // Source-exchange replies are opportunistic parity traffic. The
                    // direct downloader does not consume them yet, but the oracle does
                    // emit the request during startup, so stay tolerant here.
                }
                (OP_EMULEPROT, OP_QUEUERANKING) => {
                    queued_until = Some(tokio::time::Instant::now() + QUEUE_RANK_GRACE);
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "queue_ranking",
                        format!("file_hash={file_hash_hex}"),
                    );
                }
                (OP_EMULEPROT, OP_FILEDESC) => {
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "file_desc",
                        format!("file_hash={file_hash_hex}"),
                    );
                }
                (OP_EDONKEYPROT, OP_FILEREQANSNOFIL) => {
                    anyhow::bail!("peer {peer_addr} does not serve requested file {file_hash_hex}");
                }
                (OP_EDONKEYPROT, OP_SENDINGPART)
                | (OP_EMULEPROT, OP_SENDINGPART_I64)
                | (OP_EMULEPROT, OP_COMPRESSEDPART)
                | (OP_EMULEPROT, OP_COMPRESSEDPART_I64) => {
                    let use_i64 = packet.opcode == OP_SENDINGPART_I64
                        || packet.opcode == OP_COMPRESSEDPART_I64;
                    if packet.opcode == OP_COMPRESSEDPART || packet.opcode == OP_COMPRESSEDPART_I64 {
                        let (returned_hash, start, advertised_compressed_len, compressed_fragment) =
                            decode_compressed_part_fragment(&packet.payload, use_i64)?;
                        if returned_hash != file_hash {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_part_hash",
                                format!(
                                    "expected_file_hash={file_hash_hex} returned_file_hash={returned_hash} start={start} compressed_len={advertised_compressed_len}"
                                ),
                            );
                            continue;
                        }
                        if !pending_part_requests.iter().any(|request| request.queued) {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_compressed_part_without_queued_request",
                                format!(
                                    "file_hash={file_hash_hex} start={start} compressed_len={advertised_compressed_len}"
                                ),
                            );
                            return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                        }
                        let Some(pending_index) = pending_part_requests.iter().position(
                            |request| request.queued && request.start == start && request.end > request.start,
                        ) else {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_compressed_part_range",
                                format!(
                                    "file_hash={file_hash_hex} start={start} compressed_len={advertised_compressed_len} pending={:?}",
                                    pending_part_requests
                                ),
                            );
                            return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                        };
                        let expected_request = pending_part_requests[pending_index].clone();
                        let expected_part = expected_request.piece_index;
                        let expected_start = expected_request.start;
                        let expected_end = expected_request.end;
                        let compressed_index = if let Some(index) = pending_compressed_parts
                            .iter()
                            .position(|pending| {
                                pending.piece_index == expected_part
                                    && pending.start == expected_start
                                    && pending.end == expected_end
                            })
                        {
                            let pending = &pending_compressed_parts[index];
                            if pending.advertised_compressed_len != advertised_compressed_len {
                                anyhow::bail!(
                                    "peer {peer_addr} changed compressed-part framing for piece {expected_part} start={}..{} advertised={} expected={}..{} advertised={}",
                                    pending.start,
                                    pending.end,
                                    pending.advertised_compressed_len,
                                    expected_start,
                                    expected_end,
                                    advertised_compressed_len
                                );
                            }
                            index
                        } else {
                            pending_compressed_parts.push(PendingCompressedPart {
                                piece_index: expected_part,
                                start: expected_start,
                                end: expected_end,
                                advertised_compressed_len,
                                compressed_received: 0,
                                uncompressed_written: 0,
                                inflater: Decompress::new(true),
                            });
                            pending_compressed_parts.len() - 1
                        };
                        let (bytes, finished) = {
                            let pending = &mut pending_compressed_parts[compressed_index];
                            inflate_compressed_part_fragment(pending, compressed_fragment)?
                        };
                        let stream_end = {
                            let pending = &pending_compressed_parts[compressed_index];
                            pending.start + pending.uncompressed_written
                        };
                        if !bytes.is_empty() {
                            let stream_start = stream_end
                                .checked_sub(u64::try_from(bytes.len()).unwrap_or(0))
                                .unwrap_or(start);
                            let expected_received_start =
                                pending_part_requests[pending_index].received_end;
                            if stream_start != expected_received_start {
                                dump_ed2k_tcp_download_meta(
                                    peer_addr,
                                    Some(transport.mode),
                                    "out_of_order_compressed_part_range",
                                    format!(
                                        "file_hash={file_hash_hex} piece_index={expected_part} expected_start={} start={stream_start} end={stream_end} pending={:?}",
                                        expected_received_start,
                                        pending_part_requests
                                    ),
                                );
                                return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                            }
                            pending_part_requests[pending_index]
                                .buffer_response_bytes(stream_start, stream_end, &bytes)?;
                        }
                        let piece_len = expected_end - expected_start;
                        let pending = &pending_compressed_parts[compressed_index];
                        if pending.uncompressed_written > piece_len {
                            anyhow::bail!(
                                "peer {peer_addr} decompressed beyond requested piece boundary for piece {expected_part}: wrote {} expected {}",
                                pending.uncompressed_written,
                                piece_len
                            );
                        }
                        if finished && pending.uncompressed_written != piece_len {
                            anyhow::bail!(
                                "peer {peer_addr} ended compressed stream early for piece {expected_part}: wrote {} expected {}",
                                pending.uncompressed_written,
                                piece_len
                            );
                        }
                        if pending.uncompressed_written == piece_len {
                            pending_compressed_parts.remove(compressed_index);
                        }
                        flush_ready_download_blocks(ReadyDownloadBlocks {
                            transfer_runtime,
                            file_hash_hex,
                            pending_part_requests: &mut pending_part_requests,
                            active_piece_request: &mut active_piece_request,
                            manifest: &mut manifest,
                            peer_addr,
                            transport_mode: transport.mode,
                            completed_block_count: &mut completed_block_count,
                            session_payload_down: &mut session_payload_down,
                            part_response_deadline: &mut part_response_deadline,
                        })
                        .await?;
                    } else {
                        let (returned_hash, start, end, bytes) =
                            decode_sending_part_payload(&packet.payload, use_i64)?;
                        if returned_hash != file_hash {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_part_hash",
                                format!(
                                    "expected_file_hash={file_hash_hex} returned_file_hash={returned_hash} start={start} end={end}"
                                ),
                            );
                            continue;
                        }
                        if !pending_part_requests.iter().any(|request| request.queued) {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_part_without_queued_request",
                                format!("file_hash={file_hash_hex} start={start} end={end}"),
                            );
                            return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                        }
                        let Some(pending_index) = pending_part_requests.iter().position(
                            |request| request.matches_uncompressed_fragment(start, end),
                        ) else {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_part_range",
                                format!(
                                    "file_hash={file_hash_hex} start={start} end={end} pending={:?}",
                                    pending_part_requests
                                ),
                            );
                            return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                        };
                        let expected_request = pending_part_requests[pending_index].clone();
                        let expected_start = expected_request.start;
                        if start < expected_start {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_part_fragment_start",
                                format!(
                                    "file_hash={file_hash_hex} expected_start={expected_start} start={start} end={end} pending={:?}",
                                    pending_part_requests
                                ),
                            );
                            return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                        }
                        pending_part_requests[pending_index]
                            .buffer_response_bytes(start, end, &bytes)?;
                        flush_ready_download_blocks(ReadyDownloadBlocks {
                            transfer_runtime,
                            file_hash_hex,
                            pending_part_requests: &mut pending_part_requests,
                            active_piece_request: &mut active_piece_request,
                            manifest: &mut manifest,
                            peer_addr,
                            transport_mode: transport.mode,
                            completed_block_count: &mut completed_block_count,
                            session_payload_down: &mut session_payload_down,
                            part_response_deadline: &mut part_response_deadline,
                        })
                        .await?;
                    }
                }
                _ => {}
            }
        }
    }
    .await;

    if matches!(
        &session_result,
        Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete)
    ) {
        flush_buffered_download_prefixes(
            transfer_runtime,
            file_hash_hex,
            &mut pending_part_requests,
            &mut active_piece_request,
            &mut manifest,
            peer_addr,
            transport.mode,
        )
        .await?;
    }

    if let Some(active_piece) = active_piece_request.or_else(|| {
        pending_part_requests
            .first()
            .map(|request| ActiveDownloadPiece {
                piece_index: request.piece_index,
                next_offset: request.end,
                piece_end: request.end,
            })
    }) {
        transfer_runtime
            .release_piece_request(file_hash_hex, active_piece.piece_index)
            .await?;
    }

    session_result
}

async fn pump_download_request_window(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    state: DownloadRequestWindowState<'_>,
) -> Result<Option<tokio::time::Instant>> {
    let DownloadRequestWindowState {
        transfer_runtime,
        file_hash,
        file_hash_hex,
        file_size,
        manifest,
        active_piece_request,
        pending_part_requests,
        upload_accepted_at,
        completed_block_count,
        session_payload_down,
        part_response_grace,
    } = state;
    let window = select_download_window_limits(
        manifest,
        completed_block_count,
        session_payload_down,
        upload_accepted_at,
    );
    if pending_part_requests.len() < window.min_pending_blocks {
        while pending_part_requests.len() < window.max_pending_blocks {
            if active_piece_request.is_none() {
                let Some(next_part) = transfer_runtime
                    .claim_next_missing_part(file_hash_hex)
                    .await?
                else {
                    break;
                };
                let piece_start = u64::from(next_part.piece_index) * ED2K_PART_SIZE;
                let piece_end = (piece_start + ED2K_PART_SIZE).min(file_size);
                *active_piece_request = Some(ActiveDownloadPiece {
                    piece_index: next_part.piece_index,
                    next_offset: piece_start + next_part.bytes_written,
                    piece_end,
                });
            }
            let Some(active_piece) = active_piece_request.as_mut() else {
                break;
            };
            if active_piece.next_offset >= active_piece.piece_end {
                break;
            }
            let end = (active_piece.next_offset + ED2K_EMBLOCK_SIZE).min(active_piece.piece_end);
            pending_part_requests.push(PendingPartRequest::new(
                active_piece.piece_index,
                active_piece.next_offset,
                end,
            ));
            active_piece.next_offset = end;
        }
    }

    let mut request_indices = Vec::with_capacity(3);
    let mut requested_ranges = Vec::with_capacity(3);
    for (index, request) in pending_part_requests.iter().enumerate() {
        if request.queued {
            continue;
        }
        request_indices.push(index);
        requested_ranges.push((request.start, request.end));
        if request_indices.len() >= 3 {
            break;
        }
    }
    if requested_ranges.is_empty() {
        return Ok(None);
    }

    let request_parts = encode_request_parts_batch(file_hash, &requested_ranges)?;
    dump_ed2k_tcp_download_send(peer_addr, transport.mode, "request_parts", &request_parts);
    transport
        .write_all(&request_parts)
        .await
        .with_context(|| format!("failed to send OP_REQUESTPARTS to {peer_addr}"))?;
    for index in request_indices {
        pending_part_requests[index].queued = true;
    }
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "request_window",
        format!(
            "file_hash={file_hash_hex} queued={} total_pending={} max_pending={} min_pending={}",
            requested_ranges.len(),
            pending_part_requests.len(),
            window.max_pending_blocks,
            window.min_pending_blocks
        ),
    );
    Ok(Some(tokio::time::Instant::now() + part_response_grace))
}

#[must_use]
fn select_download_window_limits(
    manifest: &Ed2kResumeManifest,
    completed_block_count: usize,
    session_payload_down: u64,
    upload_accepted_at: tokio::time::Instant,
) -> DownloadWindowLimits {
    if completed_block_count == 0 || session_payload_down == 0 {
        return DownloadWindowLimits {
            max_pending_blocks: 1,
            min_pending_blocks: 1,
        };
    }

    let remaining_bytes = remaining_unverified_bytes(manifest);
    let elapsed_secs = upload_accepted_at.elapsed().as_secs_f64().max(0.001);
    let download_rate = session_payload_down as f64 / elapsed_secs;

    let (max_pending_blocks, block_delta) = if remaining_bytes <= ED2K_PART_SIZE * 4 {
        if completed_block_count < 2 || download_rate < 600.0 || session_payload_down < 40 * 1024 {
            (1usize, 0usize)
        } else if download_rate < 1200.0 {
            (2usize, 0usize)
        } else {
            (3usize, 1usize)
        }
    } else if completed_block_count >= 3 && download_rate > 75.0 * 1024.0 {
        (6usize, 2usize)
    } else {
        (3usize, 1usize)
    };

    DownloadWindowLimits {
        max_pending_blocks,
        min_pending_blocks: max_pending_blocks.saturating_sub(block_delta).max(1),
    }
}

#[must_use]
fn remaining_unverified_bytes(manifest: &Ed2kResumeManifest) -> u64 {
    manifest
        .pieces
        .iter()
        .map(|piece| {
            let piece_len = expected_piece_length(
                manifest.file_size,
                manifest.piece_size,
                u64::from(piece.piece_index),
            );
            piece_len.saturating_sub(piece.bytes_written)
        })
        .sum()
}

/// Pick the next ED2K download read wait so queue and part-response grace
/// windows are enforced even when the caller configured a much larger session
/// timeout.
#[must_use]
fn next_download_read_timeout(
    now: tokio::time::Instant,
    base_timeout: Duration,
    fallback_poll_delay: Option<Duration>,
    queued_until: Option<tokio::time::Instant>,
    part_response_deadline: Option<tokio::time::Instant>,
) -> Duration {
    let mut read_timeout =
        fallback_poll_delay.map_or(base_timeout, |delay| base_timeout.min(delay));
    if let Some(deadline) = queued_until {
        read_timeout = read_timeout.min(deadline.saturating_duration_since(now));
    }
    if let Some(deadline) = part_response_deadline {
        read_timeout = read_timeout.min(deadline.saturating_duration_since(now));
    }
    read_timeout
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
        let (protocol, payload) = decode_peer_payload(protocol, payload)?;
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

/// Decode one peer TCP payload exactly like the oracle socket path: packed
/// frames inflate first and then continue through the eMule extension opcode
/// dispatcher as `OP_EMULEPROT`.
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

struct ReadyDownloadBlocks<'a> {
    transfer_runtime: &'a Ed2kTransferRuntime,
    file_hash_hex: &'a str,
    pending_part_requests: &'a mut Vec<PendingPartRequest>,
    active_piece_request: &'a mut Option<ActiveDownloadPiece>,
    manifest: &'a mut Ed2kResumeManifest,
    peer_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    completed_block_count: &'a mut usize,
    session_payload_down: &'a mut u64,
    part_response_deadline: &'a mut Option<tokio::time::Instant>,
}

async fn flush_ready_download_blocks(blocks: ReadyDownloadBlocks<'_>) -> Result<()> {
    let ReadyDownloadBlocks {
        transfer_runtime,
        file_hash_hex,
        pending_part_requests,
        active_piece_request,
        manifest,
        peer_addr,
        transport_mode,
        completed_block_count,
        session_payload_down,
        part_response_deadline,
    } = blocks;
    while pending_part_requests
        .first()
        .is_some_and(|request| request.queued && request.is_ready())
    {
        let request = pending_part_requests.remove(0);
        let piece_completed = transfer_runtime
            .append_piece_block(
                file_hash_hex,
                request.piece_index,
                request.start,
                request.end,
                &request.response_bytes,
            )
            .await?;
        *manifest = transfer_runtime.manifest(file_hash_hex).await?;
        if piece_completed {
            *active_piece_request = None;
        }
        dump_ed2k_tcp_download_meta(
            peer_addr,
            Some(transport_mode),
            "piece_block_flushed",
            format!(
                "file_hash={file_hash_hex} piece_index={} start={} end={} completed={}",
                request.piece_index, request.start, request.end, manifest.completed
            ),
        );
        *completed_block_count = completed_block_count.saturating_add(1);
        *session_payload_down =
            session_payload_down.saturating_add(request.end.saturating_sub(request.start));
    }
    if !pending_part_requests.iter().any(|request| request.queued) {
        *part_response_deadline = None;
    }
    Ok(())
}

async fn flush_buffered_download_prefixes(
    transfer_runtime: &Ed2kTransferRuntime,
    file_hash_hex: &str,
    pending_part_requests: &mut Vec<PendingPartRequest>,
    active_piece_request: &mut Option<ActiveDownloadPiece>,
    manifest: &mut Ed2kResumeManifest,
    peer_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
) -> Result<()> {
    loop {
        let Some(first_request) = pending_part_requests.first() else {
            break;
        };
        if !first_request.queued || first_request.response_bytes.is_empty() {
            break;
        }

        let (piece_index, start, end, bytes, request_complete) = {
            let request = &mut pending_part_requests[0];
            let bytes = std::mem::take(&mut request.response_bytes);
            let start = request.start;
            let end = request.received_end;
            request.start = end;
            (
                request.piece_index,
                start,
                end,
                bytes,
                request.start == request.end,
            )
        };

        let piece_completed = transfer_runtime
            .append_piece_block(file_hash_hex, piece_index, start, end, &bytes)
            .await?;
        *manifest = transfer_runtime.manifest(file_hash_hex).await?;
        if piece_completed {
            *active_piece_request = None;
        }
        dump_ed2k_tcp_download_meta(
            peer_addr,
            Some(transport_mode),
            "piece_prefix_flushed",
            format!(
                "file_hash={file_hash_hex} piece_index={piece_index} start={start} end={end} completed={}",
                manifest.completed
            ),
        );

        if request_complete {
            pending_part_requests.remove(0);
            continue;
        }
        break;
    }
    Ok(())
}

async fn reconcile_download_manifest_metadata(
    transfer_runtime: &Ed2kTransferRuntime,
    file_hash_hex: &str,
    manifest: &mut Ed2kResumeManifest,
    request_file_identifier: &mut Ed2kFileIdentifier,
    peer_file_identifier: &Ed2kFileIdentifier,
    peer_file_name: Option<&str>,
) -> Result<()> {
    let learned_size = peer_file_identifier.file_size;
    let learned_name = peer_file_name
        .map(str::trim)
        .filter(|name| !name.is_empty());
    if learned_size.is_none() && learned_name.is_none() && peer_file_identifier.aich_root.is_none()
    {
        return Ok(());
    }

    *manifest = transfer_runtime
        .reconcile_job_metadata(file_hash_hex, learned_name, learned_size)
        .await?;
    *manifest = transfer_runtime
        .reconcile_aich_root(file_hash_hex, peer_file_identifier.aich_root)
        .await?;
    *request_file_identifier = Ed2kFileIdentifier::from_manifest(manifest)?;
    Ok(())
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
mod tests;
