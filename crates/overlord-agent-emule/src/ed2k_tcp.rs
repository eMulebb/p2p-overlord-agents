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
    borrow::Cow,
    collections::VecDeque,
    fs,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    str::FromStr,
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::SecondsFormat;
use flate2::{
    Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status, read::ZlibDecoder,
};
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
use tracing::{debug, info, warn};

use crate::ed2k_server::{Ed2kFoundSource, Ed2kServerState};
use crate::ed2k_transfer::{
    ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kSharedEntry, Ed2kSourceHint,
    Ed2kTransferRuntime, Ed2kTransferState, Ed2kUploadPeerIdentity, Ed2kUploadSessionHandle,
    Ed2kUploadSessionStatus, expected_piece_length, new_transfer_job,
};
use crate::kad_firewall::KadFirewallState;
use overlord_kad_dht::DhtNode;
use overlord_kad_proto::{Ed2kHash, FirewallUdp, KadPacket};

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
            aich_root: None,
        })
    }

    fn from_shared_entry(shared: &Ed2kSharedEntry) -> Result<Self> {
        Ok(Self {
            file_hash: shared.parsed_hash()?,
            file_size: Some(shared.file_size).filter(|file_size| *file_size != 0),
            aich_root: None,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ed2kAichHashset {
    master_hash: [u8; 20],
    part_hashes: Vec<[u8; 20]>,
}

type Ed2kMd4Hashset = Vec<[u8; 16]>;
type Ed2kMd4HashsetDecode<'a> = (Ed2kHash, Ed2kMd4Hashset, &'a [u8]);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ed2kHashsetAnswer2 {
    file_identifier: Ed2kFileIdentifier,
    md4_hashset: Option<Ed2kMd4Hashset>,
    aich_hashset: Option<Ed2kAichHashset>,
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
    peer_signature_received: bool,
    requested_peer_key: bool,
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

#[derive(Debug, Serialize)]
struct Ed2kTcpDumpRecord<'a> {
    schema: &'static str,
    source: &'static str,
    ts_utc: String,
    event_seq: u64,
    trace_key: String,
    state_id: String,
    state_label: &'a str,
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

fn ed2k_tcp_dump_event_seq() -> u64 {
    static NEXT_EVENT_SEQ: AtomicU64 = AtomicU64::new(1);
    NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed)
}

fn ed2k_tcp_trace_key(flow: &'static str, remote_addr: SocketAddr) -> String {
    format!("{flow}:{remote_addr}")
}

fn ed2k_tcp_state_id(flow: &'static str, phase: &str) -> String {
    format!("{flow}.{phase}")
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
        (OP_EMULEPROT, OP_COMPRESSEDPART) => "OP_COMPRESSEDPART",
        (OP_EDONKEYPROT, OP_SENDINGPART) => "OP_SENDINGPART",
        (OP_EDONKEYPROT, OP_REQUESTPARTS) => "OP_REQUESTPARTS",
        (OP_EDONKEYPROT, OP_FILEREQANSNOFIL) => "OP_FILEREQANSNOFIL",
        (OP_EDONKEYPROT, OP_SETREQFILEID) => "OP_SETREQFILEID",
        (OP_EDONKEYPROT, OP_FILESTATUS) => "OP_FILESTATUS",
        (OP_EDONKEYPROT, OP_HASHSETREQUEST) => "OP_HASHSETREQUEST",
        (OP_EDONKEYPROT, OP_HASHSETANSWER) => "OP_HASHSETANSWER",
        (OP_EDONKEYPROT, OP_STARTUPLOADREQ) => "OP_STARTUPLOADREQ",
        (OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ) => "OP_ACCEPTUPLOADREQ",
        (OP_EDONKEYPROT, OP_CANCELTRANSFER) => "OP_CANCELTRANSFER",
        (OP_EDONKEYPROT, OP_REQUESTFILENAME) => "OP_REQUESTFILENAME",
        (OP_EDONKEYPROT, OP_REQFILENAMEANSWER) => "OP_REQFILENAMEANSWER",
        (OP_EMULEPROT, OP_REQUESTSOURCES) => "OP_REQUESTSOURCES",
        (OP_EMULEPROT, OP_ANSWERSOURCES) => "OP_ANSWERSOURCES",
        (OP_EMULEPROT, OP_REQUESTSOURCES2) => "OP_REQUESTSOURCES2",
        (OP_EMULEPROT, OP_ANSWERSOURCES2) => "OP_ANSWERSOURCES2",
        (OP_EMULEPROT, OP_AICHFILEHASHANS) => "OP_AICHFILEHASHANS",
        (OP_EMULEPROT, OP_AICHFILEHASHREQ) => "OP_AICHFILEHASHREQ",
        (OP_EMULEPROT, OP_EMULEINFO) => "OP_EMULEINFO",
        (OP_EMULEPROT, OP_EMULEINFOANSWER) => "OP_EMULEINFOANSWER",
        (OP_EMULEPROT, OP_QUEUERANKING) => "OP_QUEUERANKING",
        (OP_EMULEPROT, OP_FILEDESC) => "OP_FILEDESC",
        (OP_EMULEPROT, OP_COMPRESSEDPART_I64) => "OP_COMPRESSEDPART_I64",
        (OP_EMULEPROT, OP_SENDINGPART_I64) => "OP_SENDINGPART_I64",
        (OP_EMULEPROT, OP_REQUESTPARTS_I64) => "OP_REQUESTPARTS_I64",
        (OP_EMULEPROT, OP_HASHSETREQUEST2) => "OP_HASHSETREQUEST2",
        (OP_EMULEPROT, OP_HASHSETANSWER2) => "OP_HASHSETANSWER2",
        (OP_EMULEPROT, OP_PUBLICKEY) => "OP_PUBLICKEY",
        (OP_EMULEPROT, OP_SIGNATURE) => "OP_SIGNATURE",
        (OP_EMULEPROT, OP_SECIDENTSTATE) => "OP_SECIDENTSTATE",
        (OP_EMULEPROT, OP_FWCHECKUDPREQ) => "OP_FWCHECKUDPREQ",
        _ => "UNKNOWN",
    }
}

fn oracle_ed2k_send_phase(flow: &'static str, protocol: u8, opcode: u8) -> Option<&'static str> {
    let phase = match (protocol, opcode) {
        (OP_EDONKEYPROT, OP_HELLO) => "hello_request",
        (OP_EDONKEYPROT, OP_HELLOANSWER) => "hello_answer",
        (OP_EDONKEYPROT, OP_REQFILENAMEANSWER) => "filename_answer",
        (OP_EDONKEYPROT, OP_FILESTATUS) => "file_status",
        (OP_EMULEPROT, OP_EMULEINFO) => "mule_info",
        (OP_EMULEPROT, OP_EMULEINFOANSWER) => "mule_info_answer",
        (OP_EMULEPROT, OP_PUBLICKEY) => "public_key",
        (OP_EMULEPROT, OP_SIGNATURE) => "signature",
        (OP_EMULEPROT, OP_SECIDENTSTATE) => "secure_ident_probe",
        (OP_EMULEPROT, OP_FWCHECKUDPREQ) => "fwcheck_request",
        _ => match flow {
            // The oracle emits generic per-session labels for ordinary listener and
            // downloader traffic, and only uses dedicated phase names for a small
            // parity-critical subset.
            "listener" | "native_download" => "session",
            "udp_firewall_check" => "hello_exchange",
            _ => return None,
        },
    };
    Some(phase)
}

fn oracle_ed2k_recv_phase(flow: &'static str, protocol: u8, opcode: u8) -> Option<&'static str> {
    let phase = match (protocol, opcode) {
        (OP_EMULEPROT, OP_FWCHECKUDPREQ) => "fwcheck_request",
        _ => match flow {
            "listener" | "native_download" => "session",
            "udp_firewall_check" => "hello_exchange",
            _ => return None,
        },
    };
    Some(phase)
}

fn canonical_ed2k_send_phase<'a>(
    flow: &'static str,
    fallback: &'a str,
    protocol: Option<u8>,
    opcode: Option<u8>,
) -> Cow<'a, str> {
    if let Some((protocol, opcode)) = protocol.zip(opcode)
        && let Some(phase) = oracle_ed2k_send_phase(flow, protocol, opcode)
    {
        return Cow::Borrowed(phase);
    }

    Cow::Borrowed(fallback)
}

fn canonical_ed2k_recv_phase<'a>(
    flow: &'static str,
    fallback: &'a str,
    protocol: u8,
    opcode: u8,
) -> Cow<'a, str> {
    if let Some(phase) = oracle_ed2k_recv_phase(flow, protocol, opcode) {
        return Cow::Borrowed(phase);
    }

    Cow::Borrowed(fallback)
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
        source: "agent",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: ed2k_tcp_dump_event_seq(),
        trace_key: ed2k_tcp_trace_key(flow, remote_addr),
        state_id: ed2k_tcp_state_id(flow, phase),
        state_label: phase,
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
    let canonical_phase = canonical_ed2k_send_phase(flow, phase, protocol, opcode);
    let record = Ed2kTcpDumpRecord {
        schema: "ed2k_tcp_helper_v1",
        source: "agent",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: ed2k_tcp_dump_event_seq(),
        trace_key: ed2k_tcp_trace_key(flow, remote_addr),
        state_id: ed2k_tcp_state_id(flow, canonical_phase.as_ref()),
        state_label: canonical_phase.as_ref(),
        flow,
        phase: canonical_phase.as_ref(),
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
    let canonical_phase = canonical_ed2k_recv_phase(flow, phase, packet.protocol, packet.opcode);
    let record = Ed2kTcpDumpRecord {
        schema: "ed2k_tcp_helper_v1",
        source: "agent",
        ts_utc: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_seq: ed2k_tcp_dump_event_seq(),
        trace_key: ed2k_tcp_trace_key(flow, remote_addr),
        state_id: ed2k_tcp_state_id(flow, canonical_phase.as_ref()),
        state_label: canonical_phase.as_ref(),
        flow,
        phase: canonical_phase.as_ref(),
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

pub(crate) fn dump_ed2k_tcp_download_meta(
    remote_addr: SocketAddr,
    transport_mode: Option<Ed2kTransportMode>,
    phase: &str,
    note: impl Into<String>,
) {
    dump_ed2k_tcp_meta("native_download", remote_addr, transport_mode, phase, note);
}

fn dump_ed2k_tcp_download_send(
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    bytes: &[u8],
) {
    dump_ed2k_tcp_send("native_download", remote_addr, transport_mode, phase, bytes);
}

fn dump_ed2k_tcp_download_recv(
    remote_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    phase: &str,
    packet: &EmuleTcpPacket,
) {
    dump_ed2k_tcp_recv(
        "native_download",
        remote_addr,
        transport_mode,
        phase,
        packet,
    );
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
#[allow(clippy::too_many_arguments)]
pub(crate) async fn download_file_from_peer(
    bind_ip: Ipv4Addr,
    peer: &Ed2kFoundSource,
    hello_identity: Ed2kHelloIdentity,
    secure_ident: &Arc<Ed2kSecureIdent>,
    transfer_runtime: &Ed2kTransferRuntime,
    canonical_name: String,
    file_size: u64,
    timeout: Duration,
) -> Result<Ed2kPeerDownloadOutcome> {
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
        let session_result = drive_download_session(
            &mut transport,
            peer_addr,
            hello_identity,
            secure_ident.as_ref(),
            transfer_runtime,
            file_hash,
            &file_hash_hex,
            file_size,
            timeout,
            true,
            false,
            false,
        )
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

#[allow(clippy::too_many_arguments)]
async fn drive_download_session(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    hello_identity: Ed2kHelloIdentity,
    secure_ident: &Ed2kSecureIdent,
    transfer_runtime: &Ed2kTransferRuntime,
    file_hash: Ed2kHash,
    file_hash_hex: &str,
    file_size: u64,
    timeout: Duration,
    send_initial_requests: bool,
    initial_hello_complete: bool,
    initial_secure_ident_started: bool,
) -> Result<Ed2kPeerDownloadOutcome> {
    const HASHSET_STALL_UPLOAD_FALLBACK: Duration = Duration::from_millis(500);
    const QUEUE_RANK_GRACE: Duration = Duration::from_secs(20);
    const PART_RESPONSE_GRACE: Duration = Duration::from_secs(20);
    // eMule keeps a pending block scheduler that is broader than one live wire
    // request. We mirror that with one claimed piece, a queued-vs-unqueued
    // block list, and wire packets that carry up to three queued ranges.
    let mut pending_part_requests: Vec<PendingPartRequest> = Vec::new();
    let mut pending_compressed_parts: Vec<PendingCompressedPart> = Vec::new();
    let mut manifest = transfer_runtime.manifest(file_hash_hex).await?;
    let request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
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

                    if file_size > ED2K_PART_SIZE {
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
                && !manifest.md4_hashset_acquired
                && !hashset_requested
                && !waiting_for_peer_secure_ident
                && startup_file_response_received
            {
                if file_size <= ED2K_PART_SIZE {
                    manifest = transfer_runtime
                        .store_md4_hashset(file_hash_hex, Vec::new())
                        .await?;
                } else {
                    let hashset_request = if remote_supports_file_identifiers {
                        encode_hashset_request2(
                            &request_file_identifier,
                            Ed2kHashsetRequestOptions {
                                request_md4: true,
                                request_aich: false,
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
                        file_size,
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
                    if let Some(hashset) = hashset_answer.md4_hashset {
                        manifest = transfer_runtime
                            .store_md4_hashset(file_hash_hex, hashset)
                            .await?;
                    }
                }
                (OP_EDONKEYPROT, OP_REQFILENAMEANSWER) => {
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
                    while let Some((&sub_opcode, rest)) = remaining.split_first() {
                        remaining = rest;
                        match sub_opcode {
                            OP_REQFILENAMEANSWER => {
                                remaining = skip_request_filename_answer_body(remaining)?;
                                startup_file_response_received = true;
                            }
                            OP_FILESTATUS => {
                                let (_part_count, rest) = skip_file_status_body(remaining)?;
                                remaining = rest;
                                startup_file_response_received = true;
                            }
                            _ => {
                                anyhow::bail!(
                                    "unsupported OP_MULTIPACKETANSWER_EXT2 sub-op 0x{sub_opcode:02X}"
                                );
                            }
                        }
                    }
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
                        flush_ready_download_blocks(
                            transfer_runtime,
                            file_hash_hex,
                            &mut pending_part_requests,
                            &mut active_piece_request,
                            &mut manifest,
                            peer_addr,
                            transport.mode,
                            &mut completed_block_count,
                            &mut session_payload_down,
                            &mut part_response_deadline,
                        )
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
                        flush_ready_download_blocks(
                            transfer_runtime,
                            file_hash_hex,
                            &mut pending_part_requests,
                            &mut active_piece_request,
                            &mut manifest,
                            peer_addr,
                            transport.mode,
                            &mut completed_block_count,
                            &mut session_payload_down,
                            &mut part_response_deadline,
                        )
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
fn decode_peer_payload(protocol: u8, payload: Vec<u8>) -> Result<(u8, Vec<u8>)> {
    if protocol != OP_PACKEDPROT {
        return Ok((protocol, payload));
    }

    let mut decoder = ZlibDecoder::new(payload.as_slice());
    let mut decoded = Vec::with_capacity(
        payload
            .len()
            .saturating_mul(10)
            .saturating_add(300)
            .min(MAX_PEER_DECOMPRESSED_PACKET_LEN),
    );
    let mut chunk = [0u8; 4096];
    loop {
        let read = decoder.read(&mut chunk).context("zlib inflate failed")?;
        if read == 0 {
            break;
        }
        if decoded.len().saturating_add(read) > MAX_PEER_DECOMPRESSED_PACKET_LEN {
            anyhow::bail!(
                "decompressed ED2K peer packet exceeded {} bytes",
                MAX_PEER_DECOMPRESSED_PACKET_LEN
            );
        }
        decoded.extend_from_slice(&chunk[..read]);
    }
    Ok((OP_EMULEPROT, decoded))
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
    payload.extend_from_slice(&encode_hello_type_payload(
        identity,
        append_emule_hello_request_tags,
    ));
    encode_packet(OP_EDONKEYPROT, OP_HELLO, &payload)
}

fn encode_hello_type_payload(
    identity: Ed2kHelloIdentity,
    append_tags: fn(&mut Vec<u8>, Ed2kHelloIdentity),
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(96);
    payload.extend_from_slice(&identity.user_hash);
    payload.extend_from_slice(&identity.client_id.to_le_bytes());
    payload.extend_from_slice(&identity.tcp_port.to_le_bytes());
    append_tags(&mut payload, identity);
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

fn ed2k_string_tag_type(len: usize) -> u8 {
    if (1..=16).contains(&len) {
        TAGTYPE_STR1 + u8::try_from(len - 1).expect("string tag length fits in u8")
    } else {
        TAGTYPE_STRING
    }
}

fn push_ed2k_string_tag(payload: &mut Vec<u8>, name: u8, value: &str) {
    let value_bytes = value.as_bytes();
    let type_byte = ed2k_string_tag_type(value_bytes.len());
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
    // Recent stock eMule no longer advertises peer cache support.
    let peer_cache = 0u32;
    let no_view_shared_files = 1u32;
    // Recent live-network captures and the local 0.72a source both advertise
    // the packed/multipacket startup profile on the peer hello path.
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
    // Mirror the recent eMule hello profile instead of the older conservative
    // advert. The runtime already exchanges the newer sources2, EXT2, and
    // hashset-request2 startup path that recent peers expect.
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

fn append_emule_hello_request_tags(payload: &mut Vec<u8>, identity: Ed2kHelloIdentity) {
    append_recent_emule_hello_tags(payload, identity);
}

fn append_emule_hello_answer_tags(payload: &mut Vec<u8>, identity: Ed2kHelloIdentity) {
    append_recent_emule_hello_tags(payload, identity);
}

fn append_recent_emule_hello_tags(payload: &mut Vec<u8>, identity: Ed2kHelloIdentity) {
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
        &encode_hello_type_payload(identity, append_emule_hello_answer_tags),
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

struct DecodedHelloTag<'a> {
    tag_name: Option<u8>,
    base_type: u8,
    value: &'a [u8],
    remaining: &'a [u8],
}

fn decode_hello_tag(mut bytes: &[u8]) -> Result<DecodedHelloTag<'_>> {
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

    let (value, remaining) = match base_type {
        TAGTYPE_STRING => {
            if bytes.len() < 2 {
                anyhow::bail!("short eD2k hello string tag length");
            }
            let len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            if bytes.len() < 2 + len {
                anyhow::bail!("short eD2k hello string tag value");
            }
            (&bytes[2..2 + len], &bytes[2 + len..])
        }
        TAGTYPE_STR1..=0x20 => {
            let len = usize::from(base_type - TAGTYPE_STR1 + 1);
            if bytes.len() < len {
                anyhow::bail!("short eD2k hello compact string tag value");
            }
            (&bytes[..len], &bytes[len..])
        }
        TAGTYPE_UINT32 | TAGTYPE_FLOAT32 => {
            if bytes.len() < 4 {
                anyhow::bail!("short eD2k hello 32-bit tag value");
            }
            (&bytes[..4], &bytes[4..])
        }
        TAGTYPE_UINT64 => {
            if bytes.len() < 8 {
                anyhow::bail!("short eD2k hello uint64 tag value");
            }
            (&bytes[..8], &bytes[8..])
        }
        TAGTYPE_UINT16 => {
            if bytes.len() < 2 {
                anyhow::bail!("short eD2k hello uint16 tag value");
            }
            (&bytes[..2], &bytes[2..])
        }
        TAGTYPE_UINT8 | TAGTYPE_BOOL => {
            if bytes.is_empty() {
                anyhow::bail!("short eD2k hello uint8/bool tag value");
            }
            (&bytes[..1], &bytes[1..])
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
            (&bytes[..2 + byte_len], &bytes[2 + byte_len..])
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
            (&bytes[4..4 + blob_len], &bytes[4 + blob_len..])
        }
        0x01 => {
            if bytes.len() < 16 {
                anyhow::bail!("short eD2k hello hash tag value");
            }
            (&bytes[..16], &bytes[16..])
        }
        _ => anyhow::bail!("unsupported eD2k hello tag type 0x{base_type:02X}"),
    };

    Ok(DecodedHelloTag {
        tag_name,
        base_type,
        value,
        remaining,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecodedHelloIdentity {
    user_hash: [u8; 16],
    client_id: u32,
    tcp_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecodedHelloProfile {
    identity: DecodedHelloIdentity,
    is_mule_hello: bool,
    supports_file_identifiers: bool,
}

fn decode_hello_tag_u32(tag: &DecodedHelloTag<'_>) -> Option<u32> {
    match tag.base_type {
        TAGTYPE_UINT32 | TAGTYPE_FLOAT32 => Some(u32::from_le_bytes(tag.value.try_into().ok()?)),
        TAGTYPE_UINT16 => Some(u16::from_le_bytes(tag.value.try_into().ok()?).into()),
        TAGTYPE_UINT8 | TAGTYPE_BOOL => Some(u32::from(tag.value.first().copied()?)),
        _ => None,
    }
}

fn decode_hello_profile_from_type_payload(type_payload: &[u8]) -> Result<DecodedHelloProfile> {
    if type_payload.len() < 16 + 4 + 2 + 4 {
        anyhow::bail!("short eD2k hello identity payload");
    }
    let identity = DecodedHelloIdentity {
        user_hash: type_payload[..16]
            .try_into()
            .context("short eD2k hello user hash")?,
        client_id: u32::from_le_bytes([
            type_payload[16],
            type_payload[17],
            type_payload[18],
            type_payload[19],
        ]),
        tcp_port: u16::from_le_bytes([type_payload[20], type_payload[21]]),
    };

    let mut cursor = &type_payload[22..];
    let tag_count = usize::try_from(u32::from_le_bytes(cursor[..4].try_into().unwrap()))
        .context("eD2k hello tag count overflow")?;
    cursor = &cursor[4..];

    let mut is_mule_hello = false;
    let mut supports_file_identifiers = false;
    for _ in 0..tag_count {
        let tag = decode_hello_tag(cursor)?;
        if tag.tag_name == Some(CT_EMULE_VERSION) {
            is_mule_hello = true;
        }
        if tag.tag_name == Some(CT_EMULE_MISCOPTIONS2)
            && let Some(misc_options2) = decode_hello_tag_u32(&tag)
        {
            supports_file_identifiers = ((misc_options2 >> 13) & 1) != 0;
        }
        cursor = tag.remaining;
    }

    Ok(DecodedHelloProfile {
        identity,
        is_mule_hello,
        supports_file_identifiers,
    })
}

fn decode_hello_profile(payload: &[u8]) -> Result<DecodedHelloProfile> {
    let type_payload = match payload.split_first() {
        Some((&16, rest)) => rest,
        _ => payload,
    };
    decode_hello_profile_from_type_payload(type_payload)
}

fn is_mule_hello_type_payload(payload: &[u8]) -> Result<bool> {
    Ok(decode_hello_profile_from_type_payload(payload)?.is_mule_hello)
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

fn decode_file_status_payload(payload: &[u8]) -> Result<(overlord_kad_proto::Ed2kHash, u16)> {
    if payload.len() < 18 {
        anyhow::bail!("short OP_FILESTATUS payload size {}", payload.len());
    }
    let returned_hash = overlord_kad_proto::Ed2kHash::from_bytes(payload[..16].try_into()?);
    let part_count = u16::from_le_bytes([payload[16], payload[17]]);
    let expected_bitfield_len = usize::from(part_count).div_ceil(8);
    if payload.len() != 18 + expected_bitfield_len {
        anyhow::bail!(
            "invalid OP_FILESTATUS payload size {} for part_count {}",
            payload.len(),
            part_count
        );
    }
    Ok((returned_hash, part_count))
}

fn encode_file_status_complete(file_hash: &overlord_kad_proto::Ed2kHash) -> Vec<u8> {
    let mut payload = Vec::with_capacity(18);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    encode_packet(OP_EDONKEYPROT, OP_FILESTATUS, &payload)
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
#[allow(clippy::too_many_arguments)]
pub async fn run_ed2k_listener(
    listener: Arc<TcpListener>,
    dht: DhtNode,
    server_state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    secure_ident: Arc<Ed2kSecureIdent>,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    hello_identity: Ed2kHelloIdentity,
    shutdown: Arc<AtomicBool>,
) {
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
                        &dht,
                        &server_state,
                        &kad_firewall,
                        &secure_ident,
                        &transfer_runtime,
                        hello_identity,
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

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    dht: &DhtNode,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    secure_ident: &Arc<Ed2kSecureIdent>,
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
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
                    match drive_download_session(
                        &mut transport,
                        peer_addr,
                        response_identity,
                        secure_ident.as_ref(),
                        transfer_runtime,
                        file_hash,
                        &callback_intent.file_hash,
                        callback_intent.file_size,
                        ED2K_CONNECTION_IDLE_TIMEOUT,
                        true,
                        true,
                        true,
                    )
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
                        encode_hashset_answer2(&shared_identifier, md4_hashset.as_deref(), None)?
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

#[cfg(test)]
fn encode_packed_packet(opcode: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(payload)
        .context("failed to deflate ED2K peer payload")?;
    let packed_payload = encoder
        .finish()
        .context("failed to finalize ED2K peer payload compression")?;
    Ok(encode_packet(OP_PACKEDPROT, opcode, &packed_payload))
}

fn decode_file_hash_payload(payload: &[u8]) -> Result<Ed2kHash> {
    if payload.len() < 16 {
        anyhow::bail!("expected 16-byte file hash payload, got {}", payload.len());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    Ok(Ed2kHash::from_bytes(hash))
}

fn encode_file_req_ans_nofil(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_FILEREQANSNOFIL, &file_hash.0)
}

fn encode_accept_upload_req() -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ, &[])
}

fn encode_queue_ranking(rank: u16) -> Vec<u8> {
    let mut payload = [0u8; 12];
    payload[..2].copy_from_slice(&rank.to_le_bytes());
    encode_packet(OP_EMULEPROT, OP_QUEUERANKING, &payload)
}

fn encode_start_upload_req(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_STARTUPLOADREQ, &file_hash.0)
}

fn ed2k_file_part_count(file_size: u64) -> u16 {
    if file_size == 0 {
        return 0;
    }
    u16::try_from(file_size.div_ceil(ED2K_PART_SIZE)).unwrap_or(u16::MAX)
}

fn encode_request_filename_ext_info(manifest: &Ed2kResumeManifest) -> Vec<u8> {
    let piece_count = u16::try_from(manifest.pieces.len()).unwrap_or(u16::MAX);
    let bitfield_len = usize::from(piece_count).div_ceil(8);
    let mut payload = Vec::with_capacity(2 + bitfield_len + 2);
    payload.extend_from_slice(&piece_count.to_le_bytes());
    let mut current_byte = 0u8;
    for (index, piece) in manifest.pieces.iter().enumerate() {
        if piece.state == Ed2kTransferState::Verified {
            current_byte |= 1 << (index % 8);
        }
        if index % 8 == 7 {
            payload.push(current_byte);
            current_byte = 0;
        }
    }
    if piece_count % 8 != 0 {
        payload.push(current_byte);
    }
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload
}

fn skip_request_filename_ext_info(payload: &[u8], file_size: u64) -> Result<&[u8]> {
    if payload.len() < 2 {
        anyhow::bail!("short OP_REQUESTFILENAME ext-info payload");
    }
    let part_count = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
    let expected_parts = usize::from(ed2k_file_part_count(file_size));
    let bitfield_len = part_count.div_ceil(8);
    let expected_len = 2 + bitfield_len + 2;
    if payload.len() < expected_len {
        anyhow::bail!(
            "short OP_REQUESTFILENAME ext-info payload {} expected at least {}",
            payload.len(),
            expected_len
        );
    }
    if expected_parts != 0 && part_count != expected_parts {
        anyhow::bail!(
            "OP_REQUESTFILENAME part count mismatch {} expected {}",
            part_count,
            expected_parts
        );
    }
    Ok(&payload[expected_len..])
}

fn encode_request_filename(file_hash: &Ed2kHash, manifest: &Ed2kResumeManifest) -> Vec<u8> {
    let ext_info = encode_request_filename_ext_info(manifest);
    let mut payload = Vec::with_capacity(16 + ext_info.len());
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&ext_info);
    encode_packet(OP_EDONKEYPROT, OP_REQUESTFILENAME, &payload)
}

fn encode_request_sources2_subpayload() -> [u8; 3] {
    let mut payload = [0u8; 3];
    payload[0] = ED2K_SOURCE_EXCHANGE2_VERSION;
    payload[1..].copy_from_slice(&0u16.to_le_bytes());
    payload
}

fn encode_request_sources2(file_hash: &Ed2kHash) -> Vec<u8> {
    let mut payload = Vec::with_capacity(19);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&encode_request_sources2_subpayload());
    encode_packet(OP_EMULEPROT, OP_REQUESTSOURCES2, &payload)
}

fn encode_answer_sources_empty(file_hash: &Ed2kHash) -> Vec<u8> {
    let mut payload = Vec::with_capacity(18);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    encode_packet(OP_EMULEPROT, OP_ANSWERSOURCES, &payload)
}

fn encode_answer_sources2_empty(file_hash: &Ed2kHash, version: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(19);
    payload.push(version);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    encode_packet(OP_EMULEPROT, OP_ANSWERSOURCES2, &payload)
}

fn encode_aich_file_hash_request(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EMULEPROT, OP_AICHFILEHASHREQ, &file_hash.0)
}

fn encode_set_req_file_id(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_SETREQFILEID, &file_hash.0)
}

fn encode_request_filename_answer_body(file_name: &str) -> Result<Vec<u8>> {
    let file_name = file_name.as_bytes();
    let mut payload = Vec::with_capacity(2 + file_name.len());
    payload.extend_from_slice(
        &(u16::try_from(file_name.len()).context("file name too large for ED2K filename reply")?)
            .to_le_bytes(),
    );
    payload.extend_from_slice(file_name);
    Ok(payload)
}

fn skip_request_filename_answer_body(payload: &[u8]) -> Result<&[u8]> {
    if payload.len() < 2 {
        anyhow::bail!("short OP_REQFILENAMEANSWER body");
    }
    let len = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
    if payload.len() < 2 + len {
        anyhow::bail!("short OP_REQFILENAMEANSWER string");
    }
    Ok(&payload[2 + len..])
}

fn encode_file_status_body_complete() -> Vec<u8> {
    0u16.to_le_bytes().to_vec()
}

fn skip_file_status_body(payload: &[u8]) -> Result<(u16, &[u8])> {
    if payload.len() < 2 {
        anyhow::bail!("short OP_FILESTATUS body");
    }
    let part_count = u16::from_le_bytes([payload[0], payload[1]]);
    let bitfield_len = usize::from(part_count).div_ceil(8);
    let expected_len = 2 + bitfield_len;
    if payload.len() < expected_len {
        anyhow::bail!(
            "short OP_FILESTATUS body {} expected at least {}",
            payload.len(),
            expected_len
        );
    }
    Ok((part_count, &payload[expected_len..]))
}

fn encode_multipacket_ext2_request(
    file_identifier: &Ed2kFileIdentifier,
    manifest: &Ed2kResumeManifest,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    file_identifier.encode_into(&mut payload);
    payload.push(OP_REQUESTFILENAME);
    payload.extend_from_slice(&encode_request_filename_ext_info(manifest));
    if manifest.file_size > ED2K_PART_SIZE {
        payload.push(OP_SETREQFILEID);
    }
    payload.push(OP_REQUESTSOURCES2);
    payload.extend_from_slice(&encode_request_sources2_subpayload());
    encode_packet(OP_EMULEPROT, OP_MULTIPACKET_EXT2, &payload)
}

fn encode_multipacket_ext2_answer(
    file_identifier: &Ed2kFileIdentifier,
    file_name: &str,
    include_filename_answer: bool,
    include_file_status: bool,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(64);
    file_identifier.encode_into(&mut payload);
    if include_filename_answer {
        payload.push(OP_REQFILENAMEANSWER);
        payload.extend_from_slice(&encode_request_filename_answer_body(file_name)?);
    }
    if include_file_status {
        payload.push(OP_FILESTATUS);
        payload.extend_from_slice(&encode_file_status_body_complete());
    }
    Ok(encode_packet(
        OP_EMULEPROT,
        OP_MULTIPACKETANSWER_EXT2,
        &payload,
    ))
}

fn encode_hashset_request(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_HASHSETREQUEST, &file_hash.0)
}

fn encode_hashset_request2(
    file_identifier: &Ed2kFileIdentifier,
    request_options: Ed2kHashsetRequestOptions,
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        request_options.has_known_request(),
        "OP_HASHSETREQUEST2 expects at least one known hashset request"
    );
    let mut payload = Vec::with_capacity(46);
    file_identifier.encode_into(&mut payload);
    payload.push(request_options.encode());
    Ok(encode_packet(OP_EMULEPROT, OP_HASHSETREQUEST2, &payload))
}

fn encode_hashset_answer(file_hash: &Ed2kHash, md4_hashset: &[[u8; 16]]) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(16 + 2 + (md4_hashset.len() * 16));
    encode_md4_hashset_body(file_hash, md4_hashset, &mut payload)?;
    Ok(encode_packet(OP_EDONKEYPROT, OP_HASHSETANSWER, &payload))
}

fn encode_hashset_answer2(
    file_identifier: &Ed2kFileIdentifier,
    md4_hashset: Option<&[[u8; 16]]>,
    aich_hashset: Option<&Ed2kAichHashset>,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(48);
    file_identifier.encode_into(&mut payload);

    let include_md4 = md4_hashset.is_some_and(|hashset| {
        !hashset.is_empty()
            || file_identifier
                .file_size
                .is_some_and(|file_size| file_size > ED2K_PART_SIZE)
    });
    let include_aich = aich_hashset.is_some();
    payload.push(
        Ed2kHashsetRequestOptions {
            request_md4: include_md4,
            request_aich: include_aich,
        }
        .encode(),
    );
    if let Some(hashset) = md4_hashset.filter(|_| include_md4) {
        encode_md4_hashset_body(&file_identifier.file_hash, hashset, &mut payload)?;
    }
    if let Some(hashset) = aich_hashset {
        encode_aich_hashset_body(hashset, &mut payload)?;
    }

    Ok(encode_packet(OP_EMULEPROT, OP_HASHSETANSWER2, &payload))
}

fn encode_md4_hashset_body(
    file_hash: &Ed2kHash,
    md4_hashset: &[[u8; 16]],
    payload: &mut Vec<u8>,
) -> Result<()> {
    let count = u16::try_from(md4_hashset.len()).context("MD4 hashset entry count exceeds u16")?;
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&count.to_le_bytes());
    for part_hash in md4_hashset {
        payload.extend_from_slice(part_hash);
    }
    Ok(())
}

fn encode_aich_hashset_body(hashset: &Ed2kAichHashset, payload: &mut Vec<u8>) -> Result<()> {
    let count =
        u16::try_from(hashset.part_hashes.len()).context("AICH hashset entry count exceeds u16")?;
    payload.extend_from_slice(&hashset.master_hash);
    payload.extend_from_slice(&count.to_le_bytes());
    for part_hash in &hashset.part_hashes {
        payload.extend_from_slice(part_hash);
    }
    Ok(())
}

fn encode_request_filename_answer(file_hash: &Ed2kHash, file_name: &str) -> Result<Vec<u8>> {
    let body = encode_request_filename_answer_body(file_name)?;
    let mut payload = Vec::with_capacity(16 + body.len());
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&body);
    Ok(encode_packet(
        OP_EDONKEYPROT,
        OP_REQFILENAMEANSWER,
        &payload,
    ))
}

fn decode_hashset_request2(
    payload: &[u8],
) -> Result<(Ed2kFileIdentifier, Ed2kHashsetRequestOptions)> {
    let (file_identifier, remaining) = Ed2kFileIdentifier::decode(payload)?;
    let Some((&options, rest)) = remaining.split_first() else {
        anyhow::bail!("short OP_HASHSETREQUEST2 payload");
    };
    if !rest.is_empty() {
        anyhow::bail!("trailing OP_HASHSETREQUEST2 payload {}", rest.len());
    }
    Ok((file_identifier, Ed2kHashsetRequestOptions::decode(options)))
}

fn decode_request_parts_payload(
    payload: &[u8],
    use_i64: bool,
) -> Result<(Ed2kHash, Vec<(u64, u64)>)> {
    if payload.len() < 16 {
        anyhow::bail!("short OP_REQUESTPARTS payload");
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let width = if use_i64 { 8 } else { 4 };
    let expected = 16 + (width * 3) + (width * 3);
    if payload.len() < expected {
        anyhow::bail!(
            "short OP_REQUESTPARTS payload {} expected at least {}",
            payload.len(),
            expected
        );
    }
    let starts = &payload[16..16 + (width * 3)];
    let ends = &payload[16 + (width * 3)..expected];
    let mut ranges = Vec::new();
    for index in 0..3usize {
        let start = if use_i64 {
            u64::from_le_bytes(
                starts[index * 8..index * 8 + 8]
                    .try_into()
                    .expect("i64 width"),
            )
        } else {
            u64::from(u32::from_le_bytes(
                starts[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("u32 width"),
            ))
        };
        let end = if use_i64 {
            u64::from_le_bytes(
                ends[index * 8..index * 8 + 8]
                    .try_into()
                    .expect("i64 width"),
            )
        } else {
            u64::from(u32::from_le_bytes(
                ends[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("u32 width"),
            ))
        };
        if end > start {
            ranges.push((start, end));
        }
    }
    Ok((Ed2kHash::from_bytes(hash), ranges))
}

fn decode_request_sources_payload(opcode: u8, payload: &[u8]) -> Result<(Ed2kHash, u8)> {
    match opcode {
        OP_REQUESTSOURCES => Ok((decode_file_hash_payload(payload)?, 0)),
        OP_REQUESTSOURCES2 => {
            if payload.len() < 19 {
                anyhow::bail!("short OP_REQUESTSOURCES2 payload {}", payload.len());
            }
            Ok((decode_file_hash_payload(payload)?, payload[16]))
        }
        _ => anyhow::bail!("unsupported source request opcode 0x{opcode:02X}"),
    }
}

fn decode_aich_file_hash_answer(payload: &[u8]) -> Result<Ed2kHash> {
    if payload.len() < 16 {
        anyhow::bail!("short OP_AICHFILEHASHANS payload {}", payload.len());
    }
    Ok(Ed2kHash::from_bytes(payload[..16].try_into()?))
}

/// Encode one ED2K `OP_REQUESTPARTS` packet with up to three ranges.
///
/// The successful public oracle capture used rolling multi-range requests
/// instead of emitting one separate request packet per range, so the native
/// downloader batches adjacent work into one packet to stay closer to that
/// accepted wire shape.
fn encode_request_parts_batch(file_hash: &Ed2kHash, ranges: &[(u64, u64)]) -> Result<Vec<u8>> {
    anyhow::ensure!(
        !ranges.is_empty() && ranges.len() <= 3,
        "OP_REQUESTPARTS expects between one and three ranges"
    );
    let use_i64 = ranges.iter().any(|(_, end)| *end > u64::from(u32::MAX));
    let mut payload = Vec::with_capacity(16 + if use_i64 { 48 } else { 24 });
    payload.extend_from_slice(&file_hash.0);
    if use_i64 {
        for index in 0..3usize {
            let start = ranges.get(index).map_or(0, |(start, _)| *start);
            payload.extend_from_slice(&start.to_le_bytes());
        }
        for index in 0..3usize {
            let end = ranges.get(index).map_or(0, |(_, end)| *end);
            payload.extend_from_slice(&end.to_le_bytes());
        }
        return Ok(encode_packet(OP_EMULEPROT, OP_REQUESTPARTS_I64, &payload));
    }
    for index in 0..3usize {
        let start = ranges.get(index).map_or(0, |(start, _)| *start);
        let start = u32::try_from(start).context("start offset exceeds OP_REQUESTPARTS limit")?;
        payload.extend_from_slice(&start.to_le_bytes());
    }
    for index in 0..3usize {
        let end = ranges.get(index).map_or(0, |(_, end)| *end);
        let end = u32::try_from(end).context("end offset exceeds OP_REQUESTPARTS limit")?;
        payload.extend_from_slice(&end.to_le_bytes());
    }
    Ok(encode_packet(OP_EDONKEYPROT, OP_REQUESTPARTS, &payload))
}

fn decode_hashset_answer(payload: &[u8]) -> Result<(Ed2kHash, Vec<[u8; 16]>)> {
    let (file_hash, hashset, remaining) = decode_md4_hashset_body(payload)?;
    if !remaining.is_empty() {
        anyhow::bail!("trailing OP_HASHSETANSWER payload {}", remaining.len());
    }
    Ok((file_hash, hashset))
}

fn decode_hashset_answer2(payload: &[u8]) -> Result<Ed2kHashsetAnswer2> {
    let (file_identifier, remaining) = Ed2kFileIdentifier::decode(payload)?;
    let Some((&options, mut remaining)) = remaining.split_first() else {
        anyhow::bail!("short OP_HASHSETANSWER2 payload");
    };
    let options = Ed2kHashsetRequestOptions::decode(options);
    let md4_hashset = if options.request_md4 {
        let (returned_hash, hashset, rest) = decode_md4_hashset_body(remaining)?;
        if returned_hash != file_identifier.file_hash {
            anyhow::bail!(
                "OP_HASHSETANSWER2 MD4 section was for {} instead of {}",
                returned_hash,
                file_identifier.file_hash
            );
        }
        remaining = rest;
        Some(hashset)
    } else {
        None
    };
    let aich_hashset = if options.request_aich {
        let (hashset, rest) = decode_aich_hashset_body(remaining)?;
        if let Some(expected_root) = file_identifier.aich_root
            && hashset.master_hash != expected_root
        {
            anyhow::bail!(
                "OP_HASHSETANSWER2 AICH section root mismatch for {}",
                file_identifier.file_hash
            );
        }
        remaining = rest;
        Some(hashset)
    } else {
        None
    };
    if !remaining.is_empty() {
        anyhow::bail!("trailing OP_HASHSETANSWER2 payload {}", remaining.len());
    }
    Ok(Ed2kHashsetAnswer2 {
        file_identifier,
        md4_hashset,
        aich_hashset,
    })
}

fn decode_md4_hashset_body(payload: &[u8]) -> Result<Ed2kMd4HashsetDecode<'_>> {
    if payload.len() < 18 {
        anyhow::bail!("short OP_HASHSETANSWER payload {}", payload.len());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let count = usize::from(u16::from_le_bytes([payload[16], payload[17]]));
    let expected = 18 + (count * 16);
    if payload.len() < expected {
        anyhow::bail!(
            "short OP_HASHSETANSWER payload length {} expected at least {}",
            payload.len(),
            expected
        );
    }
    let mut hashset = Vec::with_capacity(count);
    let mut cursor = 18usize;
    for _ in 0..count {
        let mut part_hash = [0u8; 16];
        part_hash.copy_from_slice(&payload[cursor..cursor + 16]);
        hashset.push(part_hash);
        cursor += 16;
    }
    Ok((Ed2kHash::from_bytes(hash), hashset, &payload[cursor..]))
}

fn decode_aich_hashset_body(payload: &[u8]) -> Result<(Ed2kAichHashset, &[u8])> {
    if payload.len() < 22 {
        anyhow::bail!("short AICH hashset body {}", payload.len());
    }
    let mut master_hash = [0u8; 20];
    master_hash.copy_from_slice(&payload[..20]);
    let count = usize::from(u16::from_le_bytes([payload[20], payload[21]]));
    let expected = 22 + (count * 20);
    if payload.len() < expected {
        anyhow::bail!(
            "short AICH hashset body {} expected at least {}",
            payload.len(),
            expected
        );
    }
    let mut part_hashes = Vec::with_capacity(count);
    let mut cursor = 22usize;
    for _ in 0..count {
        let mut part_hash = [0u8; 20];
        part_hash.copy_from_slice(&payload[cursor..cursor + 20]);
        part_hashes.push(part_hash);
        cursor += 20;
    }
    Ok((
        Ed2kAichHashset {
            master_hash,
            part_hashes,
        },
        &payload[cursor..],
    ))
}

fn decode_sending_part_payload(
    payload: &[u8],
    use_i64: bool,
) -> Result<(Ed2kHash, u64, u64, Vec<u8>)> {
    let header_len = 16 + if use_i64 { 16 } else { 8 };
    if payload.len() < header_len {
        anyhow::bail!("short OP_SENDINGPART payload {}", payload.len());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let (start, end) = if use_i64 {
        let start = u64::from_le_bytes(payload[16..24].try_into().expect("u64 width"));
        let end = u64::from_le_bytes(payload[24..32].try_into().expect("u64 width"));
        (start, end)
    } else {
        let start = u64::from(u32::from_le_bytes(
            payload[16..20].try_into().expect("u32 width"),
        ));
        let end = u64::from(u32::from_le_bytes(
            payload[20..24].try_into().expect("u32 width"),
        ));
        (start, end)
    };
    if end < start {
        anyhow::bail!("invalid OP_SENDINGPART range {start}..{end}");
    }
    let bytes = payload[header_len..].to_vec();
    if usize::try_from(end - start).unwrap_or(usize::MAX) != bytes.len() {
        anyhow::bail!(
            "OP_SENDINGPART body length {} does not match range {}..{}",
            bytes.len(),
            start,
            end
        );
    }
    Ok((Ed2kHash::from_bytes(hash), start, end, bytes))
}

fn decode_compressed_part_fragment(
    payload: &[u8],
    use_i64: bool,
) -> Result<(Ed2kHash, u64, usize, &[u8])> {
    let header_len = 16 + if use_i64 { 12 } else { 8 };
    if payload.len() < header_len {
        anyhow::bail!("short OP_COMPRESSEDPART payload {}", payload.len());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let (start, advertised_compressed_len) = if use_i64 {
        let start = u64::from_le_bytes(payload[16..24].try_into().expect("u64 width"));
        let advertised_compressed_len = usize::try_from(u32::from_le_bytes(
            payload[24..28].try_into().expect("u32 width"),
        ))
        .unwrap_or(usize::MAX);
        (start, advertised_compressed_len)
    } else {
        let start = u64::from(u32::from_le_bytes(
            payload[16..20].try_into().expect("u32 width"),
        ));
        let advertised_compressed_len = usize::try_from(u32::from_le_bytes(
            payload[20..24].try_into().expect("u32 width"),
        ))
        .unwrap_or(usize::MAX);
        (start, advertised_compressed_len)
    };
    Ok((
        Ed2kHash::from_bytes(hash),
        start,
        advertised_compressed_len,
        &payload[header_len..],
    ))
}

fn inflate_compressed_part_fragment(
    pending: &mut PendingCompressedPart,
    compressed_fragment: &[u8],
) -> Result<(Vec<u8>, bool)> {
    let mut remaining = compressed_fragment;
    let mut bytes = Vec::new();
    let mut finished = false;

    while !remaining.is_empty() {
        let mut output = [0u8; 16 * 1024];
        let total_in_before = pending.inflater.total_in();
        let total_out_before = pending.inflater.total_out();
        let status = pending
            .inflater
            .decompress(remaining, &mut output, FlushDecompress::Sync)
            .context("failed to inflate OP_COMPRESSEDPART fragment")?;
        let consumed = usize::try_from(pending.inflater.total_in() - total_in_before).unwrap_or(0);
        let produced =
            usize::try_from(pending.inflater.total_out() - total_out_before).unwrap_or(0);
        if produced != 0 {
            bytes.extend_from_slice(&output[..produced]);
        }
        remaining = &remaining[consumed..];
        match status {
            Status::StreamEnd => {
                finished = true;
                break;
            }
            Status::Ok => {
                if consumed == 0 && produced == 0 {
                    anyhow::bail!("OP_COMPRESSEDPART inflate made no progress");
                }
            }
            Status::BufError => {
                if consumed == 0 && produced == 0 {
                    break;
                }
            }
        }
    }

    pending.compressed_received += compressed_fragment.len();
    if pending.compressed_received > pending.advertised_compressed_len {
        anyhow::bail!(
            "OP_COMPRESSEDPART received {} compressed bytes, above advertised {}",
            pending.compressed_received,
            pending.advertised_compressed_len
        );
    }
    if pending.compressed_received == pending.advertised_compressed_len && !finished {
        loop {
            let mut output = [0u8; 16 * 1024];
            let total_out_before = pending.inflater.total_out();
            let status = pending
                .inflater
                .decompress(&[], &mut output, FlushDecompress::Finish)
                .context("failed to finish OP_COMPRESSEDPART inflate stream")?;
            let produced =
                usize::try_from(pending.inflater.total_out() - total_out_before).unwrap_or(0);
            if produced != 0 {
                bytes.extend_from_slice(&output[..produced]);
            }
            match status {
                Status::StreamEnd => {
                    finished = true;
                    break;
                }
                Status::Ok | Status::BufError if produced == 0 => {
                    finished = true;
                    break;
                }
                Status::Ok | Status::BufError => {}
            }
        }
    }
    pending.uncompressed_written += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    Ok((bytes, finished))
}

#[allow(clippy::too_many_arguments)]
async fn flush_ready_download_blocks(
    transfer_runtime: &Ed2kTransferRuntime,
    file_hash_hex: &str,
    pending_part_requests: &mut Vec<PendingPartRequest>,
    active_piece_request: &mut Option<ActiveDownloadPiece>,
    manifest: &mut Ed2kResumeManifest,
    peer_addr: SocketAddr,
    transport_mode: Ed2kTransportMode,
    completed_block_count: &mut usize,
    session_payload_down: &mut u64,
    part_response_deadline: &mut Option<tokio::time::Instant>,
) -> Result<()> {
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

fn upload_packet_fragment_len(remaining: usize) -> usize {
    if remaining < ED2K_UPLOAD_PACKET_SPLIT_THRESHOLD {
        remaining
    } else {
        ED2K_UPLOAD_PACKET_FRAGMENT_LEN
    }
}

fn should_attempt_upload_compression(canonical_name: &str) -> bool {
    let Some(extension) = Path::new(canonical_name)
        .extension()
        .and_then(|value| value.to_str())
    else {
        return true;
    };
    let extension = extension.to_ascii_lowercase();
    !matches!(
        extension.as_str(),
        "zip" | "rar" | "7z" | "cbz" | "cbr" | "ogm" | "ace"
    )
}

fn compress_upload_payload(canonical_name: &str, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    if !should_attempt_upload_compression(canonical_name) {
        return Ok(None);
    }

    let mut compressor = Compress::new(Compression::new(1), true);
    let mut compressed = Vec::with_capacity(bytes.len().saturating_add(300));
    let mut remaining = bytes;
    let mut output = [0u8; 16 * 1024];
    loop {
        let total_in_before = compressor.total_in();
        let total_out_before = compressor.total_out();
        let status = compressor
            .compress(remaining, &mut output, FlushCompress::Finish)
            .context("failed to deflate ED2K upload payload")?;
        let consumed = usize::try_from(compressor.total_in() - total_in_before).unwrap_or(0);
        let produced = usize::try_from(compressor.total_out() - total_out_before).unwrap_or(0);
        if produced != 0 {
            compressed.extend_from_slice(&output[..produced]);
        }
        remaining = &remaining[consumed..];
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError => {
                if consumed == 0 && produced == 0 {
                    anyhow::bail!("ED2K upload compression made no progress");
                }
            }
        }
    }

    if compressed.len() >= bytes.len() {
        return Ok(None);
    }

    Ok(Some(compressed))
}

fn build_upload_part_packets(
    file_hash: &Ed2kHash,
    canonical_name: &str,
    start: u64,
    end: u64,
    bytes: &[u8],
    use_i64: bool,
) -> Result<Vec<EncodedUploadPartPacket>> {
    let range_len = usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX);
    if range_len != bytes.len() {
        anyhow::bail!(
            "upload payload length {} does not match requested range {}..{}",
            bytes.len(),
            start,
            end
        );
    }

    if let Some(compressed) = compress_upload_payload(canonical_name, bytes)? {
        let mut packets = Vec::new();
        let mut offset = 0usize;
        while offset < compressed.len() {
            let fragment_len = upload_packet_fragment_len(compressed.len() - offset);
            let packet = encode_compressed_part_fragment(
                file_hash,
                start,
                compressed.len(),
                &compressed[offset..offset + fragment_len],
                use_i64,
            )?;
            packets.push(EncodedUploadPartPacket {
                phase: "compressed_part",
                packet,
            });
            offset += fragment_len;
        }
        return Ok(packets);
    }

    let mut packets = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let fragment_len = upload_packet_fragment_len(bytes.len() - offset);
        let fragment_start = start + u64::try_from(offset).unwrap_or(u64::MAX);
        let fragment_end = fragment_start + u64::try_from(fragment_len).unwrap_or(u64::MAX);
        let packet = encode_sending_part(
            file_hash,
            fragment_start,
            fragment_end,
            &bytes[offset..offset + fragment_len],
            use_i64,
        )?;
        packets.push(EncodedUploadPartPacket {
            phase: "sending_part",
            packet,
        });
        offset += fragment_len;
    }
    Ok(packets)
}

fn encode_sending_part(
    file_hash: &Ed2kHash,
    start: u64,
    end: u64,
    bytes: &[u8],
    use_i64: bool,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(16 + if use_i64 { 16 } else { 8 } + bytes.len());
    payload.extend_from_slice(&file_hash.0);
    if use_i64 {
        payload.extend_from_slice(&start.to_le_bytes());
        payload.extend_from_slice(&end.to_le_bytes());
        payload.extend_from_slice(bytes);
        return Ok(encode_packet(OP_EMULEPROT, OP_SENDINGPART_I64, &payload));
    }
    let start = u32::try_from(start).context("start offset exceeds OP_SENDINGPART limit")?;
    let end = u32::try_from(end).context("end offset exceeds OP_SENDINGPART limit")?;
    payload.extend_from_slice(&start.to_le_bytes());
    payload.extend_from_slice(&end.to_le_bytes());
    payload.extend_from_slice(bytes);
    Ok(encode_packet(OP_EDONKEYPROT, OP_SENDINGPART, &payload))
}

fn encode_compressed_part_fragment(
    file_hash: &Ed2kHash,
    start: u64,
    advertised_compressed_len: usize,
    compressed_fragment: &[u8],
    use_i64: bool,
) -> Result<Vec<u8>> {
    let advertised_compressed_len = u32::try_from(advertised_compressed_len)
        .context("compressed payload exceeds OP_COMPRESSEDPART length field")?;
    let mut payload =
        Vec::with_capacity(16 + if use_i64 { 12 } else { 8 } + compressed_fragment.len());
    payload.extend_from_slice(&file_hash.0);
    if use_i64 {
        payload.extend_from_slice(&start.to_le_bytes());
        payload.extend_from_slice(&advertised_compressed_len.to_le_bytes());
        payload.extend_from_slice(compressed_fragment);
        return Ok(encode_packet(OP_EMULEPROT, OP_COMPRESSEDPART_I64, &payload));
    }

    let start = u32::try_from(start).context("start offset exceeds OP_COMPRESSEDPART limit")?;
    payload.extend_from_slice(&start.to_le_bytes());
    payload.extend_from_slice(&advertised_compressed_len.to_le_bytes());
    payload.extend_from_slice(compressed_fragment);
    Ok(encode_packet(OP_EMULEPROT, OP_COMPRESSEDPART, &payload))
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
        CT_VERSION, DownloadWindowLimits, ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
        EDONKEY_VERSION, EMULE_CRYPT_REQUESTS, EMULE_CRYPT_SUPPORTS,
        EMULE_ENCRYPTION_METHOD_OBFUSCATION, EMULE_PROTOCOL_VERSION,
        EMULE_TCP_CRYPT_MAGIC_REQUESTER, EMULE_TCP_CRYPT_MAGIC_SERVER, EMULE_TCP_CRYPT_MAGIC_SYNC,
        EMULE_VERSION_SHORT, Ed2kHelloIdentity, Ed2kPeerConnectMode, Ed2kPeerDownloadOutcome,
        Ed2kPeerSecureIdentState, Ed2kSecureIdent, Ed2kTransport, Ed2kTransportMode,
        FirewallCheckUdpRequest, HELLO_NICKNAME, OP_EDONKEYPROT, OP_EMULEINFO, OP_EMULEINFOANSWER,
        OP_EMULEPROT, OP_FILESTATUS, OP_FWCHECKUDPREQ, OP_HELLO, OP_HELLOANSWER,
        OP_REQFILENAMEANSWER, OP_REQUESTPARTS, OP_SECIDENTSTATE, TAGTYPE_UINT32,
        begin_secure_ident_probe, build_hello_responses, connect_callback_peer,
        decode_incoming_obfuscation_header, decode_peer_payload, decode_public_key_payload,
        decode_request_parts_payload, decode_secident_state, derive_obfuscation_key,
        download_file_from_peer, drive_download_session, ed2k_string_tag_type,
        emule_connect_options, emule_misc_options1, emule_misc_options2, emule_version_tag,
        encode_accept_upload_req, encode_emule_info_answer, encode_emule_info_request,
        encode_hello_answer, encode_hello_request, encode_incoming_obfuscation_response,
        encode_packed_packet, encode_packet, encode_secident_state, encode_sending_part,
        enrich_hello_identity, is_mule_hello, next_download_read_timeout,
        request_udp_firewall_check, select_download_window_limits,
    };
    use crate::{
        ed2k_server::{Ed2kFoundSource, Ed2kServerState},
        ed2k_transfer::{
            ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kTransferRuntime, Ed2kUploadQueueConfig,
            new_transfer_job,
        },
        kad_firewall::KadFirewallState,
        paths::unique_test_dir,
    };
    use flate2::Decompress;
    use hex::decode;
    use md4::{Digest, Md4};
    use overlord_kad_dht::{DhtConfig, DhtNode};
    use overlord_kad_proto::{Ed2kHash, NodeId};
    use rsa::{
        RsaPrivateKey, RsaPublicKey,
        pkcs1v15::{Signature, VerifyingKey},
        pkcs8::EncodePublicKey,
        rand_core::OsRng,
        signature::Verifier,
    };
    use sha1::Sha1;
    use std::collections::VecDeque;
    use std::io::{self, Write as _};
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
    fn queue_ranking_matches_emule_twelve_byte_payload_shape() {
        let packet = super::encode_queue_ranking(7);

        assert_eq!(packet[0], OP_EMULEPROT);
        assert_eq!(packet[5], super::OP_QUEUERANKING);
        assert_eq!(&packet[6..8], &7u16.to_le_bytes());
        assert_eq!(packet.len(), 18);
        assert!(packet[8..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn public_key_payload_rejects_mismatched_length_prefix() {
        assert!(decode_public_key_payload(&[5, 1, 2, 3]).is_err());
    }

    #[test]
    fn file_identifier_roundtrip_matches_stock_md4_plus_size_shape() {
        let identifier = super::Ed2kFileIdentifier {
            file_hash: Ed2kHash([0xAB; 16]),
            file_size: Some(9_728_000),
            aich_root: None,
        };
        let mut payload = Vec::new();
        identifier.encode_into(&mut payload);

        assert_eq!(payload[0], 0x03);
        assert_eq!(&payload[1..17], &[0xAB; 16]);
        assert_eq!(&payload[17..25], &9_728_000u64.to_le_bytes());

        let (decoded, remaining) = super::Ed2kFileIdentifier::decode(&payload).unwrap();
        assert_eq!(decoded, identifier);
        assert!(remaining.is_empty());
    }

    #[test]
    fn file_identifier_relaxed_match_tolerates_missing_optional_fields() {
        let strict = super::Ed2kFileIdentifier {
            file_hash: Ed2kHash([0x42; 16]),
            file_size: Some(1_234),
            aich_root: Some([0x7C; 20]),
        };
        let loose = super::Ed2kFileIdentifier {
            file_hash: strict.file_hash,
            file_size: None,
            aich_root: None,
        };

        assert!(strict.matches_relaxed(&loose));
        assert!(loose.matches_relaxed(&strict));
    }

    #[test]
    fn file_identifier_rejects_reserved_descriptor_bits() {
        let mut payload = vec![0x08];
        payload.extend_from_slice(&[0x11; 16]);
        assert!(super::Ed2kFileIdentifier::decode(&payload).is_err());
    }

    #[test]
    fn hashset_request2_roundtrip_preserves_file_identifier_and_request_bits() {
        let file_identifier = super::Ed2kFileIdentifier {
            file_hash: Ed2kHash([0x31; 16]),
            file_size: Some(ED2K_PART_SIZE + 1),
            aich_root: Some([0x7C; 20]),
        };
        let packet = super::encode_hashset_request2(
            &file_identifier,
            super::Ed2kHashsetRequestOptions {
                request_md4: true,
                request_aich: true,
            },
        )
        .unwrap();

        assert_eq!(packet[0], OP_EMULEPROT);
        assert_eq!(packet[5], super::OP_HASHSETREQUEST2);

        let (decoded_identifier, decoded_options) =
            super::decode_hashset_request2(&packet[6..]).unwrap();
        assert_eq!(decoded_identifier, file_identifier);
        assert!(decoded_options.request_md4);
        assert!(decoded_options.request_aich);
    }

    #[test]
    fn hashset_answer2_roundtrip_preserves_modern_md4_and_aich_sections() {
        let file_identifier = super::Ed2kFileIdentifier {
            file_hash: Ed2kHash([0x44; 16]),
            file_size: Some(ED2K_PART_SIZE + 1),
            aich_root: Some([0x7D; 20]),
        };
        let md4_hashset = vec![[0x11; 16], [0x22; 16]];
        let aich_hashset = super::Ed2kAichHashset {
            master_hash: [0x7D; 20],
            part_hashes: vec![[0x55; 20], [0x66; 20]],
        };
        let packet = super::encode_hashset_answer2(
            &file_identifier,
            Some(&md4_hashset),
            Some(&aich_hashset),
        )
        .unwrap();

        assert_eq!(packet[0], OP_EMULEPROT);
        assert_eq!(packet[5], super::OP_HASHSETANSWER2);

        let decoded = super::decode_hashset_answer2(&packet[6..]).unwrap();
        assert_eq!(decoded.file_identifier, file_identifier);
        assert_eq!(decoded.md4_hashset.unwrap(), md4_hashset);
        assert_eq!(decoded.aich_hashset.unwrap(), aich_hashset);
    }

    #[test]
    fn request_filename_answer_uses_stock_u16_string_length_prefix() {
        let packet =
            super::encode_request_filename_answer(&Ed2kHash([0x55; 16]), "captured.epub").unwrap();

        assert_eq!(packet[0], OP_EDONKEYPROT);
        assert_eq!(packet[5], OP_REQFILENAMEANSWER);
        assert_eq!(&packet[6..22], &[0x55; 16]);
        assert_eq!(
            u16::from_le_bytes([packet[22], packet[23]]) as usize,
            "captured.epub".len()
        );
        assert_eq!(&packet[24..], b"captured.epub");
    }

    fn assert_startup_multipacket_ext2(
        protocol: u8,
        opcode: u8,
        payload: &[u8],
        file_hash: &Ed2kHash,
        file_size: u64,
        expect_set_req_file_id: bool,
    ) {
        assert_eq!(protocol, OP_EMULEPROT);
        assert_eq!(opcode, super::OP_MULTIPACKET_EXT2);
        let (identifier, mut remaining) = super::Ed2kFileIdentifier::decode(payload).unwrap();
        assert_eq!(identifier.file_hash, *file_hash);
        assert_eq!(
            identifier.file_size,
            Some(file_size).filter(|size| *size != 0)
        );

        let mut saw_request_filename = false;
        let mut saw_request_sources2 = false;
        let mut saw_set_req_file_id = false;
        while let Some((&sub_opcode, rest)) = remaining.split_first() {
            remaining = rest;
            match sub_opcode {
                super::OP_REQUESTFILENAME => {
                    remaining =
                        super::skip_request_filename_ext_info(remaining, file_size).unwrap();
                    saw_request_filename = true;
                }
                super::OP_SETREQFILEID => {
                    saw_set_req_file_id = true;
                }
                super::OP_REQUESTSOURCES2 => {
                    assert!(remaining.len() >= 3, "short OP_REQUESTSOURCES2 sub-payload");
                    assert_eq!(
                        &remaining[..3],
                        &super::encode_request_sources2_subpayload()
                    );
                    remaining = &remaining[3..];
                    saw_request_sources2 = true;
                }
                unexpected => panic!("unexpected startup sub-op 0x{unexpected:02X}"),
            }
        }

        assert!(saw_request_filename);
        assert!(saw_request_sources2);
        assert_eq!(saw_set_req_file_id, expect_set_req_file_id);
    }

    fn encode_startup_multipacket_ext2_answer(
        file_hash: &Ed2kHash,
        file_size: u64,
        file_name: &str,
        include_file_status: bool,
    ) -> Vec<u8> {
        super::encode_multipacket_ext2_answer(
            &super::Ed2kFileIdentifier {
                file_hash: *file_hash,
                file_size: Some(file_size).filter(|size| *size != 0),
                aich_root: None,
            },
            file_name,
            true,
            include_file_status,
        )
        .unwrap()
    }

    #[test]
    fn compressed_part_fragment_roundtrip_preserves_header_shape() {
        let file_hash = Ed2kHash([0xAB; 16]);
        let start = 0u64;
        let bytes = vec![0x5A; 32_768];
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&bytes).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut payload = Vec::with_capacity(16 + 4 + 4 + compressed.len());
        payload.extend_from_slice(&file_hash.0);
        payload.extend_from_slice(&(u32::try_from(start).unwrap()).to_le_bytes());
        payload.extend_from_slice(&(u32::try_from(compressed.len()).unwrap()).to_le_bytes());
        payload.extend_from_slice(&compressed);

        let (decoded_hash, decoded_start, advertised_compressed_len, decoded_fragment) =
            super::decode_compressed_part_fragment(&payload, false).unwrap();
        assert_eq!(decoded_hash, file_hash);
        assert_eq!(decoded_start, start);
        assert_eq!(advertised_compressed_len, compressed.len());
        assert_eq!(decoded_fragment, compressed);
    }

    #[test]
    fn compressed_part_fragments_inflate_across_multiple_packets() {
        let bytes = vec![0x5A; 32_768];
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&bytes).unwrap();
        let compressed = encoder.finish().unwrap();
        let split_at = compressed.len() / 2;
        let mut pending = super::PendingCompressedPart {
            piece_index: 0,
            start: 0,
            end: bytes.len() as u64,
            advertised_compressed_len: compressed.len(),
            compressed_received: 0,
            uncompressed_written: 0,
            inflater: flate2::Decompress::new(true),
        };

        let (first_bytes, first_finished) =
            super::inflate_compressed_part_fragment(&mut pending, &compressed[..split_at]).unwrap();
        let (second_bytes, second_finished) =
            super::inflate_compressed_part_fragment(&mut pending, &compressed[split_at..]).unwrap();

        assert!(!first_finished);
        assert!(second_finished);
        assert_eq!(pending.compressed_received, compressed.len());
        assert_eq!(pending.uncompressed_written, bytes.len() as u64);
        assert_eq!([first_bytes, second_bytes].concat(), bytes);
    }

    #[test]
    fn packed_peer_payload_decodes_to_emule_protocol() {
        let payload = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let packed = encode_packed_packet(super::OP_PUBLICKEY, &payload).unwrap();
        let (protocol, decoded) =
            decode_peer_payload(super::OP_PACKEDPROT, packed[6..].to_vec()).unwrap();

        assert_eq!(protocol, OP_EMULEPROT);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn dump_send_phases_follow_oracle_labels() {
        assert_eq!(
            super::canonical_ed2k_send_phase(
                "listener",
                "hello_reply",
                Some(OP_EDONKEYPROT),
                Some(OP_HELLOANSWER),
            )
            .as_ref(),
            "hello_answer"
        );
        assert_eq!(
            super::canonical_ed2k_send_phase(
                "listener",
                "request_filename",
                Some(OP_EDONKEYPROT),
                Some(OP_REQFILENAMEANSWER),
            )
            .as_ref(),
            "filename_answer"
        );
        assert_eq!(
            super::canonical_ed2k_send_phase(
                "listener",
                "set_req_file_id",
                Some(OP_EDONKEYPROT),
                Some(OP_FILESTATUS),
            )
            .as_ref(),
            "file_status"
        );
        assert_eq!(
            super::canonical_ed2k_send_phase(
                "native_download",
                "hello",
                Some(OP_EDONKEYPROT),
                Some(OP_HELLO),
            )
            .as_ref(),
            "hello_request"
        );
        assert_eq!(
            super::canonical_ed2k_send_phase(
                "native_download",
                "request_parts",
                Some(OP_EDONKEYPROT),
                Some(OP_REQUESTPARTS),
            )
            .as_ref(),
            "session"
        );
    }

    #[test]
    fn dump_recv_phases_follow_oracle_labels() {
        assert_eq!(
            super::canonical_ed2k_recv_phase("listener", "custom", OP_EDONKEYPROT, OP_HELLOANSWER,)
                .as_ref(),
            "session"
        );
        assert_eq!(
            super::canonical_ed2k_recv_phase(
                "udp_firewall_check",
                "session",
                OP_EDONKEYPROT,
                OP_HELLO,
            )
            .as_ref(),
            "hello_exchange"
        );
        assert_eq!(
            super::canonical_ed2k_recv_phase(
                "udp_firewall_check",
                "session",
                OP_EMULEPROT,
                OP_FWCHECKUDPREQ,
            )
            .as_ref(),
            "fwcheck_request"
        );
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
        let expected_name_header = [
            ed2k_string_tag_type(HELLO_NICKNAME.len()),
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
    fn hello_answer_matches_stock_072a_plaintext_sample() {
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
            "e3520000004c73bec566140e7e6083c450c9af026f8395581b524fb60600000015010001654d756c65030100113c000000030100f951b651b6030100fa16421334030100fe3a2c0000030100fb00200100b07b02ef8810",
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
    async fn small_file_download_waits_for_peer_signature_before_start_upload() {
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

        let root = unique_test_dir("ed2k-small-file-capture");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5A; 2_409_452];
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "captured.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let peer_public_key = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let payload_for_server = payload.clone();
        let peer_public_key_for_server = Arc::clone(&peer_public_key);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let hello = read_packet(&mut stream).await;
            assert_eq!(hello[0], OP_EDONKEYPROT);
            assert_eq!(hello[5], OP_HELLO);

            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&hello_answer).await.unwrap();

            let secure_ident_probe = read_packet(&mut stream).await;
            assert_eq!(secure_ident_probe[0], OP_EMULEPROT);
            assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);

            let peer_challenge =
                encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
            stream.write_all(&peer_challenge).await.unwrap();

            let public_key = read_packet(&mut stream).await;
            assert_eq!(public_key[0], OP_EMULEPROT);
            assert_eq!(public_key[5], super::OP_PUBLICKEY);

            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key_for_server.public_key_payload().unwrap(),
            );
            stream.write_all(&peer_public_key_packet).await.unwrap();

            let signature = read_packet(&mut stream).await;
            assert_eq!(signature[0], OP_EMULEPROT);
            assert_eq!(signature[5], super::OP_SIGNATURE);

            // Oracle-shaped sessions keep file startup traffic behind the full
            // secure-ident roundtrip, so no filename/upload request should
            // arrive before the peer signature closes the exchange.
            assert!(
                tokio::time::timeout(Duration::from_millis(150), read_packet(&mut stream))
                    .await
                    .is_err(),
                "startup requests must wait for peer OP_SIGNATURE"
            );

            let peer_signature = encode_packet(OP_EMULEPROT, super::OP_SIGNATURE, &[0xAA; 49]);
            stream.write_all(&peer_signature).await.unwrap();

            let startup_request = read_packet(&mut stream).await;
            assert_startup_multipacket_ext2(
                startup_request[0],
                startup_request[5],
                &startup_request[6..],
                &file_hash,
                payload_for_server.len() as u64,
                false,
            );

            let filename_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                payload_for_server.len() as u64,
                "captured.epub",
                false,
            );
            stream.write_all(&filename_answer).await.unwrap();
        });

        let result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_addr.port(),
                client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            },
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            &Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            &transfer_runtime,
            "captured.epub".to_string(),
            (180 * 1024) as u64,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);

        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(!manifest.completed);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn small_file_download_accepts_split_sending_part_frames() {
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

        let root = unique_test_dir("ed2k-small-file-split-sendingpart");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5A; 180 * 1024];
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "captured.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let peer_public_key = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let payload_for_server = payload.clone();
        let peer_public_key_for_server = Arc::clone(&peer_public_key);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let hello = read_packet(&mut stream).await;
            assert_eq!(hello[5], OP_HELLO);

            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&hello_answer).await.unwrap();

            let secure_ident_probe = read_packet(&mut stream).await;
            assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);
            let peer_challenge =
                encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
            stream.write_all(&peer_challenge).await.unwrap();

            let public_key = read_packet(&mut stream).await;
            assert_eq!(public_key[5], super::OP_PUBLICKEY);
            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key_for_server.public_key_payload().unwrap(),
            );
            stream.write_all(&peer_public_key_packet).await.unwrap();

            let signature = read_packet(&mut stream).await;
            assert_eq!(signature[5], super::OP_SIGNATURE);
            let peer_signature = encode_packet(OP_EMULEPROT, super::OP_SIGNATURE, &[0xAA; 49]);
            stream.write_all(&peer_signature).await.unwrap();

            let startup_request = read_packet(&mut stream).await;
            assert_startup_multipacket_ext2(
                startup_request[0],
                startup_request[5],
                &startup_request[6..],
                &file_hash,
                payload.len() as u64,
                false,
            );

            let filename_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                payload.len() as u64,
                "captured.epub",
                false,
            );
            stream.write_all(&filename_answer).await.unwrap();

            let start_upload = read_packet(&mut stream).await;
            assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
            let accept = encode_accept_upload_req();
            stream.write_all(&accept).await.unwrap();

            let request_parts = read_packet(&mut stream).await;
            assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
            let (requested_hash, ranges) =
                decode_request_parts_payload(&request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            let (start, end) = ranges[0];
            let midpoint = start + ((end - start) / 2);

            let first_fragment = encode_sending_part(
                &file_hash,
                start,
                midpoint,
                &payload_for_server
                    [usize::try_from(start).unwrap()..usize::try_from(midpoint).unwrap()],
                false,
            )
            .unwrap();
            stream.write_all(&first_fragment).await.unwrap();

            let second_fragment = encode_sending_part(
                &file_hash,
                midpoint,
                end,
                &payload_for_server
                    [usize::try_from(midpoint).unwrap()..usize::try_from(end).unwrap()],
                false,
            )
            .unwrap();
            stream.write_all(&second_fragment).await.unwrap();
        });

        let result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_addr.port(),
                client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            },
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            &Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            &transfer_runtime,
            "captured.epub".to_string(),
            (180 * 1024) as u64,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);

        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(manifest.completed);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn small_file_download_accepts_split_compressed_part_frames() {
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

        let root = unique_test_dir("ed2k-small-file-split-compressedpart");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5A; 8 * 1024];
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "captured.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let peer_public_key = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let peer_public_key_for_server = Arc::clone(&peer_public_key);
        let payload_for_server = payload.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let hello = read_packet(&mut stream).await;
            assert_eq!(hello[5], OP_HELLO);

            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&hello_answer).await.unwrap();

            let secure_ident_probe = read_packet(&mut stream).await;
            assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);
            let peer_challenge =
                encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
            stream.write_all(&peer_challenge).await.unwrap();

            let public_key = read_packet(&mut stream).await;
            assert_eq!(public_key[5], super::OP_PUBLICKEY);
            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key_for_server.public_key_payload().unwrap(),
            );
            stream.write_all(&peer_public_key_packet).await.unwrap();

            let signature = read_packet(&mut stream).await;
            assert_eq!(signature[5], super::OP_SIGNATURE);
            let peer_signature = encode_packet(OP_EMULEPROT, super::OP_SIGNATURE, &[0xAA; 49]);
            stream.write_all(&peer_signature).await.unwrap();

            let startup_request = read_packet(&mut stream).await;
            assert_startup_multipacket_ext2(
                startup_request[0],
                startup_request[5],
                &startup_request[6..],
                &file_hash,
                payload_for_server.len() as u64,
                false,
            );

            let filename_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                payload_for_server.len() as u64,
                "captured.epub",
                false,
            );
            stream.write_all(&filename_answer).await.unwrap();

            let start_upload = read_packet(&mut stream).await;
            assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
            stream.write_all(&encode_accept_upload_req()).await.unwrap();

            let request_parts = read_packet(&mut stream).await;
            assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
            let (requested_hash, ranges) =
                decode_request_parts_payload(&request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(ranges, vec![(0, payload_for_server.len() as u64)]);

            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(&payload_for_server).unwrap();
            let compressed = encoder.finish().unwrap();
            let split_at = (compressed.len() / 2).max(1);

            let first_fragment = super::encode_compressed_part_fragment(
                &file_hash,
                0,
                compressed.len(),
                &compressed[..split_at],
                false,
            )
            .unwrap();
            stream.write_all(&first_fragment).await.unwrap();

            let second_fragment = super::encode_compressed_part_fragment(
                &file_hash,
                0,
                compressed.len(),
                &compressed[split_at..],
                false,
            )
            .unwrap();
            stream.write_all(&second_fragment).await.unwrap();
        });

        let result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_addr.port(),
                client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            },
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            &Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            &transfer_runtime,
            "captured.epub".to_string(),
            payload.len() as u64,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);

        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(manifest.completed);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn small_file_download_accepts_obfuscated_packed_startup_and_compressed_part_frames() {
        let root = unique_test_dir("ed2k-small-file-obfuscated-packed-compressedpart");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5A; 8 * 1024];
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "captured.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let peer_user_hash = [0x42; 16];
        let peer_public_key = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let peer_public_key_for_server = Arc::clone(&peer_public_key);
        let payload_for_server = payload.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut transport = Ed2kTransport::accept(stream, peer_user_hash).await.unwrap();
            assert_eq!(transport.mode, Ed2kTransportMode::Obfuscated);

            let hello = transport.read_packet().await.unwrap().unwrap();
            assert_eq!(hello.protocol, OP_EDONKEYPROT);
            assert_eq!(hello.opcode, OP_HELLO);

            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: peer_user_hash,
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(true),
                direct_udp_callback: false,
            });
            transport.write_all(&hello_answer).await.unwrap();

            let secure_ident_probe = transport.read_packet().await.unwrap().unwrap();
            assert_eq!(secure_ident_probe.protocol, OP_EMULEPROT);
            assert_eq!(secure_ident_probe.opcode, OP_SECIDENTSTATE);

            let peer_challenge =
                encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
            transport.write_all(&peer_challenge).await.unwrap();

            let public_key = transport.read_packet().await.unwrap().unwrap();
            assert_eq!(public_key.protocol, OP_EMULEPROT);
            assert_eq!(public_key.opcode, super::OP_PUBLICKEY);

            let peer_public_key_packet = encode_packed_packet(
                super::OP_PUBLICKEY,
                &peer_public_key_for_server.public_key_payload().unwrap(),
            )
            .unwrap();
            transport.write_all(&peer_public_key_packet).await.unwrap();

            let signature = transport.read_packet().await.unwrap().unwrap();
            assert_eq!(signature.protocol, OP_EMULEPROT);
            assert_eq!(signature.opcode, super::OP_SIGNATURE);

            let peer_signature = encode_packed_packet(super::OP_SIGNATURE, &[0xAA; 49]).unwrap();
            transport.write_all(&peer_signature).await.unwrap();

            let startup_request = transport.read_packet().await.unwrap().unwrap();
            assert_startup_multipacket_ext2(
                startup_request.protocol,
                startup_request.opcode,
                &startup_request.payload,
                &file_hash,
                payload_for_server.len() as u64,
                false,
            );

            let filename_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                payload_for_server.len() as u64,
                "captured.epub",
                false,
            );
            transport.write_all(&filename_answer).await.unwrap();

            let start_upload = transport.read_packet().await.unwrap().unwrap();
            assert_eq!(start_upload.protocol, OP_EDONKEYPROT);
            assert_eq!(start_upload.opcode, super::OP_STARTUPLOADREQ);
            transport
                .write_all(&encode_accept_upload_req())
                .await
                .unwrap();

            let request_parts = transport.read_packet().await.unwrap().unwrap();
            assert_eq!(request_parts.protocol, OP_EDONKEYPROT);
            assert_eq!(request_parts.opcode, super::OP_REQUESTPARTS);
            let (requested_hash, ranges) =
                decode_request_parts_payload(&request_parts.payload, false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(ranges, vec![(0, payload_for_server.len() as u64)]);

            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(&payload_for_server).unwrap();
            let compressed = encoder.finish().unwrap();
            let split_at = (compressed.len() / 2).max(1);

            let first_fragment = super::encode_compressed_part_fragment(
                &file_hash,
                0,
                compressed.len(),
                &compressed[..split_at],
                false,
            )
            .unwrap();
            transport.write_all(&first_fragment).await.unwrap();

            let second_fragment = super::encode_compressed_part_fragment(
                &file_hash,
                0,
                compressed.len(),
                &compressed[split_at..],
                false,
            )
            .unwrap();
            transport.write_all(&second_fragment).await.unwrap();
        });

        let result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_addr.port(),
                client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                low_id: false,
                obfuscated: true,
                obfuscation_options: Some(
                    super::EMULE_CRYPT_SUPPORTS | super::EMULE_CRYPT_REQUESTS,
                ),
                user_hash: Some(peer_user_hash),
                source_server: None,
            },
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(true),
                direct_udp_callback: false,
            },
            &Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            &transfer_runtime,
            "captured.epub".to_string(),
            payload.len() as u64,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);

        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(manifest.completed);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn small_file_download_rejects_wrong_payload_and_keeps_manifest_incomplete() {
        async fn read_packet(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
            let mut header = [0u8; 6];
            stream.read_exact(&mut header).await?;
            let packet_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
            let mut packet = header.to_vec();
            let mut payload = vec![0u8; packet_len - 1];
            stream.read_exact(&mut payload).await?;
            packet.extend_from_slice(&payload);
            Ok(packet)
        }

        let root = unique_test_dir("ed2k-small-file-bad-payload");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5A; 32_768];
        let wrong_payload = vec![0x33; payload.len()];
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "captured.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let Ok(hello) = read_packet(&mut stream).await else {
                return;
            };
            assert_eq!(hello[5], OP_HELLO);

            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&hello_answer).await.unwrap();

            let Ok(_secure_ident_probe) = read_packet(&mut stream).await else {
                return;
            };
            stream
                .write_all(&encode_secident_state(
                    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                    0x4436_EEAC,
                ))
                .await
                .unwrap();

            let Ok(_public_key) = read_packet(&mut stream).await else {
                return;
            };
            let peer_public_key = Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            );
            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key.public_key_payload().unwrap(),
            );
            stream.write_all(&peer_public_key_packet).await.unwrap();

            let Ok(_signature) = read_packet(&mut stream).await else {
                return;
            };
            stream
                .write_all(&encode_packet(
                    OP_EMULEPROT,
                    super::OP_SIGNATURE,
                    &[0xAA; 49],
                ))
                .await
                .unwrap();
            let Ok(startup_request) = read_packet(&mut stream).await else {
                return;
            };
            assert_startup_multipacket_ext2(
                startup_request[0],
                startup_request[5],
                &startup_request[6..],
                &file_hash,
                wrong_payload.len() as u64,
                false,
            );
            let startup_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                wrong_payload.len() as u64,
                "captured.epub",
                false,
            );
            stream.write_all(&startup_answer).await.unwrap();
            let Ok(_start_upload) = read_packet(&mut stream).await else {
                return;
            };
            stream.write_all(&encode_accept_upload_req()).await.unwrap();

            let Ok(request_parts) = read_packet(&mut stream).await else {
                return;
            };
            assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
            let sending_part = encode_sending_part(
                &file_hash,
                0,
                wrong_payload.len() as u64,
                &wrong_payload,
                false,
            )
            .unwrap();
            stream.write_all(&sending_part).await.unwrap();
        });

        let result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_addr.port(),
                client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            },
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            &Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            &transfer_runtime,
            "captured.epub".to_string(),
            payload.len() as u64,
            Duration::from_secs(3),
        )
        .await;

        assert_eq!(
            result.unwrap(),
            Ed2kPeerDownloadOutcome::AcceptedButIncomplete
        );
        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(!manifest.completed);
        assert_eq!(
            manifest.pieces[0].state,
            crate::ed2k_transfer::Ed2kTransferState::Missing
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn large_file_download_waits_for_secure_ident_before_hashset_and_upload() {
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

        let root = unique_test_dir("ed2k-large-file-secure-ident-order");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5A; (ED2K_PART_SIZE as usize) + 32_768];
        let md4_hashset = payload
            .chunks(ED2K_PART_SIZE as usize)
            .map(|chunk| Md4::digest(chunk).into())
            .collect::<Vec<[u8; 16]>>();
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(
            Md4::digest(md4_hashset.iter().flatten().copied().collect::<Vec<u8>>()).into(),
        );
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "captured.iso".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let peer_public_key_for_server = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let payload_for_server = payload.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let hello = read_packet(&mut stream).await;
            assert_eq!(hello[0], OP_EDONKEYPROT);
            assert_eq!(hello[5], OP_HELLO);

            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&hello_answer).await.unwrap();

            let secure_ident_probe = read_packet(&mut stream).await;
            assert_eq!(secure_ident_probe[0], OP_EMULEPROT);
            assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);

            let peer_challenge =
                encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
            stream.write_all(&peer_challenge).await.unwrap();

            let public_key = read_packet(&mut stream).await;
            assert_eq!(public_key[0], OP_EMULEPROT);
            assert_eq!(public_key[5], super::OP_PUBLICKEY);

            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key_for_server.public_key_payload().unwrap(),
            );
            stream.write_all(&peer_public_key_packet).await.unwrap();

            let signature = read_packet(&mut stream).await;
            assert_eq!(signature[0], OP_EMULEPROT);
            assert_eq!(signature[5], super::OP_SIGNATURE);

            let peer_signature = encode_packet(OP_EMULEPROT, super::OP_SIGNATURE, &[0xAA; 49]);
            stream.write_all(&peer_signature).await.unwrap();

            let startup_request = read_packet(&mut stream).await;
            assert_startup_multipacket_ext2(
                startup_request[0],
                startup_request[5],
                &startup_request[6..],
                &file_hash,
                payload_for_server.len() as u64,
                true,
            );

            let startup_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                payload_for_server.len() as u64,
                "captured-fallback.iso",
                true,
            );
            stream.write_all(&startup_answer).await.unwrap();

            let hashset_request = read_packet(&mut stream).await;
            assert_eq!(hashset_request[0], OP_EMULEPROT);
            assert_eq!(hashset_request[5], super::OP_HASHSETREQUEST2);
            let (requested_identifier, request_options) =
                super::decode_hashset_request2(&hashset_request[6..]).unwrap();
            assert_eq!(requested_identifier.file_hash, file_hash);
            assert_eq!(
                requested_identifier.file_size,
                Some(payload_for_server.len() as u64)
            );
            assert!(request_options.request_md4);
            assert!(!request_options.request_aich);

            let hashset_answer = super::encode_hashset_answer2(
                &super::Ed2kFileIdentifier {
                    file_hash,
                    file_size: Some(payload_for_server.len() as u64),
                    aich_root: None,
                },
                Some(&md4_hashset),
                None,
            )
            .unwrap();
            stream.write_all(&hashset_answer).await.unwrap();

            let start_upload = read_packet(&mut stream).await;
            assert_eq!(start_upload[0], OP_EDONKEYPROT);
            assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
            assert_eq!(&start_upload[6..22], &file_hash.0);

            let accept = encode_accept_upload_req();
            stream.write_all(&accept).await.unwrap();

            let request_parts = read_packet(&mut stream).await;
            let request_uses_i64 = request_parts[5] == super::OP_REQUESTPARTS_I64;
            if request_uses_i64 {
                assert_eq!(request_parts[0], OP_EMULEPROT);
            } else {
                assert_eq!(request_parts[0], OP_EDONKEYPROT);
                assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
            }
            let (requested_hash, ranges) =
                decode_request_parts_payload(&request_parts[6..], request_uses_i64).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(
                ranges,
                vec![(
                    0,
                    super::ED2K_EMBLOCK_SIZE.min(payload_for_server.len() as u64)
                )]
            );

            let mut expected_start = 0u64;
            for (start, end) in ranges {
                assert_eq!(start, expected_start);
                let start_index = usize::try_from(start).unwrap();
                let end_index = usize::try_from(end).unwrap();
                let sending_part = encode_sending_part(
                    &file_hash,
                    start,
                    end,
                    &payload_for_server[start_index..end_index],
                    request_uses_i64,
                )
                .unwrap();
                stream.write_all(&sending_part).await.unwrap();
                expected_start = end;
            }
            while expected_start < payload_for_server.len() as u64 {
                let next_request_parts = read_packet(&mut stream).await;
                let next_request_uses_i64 = next_request_parts[5] == super::OP_REQUESTPARTS_I64;
                if next_request_uses_i64 {
                    assert_eq!(next_request_parts[0], OP_EMULEPROT);
                } else {
                    assert_eq!(next_request_parts[0], OP_EDONKEYPROT);
                    assert_eq!(next_request_parts[5], super::OP_REQUESTPARTS);
                }
                let (next_requested_hash, next_ranges) =
                    decode_request_parts_payload(&next_request_parts[6..], next_request_uses_i64)
                        .unwrap();
                assert_eq!(next_requested_hash, file_hash);
                assert!(!next_ranges.is_empty());
                for (start, end) in next_ranges {
                    assert_eq!(start, expected_start);
                    let start_index = usize::try_from(start).unwrap();
                    let end_index = usize::try_from(end).unwrap();
                    let sending_part = encode_sending_part(
                        &file_hash,
                        start,
                        end,
                        &payload_for_server[start_index..end_index],
                        next_request_uses_i64,
                    )
                    .unwrap();
                    stream.write_all(&sending_part).await.unwrap();
                    expected_start = end;
                }
            }
        });

        let result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_addr.port(),
                client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            },
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            &Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            &transfer_runtime,
            "captured.iso".to_string(),
            payload.len() as u64,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);

        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(manifest.completed);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn queue_only_peer_is_accepted_without_counting_as_failure() {
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

        let root = unique_test_dir("ed2k-queue-only-accepted");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5A; 32_768];
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "captured.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let peer_public_key = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let hello = read_packet(&mut stream).await;
            assert_eq!(hello[5], OP_HELLO);

            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&hello_answer).await.unwrap();

            let secure_ident_probe = read_packet(&mut stream).await;
            assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);
            stream
                .write_all(&encode_secident_state(
                    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                    0x4436_EEAC,
                ))
                .await
                .unwrap();

            let public_key = read_packet(&mut stream).await;
            assert_eq!(public_key[5], super::OP_PUBLICKEY);
            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key.public_key_payload().unwrap(),
            );
            stream.write_all(&peer_public_key_packet).await.unwrap();

            let signature = read_packet(&mut stream).await;
            assert_eq!(signature[5], super::OP_SIGNATURE);
            drop(stream);
        });

        let result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_addr.port(),
                client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            },
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            &Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            &transfer_runtime,
            "captured.epub".to_string(),
            payload.len() as u64,
            Duration::from_secs(3),
        )
        .await
        .unwrap();

        assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(!manifest.completed);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn queued_peer_waits_past_read_timeout_for_late_accept_upload() {
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

        let root = unique_test_dir("ed2k-queued-peer-late-accept");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5A; 32_768];
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "queued.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let peer_public_key = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let payload_for_server = payload.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let hello = read_packet(&mut stream).await;
            assert_eq!(hello[5], OP_HELLO);

            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&hello_answer).await.unwrap();

            let secure_ident_probe = read_packet(&mut stream).await;
            assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);
            stream
                .write_all(&encode_secident_state(
                    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                    0x4436_EEAC,
                ))
                .await
                .unwrap();

            let public_key = read_packet(&mut stream).await;
            assert_eq!(public_key[5], super::OP_PUBLICKEY);
            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key.public_key_payload().unwrap(),
            );
            stream.write_all(&peer_public_key_packet).await.unwrap();

            let signature = read_packet(&mut stream).await;
            assert_eq!(signature[5], super::OP_SIGNATURE);
            stream
                .write_all(&encode_packet(
                    OP_EMULEPROT,
                    super::OP_SIGNATURE,
                    &[0xAA; 49],
                ))
                .await
                .unwrap();

            let startup_request = read_packet(&mut stream).await;
            assert_startup_multipacket_ext2(
                startup_request[0],
                startup_request[5],
                &startup_request[6..],
                &file_hash,
                payload.len() as u64,
                false,
            );
            let filename_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                payload.len() as u64,
                "queued.epub",
                false,
            );
            stream.write_all(&filename_answer).await.unwrap();

            let start_upload = read_packet(&mut stream).await;
            assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);

            let file_desc = encode_packet(
                OP_EMULEPROT,
                super::OP_FILEDESC,
                &[0x05, 0x00, b'q', b'u', b'e', b'u', b'e'],
            );
            stream.write_all(&file_desc).await.unwrap();

            let queue_ranking = super::encode_queue_ranking(1);
            stream.write_all(&queue_ranking).await.unwrap();

            tokio::time::sleep(Duration::from_millis(1500)).await;

            stream.write_all(&encode_accept_upload_req()).await.unwrap();

            let request_parts = read_packet(&mut stream).await;
            assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
            let (requested_hash, ranges) =
                decode_request_parts_payload(&request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(ranges, vec![(0, payload_for_server.len() as u64)]);

            let sending_part = encode_sending_part(
                &file_hash,
                0,
                payload_for_server.len() as u64,
                &payload_for_server,
                false,
            )
            .unwrap();
            stream.write_all(&sending_part).await.unwrap();
        });

        let result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_addr.port(),
                client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            },
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            &Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            &transfer_runtime,
            "queued.epub".to_string(),
            32_768,
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);
        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(manifest.completed);
        server.await.unwrap();
    }

    #[test]
    fn download_read_timeout_uses_earliest_queue_deadline() {
        let now = tokio::time::Instant::now();
        let read_timeout = next_download_read_timeout(
            now,
            Duration::from_secs(300),
            None,
            Some(now + Duration::from_secs(20)),
            None,
        );
        assert_eq!(read_timeout, Duration::from_secs(20));
    }

    #[test]
    fn download_read_timeout_uses_earliest_part_deadline() {
        let now = tokio::time::Instant::now();
        let read_timeout = next_download_read_timeout(
            now,
            Duration::from_secs(300),
            Some(Duration::from_secs(120)),
            Some(now + Duration::from_secs(25)),
            Some(now + Duration::from_secs(7)),
        );
        assert_eq!(read_timeout, Duration::from_secs(7));
    }

    #[test]
    fn download_read_timeout_immediately_wakes_for_elapsed_deadline() {
        let now = tokio::time::Instant::now();
        let read_timeout = next_download_read_timeout(
            now,
            Duration::from_secs(300),
            None,
            Some(now - Duration::from_secs(1)),
            None,
        );
        assert_eq!(read_timeout, Duration::ZERO);
    }

    #[test]
    fn download_window_starts_with_one_block_before_any_completed_payload() {
        let job = new_transfer_job(
            Ed2kHash::from_bytes([0x21; 16]),
            "window.iso".to_string(),
            ED2K_PART_SIZE * 5,
        );
        let manifest = Ed2kResumeManifest::new(&job);
        let limits = select_download_window_limits(&manifest, 0, 0, tokio::time::Instant::now());
        assert_eq!(
            limits,
            DownloadWindowLimits {
                max_pending_blocks: 1,
                min_pending_blocks: 1,
            }
        );
    }

    #[test]
    fn download_window_grows_for_fast_large_transfer() {
        let job = new_transfer_job(
            Ed2kHash::from_bytes([0x31; 16]),
            "window.iso".to_string(),
            ED2K_PART_SIZE * 5,
        );
        let manifest = Ed2kResumeManifest::new(&job);
        let limits = select_download_window_limits(
            &manifest,
            3,
            1_024 * 1024,
            tokio::time::Instant::now() - Duration::from_secs(10),
        );
        assert_eq!(
            limits,
            DownloadWindowLimits {
                max_pending_blocks: 6,
                min_pending_blocks: 4,
            }
        );
    }

    #[test]
    fn download_window_stays_small_for_slow_endgame_transfer() {
        let job = new_transfer_job(
            Ed2kHash::from_bytes([0x41; 16]),
            "window.iso".to_string(),
            ED2K_PART_SIZE * 2,
        );
        let manifest = Ed2kResumeManifest::new(&job);
        let limits = select_download_window_limits(
            &manifest,
            1,
            32 * 1024,
            tokio::time::Instant::now() - Duration::from_secs(20),
        );
        assert_eq!(
            limits,
            DownloadWindowLimits {
                max_pending_blocks: 1,
                min_pending_blocks: 1,
            }
        );
    }

    #[tokio::test]
    async fn callback_session_with_completed_hello_starts_upload_flow() {
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

        let root = unique_test_dir("ed2k-callback-session-start-upload");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5A; 32_768];
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "callback.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut stream = TcpStream::connect(peer_addr).await.unwrap();

            stream
                .write_all(&encode_secident_state(
                    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                    0x4436_EEAC,
                ))
                .await
                .unwrap();

            let public_key = tokio::time::timeout(Duration::from_secs(3), read_packet(&mut stream))
                .await
                .unwrap();
            assert_eq!(public_key[0], OP_EMULEPROT);
            assert_eq!(public_key[5], super::OP_PUBLICKEY);

            let peer_public_key = Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            );
            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key.public_key_payload().unwrap(),
            );
            stream.write_all(&peer_public_key_packet).await.unwrap();

            let signature = tokio::time::timeout(Duration::from_secs(3), read_packet(&mut stream))
                .await
                .unwrap();
            assert_eq!(signature[0], OP_EMULEPROT);
            assert_eq!(signature[5], super::OP_SIGNATURE);

            let request_filename =
                tokio::time::timeout(Duration::from_secs(3), read_packet(&mut stream))
                    .await
                    .unwrap();
            assert_eq!(request_filename[0], OP_EDONKEYPROT);
            assert_eq!(request_filename[5], super::OP_REQUESTFILENAME);
            assert_eq!(&request_filename[6..22], &file_hash.0);

            let request_sources =
                tokio::time::timeout(Duration::from_secs(3), read_packet(&mut stream))
                    .await
                    .unwrap();
            assert_eq!(request_sources[0], OP_EMULEPROT);
            assert_eq!(request_sources[5], super::OP_REQUESTSOURCES2);

            let aich_file_hash_request =
                tokio::time::timeout(Duration::from_secs(3), read_packet(&mut stream))
                    .await
                    .unwrap();
            assert_eq!(aich_file_hash_request[0], OP_EMULEPROT);
            assert_eq!(aich_file_hash_request[5], super::OP_AICHFILEHASHREQ);
            assert_eq!(&aich_file_hash_request[6..22], &file_hash.0);

            let filename_answer =
                super::encode_request_filename_answer(&file_hash, "callback.epub").unwrap();
            stream.write_all(&filename_answer).await.unwrap();

            let start_upload =
                tokio::time::timeout(Duration::from_secs(3), read_packet(&mut stream))
                    .await
                    .unwrap();
            assert_eq!(start_upload[0], OP_EDONKEYPROT);
            assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
            assert_eq!(&start_upload[6..22], &file_hash.0);
        });

        let (stream, remote_addr) = listener.accept().await.unwrap();
        let mut transport = Ed2kTransport {
            stream,
            prefetched: VecDeque::new(),
            receive_cipher: None,
            send_cipher: None,
            mode: Ed2kTransportMode::Plaintext,
        };
        let secure_ident = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );

        let result = drive_download_session(
            &mut transport,
            remote_addr,
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            secure_ident.as_ref(),
            &transfer_runtime,
            file_hash,
            &file_hash_hex,
            payload.len() as u64,
            Duration::from_secs(3),
            true,
            true,
            true,
        )
        .await
        .unwrap();

        assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(!manifest.completed);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn large_file_download_falls_back_to_upload_request_when_hashset_stalls() {
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

        let root = unique_test_dir("ed2k-large-file-hashset-stall-fallback");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5A; (ED2K_PART_SIZE as usize) + 32_768];
        let md4_hashset = payload
            .chunks(ED2K_PART_SIZE as usize)
            .map(|chunk| Md4::digest(chunk).into())
            .collect::<Vec<[u8; 16]>>();
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(
            Md4::digest(md4_hashset.iter().flatten().copied().collect::<Vec<u8>>()).into(),
        );
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "captured-fallback.iso".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let peer_public_key_for_server = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let payload_for_server = payload.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let hello = read_packet(&mut stream).await;
            assert_eq!(hello[0], OP_EDONKEYPROT);
            assert_eq!(hello[5], OP_HELLO);

            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&hello_answer).await.unwrap();

            let secure_ident_probe = read_packet(&mut stream).await;
            assert_eq!(secure_ident_probe[0], OP_EMULEPROT);
            assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);

            stream
                .write_all(&encode_secident_state(
                    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                    0x4436_EEAC,
                ))
                .await
                .unwrap();

            let public_key = read_packet(&mut stream).await;
            assert_eq!(public_key[0], OP_EMULEPROT);
            assert_eq!(public_key[5], super::OP_PUBLICKEY);

            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key_for_server.public_key_payload().unwrap(),
            );
            stream.write_all(&peer_public_key_packet).await.unwrap();

            let signature = read_packet(&mut stream).await;
            assert_eq!(signature[0], OP_EMULEPROT);
            assert_eq!(signature[5], super::OP_SIGNATURE);

            let peer_signature = encode_packet(OP_EMULEPROT, super::OP_SIGNATURE, &[0xAA; 49]);
            stream.write_all(&peer_signature).await.unwrap();

            let startup_request = read_packet(&mut stream).await;
            assert_startup_multipacket_ext2(
                startup_request[0],
                startup_request[5],
                &startup_request[6..],
                &file_hash,
                payload_for_server.len() as u64,
                true,
            );

            let startup_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                payload_for_server.len() as u64,
                "captured.epub",
                true,
            );
            stream.write_all(&startup_answer).await.unwrap();

            let hashset_request = read_packet(&mut stream).await;
            assert_eq!(hashset_request[0], OP_EMULEPROT);
            assert_eq!(hashset_request[5], super::OP_HASHSETREQUEST2);
            let (requested_identifier, request_options) =
                super::decode_hashset_request2(&hashset_request[6..]).unwrap();
            assert_eq!(requested_identifier.file_hash, file_hash);
            assert_eq!(
                requested_identifier.file_size,
                Some(payload_for_server.len() as u64)
            );
            assert!(request_options.request_md4);
            assert!(!request_options.request_aich);

            let start_upload = read_packet(&mut stream).await;
            assert_eq!(start_upload[0], OP_EDONKEYPROT);
            assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
            assert_eq!(&start_upload[6..22], &file_hash.0);

            let hashset_answer = super::encode_hashset_answer2(
                &super::Ed2kFileIdentifier {
                    file_hash,
                    file_size: Some(payload_for_server.len() as u64),
                    aich_root: None,
                },
                Some(&md4_hashset),
                None,
            )
            .unwrap();
            stream.write_all(&hashset_answer).await.unwrap();

            let accept = encode_accept_upload_req();
            stream.write_all(&accept).await.unwrap();

            let request_parts = read_packet(&mut stream).await;
            let request_uses_i64 = request_parts[5] == super::OP_REQUESTPARTS_I64;
            if request_uses_i64 {
                assert_eq!(request_parts[0], OP_EMULEPROT);
            } else {
                assert_eq!(request_parts[0], OP_EDONKEYPROT);
                assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
            }
            let (requested_hash, ranges) =
                decode_request_parts_payload(&request_parts[6..], request_uses_i64).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(
                ranges,
                vec![(
                    0,
                    super::ED2K_EMBLOCK_SIZE.min(payload_for_server.len() as u64)
                )]
            );
            let (start, end) = ranges[0];
            let start_index = usize::try_from(start).unwrap();
            let end_index = usize::try_from(end).unwrap();
            let sending_part = encode_sending_part(
                &file_hash,
                start,
                end,
                &payload_for_server[start_index..end_index],
                request_uses_i64,
            )
            .unwrap();
            stream.write_all(&sending_part).await.unwrap();
        });

        let result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_addr.port(),
                client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            },
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            &Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            &transfer_runtime,
            "captured-fallback.iso".to_string(),
            payload.len() as u64,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);

        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(!manifest.completed);
        assert_eq!(
            manifest.pieces[0].state,
            crate::ed2k_transfer::Ed2kTransferState::Missing
        );
        assert_eq!(manifest.pieces[0].bytes_written, super::ED2K_EMBLOCK_SIZE);
        server.await.unwrap();
    }

    #[test]
    fn upload_part_packets_split_large_uncompressed_ranges() {
        let file_hash = Ed2kHash::from_bytes([0x5A; 16]);
        let mut lcg = 0x1234_5678u32;
        let payload = (0..32_768)
            .map(|_| {
                lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (lcg >> 24) as u8
            })
            .collect::<Vec<_>>();

        let packets = super::build_upload_part_packets(
            &file_hash,
            "upload.bin",
            0,
            payload.len() as u64,
            &payload,
            false,
        )
        .unwrap();

        assert!(packets.len() > 1);
        let mut reconstructed = Vec::new();
        let mut expected_start = 0u64;
        for packet in packets {
            assert_eq!(packet.phase, "sending_part");
            let (decoded_hash, start, end, bytes) =
                super::decode_sending_part_payload(&packet.packet[6..], false).unwrap();
            assert_eq!(decoded_hash, file_hash);
            assert_eq!(start, expected_start);
            expected_start = end;
            reconstructed.extend_from_slice(&bytes);
        }

        assert_eq!(reconstructed, payload);
    }

    #[tokio::test]
    async fn listener_upload_session_serves_verified_file_via_compressed_parts() {
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

        async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
            loop {
                let packet = read_packet(stream).await;
                if packet[0] == protocol && packet[5] == opcode {
                    return packet;
                }
            }
        }

        let mut payload = Vec::new();
        for index in 0..12_000u32 {
            writeln!(
                &mut payload,
                "ubuntu linux upload parity line {:05} repeated request surface",
                index % 1024
            )
            .unwrap();
        }
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();

        let root = unique_test_dir("ed2k-upload-listener-compressed");
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
        let job = new_transfer_job(file_hash, "upload.txt".to_string(), payload.len() as u64);
        transfer_runtime.ensure_job(&job).await.unwrap();
        transfer_runtime
            .store_md4_hashset(&file_hash_hex, Vec::new())
            .await
            .unwrap();
        transfer_runtime
            .store_piece_data(&file_hash_hex, 0, &payload)
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let dht = DhtNode::new(DhtConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            node_id: NodeId::from_bytes([0x3C; 16]),
            udp_key: 0x1122_3344,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let secure_ident = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let hello_identity = Ed2kHelloIdentity {
            user_hash: [0x22; 16],
            client_id: 0x1234_5678,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };

        let server = tokio::spawn({
            let transfer_runtime = Arc::clone(&transfer_runtime);
            let server_state = Arc::clone(&server_state);
            let kad_firewall = Arc::clone(&kad_firewall);
            let secure_ident = Arc::clone(&secure_ident);
            async move {
                let (stream, remote_addr) = listener.accept().await.unwrap();
                super::handle_connection(
                    stream,
                    remote_addr,
                    &dht,
                    &server_state,
                    &kad_firewall,
                    &secure_ident,
                    &transfer_runtime,
                    hello_identity,
                )
                .await
                .unwrap();
            }
        });

        let mut stream = TcpStream::connect(peer_addr).await.unwrap();
        let peer_identity = Ed2kHelloIdentity {
            user_hash: [0x77; 16],
            client_id: 0x8765_4321,
            tcp_port: 46671,
            udp_port: 46672,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        stream
            .write_all(&encode_hello_request(peer_identity))
            .await
            .unwrap();
        let _hello_answer = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;

        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        stream
            .write_all(&super::encode_request_filename(&file_hash, &manifest))
            .await
            .unwrap();
        let request_filename_answer =
            read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_REQFILENAMEANSWER).await;
        assert_eq!(&request_filename_answer[6..22], &file_hash.0);

        stream
            .write_all(&super::encode_start_upload_req(&file_hash))
            .await
            .unwrap();
        let accept_upload =
            read_until_opcode(&mut stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;
        assert_eq!(accept_upload.len(), 6);

        stream
            .write_all(
                &super::encode_request_parts_batch(&file_hash, &[(0, payload.len() as u64)])
                    .unwrap(),
            )
            .await
            .unwrap();

        let mut reconstructed = Vec::new();
        let mut saw_compressed = false;
        let mut pending = None;
        while reconstructed.len() < payload.len() {
            let packet = read_packet(&mut stream).await;
            match (packet[0], packet[5]) {
                (OP_EMULEPROT, super::OP_COMPRESSEDPART) => {
                    saw_compressed = true;
                    let (decoded_hash, start, advertised_len, fragment) =
                        super::decode_compressed_part_fragment(&packet[6..], false).unwrap();
                    assert_eq!(decoded_hash, file_hash);
                    assert_eq!(start, 0);
                    let pending_stream =
                        pending.get_or_insert_with(|| super::PendingCompressedPart {
                            piece_index: 0,
                            start: 0,
                            end: payload.len() as u64,
                            advertised_compressed_len: advertised_len,
                            compressed_received: 0,
                            uncompressed_written: 0,
                            inflater: Decompress::new(true),
                        });
                    let (bytes, finished) =
                        super::inflate_compressed_part_fragment(pending_stream, fragment).unwrap();
                    reconstructed.extend_from_slice(&bytes);
                    if finished {
                        pending = None;
                    }
                }
                (OP_EDONKEYPROT, super::OP_SENDINGPART) => {
                    let (_, _, _, bytes) =
                        super::decode_sending_part_payload(&packet[6..], false).unwrap();
                    reconstructed.extend_from_slice(&bytes);
                }
                _ => {}
            }
        }

        assert!(saw_compressed);
        assert_eq!(reconstructed, payload);
        drop(stream);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn listener_upload_startup_tolerates_source_exchange_and_aich_probe() {
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

        async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
            loop {
                let packet = read_packet(stream).await;
                if packet[0] == protocol && packet[5] == opcode {
                    return packet;
                }
            }
        }

        let payload = b"ubuntu linux upload startup handshake".repeat(512);
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        let root = unique_test_dir("ed2k-upload-listener-startup");
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
        let job = new_transfer_job(file_hash, "startup.txt".to_string(), payload.len() as u64);
        transfer_runtime.ensure_job(&job).await.unwrap();
        transfer_runtime
            .store_md4_hashset(&file_hash_hex, Vec::new())
            .await
            .unwrap();
        transfer_runtime
            .store_piece_data(&file_hash_hex, 0, &payload)
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let dht = DhtNode::new(DhtConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            node_id: NodeId::from_bytes([0x4D; 16]),
            udp_key: 0x5566_7788,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let secure_ident = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let hello_identity = Ed2kHelloIdentity {
            user_hash: [0x31; 16],
            client_id: 0x1357_2468,
            tcp_port: 41011,
            udp_port: 41010,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };

        let server = tokio::spawn({
            let transfer_runtime = Arc::clone(&transfer_runtime);
            let server_state = Arc::clone(&server_state);
            let kad_firewall = Arc::clone(&kad_firewall);
            let secure_ident = Arc::clone(&secure_ident);
            async move {
                let (stream, remote_addr) = listener.accept().await.unwrap();
                super::handle_connection(
                    stream,
                    remote_addr,
                    &dht,
                    &server_state,
                    &kad_firewall,
                    &secure_ident,
                    &transfer_runtime,
                    hello_identity,
                )
                .await
                .unwrap();
            }
        });

        let mut stream = TcpStream::connect(peer_addr).await.unwrap();
        let peer_identity = Ed2kHelloIdentity {
            user_hash: [0x41; 16],
            client_id: 0x2468_1357,
            tcp_port: 4662,
            udp_port: 4672,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        stream
            .write_all(&encode_hello_request(peer_identity))
            .await
            .unwrap();
        let _ = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;

        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        stream
            .write_all(&super::encode_request_filename(&file_hash, &manifest))
            .await
            .unwrap();
        let filename_answer =
            read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_REQFILENAMEANSWER).await;
        assert_eq!(&filename_answer[6..22], &file_hash.0);

        stream
            .write_all(&super::encode_request_sources2(&file_hash))
            .await
            .unwrap();
        let source_answer =
            read_until_opcode(&mut stream, OP_EMULEPROT, super::OP_ANSWERSOURCES2).await;
        assert_eq!(source_answer[6], super::ED2K_SOURCE_EXCHANGE2_VERSION);
        assert_eq!(&source_answer[7..23], &file_hash.0);
        assert_eq!(
            u16::from_le_bytes([source_answer[23], source_answer[24]]),
            0
        );

        let modern_hashset_request = super::encode_hashset_request2(
            &super::Ed2kFileIdentifier::from_manifest(&manifest).unwrap(),
            super::Ed2kHashsetRequestOptions {
                request_md4: true,
                request_aich: false,
            },
        )
        .unwrap();
        stream.write_all(&modern_hashset_request).await.unwrap();
        let modern_hashset_answer =
            read_until_opcode(&mut stream, OP_EMULEPROT, super::OP_HASHSETANSWER2).await;
        let returned = super::decode_hashset_answer2(&modern_hashset_answer[6..]).unwrap();
        assert_eq!(returned.file_identifier.file_hash, file_hash);
        assert_eq!(
            returned.file_identifier.file_size,
            Some(payload.len() as u64)
        );
        assert!(returned.md4_hashset.is_none());
        assert!(returned.aich_hashset.is_none());

        stream
            .write_all(&super::encode_aich_file_hash_request(&file_hash))
            .await
            .unwrap();
        stream
            .write_all(&super::encode_start_upload_req(&file_hash))
            .await
            .unwrap();
        let accept_upload =
            read_until_opcode(&mut stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;
        assert_eq!(accept_upload.len(), 6);

        drop(stream);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn listener_upload_queue_promotes_waiter_after_disconnect() {
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

        async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
            loop {
                let packet = read_packet(stream).await;
                if packet[0] == protocol && packet[5] == opcode {
                    return packet;
                }
            }
        }

        let payload = vec![0x51; 4096];
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        let root = unique_test_dir("ed2k-upload-listener-queue-disconnect");
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
        transfer_runtime
            .configure_upload_queue(Ed2kUploadQueueConfig {
                active_slots: 1,
                waiting_capacity: 8,
                waiting_timeout: Duration::from_secs(30),
                granted_timeout: Duration::from_secs(30),
                upload_timeout: Duration::from_secs(30),
            })
            .await;
        let job = new_transfer_job(file_hash, "queued.txt".to_string(), payload.len() as u64);
        transfer_runtime.ensure_job(&job).await.unwrap();
        transfer_runtime
            .store_md4_hashset(&file_hash_hex, Vec::new())
            .await
            .unwrap();
        transfer_runtime
            .store_piece_data(&file_hash_hex, 0, &payload)
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let dht = DhtNode::new(DhtConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            node_id: NodeId::from_bytes([0x3D; 16]),
            udp_key: 0x1122_3344,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let secure_ident = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let hello_identity = Ed2kHelloIdentity {
            user_hash: [0x22; 16],
            client_id: 0x1234_5678,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };

        let server = tokio::spawn({
            let dht = dht.clone();
            let transfer_runtime = Arc::clone(&transfer_runtime);
            let server_state = Arc::clone(&server_state);
            let kad_firewall = Arc::clone(&kad_firewall);
            let secure_ident = Arc::clone(&secure_ident);
            async move {
                let (first_stream, first_addr) = listener.accept().await.unwrap();
                let first = tokio::spawn({
                    let dht = dht.clone();
                    let transfer_runtime = Arc::clone(&transfer_runtime);
                    let server_state = Arc::clone(&server_state);
                    let kad_firewall = Arc::clone(&kad_firewall);
                    let secure_ident = Arc::clone(&secure_ident);
                    async move {
                        super::handle_connection(
                            first_stream,
                            first_addr,
                            &dht,
                            &server_state,
                            &kad_firewall,
                            &secure_ident,
                            &transfer_runtime,
                            hello_identity,
                        )
                        .await
                    }
                });

                let (second_stream, second_addr) = listener.accept().await.unwrap();
                let second = tokio::spawn({
                    let transfer_runtime = Arc::clone(&transfer_runtime);
                    let server_state = Arc::clone(&server_state);
                    let kad_firewall = Arc::clone(&kad_firewall);
                    let secure_ident = Arc::clone(&secure_ident);
                    async move {
                        super::handle_connection(
                            second_stream,
                            second_addr,
                            &dht,
                            &server_state,
                            &kad_firewall,
                            &secure_ident,
                            &transfer_runtime,
                            hello_identity,
                        )
                        .await
                    }
                });

                first.await.unwrap().unwrap();
                second.await.unwrap().unwrap();
            }
        });

        let first_identity = Ed2kHelloIdentity {
            user_hash: [0x31; 16],
            client_id: 0x0102_0304,
            tcp_port: 4661,
            udp_port: 4665,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        let mut first_stream = TcpStream::connect(peer_addr).await.unwrap();
        first_stream
            .write_all(&encode_hello_request(first_identity))
            .await
            .unwrap();
        let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
        first_stream
            .write_all(&super::encode_start_upload_req(&file_hash))
            .await
            .unwrap();
        let _ =
            read_until_opcode(&mut first_stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;

        let second_identity = Ed2kHelloIdentity {
            user_hash: [0x32; 16],
            client_id: 0x0506_0708,
            tcp_port: 4662,
            udp_port: 4666,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        let mut second_stream = TcpStream::connect(peer_addr).await.unwrap();
        second_stream
            .write_all(&encode_hello_request(second_identity))
            .await
            .unwrap();
        let _ = read_until_opcode(&mut second_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
        second_stream
            .write_all(&super::encode_start_upload_req(&file_hash))
            .await
            .unwrap();
        let queue_ranking =
            read_until_opcode(&mut second_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
        assert_eq!(u16::from_le_bytes([queue_ranking[6], queue_ranking[7]]), 1);

        drop(first_stream);

        let promoted = tokio::time::timeout(
            Duration::from_secs(3),
            read_until_opcode(
                &mut second_stream,
                OP_EDONKEYPROT,
                super::OP_ACCEPTUPLOADREQ,
            ),
        )
        .await
        .unwrap();
        assert_eq!(promoted.len(), 6);
        drop(second_stream);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn listener_upload_queue_promotes_waiter_after_cancel_transfer() {
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

        async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
            loop {
                let packet = read_packet(stream).await;
                if packet[0] == protocol && packet[5] == opcode {
                    return packet;
                }
            }
        }

        let payload = vec![0x61; 4096];
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        let root = unique_test_dir("ed2k-upload-listener-queue-cancel");
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
        transfer_runtime
            .configure_upload_queue(Ed2kUploadQueueConfig {
                active_slots: 1,
                waiting_capacity: 8,
                waiting_timeout: Duration::from_secs(30),
                granted_timeout: Duration::from_secs(30),
                upload_timeout: Duration::from_secs(30),
            })
            .await;
        let job = new_transfer_job(file_hash, "queued.txt".to_string(), payload.len() as u64);
        transfer_runtime.ensure_job(&job).await.unwrap();
        transfer_runtime
            .store_md4_hashset(&file_hash_hex, Vec::new())
            .await
            .unwrap();
        transfer_runtime
            .store_piece_data(&file_hash_hex, 0, &payload)
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let dht = DhtNode::new(DhtConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            node_id: NodeId::from_bytes([0x3E; 16]),
            udp_key: 0x5566_7788,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let secure_ident = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let hello_identity = Ed2kHelloIdentity {
            user_hash: [0x23; 16],
            client_id: 0x2233_4455,
            tcp_port: 41002,
            udp_port: 41003,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };

        let server = tokio::spawn({
            let dht = dht.clone();
            let transfer_runtime = Arc::clone(&transfer_runtime);
            let server_state = Arc::clone(&server_state);
            let kad_firewall = Arc::clone(&kad_firewall);
            let secure_ident = Arc::clone(&secure_ident);
            async move {
                let (first_stream, first_addr) = listener.accept().await.unwrap();
                let first = tokio::spawn({
                    let dht = dht.clone();
                    let transfer_runtime = Arc::clone(&transfer_runtime);
                    let server_state = Arc::clone(&server_state);
                    let kad_firewall = Arc::clone(&kad_firewall);
                    let secure_ident = Arc::clone(&secure_ident);
                    async move {
                        super::handle_connection(
                            first_stream,
                            first_addr,
                            &dht,
                            &server_state,
                            &kad_firewall,
                            &secure_ident,
                            &transfer_runtime,
                            hello_identity,
                        )
                        .await
                    }
                });

                let (second_stream, second_addr) = listener.accept().await.unwrap();
                let second = tokio::spawn({
                    let transfer_runtime = Arc::clone(&transfer_runtime);
                    let server_state = Arc::clone(&server_state);
                    let kad_firewall = Arc::clone(&kad_firewall);
                    let secure_ident = Arc::clone(&secure_ident);
                    async move {
                        super::handle_connection(
                            second_stream,
                            second_addr,
                            &dht,
                            &server_state,
                            &kad_firewall,
                            &secure_ident,
                            &transfer_runtime,
                            hello_identity,
                        )
                        .await
                    }
                });

                first.await.unwrap().unwrap();
                second.await.unwrap().unwrap();
            }
        });

        let first_identity = Ed2kHelloIdentity {
            user_hash: [0x41; 16],
            client_id: 0x1111_1111,
            tcp_port: 4661,
            udp_port: 4665,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        let mut first_stream = TcpStream::connect(peer_addr).await.unwrap();
        first_stream
            .write_all(&encode_hello_request(first_identity))
            .await
            .unwrap();
        let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
        first_stream
            .write_all(&super::encode_start_upload_req(&file_hash))
            .await
            .unwrap();
        let _ =
            read_until_opcode(&mut first_stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;

        let second_identity = Ed2kHelloIdentity {
            user_hash: [0x42; 16],
            client_id: 0x2222_2222,
            tcp_port: 4662,
            udp_port: 4666,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        let mut second_stream = TcpStream::connect(peer_addr).await.unwrap();
        second_stream
            .write_all(&encode_hello_request(second_identity))
            .await
            .unwrap();
        let _ = read_until_opcode(&mut second_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
        second_stream
            .write_all(&super::encode_start_upload_req(&file_hash))
            .await
            .unwrap();
        let queue_ranking =
            read_until_opcode(&mut second_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
        assert_eq!(u16::from_le_bytes([queue_ranking[6], queue_ranking[7]]), 1);

        first_stream
            .write_all(&encode_packet(
                OP_EDONKEYPROT,
                super::OP_CANCELTRANSFER,
                &[],
            ))
            .await
            .unwrap();
        drop(first_stream);

        let promoted = tokio::time::timeout(
            Duration::from_secs(3),
            read_until_opcode(
                &mut second_stream,
                OP_EDONKEYPROT,
                super::OP_ACCEPTUPLOADREQ,
            ),
        )
        .await
        .unwrap();
        assert_eq!(promoted.len(), 6);
        drop(second_stream);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn listener_upload_queue_refreshes_waiting_rank_before_promotion() {
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

        async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
            loop {
                let packet = read_packet(stream).await;
                if packet[0] == protocol && packet[5] == opcode {
                    return packet;
                }
            }
        }

        let payload = vec![0x71; 4096];
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        let root = unique_test_dir("ed2k-upload-listener-queue-refresh");
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
        transfer_runtime
            .configure_upload_queue(Ed2kUploadQueueConfig {
                active_slots: 1,
                waiting_capacity: 8,
                waiting_timeout: Duration::from_secs(30),
                granted_timeout: Duration::from_secs(30),
                upload_timeout: Duration::from_secs(30),
            })
            .await;
        let job = new_transfer_job(file_hash, "queued.txt".to_string(), payload.len() as u64);
        transfer_runtime.ensure_job(&job).await.unwrap();
        transfer_runtime
            .store_md4_hashset(&file_hash_hex, Vec::new())
            .await
            .unwrap();
        transfer_runtime
            .store_piece_data(&file_hash_hex, 0, &payload)
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let dht = DhtNode::new(DhtConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            node_id: NodeId::from_bytes([0x4E; 16]),
            udp_key: 0x2233_4455,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let secure_ident = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let hello_identity = Ed2kHelloIdentity {
            user_hash: [0x51; 16],
            client_id: 0x3141_5926,
            tcp_port: 41002,
            udp_port: 41003,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };

        let server = tokio::spawn({
            let dht = dht.clone();
            let transfer_runtime = Arc::clone(&transfer_runtime);
            let server_state = Arc::clone(&server_state);
            let kad_firewall = Arc::clone(&kad_firewall);
            let secure_ident = Arc::clone(&secure_ident);
            async move {
                let (first_stream, first_addr) = listener.accept().await.unwrap();
                let first = tokio::spawn({
                    let dht = dht.clone();
                    let transfer_runtime = Arc::clone(&transfer_runtime);
                    let server_state = Arc::clone(&server_state);
                    let kad_firewall = Arc::clone(&kad_firewall);
                    let secure_ident = Arc::clone(&secure_ident);
                    async move {
                        super::handle_connection(
                            first_stream,
                            first_addr,
                            &dht,
                            &server_state,
                            &kad_firewall,
                            &secure_ident,
                            &transfer_runtime,
                            hello_identity,
                        )
                        .await
                    }
                });

                let (second_stream, second_addr) = listener.accept().await.unwrap();
                let second = tokio::spawn({
                    let transfer_runtime = Arc::clone(&transfer_runtime);
                    let server_state = Arc::clone(&server_state);
                    let kad_firewall = Arc::clone(&kad_firewall);
                    let secure_ident = Arc::clone(&secure_ident);
                    async move {
                        super::handle_connection(
                            second_stream,
                            second_addr,
                            &dht,
                            &server_state,
                            &kad_firewall,
                            &secure_ident,
                            &transfer_runtime,
                            hello_identity,
                        )
                        .await
                    }
                });

                first.await.unwrap().unwrap();
                second.await.unwrap().unwrap();
            }
        });

        let first_identity = Ed2kHelloIdentity {
            user_hash: [0x61; 16],
            client_id: 0x1111_2222,
            tcp_port: 4661,
            udp_port: 4665,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        let mut first_stream = TcpStream::connect(peer_addr).await.unwrap();
        first_stream
            .write_all(&encode_hello_request(first_identity))
            .await
            .unwrap();
        let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
        first_stream
            .write_all(&super::encode_start_upload_req(&file_hash))
            .await
            .unwrap();
        let _ =
            read_until_opcode(&mut first_stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;

        let second_identity = Ed2kHelloIdentity {
            user_hash: [0x62; 16],
            client_id: 0x2222_3333,
            tcp_port: 4662,
            udp_port: 4666,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        let mut second_stream = TcpStream::connect(peer_addr).await.unwrap();
        second_stream
            .write_all(&encode_hello_request(second_identity))
            .await
            .unwrap();
        let _ = read_until_opcode(&mut second_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
        second_stream
            .write_all(&super::encode_start_upload_req(&file_hash))
            .await
            .unwrap();
        let first_rank =
            read_until_opcode(&mut second_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
        assert_eq!(u16::from_le_bytes([first_rank[6], first_rank[7]]), 1);

        let refreshed = tokio::time::timeout(
            Duration::from_secs(2),
            read_until_opcode(&mut second_stream, OP_EMULEPROT, super::OP_QUEUERANKING),
        )
        .await
        .unwrap();
        assert_eq!(u16::from_le_bytes([refreshed[6], refreshed[7]]), 1);

        first_stream
            .write_all(&encode_packet(
                OP_EDONKEYPROT,
                super::OP_CANCELTRANSFER,
                &[],
            ))
            .await
            .unwrap();
        drop(first_stream);

        let promoted = tokio::time::timeout(
            Duration::from_secs(3),
            read_until_opcode(
                &mut second_stream,
                OP_EDONKEYPROT,
                super::OP_ACCEPTUPLOADREQ,
            ),
        )
        .await
        .unwrap();
        assert_eq!(promoted.len(), 6);
        drop(second_stream);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn listener_upload_queue_reconnects_waiter_by_hello_identity() {
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

        async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
            loop {
                let packet = read_packet(stream).await;
                if packet[0] == protocol && packet[5] == opcode {
                    return packet;
                }
            }
        }

        let payload = vec![0x7B; 4096];
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        let root = unique_test_dir("ed2k-upload-listener-queue-reconnect-hello");
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
        transfer_runtime
            .configure_upload_queue(Ed2kUploadQueueConfig {
                active_slots: 1,
                waiting_capacity: 8,
                waiting_timeout: Duration::from_secs(30),
                granted_timeout: Duration::from_secs(30),
                upload_timeout: Duration::from_secs(30),
            })
            .await;
        let job = new_transfer_job(file_hash, "queued.txt".to_string(), payload.len() as u64);
        transfer_runtime.ensure_job(&job).await.unwrap();
        transfer_runtime
            .store_md4_hashset(&file_hash_hex, Vec::new())
            .await
            .unwrap();
        transfer_runtime
            .store_piece_data(&file_hash_hex, 0, &payload)
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let dht = DhtNode::new(DhtConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            node_id: NodeId::from_bytes([0x5E; 16]),
            udp_key: 0x6677_8899,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let secure_ident = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let hello_identity = Ed2kHelloIdentity {
            user_hash: [0x71; 16],
            client_id: 0x4242_2424,
            tcp_port: 41002,
            udp_port: 41003,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };

        let server = tokio::spawn({
            let dht = dht.clone();
            let transfer_runtime = Arc::clone(&transfer_runtime);
            let server_state = Arc::clone(&server_state);
            let kad_firewall = Arc::clone(&kad_firewall);
            let secure_ident = Arc::clone(&secure_ident);
            async move {
                loop {
                    let (stream, addr) = listener.accept().await.unwrap();
                    let dht = dht.clone();
                    let transfer_runtime = Arc::clone(&transfer_runtime);
                    let server_state = Arc::clone(&server_state);
                    let kad_firewall = Arc::clone(&kad_firewall);
                    let secure_ident = Arc::clone(&secure_ident);
                    tokio::spawn(async move {
                        let _ = super::handle_connection(
                            stream,
                            addr,
                            &dht,
                            &server_state,
                            &kad_firewall,
                            &secure_ident,
                            &transfer_runtime,
                            hello_identity,
                        )
                        .await;
                    });
                }
            }
        });

        let first_identity = Ed2kHelloIdentity {
            user_hash: [0x81; 16],
            client_id: 0x1111_1111,
            tcp_port: 4661,
            udp_port: 4665,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        let mut first_stream = TcpStream::connect(peer_addr).await.unwrap();
        first_stream
            .write_all(&encode_hello_request(first_identity))
            .await
            .unwrap();
        let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
        first_stream
            .write_all(&super::encode_start_upload_req(&file_hash))
            .await
            .unwrap();
        let _ =
            read_until_opcode(&mut first_stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;

        let queued_identity = Ed2kHelloIdentity {
            user_hash: [0x91; 16],
            client_id: 0x3333_3333,
            tcp_port: 4662,
            udp_port: 4666,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        let mut queued_stream = TcpStream::connect(peer_addr).await.unwrap();
        queued_stream
            .write_all(&encode_hello_request(queued_identity))
            .await
            .unwrap();
        let _ = read_until_opcode(&mut queued_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
        queued_stream
            .write_all(&super::encode_start_upload_req(&file_hash))
            .await
            .unwrap();
        let queue_ranking =
            read_until_opcode(&mut queued_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
        assert_eq!(u16::from_le_bytes([queue_ranking[6], queue_ranking[7]]), 1);
        drop(queued_stream);

        let mut reconnected_stream = TcpStream::connect(peer_addr).await.unwrap();
        reconnected_stream
            .write_all(&encode_hello_request(queued_identity))
            .await
            .unwrap();
        let _ = read_until_opcode(&mut reconnected_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
        reconnected_stream
            .write_all(&super::encode_start_upload_req(&file_hash))
            .await
            .unwrap();
        let refreshed_rank = read_until_opcode(
            &mut reconnected_stream,
            OP_EMULEPROT,
            super::OP_QUEUERANKING,
        )
        .await;
        assert_eq!(
            u16::from_le_bytes([refreshed_rank[6], refreshed_rank[7]]),
            1
        );

        first_stream
            .write_all(&encode_packet(
                OP_EDONKEYPROT,
                super::OP_CANCELTRANSFER,
                &[],
            ))
            .await
            .unwrap();
        drop(first_stream);

        let promoted = tokio::time::timeout(
            Duration::from_secs(3),
            read_until_opcode(
                &mut reconnected_stream,
                OP_EDONKEYPROT,
                super::OP_ACCEPTUPLOADREQ,
            ),
        )
        .await
        .unwrap();
        assert_eq!(promoted.len(), 6);
        drop(reconnected_stream);
        server.abort();
    }

    #[tokio::test]
    async fn listener_upload_queue_preserves_waiter_rank_across_file_switch() {
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

        async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
            loop {
                let packet = read_packet(stream).await;
                if packet[0] == protocol && packet[5] == opcode {
                    return packet;
                }
            }
        }

        let first_payload = vec![0x7B; 4096];
        let second_payload = vec![0x8C; 4096];
        let first_file_hash = Ed2kHash::from_bytes(Md4::digest(&first_payload).into());
        let second_file_hash = Ed2kHash::from_bytes(Md4::digest(&second_payload).into());
        let first_file_hash_hex = first_file_hash.to_string();
        let second_file_hash_hex = second_file_hash.to_string();
        let root = unique_test_dir("ed2k-upload-listener-queue-file-switch");
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
        transfer_runtime
            .configure_upload_queue(Ed2kUploadQueueConfig {
                active_slots: 1,
                waiting_capacity: 8,
                waiting_timeout: Duration::from_secs(30),
                granted_timeout: Duration::from_secs(30),
                upload_timeout: Duration::from_secs(30),
            })
            .await;

        let first_job = new_transfer_job(
            first_file_hash,
            "queued-one.txt".to_string(),
            first_payload.len() as u64,
        );
        transfer_runtime.ensure_job(&first_job).await.unwrap();
        transfer_runtime
            .store_md4_hashset(&first_file_hash_hex, Vec::new())
            .await
            .unwrap();
        transfer_runtime
            .store_piece_data(&first_file_hash_hex, 0, &first_payload)
            .await
            .unwrap();

        let second_job = new_transfer_job(
            second_file_hash,
            "queued-two.txt".to_string(),
            second_payload.len() as u64,
        );
        transfer_runtime.ensure_job(&second_job).await.unwrap();
        transfer_runtime
            .store_md4_hashset(&second_file_hash_hex, Vec::new())
            .await
            .unwrap();
        transfer_runtime
            .store_piece_data(&second_file_hash_hex, 0, &second_payload)
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let dht = DhtNode::new(DhtConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            node_id: NodeId::from_bytes([0x6E; 16]),
            udp_key: 0x7788_99AA,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let secure_ident = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let hello_identity = Ed2kHelloIdentity {
            user_hash: [0x71; 16],
            client_id: 0x4343_2525,
            tcp_port: 41002,
            udp_port: 41003,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };

        let server = tokio::spawn({
            let dht = dht.clone();
            let transfer_runtime = Arc::clone(&transfer_runtime);
            let server_state = Arc::clone(&server_state);
            let kad_firewall = Arc::clone(&kad_firewall);
            let secure_ident = Arc::clone(&secure_ident);
            async move {
                loop {
                    let (stream, addr) = listener.accept().await.unwrap();
                    let dht = dht.clone();
                    let transfer_runtime = Arc::clone(&transfer_runtime);
                    let server_state = Arc::clone(&server_state);
                    let kad_firewall = Arc::clone(&kad_firewall);
                    let secure_ident = Arc::clone(&secure_ident);
                    tokio::spawn(async move {
                        let _ = super::handle_connection(
                            stream,
                            addr,
                            &dht,
                            &server_state,
                            &kad_firewall,
                            &secure_ident,
                            &transfer_runtime,
                            hello_identity,
                        )
                        .await;
                    });
                }
            }
        });

        let first_identity = Ed2kHelloIdentity {
            user_hash: [0x81; 16],
            client_id: 0x1111_1111,
            tcp_port: 4661,
            udp_port: 4665,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        let mut first_stream = TcpStream::connect(peer_addr).await.unwrap();
        first_stream
            .write_all(&encode_hello_request(first_identity))
            .await
            .unwrap();
        let _ = read_until_opcode(&mut first_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
        first_stream
            .write_all(&super::encode_start_upload_req(&first_file_hash))
            .await
            .unwrap();
        let _ =
            read_until_opcode(&mut first_stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;

        let queued_identity = Ed2kHelloIdentity {
            user_hash: [0x91; 16],
            client_id: 0x3333_3333,
            tcp_port: 4662,
            udp_port: 4666,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        let mut queued_stream = TcpStream::connect(peer_addr).await.unwrap();
        queued_stream
            .write_all(&encode_hello_request(queued_identity))
            .await
            .unwrap();
        let _ = read_until_opcode(&mut queued_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
        queued_stream
            .write_all(&super::encode_start_upload_req(&first_file_hash))
            .await
            .unwrap();
        let first_rank =
            read_until_opcode(&mut queued_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
        assert_eq!(u16::from_le_bytes([first_rank[6], first_rank[7]]), 1);

        let trailing_identity = Ed2kHelloIdentity {
            user_hash: [0xA1; 16],
            client_id: 0x4444_4444,
            tcp_port: 4663,
            udp_port: 4667,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        let mut trailing_stream = TcpStream::connect(peer_addr).await.unwrap();
        trailing_stream
            .write_all(&encode_hello_request(trailing_identity))
            .await
            .unwrap();
        let _ = read_until_opcode(&mut trailing_stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;
        trailing_stream
            .write_all(&super::encode_start_upload_req(&first_file_hash))
            .await
            .unwrap();
        let trailing_rank =
            read_until_opcode(&mut trailing_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
        assert_eq!(u16::from_le_bytes([trailing_rank[6], trailing_rank[7]]), 2);

        queued_stream
            .write_all(&super::encode_start_upload_req(&second_file_hash))
            .await
            .unwrap();
        let switched_rank =
            read_until_opcode(&mut queued_stream, OP_EMULEPROT, super::OP_QUEUERANKING).await;
        assert_eq!(u16::from_le_bytes([switched_rank[6], switched_rank[7]]), 1);

        let refreshed_trailing_rank = tokio::time::timeout(
            Duration::from_secs(2),
            read_until_opcode(&mut trailing_stream, OP_EMULEPROT, super::OP_QUEUERANKING),
        )
        .await
        .unwrap();
        assert_eq!(
            u16::from_le_bytes([refreshed_trailing_rank[6], refreshed_trailing_rank[7]]),
            2
        );

        first_stream
            .write_all(&encode_packet(
                OP_EDONKEYPROT,
                super::OP_CANCELTRANSFER,
                &[],
            ))
            .await
            .unwrap();
        drop(first_stream);

        let promoted = tokio::time::timeout(
            Duration::from_secs(3),
            read_until_opcode(
                &mut queued_stream,
                OP_EDONKEYPROT,
                super::OP_ACCEPTUPLOADREQ,
            ),
        )
        .await
        .unwrap();
        assert_eq!(promoted.len(), 6);

        drop(queued_stream);
        drop(trailing_stream);
        server.abort();
    }

    #[tokio::test]
    async fn listener_upload_peer_can_resume_partial_download_after_reconnect() {
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

        async fn read_until_opcode(stream: &mut TcpStream, protocol: u8, opcode: u8) -> Vec<u8> {
            loop {
                let packet = read_packet(stream).await;
                if packet[0] == protocol && packet[5] == opcode {
                    return packet;
                }
            }
        }

        async fn read_until_opcode_timeout(
            stream: &mut TcpStream,
            protocol: u8,
            opcode: u8,
            context: &str,
        ) -> Vec<u8> {
            tokio::time::timeout(
                Duration::from_secs(5),
                read_until_opcode(stream, protocol, opcode),
            )
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {context}"))
        }

        async fn read_upload_bytes(
            stream: &mut TcpStream,
            file_hash: &Ed2kHash,
            expected_start: u64,
            expected_end: u64,
        ) -> Vec<u8> {
            let mut reconstructed = Vec::new();
            let mut pending = None;
            while reconstructed.len() < usize::try_from(expected_end - expected_start).unwrap() {
                let packet = tokio::time::timeout(Duration::from_secs(5), read_packet(stream))
                    .await
                    .expect("timed out waiting for upload payload");
                match (packet[0], packet[5]) {
                    (OP_EMULEPROT, super::OP_COMPRESSEDPART) => {
                        let (decoded_hash, start, advertised_len, fragment) =
                            super::decode_compressed_part_fragment(&packet[6..], false).unwrap();
                        assert_eq!(decoded_hash, *file_hash);
                        assert_eq!(start, expected_start);
                        let pending_stream =
                            pending.get_or_insert_with(|| super::PendingCompressedPart {
                                piece_index: 0,
                                start: expected_start,
                                end: expected_end,
                                advertised_compressed_len: advertised_len,
                                compressed_received: 0,
                                uncompressed_written: 0,
                                inflater: Decompress::new(true),
                            });
                        let (bytes, finished) =
                            super::inflate_compressed_part_fragment(pending_stream, fragment)
                                .unwrap();
                        reconstructed.extend_from_slice(&bytes);
                        if finished {
                            pending = None;
                        }
                    }
                    (OP_EDONKEYPROT, super::OP_SENDINGPART) => {
                        let (decoded_hash, start, end, bytes) =
                            super::decode_sending_part_payload(&packet[6..], false).unwrap();
                        assert_eq!(decoded_hash, *file_hash);
                        assert_eq!(
                            start,
                            expected_start + u64::try_from(reconstructed.len()).unwrap()
                        );
                        assert_eq!(end, start + u64::try_from(bytes.len()).unwrap());
                        reconstructed.extend_from_slice(&bytes);
                    }
                    _ => {}
                }
            }
            reconstructed
        }

        let payload = (0..32_768u32)
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>();
        let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        let root = unique_test_dir("ed2k-upload-listener-resume-reconnect");
        let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
        let job = new_transfer_job(file_hash, "resume.bin".to_string(), payload.len() as u64);
        transfer_runtime.ensure_job(&job).await.unwrap();
        transfer_runtime
            .store_md4_hashset(&file_hash_hex, Vec::new())
            .await
            .unwrap();
        transfer_runtime
            .store_piece_data(&file_hash_hex, 0, &payload)
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let dht = DhtNode::new(DhtConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            node_id: NodeId::from_bytes([0x6E; 16]),
            udp_key: 0x99AA_5500,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let secure_ident = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let hello_identity = Ed2kHelloIdentity {
            user_hash: [0xA1; 16],
            client_id: 0x5151_0101,
            tcp_port: 41002,
            udp_port: 41003,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };

        let server = tokio::spawn({
            let dht = dht.clone();
            let transfer_runtime = Arc::clone(&transfer_runtime);
            let server_state = Arc::clone(&server_state);
            let kad_firewall = Arc::clone(&kad_firewall);
            let secure_ident = Arc::clone(&secure_ident);
            async move {
                loop {
                    let (stream, addr) = listener.accept().await.unwrap();
                    let dht = dht.clone();
                    let transfer_runtime = Arc::clone(&transfer_runtime);
                    let server_state = Arc::clone(&server_state);
                    let kad_firewall = Arc::clone(&kad_firewall);
                    let secure_ident = Arc::clone(&secure_ident);
                    tokio::spawn(async move {
                        let _ = super::handle_connection(
                            stream,
                            addr,
                            &dht,
                            &server_state,
                            &kad_firewall,
                            &secure_ident,
                            &transfer_runtime,
                            hello_identity,
                        )
                        .await;
                    });
                }
            }
        });

        let peer_identity = Ed2kHelloIdentity {
            user_hash: [0xB1; 16],
            client_id: 0x7777_0001,
            tcp_port: 4662,
            udp_port: 4666,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };
        let first_end = (payload.len() as u64) / 2;
        let second_start = first_end;
        let second_end = payload.len() as u64;

        let mut first_stream = TcpStream::connect(peer_addr).await.unwrap();
        first_stream
            .write_all(&encode_hello_request(peer_identity))
            .await
            .unwrap();
        let _ = read_until_opcode_timeout(
            &mut first_stream,
            OP_EDONKEYPROT,
            OP_HELLOANSWER,
            "first hello answer",
        )
        .await;
        first_stream
            .write_all(&super::encode_start_upload_req(&file_hash))
            .await
            .unwrap();
        let _ = read_until_opcode_timeout(
            &mut first_stream,
            OP_EDONKEYPROT,
            super::OP_ACCEPTUPLOADREQ,
            "first accept upload",
        )
        .await;
        first_stream
            .write_all(&super::encode_request_parts_batch(&file_hash, &[(0, first_end)]).unwrap())
            .await
            .unwrap();
        let first_bytes = read_upload_bytes(&mut first_stream, &file_hash, 0, first_end).await;
        assert_eq!(
            first_bytes,
            payload[0..usize::try_from(first_end).unwrap()].to_vec()
        );
        drop(first_stream);

        let mut resumed_stream = TcpStream::connect(peer_addr).await.unwrap();
        resumed_stream
            .write_all(&encode_hello_request(peer_identity))
            .await
            .unwrap();
        let _ = read_until_opcode_timeout(
            &mut resumed_stream,
            OP_EDONKEYPROT,
            OP_HELLOANSWER,
            "resumed hello answer",
        )
        .await;
        resumed_stream
            .write_all(&super::encode_start_upload_req(&file_hash))
            .await
            .unwrap();
        let _ = read_until_opcode_timeout(
            &mut resumed_stream,
            OP_EDONKEYPROT,
            super::OP_ACCEPTUPLOADREQ,
            "resumed accept upload",
        )
        .await;
        resumed_stream
            .write_all(
                &super::encode_request_parts_batch(&file_hash, &[(second_start, second_end)])
                    .unwrap(),
            )
            .await
            .unwrap();

        let resumed_bytes =
            read_upload_bytes(&mut resumed_stream, &file_hash, second_start, second_end).await;
        assert_eq!(
            resumed_bytes,
            payload[usize::try_from(second_start).unwrap()..usize::try_from(second_end).unwrap()]
                .to_vec()
        );

        resumed_stream
            .write_all(&encode_packet(
                OP_EDONKEYPROT,
                super::OP_CANCELTRANSFER,
                &[],
            ))
            .await
            .unwrap();
        drop(resumed_stream);
        server.abort();
    }

    #[tokio::test]
    async fn small_file_download_resumes_partial_piece_after_reconnect() {
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

        let root = unique_test_dir("ed2k-small-file-download-resume-reconnect");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5A; 32_768];
        let split = 8_192usize;
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        let source_name = "resume-download.epub";
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                source_name.to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let payload_for_server = payload.clone();
        let server = tokio::spawn(async move {
            let peer_public_key = Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            );

            let (mut first_stream, _) = listener.accept().await.unwrap();
            let _hello = read_packet(&mut first_stream).await;
            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            first_stream.write_all(&hello_answer).await.unwrap();

            let _secure_ident_probe = read_packet(&mut first_stream).await;
            first_stream
                .write_all(&encode_secident_state(
                    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                    0x4436_EEAC,
                ))
                .await
                .unwrap();

            let _public_key = read_packet(&mut first_stream).await;
            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key.public_key_payload().unwrap(),
            );
            first_stream
                .write_all(&peer_public_key_packet)
                .await
                .unwrap();

            let _signature = read_packet(&mut first_stream).await;
            first_stream
                .write_all(&encode_packet(
                    OP_EMULEPROT,
                    super::OP_SIGNATURE,
                    &[0xAA; 49],
                ))
                .await
                .unwrap();

            let startup_request = read_packet(&mut first_stream).await;
            assert_startup_multipacket_ext2(
                startup_request[0],
                startup_request[5],
                &startup_request[6..],
                &file_hash,
                payload_for_server.len() as u64,
                false,
            );
            let filename_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                payload_for_server.len() as u64,
                source_name,
                false,
            );
            first_stream.write_all(&filename_answer).await.unwrap();

            let _start_upload = read_packet(&mut first_stream).await;
            first_stream
                .write_all(&encode_accept_upload_req())
                .await
                .unwrap();

            let first_request_parts = read_packet(&mut first_stream).await;
            assert_eq!(first_request_parts[5], super::OP_REQUESTPARTS);
            let (requested_hash, first_ranges) =
                decode_request_parts_payload(&first_request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(first_ranges, vec![(0, payload_for_server.len() as u64)]);

            let first_fragment = encode_sending_part(
                &file_hash,
                0,
                split as u64,
                &payload_for_server[..split],
                false,
            )
            .unwrap();
            first_stream.write_all(&first_fragment).await.unwrap();
            drop(first_stream);

            let (mut resumed_stream, _) = listener.accept().await.unwrap();
            let _hello = read_packet(&mut resumed_stream).await;
            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            resumed_stream.write_all(&hello_answer).await.unwrap();

            let _secure_ident_probe = read_packet(&mut resumed_stream).await;
            resumed_stream
                .write_all(&encode_secident_state(
                    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                    0x4436_EEAC,
                ))
                .await
                .unwrap();

            let _public_key = read_packet(&mut resumed_stream).await;
            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key.public_key_payload().unwrap(),
            );
            resumed_stream
                .write_all(&peer_public_key_packet)
                .await
                .unwrap();

            let _signature = read_packet(&mut resumed_stream).await;
            resumed_stream
                .write_all(&encode_packet(
                    OP_EMULEPROT,
                    super::OP_SIGNATURE,
                    &[0xAA; 49],
                ))
                .await
                .unwrap();

            let startup_request = read_packet(&mut resumed_stream).await;
            assert_startup_multipacket_ext2(
                startup_request[0],
                startup_request[5],
                &startup_request[6..],
                &file_hash,
                payload_for_server.len() as u64,
                false,
            );
            let filename_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                payload_for_server.len() as u64,
                source_name,
                false,
            );
            resumed_stream.write_all(&filename_answer).await.unwrap();

            let _start_upload = read_packet(&mut resumed_stream).await;
            resumed_stream
                .write_all(&encode_accept_upload_req())
                .await
                .unwrap();

            let resumed_request_parts = read_packet(&mut resumed_stream).await;
            assert_eq!(resumed_request_parts[5], super::OP_REQUESTPARTS);
            let (requested_hash, resumed_ranges) =
                decode_request_parts_payload(&resumed_request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(
                resumed_ranges,
                vec![(split as u64, payload_for_server.len() as u64)]
            );

            let resumed_fragment = encode_sending_part(
                &file_hash,
                split as u64,
                payload_for_server.len() as u64,
                &payload_for_server[split..],
                false,
            )
            .unwrap();
            resumed_stream.write_all(&resumed_fragment).await.unwrap();
        });

        let source = Ed2kFoundSource {
            file_hash,
            ip: Ipv4Addr::LOCALHOST,
            tcp_port: peer_addr.port(),
            client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
        };
        let secure_ident = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let hello_identity = Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        };

        let first_result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &source,
            hello_identity,
            &secure_ident,
            &transfer_runtime,
            source_name.to_string(),
            payload.len() as u64,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert_eq!(first_result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);

        let partial_manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(!partial_manifest.completed);
        assert_eq!(
            partial_manifest.pieces[0].state,
            crate::ed2k_transfer::Ed2kTransferState::Missing
        );
        assert_eq!(partial_manifest.pieces[0].bytes_written, split as u64);

        let resumed_result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &source,
            hello_identity,
            &secure_ident,
            &transfer_runtime,
            source_name.to_string(),
            payload.len() as u64,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert_eq!(resumed_result, Ed2kPeerDownloadOutcome::Completed);

        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(manifest.completed);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn small_file_download_ignores_malformed_range_and_releases_pending_piece() {
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

        let root = unique_test_dir("ed2k-small-file-malformed-range");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5A; 32_768];
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "captured.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let payload_for_server = payload.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let _hello = read_packet(&mut stream).await;
            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&hello_answer).await.unwrap();

            let _secure_ident_probe = read_packet(&mut stream).await;
            stream
                .write_all(&encode_secident_state(
                    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                    0x4436_EEAC,
                ))
                .await
                .unwrap();

            let _public_key = read_packet(&mut stream).await;
            let peer_public_key = Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            );
            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key.public_key_payload().unwrap(),
            );
            stream.write_all(&peer_public_key_packet).await.unwrap();

            let _signature = read_packet(&mut stream).await;
            stream
                .write_all(&encode_packet(
                    OP_EMULEPROT,
                    super::OP_SIGNATURE,
                    &[0xAA; 49],
                ))
                .await
                .unwrap();
            let startup_request = read_packet(&mut stream).await;
            assert_startup_multipacket_ext2(
                startup_request[0],
                startup_request[5],
                &startup_request[6..],
                &file_hash,
                payload_for_server.len() as u64,
                false,
            );
            let filename_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                payload_for_server.len() as u64,
                "captured.epub",
                false,
            );
            stream.write_all(&filename_answer).await.unwrap();
            let _start_upload = read_packet(&mut stream).await;
            stream.write_all(&encode_accept_upload_req()).await.unwrap();

            let request_parts = read_packet(&mut stream).await;
            assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
            let sending_part = encode_sending_part(
                &file_hash,
                1,
                payload_for_server.len() as u64 + 1,
                &payload_for_server,
                false,
            )
            .unwrap();
            stream.write_all(&sending_part).await.unwrap();
        });

        let result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_addr.port(),
                client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            },
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            &Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            &transfer_runtime,
            "captured.epub".to_string(),
            payload.len() as u64,
            Duration::from_secs(3),
        )
        .await;

        assert_eq!(
            result.unwrap(),
            Ed2kPeerDownloadOutcome::AcceptedButIncomplete
        );
        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(!manifest.completed);
        assert_eq!(
            manifest.pieces[0].state,
            crate::ed2k_transfer::Ed2kTransferState::Missing
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn small_file_download_releases_piece_after_out_of_order_multi_range_response() {
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

        let root = unique_test_dir("ed2k-small-file-out-of-order-window");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x5A; (super::ED2K_EMBLOCK_SIZE as usize) * 4];
        let first_end = super::ED2K_EMBLOCK_SIZE;
        let second_end = super::ED2K_EMBLOCK_SIZE * 2;
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "window.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let payload_for_server = payload.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let _hello = read_packet(&mut stream).await;
            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&hello_answer).await.unwrap();

            let _secure_ident_probe = read_packet(&mut stream).await;
            stream
                .write_all(&encode_secident_state(
                    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                    0x4436_EEAC,
                ))
                .await
                .unwrap();

            let _public_key = read_packet(&mut stream).await;
            let peer_public_key = Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            );
            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key.public_key_payload().unwrap(),
            );
            stream.write_all(&peer_public_key_packet).await.unwrap();

            let _signature = read_packet(&mut stream).await;
            stream
                .write_all(&encode_packet(
                    OP_EMULEPROT,
                    super::OP_SIGNATURE,
                    &[0xAA; 49],
                ))
                .await
                .unwrap();

            let startup_request = read_packet(&mut stream).await;
            assert_startup_multipacket_ext2(
                startup_request[0],
                startup_request[5],
                &startup_request[6..],
                &file_hash,
                payload_for_server.len() as u64,
                false,
            );
            let filename_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                payload_for_server.len() as u64,
                "window.epub",
                false,
            );
            stream.write_all(&filename_answer).await.unwrap();

            let _start_upload = read_packet(&mut stream).await;
            stream.write_all(&encode_accept_upload_req()).await.unwrap();

            let first_request_parts = read_packet(&mut stream).await;
            let (requested_hash, first_ranges) =
                decode_request_parts_payload(&first_request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(first_ranges, vec![(0, first_end)]);
            let first_fragment = encode_sending_part(
                &file_hash,
                0,
                first_end,
                &payload_for_server[..usize::try_from(first_end).unwrap()],
                false,
            )
            .unwrap();
            stream.write_all(&first_fragment).await.unwrap();

            let second_request_parts = read_packet(&mut stream).await;
            let (requested_hash, second_ranges) =
                decode_request_parts_payload(&second_request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(second_ranges, vec![(first_end, second_end)]);
            let second_fragment = encode_sending_part(
                &file_hash,
                first_end,
                second_end,
                &payload_for_server
                    [usize::try_from(first_end).unwrap()..usize::try_from(second_end).unwrap()],
                false,
            )
            .unwrap();
            stream.write_all(&second_fragment).await.unwrap();

            let third_request_parts = read_packet(&mut stream).await;
            let (requested_hash, third_ranges) =
                decode_request_parts_payload(&third_request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(
                third_ranges,
                vec![
                    (second_end, second_end + super::ED2K_EMBLOCK_SIZE),
                    (
                        second_end + super::ED2K_EMBLOCK_SIZE,
                        payload_for_server.len() as u64,
                    ),
                ]
            );

            let (late_start, late_end) = third_ranges[1];
            let late_fragment = encode_sending_part(
                &file_hash,
                late_start,
                late_end,
                &payload_for_server
                    [usize::try_from(late_start).unwrap()..usize::try_from(late_end).unwrap()],
                false,
            )
            .unwrap();
            stream.write_all(&late_fragment).await.unwrap();
        });

        let result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_addr.port(),
                client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            },
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            &Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            &transfer_runtime,
            "window.epub".to_string(),
            payload.len() as u64,
            Duration::from_secs(3),
        )
        .await
        .unwrap();

        assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(!manifest.completed);
        assert_eq!(
            manifest.pieces[0].state,
            crate::ed2k_transfer::Ed2kTransferState::Missing
        );
        assert_eq!(manifest.pieces[0].bytes_written, second_end);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn small_file_download_completes_after_out_of_order_multi_range_response() {
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

        let root = unique_test_dir("ed2k-small-file-out-of-order-window-complete");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x6C; (super::ED2K_EMBLOCK_SIZE as usize) * 4];
        let first_end = super::ED2K_EMBLOCK_SIZE;
        let second_end = super::ED2K_EMBLOCK_SIZE * 2;
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "window-complete.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let payload_for_server = payload.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let _hello = read_packet(&mut stream).await;
            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&hello_answer).await.unwrap();

            let _secure_ident_probe = read_packet(&mut stream).await;
            stream
                .write_all(&encode_secident_state(
                    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                    0x4436_EEAC,
                ))
                .await
                .unwrap();

            let _public_key = read_packet(&mut stream).await;
            let peer_public_key = Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            );
            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key.public_key_payload().unwrap(),
            );
            stream.write_all(&peer_public_key_packet).await.unwrap();

            let _signature = read_packet(&mut stream).await;
            stream
                .write_all(&encode_packet(
                    OP_EMULEPROT,
                    super::OP_SIGNATURE,
                    &[0xAA; 49],
                ))
                .await
                .unwrap();

            let startup_request = read_packet(&mut stream).await;
            assert_startup_multipacket_ext2(
                startup_request[0],
                startup_request[5],
                &startup_request[6..],
                &file_hash,
                payload_for_server.len() as u64,
                false,
            );
            let filename_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                payload_for_server.len() as u64,
                "window-complete.epub",
                false,
            );
            stream.write_all(&filename_answer).await.unwrap();

            let _start_upload = read_packet(&mut stream).await;
            stream.write_all(&encode_accept_upload_req()).await.unwrap();

            let first_request_parts = read_packet(&mut stream).await;
            let (requested_hash, first_ranges) =
                decode_request_parts_payload(&first_request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(first_ranges, vec![(0, first_end)]);
            let first_fragment = encode_sending_part(
                &file_hash,
                0,
                first_end,
                &payload_for_server[..usize::try_from(first_end).unwrap()],
                false,
            )
            .unwrap();
            stream.write_all(&first_fragment).await.unwrap();

            let second_request_parts = read_packet(&mut stream).await;
            let (requested_hash, second_ranges) =
                decode_request_parts_payload(&second_request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(second_ranges, vec![(first_end, second_end)]);
            let second_fragment = encode_sending_part(
                &file_hash,
                first_end,
                second_end,
                &payload_for_server
                    [usize::try_from(first_end).unwrap()..usize::try_from(second_end).unwrap()],
                false,
            )
            .unwrap();
            stream.write_all(&second_fragment).await.unwrap();

            let third_request_parts = read_packet(&mut stream).await;
            let (requested_hash, third_ranges) =
                decode_request_parts_payload(&third_request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(
                third_ranges,
                vec![
                    (second_end, second_end + super::ED2K_EMBLOCK_SIZE),
                    (
                        second_end + super::ED2K_EMBLOCK_SIZE,
                        payload_for_server.len() as u64,
                    ),
                ]
            );

            let (early_start, early_end) = third_ranges[0];
            let (late_start, late_end) = third_ranges[1];
            let late_fragment = encode_sending_part(
                &file_hash,
                late_start,
                late_end,
                &payload_for_server
                    [usize::try_from(late_start).unwrap()..usize::try_from(late_end).unwrap()],
                false,
            )
            .unwrap();
            stream.write_all(&late_fragment).await.unwrap();

            let early_fragment = encode_sending_part(
                &file_hash,
                early_start,
                early_end,
                &payload_for_server
                    [usize::try_from(early_start).unwrap()..usize::try_from(early_end).unwrap()],
                false,
            )
            .unwrap();
            stream.write_all(&early_fragment).await.unwrap();
        });

        let result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_addr.port(),
                client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            },
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            &Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            &transfer_runtime,
            "window-complete.epub".to_string(),
            payload.len() as u64,
            Duration::from_secs(3),
        )
        .await
        .unwrap();

        assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);
        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(manifest.completed);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn small_file_download_completes_after_out_of_order_multi_range_compressed_response() {
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

        let root = unique_test_dir("ed2k-small-file-out-of-order-window-compressed");
        let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = vec![0x37; (super::ED2K_EMBLOCK_SIZE as usize) * 4];
        let first_end = super::ED2K_EMBLOCK_SIZE;
        let second_end = super::ED2K_EMBLOCK_SIZE * 2;
        let file_hash = overlord_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
        let file_hash_hex = file_hash.to_string();
        transfer_runtime
            .ensure_job(&new_transfer_job(
                file_hash,
                "window-complete-compressed.epub".to_string(),
                payload.len() as u64,
            ))
            .await
            .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let payload_for_server = payload.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let _hello = read_packet(&mut stream).await;
            let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
                client_id: 0x5912_0559,
                tcp_port: peer_addr.port(),
                udp_port: 0,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            });
            stream.write_all(&hello_answer).await.unwrap();

            let _secure_ident_probe = read_packet(&mut stream).await;
            stream
                .write_all(&encode_secident_state(
                    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                    0x4436_EEAC,
                ))
                .await
                .unwrap();

            let _public_key = read_packet(&mut stream).await;
            let peer_public_key = Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            );
            let peer_public_key_packet = encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key.public_key_payload().unwrap(),
            );
            stream.write_all(&peer_public_key_packet).await.unwrap();

            let _signature = read_packet(&mut stream).await;
            stream
                .write_all(&encode_packet(
                    OP_EMULEPROT,
                    super::OP_SIGNATURE,
                    &[0xAA; 49],
                ))
                .await
                .unwrap();

            let startup_request = read_packet(&mut stream).await;
            assert_startup_multipacket_ext2(
                startup_request[0],
                startup_request[5],
                &startup_request[6..],
                &file_hash,
                payload_for_server.len() as u64,
                false,
            );
            let filename_answer = encode_startup_multipacket_ext2_answer(
                &file_hash,
                payload_for_server.len() as u64,
                "window-complete-compressed.epub",
                false,
            );
            stream.write_all(&filename_answer).await.unwrap();

            let _start_upload = read_packet(&mut stream).await;
            stream.write_all(&encode_accept_upload_req()).await.unwrap();

            let first_request_parts = read_packet(&mut stream).await;
            let (requested_hash, first_ranges) =
                decode_request_parts_payload(&first_request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(first_ranges, vec![(0, first_end)]);
            let first_fragment = encode_sending_part(
                &file_hash,
                0,
                first_end,
                &payload_for_server[..usize::try_from(first_end).unwrap()],
                false,
            )
            .unwrap();
            stream.write_all(&first_fragment).await.unwrap();

            let second_request_parts = read_packet(&mut stream).await;
            let (requested_hash, second_ranges) =
                decode_request_parts_payload(&second_request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(second_ranges, vec![(first_end, second_end)]);
            let second_fragment = encode_sending_part(
                &file_hash,
                first_end,
                second_end,
                &payload_for_server
                    [usize::try_from(first_end).unwrap()..usize::try_from(second_end).unwrap()],
                false,
            )
            .unwrap();
            stream.write_all(&second_fragment).await.unwrap();

            let third_request_parts = read_packet(&mut stream).await;
            let (requested_hash, third_ranges) =
                decode_request_parts_payload(&third_request_parts[6..], false).unwrap();
            assert_eq!(requested_hash, file_hash);
            assert_eq!(
                third_ranges,
                vec![
                    (second_end, second_end + super::ED2K_EMBLOCK_SIZE),
                    (
                        second_end + super::ED2K_EMBLOCK_SIZE,
                        payload_for_server.len() as u64,
                    ),
                ]
            );

            let (early_start, early_end) = third_ranges[0];
            let (late_start, late_end) = third_ranges[1];

            let mut late_encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            late_encoder
                .write_all(
                    &payload_for_server
                        [usize::try_from(late_start).unwrap()..usize::try_from(late_end).unwrap()],
                )
                .unwrap();
            let late_compressed = late_encoder.finish().unwrap();
            let late_fragment = super::encode_compressed_part_fragment(
                &file_hash,
                late_start,
                late_compressed.len(),
                &late_compressed,
                false,
            )
            .unwrap();
            stream.write_all(&late_fragment).await.unwrap();

            let mut early_encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            early_encoder
                .write_all(
                    &payload_for_server[usize::try_from(early_start).unwrap()
                        ..usize::try_from(early_end).unwrap()],
                )
                .unwrap();
            let early_compressed = early_encoder.finish().unwrap();
            let early_fragment = super::encode_compressed_part_fragment(
                &file_hash,
                early_start,
                early_compressed.len(),
                &early_compressed,
                false,
            )
            .unwrap();
            stream.write_all(&early_fragment).await.unwrap();
        });

        let result = download_file_from_peer(
            Ipv4Addr::LOCALHOST,
            &Ed2kFoundSource {
                file_hash,
                ip: Ipv4Addr::LOCALHOST,
                tcp_port: peer_addr.port(),
                client_id: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                low_id: false,
                obfuscated: false,
                obfuscation_options: None,
                user_hash: None,
                source_server: None,
            },
            Ed2kHelloIdentity {
                user_hash: [0x11; 16],
                client_id: 0,
                tcp_port: 41001,
                udp_port: 41000,
                server_ip: 0,
                server_port: 0,
                connect_options: emule_connect_options(false),
                direct_udp_callback: false,
            },
            &Arc::new(
                Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                    .unwrap(),
            ),
            &transfer_runtime,
            "window-complete-compressed.epub".to_string(),
            payload.len() as u64,
            Duration::from_secs(3),
        )
        .await
        .unwrap();

        assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);
        let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
        assert!(manifest.completed);
        server.await.unwrap();
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
