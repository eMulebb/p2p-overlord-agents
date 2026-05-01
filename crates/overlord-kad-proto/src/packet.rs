//! Kad2 packet codecs and typed wire layouts.
//!
//! Several Kad packets reuse 16-byte fields for different logical identities.
//! Field names in this module therefore document the oracle meaning of each
//! slot, not just the raw byte width.

use binrw::{BinRead, BinReaderExt, BinWrite, BinWriterExt, binrw};
use std::io::{Cursor, Read, Write};

use crate::constants::{OP_KADEMLIAHEADER, OP_KADEMLIAPACKEDPROT, opcode};
use crate::error::ProtoError;
use crate::hash::Ed2kHash;
use crate::node_id::NodeId;
use crate::tag::{StringDecodeMode, Tag};

// ── ContactEntry ──────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct ContactEntry {
    pub node_id: NodeId,
    /// IPv4 as little-endian u32 (eMule host byte order)
    pub ip: u32,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub version: u8,
}

impl ContactEntry {
    #[must_use]
    pub fn ip_addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(self.ip.to_be_bytes())
    }
}

// ── BootstrapReq ─────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct BootstrapReq;

// ── BootstrapRes ─────────────────────────────────────────────────────────────

/// Real on-wire format (from eMule source
/// `CKademliaUDPListener::ProcessBootstrapRequest`):
///   `sender_id` (`NodeId`, 16 bytes)
///   `tcp_port` (`u16`, 2 bytes)
///   `version` (`u8`, 1 byte)
///   `count` (`u16`, 2 bytes)
///   `contacts` (`count × 25` bytes each)
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct BootstrapRes {
    pub sender_id: NodeId,
    pub sender_tcp_port: u16,
    pub sender_version: u8,
    #[br(temp)]
    #[bw(calc = u16::try_from(contacts.len()).expect("contact count exceeds u16"))]
    count: u16,
    #[br(count = count)]
    pub contacts: Vec<ContactEntry>,
}

// ── HelloReq ─────────────────────────────────────────────────────────────────

/// Real on-wire format (from eMule source `CKademliaUDPListener::SendMyDetails`):
///   `node_id` (`NodeId`, 16 bytes)
///   `tcp_port` (`u16`, 2 bytes)
///   `version` (`u8`, 1 byte)
///   `tag_count` (`u8`, 1 byte)
///   `tags` (`tag_count × variable`)
///
/// Kad2 HELLO packets do not carry an explicit TCP IP nor a UDP verify key in
/// the payload. The sender verify key is recovered from the Kad UDP
/// obfuscation trailer instead.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct HelloReq {
    pub node_id: NodeId,
    pub tcp_port: u16,
    pub version: u8,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── HelloRes ─────────────────────────────────────────────────────────────────

/// Real on-wire format matches [`HelloReq`].
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct HelloRes {
    pub node_id: NodeId,
    pub tcp_port: u16,
    pub version: u8,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── HelloResAck ──────────────────────────────────────────────────────────────

/// Kad hello acknowledgment payload used by the three-way hello handshake.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct HelloResAck {
    /// Node ID that confirms the ACK sender's identity.
    pub node_id: NodeId,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    /// Reserved tag list. eMule currently sends an empty list here.
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── Req ──────────────────────────────────────────────────────────────────────
//
// eMule wire format (KADEMLIA2_REQ):
//   count_to_return: u8   — KADEMLIA_FIND_VALUE(2), KADEMLIA_FIND_NODE(0x0B), KADEMLIA_STORE(4)
//   target:          NodeId (16 bytes)
//   recipient_id:    NodeId (16 bytes) — the ID we believe the recipient has (sanity check)

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct Req {
    /// How many closest contacts to return (`KADEMLIA_FIND_VALUE/FIND_NODE/STORE`).
    pub count: u8,
    pub target: NodeId,
    /// The `NodeId` we believe the recipient has. Recipient drops packet if mismatch.
    pub recipient_id: NodeId,
}

// ── Res ──────────────────────────────────────────────────────────────────────

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct Res {
    pub target: NodeId,
    #[br(temp)]
    #[bw(calc = u8::try_from(contacts.len()).expect("contact count exceeds u8"))]
    count: u8,
    #[br(count = count)]
    pub contacts: Vec<ContactEntry>,
}

// ── SearchKeyReq ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchKeyReq {
    pub target: NodeId,
    pub start_position: u16,
    /// Raw trailing bytes preserved for restrictive keyword searches.
    ///
    /// eMule/aMule append the serialized search expression tree here when the
    /// high bit of `start_position` is set. We keep the payload opaque so the
    /// runtime can harvest and replay the exact wire shape without attempting
    /// to parse it yet.
    pub restrictive_payload: Vec<u8>,
}

// ── SearchSourceReq ──────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct SearchSourceReq {
    pub target: NodeId,
    /// Legacy source-page offset that still remains on the classic eMule wire.
    ///
    /// The oracle expects `KADEMLIA2_SEARCH_SOURCE_REQ` to carry this `u16`
    /// field immediately before the 64-bit file size.
    pub start_position: u16,
    pub size: u64,
}

// ── SearchNotesReq ───────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct SearchNotesReq {
    pub target: NodeId,
    pub size: u64,
}

// ── SearchResultEntry ────────────────────────────────────────────────────────
//
// eMule CEntry::WriteTagListInc writes: [tag_count:u8][tags...]
// So each result in SearchRes is: [entry_id:16][tag_count:u8][tags...]

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResultEntry {
    /// Generic per-entry identity from the oracle `SEARCH_RES` layout.
    ///
    /// Keyword results carry the file hash here. Source results carry the
    /// source/client identity. Notes results carry the note author/source
    /// identity.
    pub entry_id: Ed2kHash,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── SearchRes ────────────────────────────────────────────────────────────────
//
// eMule Indexed.cpp SendValidKeywordResult wire format:
//   sender_id: NodeId (16 bytes) — the responder's Kad ID
//   target:    NodeId (16 bytes) — echoed request target
//   count:     u16               — number of results in this packet
//   count × SearchResultEntry

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct SearchRes {
    /// The Kad ID of the node sending this response.
    pub sender_id: NodeId,
    /// Echoed search target from the request.
    ///
    /// Keyword searches echo the keyword hash here, while source and notes
    /// searches echo the searched file hash in the same 16-byte slot.
    pub target: NodeId,
    #[br(temp)]
    #[bw(calc = u16::try_from(results.len()).expect("result count exceeds u16"))]
    count: u16,
    #[br(count = count)]
    pub results: Vec<SearchResultEntry>,
}

// ── PublishEntry ─────────────────────────────────────────────────────────────

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct PublishEntry {
    pub hash: Ed2kHash,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── PublishKeyReq ────────────────────────────────────────────────────────────

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct PublishKeyReq {
    pub target: NodeId,
    #[br(temp)]
    #[bw(calc = u16::try_from(entries.len()).expect("entry count exceeds u16"))]
    count: u16,
    #[br(count = count)]
    pub entries: Vec<PublishEntry>,
}

// ── PublishSourceReq ─────────────────────────────────────────────────────────

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct PublishSourceReq {
    /// File-hash target being published.
    pub target: NodeId,
    /// Publisher/source identity carried in the second 16-byte slot.
    ///
    /// eMule uses a source-publish client identity here rather than another
    /// file hash. The Rust type stays `NodeId` because the wire slot is just 16
    /// opaque bytes.
    pub publisher_id: NodeId,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── PublishNotesReq ──────────────────────────────────────────────────────────

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct PublishNotesReq {
    /// File hash target of the notes publish operation.
    pub target: NodeId,
    /// Publisher Kad node identity written into the second 128-bit field.
    ///
    /// The wire width is still 16 bytes, but the semantic meaning is publisher
    /// identity rather than a note-specific hash.
    pub publisher_id: NodeId,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    /// Note payload tags such as filename, filesize, rating, and description.
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── PublishRes ───────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct PublishRes {
    pub target: NodeId,
    pub load: u8,
}

// ── PublishResAck ────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct PublishResAck;

// ── FirewalledReq ────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct FirewalledReq {
    pub tcp_port: u16,
}

// ── Firewalled2Req ───────────────────────────────────────────────────────────

/// Extended TCP firewall-check request used by Kad version 7+ peers.
#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct Firewalled2Req {
    pub tcp_port: u16,
    pub user_hash: Ed2kHash,
    pub connect_options: u8,
}

// ── FirewalledRes ────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct FirewalledRes {
    pub ip: u32,
}

// ── FirewalledAckRes ─────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct FirewalledAckRes;

// ── FirewallUdp ──────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct FirewallUdp {
    pub error_code: u8,
    pub udp_port: u16,
}

// ── FindBuddyReq / FindBuddyRes / CallbackReq ───────────────────────────────

/// Buddy-discovery request sent by a firewalled Kad node.
///
/// Oracle semantics from eMule `Search.cpp` and `KademliaUDPListener.cpp`:
/// `buddy_id` is the Kad search target used to find a relay node, while
/// `client_hash` is the requester's eD2k client hash used for later TCP
/// callback routing.
#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct FindBuddyReq {
    pub buddy_id: NodeId,
    pub client_hash: Ed2kHash,
    pub tcp_port: u16,
}

/// Buddy-discovery response returned by the selected relay candidate.
///
/// The optional `connect_options` byte is appended by newer oracle versions so
/// the requester can decide whether future buddy traffic should prefer an
/// obfuscated TCP connection.
#[derive(Debug, Clone, PartialEq)]
pub struct FindBuddyRes {
    pub buddy_id: NodeId,
    pub client_hash: Ed2kHash,
    pub tcp_port: u16,
    pub connect_options: Option<u8>,
}

/// Buddy callback request asking the relay node to initiate a TCP callback.
///
/// `buddy_id` is the buddy-search target originally used by the remote low-ID
/// client, while `file_hash` identifies the shared file that motivated the
/// callback in the common source-search flow.
#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct CallbackReq {
    pub buddy_id: NodeId,
    pub file_hash: Ed2kHash,
    pub tcp_port: u16,
}

// ── Ping / Pong ──────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct Ping;

/// Kad liveness response carrying the UDP source port observed by the responder.
///
/// eMule uses this packet not only as a reply-to-ping marker, but also as an
/// external-port hint for Kad firewall probing.
#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct Pong {
    pub udp_port: u16,
}

// ── KadPacket ────────────────────────────────────────────────────────────────

/// The top-level Kad2 packet enum.
#[derive(Debug, Clone)]
pub enum KadPacket {
    BootstrapReq,
    BootstrapRes(BootstrapRes),
    HelloReq(HelloReq),
    HelloRes(HelloRes),
    HelloResAck(HelloResAck),
    Req(Req),
    Res(Res),
    SearchKeyReq(SearchKeyReq),
    SearchSourceReq(SearchSourceReq),
    SearchNotesReq(SearchNotesReq),
    SearchRes(SearchRes),
    PublishKeyReq(PublishKeyReq),
    PublishSourceReq(PublishSourceReq),
    PublishNotesReq(PublishNotesReq),
    PublishRes(PublishRes),
    PublishResAck,
    FirewalledReq(FirewalledReq),
    Firewalled2Req(Firewalled2Req),
    FirewalledRes(FirewalledRes),
    FirewalledAckRes,
    FirewallUdp(FirewallUdp),
    FindBuddyReq(FindBuddyReq),
    FindBuddyRes(FindBuddyRes),
    CallbackReq(CallbackReq),
    Ping,
    Pong(Pong),
    // KAD1_IGNORED: Kad1 packets dropped silently. See KADKAD.md §6 Kad1 Policy.
    Unknown { opcode: u8, payload: Vec<u8> },
}

impl KadPacket {
    /// Decode a Kad2 packet from a raw buffer.
    /// Handles both plain (0xE4) and zlib-compressed (0xE5) packets.
    ///
    /// # Errors
    ///
    /// Returns [`ProtoError`] when the buffer is too short, the protocol header
    /// is invalid, decompression fails, or the packet body cannot be decoded.
    pub fn decode(buf: &[u8]) -> Result<KadPacket, ProtoError> {
        if buf.len() < 2 {
            return Err(ProtoError::BufferTooShort);
        }

        // 0xE5 = OP_KADEMLIAPACKEDPROT: zlib-compressed body, same opcode byte.
        let (op, body_cow): (u8, std::borrow::Cow<[u8]>) = if buf[0] == OP_KADEMLIAPACKEDPROT {
            use flate2::read::ZlibDecoder;
            use std::io::Read;
            let mut decoder = ZlibDecoder::new(&buf[2..]);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|_| ProtoError::DecompressError)?;
            (buf[1], std::borrow::Cow::Owned(decompressed))
        } else if buf[0] == OP_KADEMLIAHEADER {
            (buf[1], std::borrow::Cow::Borrowed(&buf[2..]))
        } else {
            return Err(ProtoError::InvalidProtocol(buf[0]));
        };

        let body: &[u8] = &body_cow;
        let mut cursor = Cursor::new(body);

        let packet = match op {
            opcode::BOOTSTRAP_REQ => KadPacket::BootstrapReq,
            opcode::BOOTSTRAP_RES => {
                let p = cursor.read_le::<BootstrapRes>()?;
                KadPacket::BootstrapRes(p)
            }
            opcode::HELLO_REQ => {
                let p = cursor.read_le::<HelloReq>()?;
                KadPacket::HelloReq(p)
            }
            opcode::HELLO_RES => {
                let p = cursor.read_le::<HelloRes>()?;
                KadPacket::HelloRes(p)
            }
            opcode::HELLO_RES_ACK => {
                let p = cursor.read_le::<HelloResAck>()?;
                KadPacket::HelloResAck(p)
            }
            opcode::REQ => {
                let p = cursor.read_le::<Req>()?;
                KadPacket::Req(p)
            }
            opcode::RES => {
                let p = cursor.read_le::<Res>()?;
                KadPacket::Res(p)
            }
            opcode::SEARCH_KEY_REQ => {
                let p = read_search_key_req(&mut cursor)?;
                KadPacket::SearchKeyReq(p)
            }
            opcode::SEARCH_SOURCE_REQ => {
                let p = read_search_source_req(&mut cursor)?;
                KadPacket::SearchSourceReq(p)
            }
            opcode::SEARCH_NOTES_REQ => {
                let p = cursor.read_le::<SearchNotesReq>()?;
                KadPacket::SearchNotesReq(p)
            }
            opcode::SEARCH_RES => {
                let p = read_search_res(&mut cursor)?;
                KadPacket::SearchRes(p)
            }
            opcode::PUBLISH_KEY_REQ => {
                let p = cursor.read_le::<PublishKeyReq>()?;
                KadPacket::PublishKeyReq(p)
            }
            opcode::PUBLISH_SOURCE_REQ => {
                let p = cursor.read_le::<PublishSourceReq>()?;
                KadPacket::PublishSourceReq(p)
            }
            opcode::PUBLISH_NOTES_REQ => {
                let p = cursor.read_le::<PublishNotesReq>()?;
                KadPacket::PublishNotesReq(p)
            }
            opcode::PUBLISH_RES => {
                let p = cursor.read_le::<PublishRes>()?;
                KadPacket::PublishRes(p)
            }
            opcode::PUBLISH_RES_ACK => KadPacket::PublishResAck,
            opcode::FIREWALLED_REQ => {
                let p = cursor.read_le::<FirewalledReq>()?;
                KadPacket::FirewalledReq(p)
            }
            opcode::FIREWALLED2_REQ => {
                let p = cursor.read_le::<Firewalled2Req>()?;
                KadPacket::Firewalled2Req(p)
            }
            opcode::FIREWALLED_RES => {
                let p = cursor.read_le::<FirewalledRes>()?;
                KadPacket::FirewalledRes(p)
            }
            opcode::FIREWALLED_ACK_RES => KadPacket::FirewalledAckRes,
            opcode::FIREWALLUDP => {
                let p = cursor.read_le::<FirewallUdp>()?;
                KadPacket::FirewallUdp(p)
            }
            opcode::FINDBUDDY_REQ => {
                let p = cursor.read_le::<FindBuddyReq>()?;
                KadPacket::FindBuddyReq(p)
            }
            opcode::FINDBUDDY_RES => {
                let p = read_find_buddy_res(&mut cursor)?;
                KadPacket::FindBuddyRes(p)
            }
            opcode::CALLBACK_REQ => {
                let p = cursor.read_le::<CallbackReq>()?;
                KadPacket::CallbackReq(p)
            }
            opcode::PING => KadPacket::Ping,
            opcode::PONG => {
                let p = cursor.read_le::<Pong>()?;
                KadPacket::Pong(p)
            }
            other => KadPacket::Unknown {
                opcode: other,
                payload: body.to_vec(),
            },
        };

        Ok(packet)
    }

    /// Encode a `KadPacket` to a byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ProtoError`] when writing the packet body fails.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let mut buf = Cursor::new(Vec::new());
        buf.write_le(&OP_KADEMLIAHEADER)?;
        let op = self.opcode();
        buf.write_le(&op)?;

        match self {
            KadPacket::BootstrapRes(p) => buf.write_le(p)?,
            KadPacket::HelloReq(p) => buf.write_le(p)?,
            KadPacket::HelloRes(p) => buf.write_le(p)?,
            KadPacket::HelloResAck(p) => buf.write_le(p)?,
            KadPacket::Req(p) => buf.write_le(p)?,
            KadPacket::Res(p) => buf.write_le(p)?,
            KadPacket::SearchKeyReq(p) => write_search_key_req(&mut buf, p)?,
            KadPacket::SearchSourceReq(p) => write_search_source_req(&mut buf, p)?,
            KadPacket::SearchNotesReq(p) => buf.write_le(p)?,
            KadPacket::SearchRes(p) => write_search_res(&mut buf, p)?,
            KadPacket::PublishKeyReq(p) => buf.write_le(p)?,
            KadPacket::PublishSourceReq(p) => buf.write_le(p)?,
            KadPacket::PublishNotesReq(p) => buf.write_le(p)?,
            KadPacket::PublishRes(p) => buf.write_le(p)?,
            KadPacket::FirewalledReq(p) => buf.write_le(p)?,
            KadPacket::Firewalled2Req(p) => buf.write_le(p)?,
            KadPacket::FirewalledRes(p) => buf.write_le(p)?,
            KadPacket::FirewallUdp(p) => buf.write_le(p)?,
            KadPacket::FindBuddyReq(p) => buf.write_le(p)?,
            KadPacket::FindBuddyRes(p) => write_find_buddy_res(&mut buf, p)?,
            KadPacket::CallbackReq(p) => buf.write_le(p)?,
            KadPacket::Pong(p) => buf.write_le(p)?,
            KadPacket::BootstrapReq
            | KadPacket::PublishResAck
            | KadPacket::FirewalledAckRes
            | KadPacket::Ping => {}
            KadPacket::Unknown { payload, .. } => {
                buf.write_all(payload).map_err(ProtoError::Io)?;
            }
        }

        Ok(buf.into_inner())
    }

    /// Returns the opcode byte for this packet.
    #[must_use]
    pub fn opcode(&self) -> u8 {
        match self {
            KadPacket::BootstrapReq => opcode::BOOTSTRAP_REQ,
            KadPacket::BootstrapRes(_) => opcode::BOOTSTRAP_RES,
            KadPacket::HelloReq(_) => opcode::HELLO_REQ,
            KadPacket::HelloRes(_) => opcode::HELLO_RES,
            KadPacket::HelloResAck(_) => opcode::HELLO_RES_ACK,
            KadPacket::Req(_) => opcode::REQ,
            KadPacket::Res(_) => opcode::RES,
            KadPacket::SearchKeyReq(_) => opcode::SEARCH_KEY_REQ,
            KadPacket::SearchSourceReq(_) => opcode::SEARCH_SOURCE_REQ,
            KadPacket::SearchNotesReq(_) => opcode::SEARCH_NOTES_REQ,
            KadPacket::SearchRes(_) => opcode::SEARCH_RES,
            KadPacket::PublishKeyReq(_) => opcode::PUBLISH_KEY_REQ,
            KadPacket::PublishSourceReq(_) => opcode::PUBLISH_SOURCE_REQ,
            KadPacket::PublishNotesReq(_) => opcode::PUBLISH_NOTES_REQ,
            KadPacket::PublishRes(_) => opcode::PUBLISH_RES,
            KadPacket::PublishResAck => opcode::PUBLISH_RES_ACK,
            KadPacket::FirewalledReq(_) => opcode::FIREWALLED_REQ,
            KadPacket::Firewalled2Req(_) => opcode::FIREWALLED2_REQ,
            KadPacket::FirewalledRes(_) => opcode::FIREWALLED_RES,
            KadPacket::FirewalledAckRes => opcode::FIREWALLED_ACK_RES,
            KadPacket::FirewallUdp(_) => opcode::FIREWALLUDP,
            KadPacket::FindBuddyReq(_) => opcode::FINDBUDDY_REQ,
            KadPacket::FindBuddyRes(_) => opcode::FINDBUDDY_RES,
            KadPacket::CallbackReq(_) => opcode::CALLBACK_REQ,
            KadPacket::Ping => opcode::PING,
            KadPacket::Pong(_) => opcode::PONG,
            KadPacket::Unknown { opcode, .. } => *opcode,
        }
    }
}

fn read_kad_search_entry_id(cursor: &mut Cursor<&[u8]>) -> Result<Ed2kHash, ProtoError> {
    let entry_id = cursor.read_le::<NodeId>()?;
    Ok(Ed2kHash::from_bytes(entry_id.to_be_bytes()))
}

fn write_kad_search_entry_id(
    cursor: &mut Cursor<Vec<u8>>,
    entry_id: &Ed2kHash,
) -> Result<(), ProtoError> {
    cursor.write_le(&NodeId::from_be_bytes(entry_id.0))?;
    Ok(())
}

fn read_search_res(cursor: &mut Cursor<&[u8]>) -> Result<SearchRes, ProtoError> {
    // SEARCH_RES is the one Kad path where eMule/aMule allow non-UTF-8 strings to
    // fall back to the local ANSI code page for backward-compatible display.
    // Reference:
    // - eMule srchybrid/kademlia/net/KademliaUDPListener.cpp Process_KADEMLIA2_SEARCH_RES
    // - eMule srchybrid/kademlia/io/DataIO.cpp CDataIO::ReadStringUTF8(bool bOptACP)
    // - aMule src/kademlia/net/KademliaUDPListener.cpp ProcessSearchResponse
    let sender_id = cursor.read_le::<NodeId>()?;
    let target = cursor.read_le::<NodeId>()?;
    let count = cursor.read_le::<u16>()?;
    let mut results = Vec::with_capacity(count as usize);

    for _ in 0..count {
        let entry_id = read_kad_search_entry_id(cursor)?;
        let tag_count = cursor.read_le::<u8>()?;
        let mut tags = Vec::with_capacity(tag_count as usize);
        for _ in 0..tag_count {
            tags.push(Tag::read_with_mode(
                cursor,
                binrw::Endian::Little,
                StringDecodeMode::SearchResult,
            )?);
        }
        results.push(SearchResultEntry { entry_id, tags });
    }

    Ok(SearchRes {
        sender_id,
        target,
        results,
    })
}

fn write_search_res(cursor: &mut Cursor<Vec<u8>>, packet: &SearchRes) -> Result<(), ProtoError> {
    cursor.write_le(&packet.sender_id)?;
    cursor.write_le(&packet.target)?;
    cursor
        .write_le(&u16::try_from(packet.results.len()).expect("search result count exceeds u16"))?;
    for result in &packet.results {
        write_kad_search_entry_id(cursor, &result.entry_id)?;
        cursor.write_le(&u8::try_from(result.tags.len()).expect("tag count exceeds u8"))?;
        for tag in &result.tags {
            cursor.write_le(tag)?;
        }
    }
    Ok(())
}

fn read_find_buddy_res(cursor: &mut Cursor<&[u8]>) -> Result<FindBuddyRes, ProtoError> {
    let buddy_id = cursor.read_le::<NodeId>()?;
    let client_hash = cursor.read_le::<Ed2kHash>()?;
    let tcp_port = cursor.read_le::<u16>()?;
    let connect_options = if cursor.position() < cursor.get_ref().len() as u64 {
        Some(cursor.read_le::<u8>()?)
    } else {
        None
    };

    Ok(FindBuddyRes {
        buddy_id,
        client_hash,
        tcp_port,
        connect_options,
    })
}

fn write_find_buddy_res(
    cursor: &mut Cursor<Vec<u8>>,
    packet: &FindBuddyRes,
) -> Result<(), ProtoError> {
    cursor.write_le(&packet.buddy_id)?;
    cursor.write_le(&packet.client_hash)?;
    cursor.write_le(&packet.tcp_port)?;
    if let Some(connect_options) = packet.connect_options {
        cursor.write_le(&connect_options)?;
    }
    Ok(())
}

fn read_search_key_req(cursor: &mut Cursor<&[u8]>) -> Result<SearchKeyReq, ProtoError> {
    let target = cursor.read_le::<NodeId>()?;
    let start_position = cursor.read_le::<u16>()?;
    let mut restrictive_payload = Vec::new();
    cursor
        .read_to_end(&mut restrictive_payload)
        .map_err(ProtoError::Io)?;
    Ok(SearchKeyReq {
        target,
        start_position,
        restrictive_payload,
    })
}

fn write_search_key_req(
    buf: &mut Cursor<Vec<u8>>,
    packet: &SearchKeyReq,
) -> Result<(), ProtoError> {
    buf.write_le(&packet.target)?;
    buf.write_le(&packet.start_position)?;
    buf.write_all(&packet.restrictive_payload)
        .map_err(ProtoError::Io)?;
    Ok(())
}

fn read_search_source_req(cursor: &mut Cursor<&[u8]>) -> Result<SearchSourceReq, ProtoError> {
    let target = cursor.read_le::<NodeId>()?;
    let remaining = cursor
        .get_ref()
        .len()
        .saturating_sub(cursor.position() as usize);
    let size = match remaining {
        4 => u64::from(cursor.read_le::<u32>()?),
        8 => cursor.read_le::<u64>()?,
        10 => {
            let _legacy_start_position = cursor.read_le::<u16>()?;
            cursor.read_le::<u64>()?
        }
        _ => return Err(ProtoError::BufferTooShort),
    };
    Ok(SearchSourceReq {
        target,
        start_position: 0,
        size,
    })
}

fn write_search_source_req(
    buf: &mut Cursor<Vec<u8>>,
    packet: &SearchSourceReq,
) -> Result<(), ProtoError> {
    buf.write_le(&packet.target)?;
    buf.write_le(&packet.start_position)?;
    buf.write_le(&packet.size)?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
