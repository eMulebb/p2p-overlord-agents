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
// So each result in SearchRes is: [file_hash:16][tag_count:u8][tags...]

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResultEntry {
    pub hash: Ed2kHash,
    #[br(temp)]
    #[bw(calc = u8::try_from(tags.len()).expect("tag count exceeds u8"))]
    tag_count: u8,
    #[br(count = tag_count)]
    pub tags: Vec<Tag>,
}

// ── SearchRes ────────────────────────────────────────────────────────────────
//
// eMule Indexed.cpp SendValidKeywordResult wire format:
//   sender_id:  NodeId (16 bytes) — the responder's Kad ID
//   keyword_id: NodeId (16 bytes) — the keyword hash that was queried
//   count:      u16              — number of results in this packet
//   count × SearchResultEntry

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq)]
pub struct SearchRes {
    /// The Kad ID of the node sending this response.
    pub sender_id: NodeId,
    /// The keyword hash that was queried (echo of SearchKeyReq.target).
    pub keyword_id: NodeId,
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
    pub target: NodeId,
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

// ── Ping / Pong ──────────────────────────────────────────────────────────────

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct Ping;

#[derive(BinRead, BinWrite, Debug, Clone, PartialEq)]
#[brw(little)]
pub struct Pong;

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
    Ping,
    Pong,
    // KAD1_IGNORED: Kad1 packets dropped silently. See KADKAD.md §6 Kad1 Policy.
    // FUTURE(buddy): FindBuddyReq/Res and CallbackReq reserved for Phase 3.
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
                let p = cursor.read_le::<SearchSourceReq>()?;
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
            opcode::PING => KadPacket::Ping,
            opcode::PONG => KadPacket::Pong,
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
            KadPacket::SearchSourceReq(p) => buf.write_le(p)?,
            KadPacket::SearchNotesReq(p) => buf.write_le(p)?,
            KadPacket::SearchRes(p) => buf.write_le(p)?,
            KadPacket::PublishKeyReq(p) => buf.write_le(p)?,
            KadPacket::PublishSourceReq(p) => buf.write_le(p)?,
            KadPacket::PublishNotesReq(p) => buf.write_le(p)?,
            KadPacket::PublishRes(p) => buf.write_le(p)?,
            KadPacket::FirewalledReq(p) => buf.write_le(p)?,
            KadPacket::Firewalled2Req(p) => buf.write_le(p)?,
            KadPacket::FirewalledRes(p) => buf.write_le(p)?,
            KadPacket::FirewallUdp(p) => buf.write_le(p)?,
            KadPacket::BootstrapReq
            | KadPacket::PublishResAck
            | KadPacket::FirewalledAckRes
            | KadPacket::Ping
            | KadPacket::Pong => {}
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
            KadPacket::Ping => opcode::PING,
            KadPacket::Pong => opcode::PONG,
            KadPacket::Unknown { opcode, .. } => *opcode,
        }
    }
}

fn read_search_res(cursor: &mut Cursor<&[u8]>) -> Result<SearchRes, ProtoError> {
    // SEARCH_RES is the one Kad path where eMule/aMule allow non-UTF-8 strings to
    // fall back to the local ANSI code page for backward-compatible display.
    // Reference:
    // - eMule srchybrid/kademlia/net/KademliaUDPListener.cpp Process_KADEMLIA2_SEARCH_RES
    // - eMule srchybrid/kademlia/io/DataIO.cpp CDataIO::ReadStringUTF8(bool bOptACP)
    // - aMule src/kademlia/net/KademliaUDPListener.cpp ProcessSearchResponse
    let sender_id = cursor.read_le::<NodeId>()?;
    let keyword_id = cursor.read_le::<NodeId>()?;
    let count = cursor.read_le::<u16>()?;
    let mut results = Vec::with_capacity(count as usize);

    for _ in 0..count {
        let hash = cursor.read_le::<Ed2kHash>()?;
        let tag_count = cursor.read_le::<u8>()?;
        let mut tags = Vec::with_capacity(tag_count as usize);
        for _ in 0..tag_count {
            tags.push(Tag::read_with_mode(
                cursor,
                binrw::Endian::Little,
                StringDecodeMode::SearchResult,
            )?);
        }
        results.push(SearchResultEntry { hash, tags });
    }

    Ok(SearchRes {
        sender_id,
        keyword_id,
        results,
    })
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TagValue;
    use crate::tag::Tag;

    fn roundtrip(pkt: &KadPacket) -> KadPacket {
        let bytes = pkt.encode().expect("encode failed");
        KadPacket::decode(&bytes).expect("decode failed")
    }

    #[test]
    fn test_ping_roundtrip() {
        let pkt = KadPacket::Ping;
        let bytes = pkt.encode().unwrap();
        assert_eq!(bytes, vec![0xE4, 0x60]);
        let pkt2 = KadPacket::decode(&bytes).unwrap();
        assert!(matches!(pkt2, KadPacket::Ping));
    }

    #[test]
    fn test_pong_roundtrip() {
        let pkt = KadPacket::Pong;
        let pkt2 = roundtrip(&pkt);
        assert!(matches!(pkt2, KadPacket::Pong));
    }

    #[test]
    fn test_bootstrap_res_roundtrip() {
        let contacts = vec![
            ContactEntry {
                node_id: NodeId::from_bytes([1u8; 16]),
                ip: 0x0102_0304,
                udp_port: 4672,
                tcp_port: 4662,
                version: 9,
            },
            ContactEntry {
                node_id: NodeId::from_bytes([2u8; 16]),
                ip: 0x0506_0708,
                udp_port: 4673,
                tcp_port: 4663,
                version: 8,
            },
        ];
        let pkt = KadPacket::BootstrapRes(BootstrapRes {
            sender_id: NodeId::from_bytes([0xAA; 16]),
            sender_tcp_port: 4662,
            sender_version: 9,
            contacts: contacts.clone(),
        });
        let bytes = pkt.encode().unwrap();
        let pkt2 = KadPacket::decode(&bytes).unwrap();
        if let KadPacket::BootstrapRes(res) = pkt2 {
            assert_eq!(res.contacts.len(), 2);
            assert_eq!(res.contacts[0].node_id, contacts[0].node_id);
            assert_eq!(res.contacts[1].udp_port, 4673);
            assert_eq!(res.sender_version, 9);
        } else {
            panic!("wrong packet type");
        }
    }

    #[test]
    fn test_packed_packet_decode() {
        // Build a plain Ping, then zlib-compress it to simulate 0xE5 packet
        use flate2::{Compression, write::ZlibEncoder};
        use std::io::Write;

        // Body of a Ping is empty; encode as 0xE4 0x60, body = []
        // For 0xE5 format: compress just the body (buf[2..] of the plain packet)
        let plain = KadPacket::Ping.encode().unwrap();
        let body = &plain[2..]; // empty for Ping

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut packed = vec![OP_KADEMLIAPACKEDPROT, plain[1]]; // 0xE5 + opcode
        packed.extend_from_slice(&compressed);

        let decoded = KadPacket::decode(&packed).unwrap();
        assert!(matches!(decoded, KadPacket::Ping));
    }

    #[test]
    fn test_hello_req_v10_with_tags_roundtrip() {
        let pkt = KadPacket::HelloReq(HelloReq {
            node_id: NodeId::from_bytes([0xAA; 16]),
            tcp_port: 4662,
            version: 10,
            tags: vec![Tag::filename("test.txt"), Tag::filesize(12345)],
        });
        let bytes = pkt.encode().unwrap();
        let pkt2 = KadPacket::decode(&bytes).unwrap();
        if let KadPacket::HelloReq(req) = pkt2 {
            assert_eq!(req.version, 10);
            assert_eq!(req.tags.len(), 2);
        } else {
            panic!("wrong packet type");
        }
    }

    #[test]
    fn test_hello_req_v4_roundtrip_without_optional_fields() {
        let pkt = KadPacket::HelloReq(HelloReq {
            node_id: NodeId::from_bytes([0xBB; 16]),
            tcp_port: 4662,
            version: 4,
            tags: vec![],
        });
        let bytes = pkt.encode().unwrap();
        let pkt2 = KadPacket::decode(&bytes).unwrap();
        if let KadPacket::HelloReq(req) = pkt2 {
            assert_eq!(req.version, 4);
            assert!(req.tags.is_empty());
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_hello_req_wire_shape_matches_oracle_layout() {
        let node_id = NodeId::from_bytes([0xDD; 16]);
        let pkt = KadPacket::HelloReq(HelloReq {
            node_id,
            tcp_port: 4662,
            version: crate::constants::KAD_VERSION,
            tags: vec![Tag::new_short(
                crate::constants::tag_name::SOURCEUPORT,
                TagValue::U16(41000),
            )],
        });

        let bytes = pkt.encode().unwrap();

        assert_eq!(bytes[0], crate::constants::OP_KADEMLIAHEADER);
        assert_eq!(bytes[1], crate::constants::opcode::HELLO_REQ);
        assert_eq!(&bytes[2..18], &node_id.0);
        assert_eq!(u16::from_le_bytes([bytes[18], bytes[19]]), 4662);
        assert_eq!(bytes[20], crate::constants::KAD_VERSION);
        assert_eq!(bytes[21], 1);
    }

    #[test]
    fn test_hello_res_ack_roundtrip() {
        let pkt = KadPacket::HelloResAck(HelloResAck {
            node_id: NodeId::from_bytes([0xCC; 16]),
            tags: vec![Tag::new_short(
                crate::constants::tag_name::KADMISCOPTIONS,
                TagValue::U8(4),
            )],
        });
        let bytes = pkt.encode().unwrap();
        let pkt2 = KadPacket::decode(&bytes).unwrap();
        if let KadPacket::HelloResAck(ack) = pkt2 {
            assert_eq!(ack.node_id, NodeId::from_bytes([0xCC; 16]));
            assert_eq!(ack.tags.len(), 1);
        } else {
            panic!("wrong packet type");
        }
    }

    #[test]
    fn test_search_res_roundtrip() {
        let entry = SearchResultEntry {
            hash: Ed2kHash::from_bytes([0xAB; 16]),
            tags: vec![Tag::filename("ubuntu.iso"), Tag::filesize(1_000_000_000)],
        };
        let pkt = KadPacket::SearchRes(SearchRes {
            sender_id: NodeId::from_bytes([0x11; 16]),
            keyword_id: NodeId::from_bytes([0x22; 16]),
            results: vec![entry],
        });
        let bytes = pkt.encode().unwrap();
        let pkt2 = KadPacket::decode(&bytes).unwrap();
        if let KadPacket::SearchRes(res) = pkt2 {
            assert_eq!(res.results.len(), 1);
            assert_eq!(res.results[0].tags.len(), 2);
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_search_res_decodes_legacy_cp1252_strings() {
        let mut bytes = vec![OP_KADEMLIAHEADER, opcode::SEARCH_RES];
        bytes.extend_from_slice(&[0x11; 16]); // sender_id
        bytes.extend_from_slice(&[0x22; 16]); // keyword_id
        bytes.extend_from_slice(&1u16.to_le_bytes()); // result count
        bytes.extend_from_slice(&[0x33; 16]); // file hash
        bytes.push(1); // tag count
        bytes.push(0x82); // short-name string tag
        bytes.push(crate::constants::tag_name::FILENAME);
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&[b'T', 0xE9, b's', b't']); // "Tést" in cp1252

        let decoded = KadPacket::decode(&bytes).expect("decode search res");
        let KadPacket::SearchRes(search_res) = decoded else {
            panic!("wrong packet type");
        };
        assert_eq!(search_res.results.len(), 1);
        assert_eq!(search_res.results[0].tags.len(), 1);
        assert_eq!(search_res.results[0].tags[0], Tag::filename("Tést"));
    }

    #[test]
    fn test_publish_key_req_roundtrip() {
        let entry = PublishEntry {
            hash: Ed2kHash::from_bytes([0xCC; 16]),
            tags: vec![Tag::filename("myfile.mp3"), Tag::sources(3)],
        };
        let pkt = KadPacket::PublishKeyReq(PublishKeyReq {
            target: NodeId::from_bytes([0x22; 16]),
            entries: vec![entry],
        });
        let bytes = pkt.encode().unwrap();
        let pkt2 = KadPacket::decode(&bytes).unwrap();
        if let KadPacket::PublishKeyReq(req) = pkt2 {
            assert_eq!(req.entries.len(), 1);
            assert_eq!(req.entries[0].tags.len(), 2);
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_unknown_opcode_preserved() {
        let buf = vec![0xE4, 0xFE, 0x01, 0x02, 0x03];
        let pkt = KadPacket::decode(&buf).unwrap();
        if let KadPacket::Unknown { opcode, payload } = &pkt {
            assert_eq!(*opcode, 0xFE);
            assert_eq!(payload, &vec![0x01, 0x02, 0x03]);
        } else {
            panic!("expected Unknown");
        }
        // Re-encode should preserve bytes
        let encoded = pkt.encode().unwrap();
        assert_eq!(encoded, buf);
    }

    #[test]
    fn test_invalid_protocol_byte() {
        let buf = vec![0xE3, 0x60]; // wrong header
        let err = KadPacket::decode(&buf);
        assert!(matches!(err, Err(ProtoError::InvalidProtocol(0xE3))));
    }

    #[test]
    fn test_buffer_too_short() {
        let err = KadPacket::decode(&[0xE4]);
        assert!(matches!(err, Err(ProtoError::BufferTooShort)));
    }

    #[test]
    fn test_req_roundtrip() {
        use crate::constants::KADEMLIA_FIND_VALUE;
        let pkt = KadPacket::Req(Req {
            count: KADEMLIA_FIND_VALUE,
            target: NodeId::from_bytes([0x33; 16]),
            recipient_id: NodeId::from_bytes([0x44; 16]),
        });
        let pkt2 = roundtrip(&pkt);
        if let KadPacket::Req(r) = pkt2 {
            assert_eq!(r.count, KADEMLIA_FIND_VALUE);
            assert_eq!(r.target, NodeId::from_bytes([0x33; 16]));
            assert_eq!(r.recipient_id, NodeId::from_bytes([0x44; 16]));
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_firewalled_req_roundtrip() {
        let pkt = KadPacket::FirewalledReq(FirewalledReq { tcp_port: 4662 });
        let pkt2 = roundtrip(&pkt);
        if let KadPacket::FirewalledReq(f) = pkt2 {
            assert_eq!(f.tcp_port, 4662);
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_firewalled2_req_roundtrip() {
        let pkt = KadPacket::Firewalled2Req(Firewalled2Req {
            tcp_port: 4662,
            user_hash: Ed2kHash::from_bytes([0x11; 16]),
            connect_options: 0x07,
        });
        let pkt2 = roundtrip(&pkt);
        if let KadPacket::Firewalled2Req(f) = pkt2 {
            assert_eq!(f.tcp_port, 4662);
            assert_eq!(f.user_hash, Ed2kHash::from_bytes([0x11; 16]));
            assert_eq!(f.connect_options, 0x07);
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_publish_source_req_roundtrip() {
        let pkt = KadPacket::PublishSourceReq(PublishSourceReq {
            target: NodeId::from_bytes([0x44; 16]),
            publisher_id: NodeId::from_bytes([0x55; 16]),
            tags: vec![Tag::sources(10)],
        });
        let pkt2 = roundtrip(&pkt);
        if let KadPacket::PublishSourceReq(req) = pkt2 {
            assert_eq!(req.target, NodeId::from_bytes([0x44; 16]));
            assert_eq!(req.publisher_id, NodeId::from_bytes([0x55; 16]));
            assert_eq!(req.tags.len(), 1);
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_publish_source_req_uses_u8_tag_count_on_wire() {
        let pkt = KadPacket::PublishSourceReq(PublishSourceReq {
            target: NodeId::from_bytes([0x44; 16]),
            publisher_id: NodeId::from_bytes([0x55; 16]),
            tags: vec![Tag::sources(10), Tag::filesize(1234)],
        });

        let encoded = pkt.encode().unwrap();
        assert_eq!(encoded[0], OP_KADEMLIAHEADER);
        assert_eq!(encoded[1], opcode::PUBLISH_SOURCE_REQ);
        assert_eq!(encoded[34], 2, "source publish tag count must be u8");
    }

    #[test]
    fn test_publish_notes_req_roundtrip() {
        let pkt = KadPacket::PublishNotesReq(PublishNotesReq {
            target: NodeId::from_bytes([0x44; 16]),
            publisher_id: NodeId::from_bytes([0x55; 16]),
            tags: vec![
                Tag::new_short(
                    crate::constants::tag_name::FILERATING,
                    crate::tag::TagValue::U8(4),
                ),
                Tag::new_short(
                    crate::constants::tag_name::DESCRIPTION,
                    crate::tag::TagValue::String("oracle-style validation note".to_string()),
                ),
            ],
        });
        let pkt2 = roundtrip(&pkt);
        if let KadPacket::PublishNotesReq(req) = pkt2 {
            assert_eq!(req.target, NodeId::from_bytes([0x44; 16]));
            assert_eq!(req.publisher_id, NodeId::from_bytes([0x55; 16]));
            assert_eq!(req.tags.len(), 2);
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_publish_notes_req_uses_u8_tag_count_on_wire() {
        let pkt = KadPacket::PublishNotesReq(PublishNotesReq {
            target: NodeId::from_bytes([0x44; 16]),
            publisher_id: NodeId::from_bytes([0x55; 16]),
            tags: vec![
                Tag::new_short(
                    crate::constants::tag_name::FILERATING,
                    crate::tag::TagValue::U8(4),
                ),
                Tag::new_short(
                    crate::constants::tag_name::DESCRIPTION,
                    crate::tag::TagValue::String("validation".to_string()),
                ),
            ],
        });

        let encoded = pkt.encode().unwrap();
        assert_eq!(encoded[0], OP_KADEMLIAHEADER);
        assert_eq!(encoded[1], opcode::PUBLISH_NOTES_REQ);
        assert_eq!(encoded[34], 2, "notes publish tag count must be u8");
    }

    #[test]
    fn test_publish_key_req_entry_uses_u8_tag_count_on_wire() {
        let pkt = KadPacket::PublishKeyReq(PublishKeyReq {
            target: NodeId::from_bytes([0x22; 16]),
            entries: vec![PublishEntry {
                hash: Ed2kHash([0x33; 16]),
                tags: vec![Tag::filename("ubuntu linux"), Tag::sources(10)],
            }],
        });

        let encoded = pkt.encode().unwrap();
        assert_eq!(encoded[0], OP_KADEMLIAHEADER);
        assert_eq!(encoded[1], opcode::PUBLISH_KEY_REQ);
        // 2-byte Kad header + 16-byte target + 2-byte entry count + 16-byte file hash.
        assert_eq!(encoded[36], 2, "keyword publish tag count must be u8");
    }

    #[test]
    fn test_search_source_req_roundtrip() {
        let pkt = KadPacket::SearchSourceReq(SearchSourceReq {
            target: NodeId::from_bytes([0x66; 16]),
            start_position: 0,
            size: 99_999_999,
        });
        let pkt2 = roundtrip(&pkt);
        if let KadPacket::SearchSourceReq(req) = pkt2 {
            assert_eq!(req.start_position, 0);
            assert_eq!(req.size, 99_999_999);
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_search_key_req_roundtrip_plain() {
        let pkt = KadPacket::SearchKeyReq(SearchKeyReq {
            target: NodeId::from_bytes([0x22; 16]),
            start_position: 0,
            restrictive_payload: Vec::new(),
        });
        let pkt2 = roundtrip(&pkt);
        if let KadPacket::SearchKeyReq(req) = pkt2 {
            assert_eq!(req.target, NodeId::from_bytes([0x22; 16]));
            assert_eq!(req.start_position, 0);
            assert!(req.restrictive_payload.is_empty());
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_search_key_req_roundtrip_restrictive_payload() {
        let pkt = KadPacket::SearchKeyReq(SearchKeyReq {
            target: NodeId::from_bytes([0x33; 16]),
            start_position: 0x8000,
            restrictive_payload: vec![0x01, 0x02, 0xA5, 0xFF],
        });
        let pkt2 = roundtrip(&pkt);
        if let KadPacket::SearchKeyReq(req) = pkt2 {
            assert_eq!(req.target, NodeId::from_bytes([0x33; 16]));
            assert_eq!(req.start_position, 0x8000);
            assert_eq!(req.restrictive_payload, vec![0x01, 0x02, 0xA5, 0xFF]);
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_search_notes_req_roundtrip() {
        let pkt = KadPacket::SearchNotesReq(SearchNotesReq {
            target: NodeId::from_bytes([0x77; 16]),
            size: 123_456_789,
        });
        let pkt2 = roundtrip(&pkt);
        if let KadPacket::SearchNotesReq(req) = pkt2 {
            assert_eq!(req.target, NodeId::from_bytes([0x77; 16]));
            assert_eq!(req.size, 123_456_789);
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_contact_entry_ip_addr() {
        // Store as little-endian u32: 192.168.1.1 = 0xC0A80101
        // to_be_bytes() of 0xC0A80101 = [0xC0, 0xA8, 0x01, 0x01]
        let c = ContactEntry {
            node_id: NodeId::ZERO,
            ip: 0xC0A8_0101_u32,
            udp_port: 4672,
            tcp_port: 4662,
            version: 9,
        };
        assert_eq!(c.ip_addr(), std::net::Ipv4Addr::new(192, 168, 1, 1));
    }
}
