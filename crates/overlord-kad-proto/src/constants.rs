/// Protocol header byte for all Kad2 packets.
pub const OP_KADEMLIAHEADER: u8 = 0xE4;

/// Protocol header byte for zlib-compressed Kad2 packets.
pub const OP_KADEMLIAPACKEDPROT: u8 = 0xE5;

/// Our announced Kad version.
///
/// Live oracle captures from the local eMule debug build advertise `0x0A` in
/// Kad HELLO packets, matching upstream `KADEMLIA_VERSION`.
pub const KAD_VERSION: u8 = 10;

/// K — k-bucket size.
pub const K: usize = 10;

/// Alpha — parallel lookup queries.
pub const ALPHA: usize = 3;

/// KBASE — zone splitting base exponent.
pub const KBASE: usize = 4;

/// KK — peer selection parameter.
pub const KK: usize = 5;

pub const SEARCH_TIMEOUT_SECS: u64 = 45;
pub const STORE_TIMEOUT_SECS: u64 = 140;
pub const REPUBLISH_INTERVAL_SECS: u64 = 18_000;

/// Contacts to request in Req for value lookups (Keyword/Source/Notes/File).
pub const KADEMLIA_FIND_VALUE: u8 = 0x02;
/// Contacts to request in Req for node lookups.
pub const KADEMLIA_FIND_NODE: u8 = 0x0B;
/// Contacts to request in Req for store operations.
pub const KADEMLIA_STORE: u8 = 0x04;
/// Max XOR distance high-32-bits for sending search packets to a node.
pub const SEARCHTOLERANCE: u32 = 0x0100_0000;

/// Kad2 packet opcodes.
pub mod opcode {
    pub const BOOTSTRAP_REQ: u8 = 0x01;
    pub const BOOTSTRAP_RES: u8 = 0x09;
    pub const HELLO_REQ: u8 = 0x11;
    pub const HELLO_RES: u8 = 0x19;
    pub const HELLO_RES_ACK: u8 = 0x22;
    pub const REQ: u8 = 0x21;
    pub const RES: u8 = 0x29;
    pub const SEARCH_KEY_REQ: u8 = 0x33;
    pub const SEARCH_SOURCE_REQ: u8 = 0x34;
    pub const SEARCH_NOTES_REQ: u8 = 0x35;
    pub const SEARCH_RES: u8 = 0x3B;
    pub const PUBLISH_KEY_REQ: u8 = 0x43;
    pub const PUBLISH_SOURCE_REQ: u8 = 0x44;
    pub const PUBLISH_NOTES_REQ: u8 = 0x45;
    pub const PUBLISH_RES: u8 = 0x4B;
    pub const PUBLISH_RES_ACK: u8 = 0x4C;
    pub const FIREWALLED_REQ: u8 = 0x50;
    pub const FIREWALLED2_REQ: u8 = 0x53;
    pub const FIREWALLED_RES: u8 = 0x58;
    pub const FIREWALLED_ACK_RES: u8 = 0x59;
    pub const FIREWALLUDP: u8 = 0x62;
    // KAD1_IGNORED: FINDBUDDY and CALLBACK are reserved for Phase 3 (buddy system).
    // See KADKAD.md §20 Future Work.
    pub const FINDBUDDY_REQ: u8 = 0x51;
    pub const FINDBUDDY_RES: u8 = 0x5A;
    pub const CALLBACK_REQ: u8 = 0x52;
    pub const PING: u8 = 0x60;
    pub const PONG: u8 = 0x61;
}

/// Short tag name constants (1-byte eMule FT_* codes).
pub mod tag_name {
    pub const FILENAME: u8 = 0x01;
    pub const FILESIZE: u8 = 0x02;
    pub const FILETYPE: u8 = 0x03;
    pub const FILEFORMAT: u8 = 0x04;
    pub const DESCRIPTION: u8 = 0x0B;
    pub const SOURCES: u8 = 0x15;
    pub const FILESIZE_HI: u8 = 0x3A;
    pub const MEDIA_ARTIST: u8 = 0xD0;
    pub const MEDIA_ALBUM: u8 = 0xD1;
    pub const MEDIA_TITLE: u8 = 0xD2;
    pub const MEDIA_LENGTH: u8 = 0xD3;
    pub const MEDIA_BITRATE: u8 = 0xD4;
    pub const MEDIA_CODEC: u8 = 0xD5;
    /// Kad hello/firewall capability bits.
    pub const KADMISCOPTIONS: u8 = 0xF2;
    pub const ENCRYPTION: u8 = 0xF3;
    pub const FILERATING: u8 = 0xF7;
    pub const SOURCEUPORT: u8 = 0xFC;
    pub const SOURCEPORT: u8 = 0xFD;
    pub const SOURCEIP: u8 = 0xFE;
    pub const SOURCETYPE: u8 = 0xFF;
}
