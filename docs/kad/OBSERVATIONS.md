# Kad Protocol Observations

Comparative analysis of the Overlord Rust port against the eMule and aMule oracle implementations for Kad2 and ED2K protocols.

This document was produced by cross-reading `PROTOCOL_REFERENCE.md`, `PROTOCOL_DIFFS.md`, `IMPLEMENTATION_REFERENCE.md`, and the current Rust source tree (`constants.rs`, `packet.rs`, `zone.rs`, `ed2k_server.rs`, and related crates).

---

## Methodology

- **Oracle authority order**: eMule > aMule > libed2k (per project policy in `PROTOCOL_REFERENCE.md §1`)
- **Primary oracle anchors**: `KademliaUDPListener.cpp`, `Search.cpp`, `Indexed.cpp`, `PacketTracking.cpp`, `RoutingBin.cpp`, `RoutingZone.cpp`
- **Status labels**
  - `Equivalent behavior` — Rust matches the oracle meaningfully enough for protocol work
  - `Verified difference` — known divergence from eMule
  - `Pending parity gap` — parity not yet completed or not yet reachable end-to-end
  - `Repo policy` — intentional Overlord implementation decision, compatible with Kad2 but not itself a wire fact

---

## 1. Wire Framing and Protocol Headers

| Item | Oracle (eMule/aMule) | Rust Port | Status |
|---|---|---|---|
| Plain Kad2 header byte | `0xE4` (`OP_KADEMLIAHEADER`) | `0xE4` in `constants.rs` | Equivalent behavior |
| Compressed Kad2 header byte | `0xE5` (`OP_KADEMLIAPACKEDPROT`) | `0xE5` in `constants.rs` | Equivalent behavior |
| Multi-byte integer order | Little-endian throughout | `#[brw(little)]` on all structs | Equivalent behavior |
| IPv4 `u32` byte order | Stored LE in packet, interpret as network-order octets | `Ipv4Addr::from(self.ip.to_be_bytes())` in `ContactEntry::ip_addr` | Equivalent behavior |
| 128-bit IDs (node, file, keyword, author) | 16 raw bytes, context-interpreted | `NodeId` and `Ed2kHash` wrappers, same wire size | Equivalent behavior |
| Obfuscation framing | RC4 layer around the entire UDP datagram; no separate Kad opcode | `obfuscation.rs` wraps transport pre/post codec | Equivalent behavior (see §10 for depth) |

---

## 2. Opcode Registry

The Rust `constants::opcode` module defines 25 opcodes. All hex values match eMule `srchybrid/Opcodes.h` and aMule `include/protocol/kad2/Client2Client/UDP.h`. The oracle keeps mixed naming for these families: the older firewall and buddy packets use `KADEMLIA_*`, while ping/pong and `FIREWALLUDP` keep the `KADEMLIA2_*` prefix.

| Opcode | Hex | Rust Runtime Status | Protocol Role |
|---|---|---|---|
| `BOOTSTRAP_REQ` | `0x01` | used | Ask a node for bootstrap contacts |
| `BOOTSTRAP_RES` | `0x09` | used | Bootstrap response with sender info and contacts |
| `HELLO_REQ` | `0x11` | used | Hello handshake and UDP-key exchange setup |
| `HELLO_RES` | `0x19` | used | Hello response |
| `HELLO_RES_ACK` | `0x22` | used | Hello acknowledgement (three-way handshake completion) |
| `REQ` | `0x21` | used | Generic iterative lookup request |
| `RES` | `0x29` | used | Closest-contact response |
| `SEARCH_KEY_REQ` | `0x33` | used | Keyword search request |
| `SEARCH_SOURCE_REQ` | `0x34` | used | File source search request (opcode previously wrong — fixed) |
| `SEARCH_NOTES_REQ` | `0x35` | used | File notes search request (opcode previously wrong — fixed) |
| `SEARCH_RES` | `0x3B` | used | Search result packet for keyword, source, and notes flows |
| `PUBLISH_KEY_REQ` | `0x43` | used | Publish keyword index entries |
| `PUBLISH_SOURCE_REQ` | `0x44` | used | Publish source availability for a file |
| `PUBLISH_NOTES_REQ` | `0x45` | used | Publish note or rating for a file |
| `PUBLISH_RES` | `0x4B` | used | Publish acknowledgement with load byte |
| `PUBLISH_RES_ACK` | `0x4C` | codec | Publish ack acknowledgement |
| `FIREWALLED_REQ` | `0x50` | used | Firewall check request carrying TCP port |
| `FIREWALLED2_REQ` | `0x53` | used | Extended firewall check for Kad v7+ |
| `FIREWALLED_RES` | `0x58` | used | Firewall response carrying external IP |
| `FIREWALLED_ACK_RES` | `0x59` | codec | Empty firewall acknowledgement |
| `FIREWALLUDP` | `0x62` | used | UDP reachability test packet |
| `FINDBUDDY_REQ` | `0x51` | codec | Buddy discovery for firewalled mode |
| `FINDBUDDY_RES` | `0x5A` | codec | Buddy discovery response |
| `CALLBACK_REQ` | `0x52` | codec | Buddy callback request |
| `PING` | `0x60` | used | Liveness check |
| `PONG` | `0x61` | used | Liveness response |

---

## 3. Packet Wire Layouts

All layouts are little-endian for multi-byte integers unless noted. Sizes are in bytes.

### 3.1 Bootstrap and Contact Entry

**`KADEMLIA2_BOOTSTRAP_REQ` (`0x01`)**

Empty payload. Both oracle and Rust agree: no body.

**`KADEMLIA2_BOOTSTRAP_RES` (`0x09`)**

| Field | Size | Meaning |
|---|---:|---|
| `sender_id` | 16 | Kad ID of the responding node |
| `sender_tcp_port` | 2 | TCP port of the responding node |
| `sender_version` | 1 | Kad version byte |
| `count` | 2 | Number of contact entries |
| `contacts[count]` | 25 each | Contact entries |

Status: `Equivalent behavior`. Rust `BootstrapRes` struct matches the layout verified in eMule `CKademliaUDPListener::ProcessBootstrapRequest`.

**`ContactEntry`** (used in `BOOTSTRAP_RES`, `RES`)

| Field | Size | Meaning |
|---|---:|---|
| `node_id` | 16 | Kad node ID |
| `ip` | 4 | IPv4 as packed `u32` (LE stored, BE interpreted for dotted notation) |
| `udp_port` | 2 | Kad UDP port |
| `tcp_port` | 2 | eD2k TCP port |
| `version` | 1 | Kad version byte |

Total: 25 bytes. Status: `Equivalent behavior`.

---

### 3.2 Hello Family

**`KADEMLIA2_HELLO_REQ` (`0x11`) and `KADEMLIA2_HELLO_RES` (`0x19`)**

| Field | Size | Meaning |
|---|---:|---|
| `node_id` | 16 | Sender's Kad node ID |
| `tcp_port` | 2 | Sender's TCP port |
| `version` | 1 | Sender's Kad version |
| `tag_count` | 1 | Number of capability tags |
| `tags[tag_count]` | variable | Typed Kad tags (capabilities, encryption options, etc.) |

Status: `Equivalent behavior` for wire shape. Both `HelloReq` and `HelloRes` Rust structs match the layout verified in eMule `CKademliaUDPListener::SendMyDetails`.

Pending parity gap: The full HELLO flow around obfuscation key registration, including how the sender verify key is extracted from the obfuscation trailer and how HELLO_RES_ACK acknowledges the three-way exchange, is not yet fully audited. This matters because without correct HELLO key exchange, the Rust runtime cannot build up per-peer obfuscation context to reach oracle-level obfuscated traffic ratios.

**`KADEMLIA2_HELLO_RES_ACK` (`0x22`)**

| Field | Size | Meaning |
|---|---:|---|
| `node_id` | 16 | ACK sender's Kad node ID |
| `tag_count` | 1 | Number of tags (eMule currently sends 0) |
| `tags[tag_count]` | variable | Reserved tag list |

Status: `Equivalent behavior` for wire shape. eMule currently sends an empty tag list.

---

### 3.3 Lookup Backbone (`REQ` / `RES`)

**`KADEMLIA2_REQ` (`0x21`)**

| Field | Size | Meaning |
|---|---:|---|
| `count` | 1 | Request type selector (`FIND_VALUE=0x02`, `FIND_NODE=0x0B`, `STORE=0x04`) |
| `target` | 16 | Lookup target ID |
| `recipient_id` | 16 | Node ID we believe the recipient has (sanity guard; recipient may drop on mismatch) |

Status: `Equivalent behavior`. Rust `Req` struct matches eMule wire format.

**`KADEMLIA2_RES` (`0x29`)**

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | Echoed lookup target |
| `count` | 1 | Number of contact entries |
| `contacts[count]` | 25 each | `ContactEntry` records |

Status: `Equivalent behavior`. Rust `Res` struct matches.

---

### 3.4 Search Family

**`KADEMLIA2_SEARCH_KEY_REQ` (`0x33`)**

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | Keyword hash (derived from first significant keyword word using MD4) |
| `start_position` | 2 | Page offset (`0x0000–0x7FFF`) or expression-data flag (`0x8000–0xFFFF`) |
| `restrictive_payload` | variable | Expression tree bytes when `start_position & 0x8000 != 0` (opaque; preserved for replay) |

Status: `Equivalent behavior` for wire shape. The Rust struct captures the restrictive payload opaquely so the runtime can harvest and replay snooped oracle requests without attempting to parse the expression tree yet.

Pending parity gap: The current runtime always sends `start_position = 0`. True numeric start-position pagination and full expression-tree serialization (as used by `kademlia/Search.cpp CSearch::StorePacket` when `start_position & 0x8000 != 0`) are not yet implemented. The runtime stays on the parity-safe request shape and does not invent speculative page-walking.

Oracle anchors:
- eMule `srchybrid/kademlia/net/KademliaUDPListener.cpp Process_KADEMLIA2_SEARCH_KEY_REQ`
- eMule `srchybrid/kademlia/kademlia/Search.cpp CSearch::StorePacket`
- aMule `src/kademlia/net/KademliaUDPListener.cpp Process2SearchKeyRequest`

**`KADEMLIA2_SEARCH_SOURCE_REQ` (`0x34`)**

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | File hash (treated as Kad target ID) |
| `start_position` | 2 | Source-result page start |
| `size` | 8 | Exact file size (required on wire) |

Status: `Equivalent behavior`. The `size` field was previously missing from the Rust codec — this was a critical mismatch that was fixed. The oracle (eMule `Process_KADEMLIA2_SEARCH_SOURCE_REQ` and `aMule Process2SearchSourceRequest`) requires the file size in this position. The agent now resolves the file size from the local index before sending; if the file is unknown or its indexed size is zero, the search is rejected before any packet is emitted.

**`KADEMLIA2_SEARCH_NOTES_REQ` (`0x35`)**

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | File hash (treated as Kad target ID) |
| `size` | 8 | Exact file size (required on wire) |

Status: `Equivalent behavior`. The `size` field was also previously missing — the second critical search-layout fix in the same pass. Same resolution policy as source search.

Oracle anchors:
- eMule `srchybrid/kademlia/net/KademliaUDPListener.cpp Process_KADEMLIA2_SEARCH_NOTES_REQ`
- eMule `srchybrid/kademlia/kademlia/Search.cpp CSearch::StorePacket`
- aMule `src/kademlia/net/KademliaUDPListener.cpp Process2SearchNotesRequest`

**`KADEMLIA2_SEARCH_RES` (`0x3B`)**

| Field | Size | Meaning |
|---|---:|---|
| `sender_id` | 16 | Kad ID of the responding node |
| `target` | 16 | Echoed search target |
| `count` | 2 | Number of result entries in this packet |
| `results[count]` | variable | `SearchResultEntry` records |

`SearchResultEntry`:

| Field | Size | Meaning |
|---|---:|---|
| `entry_id` | 16 | Entry ID — file hash (keyword), source/client ID (source search), note author/source ID (notes search) |
| `tag_count` | 1 | Number of tags |
| `tags[tag_count]` | variable | Typed Kad tags describing the result |

Status: `Equivalent behavior` for wire shape. The Rust codec correctly encodes and decodes this layout, and the Rust field is now named `entry_id` to match the oracle's generic per-entry identity semantics.

Oracle anchors:
- eMule `srchybrid/kademlia/kademlia/Indexed.cpp SendValidKeywordResult`, `SendValidSourceResult`, `SendValidNoteResult`
- aMule `src/kademlia/kademlia/Indexed.cpp` matching functions

---

### 3.5 Publish Family

**`KADEMLIA2_PUBLISH_KEY_REQ` (`0x43`)**

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | Keyword hash target |
| `count` | 2 | Number of published file entries |
| `entries[count]` | variable | `PublishEntry` records |

`PublishEntry`:

| Field | Size | Meaning |
|---|---:|---|
| `hash` | 16 | Published file hash |
| `tag_count` | 1 | Number of tags |
| `tags[tag_count]` | variable | File metadata tags |

Status: `Equivalent behavior`. Layout matches oracle.

Typical oracle tags in keyword publish: `FILENAME`, `FILESIZE`, `FILETYPE`, `FILEFORMAT`, `SOURCES`, `MEDIA_ARTIST`, `MEDIA_ALBUM`, `MEDIA_TITLE`, `MEDIA_LENGTH`, `MEDIA_BITRATE`, `MEDIA_CODEC`.

**`KADEMLIA2_PUBLISH_SOURCE_REQ` (`0x44`)**

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | File hash target |
| `publisher_id` | 16 | Publisher client hash / source identifier |
| `tag_count` | 1 | Number of tags |
| `tags[tag_count]` | variable | Source metadata tags |

Status: `Equivalent behavior`. The Rust field `publisher_id: NodeId` now carries the sender's source-publish identity in this position, matching eMule `net/KademliaUDPListener.cpp SendPublishSourcePacket` and `kademlia/Search.cpp CSearch::StorePacket`. The Rust type stays `NodeId` only because the wire slot is still a raw 16-byte identity field.

Oracle source type values carried in `TAG_SOURCETYPE`:
- `1`: high-ID source
- `3`: firewalled Kad source
- `4`: high-ID source for file larger than 4 GiB
- `5`: firewalled Kad source for file larger than 4 GiB
- `6`: firewalled source with direct callback support

Pending parity gap: encryption capability tags and buddy/callback tag handling in source publish have not been fully audited against the oracle send path.

**`KADEMLIA2_PUBLISH_NOTES_REQ` (`0x45`)**

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | File hash target |
| `publisher_id` | 16 | Publisher Kad ID — the sender's `NodeId` |
| `tag_count` | 1 | Number of tags |
| `tags[tag_count]` | variable | Note tags |

Status: `Equivalent behavior`.

The Rust struct now models the second field as `publisher_id: NodeId`, matching
the oracle contract directly instead of relying on the accidental 16-byte size
match between `NodeId` and `Ed2kHash`. End-to-end notes publish validation is no
longer blocked by a semantic field mismatch.

Oracle typical tags in notes publish: `FILENAME`, `FILERATING`, `DESCRIPTION`, `FILESIZE` (for Kad2-capable peers).

**`KADEMLIA2_PUBLISH_RES` (`0x4B`)**

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | Echoed publish target |
| `load` | 1 | Remote-side load or acceptance hint |

Status: `Equivalent behavior`. Wire shape matches.

Pending parity gap: The Rust runtime currently treats publish acks as success/failure for counting purposes only. The deeper oracle load semantics from eMule `kademlia/Indexed.cpp` (load-based acceptance decisions, per-opcode load tracking) are not yet modeled.

**`KADEMLIA2_PUBLISH_RES_ACK` (`0x4C`)**

Empty payload. Status: `Equivalent behavior`.

---

### 3.6 Firewall Family

**`KADEMLIA_FIREWALLED_REQ` (`0x50`)**

| Field | Size | Meaning |
|---|---:|---|
| `tcp_port` | 2 | Sender's TCP port for connection test |

Status: `Equivalent behavior` for wire shape.

**`KADEMLIA_FIREWALLED2_REQ` (`0x53`)** — Kad v7+ extended variant

| Field | Size | Meaning |
|---|---:|---|
| `tcp_port` | 2 | Sender's TCP port |
| `user_hash` | 16 | Sender's eD2k user hash |
| `connect_options` | 1 | Connection capability flags |

Status: `Equivalent behavior` for wire shape. Newer oracle peers use this Kad v7+ variant for the extended firewall check, and the current Rust runtime decodes and responds to it.

**`KADEMLIA_FIREWALLED_RES` (`0x58`)**

| Field | Size | Meaning |
|---|---:|---|
| `ip` | 4 | Sender's external IPv4 as seen by the responder |

Status: `Equivalent behavior`.

**`KADEMLIA_FIREWALLED_ACK_RES` (`0x59`)** and **`KADEMLIA2_FIREWALLUDP` (`0x62`)**

Both are implemented with correct wire shapes. The current Rust runtime actively uses the firewalled probe flow, and the April 3, 2026 JSONL parity rerun exercised inbound `FIREWALLUDP` on the Rust side after the helper TCP request path was bound to the P2P IPv4 and the outgoing hello exchange stopped behaving like a one-packet stub. The larger firewall-plus-buddy state machine is still not at full oracle parity, because the oracle still emitted more `FIREWALLUDP` traffic and broader helper-role behavior in the same family.

---

### 3.7 Ping / Pong

`KADEMLIA2_PING` (`0x60`)` has an empty payload.

`KADEMLIA2_PONG` (`0x61`) carries:

| Field | Size | Meaning |
|---|---:|---|
| `udp_port` | 2 | sender-observed UDP port of the pinging peer |

Status: `Equivalent behavior`. The Rust runtime now mirrors the oracle’s non-empty `PONG` body and echoes the source UDP port the responder observed.

---

## 4. Tag Registry

All tag IDs are defined in `constants::tag_name` and verified against eMule `srchybrid/Opcodes.h` and aMule `src/include/tags/FileTags.h`. Several tags were previously mapped to wrong IDs; those have been corrected.

| ID | Rust constant | Type | Meaning | Prior issue |
|---|---|---|---|---|
| `0x01` | `FILENAME` | string | File name | — |
| `0x02` | `FILESIZE` | uint32 or uint64 | File size low part | — |
| `0x03` | `FILETYPE` | string | Coarse file type | — |
| `0x04` | `FILEFORMAT` | string | Format / subtype | — |
| `0x0B` | `DESCRIPTION` | string | Note / comment text | Previously mapped as a "COMMENT" tag with a different ID |
| `0x15` | `SOURCES` | uint32 | Source count (exposed in Rust as `source_count`) | Previously confused with `FILERATING` |
| `0x3A` | `FILESIZE_HI` | uint32 | High 32 bits for files larger than 4 GiB | — |
| `0xD0` | `MEDIA_ARTIST` | string | Artist metadata | — |
| `0xD1` | `MEDIA_ALBUM` | string | Album metadata | — |
| `0xD2` | `MEDIA_TITLE` | string | Track title metadata | — |
| `0xD3` | `MEDIA_LENGTH` | uint32 | Media duration | — |
| `0xD4` | `MEDIA_BITRATE` | uint32 | Media bitrate | — |
| `0xD5` | `MEDIA_CODEC` | string | Codec identifier | — |
| `0xF2` | `KADMISCOPTIONS` | uint8 | Hello / firewall capability bits | — |
| `0xF3` | `ENCRYPTION` | uint8 | Encryption capability | — |
| `0xF7` | `FILERATING` | uint8 | File note rating | Previously placed at `0x15` |
| `0xFC` | `SOURCEUPORT` | uint16 | Source Kad UDP port | Previously mapped at `0x23` |
| `0xFD` | `SOURCEPORT` | uint16 | Source TCP port | Previously mapped at `0x22` |
| `0xFE` | `SOURCEIP` | uint32 | Source IPv4 | Previously mapped at `0x21` |
| `0xFF` | `SOURCETYPE` | uint8 | Source reachability type | — |

Notes:

- `SOURCES (0x15)` carries the remote complete source count. The Rust public field is now named `source_count` so the code matches the oracle semantics directly.
- `DESCRIPTION (0x0B)` is the tag used for note/comment text in both `SEARCH_RES` (notes results) and `PUBLISH_NOTES_REQ`. The old "COMMENT" mapping was wrong for Kad search/notes parsing.
- Large-file sizes are split across `FILESIZE (0x02)` (low 32 bits) and `FILESIZE_HI (0x3A)` (high 32 bits). The `overlord-kad-dht` crate combines the two into one `u64`.
- Source result tags (`0xFC–0xFF`) live in the high numeric range. Their previous incorrect mapping at `0x21–0x23` broke source result interoperability.

---

## 5. Protocol Constants

| Constant | Oracle (eMule) | Rust (`constants.rs`) | Status |
|---|---|---|---|
| `K` (k-bucket size) | 10 | 10 | Equivalent behavior |
| `ALPHA` (parallel lookup queries) | 3 | 3 | Equivalent behavior |
| `KBASE` (zone split base exponent) | 4 | 4 | Equivalent behavior |
| `KK` (peer selection parameter) | 5 | 5 | Equivalent behavior |
| `KAD_VERSION` (announced version byte) | 9 | 9 | Equivalent behavior |
| `OP_KADEMLIAHEADER` | `0xE4` | `0xE4` | Equivalent behavior |
| `OP_KADEMLIAPACKEDPROT` | `0xE5` | `0xE5` | Equivalent behavior |
| `SEARCHTOLERANCE` | `0x0100_0000` (high-32 XOR chunk) | `0x0100_0000` | Equivalent behavior |
| `KADEMLIA_FIND_VALUE` | `0x02` | `0x02` | Equivalent behavior |
| `KADEMLIA_FIND_NODE` | `0x0B` | `0x0B` | Equivalent behavior |
| `KADEMLIA_STORE` | `0x04` | `0x04` | Equivalent behavior |
| `SEARCH_TIMEOUT_SECS` | 45 s | 45 | Equivalent behavior |
| `STORE_TIMEOUT_SECS` | 140 s | 140 | Equivalent behavior |
| `REPUBLISH_INTERVAL_SECS` | ~18 000 s (~5 h) | 18 000 | Equivalent behavior |

---

## 6. Routing Table

### 6.1 Zone Tree Structure

Both oracle trees (eMule `routing/RoutingZone.cpp`, aMule `routing/RoutingZone.cpp`) use a binary zone tree where each node is either a leaf holding a k-bucket (`RoutingBin`) or an internal branch with two child zones. The Rust `overlord-kad-routing` crate follows the same structure: `RoutingZone` with `ZoneContent::Leaf(RoutingBin)` or `ZoneContent::Branch { left, right }`. Status: `Equivalent behavior`.

### 6.2 Zone Split Condition

Oracle rule from eMule/aMule `RoutingZone::CanSplit`:

```
split only when:
  bin_size == K
  AND level < 127
  AND (zone_index < KK OR level < KBASE)
```

Rust rule from `zone.rs fn can_split`:

```rust
depth < 127
AND total_contacts < max_table_size
AND (depth < KBASE || zone_index < KK)
```

Status: `Equivalent behavior` for the oracle split predicate, with one explicit local guard.

- The earlier Rust `on_own_side` heuristic has been removed. The routing table now carries the absolute `zone_index` and applies the oracle predicate `depth < KBASE || zone_index < KK`.
- The extra `total_contacts < max_table_size` guard remains a local Overlord table-size safety limit. This is `Repo policy`, not oracle behavior, and it now surfaces as an explicit split-denied reason instead of being silently folded into generic add failures.
- Live validation on April 2, 2026 showed oracle-style split decisions during bootstrap, with routing logs recording the accepted split depth and `zone_index` as the table grew to 156 contacts while still returning live `ubuntu linux` search results.

### 6.3 IP and Subnet Limits

Oracle rule from eMule/aMule `RoutingBin::AddContact`, `CheckGlobalIPLimits`, and `ChangeContactIPAddress`:

- Maximum 1 contact per IP address globally
- Maximum 10 contacts per `/24` subnet globally
- Maximum 2 contacts from the same `/24` inside one single bin
- LAN addresses (RFC1918) are exempt from subnet limits

Rust status:

| Limit | Rust `table.rs` | Status |
|---|---|---|
| Global 1-per-IP | Implemented | Equivalent behavior |
| Global 10-per-/24 | Implemented | Equivalent behavior |
| LAN exemption | Implemented | Equivalent behavior |
| Per-bin 2-per-/24 | Implemented in `bin.rs` | Equivalent behavior |

The Rust routing layer now distinguishes global `/24` rejects from bin-local `/24` rejects and reports both paths explicitly. That makes the oracle-equivalent anti-clustering rule observable during live testing instead of only being implied by insertion behavior.

### 6.4 Contact Fields

The Rust `Contact` struct:

```rust
pub struct Contact {
    pub id: NodeId,
    pub ip: Ipv4Addr,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub kad_version: u8,
    pub udp_key: KadUdpKey,
    pub verified: bool,
    pub contact_type: ContactType,  // Active / Inactive / Dead
    pub last_seen: SystemTime,
    pub created_at: SystemTime,
}
```

Status: `Equivalent behavior`. All fields correspond to oracle contact fields. The `udp_key` field enables per-contact obfuscation key retention across restarts when loaded from `nodes.dat`.

---

## 7. Search Semantics

### 7.1 SEARCHTOLERANCE Gate

Oracle behavior from eMule `kademlia/Defines.h` and `kademlia/Search.cpp`: before sending phase-2 search packets (the actual `SEARCH_KEY_REQ`, `SEARCH_SOURCE_REQ`, or `SEARCH_NOTES_REQ`), eMule checks that the target node is within `SEARCHTOLERANCE = 0x0100_0000` on the high-32 bits of the XOR distance, using `CUInt128::Get32BitChunk(0)` semantics (first chunk in eMule's little-endian 32-bit chunk order).

Rust status: The constant exists in `constants.rs` and `traversal.rs` now enforces the SEARCHTOLERANCE gate before sending phase-2 search packets, using the same first-chunk ordering and including a LAN exemption. The runtime now also caps phase 2 at the oracle's closest `K` tolerated responders, while still allowing configuration to lower that ceiling for tests. Status: `Equivalent behavior`.

### 7.2 Keyword Target Derivation

Oracle: keyword search targets are derived from the first significant word in the query, hashed with MD4.

Rust status: The runtime hashes the first significant word with MD4 and sends a plain `SearchKeyReq`. Full expression serialization, post-filtering by keyword, and start-position pagination are pending. Status: `Equivalent behavior` for the common case.

### 7.3 Source Search File Size Requirement

Oracle: eMule and aMule both require the exact file size in `SEARCH_SOURCE_REQ`. eMule aborts the search if the referenced file cannot be found locally (and therefore the size cannot be serialized).

Rust status: `Equivalent behavior`. The runtime resolves size from the local `files` index before starting the DHT search. If the file is not indexed or its size is zero, the API request returns 400 and no Kad packet is sent. The external API remains hash-only (`POST /api/v1/search/source { "hash": "..." }`); the daemon is responsible for size resolution.

### 7.4 Notes Search File Size Requirement

Same requirement and same resolution policy as source search. Status: `Equivalent behavior`.

### 7.5 Search Result Interpretation

Keyword results:

- `entry_id` is the file hash
- Relevant tags: `FILENAME`, `FILESIZE`, `FILESIZE_HI`, `FILETYPE`, `FILEFORMAT`, `SOURCES`, media tags
- Acceptance condition: at least one filename and a non-zero filesize

Source results:

- `entry_id` is the source/client ID, not the searched file hash
- Relevant tags: `SOURCEIP`, `SOURCEPORT`, `SOURCEUPORT`, `SOURCETYPE`
- If `SOURCEUPORT` is absent, UDP port falls back to TCP port
- Acceptance condition: valid IPv4 endpoint with non-zero TCP port

Notes results:

- `entry_id` identifies the note author/source
- Relevant tags: `DESCRIPTION`, `FILERATING`
- The `entry_id` is persisted as note `source_id`, matching eMule's `uAnswer` / `m_uSourceID` treatment of that field as source/author identity
- Acceptance condition: usable rating or non-empty comment

### 7.6 Search Result String Decoding

Oracle behavior: `SEARCH_RES` string tags are decoded differently from ordinary Kad strings. eMule first tries UTF-8; if the bytes are not valid UTF-8, it falls back to the local ANSI code page.

Rust behavior: `overlord-kad-proto` mirrors this for incoming `SEARCH_RES` tags only. On Windows, fallback uses the current ACP. On non-Windows, fallback uses Windows-1252 as a deterministic compatibility approximation. Normal tag decoding elsewhere uses UTF-8-lossy. Status: `Equivalent behavior`.

### 7.7 Search Result Batching (Oracle vs Oracle)

eMule `Indexed.cpp SendValidKeywordResult` / `SendValidSourceResult` / `SendValidNoteResult` fragment on `UDP_KAD_MAXFRAGMENT` byte budget.
aMule uses fixed 50-result chunks in matching functions.

Both may emit multiple `KADEMLIA2_SEARCH_RES` packets per request. Status: `Equivalent behavior, different implementation` between oracles.

Rust status: The Rust runtime accepts configurable caps (keyword: 5000, source: 1000, notes: 1000) and does not enforce byte-budget fragmentation on the receive path. Status: `Repo policy`. The Overlord runtime is optimized for broad collection and later filtering rather than interactive client-style small result windows.

### 7.8 Notes Search End-to-End Validation

Status: **Equivalent behavior, remaining modeling gap**.

`overlord-kad-dht/src/traversal.rs` emits `SearchNotesReq { target, size }`, matching oracle wire shape, and `overlord-agent-emule/src/agent.rs` now dispatches coordinator-triggered Kad notes searches through the live runtime. Real-network validation on April 2, 2026 confirmed the coordinator accepted a notes job, the agent emitted `KADEMLIA2_SEARCH_NOTES_REQ` on the wire, and the job completed cleanly. The remaining gap is on the coordinator side: notes are still projected into file-centric `SearchResult` / `FileRecord` views, so distinct note authors would collapse onto one file record for the same file hash.

---

## 8. Publish Semantics

### 8.1 Keyword Publish

Oracle: `KADEMLIA2_PUBLISH_KEY_REQ` carries a keyword hash target and one or more `PublishEntry` records. eMule may batch multiple entries in one packet. Status: `Equivalent behavior`. End-to-end acceptance against live eMule nodes still needs broader validation.

### 8.2 Source Publish Identity Field

Oracle: The second 128-bit field in `KADEMLIA2_PUBLISH_SOURCE_REQ` is the publisher's client hash / Kad identity — the sender's node identity, not the file hash.

Previous Rust state: this field was incorrectly described or populated.

Current Rust state: `publish_source` in `overlord-kad-dht/src/publish.rs` now fills this field with the stable source-publish identity, and the struct field is still typed `publisher_id: NodeId` only for 16-byte wire compatibility. Status: `Equivalent behavior`.

### 8.3 Notes Publish Identity Field

Oracle: The second 128-bit field in `KADEMLIA2_PUBLISH_NOTES_REQ` is the publisher's Kad node ID — a `NodeId`, the sender's identity.

Current Rust state: `PublishNotesReq` now uses `publisher_id: NodeId`, and the
agent-local notes store keys notes publishes by publisher identity rather than a
fictitious note hash. The remaining work is live validation and broader
coordinator-side notes-result modeling. Status: `Equivalent behavior`.

### 8.4 Publish Result Load Semantics

Oracle: `PUBLISH_RES.load` carries a per-node load hint used by eMule to track indexing capacity and acceptance rates.

Rust status: The `load` byte is received and stored, but deeper oracle load semantics (load-based acceptance decisions, per-opcode load tracking) are not yet modeled. Status: `Pending parity gap`.

---

## 9. Packet Tracking and Rate Limiting

Oracle behavior from eMule `net/PacketTracking.cpp` and aMule `net/PacketTracking.cpp`:

Both implement per-IP, per-opcode inbound request throttling. The two oracles differ slightly on publish limits:

| Opcode | eMule limit (per IP/min) | aMule limit (per IP/min) |
|---|---|---|
| `KADEMLIA2_PUBLISH_KEY_REQ` | 4 | 3 |
| `KADEMLIA2_PUBLISH_SOURCE_REQ` | 3 | 2 |
| `KADEMLIA2_PUBLISH_NOTES_REQ` | 2 | 2 |
| Search opcodes | 3 | 3 |

Overlord policy: eMule wins. The Rust implementation should use eMule's limits.

Current Rust status: `overlord-kad-net/src/tracker.rs` now mirrors the oracle's per-IP, per-opcode buckets for bootstrap, HELLO, lookup, search, publish, firewall, buddy, callback, and ping traffic. The Rust runtime also now mirrors the oracle's three-state punishment model:

- allow
- ordinary flood drop
- massive flood drop at `4x` the per-minute bucket, with a higher punishment path

The response side is also tracked separately through `OutboundRequestTracker`, including the oracle's publish-response "peek then consume" behavior. The remaining gap is no longer bucket shape; it is broader live-behavior validation and acceptance tuning around the now-instrumented tracker decisions. Status: **Equivalent behavior (recently improved)**.

---

## 10. Obfuscation (RC4)

This is the single most impactful remaining parity gap for live network interoperability.

### 10.1 Oracle Behavior

Modern eMule nodes use RC4-based UDP obfuscation on all Kad2 traffic from version 6 onward. Key generation uses a per-peer session key negotiated through the `KADEMLIA2_HELLO_REQ/RES` exchange. Modern `nodes.dat` snapshots carry peer UDP keys enabling obfuscated communication on the first packet of a restart.

A 5-minute isolated oracle run on `46663/udp` (2026-03-22, see `IMPLEMENTATION_REFERENCE.md §9`) produced:

- Total packets: 1009
- Plaintext Kad packets (`0xE4`): 55 (5.5%)
- Non-plaintext (obfuscated): 954 (94.5%)

No plaintext `PUBLISH_KEY_REQ`, `PUBLISH_SOURCE_REQ`, `PUBLISH_RES`, or `PUBLISH_RES_ACK` packets were visible despite the oracle trace log confirming successful publish operations during that window. This proves that oracle publish interactions happen overwhelmingly over obfuscated transport.

### 10.2 Rust Status

| Feature | Oracle | Rust | Status |
|---|---|---|---|
| Obfuscation default | Enabled | Enabled | Equivalent behavior |
| Request packet key schedule | NodeID-based RC4 key derivation | Now follows oracle key schedule more closely | Equivalent behavior (recently improved) |
| Reply packet key schedule | Receiver verify key from prior HELLO/obfuscated traffic | Prefers receiver verify key when available | Equivalent behavior (recently improved) |
| Inbound packet decode order | Try obfuscated first, then plain fallback | Obfuscated first, plain fallback | Equivalent behavior |
| UDP key persistence from `nodes.dat` | Keys loaded at startup, enabling obfuscated first contact | Now preserved across restarts | Equivalent behavior (recently improved) |
| Live network obfuscation ratio | ~94% of packets non-plaintext | Runtime still produces more plaintext than oracle | **Pending parity gap** (critical) |
| HELLO key registration completeness | Full three-way key exchange builds per-peer context | Full HELLO flow not yet at oracle parity | **Pending parity gap** |

The combined oracle conclusion (from pcap traces `a3` through `a7`) is that live Kad interoperability depends more on transport-shape parity than on individual packet layout correctness. A Rust node that stays mostly plaintext will not look like the oracle on the network, even if every packet layout is individually correct. Reaching oracle-level obfuscation density is the highest-priority remaining parity task.

---

## 11. ED2K Server Protocol (TCP)

The `ed2k_server.rs` and `ed2k_tcp.rs` modules in `overlord-agent-emule` implement a minimal eD2k server session. This scope is intentional — full server protocol is listed as Phase 2+ in `IMPLEMENTATION_REFERENCE.md §2`.

### 11.1 Protocol Headers

| Constant | Hex | Oracle | Rust | Status |
|---|---|---|---|---|
| `OP_EDONKEYPROT` | `0xE3` | eMule TCP main protocol header | Defined | Equivalent behavior |
| `OP_EMULEPROT` | `0xC5` | eMule extension protocol header | Defined | Equivalent behavior |
| `OP_PACKEDPROT` | `0xD4` | zlib-compressed packet | `ZlibDecoder` used | Equivalent behavior |

### 11.2 Implemented Oracle Operations

| Opcode | Hex | Oracle function | Rust status |
|---|---|---|---|
| `OP_LOGINREQUEST` | `0x01` | Oracle-shaped login with hash, ports, tags | Implemented |
| `OP_IDCHANGE` | `0x40` | HighID / LowID assignment from server | Processed |
| `OP_SERVERSTATUS` | `0x34` | User and file count from server | Processed |
| `OP_SERVERMESSAGE` | `0x38` | Server welcome or message text | Processed |
| `OP_SERVERIDENT` | `0x41` | Server hash, name, description | Defined |
| `OP_OFFERFILES` | `0x15` | Announce shared files | Empty keepalive packets only |

### 11.3 Defined But Not Fully Implemented

| Opcode | Hex | Oracle function | Rust status |
|---|---|---|---|
| `OP_SEARCHREQUEST` | `0x16` | Server-side keyword search | Defined |
| `OP_SEARCHRESULT` | `0x33` | Server search result | Defined |
| `OP_GETSERVERLIST` | `0x14` | Fetch additional servers | Defined |
| `OP_SERVERLIST` | `0x32` | Server list response | Defined |
| `OP_CALLBACKREQUESTED` | `0x35` | Peer callback via server | Defined (Phase 2+) |
| `OP_CALLBACK_FAIL` | `0x36` | Callback failure | Defined (Phase 2+) |
| `OP_REJECT` | `0x05` | Server rejection | Defined |

### 11.4 Out of Scope

- Full `OP_OFFERFILES` with actual file metadata
- ED2K peer-to-peer TCP connection and file download
- AICH hash tree computation
- Full server-side search and result pagination

---

## 12. eMule vs aMule Oracle Differences Relevant to Porting

These are the confirmed behavioral differences between the two oracle trees, as documented in `PROTOCOL_DIFFS.md`. They inform which oracle to follow for which decision.

| Area | eMule | aMule | Overlord follows |
|---|---|---|---|
| Publish inbound rate for `PUBLISH_KEY_REQ` | 4/min per IP | 3/min per IP | eMule |
| Publish inbound rate for `PUBLISH_SOURCE_REQ` | 3/min per IP | 2/min per IP | eMule |
| Publish inbound rate for `PUBLISH_NOTES_REQ` | 2/min per IP | 2/min per IP | Either (same) |
| `SEARCH_RES` packetization | Byte-budget fragmentation (`UDP_KAD_MAXFRAGMENT`) | Fixed 50-result chunks | Neither (Repo policy: configurable caps) |
| Keyword result post-processing | Filters `TAG_PUBLISHINFO` and `TAG_KADAICHHASHRESULT` based on responder Kad version | Accepts `TAG_PUBLISHINFO` more directly, no sender-version gate | eMule (not yet ported) |
| IO layer | Dedicated `ByteIO` / `DataIO` / `CSafeMemFile` stack | `CMemFile` + wxWidgets containers | N/A (Rust codec is independent) |
| MFC/GUI surface | `GetGUIName`, `SetGUIName`, `GetNodeLoad`, `UpdateNodeLoad` in `Search.cpp` | Trimmed | Not ported (out of scope) |

Porting rule: Use eMule for wire format, security filters, and sender-version-dependent behavior. Use aMule for readable portable control flow and to confirm whether an eMule quirk is protocol behavior or Windows/MFC scaffolding.

---

## 13. Summary of Outstanding Parity Gaps

Ranked by severity for live network interoperability.

| # | Area | Gap description | Severity |
|---|---|---|---|
| 1 | **Obfuscation transport dominance** | Live oracle is ~94% obfuscated; Rust runtime is still more plaintext than the oracle. Without matching obfuscation density, many live peers will ignore publish and search traffic. | Critical |
| 2 | **HELLO / obfuscation key registration** | Full three-way HELLO parity around obfuscation key exchange not yet audited. Blocking full obfuscation context build-up with peers. | High |
| 3 | **Packet-tracking live validation** | Oracle-shaped per-opcode packet tracking is now in place, but live acceptance still needs repeated validation against the oracle with the new tracker counters and drop reasons. | Medium |
| 4 | **Kad notes result modeling** | Active Kad notes search is wired and live-validated, but coordinator result storage is still file-centric. Distinct note authors for the same file would collapse into one `FileRecord`. | Medium |
| 5 | **Search response target semantics** | `SEARCH_RES.target` is now documented and named for the generic echoed target semantics shared by keyword, source, and notes responses. | Closed |
| 6 | **Keyword expression serialization** | `start_position=0` only. Oracle expression-tree mode (`0x8000`) and numeric pagination not yet implemented. | Low |
| 7 | **Source publish encryption and buddy tags** | Not audited against oracle send path for encryption capability tags and buddy/callback tag handling. | Low |
| 8 | **Publish result load semantics** | `PUBLISH_RES.load` received but oracle load-tracking logic not modeled. | Low |
| 9 | **Firewall and buddy inventory drift** | The mixed `KADEMLIA_*` and `KADEMLIA2_*` oracle naming previously drifted in the docs; the canonical protocol inventory now reflects the exact oracle constants and wire layouts. | Closed |
| 10 | **ED2K full server protocol** | `OP_OFFERFILES` body, server search, peer callback, file transfer. Intentionally deferred to Phase 2+. | Out of scope |

---

## 14. Reference Map

### Oracle Sources

- eMule `srchybrid/Opcodes.h` — Kad2 opcode values, tag IDs, `FT_FILESIZE_HI`
- eMule `srchybrid/kademlia/net/KademliaUDPListener.cpp` — search/publish parsing, HELLO, firewall, UDP key handling
- eMule `srchybrid/kademlia/kademlia/Search.cpp` — search and publish serialization, source type semantics
- eMule `srchybrid/kademlia/kademlia/Indexed.cpp` — `SEARCH_RES` emission, result batching, result limits
- eMule `srchybrid/kademlia/net/PacketTracking.cpp` — per-opcode inbound request throttling
- eMule `srchybrid/kademlia/kademlia/Prefs.cpp` — UDP verify key derivation
- eMule `srchybrid/kademlia/kademlia/SearchManager.cpp` — keyword preparation and duplicate-search policy
- eMule `srchybrid/kademlia/kademlia/Defines.h` — `SEARCHTOLERANCE` and search constants
- eMule `srchybrid/kademlia/routing/RoutingZone.cpp` — zone split logic
- eMule `srchybrid/kademlia/routing/RoutingBin.cpp` — IP/subnet limits, contact add logic
- aMule equivalents in `src/kademlia/` for each of the above
- aMule `src/include/protocol/kad2/Client2Client/UDP.h` — opcode cross-check
- aMule `src/include/tags/FileTags.h` — tag ID cross-check

### Overlord Rust Sources

- `crates/overlord-kad-proto/src/constants.rs` — opcode and tag registry
- `crates/overlord-kad-proto/src/packet.rs` — Rust wire layouts
- `crates/overlord-kad-proto/src/tag.rs` — tag encode/decode and helper constructors
- `crates/overlord-kad-routing/src/zone.rs` — zone split logic
- `crates/overlord-kad-routing/src/bin.rs` — k-bucket and IP limit enforcement
- `crates/overlord-kad-routing/src/table.rs` — global IP/subnet duplicate tracking
- `crates/overlord-kad-net/src/rpc.rs` — pending request map and unsolicited packet policy
- `crates/overlord-kad-net/src/obfuscation.rs` — RC4 obfuscation implementation
- `crates/overlord-kad-net/src/tracker.rs` — inbound flood protection
- `crates/overlord-kad-dht/src/traversal.rs` — search-phase request emission, SEARCHTOLERANCE gate
- `crates/overlord-kad-dht/src/publish.rs` — publish request emission and publisher identity fields
- `crates/overlord-kad-dht/src/types.rs` — keyword/source/notes result decoding
- `crates/overlord-agent-emule/src/agent.rs` — agent-side search dispatch, result posting, coordinator integration
- `crates/overlord-agent-emule/src/ed2k_server.rs` — eD2k TCP server session
- `crates/overlord-agent-emule/src/ed2k_tcp.rs` — eD2k TCP peer helpers
