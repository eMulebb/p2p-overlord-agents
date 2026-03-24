# KAD_PROTOCOL

Kad2 wire-reference document for the Overlord Kad crates.
This file is maintained in the current Overlord workspace under `overlord-agents/crates/overlord-kad-proto/docs/`.

Deep Kad2 wire-protocol reference for this repository.

This document is the packet- and tag-level companion to the architecture document in this directory.
That companion document owns architecture, crate responsibilities, API surface, and product-level behavior.
This file owns verified Kad2 wire facts, repo policy choices, and protocol notes that are easy to forget.

## 1. Scope And Authority

### Scope

- Kad2 only
- IPv4 only
- UDP packet layer and the search/publish-related tag model
- eMule-compatible behavior as implemented by this repo

### Authority Order

1. eMule: `c:\prj\p2p\eMule-my\deps-repos\eMule\srchybrid\kademlia\`
2. aMule: `c:\prj\p2p\amule\src\kademlia\`
3. libed2k: `c:\prj\p2p\libed2k\src\kademlia\`

### Reading Rule

- If eMule and this document disagree, eMule wins.
- aMule is the portability cross-check when eMule code is awkward or MFC-heavy.
- libed2k is useful for architecture and traversal ideas, but it is not authoritative for eMule wire format.

### Verified Facts vs Repo Policy

This document explicitly distinguishes:

- `Verified`: directly grounded in eMule and cross-checked with aMule where practical
- `Repo policy`: an implementation decision in the current Overlord Kad runtime that is compatible with Kad2 but not itself a wire fact
- `Pending`: behavior not fully audited yet and therefore not safe to treat as settled

## 2. Wire Framing Basics

### Packet Headers

- `0xE4` = `OP_KADEMLIAHEADER`
- `0xE5` = `OP_KADEMLIAPACKEDPROT`

`0xE4` frames plain Kad2 packets.
`0xE5` frames zlib-packed Kad2 payloads.
Obfuscation is layered around the UDP datagram and is not represented by a separate Kad opcode family.

### Endianness

Unless noted otherwise, multi-byte integers in Kad2 UDP packets are little-endian.

Important special case:

- IPv4 addresses in contact entries and source tags are carried as a `u32`
- when turned into dotted IPv4, treat the `u32` bytes as network-order octets
- in Rust this repo converts with `Ipv4Addr::from(value.to_be_bytes())`

### 128-Bit IDs

Kad2 reuses 128-bit fields heavily:

- Kad node IDs
- ed2k file hashes
- keyword hashes
- source / author IDs inside search results

On the wire, these are all just 16 raw bytes.
Interpretation depends on the packet family and search mode.

## 3. Verified Kad2 Opcode Registry

Status legend:

- `used`: codec exists and the runtime currently sends/receives it
- `codec`: packet is modeled in `overlord-kad-proto`, but runtime behavior is not fully wired or audited
- `reserved`: kept for future work only

| Opcode | Name | Direction | Pairing | Purpose | Status In Current Overlord Kad Runtime |
|---|---|---|---|---|---|
| `0x01` | `KADEMLIA2_BOOTSTRAP_REQ` | out | `BOOTSTRAP_RES` | ask a node for bootstrap contacts | used |
| `0x09` | `KADEMLIA2_BOOTSTRAP_RES` | in | `BOOTSTRAP_REQ` | bootstrap response with sender info and contacts | used |
| `0x11` | `KADEMLIA2_HELLO_REQ` | both | `HELLO_RES` | hello handshake and UDP-key exchange setup | codec |
| `0x19` | `KADEMLIA2_HELLO_RES` | both | `HELLO_REQ` | hello response | codec |
| `0x21` | `KADEMLIA2_REQ` | out | `RES` | generic Kad lookup request | used |
| `0x22` | `KADEMLIA2_HELLO_RES_ACK` | both | `HELLO_RES` | hello acknowledgement | codec |
| `0x29` | `KADEMLIA2_RES` | in | `REQ` | closest-contact response | used |
| `0x33` | `KADEMLIA2_SEARCH_KEY_REQ` | out | `SEARCH_RES` | keyword search request | used |
| `0x34` | `KADEMLIA2_SEARCH_SOURCE_REQ` | out | `SEARCH_RES` | file source search request | used |
| `0x35` | `KADEMLIA2_SEARCH_NOTES_REQ` | out | `SEARCH_RES` | file notes search request | used |
| `0x3B` | `KADEMLIA2_SEARCH_RES` | in | search requests | search result packet for keyword, source, or notes flows | used |
| `0x43` | `KADEMLIA2_PUBLISH_KEY_REQ` | out | `PUBLISH_RES` | publish keyword index entries | used |
| `0x44` | `KADEMLIA2_PUBLISH_SOURCE_REQ` | out | `PUBLISH_RES` | publish source availability for a file | used |
| `0x45` | `KADEMLIA2_PUBLISH_NOTES_REQ` | out | `PUBLISH_RES` | publish note/rating for a file | used |
| `0x4B` | `KADEMLIA2_PUBLISH_RES` | in | publish requests | publish acknowledgement with load byte | used |
| `0x4C` | `KADEMLIA2_PUBLISH_RES_ACK` | both | `PUBLISH_RES` | publish ack acknowledgement | codec |
| `0x50` | `KADEMLIA2_FIREWALLED_REQ` | both | `FIREWALLED_RES` | firewall-related request carrying TCP port | codec |
| `0x51` | `KADEMLIA2_FINDBUDDY_REQ` | both | `FINDBUDDY_RES` | buddy discovery for firewalled mode | reserved |
| `0x52` | `KADEMLIA2_CALLBACK_REQ` | both | none | buddy callback request | reserved |
| `0x58` | `KADEMLIA2_FIREWALLED_RES` | both | `FIREWALLED_REQ` | firewall-related response carrying IP | codec |
| `0x59` | `KADEMLIA2_FIREWALLED_ACK_RES` | both | `FIREWALLED_RES` | empty acknowledgement | codec |
| `0x5A` | `KADEMLIA2_FINDBUDDY_RES` | both | `FINDBUDDY_REQ` | buddy discovery response | reserved |
| `0x60` | `KADEMLIA2_PING` | both | `PONG` | liveness check | used |
| `0x61` | `KADEMLIA2_PONG` | both | `PING` | liveness response | used |
| `0x62` | `KADEMLIA2_FIREWALLUDP` | both | none | UDP firewall test packet | codec |

Notes:

- The opcode corrections in this pass were the important search-family fixes:
  - `SEARCH_SOURCE_REQ = 0x34`
  - `SEARCH_NOTES_REQ = 0x35`
- `REQ`/`RES` are the iterative lookup backbone.
- Search and publish logic ride on top of that lookup layer.

## 4. Core Packet Layouts

All layouts below are little-endian for multi-byte integer fields.

### `KADEMLIA2_REQ` (`0x21`)

Purpose:
- iterative node/value/store lookup request

Layout:

| Field | Size | Meaning |
|---|---:|---|
| `count` | 1 | request type / count selector used by eMule Kad logic |
| `target` | 16 | lookup target ID |
| `recipient_id` | 16 | node ID we believe the recipient has |

Notes:

- `recipient_id` is a sanity guard; a recipient may drop the packet if it is not its own ID.
- This repo currently uses `REQ` in traversal before the actual search/store phase.

### `KADEMLIA2_RES` (`0x29`)

Purpose:
- closest-node response to `REQ`

Layout:

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | echoed lookup target |
| `count` | 1 | number of contacts |
| `contacts[count]` | 25 each | contact entries |

Contact entry layout:

| Field | Size | Meaning |
|---|---:|---|
| `node_id` | 16 | Kad node ID |
| `ip` | 4 | IPv4 as packed `u32` |
| `udp_port` | 2 | Kad UDP port |
| `tcp_port` | 2 | eD2k TCP port |
| `version` | 1 | Kad version byte |

### `KADEMLIA2_SEARCH_KEY_REQ` (`0x33`)

Purpose:
- keyword search request

Verified eMule/aMule layout:

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | keyword hash |
| `start_position` | 2 | paging / expression selector |

`start_position` meaning:

- `0x0000` to `0x7FFF`: normal start-position window
- `0x8000` to `0xFFFF`: signals that search-expression bytes follow instead of a plain page offset

Repo policy:

- the current Overlord Kad runtime currently sends `0` only
- expression payloads and start-position pagination are still pending work

Oracle anchors:

- eMule `srchybrid/kademlia/net/KademliaUDPListener.cpp Process_KADEMLIA2_SEARCH_KEY_REQ`
- eMule `srchybrid/kademlia/kademlia/Search.cpp CSearch::StorePacket`
- aMule `src/kademlia/net/KademliaUDPListener.cpp Process2SearchKeyRequest`
- aMule `src/kademlia/kademlia/Search.cpp CSearch::StorePacket`

### `KADEMLIA2_SEARCH_SOURCE_REQ` (`0x34`)

Purpose:
- ask a close node for sources of a known file

Verified eMule/aMule layout:

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | file hash, treated as Kad target ID |
| `start_position` | 2 | source-result page start |
| `size` | 8 | exact file size |

Important:

- the file size is required on the wire
- this was one of the critical mismatches fixed in this pass

Repo policy:

- the agent/coordinator contract stays hash-only
- `overlord-agent-emule` resolves `size` from coordinator-backed knowledge before starting the DHT search
- if the file is unknown to the current indexing plane or indexed as size `0`, the request should fail early
- `start_position` currently stays `0`

Oracle anchors:

- eMule `srchybrid/kademlia/net/KademliaUDPListener.cpp Process_KADEMLIA2_SEARCH_SOURCE_REQ`
- eMule `srchybrid/kademlia/kademlia/Search.cpp CSearch::StorePacket`
- aMule `src/kademlia/net/KademliaUDPListener.cpp Process2SearchSourceRequest`
- aMule `src/kademlia/kademlia/Search.cpp CSearch::StorePacket`

### `KADEMLIA2_SEARCH_NOTES_REQ` (`0x35`)

Purpose:
- ask a close node for notes/comments/ratings of a known file

Verified eMule/aMule layout:

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | file hash, treated as Kad target ID |
| `size` | 8 | exact file size |

Important:

- notes search also requires the exact file size on the wire
- this was the second critical search-layout fix in this pass

Repo policy:

- same hash-only API rule as source search
- the node resolves size from the local index
- unknown or zero-size entries are rejected before any Kad packet is sent

Oracle anchors:

- eMule `srchybrid/kademlia/net/KademliaUDPListener.cpp Process_KADEMLIA2_SEARCH_NOTES_REQ`
- eMule `srchybrid/kademlia/kademlia/Search.cpp CSearch::StorePacket`
- aMule `src/kademlia/net/KademliaUDPListener.cpp Process2SearchNotesRequest`
- aMule `src/kademlia/kademlia/Search.cpp CSearch::StorePacket`

### `KADEMLIA2_SEARCH_RES` (`0x3B`)

Purpose:
- carries search results for keyword, source, and notes searches

Verified eMule/aMule wire layout matched by this repo:

| Field | Size | Meaning |
|---|---:|---|
| `sender_id` | 16 | Kad ID of the responding node |
| `target` | 16 | echoed search target |
| `count` | 2 | result count |
| `results[count]` | variable | search result entries |

Search result entry layout:

| Field | Size | Meaning |
|---|---:|---|
| `entry_id` | 16 | interpretation depends on search family |
| `tag_count` | 1 | number of tags in this result |
| `tags[tag_count]` | variable | typed Kad tags |

Interpretation of `entry_id`:

- keyword search: file hash
- source search: source/client-related 128-bit ID, not the searched file hash
- notes search: note author/source ID

Important repo note:

- the Rust struct currently names the echoed target field `keyword_id`
- that name is narrower than the wire reality
- for source and notes searches it is still the echoed file-hash target, not a keyword-only concept

Oracle anchors:

- eMule `srchybrid/kademlia/net/KademliaUDPListener.cpp Process_KADEMLIA2_SEARCH_RES`
- eMule `srchybrid/kademlia/kademlia/Indexed.cpp SendValidKeywordResult`
- eMule `srchybrid/kademlia/kademlia/Indexed.cpp SendValidSourceResult`
- eMule `srchybrid/kademlia/kademlia/Indexed.cpp SendValidNoteResult`
- aMule `src/kademlia/net/KademliaUDPListener.cpp Process2SearchResponse`
- aMule `src/kademlia/kademlia/Indexed.cpp SendValidKeywordResult`
- aMule `src/kademlia/kademlia/Indexed.cpp SendValidSourceResult`
- aMule `src/kademlia/kademlia/Indexed.cpp SendValidNoteResult`

### `KADEMLIA2_PUBLISH_KEY_REQ` (`0x43`)

Purpose:
- publish keyword index entries to close nodes

Verified layout:

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | keyword hash target |
| `count` | 2 | number of published entries |
| `entries[count]` | variable | published file entries |

Publish entry layout:

| Field | Size | Meaning |
|---|---:|---|
| `hash` | 16 | published file hash |
| `tag_count` | 1 | number of tags |
| `tags[tag_count]` | variable | file metadata tags |

### `KADEMLIA2_PUBLISH_SOURCE_REQ` (`0x44`)

Purpose:
- publish source availability for a file

Verified wire shape in this repo and eMule send path:

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | file hash target |
| `publisher_id` | 16 | publisher client hash / source identifier |
| `tag_count` | 1 | number of tags |
| `tags[tag_count]` | variable | source metadata tags |

Important caution:

- the current Rust field name is `publisher_id`
- eMule uses the sender's Kad identity in this position, not the file hash again
- the current Rust send path now matches that oracle behavior

### `KADEMLIA2_PUBLISH_NOTES_REQ` (`0x45`)

Purpose:
- publish note/rating metadata for a file

Verified wire shape in this repo and eMule send path:

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | file hash target |
| `author_id` | 16 | publisher Kad ID |
| `tag_count` | 1 | number of tags |
| `tags[tag_count]` | variable | note tags |

Important caution:

- the current Rust field name is `note_hash`
- eMule writes the publisher Kad ID here
- the current Rust public API still implies a note-hash style value even though the oracle semantics are publisher identity
- end-to-end notes publish parity is still `Pending`

### `KADEMLIA2_PUBLISH_RES` (`0x4B`)

Purpose:
- acknowledge a publish request

Layout:

| Field | Size | Meaning |
|---|---:|---|
| `target` | 16 | echoed publish target |
| `load` | 1 | remote-side load / acceptance hint |

### Search And Publish Runtime Notes

- `Verified`: restrictive keyword mode is not just a flag bit. Oracle receive paths immediately parse a trailing search-expression tree via `CreateSearchExpressionTree` when `start_position & 0x8000 != 0`.
- `Equivalent behavior, different implementation`: both eMule and aMule may emit multiple `KADEMLIA2_SEARCH_RES` packets for one request. eMule `kademlia/Indexed.cpp SendValid*Result` fragments on byte budget, while aMule `kademlia/Indexed.cpp SendValid*Result` sends fixed 50-result chunks.
- `Verified difference (oracles)`: `net/PacketTracking.cpp` is not identical for publish opcodes. eMule allows 4/3/2 requests per minute for publish key/source/notes; aMule allows 3/2/2.
- `Pending parity gap (Rust runtime)`: `crates/overlord-kad-net/src/rpc.rs` and `crates/overlord-kad-net/src/tracker.rs` currently apply generic per-IP flood blocking instead of oracle per-IP, per-opcode request tracking.

## 5. Verified Tag Registry For Search And Publish

The table below focuses on Kad tags that matter directly to this repo's current search and publish work.

| ID | Canonical Name In Overlord Kad Code | Type | Meaning | Typical Appearance |
|---|---|---|---|---|
| `0x01` | `FILENAME` | string | file name | keyword results, notes publish |
| `0x02` | `FILESIZE` | uint32 or uint64 | file size low part or full size | keyword results, source publish, notes publish |
| `0x03` | `FILETYPE` | string | coarse file type | keyword results, keyword publish |
| `0x04` | `FILEFORMAT` | string | format / subtype | keyword results, keyword publish |
| `0x0B` | `DESCRIPTION` | string | note/comment text | notes results, notes publish |
| `0x15` | `SOURCES` | uint32 | complete source count | keyword results, keyword publish |
| `0x3A` | `FILESIZE_HI` | uint32 | high 32 bits for large-file size | keyword results |
| `0xD0` | `MEDIA_ARTIST` | string | media metadata | keyword publish/results |
| `0xD1` | `MEDIA_ALBUM` | string | media metadata | keyword publish/results |
| `0xD2` | `MEDIA_TITLE` | string | media metadata | keyword publish/results |
| `0xD3` | `MEDIA_LENGTH` | uint32 | media duration | keyword publish/results |
| `0xD4` | `MEDIA_BITRATE` | uint32 | media bitrate | keyword publish/results |
| `0xD5` | `MEDIA_CODEC` | string | codec | keyword publish/results |
| `0xF7` | `FILERATING` | uint8 | file note rating | notes results, notes publish |
| `0xFC` | `SOURCEUPORT` | uint16 | Kad UDP port of a source | source results, source publish |
| `0xFD` | `SOURCEPORT` | uint16 | TCP port of a source | source results, source publish |
| `0xFE` | `SOURCEIP` | uint32 | IPv4 of a source | source results |
| `0xFF` | `SOURCETYPE` | uint8 | source reachability/type | source results, source publish |

### Common Traps

#### `SOURCES` is not a local-only “availability” tag code

Verified:

- eMule and aMule use `TAG_SOURCES = 0x15`
- this repo now parses that tag into `SearchResult.availability`

Repo note:

- the public Rust field is still named `availability` to avoid wider churn
- the wire meaning comes from `TAG_SOURCES`

#### `DESCRIPTION` is the note/comment tag

Verified:

- note comments travel as `TAG_DESCRIPTION = 0x0B`
- the old local `COMMENT` mapping was wrong for Kad search/notes parsing

#### `FILERATING` is not `0x15`

Verified:

- `TAG_FILERATING = 0xF7`
- `0x15` is `TAG_SOURCES`

#### Source-result tags live in the high numeric range

Verified:

- `TAG_SOURCEUPORT = 0xFC`
- `TAG_SOURCEPORT = 0xFD`
- `TAG_SOURCEIP = 0xFE`
- `TAG_SOURCETYPE = 0xFF`

This is one reason the old `0x21` / `0x22` / `0x23` mapping broke interoperability.

#### Large-file size is split

Verified:

- `FT_FILESIZE` can carry the low 32 bits
- `FT_FILESIZE_HI = 0x3A` carries the high 32 bits

Repo behavior:

- `overlord-kad-dht` combines the two into one `u64`

## 6. Search Semantics

### Keyword Target Derivation

Verified from eMule behavior:

- keyword search targets are derived from the first significant word
- the full search expression may still matter for filtering and optional extra request data

Pending:

- the current Overlord Kad runtime hashes the first significant word and sends a plain `SearchKeyReq`
- full expression serialization is not yet at eMule parity

Repo policy:

- the Overlord Kad runtime is an indexer-first implementation
- keyword searches intentionally collect broadly and defer narrowing/filtering until after indexing
- the daemon therefore does not apply local query-word post-filtering by default

### Keyword `start_position` And Expression Mode

Verified from `Search.cpp`:

- `0x0000..0x7FFF`: page position
- `0x8000`: expression-data mode in Kad2 request path

Repo behavior:

- current implementation always sends `0`
- true numeric start-position pagination remains pending
- this is intentional: the repo stays on the parity-safe request shape and does not invent
  speculative page-walking beyond what was clearly verified in eMule/aMule

### Source Search Requires File Size

Verified from eMule and aMule:

- source search packets include the exact file size
- eMule aborts if it cannot find the referenced file and therefore cannot serialize the size

Repo policy:

- external API remains `{"hash":"..."}` only
- local index is the authoritative source for `size`
- if there is no local indexed file row, source search is rejected
- if the local row exists but `size == 0`, source search is rejected

### Notes Search Requires File Size

Verified from eMule and aMule:

- notes search packets include the exact file size

Repo policy:

- same hash-only API behavior as source search
- local `files.size` must be present and non-zero before any notes search starts

### `SEARCH_RES` Result Interpretation

Keyword results:

- `entry_id` is the file hash
- tags describe the file
- this repo extracts file names, size, source count, and keeps raw tags

Source results:

- `entry_id` is not the searched file hash
- relevant tags are `SOURCEIP`, `SOURCEPORT`, `SOURCEUPORT`, and `SOURCETYPE`
- this repo currently keeps `file_hash` from the search target and extracts IP/ports from tags
- if `SOURCEUPORT` is absent, `udp_port` falls back to `tcp_port`

Notes results:

- `entry_id` identifies the note author/source
- relevant tags are `DESCRIPTION` and `FILERATING`
- this repo now persists that `entry_id` as note `author_hash`

### Search Tolerance

Verified eMule constant:

- `SEARCHTOLERANCE = 0x0100_0000` on the high 32 bits of XOR distance

Status:

- the constant exists in `overlord-kad-proto`
- the current traversal code now enforces eMule's `SEARCHTOLERANCE` gate before sending phase-2
  search packets, with the same LAN exemption idea
- implementation detail that matters: the comparison must use the first XOR chunk in eMule's
  little-endian chunk order (`CUInt128::Get32BitChunk(0)` semantics), not network-byte order

Repo policy:

- unlike eMule's UI-oriented search manager, the Overlord Kad runtime does not stop phase 2 at the closest `K`
- after applying `SEARCHTOLERANCE`, it caps phase 2 at the oracle's closest `K` responders
- `search_phase2_fanout` can still lower that ceiling for tests or stricter runs

Scope note:

- passive replay / harvest of unsolicited Kad demand is an Overlord indexer extension; eMule is only the oracle for the underlying source-search packet cadence, contact ordering, and `SEARCH_RES` handling once such a search is emitted

### Search Result Acceptance And Caps

Repo policy:

- keyword results are accepted when they contain the core fields needed for indexing:
  at least one filename and a filesize
- source results are accepted when they contain a valid IPv4 endpoint with nonzero TCP port
- notes results still require a usable rating or non-empty comment

Configured default caps:

- keyword results: `5000`
- source results: `1000`
- notes results: `1000`

Why this differs from eMule:

- eMule's search manager is optimized for interactive client searches and small result windows
- the Overlord Kad runtime is optimized for broad collection and later filtering in the coordinator/indexing plane

### Search Result String Decoding

Verified special case:

- `SEARCH_RES` strings are not decoded the same way as ordinary Kad strings in eMule/aMule
- for search results, eMule first tries UTF-8
- if the bytes are not valid UTF-8, it falls back to the local ANSI code page for display compatibility

Repo behavior:

- `overlord-kad-proto` mirrors that behavior for incoming `SEARCH_RES` tags only
- normal tag decoding elsewhere still uses the safer generic UTF-8-lossy path
- on Windows, fallback uses the current ACP
- on non-Windows, fallback uses Windows-1252 as the deterministic compatibility approximation

## 7. Publish Semantics

This section is intentionally split between verified wire facts and still-pending parity questions.

### Keyword Publish

Verified:

- `KADEMLIA2_PUBLISH_KEY_REQ` sends a target keyword hash plus one or more file entries
- each file entry contains the published file hash and a tag list
- eMule may batch multiple entries in one packet

Typical tags seen in keyword publish flows:

- `FILENAME`
- `FILESIZE`
- `FILETYPE`
- `FILEFORMAT`
- `SOURCES`
- media tags such as artist, album, title, bitrate, codec, length

Repo status:

- outbound keyword publish is implemented
- end-to-end acceptance against live eMule nodes still needs broader validation

### Source Publish

Verified from eMule send path:

- the publish target is the file hash
- the second 128-bit field is the publisher client hash
- source tag lists include `SOURCETYPE`, `SOURCEPORT`, optional `SOURCEUPORT`
- for sufficiently new peers, eMule also includes `FILESIZE`
- eMule also includes encryption capability tags in this flow

Verified source-type values used by eMule:

- `1`: high-ID source
- `3`: firewalled Kad source
- `4`: high-ID source for file > 4 GiB
- `5`: firewalled Kad source for file > 4 GiB
- `6`: firewalled source with direct callback support

Pending:

- this repo has not yet done a full publish-source semantic audit for buddy, callback, or encryption tags
- the Rust field name `publisher_id` now matches the sender-identity semantics used by eMule

### Notes Publish

Verified from eMule send path:

- target is the file hash
- second 128-bit field is the publisher Kad ID
- tag list may include:
  - `FILENAME`
  - `FILERATING`
  - `DESCRIPTION`
  - `FILESIZE` for Kad2-capable peers

Pending:

- the Rust field name `note_hash` is semantically misleading
- end-to-end interoperability for notes publish remains to be verified against live peers

### Publish Result

Verified:

- `PUBLISH_RES` carries the echoed target plus a one-byte load value

Pending:

- this repo currently treats publish acks mostly as success/failure for counting purposes
- deeper eMule load semantics are not yet modeled

## 8. Repo Policy Notes

These are intentional Overlord implementation decisions, not raw wire facts.

### Hash-Only Source And Notes API

API shape:

- `POST /api/v1/search/source { "hash": "..." }`
- `POST /api/v1/search/notes { "hash": "..." }`

Policy:

- the client does not provide `size`
- the daemon resolves `size` from the local index
- request fails early if the size is unavailable

Reason:

- this keeps the API minimal while still generating eMule-correct Kad2 packets

### Public Search Result Shape

Policy:

- `SearchResult.availability` stays named `availability`
- its value comes from `TAG_SOURCES`

Reason:

- preserves the existing public Rust/API shape while correcting the wire semantics

### Notes Result Persistence

Policy:

- the search-result entry ID for note searches is stored as `author_hash`

Reason:

- that matches how eMule treats the entry as the source/author identity for the note

## 9. Known Gaps / Still Unverified

The following are still not safe to treat as fully settled:

- full HELLO / HELLO_RES / HELLO_RES_ACK parity with eMule, especially around obfuscation registration
- source publish and notes publish semantic naming cleanup in Rust structs
- source-encryption and buddy/callback tag handling
- strict `SEARCHTOLERANCE` gating before sending phase-2 search packets
- keyword expression payloads and filename post-filtering parity
- start-position pagination for keyword and source search
- full live-network validation that remote eMule nodes accept all publish variants sent by this repo
- whether any additional version-gated tags should be filtered before exposing results

## 10. Reference Map

Use this section first when re-auditing a protocol area.

### eMule

- `c:\prj\p2p\eMule-my\deps-repos\eMule\srchybrid\Opcodes.h`
  - Kad2 UDP opcodes
  - Kad search/publish tag IDs
  - `FT_FILESIZE_HI`
- `c:\prj\p2p\eMule-my\deps-repos\eMule\srchybrid\kademlia\net\KademliaUDPListener.cpp`
  - search request parsing
  - search response parsing
  - HELLO / firewall / UDP-key handling
- `c:\prj\p2p\eMule-my\deps-repos\eMule\srchybrid\kademlia\kademlia\Search.cpp`
  - search request serialization
  - search result parsing
  - publish request serialization
  - source type semantics
- `c:\prj\p2p\eMule-my\deps-repos\eMule\srchybrid\kademlia\kademlia\Indexed.cpp`
  - `SEARCH_RES` emission
  - search result batching
  - keyword/source/notes result limits
- `c:\prj\p2p\eMule-my\deps-repos\eMule\srchybrid\kademlia\net\PacketTracking.cpp`
  - per-opcode inbound request throttling
- `c:\prj\p2p\eMule-my\deps-repos\eMule\srchybrid\kademlia\kademlia\Prefs.cpp`
  - UDP verify key derivation
- `c:\prj\p2p\eMule-my\deps-repos\eMule\srchybrid\kademlia\kademlia\SearchManager.cpp`
  - keyword preparation and duplicate-search policy
- `c:\prj\p2p\eMule-my\deps-repos\eMule\srchybrid\kademlia\kademlia\Defines.h`
  - search-related constants such as totals and `SEARCHTOLERANCE`

### aMule

- `c:\prj\p2p\amule\src\include\protocol\kad2\Client2Client\UDP.h`
  - Kad2 UDP opcode cross-check
- `c:\prj\p2p\amule\src\include\tags\FileTags.h`
  - Kad search/publish tag IDs
- `c:\prj\p2p\amule\src\kademlia\net\KademliaUDPListener.cpp`
  - portable cross-check for search/publish parsing
  - HELLO / firewall / UDP-key handling
- `c:\prj\p2p\amule\src\kademlia\kademlia\Search.cpp`
  - portable cross-check for search serialization and parsing
- `c:\prj\p2p\amule\src\kademlia\kademlia\Indexed.cpp`
  - portable cross-check for `SEARCH_RES` emission
- `c:\prj\p2p\amule\src\kademlia\net\PacketTracking.cpp`
  - portable cross-check for inbound request throttling
- `c:\prj\p2p\amule\src\kademlia\kademlia\Prefs.cpp`
  - UDP verify key derivation

### Overlord Kad Implementation

- `crates/overlord-kad-proto/src/constants.rs`
  - local opcode and tag registry
- `crates/overlord-kad-proto/src/packet.rs`
  - Rust wire layouts
- `crates/overlord-kad-proto/src/tag.rs`
  - tag encode/decode and helper constructors
- `crates/overlord-kad-net/src/rpc.rs`
  - current unsolicited packet and flood-tracking policy
- `crates/overlord-kad-net/src/obfuscation.rs`
  - current UDP obfuscation implementation
- `crates/overlord-kad-dht/src/traversal.rs`
  - search-phase request emission
- `crates/overlord-kad-dht/src/publish.rs`
  - current publish request emission
- `crates/overlord-kad-dht/src/types.rs`
  - keyword/source/notes result decoding
- `crates/overlord-agent-emule/src/agent.rs`
  - agent-side search dispatch, result posting, and coordinator integration policy
