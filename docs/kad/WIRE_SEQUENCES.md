# Kad and ED2K Wire Sequences

Detailed sequence diagrams for every significant protocol exchange in the Overlord Kad2 and ED2K implementations.

Oracle authority: eMule `KademliaUDPListener.cpp`, `Search.cpp`, `Indexed.cpp`, `PacketTracking.cpp`, `RoutingBin.cpp`, `RoutingZone.cpp`.

All UDP packets are prefixed with `0xE4` (plain) or obfuscated (RC4). All packet names use the short form without the `KADEMLIA2_` prefix for readability.

---

## Table of Contents

1. [Bootstrap](#1-bootstrap)
2. [Hello Handshake](#2-hello-handshake)
3. [Node Lookup — Iterative Find Node](#3-node-lookup--iterative-find-node)
4. [Keyword Search — Full Flow](#4-keyword-search--full-flow)
5. [Source Search — Full Flow](#5-source-search--full-flow)
6. [Notes Search — Full Flow](#6-notes-search--full-flow)
7. [Keyword Publish](#7-keyword-publish)
8. [Source Publish](#8-source-publish)
9. [Notes Publish](#9-notes-publish)
10. [Firewall Check (Kad)](#10-firewall-check-kad)
11. [UDP Firewall Test](#11-udp-firewall-test)
12. [Ping / Pong Liveness](#12-ping--pong-liveness)
13. [Passive Snoop — Unsolicited Search Request](#13-passive-snoop--unsolicited-search-request)
14. [Obfuscation Key Setup Across Sessions](#14-obfuscation-key-setup-across-sessions)
15. [ED2K Server — Login and Session Keepalive](#15-ed2k-server--login-and-session-keepalive)
16. [ED2K Server — ID Assignment and High-ID Confirmation](#16-ed2k-server--id-assignment-and-high-id-confirmation)
17. [Full Combined Startup Sequence](#17-full-combined-startup-sequence)

---

## Notation

```
Participant roles used throughout:

  US      = Overlord Rust node (our node)
  PEER    = Remote Kad2 node on the live network
  PEER_A  = First remote Kad2 node queried during traversal
  PEER_B  = Second remote Kad2 node queried during traversal
  PEER_C  = Third remote Kad2 node (and so on)
  CLOSE_N = A node identified as close to the target during traversal
  SRV     = eD2k TCP server

Arrow styles:
  ->>     = UDP packet sent (fire and forget)
  -->>    = UDP packet received
  ->      = TCP segment sent
  <-      = TCP segment received
  note    = inline annotation explaining wire fields or oracle behavior
```

---

## 1. Bootstrap

Bootstrap is the first step after loading `nodes.dat`. The node picks one or more seed contacts and sends `BOOTSTRAP_REQ`. The response carries the responder's own info plus up to a configurable number of additional contacts.

```
US                                          PEER
|                                              |
|  BOOTSTRAP_REQ  (0xE4 0x01)                 |
|  payload: (empty)                            |
| -------------------------------------------> |
|                                              |
|                                              | note: PEER calls ProcessBootstrapRequest.
|                                              |       Gathers closest K contacts from its
|                                              |       routing table and appends them.
|                                              |
|  BOOTSTRAP_RES  (0xE4 0x09)                 |
|  sender_id:         [16 bytes] PEER node ID  |
|  sender_tcp_port:   [2 bytes]  PEER TCP port |
|  sender_version:    [1 byte]   Kad version   |
|  count:             [2 bytes]  N contacts    |
|  contacts[0..N]:    [25 each]                |
|    node_id:         [16 bytes]               |
|    ip:              [4 bytes]  IPv4 u32 LE   |
|    udp_port:        [2 bytes]                |
|    tcp_port:        [2 bytes]                |
|    version:         [1 byte]   Kad version   |
| <------------------------------------------- |
|                                              |
| note: US adds PEER and all N contacts to     |
|       its routing table.                     |
|       Triggers zone refresh once table has   |
|       at least 1 contact.                    |
|       Proceeds to send HELLO_REQ to each     |
|       newly learned contact to build         |
|       obfuscation context (see §2).          |
```

Bootstrap is repeated with additional seed contacts if the routing table remains too sparse after the first round. The Rust bootstrap logic in `overlord-kad-dht/src/bootstrap.rs` retries until the table reaches a minimum size.

---

## 2. Hello Handshake

The HELLO exchange is the three-way handshake used to:

- Announce our presence and Kad version to a peer
- Exchange UDP verify keys used for obfuscation
- Establish a verified contact in the routing table

In the oracle, the sender verify key travels in the obfuscation trailer (not in the packet payload). `HELLO_RES_ACK` closes the exchange and confirms mutual verification.

```
US                                          PEER
|                                              |
| note: US wants to introduce itself to PEER   |
|       and build obfuscation context.         |
|                                              |
|  HELLO_REQ  (0xE4 0x11)                     |
|  node_id:      [16 bytes] our Kad ID         |
|  tcp_port:     [2 bytes]  our TCP port       |
|  version:      [1 byte]   KAD_VERSION = 9   |
|  tag_count:    [1 byte]                      |
|  tags[]:       capability tags               |
|    TAG_KADMISCOPTIONS (0xF2): capability bits|
|    TAG_ENCRYPTION (0xF3):     encryption cap |
| -------------------------------------------> |
|                                              |
|                                              | note: PEER calls ProcessHelloRequest.
|                                              |       Extracts our sender verify key from
|                                              |       the obfuscation trailer.
|                                              |       Adds or updates US in its routing table.
|                                              |
|  HELLO_RES  (0xE4 0x19)                     |
|  node_id:      [16 bytes] PEER Kad ID        |
|  tcp_port:     [2 bytes]  PEER TCP port      |
|  version:      [1 byte]   PEER Kad version   |
|  tag_count:    [1 byte]                      |
|  tags[]:       PEER capability tags          |
| <------------------------------------------- |
|                                              |
| note: US extracts PEER sender verify key     |
|       from the obfuscation trailer.          |
|       Stores it as PEER's KadUdpKey in the   |
|       routing table contact entry.           |
|       Subsequent packets to PEER use this    |
|       key for obfuscation instead of the     |
|       NodeID-derived key.                    |
|                                              |
|  HELLO_RES_ACK  (0xE4 0x22)                 |
|  node_id:      [16 bytes] our Kad ID         |
|  tag_count:    [1 byte]   0 (empty list)     |
| -------------------------------------------> |
|                                              |
|                                              | note: PEER marks US as verified.
|                                              |       Three-way exchange complete.
```

After this exchange, both sides can use the verified UDP key for all subsequent obfuscated packets to each other. Keys are persisted in `nodes.dat` so the next session can start obfuscated immediately without repeating the HELLO exchange.

---

## 3. Node Lookup — Iterative Find Node

The iterative node lookup is the backbone of all Kad2 DHT operations. It finds the K nodes closest to a target ID. This same traversal is reused for keyword search, source search, notes search, and all publish flows — the difference is what is sent to the closest nodes once they are found.

ALPHA = 3 parallel queries are sent at each round.

```
US              PEER_A              PEER_B              PEER_C
|                  |                   |                   |
| note: US picks K closest contacts   |                   |
|       to TARGET from local routing  |                   |
|       table. Sorts by XOR distance. |                   |
|       Sends REQ to ALPHA=3 closest  |                   |
|       unqueried contacts.           |                   |
|                  |                   |                   |
|  REQ  (0xE4 0x21)|                   |                   |
|  count:      [1 byte]  FIND_NODE=0x0B or FIND_VALUE=0x02|
|  target:     [16 bytes] lookup TARGET ID                 |
|  recipient_id:[16 bytes] PEER_A's node ID (sanity check) |
| ---------------> |                   |                   |
|                  |                   |                   |
|  REQ  (0xE4 0x21)|                   |                   |
|  count / target / recipient_id (PEER_B's ID)             |
| ---------------------------------> |                    |
|                  |                   |                   |
|  REQ  (0xE4 0x21)                    |                   |
|  count / target / recipient_id (PEER_C's ID)             |
| --------------------------------------------> |          |
|                  |                   |                   |
|                  | note: Each PEER looks up the K closest|
|                  |       contacts it knows to TARGET and |
|                  |       returns them. If recipient_id   |
|                  |       does not match its own ID, the  |
|                  |       packet is dropped.              |
|                  |                   |                   |
|  RES  (0xE4 0x29)|                   |                   |
|  target:    [16 bytes] echoed TARGET |                   |
|  count:     [1 byte]   M contacts    |                   |
|  contacts[0..M]: [25 each]           |                   |
| <--------------- |                   |                   |
|                  |                   |                   |
|  RES  (0xE4 0x29)                    |                   |
|  target / count / contacts[]         |                   |
| <--------------------------------- |                    |
|                  |                   |                   |
|  RES  (0xE4 0x29)                                        |
|  target / count / contacts[]                             |
| <-------------------------------------------- |          |
|                  |                   |                   |
| note: US merges all returned contacts into    |          |
|       its closest-set for TARGET.             |          |
|       Any contacts closer than the current    |          |
|       K-closest are added to the unqueried    |          |
|       set.                                    |          |
|       Sends REQ to next ALPHA=3 unqueried     |          |
|       contacts.                               |          |
|       Repeat until no closer nodes are found  |          |
|       or all K closest have been queried.     |          |
|                  |                   |                   |
| note: SEARCHTOLERANCE gate (search flows only):          |
|       Before sending SEARCH_*_REQ to a node, US checks  |
|       that the XOR distance to TARGET satisfies          |
|       distance.get_chunk(0) < SEARCHTOLERANCE=0x01000000 |
|       where get_chunk(0) is the first 32-bit chunk in    |
|       eMule little-endian chunk order.                   |
|       LAN contacts (RFC1918) are exempt from this gate.  |
```

---

## 4. Keyword Search — Full Flow

A keyword search runs the node lookup (§3) and, once nodes are close enough to the target (SEARCHTOLERANCE check), sends `SEARCH_KEY_REQ` to each qualifying node. Results arrive asynchronously as `SEARCH_RES` from any of those nodes.

```
Coordinator/Agent       US                          CLOSE_N
       |                  |                              |
       |  POST /search/keyword { "keyword": "..." }      |
       | ----------------> |                             |
       |                   |                             |
       |                   | note: US derives the target  |
       |                   |       by hashing the first   |
       |                   |       significant keyword    |
       |                   |       word with MD4.         |
       |                   |       Starts node lookup     |
       |                   |       toward TARGET.         |
       |                   |       (§3 iterative find)    |
       |                   |                              |
       |                   | note: For each queried node  |
       |                   |       that passes the        |
       |                   |       SEARCHTOLERANCE gate:  |
       |                   |                              |
       |  SEARCH_KEY_REQ  (0xE4 0x33)                    |
       |                   |                              |
       |                   |  target:         [16 bytes]  |
       |                   |    keyword hash (MD4)         |
       |                   |  start_position: [2 bytes]   |
       |                   |    currently always 0x0000   |
       |                   |    (0x8000+ = expression mode|
       |                   |     not yet used by Overlord)|
       |                   | ---------------------------> |
       |                   |                              |
       |                   |                              | note: CLOSE_N calls
       |                   |                              |       Process_KADEMLIA2_SEARCH_KEY_REQ.
       |                   |                              |       Looks up indexed keyword entries.
       |                   |                              |       Fragments results on byte budget
       |                   |                              |       (eMule: UDP_KAD_MAXFRAGMENT).
       |                   |                              |       May send multiple SEARCH_RES
       |                   |                              |       packets for one request.
       |                   |                              |
       |  SEARCH_RES  (0xE4 0x3B)  [may repeat]          |
       |                   |                              |
       |                   |  sender_id:  [16 bytes]      |
       |                   |    CLOSE_N Kad ID            |
       |                   |  keyword_id: [16 bytes]      |
       |                   |    echoed target (keyword hash)
       |                   |  count:      [2 bytes]       |
       |                   |  results[0..count]:          |
       |                   |    hash:      [16 bytes]     |
       |                   |      file hash               |
       |                   |    tag_count: [1 byte]       |
       |                   |    tags[]:                   |
       |                   |      TAG_FILENAME (0x01)     |
       |                   |      TAG_FILESIZE (0x02)     |
       |                   |      TAG_FILESIZE_HI (0x3A)  |
       |                   |      TAG_FILETYPE (0x03)     |
       |                   |      TAG_FILEFORMAT (0x04)   |
       |                   |      TAG_SOURCES (0x15)      |
       |                   |      TAG_MEDIA_* (0xD0–0xD5) |
       |                   | <--------------------------- |
       |                   |                              |
       |                   | note: US accepts result if   |
       |                   |       it has at least one    |
       |                   |       FILENAME and a non-zero|
       |                   |       FILESIZE.              |
       |                   |       Combines FILESIZE_HI   |
       |                   |       and FILESIZE into u64. |
       |                   |       SOURCES becomes the    |
       |                   |       public availability    |
       |                   |       field.                 |
       |                   |       String tags decoded    |
       |                   |       UTF-8 first, then      |
       |                   |       Windows-1252 fallback. |
       |                   |                              |
       | POST /results (batch)                            |
       | <---------------- |                              |
       |                   |                              |
       | note: Search continues until SEARCH_TIMEOUT_SECS |
       |       (45 s) or no closer nodes remain.          |
       |       Result cap: 5000 keyword results.          |
```

---

## 5. Source Search — Full Flow

Source search finds peers who have a known file (by its ED2K hash). It requires the exact file size on the wire. The daemon resolves the size from the local files index before any packet is sent.

```
Coordinator/Agent       US                          CLOSE_N
       |                  |                              |
       | POST /search/source { "hash": "..." }           |
       | ----------------> |                             |
       |                   |                             |
       |                   | note: US resolves file size |
       |                   |       from local files index.|
       |                   |       If file unknown or    |
       |                   |       size == 0:            |
       |                   |       return 400, stop.     |
       |                   |                             |
       |                   | note: TARGET = file hash.   |
       |                   |       Starts node lookup    |
       |                   |       toward TARGET. (§3)   |
       |                   |                             |
       |  SEARCH_SOURCE_REQ  (0xE4 0x34)                |
       |                   |                             |
       |                   |  target:         [16 bytes] |
       |                   |    file hash (ED2K/MD4)     |
       |                   |  start_position: [2 bytes]  |
       |                   |    currently always 0x0000  |
       |                   |  size:           [8 bytes]  |
       |                   |    exact file size (u64 LE) |
       |                   | --------------------------> |
       |                   |                             |
       |                   |                             | note: CLOSE_N calls
       |                   |                             |       Process_KADEMLIA2_SEARCH_SOURCE_REQ.
       |                   |                             |       Looks up source entries for the
       |                   |                             |       queried file hash.
       |                   |                             |       Validates size match.
       |                   |                             |       Returns source contact info.
       |                   |                             |
       |  SEARCH_RES  (0xE4 0x3B)  [may repeat]         |
       |                   |                             |
       |                   |  sender_id:  [16 bytes]     |
       |                   |    CLOSE_N Kad ID           |
       |                   |  keyword_id: [16 bytes]     |
       |                   |    echoed file hash (TARGET)|
       |                   |  count:      [2 bytes]      |
       |                   |  results[0..count]:         |
       |                   |    hash:      [16 bytes]    |
       |                   |      source/client ID       |
       |                   |      (NOT the file hash)    |
       |                   |    tag_count: [1 byte]      |
       |                   |    tags[]:                  |
       |                   |      TAG_SOURCEIP  (0xFE)   |
       |                   |      TAG_SOURCEPORT (0xFD)  |
       |                   |      TAG_SOURCEUPORT (0xFC) |
       |                   |      TAG_SOURCETYPE (0xFF)  |
       |                   | <-------------------------- |
       |                   |                             |
       |                   | note: US accepts result if  |
       |                   |       it has a valid IPv4   |
       |                   |       with non-zero TCP port.|
       |                   |       If SOURCEUPORT absent,|
       |                   |       udp_port = tcp_port.  |
       |                   |       Source type values:   |
       |                   |       1=highID,3=firewalled |
       |                   |       4=highID>4GB          |
       |                   |       5=firewalled>4GB      |
       |                   |       6=firewalled+callback |
       |                   |                             |
       | POST /results (batch)                           |
       | <---------------- |                             |
       |                   |                             |
       | note: Result cap: 1000 source results.          |
       |       Timeout: SEARCH_TIMEOUT_SECS = 45 s.      |
```

---

## 6. Notes Search — Full Flow

Notes search finds comments and ratings that peers have published for a known file. Like source search, it requires the exact file size on the wire.

```
Coordinator/Agent       US                          CLOSE_N
       |                  |                              |
       | POST /search/notes { "hash": "..." }            |
       | ----------------> |                             |
       |                   |                             |
       |                   | note: US resolves file size |
       |                   |       from local files index.|
       |                   |       If file unknown or    |
       |                   |       size == 0:            |
       |                   |       return 400, stop.     |
       |                   |                             |
       |                   | note: TARGET = file hash.   |
       |                   |       Starts node lookup    |
       |                   |       toward TARGET. (§3)   |
       |                   |                             |
       |  SEARCH_NOTES_REQ  (0xE4 0x35)                 |
       |                   |                             |
       |                   |  target: [16 bytes]         |
       |                   |    file hash (ED2K/MD4)     |
       |                   |  size:   [8 bytes]          |
       |                   |    exact file size (u64 LE) |
       |                   | --------------------------> |
       |                   |                             |
       |                   |                             | note: CLOSE_N calls
       |                   |                             |       Process_KADEMLIA2_SEARCH_NOTES_REQ.
       |                   |                             |       Returns note entries for the
       |                   |                             |       queried file.
       |                   |                             |
       |  SEARCH_RES  (0xE4 0x3B)  [may repeat]         |
       |                   |                             |
       |                   |  sender_id:  [16 bytes]     |
       |                   |    CLOSE_N Kad ID           |
       |                   |  keyword_id: [16 bytes]     |
       |                   |    echoed file hash (TARGET)|
       |                   |  count:      [2 bytes]      |
       |                   |  results[0..count]:         |
       |                   |    hash:      [16 bytes]    |
       |                   |      note author/source ID  |
       |                   |      (persisted as author_hash)
       |                   |    tag_count: [1 byte]      |
       |                   |    tags[]:                  |
       |                   |      TAG_DESCRIPTION (0x0B) |
       |                   |        note comment text    |
       |                   |      TAG_FILERATING (0xF7)  |
       |                   |        rating value (u8)    |
       |                   | <-------------------------- |
       |                   |                             |
       |                   | note: US accepts result if  |
       |                   |       it has a usable rating|
       |                   |       or non-empty comment. |
       |                   |       The entry hash is     |
       |                   |       stored as author_hash.|
       |                   |                             |
       | POST /results (batch)                           |
       | <---------------- |                             |
       |                   |                             |
       | note: Result cap: 1000 notes results.           |
       |       Timeout: SEARCH_TIMEOUT_SECS = 45 s.      |
       |                                                 |
       | CURRENT STATUS: active Kad notes search now     |
       | runs end to end through the coordinator and     |
       | agent runtime; the remaining gap is that note   |
       | results still collapse into file-centric output.|
```

---

## 7. Keyword Publish

Keyword publish announces a file under one or more keyword hashes so that peers searching by keyword can find it. The publisher first runs a node lookup to find the K closest nodes to each keyword hash, then sends `PUBLISH_KEY_REQ` to each.

```
US                                          CLOSE_N
|                                              |
| note: For each keyword derived from the      |
|       file's metadata (filename words,       |
|       artist, album, title, etc.):           |
|       TARGET = MD4(keyword)                  |
|       Find K closest contacts via §3.        |
|                                              |
|  PUBLISH_KEY_REQ  (0xE4 0x43)               |
|                                              |
|  target:    [16 bytes]                       |
|    keyword hash (TARGET)                     |
|  count:     [2 bytes]  N entries (usually 1) |
|  entries[0..N]:                              |
|    hash:      [16 bytes]                     |
|      published file hash                     |
|    tag_count: [1 byte]                       |
|    tags[]:                                   |
|      TAG_FILENAME   (0x01): file name        |
|      TAG_FILESIZE   (0x02): size low 32 bits |
|      TAG_FILESIZE_HI (0x3A): size high 32 b  |
|      TAG_FILETYPE   (0x03): e.g. "Audio"     |
|      TAG_FILEFORMAT (0x04): e.g. "mp3"       |
|      TAG_SOURCES    (0x15): source count     |
|      TAG_MEDIA_ARTIST  (0xD0)  (if present)  |
|      TAG_MEDIA_ALBUM   (0xD1)  (if present)  |
|      TAG_MEDIA_TITLE   (0xD2)  (if present)  |
|      TAG_MEDIA_LENGTH  (0xD3)  (if present)  |
|      TAG_MEDIA_BITRATE (0xD4)  (if present)  |
|      TAG_MEDIA_CODEC   (0xD5)  (if present)  |
| -------------------------------------------> |
|                                              |
|                                              | note: CLOSE_N stores the entry in its
|                                              |       keyword index under target hash.
|                                              |       Sends PUBLISH_RES.
|                                              |
|  PUBLISH_RES  (0xE4 0x4B)                   |
|                                              |
|  target: [16 bytes]  echoed keyword hash     |
|  load:   [1 byte]    CLOSE_N indexing load   |
| <------------------------------------------- |
|                                              |
| note: US increments publish-ack counter.     |
|       Load byte currently used for           |
|       success/failure accounting only.       |
|       Full oracle load-tracking not yet      |
|       modeled.                               |
|                                              |
| note: Republish is triggered after           |
|       REPUBLISH_INTERVAL_SECS = 18000 s.     |
|       Oracle behavior: eMule also republishes|
|       on file add (immediate) and on schedule.|
```

---

## 8. Source Publish

Source publish announces that our node has a copy of a specific file, so other peers can contact us to download it.

```
US                                          CLOSE_N
|                                              |
| note: TARGET = file hash.                    |
|       Find K closest contacts via §3.        |
|       For each qualifying CLOSE_N:           |
|                                              |
|  PUBLISH_SOURCE_REQ  (0xE4 0x44)            |
|                                              |
|  target:      [16 bytes]                     |
|    file hash (the file being published)      |
|  publisher_id: [16 bytes]                    |
|    our Kad node ID (publisher identity)      |
|    NOTE: oracle writes sender's Kad ID here, |
|    NOT the file hash again.                  |
|    Rust field is now correctly typed NodeId. |
|  tag_count:   [1 byte]                       |
|  tags[]:                                     |
|    TAG_SOURCETYPE (0xFF):                    |
|      1 = high-ID source                      |
|      3 = firewalled Kad source               |
|      4 = high-ID source, file > 4 GiB        |
|      5 = firewalled Kad source, file > 4 GiB |
|      6 = firewalled + direct callback        |
|    TAG_SOURCEPORT (0xFD): our TCP port        |
|    TAG_SOURCEUPORT (0xFC): our Kad UDP port  |
|      (omitted if == tcp port in some cases)  |
|    TAG_FILESIZE (0x02): for new Kad peers    |
| -------------------------------------------> |
|                                              |
|                                              | note: CLOSE_N stores our source entry
|                                              |       under the file hash in its
|                                              |       source index.
|                                              |
|  PUBLISH_RES  (0xE4 0x4B)                   |
|                                              |
|  target: [16 bytes]  echoed file hash        |
|  load:   [1 byte]    CLOSE_N source-index load
| <------------------------------------------- |
|                                              |
| note: Pending parity gap:                    |
|       encryption capability tags and         |
|       buddy/callback tags in source publish  |
|       have not been fully audited against    |
|       the oracle send path.                  |
```

---

## 9. Notes Publish

Notes publish sends a rating or comment about a file to the K closest nodes to that file's hash.

```
US                                          CLOSE_N
|                                              |
| note: TARGET = file hash being noted.        |
|       Find K closest contacts via §3.        |
|       For each qualifying CLOSE_N:           |
|                                              |
|  PUBLISH_NOTES_REQ  (0xE4 0x45)             |
|                                              |
|  target:       [16 bytes]                    |
|    file hash (file being rated/commented)    |
|  publisher_id: [16 bytes]                    |
|    our Kad node ID (publisher identity)      |
|    ORACLE + RUST: this is NodeId, not a file |
|    hash. The wire stays 16 bytes wide, but   |
|    the semantic meaning is publisher identity|
|    throughout the runtime and local store.   |
|  tag_count:    [1 byte]                      |
|  tags[]:                                     |
|    TAG_FILENAME    (0x01): file name          |
|    TAG_FILERATING  (0xF7): rating (u8)       |
|    TAG_DESCRIPTION (0x0B): comment text      |
|    TAG_FILESIZE    (0x02): for Kad2 peers    |
| -------------------------------------------> |
|                                              |
|                                              | note: CLOSE_N stores the note entry
|                                              |       under the file hash in its
|                                              |       notes index.
|                                              |
|  PUBLISH_RES  (0xE4 0x4B)                   |
|                                              |
|  target: [16 bytes]  echoed file hash        |
|  load:   [1 byte]    CLOSE_N notes-index load|
| <------------------------------------------- |
|                                              |
| note: Live validation uses the seed loop with|
|       notes publish enabled explicitly. The  |
|       default runtime keeps this path off.   |
```

---

## 10. Firewall Check (Kad)

The firewall check lets a node discover whether its TCP port is reachable from the outside. A remote peer tests it by attempting a TCP connection to the reported port.

```
US                                          PEER
|                                              |
| note: US suspects it may be firewalled or    |
|       wants to confirm TCP reachability.     |
|       US picks a Kad node to ask.            |
|                                              |
|  FIREWALLED_REQ  (0xE4 0x50)                |
|                                              |
|  tcp_port: [2 bytes]  our TCP port to test   |
| -------------------------------------------> |
|                                              |
|                                              | note: PEER records US's external IP
|                                              |       (from UDP source address) and
|                                              |       the reported TCP port.
|                                              |       PEER will attempt a TCP connection
|                                              |       to US at that IP:port.
|                                              |       PEER also prepares FIREWALLED_RES
|                                              |       carrying our external IP as seen
|                                              |       from PEER's perspective.
|                                              |
|  FIREWALLED_RES  (0xE4 0x58)                |
|                                              |
|  ip: [4 bytes]  our external IPv4 (u32 LE)  |
| <------------------------------------------- |
|                                              |
| note: US learns its external IP.             |
|       If the TCP connection from PEER        |
|       succeeds: US is not firewalled (HighID).|
|       If no TCP connection arrives:          |
|       US is firewalled (LowID).              |
|                                              |
|  FIREWALLED_ACK_RES  (0xE4 0x59)            |
|  payload: (empty)                            |
| -------------------------------------------> |
|                                              |
| note: Kad v7+ extended variant:              |
|       US can send FIREWALLED2_REQ (0x53)     |
|       instead, which also carries our        |
|       user hash and connect_options byte     |
|       for richer firewall probing.           |
```

---

## 11. UDP Firewall Test

`FIREWALLUDP` is sent by a remote node to test whether our UDP port is reachable. It carries an error code and the port it is testing.

```
PEER                                        US
|                                              |
|  FIREWALLUDP  (0xE4 0x62)                   |
|                                              |
|  error_code: [1 byte]                        |
|    0 = test packet, no error                 |
|  udp_port:   [2 bytes]                       |
|    the UDP port PEER is testing on our side  |
| -------------------------------------------> |
|                                              |
| note: US uses receipt of this packet to      |
|       confirm its UDP port is externally     |
|       reachable. No reply is expected.       |
|       The KadFirewallState in the agent is   |
|       updated based on this confirmation.    |
```

---

## 12. Ping / Pong Liveness

Ping/Pong is used to check whether a contact in the routing table is still alive, and to keep verified contacts from expiring.

```
US                                          PEER
|                                              |
| note: US has a contact that has not been     |
|       seen recently. It is marked Inactive   |
|       and eligible for a liveness probe.     |
|                                              |
|  PING  (0xE4 0x60)                          |
|  payload: (empty)                            |
| -------------------------------------------> |
|                                              |
|  PONG  (0xE4 0x61)                          |
|  payload: (empty)                            |
| <------------------------------------------- |
|                                              |
| note: US marks PEER contact as Active and    |
|       updates last_seen in the routing table.|
|       If no PONG arrives within timeout:     |
|       PEER is marked Dead and becomes        |
|       eligible for replacement by a fresher  |
|       contact.                               |
```

---

## 13. Passive Snoop — Unsolicited Search Request

The Overlord agent observes unsolicited `SEARCH_*_REQ` packets addressed to our node from the live network. These represent organic Kad search traffic that happens to route through us because our node is close to the searched hash. The agent harvests these for the coordinator without actively participating in the search.

```
REMOTE_PEER                 US (Overlord)             Coordinator
|                               |                           |
|  SEARCH_KEY_REQ  (0xE4 0x33) |                           |
|  target: [16 bytes] kw hash  |                           |
|  start_position: [2 bytes]   |                           |
|  restrictive_payload: [...]  |                           |
| ---------------------------> |                           |
|                               |                           |
|                               | note: US receives unsolicited|
|                               |       SEARCH_KEY_REQ.      |
|                               |       Logs the target hash  |
|                               |       and any restrictive   |
|                               |       payload bytes to the  |
|                               |       snoop queue.          |
|                               |                           |
|                               | note: US does NOT yet send  |
|                               |       SEARCH_RES back.      |
|                               |       Overlord is an indexer|
|                               |       not a Kad index node. |
|                               |                           |
|                               | POST /snoop/flush (batch) |
|                               | ------------------------> |
|                               |                           |
|                               |                           | note: Coordinator persists
|                               |                           |       the snooped target hashes
|                               |                           |       for later replay or
|                               |                           |       popularity tracking.
|                               |                           |
|                               | note: Pending parity gap:  |
|                               |       Snoop queue entries   |
|                               |       store only the target |
|                               |       hash. Oracle request  |
|                               |       details (restrictive  |
|                               |       expression, source    |
|                               |       pagination, notes size)|
|                               |       are not yet preserved |
|                               |       for faithful replay.  |
```

Same pattern applies to unsolicited `SEARCH_SOURCE_REQ` and `SEARCH_NOTES_REQ` packets.

---

## 14. Obfuscation Key Setup Across Sessions

This diagram shows how the RC4 obfuscation context is built and preserved so that a restarting node can immediately communicate with known peers using obfuscated transport.

```
                SESSION 1 (initial)

US                                          PEER
|                                              |
| note: US has no prior key for PEER.          |
|       Uses NodeID-derived RC4 key for the    |
|       initial request packet.               |
|                                              |
|  [RC4-obfuscated using NodeID key]           |
|  BOOTSTRAP_REQ or HELLO_REQ                  |
| -------------------------------------------> |
|                                              |
|                                              | note: PEER decrypts using US's NodeID.
|                                              |       Extracts the sender verify key
|                                              |       from the obfuscation trailer.
|                                              |       Stores it as US's UDP key.
|                                              |
|  [RC4-obfuscated using PEER's verify key]    |
|  BOOTSTRAP_RES or HELLO_RES                  |
| <------------------------------------------- |
|                                              |
| note: US extracts PEER's sender verify key   |
|       from the obfuscation trailer.          |
|       Stores it in PEER's Contact.udp_key.   |
|       All subsequent packets to PEER:        |
|       - request packets: keep NodeID-mode as |
|         the primary oracle path while usable |
|         peer identity is known               |
|       - fall back to receiver verify key     |
|         when NodeID context is missing       |
|       - response packets: use PEER verify key|
|                                              |
| note: US persists PEER's udp_key in          |
|       nodes.dat alongside PEER's contact.    |
|                                              |

                SESSION 2 (restart)

US                                          PEER
|                                              |
| note: US loads nodes.dat.                    |
|       PEER's contact entry carries the       |
|       previously learned udp_key.            |
|       US can begin obfuscated communication  |
|       immediately without a new HELLO.       |
|                                              |
|  [RC4-obfuscated using stored PEER key]      |
|  BOOTSTRAP_REQ or REQ or SEARCH_*_REQ        |
| -------------------------------------------> |
|                                              |
| note: PEER accepts because the key is still  |
|       valid from its own state.              |
|                                              |
| note: Pending parity gap:                    |
|       The live oracle is ~94% obfuscated.    |
|       The Rust runtime still produces more   |
|       plaintext traffic than the oracle,     |
|       especially outside of startup.         |
|       Full obfuscation density requires      |
|       completing the HELLO key registration  |
|       flow for all newly encountered peers.  |
```

---

## 15. ED2K Server — Login and Session Keepalive

The eD2k server TCP session is used to obtain an external IP and a HighID/LowID assignment, and to remain visible on the legacy eD2k network alongside the Kad DHT.

All eD2k TCP packets use the 6-byte header format:
```
[protocol: 1 byte][payload_length: 4 bytes LE][opcode: 1 byte][payload...]
```

Protocol bytes:
- `0xE3` = `OP_EDONKEYPROT` (standard eD2k)
- `0xC5` = `OP_EMULEPROT` (eMule extension)
- `0xD4` = `OP_PACKEDPROT` (zlib-compressed)

```
US                                          SRV (eD2k server)
|                                              |
| note: US establishes TCP connection to SRV   |
|       on the configured eD2k server address  |
|       and port.                              |
|                                              |
|  TCP connect                                 |
| -------------------------------------------> |
|                                              |
|  OP_LOGINREQUEST  (0xE3 0x01)               |
|                                              |
|  user_hash:   [16 bytes]                     |
|    our eD2k client hash (MD4 of user ID)     |
|  client_id:   [4 bytes]  0x00000000 initially|
|  tcp_port:    [2 bytes]  our TCP port        |
|  tag_count:   [4 bytes]  number of tags      |
|  tags[]:                                     |
|    TAG_NAME:       client nickname           |
|    TAG_VERSION:    eMule version             |
|    TAG_PORT:       our TCP port              |
|    TAG_SERVER_FLAGS: capability bits         |
|    TAG_EMULE_VERSION: extended version info  |
| -------------------------------------------> |
|                                              |
|                                              | note: SRV processes the login.
|                                              |       Assigns a client ID (HighID if
|                                              |       TCP-reachable, LowID otherwise).
|                                              |
|  OP_SERVERMESSAGE  (0xE3 0x38)  [optional]  |
|  message: welcome text string                |
| <------------------------------------------- |
|                                              |
|  OP_IDCHANGE  (0xE3 0x40)                   |
|                                              |
|  client_id:    [4 bytes]                     |
|    assigned ID (> 16777216 = HighID)         |
|    (< 16777216 = LowID)                      |
|  server_flags: [4 bytes] capability bits     |
| <------------------------------------------- |
|                                              |
| note: US learns its HighID or LowID.         |
|       HighID means US is directly reachable  |
|       from the internet on the reported port.|
|       This maps to SOURCETYPE=1 in Kad       |
|       source publish.                        |
|                                              |
|  OP_SERVERSTATUS  (0xE3 0x34)               |
|                                              |
|  user_count:   [4 bytes]                     |
|  file_count:   [4 bytes]                     |
| <------------------------------------------- |
|                                              |
| note: US logs server user and file counts.   |
|       Session is now established.            |
|       Keepalive loop begins.                 |

                ... time passes ...

|  OP_OFFERFILES  (0xE3 0x15)                 |
|  file_count: [4 bytes]  0 (empty keepalive) |
| -------------------------------------------> |
|                                              |
| note: eMule periodically sends OP_OFFERFILES |
|       with actual file metadata to advertise |
|       shared files to the server.            |
|       Overlord currently sends an empty list |
|       as a TCP keepalive only.               |
|       Full OP_OFFERFILES with metadata is    |
|       Phase 2.                               |
```

---

## 16. ED2K Server — ID Assignment and High-ID Confirmation

This diagram zooms into the HighID confirmation and the optional callback flow used by LowID nodes.

```
US                     SRV                     PEER (wants to reach US)
|                        |                           |
| note: US received HighID (client_id > 16777216).   |
|       US is directly reachable.                    |
|       No callback needed.                          |
|                        |                           |
|                        |  PEER requests callback   |
|                        |  to US via SRV            |
|                        | <------------------------ |
|                        |                           |
|  OP_CALLBACKREQUESTED  (0xE3 0x35)                |
|  client_id: [4 bytes] PEER's client ID            |
| <---------------------- |                          |
|                        |                           |
| note: US can now connect directly to PEER          |
|       to serve the file. This path is Phase 2+     |
|       in the Overlord scope.                       |
|                        |                           |
|                        |                           |
| note: If US had LowID: SRV would forward the       |
|       callback. US is firewalled and cannot         |
|       accept direct incoming connections.           |
|       In Kad: LowID maps to firewalled Kad source  |
|       (SOURCETYPE=3 or 5 in PUBLISH_SOURCE_REQ).   |
```

---

## 17. Full Combined Startup Sequence

This diagram shows the complete sequence from process start through bootstrap, HELLO exchanges, and the first active operations.

```
Agent/Config         US                     Bootstrap Seed(s)      Live Network Peers
     |                 |                           |                       |
     | start process   |                           |                       |
     | --------------> |                           |                       |
     |                 |                           |                       |
     |                 | note: Load config.        |                       |
     |                 |       Generate or load    |                       |
     |                 |       stable NodeId and   |                       |
     |                 |       UDP key from state_dir.                     |
     |                 |       Load nodes.dat.     |                       |
     |                 |       Start Tokio UDP     |                       |
     |                 |       socket on Kad port. |                       |
     |                 |       UPnP port map if    |                       |
     |                 |       configured.         |                       |
     |                 |                           |                       |
     |                 | note: Pick first N        |                       |
     |                 |       reachable contacts  |                       |
     |                 |       from nodes.dat.     |                       |
     |                 |                           |                       |
     |  BOOTSTRAP_REQ  (0xE4 0x01) [to each seed] |                       |
     |                 | --------------------------> |                     |
     |                 |                           |                       |
     |  BOOTSTRAP_RES  (0xE4 0x09)                |                       |
     |                 |  sender_id, tcp_port, version, contacts[]         |
     |                 | <------------------------- |                      |
     |                 |                           |                       |
     |                 | note: Add seed and all    |                       |
     |                 |       returned contacts   |                       |
     |                 |       to routing table.   |                       |
     |                 |                           |                       |
     |                 | note: For each new contact|                       |
     |                 |       with no stored key: |                       |
     |                 |       Send HELLO_REQ to   |                       |
     |                 |       build obfuscation   |                       |
     |                 |       context. (§2)       |                       |
     |                 |                           |                       |
     |  HELLO_REQ (0xE4 0x11) -------------------- | -----> PEER_A        |
     |  HELLO_RES (0xE4 0x19) <------------------- | ------ PEER_A        |
     |  HELLO_RES_ACK (0xE4 0x22) ---------------- | -----> PEER_A        |
     |                 |                           |                       |
     |                 | note: Routing table now   |                       |
     |                 |       has contacts with   |                       |
     |                 |       obfuscation keys.   |                       |
     |                 |       Zone refresh begins.|                       |
     |                 |                           |                       |
     |                 | note: Zone refresh:       |                       |
     |                 |       For each zone, run  |                       |
     |                 |       a node lookup (§3)  |                       |
     |                 |       toward a random ID  |                       |
     |                 |       in the zone to      |                       |
     |                 |       populate buckets.   |                       |
     |                 |                           |                       |
     |  REQ (FIND_NODE) ----------------------------------> Live PEER_B    |
     |  RES (contacts) <---------------------------------- Live PEER_B    |
     |  ...  (repeats ALPHA=3 at a time until K closest found)             |
     |                 |                           |                       |
     |                 | note: Routing table is    |                       |
     |                 |       now populated.      |                       |
     |                 |       Agent registers     |                       |
     |                 |       with coordinator.   |                       |
     |                 |                           |                       |
     | register (HTTP) |                           |                       |
     | <-------------- |                           |                       |
     |                 |                           |                       |
     |                 | note: Agent begins:       |                       |
     |                 |       - passive snoop     |                       |
     |                 |         (§13)             |                       |
     |                 |       - periodic PING to  |                       |
     |                 |         maintain contacts |                       |
     |                 |         (§12)             |                       |
     |                 |       - publish flow for  |                       |
     |                 |         popular hashes    |                       |
     |                 |         from coordinator  |                       |
     |                 |         (§7, §8)          |                       |
     |                 |       - active searches   |                       |
     |                 |         dispatched by     |                       |
     |                 |         coordinator       |                       |
     |                 |         (§4, §5, §6)      |                       |
     |                 |                           |                       |
     |                 | note: ED2K server session |                       |
     |                 |       starts in parallel  |                       |
     |                 |       if configured.      |                       |
     |                 |       (§15, §16)          |                       |
     |                 |                           |                       |
     |                 | note: Republish timer     |                       |
     |                 |       fires every         |                       |
     |                 |       REPUBLISH_INTERVAL  |                       |
     |                 |       = 18000 s.          |                       |
```

---

## Notes on Oracle Differences in These Flows

### eMule vs aMule: Search Result Batching

- **eMule** (`Indexed.cpp SendValidKeywordResult`): fragments `SEARCH_RES` on `UDP_KAD_MAXFRAGMENT` byte budget. A single `SEARCH_KEY_REQ` may produce multiple `SEARCH_RES` packets.
- **aMule** (`Indexed.cpp`): uses fixed 50-result chunks.
- **Overlord**: accepts configurable result caps (keyword 5000, source 1000, notes 1000). Batching on the receive side handles both oracle styles transparently.

### eMule vs aMule: Inbound Publish Rate Limits

Per `PacketTracking.cpp`:

| Opcode | eMule (per IP/min) | aMule (per IP/min) |
|---|---|---|
| `PUBLISH_KEY_REQ` | 4 | 3 |
| `PUBLISH_SOURCE_REQ` | 3 | 2 |
| `PUBLISH_NOTES_REQ` | 2 | 2 |
| Search opcodes | 3 | 3 |

**Overlord follows eMule**. Current Rust tracker uses generic per-IP limiting — per-opcode granularity is a pending parity gap.

### Keyword Post-Processing Version Gate (eMule only)

eMule `Search.cpp ProcessResultKeyword` filters `TAG_PUBLISHINFO` and `TAG_KADAICHHASHRESULT` based on the responder's Kad version. aMule does not apply this version gate. Overlord does not yet implement this filtering — pending parity gap.
