# Overlord Kad2 Implementation Reference

Overlord Kad2 architecture and implementation reference.
This file is maintained in the current Overlord workspace under
`p2p-overlord-agents/docs/kad/`.

**Language**: Rust
**Protocol**: eMule Kademlia v2 (Kad2), IPv4 only
**Status**: Overlord Kad2 implementation reference for the current Rust workspace

---

## Table of Contents

1. [Goals](#1-goals)
2. [Non-Goals / Future Work](#2-non-goals--future-work)
3. [Reference Implementations](#3-reference-implementations)
4. [Workspace Structure](#4-workspace-structure)
5. [Crate Responsibilities](#5-crate-responsibilities)
6. [Protocol Overview](#6-protocol-overview)
7. [Routing Table](#7-routing-table)
8. [DHT Operations](#8-dht-operations)
9. [Obfuscation](#9-obfuscation)
10. [UPnP](#10-upnp)
11. [Coordinator Integration And Persistence](#11-coordinator-integration-and-persistence)
12. [Agent Control API](#12-agent-control-api)
13. [Configuration](#13-configuration)
14. [Logging](#14-logging)
15. [Bootstrap](#15-bootstrap)
16. [File Sharing & Publishing](#16-file-sharing--publishing)
17. [Testing Strategy](#17-testing-strategy)
18. [Phased Implementation Plan](#18-phased-implementation-plan)
19. [Key Dependencies](#19-key-dependencies)
20. [Future Work](#20-future-work)
21. [Code Conventions](#21-code-conventions)

---

## 1. Goals

Build a fully wire-compatible eMule-family Kad2 and ED2K implementation in Rust
that can:

- Join and participate in the live eMule Kad2 DHT network
- Search for files by keyword
- Find sources (peers) for a known file hash
- Fetch file notes (ratings/comments)
- Publish file availability and keywords into the DHT
- Maintain an ED2K server session with oracle-like search and source-search behavior
- Progress toward native ED2K peer transfer parity for upload and download
- Feed the coordinator with search and passive-crawl results
- Expose agent control and status through the internal Overlord agent HTTP surface
- Run as a foreground process (lifecycle managed by external tools)
- Be structured as reusable workspace crates, not just one application

---

## 2. Non-Goals / Future Work

See [§20 Future Work](#20-future-work) for detailed notes on each item.

| Feature | Status |
|---|---|
| Kad1 (legacy protocol) | Intentionally omitted |
| Full ED2K server and peer transfer parity | Staged active work, not out of scope |
| AICH hash tree computation | Deferred behind initial transfer parity |
| Firewall buddy system / NAT callback | Phase 3 |
| IPv6 | Future |
| GUI / system tray | Out of scope for this repo |
| CLI binary (interactive shell) | Separate project, possibly different language |

---

## 3. Reference Implementations

Three reference codebases were analysed prior to writing this spec:

| Repo | Path | Notes |
|---|---|---|
| eMule | `%EMULEBB_WORKSPACE_ROOT%\workspaces\workspace\app\emulebb-community-baseline\srchybrid\kademlia\` | Authoritative Kad2 wire format and protocol behaviour. Windows/MFC-only. |
| aMule | `%EMULEBB_WORKSPACE_ROOT%\repos\amule\src\kademlia\` | Cross-platform port of eMule. Better code organisation. wxWidgets. |
| libed2k | external libed2k checkout, if present | libtorrent-derived C++ library. Best architectural separation of the three. Boost/pre-C++11. |

The eMule source is ground truth for Kad2 wire format and runtime behaviour. aMule is the
portable cross-check and readability aid, not a higher authority.
libed2k's `traversal_algorithm` / `rpc_manager` / `observer` pattern informs our async design.

---

## 4. Workspace Structure

```
p2p-overlord/
├── p2p-overlord-agents/
│   ├── Cargo.toml
│   ├── overlord.toml.example
│   └── crates/
│       ├── overlord-kad-proto/    ← Kad2 wire codec: packet types, tag system, node ID
│       ├── overlord-kad-routing/  ← routing table: zone tree, k-buckets, contacts
│       ├── overlord-kad-net/      ← Tokio UDP transport, RPC manager, obfuscation
│       ├── overlord-kad-dht/      ← DHT operations: bootstrap, lookup, search, publish
│       ├── overlord-agent-common/ ← shared HTTP/control-plane contract for agents
│       └── overlord-agent-emule/  ← Kad2 agent binary and coordinator integration
├── p2p-overlord-be/
    └── overlord-be-coordinator/   ← coordinator, result ingestion, search dispatch, snoop APIs
└── ../goed2k-server/              ← eMuleBB ED2K server fork for parity scenarios
```

### Dependency Graph

```
overlord-kad-proto
    ↑
overlord-kad-routing   (depends on overlord-kad-proto for NodeId, Contact types)
    ↑
overlord-kad-net       (depends on overlord-kad-proto + overlord-kad-routing)
    ↑
overlord-kad-dht       (depends on overlord-kad-net + overlord-kad-routing)
    ↑
overlord-agent-common
    ↑
overlord-agent-emule
```

`overlord-kad-proto` and `overlord-kad-routing` have zero async, zero IO — they are pure data structures
and transformations. This makes them trivially unit-testable.

---

## 5. Crate Responsibilities

### `overlord-kad-proto`

- All Kad2 packet types as Rust enums/structs
- Binary encode/decode (`binrw` crate) — `&[u8]` ↔ `KadPacket`
- eMule tag system (typed name/value pairs: `TagName` × `TagValue`)
- `NodeId` — 128-bit (`[u8; 16]`) wrapper with XOR distance metric
- `KadUdpKey` — per-sender anti-spoofing key type
- Ed2k file hash type (`Ed2kHash` — MD4-based, 16 bytes)
- No `async`, no `tokio`, no networking of any kind
- Test vectors for all packet types (see §17)

### `overlord-kad-routing`

- `RoutingTable` — binary zone tree (eMule style, not flat k-buckets)
- `RoutingZone` — recursive zone node, splits when bin fills
- `RoutingBin` — k-bucket, max K=10 contacts
- `Contact` — node ID, IP, UDP port, TCP port, Kad version, UDP key, liveness type, last seen
- Current split logic is close to the oracle but not identical; see §7 for the parity gap
- Global IP/subnet duplicate enforcement (max 1 per IP, max 10 per /24 subnet) and the oracle per-bin two-per-`/24` cap
- No `async`, no `tokio`, no networking

### `overlord-kad-net`

- Tokio UDP socket wrapper
- Outbound rate limiter (configurable packets/sec)
- `RpcManager` — pending request map keyed by transaction ID, timeout handling
- Packet obfuscation layer (RC4, see §9)
- Receives raw UDP datagrams, attempts decrypt, dispatches to `RpcManager`
- `PacketTracker` — oracle-shaped per-IP, per-opcode flood protection with a separate search-result budget

### `overlord-kad-dht`

- `Bootstrap` — load nodes.dat, send initial HELLO/PING, populate routing table
- `NodeLookup` — iterative find_node traversal (ALPHA=3 parallel queries)
- `KeywordSearch` — iterative search returning `Stream<Item = SearchResult>`
- `SourceSearch` — iterative source lookup returning `Stream<Item = SourceResult>`
- `NotesSearch` — iterative notes lookup
- `Publish` — keyword publish, source publish, notes publish
- Scheduled republish timer
- Exposes packet subscription/hooks used by the agent runtime for unsolicited Kad traffic

### `overlord-agent-common`

- Shared agent HTTP/control plane types
- Coordinator client for:
  - registration
  - result posting
  - snoop flush/restore
  - popular-hash retrieval
- `IndexerService` trait and `IndexerServer` HTTP surface

### `overlord-agent-emule`

- Loads and validates Overlord TOML config
- Starts/stops `overlord-kad-dht`
- Owns:
  - bootstrap retry
  - passive crawl
  - active search dispatch
  - publish / seed-popular flow, including the synthetic fallback seed set used when the coordinator has no popular hashes yet
  - snoop restore/flush
- Exposes the internal agent HTTP API (`axum`, see §12)
- Persists agent-local state such as node ID, UDP key, and `nodes.dat`

### Current Oracle Parity Snapshot

Use the labels below when reading the current port status:

- `Equivalent behavior`: current Rust behavior matches the oracle meaningfully enough for protocol work, even if the structure differs.
- `Repo policy`: current Rust behavior is intentional or accepted for now, but it is not claimed to be oracle-faithful.
- `Verified difference`: the current Rust implementation is known to diverge from eMule.
- `Pending parity gap`: parity has not been completed yet or the current runtime does not expose the oracle behavior end to end.

| Crate | Status | Notes |
|---|---|---|
| `overlord-kad-proto` | `Equivalent behavior` | `src/packet.rs` matches the oracle Kad2 search-family wire shapes used by eMule `net/KademliaUDPListener.cpp Process_KADEMLIA2_SEARCH_*` and `kademlia/Search.cpp CSearch::StorePacket`, cross-checked against aMule `Process2Search*Request` and `CSearch::StorePacket`. `SearchRes.target` now uses the same generic echoed-target semantics as the wire across keyword, source, and notes responses. |
| `overlord-kad-routing` | `Equivalent behavior` | `src/table.rs`, `src/zone.rs`, and `src/bin.rs` now match the oracle global duplicate limits, `RoutingZone.cpp CanSplit`, and the per-bin two-per-`/24` clustering cap enforced in `routing/RoutingBin.cpp AddContact`. |
| `overlord-kad-net` | `Equivalent behavior` + `Pending parity gap` | `src/rpc.rs`, `src/tracker.rs`, and the transport flow now implement oracle-shaped per-IP, per-opcode request tracking and the current obfuscation-mode selection. The remaining gap is live-behavior density and HELLO-derived key registration, not generic tracker shape anymore. |
| `overlord-kad-dht` | `Equivalent behavior` + `Repo policy` | `src/traversal.rs` emits the same Kad2 search request families as oracle `CSearch::StorePacket`, and the main search/source/notes traversal shape is recognizable. `src/search.rs is_acceptable_keyword_result` is currently repo policy rather than a direct oracle port, and source publish now fills the second `KADEMLIA2_PUBLISH_SOURCE_REQ` field with publisher identity like eMule/aMule. Bootstrap persistence now also preserves peer UDP keys from `nodes.dat` so restarts retain the same obfuscation context the oracle keeps. |
| `overlord-agent-emule` | `Equivalent behavior` + `Verified difference` + `Pending parity gap` | `src/agent.rs` already observes unsolicited Kad `Search*Req` traffic, persists the full passive replay shape (`start_position`, restrictive keyword payloads, source `size`, notes `size`), and exposes active Kad notes search, ED2K-labeled notes search over Kad notes transport, plus validation-only notes publish. Verified ED2K gaps remain outside the Kad core: `src/ed2k_server.rs` is still a focused `ServerConnect`/`ServerSocket` subset, `src/ed2k_transfer.rs` has the first score-ranked upload queue slice but still lacks durable credits, real file priority, stock-like slot rotation, and harness/live queue evidence, and `src/ed2k_tcp.rs` now keeps an adaptive pending-block window with safe teardown for malformed or out-of-order replies but still stops short of full eMule A4AF/global scheduler parity. |

### Current Oracle Findings Backlog

1. `overlord-kad-net`: finish the oracle obfuscation port and verify it on the live network. The recent `a1`-`a7` eMule packet captures under `ext-deps/eMule_full_build_deps/eMule/srchybrid/x64/Debug/` show that modern oracle sessions are overwhelmingly obfuscated, while plaintext Kad appears only as a small bootstrap, hello, or fallback slice. An isolated oracle run from `ext-deps/eMule-build` on 2026-03-22 reinforced that result: a 5-minute capture on `46663/udp` produced `1009` packets, only `55` plaintext `0xE4...` packets, and `954` non-plaintext packets, while the oracle trace log still recorded successful publish sends and accepts.
2. `overlord-agent-emule`: finish the current score-ranked ED2K upload queue with durable credit inputs, real file priority, LowID/friend-slot policy, stock-like session rotation, and harness/live evidence so listener behavior stops diverging from `UploadQueue.cpp`.
3. `overlord-agent-emule`: extend the new adaptive pending-block downloader window toward fuller eMule `DownloadClient.cpp CreateBlockRequests` / `SendBlockRequests` parity, especially the broader callback and A4AF-driven control flow those paths assume.
4. `overlord-agent-emule`: finish the remaining ED2K control-plane gaps, especially preview/shared-browsing surfaces and the still-partial `ServerSocket` feature surface.
5. `overlord-kad-net` and live runtime validation: keep re-running live-network acceptance to improve HELLO key registration completeness and obfuscation density against the oracle.

### 2026-04 Stock eMule Comparison

The isolated comparison against the local stock eMule `community-0.60` tree is
tracked in [Stock eMule `community-0.60` Comparison](./EMULE_COMMUNITY_060_COMPARISON.md).

Current review summary:

- Kad routing, publish/search wire shapes, and packet-tracking budgets are now
  close to the stock oracle or intentionally repo-policy differences.
- Passive Kad replay is no longer target-only; the persisted request shape now
  keeps restrictive keyword payloads plus source and notes size metadata.
- ED2K server sessions are credible enough for login, search, source search,
  HighID or LowID handling, and callback-aware source modeling, but they still
  cover only the subset that matters for current interoperability.
- ED2K peer transfer remains the largest stock-eMule gap because upload queue
  selection and downloader block scheduling are still materially simpler than
  `community-0.60`.

---

## 6. Protocol Overview

### Kad2 Packet Types

All packets use the eMule `OP_KADEMLIAHEADER` (0xE4) or obfuscated header.
For byte-level layouts, verified tag IDs, and packet-family notes, see `PROTOCOL_REFERENCE.md`.

| Packet | Direction | Purpose |
|---|---|---|
| `KADEMLIA2_BOOTSTRAP_REQ` | out | Request bootstrap contact list |
| `KADEMLIA2_BOOTSTRAP_RES` | in | Receive bootstrap contacts |
| `KADEMLIA2_HELLO_REQ` | out | Announce presence, initiate verification |
| `KADEMLIA2_HELLO_RES` | in | Accept hello, return our info |
| `KADEMLIA2_HELLO_RES_ACK` | out | Acknowledge hello response |
| `KADEMLIA2_REQ` | out | Generic find_node / lookup |
| `KADEMLIA2_RES` | in | Response with closest contacts |
| `KADEMLIA2_SEARCH_KEY_REQ` | out | Search by keyword hash |
| `KADEMLIA2_SEARCH_SOURCE_REQ` | out | Search for file sources |
| `KADEMLIA2_SEARCH_NOTES_REQ` | out | Search for file notes |
| `KADEMLIA2_SEARCH_RES` | in | Search response (files/sources/notes) |
| `KADEMLIA2_PUBLISH_KEY_REQ` | out | Publish keyword index entry |
| `KADEMLIA2_PUBLISH_SOURCE_REQ` | out | Publish source availability |
| `KADEMLIA2_PUBLISH_NOTES_REQ` | out | Publish a note/rating |
| `KADEMLIA2_PUBLISH_RES` | in | Publish acknowledgement |
| `KADEMLIA_FIREWALLED_REQ` | both | Firewall TCP probe request |
| `KADEMLIA_FIREWALLED2_REQ` | both | Extended firewall TCP probe request |
| `KADEMLIA_FIREWALLED_RES` | in | Firewall probe response with external IP |
| `KADEMLIA_FINDBUDDY_REQ` | both | Buddy discovery request |
| `KADEMLIA_FINDBUDDY_RES` | in | Buddy discovery response |
| `KADEMLIA_CALLBACK_REQ` | both | Buddy callback request |
| `KADEMLIA2_PING` | out | Liveness check |
| `KADEMLIA2_PONG` | in | Liveness response |
| `KADEMLIA2_FIREWALLUDP` | both | UDP reachability test |

### Kad1 Policy

> **KAD1_IGNORED**: Kad1 (legacy protocol) nodes are silently ignored. Packets with Kad1
> opcodes are dropped without processing. No Kad1 packet types are implemented.
> See §20 Future Work if this changes.

This simplifies the implementation significantly. The live network (2024+) is overwhelmingly Kad2.

### Protocol Constants

```rust
pub const K: usize = 10;               // k-bucket size
pub const ALPHA: usize = 3;            // parallel lookup queries
pub const KBASE: usize = 4;            // zone splitting base
pub const KK: usize = 5;               // peer selection parameter
pub const SEARCH_TIMEOUT_SECS: u64 = 45;
pub const STORE_TIMEOUT_SECS: u64 = 140;
pub const REPUBLISH_INTERVAL_SECS: u64 = 18_000; // ~5 hours, configurable
pub const KAD_VERSION: u8 = 10;        // our announced Kad version
```

---

## 7. Routing Table

### Structure

Binary zone tree (eMule style), not a flat array of k-buckets.

- Root zone covers the entire 128-bit address space
- Each zone is either a **leaf** (holds a `RoutingBin`) or an **internal node** (has two child zones)
- A leaf splits into two children when its bin fills AND the split conditions are met
- Zones are indexed by `ZoneIndex` (a `NodeId`) — the path from root is encoded as bits

### Split Conditions

Verified oracle rule:

- eMule `routing/RoutingZone.cpp CanSplit` and aMule `routing/RoutingZone.cpp CanSplit` split only when the leaf bin is already at `K`, the level is `< 127`, and `(zone_index < KK || level < KBASE)`.

Current Rust status:

- `crates/overlord-kad-routing/src/zone.rs fn can_split` gates on `depth < 127`, `total_contacts < max_table_size`, and the oracle `zone_index < KK || depth < KBASE` predicate.
- `Equivalent behavior`: the Rust `can_split` path now uses the oracle `zone_index < KK || depth < KBASE` predicate instead of the old `on_own_side` heuristic.
- `Repo policy`: the extra `max_table_size` guard is a local Overlord limit and should not be described as oracle routing behavior.

### Contact Liveness Types

```rust
pub enum ContactType {
    Active,     // responded recently
    Inactive,   // not responded, still in table, eligible for ping
    Dead,       // failed multiple pings, candidate for replacement
}
```

### IP/Subnet Limits

Oracle rule from eMule/aMule `routing/RoutingBin.cpp AddContact`, `CheckGlobalIPLimits`, and `ChangeContactIPAddress`:

- Maximum 1 contact per IP address globally
- Maximum 10 contacts per `/24` subnet globally
- Maximum 2 contacts from the same `/24` inside one bin
- LAN addresses (RFC1918) exempt from subnet limits

Current Rust status:

- `crates/overlord-kad-routing/src/table.rs` implements the global one-per-IP rule, the global ten-per-`/24` rule, and the LAN exemption.
- `Equivalent behavior`: `crates/overlord-kad-routing/src/bin.rs` now enforces the oracle per-bin two-per-`/24` cap in addition to the global limits.

### Contact Fields

```rust
pub struct Contact {
    pub id: NodeId,
    pub ip: Ipv4Addr,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub kad_version: u8,
    pub udp_key: KadUdpKey,
    pub verified: bool,
    pub contact_type: ContactType,
    pub last_seen: SystemTime,
    pub created_at: SystemTime,
}
```

---

## 8. DHT Operations

### Bootstrap

1. Read contacts from nodes.dat (see §15)
2. Send `KADEMLIA2_BOOTSTRAP_REQ` to first N reachable contacts
3. Process responses, add contacts to routing table
4. Trigger initial zone refresh once routing table has ≥ 1 contact

### Node Lookup (Iterative Find)

1. Get K closest contacts to target from local routing table (XOR distance)
2. Send `KADEMLIA2_REQ` to ALPHA=3 closest unqueried contacts in parallel
3. Collect responses, update closest set
4. Repeat until no closer nodes found or all K closest have been queried
5. Return K closest found

### Keyword Search

1. Hash keyword with MD4 → target `NodeId`
2. Run node lookup toward target
3. At each step, also send `KADEMLIA2_SEARCH_KEY_REQ`
4. Collect `KADEMLIA2_SEARCH_RES` responses → parse into `SearchResult` structs
5. Emit each result on the search `Stream`
6. Write all results to index automatically
7. Search ends after `SEARCH_TIMEOUT_SECS` (45s) or no new nodes found

### Source Search

Same as keyword search but uses `KADEMLIA2_SEARCH_SOURCE_REQ`. Target is the file's `Ed2kHash`.
Kad2 source search requests require the file size on the wire, so the daemon resolves size from
the local `files` table before starting the network search. If the file hash is not indexed locally
or the indexed size is zero, the REST request fails with `400` and no DHT search is started.
Results include peer IP/port and are stored in `sources`. The `kad_version` column remains nullable
because Kad source-search result tags do not carry a Kad version byte.

### Notes Search

Same pattern, `KADEMLIA2_SEARCH_NOTES_REQ`. Kad2 notes search also requires the file size on the
wire, so the daemon uses the indexed size from the local `files` table and fails the API request if
that size is unavailable. Notes results are stored in `notes`; the result entry ID is treated as
the note's Kad/source identity and is persisted as `source_id`.

- `Equivalent behavior`: `crates/overlord-kad-dht/src/traversal.rs` emits `SearchNotesReq { target, size }`, matching eMule `kademlia/Search.cpp CSearch::StorePacket` and `net/KademliaUDPListener.cpp Process_KADEMLIA2_SEARCH_NOTES_REQ`, cross-checked against the aMule equivalents.
- `Equivalent behavior`: `crates/overlord-agent-emule/src/agent.rs` now exposes coordinator-triggered Kad notes searches end to end and routes `Protocol::Ed2k` notes jobs through the same stock-aligned Kad notes transport while preserving the requested ED2K result-batch label.
- `Pending parity gap`: notes are still projected into file-centric result records, so richer modeling for distinct note authors remains open.

### Publish

On file add (automatic) and on schedule (configurable interval, default 18000s):

1. `KADEMLIA2_PUBLISH_SOURCE_REQ` — announce we have the file
2. `KADEMLIA2_PUBLISH_KEY_REQ` — publish keyword→hash mapping for each keyword
3. (Optional) `KADEMLIA2_PUBLISH_NOTES_REQ` — if we have a note for the file

- `Equivalent behavior`: the Kad2 publish packet families in `crates/overlord-kad-proto/src/packet.rs` follow the oracle send paths in eMule `kademlia/Search.cpp CSearch::StorePacket` and aMule `kademlia/Search.cpp CSearch::StorePacket`.
- `Equivalent behavior`: `crates/overlord-kad-dht/src/publish.rs publish_source` now fills the second `KADEMLIA2_PUBLISH_SOURCE_REQ` field with publisher identity, matching eMule `net/KademliaUDPListener.cpp SendPublishSourcePacket` and `kademlia/Search.cpp CSearch::StorePacket`.
- `Equivalent behavior`: notes publish now uses `publisher_id` semantics end to end and has been exercised through the validation-only seed path on the live network.

### Concurrent Search Limit

Maximum simultaneous active searches: configurable, default 5.
New search requests are queued if limit is reached.

### Outbound Rate Limit

Maximum outbound Kad2 UDP packets per second: configurable, default 50.
This is a global limit across all operations.

---

## 9. Obfuscation

eMule uses an RC4-based obfuscation layer on all UDP packets (Kad2 v6+).
Most modern nodes on the live network use obfuscation. Without it, many nodes will ignore us.

### Behaviour

- Default: **enabled**
- Config: `[obfuscation] enabled = true`
- When enabled: the current Rust runtime now follows the oracle Kad UDP key schedule more closely. Requests keep NodeID-mode obfuscation as the primary path while usable peer identity is known, replies use the learned receiver verify key, and request fallback uses that verify key when NodeID context is missing. Inbound packets are still tried as obfuscated first before plain decode.
- When disabled: plain packets only (useful for debugging, Wireshark capture)

### Key Negotiation

Each node pair negotiates a session key via the `KADEMLIA2_HELLO_REQ/RES` exchange, and modern
`nodes.dat` snapshots may already contain peer UDP keys.
Keys are stored per-contact in the `KadUdpKey` field of `Contact`.

### Note

The obfuscation protocol is poorly documented. The authoritative implementation is in
`eMule: KademliaUDPListener.cpp` and `aMule: KademliaUDPListener.cpp`.
libed2k also implements it in `dht_tracker.cpp`.

### Oracle Trace Notes

Recent oracle packet captures from the prepared eMule debug workspace support the source reading above:

- `a3.pcapng` and `a4.pcapng`: clean eMule-only startup traces show almost no plaintext Kad traffic beyond bootstrap and hello. No plaintext search or publish traffic dominates those sessions.
- `a5.pcapng`: active keyword searches still did not surface plaintext `SEARCH_KEY_REQ`, which strongly suggests the real search flow stayed obfuscated end to end.
- `a6.pcapng` and `a7.pcapng`: eMule did receive visible `PUBLISH_RES` acknowledgements for plaintext fallback `PUBLISH_SOURCE_REQ`, proving that publish acks exist on the oracle, even though most of the session remained obfuscated.

The combined oracle conclusion is that live Kad interoperability depends more on transport-shape parity than on a plaintext-only packet comparison. A Rust node that stays mostly plaintext will not look like the oracle on the network, even if individual packet layouts are otherwise close.

### 2026-03-22 Isolated Oracle Run

An isolated oracle validation run from `ext-deps/eMule-build` was carried out with:

- VPN bind `10.54.220.34`
- TCP `46662`
- UDP `46663`
- UPnP enabled and verified with `miniupnpc -l`
- seeded `nodes.dat`
- oracle tracing enabled in `KademliaUDPListener.cpp`, `Search.cpp`, and `PacketTracking.cpp`

Observed results:

- The oracle trace log recorded `publish_send_opcode=40`, `publish_res_accept=50`, and `publish_source_semantic=10`.
- The matching 5-minute UDP capture on `46663` contained `1009` packets, `55` plaintext Kad packets, and `954` non-plaintext packets.
- No plaintext `PUBLISH_KEY_REQ`, `PUBLISH_SOURCE_REQ`, `PUBLISH_RES`, or `PUBLISH_RES_ACK` packets were visible in that isolated 5-minute capture, despite the oracle trace proving that publish accepts happened.

Implication:

- Publish-ack parity must be judged against obfuscated transport and startup crypto context, not against plaintext packet sightings alone.

---

## 10. UPnP

Uses the `igd` crate (pure Rust, UPnP IGD protocol).

### Behaviour

1. On startup, if `[upnp] enabled = true`: discover gateway
2. Request external UDP port mapping for our Kad2 port
3. If successful: log the external IP/port, use it as our announced address
4. On shutdown: release the port mapping

### Configuration

```toml
[upnp]
enabled = true
bind_ip = "0.0.0.0"    # local interface for UPnP discovery multicast
gateway = "auto"        # "auto" = discover via SSDP, or explicit e.g. "192.168.1.1"
```

The `bind_ip` allows selecting which network interface to use for UPnP.
The `gateway` override is for environments where SSDP discovery fails.

---

## 11. Coordinator Integration And Persistence

In the current Overlord layout, durable indexing and search history belong to the coordinator,
not the Kad crates and not the agent binary.

### Current Split Of Responsibility

- `overlord-kad-*` crates:
  - protocol, routing, transport, DHT, publish/search behavior
- `overlord-agent-emule`:
  - runtime orchestration
  - active search execution
  - passive crawl
  - snoop queue restore/flush
  - local persistence for Kad node state only
- `overlord-be-coordinator`:
  - agent registration
  - search dispatch
  - result batch ingestion
  - snoop restore/flush backing
  - popular-hash input for publish/seed flows

### Agent-Local Persistent State

The Kad agent keeps only node-local runtime state on disk:

- stable Kad node ID
- stable UDP key
- cached `nodes.dat`
- persisted Overlord agent `indexer_id`

These files live under the agent `state_dir`.

### Coordinator-Owned Data

The coordinator is the place where Overlord stores:

- registered agents
- search jobs
- ingested result batches
- indexed file records
- snoop queue snapshots
- popular-hash input used for publish seeding

The precise database schema lives with the coordinator/backend, not in this Kad protocol crate.

---

## 12. Agent Control API

Framework: `axum`.
The Kad agent exposes an internal HTTP control surface, while the coordinator exposes the
user-facing search API and the ingestion/coordination endpoints.

### Agent Internal API

Default bind address:

- `127.0.0.1:13301` for `overlord-agent-emule`

Current endpoints:

```
GET  /api/internal/health
     → { ok, protocol, indexer_id, version }

GET  /api/internal/stats
     → { indexer_id, protocol, peers_connected, crawl_rate,
          snoop_queue_depth, staging_queue_depth, uptime_secs }

POST /api/internal/search
     Body: SearchJob
     → 202

POST /api/internal/seed-popular
     Body: PopularHash[]
     → 202

POST /api/internal/config-update
     Body: ConfigUpdate
     → 202 or error if restart-required
```

### Coordinator API Touchpoints Used By The Agent

Default coordinator bind address:

- `127.0.0.1:13300`

Current endpoints used by the Kad agent:

```
POST /api/internal/register
POST /api/internal/results
POST /api/internal/snoop-flush
GET  /api/internal/snoop-restore/{indexer_id}
GET  /api/internal/popular-hashes

POST /api/search
```

### Search Flow In Overlord

1. coordinator receives `POST /api/search`
2. coordinator chooses registered Kad2 agents
3. coordinator calls each agent's `/api/internal/search`
4. agent runs Kad search in the background
5. agent posts `ResultBatch` payloads back to the coordinator
6. coordinator stores/aggregates the results

---

## 13. Configuration

Primary config file for the Rust agent workspace:

- `p2p-overlord-agents/overlord.toml`
- example: `p2p-overlord-agents/overlord.toml.example`

Path can be overridden with `--config`.

```toml
[coordinator]
url = "http://127.0.0.1:13300"

[agent]
indexer_id_path = "./runtime/overlord-agent-emule.indexer-id"
state_dir = "./runtime"
hostname = "localhost"
version = "0.1.0"

[control]
listen_port = 13301

[p2p.kad]
listen_port = 41000
nodes_dat_path = "./runtime/overlord-kad.nodes.dat"
bootstrap_nodes = []
search_timeout_secs = 45
store_timeout_secs = 140
republish_interval_secs = 18000
publish_contact_fanout = 4
routing_refresh_interval_secs = 900
hello_intro_interval_secs = 300
hello_intro_fanout = 2
max_outbound_pps = 8
interactive_max_outbound_pps = 4
harvest_max_outbound_pps = 1
maintenance_max_outbound_pps = 1
publish_max_outbound_pps = 1
search_phase2_fanout = 50
keyword_result_cap = 5000
source_result_cap = 1000
notes_result_cap = 1000
synthetic_publish_interval_secs = 120
synthetic_publish_batch_items = 1
synthetic_publish_contact_fanout = 1
obfuscation_enabled = true
enable_mock_results = false

[p2p.ed2k]
listen_port = 41001
max_concurrent_downloads = 1
max_parallel_download_peers = 2
keyword_server_attempt_budget = 3
exact_hash_keyword_server_attempt_budget = 4
source_server_attempt_budget = 3
kad_source_supplement_max_existing_sources = 2

[log]
level = "info"
```

### Config Notes

- `agent.state_dir` stores the stable Kad node ID, UDP key, and cached `nodes.dat`
- the internal control server and Kad UDP socket are separate bind addresses
- `enable_mock_results` defaults to `false` in the real Kad runtime
- config updates for socket-shape/runtime-critical Kad settings currently require restart
- Search defaults are intentionally indexer-oriented: fan out broadly in phase 2, collect a lot,
  and filter later in the coordinator/indexing plane rather than narrowing aggressively during network search

### Multi-Agent Fleet Guidance

For broad Kad search-serving coverage, prefer a fleet of long-lived agents over one oversized node.

- Run multiple agents with separate `state_dir` roots so each agent keeps its own stable Kad node ID, UDP key, ports, and cached `nodes.dat`.
- Register each agent as its own indexer instance under the coordinator.
- Prefer distinct public IPv4 addresses per agent.
- Prefer spreading those IPv4 addresses across different `/24` prefixes when possible.
- Do not treat many random Kad IDs behind one public IPv4 as a substitute for real fleet coverage.
- Do not churn Kad IDs unnecessarily; long-lived identities accumulate routing presence, peer UDP-key context, and more credible network behavior.

Rationale:

- Kad routing and publish/search ownership follow target proximity, not raw node capacity.
- Kad v9+ node IDs are partially tied to the public IP, so keyspace placement is not freely controllable with arbitrary random IDs alone.
- The routing layer also enforces duplicate-IP and subnet clustering constraints, so many agents behind one address or one tight subnet are a weaker network position than a fleet spread across real addresses.
- From a wire-parity and acceptance perspective, stable always-on nodes are more useful than frequently rotated identities.

---

## 14. Logging

Library: `tracing` + `tracing-subscriber` + `tracing-appender`.

- Log to file only (no stdout). Use rolling file appender with size-based rotation.
- `tracing-appender` handles the file sink; configure max file size and backup count.
- Structured spans: each active search has its own span with `search_id` and `query` fields.
- Key events to instrument:
  - Node start/stop
  - Bootstrap attempt / success / failure
  - Contact added / removed / rejected
  - Search started / result received / completed / timed out
  - Publish sent / acknowledged
  - Obfuscation failure (packet dropped)
  - Popular-hash seed / republish cycle
  - Snoop restore / flush
  - Agent internal API requests (at `debug` level)

---

## 15. Bootstrap

### Node ID Verification (from libed2k / eMule)

Each node's ID must be consistent with its IP address (Kad v9+ enforces this).
The first 3 bytes of the node ID are derived from `CRC32C(masked_ip)`.
Nodes that fail this check are still accepted but marked as unverified.

### Bootstrap Source Priority

1. `[dht] nodes_dat` config value (if set and file exists)
2. `.\nodes.dat` in current working directory
3. `%APPDATA%\eMule\config\nodes.dat` (if exists)
4. `%APPDATA%\aMule\nodes.dat` (if exists)
5. Hardcoded list compiled into the binary (maintained as a const array)

### Bootstrap Failure Handling

If all bootstrap sources fail or return no responding contacts:
- Enter retry loop with exponential backoff (1s, 2s, 4s, ... max 60s)
- Surface error via `GET /api/v1/status` (`"state": "bootstrapping_failed"`)
- Keep retrying indefinitely until at least one contact responds

### nodes.dat Formats

Support both:
- **eMule binary format** (version 2 and version 3 bootstrap edition)
- **Plain text format**: one `ip:port` per line (our own simple format for easy editing)

---

## 16. File Sharing & Publishing

### Adding a File

Via `POST /api/v1/share { "path": "..." }`:

1. Daemon reads the file, computes Ed2k hash (MD4-based, chunked)
2. Inserts into `files` table (or updates `last_seen` if already known)
3. Inserts filename into `file_names`
4. Inserts into `shared_files`
5. Immediately triggers publish (keyword + source)
6. Returns `{ hash, size }`

### Removing a File

Via `DELETE /api/v1/share/{hash}`:

1. Removes row from `shared_files`
2. Stops re-publishing (removed from publish schedule)
3. File record remains in `files`, `file_names`, `file_tags` — the index is permanent
4. Returns 204

### File Verification

On each scheduled republish cycle, the daemon:

1. Reads `shared_files` where `last_verified` is oldest
2. Checks each file still exists at its path
3. If exists: update `last_verified`, republish
4. If missing: log a warning, remove from `shared_files`

### Publish Schedule

- On file add: immediate publish
- Scheduled: every `republish_interval_secs` (default 18000s ≈ 5 hours)
- Manual: `POST /api/v1/publish/{hash}`
- Current cold-start behavior: once Kad bootstrap succeeds, `overlord-agent-emule` immediately runs one seed-popular pass. It prefers coordinator `popular_hashes`, and falls back to a fixed agent-local set of 40 synthetic eMule-style keyword+source publishes only when the coordinator returns an empty list.

---

## 17. Testing Strategy

### Unit Tests (no network)

Every crate has `#[cfg(test)]` modules.

- `overlord-kad-proto`: encode/decode round-trips for every packet type using test vectors
- `overlord-kad-routing`: zone split/merge, contact add/remove, IP limit enforcement, XOR distance ordering
- `overlord-kad-net`: transport, obfuscation, RPC matching, flood controls
- `overlord-kad-dht`: bootstrap, traversal, search, publish
- `overlord-agent-emule`: agent orchestration, config loading, coordinator integration

### Test Vectors

Packet test vectors should live with `overlord-kad-proto` when added to this workspace.
Vectors are generated from reference implementations (eMule/aMule/libed2k) or captured from
the live network via Wireshark.

Each vector file is named `{packet_type}_{variant}.bin` and has a corresponding
`{packet_type}_{variant}.json` with the expected decoded struct.

### Integration Tests (live network, opt-in)

Marked with `#[ignore]` — not run in CI by default. Run manually with:

```
cargo test -- --ignored
```

- Bootstrap test: start a node, bootstrap from nodes.dat, verify routing table has ≥ 10 contacts within 60s
- Search test: search for a known keyword, verify ≥ 1 result within 90s
- Ping test: ping a known stable node, verify PONG received

### Mock Transport

`overlord-kad-net` exposes a `Transport` trait. A `MockTransport` implementation is provided for
testing `overlord-kad-dht` operations without real UDP sockets. Supports:
- Injecting fake incoming packets
- Capturing outgoing packets for assertion
- Simulated packet loss and delay

---

## 18. Phased Implementation Plan

This section is archival from the original implementation plan. It is not the current oracle parity
tracker; use the audit snapshot in §5 for current status.

### Phase 1 — Codec & Routing Table

Crates: `overlord-kad-proto`, `overlord-kad-routing`

- [ ] Workspace setup, `Cargo.toml`, CI skeleton
- [ ] `NodeId` type with XOR metric, distance functions
- [ ] `Ed2kHash` type
- [ ] `KadUdpKey` type
- [ ] eMule tag system (all tag types)
- [ ] All Kad2 packet structs with `binrw` encode/decode
- [ ] Test vectors for all packet types
- [ ] `Contact` struct
- [ ] `RoutingBin` (k-bucket)
- [ ] `RoutingZone` (binary tree, split logic)
- [ ] `RoutingTable` (owns root zone, provides `add_contact`, `get_closest`)
- [ ] IP/subnet limit enforcement
- [ ] Full unit test coverage for routing table

**Milestone**: Can decode any Kad2 packet from a binary buffer. Can build and query a routing
table without any network. All unit tests pass.

### Phase 2 — Transport & RPC

Crate: `overlord-kad-net`

- [ ] `Transport` trait + `UdpTransport` (Tokio)
- [ ] `MockTransport` for testing
- [ ] Outbound packet rate limiter
- [ ] `RpcManager` — transaction IDs, pending request map, timeout handling
- [ ] Obfuscation layer (RC4 encrypt/decrypt)
- [ ] Incoming packet demux (try obfuscated → try plain → drop)
- [ ] `PacketTracker` — per-IP flood detection
- [ ] Integration test: send PING to a real node, receive PONG

**Milestone**: Can exchange packets with a real eMule node on the network.

### Phase 3 — DHT Operations

Crate: `overlord-kad-dht`

- [ ] Bootstrap algorithm
- [ ] Iterative node lookup (find_node)
- [ ] Keyword search → `Stream<Item = SearchResult>`
- [ ] Source search → `Stream<Item = SourceResult>`
- [ ] Notes search
- [ ] Publish (keyword, source, notes)
- [ ] Publish scheduler (interval timer)
- [ ] Firewall UDP tester
- [ ] Integration tests (all marked `#[ignore]`)

**Milestone**: Can join the live Kad2 network, search for files, find sources, publish.

### Phase 4 — Agent Integration

Crates: `overlord-agent-common`, `overlord-agent-emule`

- [ ] TOML config loading
- [ ] coordinator registration
- [ ] active search dispatch
- [ ] passive crawl result posting
- [ ] snoop restore/flush
- [ ] popular-hash seed / republish
- [ ] graceful shutdown

**Milestone**: Kad agent runs inside Overlord and exchanges results with the coordinator.

### Phase 5+ — ED2K transfer and sharing parity

Crate: TBD

- ED2K peer TCP protocol
- Slot negotiation
- Chunk request/response
- Piece-store payload layout + durable resume manifest
- MD4 + AICH verification
- Download queue
- Upload queue and shared-file serving
- Integration with index (mark files as downloaded/shared)

**Milestone**: Native ED2K searching, sharing, upload, and download behavior
converges toward oracle parity without relying on an external downloader.

---

## 19. Key Dependencies

```toml
# Async runtime
tokio = { version = "1", features = ["full"] }

# Binary packet parsing (declarative, derive macros)
binrw = "0.14"

# Byte buffer management
bytes = "1"

# Web framework (agent internal API / coordinator services)
axum = "0.7"
tower = "0.4"
tower-http = "0.5"

# Error handling
thiserror = "1"
anyhow = "1"

# Logging / tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tracing-appender = "0.2"

# Config
serde = { version = "1", features = ["derive"] }
toml = "0.8"

# Crypto (obfuscation)
rc4 = "0.1"                 # RC4 stream cipher
crc32c = "0.6"              # CRC32C for node ID verification

# MD4 (ed2k file hashing)
md4 = "0.10"

# Random number generation
rand = "0.8"

# CLI argument parsing
clap = { version = "4", features = ["derive"] }

# UUIDs for jobs / indexers
uuid = { version = "1", features = ["v4"] }

# Async streaming
async-stream = "0.3"
tokio-stream = "0.1"
```

---

## 20. Future Work

### Kad1 Support

> **FUTURE(kad1)**: Kad1 (legacy protocol, opcodes 0x01-0x1F range) is intentionally not
> implemented. At time of writing (2026), the live network is overwhelmingly Kad2. Implementing
> Kad1 would add significant complexity with minimal benefit. If ever needed, it would require
> a separate packet parser, separate routing table update rules, and a version negotiation layer.

### ED2K Server And Peer Protocol

Partial ED2K support already ships in `overlord-agent-emule`.

Current implemented scope:

- long-lived server TCP sessions for `OP_LOGINREQUEST`, `OP_OFFERFILES`
  keepalive, `OP_IDCHANGE`, keyword search, and source search
- callback-aware source modeling, including LowID detection and obfuscated
  source metadata
- downloader startup with secure-ident, filename and hashset requests, queue
  handling, and resumable verified-piece manifests
- listener-side queue-rank updates, verified-range serving, and reconnect-aware
  upload resume

Remaining parity work:

- broader `ServerSocket` feature coverage beyond the currently targeted subset
- eMule-like upload queue scoring and rotation instead of FIFO fixed slots
- adaptive multi-block downloader scheduling and the wider callback control flow
  that eMule couples to that scheduler
- AICH parity
- active ED2K notes search

### Buddy System / Firewall NAT Traversal

> **FUTURE(buddy)**: The FINDBUDDY / CALLBACK mechanism allows firewalled nodes to receive
> incoming connections via a "buddy" relay node. Deferred to Phase 3. When implemented:
> - `KADEMLIA_FINDBUDDY_REQ/RES` and `KADEMLIA_CALLBACK_REQ` are already modeled in the proto codec with oracle packet layouts
> - Buddy selection logic in routing table
> - Callback handling in the RPC layer
> - Config: `[dht] buddy_enabled = true`

### IPv6

> **FUTURE(ipv6)**: All address types currently use `Ipv4Addr`. IPv6 would require
> dual-stack socket handling and separate routing table instances.

### `KV6_001` — Kad2 IPv6-Compatible Overlay

> **FUTURE(kv6_001)**: See [KV6_001 Kad2 IPv6 Design](./KV6_001_KAD2_IPV6_DESIGN.md).
> The recommended model is a dual-overlay design:
> - preserve classic `kad4` wire compatibility
> - add a new IPv6-capable `kad6` overlay with Kad2-equivalent semantics
> - share routing and lookup quality improvements across both overlays without
>   breaking legacy packet compatibility

### AICH Hash Tree

> **FUTURE(aich)**: The Advanced Intelligent Corruption Handler hash tree is needed for
> chunk-level file verification during download. Deferred to Phase 7 (download crate).

### UPnP v2 / NAT-PMP

> **FUTURE(nat-pmp)**: NAT-PMP and PCP (Port Control Protocol) are alternatives to UPnP IGD.
> The `igd` crate supports IGD v1/v2. NAT-PMP would require a separate crate.

---

## 21. Code Conventions

### Kad1 / Future Work Markers

Use these comment markers so they are grep-able:

```rust
// KAD1_IGNORED: <reason>
// FUTURE(tag): <description>
```

### Error Handling

- `overlord-kad-proto`, `overlord-kad-routing`: use `thiserror` for typed errors
- `overlord-kad-net`, `overlord-kad-dht`: typed errors + `anyhow` for context in call sites
- `overlord-agent-common`, `overlord-agent-emule`: `anyhow` at orchestration boundaries

Never `.unwrap()` in non-test code. Use `expect("reason")` only where a panic is the
correct response to an invariant violation.

### Packet Parsing

All packet parsing returns `Result<T, ProtoError>`. No panics on malformed input.
Malformed or unrecognised packets from the network are logged at `debug` level and dropped.

### Async

- All async code targets Tokio exclusively
- No `async_std` or other runtimes
- Prefer `tokio::sync::mpsc` channels for cross-task communication
- Use `CancellationToken` from `tokio-util` for search/operation cancellation

### Windows Paths

Resolve `%APPDATA%` at runtime via `std::env::var("APPDATA")`. Do not hardcode paths.
Use `std::path::PathBuf` everywhere, not string concatenation.

### Versioning

Follow semver. Until v1.0.0, breaking API changes are permitted between minor versions.
The wire protocol is always Kad2-compatible regardless of library version.
