# KV6_001 — Kad2 IPv6-Compatible Overlay Design

Feature track `KV6_001` defines a Kad2-compatible, IPv6-capable distributed
search and sharing design. The central constraint is strict:

- preserve legacy Kad2 IPv4 wire compatibility
- do not overload classic 32-bit contact fields with ad hoc IPv6 hacks
- add IPv6 through a parallel Kad2-derived overlay which preserves Kad2 search,
  publish, and lookup semantics

This document is a design and rollout reference for baking the feature into the
eMule lineage first and then porting the same model into Overlord.

## 1. Goals

`KV6_001` must deliver all of the following:

- full legacy Kad2 interoperability on IPv4
- native IPv6-capable Kad-style distributed search and publish
- no protocol break for existing Kad2 nodes
- one logical search/publish system across IPv4 and IPv6
- room for internal quality improvements without wire incompatibility

## 2. Non-Goals

`KV6_001` does not attempt to:

- make classic Kad2 IPv4 nodes parse IPv6 contacts
- reuse the existing 4-byte contact format for IPv6
- introduce a supernode or hub layer
- replace XOR routing, iterative lookups, or Kad2 publish semantics
- depend on ED2K server support

## 3. Background

Classic Kad2 is IPv4-shaped on the wire. Contact and endpoint surfaces are
fundamentally built around `uint32` IP fields plus UDP/TCP ports. That means
native IPv6 cannot be added safely by reinterpreting existing contact layouts.

The correct model is the same one adopted by IPv6-capable Mainline DHT
implementations:

- keep the IPv4 overlay intact
- add a separate IPv6 overlay
- share higher-level semantics while keeping transport and contact encodings
  family-correct

## 4. References

Primary references for `KV6_001` design:

- Kademlia paper:
  - Petar Maymounkov and David Mazières, "Kademlia: A Peer-to-Peer
    Information System Based on the XOR Metric"
  - https://www.scs.stanford.edu/~dm/home/papers/kpos.pdf
- Mainline DHT IPv6 split:
  - BEP 32, "BitTorrent DHT Extensions for IPv6"
  - https://www.bittorrent.org/beps/bep_0032.html
- Mainline DHT security and node identity:
  - libtorrent DHT security extension
  - https://www.libtorrent.org/dht_sec.html
- Libtorrent DHT extension surfaces for alternative node encodings:
  - https://www.libtorrent.org/dht_extensions.html
- IPFS public DHT operational model:
  - https://docs.ipfs.tech/concepts/dht/
  - https://specs.ipfs.tech/routing/kad-dht/
- Gnutella2 search-efficiency inspiration:
  - Query hash tables: https://g2.doxu.org/wiki/Query_Hash_Tables
  - Object search: https://g2.doxu.org/wiki/Object_Search_Mechanism
- Lookup hardening and attack resistance:
  - ReDS technical report:
    https://homes.luddy.indiana.edu/kapadia/papers/reds-tr.pdf

Local oracle and mod references:

- `C:\prj\p2p\eMule\analysis\eMuleAI\Release_Notes.txt`
- `C:\prj\p2p\eMule\analysis\eMuleAI\srchybrid\BaseClient.cpp`
- `C:\prj\p2p\eMule\analysis\eMule-mods-archive\eMule-0.50a-neomuleneomule_reloaded-fa3debb\srchybrid\BaseClient.cpp`
- `C:\prj\p2p\eMule\analysis\eMule-mods-archive\eMule-0.50a-neomuleneomule_reloaded-fa3debb\srchybrid\Neo\Address.h`
- `C:\prj\p2p\eMule\analysis\eMule-mods-archive\eMule-0.50a-neomuleneomule_reloaded-fa3debb\srchybrid\kademlia\net\KademliaUDPListener.cpp`

## 5. What eMuleAI and NeoMule Already Prove

The mod trees prove that IPv6 support is practical in adjacent layers:

- dual-stack socket handling
- IPv6-aware peer/client identity handling
- IPv6 hello tags and capability flags
- IPv6-friendly direct and buddy paths
- generic address abstractions

They do not prove a finished native IPv6 Kad DHT wire format.

Observed constraints:

- `eMuleAI` explicitly describes IPv6 as early alpha in its release notes.
- `NeoMule Reloaded` contains substantial IPv6 plumbing, but its Kad listener
  still uses `uint32` destination-host style Kad surfaces.
- both are useful implementation references for address abstraction and peer
  signaling, not as a complete Kad2-over-IPv6 oracle.

## 6. Core Architecture

`KV6_001` defines two overlays and one logical service:

- `kad4`
  - the existing Kad2 IPv4 network
  - unmodified wire format
  - full legacy interoperability
- `kad6`
  - a new IPv6-capable Kad2-derived overlay
  - same XOR keyspace semantics
  - family-correct IPv6 contact encoding
- merged service layer
  - search, publish, and result aggregation span both overlays

This is the same high-level strategy as BEP 32:

- separate routing tables
- separate bootstrap pools
- separate reachability state
- shared higher-level semantics

## 7. Compatibility Rules

`KV6_001` compatibility rules are mandatory:

1. `kad4` packets remain byte-for-byte Kad2 compatible.
2. `kad6` packets use new IPv6-capable contact layouts.
3. `kad4` never stores or forwards IPv6-only contacts.
4. `kad6` never stores or forwards IPv4-only contacts as if they were IPv6.
5. Searches and publishes may run on both overlays, but transport state stays
   family-local.

## 8. Node Identity Model

Use one logical node identity across both overlays:

- one Kad node ID
- one publish/search key derivation model
- one logical DHT participant

But keep transport presence separate:

- `kad4` endpoint set and reachability
- `kad6` endpoint set and reachability
- separate firewall verification state
- separate routing tables

This preserves user-visible behavior while avoiding family confusion inside the
 routing layer.

## 9. Wire Strategy

`KV6_001` should preserve Kad2 opcode families conceptually:

- bootstrap
- hello
- node lookup
- keyword search
- source search
- notes search
- keyword publish
- source publish
- notes publish
- firewall and callback helpers

But `kad6` must use new packet and contact encodings.

Recommended rule:

- preserve opcode intent and state-machine behavior
- introduce a `KADEMLIA6_*` family or version-negotiated `KADEMLIA2_V6_*`
  family for IPv6-capable packet bodies
- use explicit 16-byte IPv6 address fields
- keep UDP/TCP ports, node IDs, and obfuscation metadata first-class

## 10. Contact Model

`kad6` contacts should carry:

- `node_id`
- `ip_family`
- `ipv6`
- `udp_port`
- `tcp_port`
- `version`
- `udp_key`
- `verified` flags
- `feature_bits`

Suggested feature bits for `KV6_001`:

- `KV6_FEATURE_IPV6_CONTACTS`
- `KV6_FEATURE_DUAL_STACK_NODE`
- `KV6_FEATURE_REQ_ACK`
- `KV6_FEATURE_FIREWALL_PROBE`
- `KV6_FEATURE_EXTENDED_SOURCE_RESULT`
- `KV6_FEATURE_PUBLISH_OBSERVABILITY`

The feature bits should be carried only in `kad6` packet bodies or capability
tags, never grafted into legacy `kad4` fields where an old client would
misinterpret them.

## 11. Routing Model

Routing remains XOR-based.

`KV6_001` changes routing management, not routing mathematics:

- one routing table for `kad4`
- one routing table for `kad6`
- same bucket and distance logic
- family-local replacement caches
- family-local liveness and scoring

Recommended improvements that do not break protocol:

- per-contact score using:
  - response success rate
  - timeout streak
  - rolling RTT
  - age and stability
  - prefix diversity
- family-aware replacement policy
- stronger anti-clustering policy for very close contacts
- disjoint-path lookup scheduling

## 12. Search Model

Search remains iterative and XOR-targeted, but the runtime should:

- search `kad4` and `kad6` in parallel when both are enabled
- keep family-local frontier queues
- merge results by semantic identity above transport
- preserve source-family metadata on results

Search improvements that are protocol-safe:

- adaptive `alpha`
- per-family timeout budgets
- family-aware result saturation thresholds
- query-family-aware contact ranking based on local success history

The Gnutella2 lesson applies here:

- do not flood blindly
- rank neighbors by historical usefulness for the query family
- preserve stop conditions that avoid wasting traffic once close-enough or
  saturated-enough conditions are met

## 13. Publish Model

Publish must run per overlay:

- keyword publish to `kad4` nearest set
- keyword publish to `kad6` nearest set
- source publish to `kad4` if the node is reachable on IPv4
- source publish to `kad6` if the node is reachable on IPv6
- notes publish to both as configured

Protocol-safe publish improvements:

- per-prefix acceptance tracking
- re-publish selection based on acceptance density
- stronger retry suppression for bad prefixes
- family-aware publish observability

## 14. Firewall and Reachability

Reachability must be family-specific:

- IPv4 UDP reachable
- IPv4 TCP reachable
- IPv6 UDP reachable
- IPv6 TCP reachable

Do not project one family’s reachability onto the other.

The `kad6` overlay should only advertise an IPv6 source/contact as public when:

- the address is global-scope
- UDP reachability has been verified or strongly inferred
- local policy allows public participation

This mirrors IPFS-style public DHT qualification and improves table quality.

## 15. Security Hardening

`KV6_001` should keep all improvements local and protocol-safe first.

Recommended hardening:

- local reputation only
- disjoint-path lookups
- duplicate-suppression on result and contact intake
- prefix-capture detection
- endpoint-family validation on intake
- stricter verification before promoting a contact into the primary table

Do not introduce shared global reputation. ReDS shows it creates new attack
surfaces even when it appears useful in simulation.

## 16. Result Aggregation

Result aggregation sits above both overlays and must preserve:

- family of origin
- contact family
- publish family
- source-family transport hints

Recommended merge key policy:

- keyword results: merge by ED2K hash plus semantic metadata
- source results: merge by file hash and endpoint
- notes results: merge by file hash plus source/author identity

The user-visible system should look like one distributed search fabric even
though it is backed by `kad4` plus `kad6`.

## 17. Observability

`KV6_001` requires reusable JSONL evidence.

Add:

- `kad4` packet dumps
- `kad6` packet dumps
- routing score dumps
- search frontier dumps
- publish acceptance dumps
- reachability-state dumps
- merge-layer result provenance dumps

Required comparisons:

- `kad4` vs classic eMule oracle
- `kad6` vs internal conformance scenarios
- dual-stack merged search behavior under controlled test swarms

## 18. Phases

### Phase KV6_001.1 — Address and endpoint abstraction

- add family-neutral endpoint/contact types
- preserve current `kad4` behavior unchanged
- port dual-stack socket primitives and address abstractions

Deliverables:

- `IpAddr`/`SocketAddr`-like internal wrappers where needed
- family-aware reachability model
- no wire change yet

### Phase KV6_001.2 — Dual routing tables

- add `kad4` and `kad6` routing-table ownership
- keep `kad6` internal-only at first
- add family-local scoring and replacement policy

Deliverables:

- separate table state
- shared logical lookup planner
- JSONL routing observability

### Phase KV6_001.3 — `kad6` wire specification

- define `kad6` contact encoding
- define `kad6` hello/bootstrap packet family
- define capability tags and feature bits

Deliverables:

- packet reference
- conformance fixtures
- version-negotiation or explicit family selection rules

### Phase KV6_001.4 — `kad6` bootstrap and hello

- implement `kad6` listener and sender
- implement `kad6` bootstrap flow
- verify dual-stack reachability handling

Deliverables:

- internal `kad6` swarm tests
- routable IPv6 contact exchange

### Phase KV6_001.5 — `kad6` lookup/search

- implement `kad6` node lookup
- implement `kad6` keyword/source/notes search
- merge results above transport

Deliverables:

- dual-overlay search execution
- family-aware merged search results

### Phase KV6_001.6 — `kad6` publish

- implement keyword/source/notes publish for `kad6`
- add family-aware publish observability
- verify acceptance behavior on IPv6-capable peers

Deliverables:

- dual-overlay publish planner
- publish result telemetry per family

### Phase KV6_001.7 — Protocol-safe quality improvements

- adaptive `alpha`
- disjoint-path lookups
- local reputation
- query-family-aware ranking
- smarter stop conditions

Deliverables:

- no wire break
- measurable lookup quality gains

### Phase KV6_001.8 — eMule-first baking

- bake `kad6` into eMule-family code first
- capture live dual-stack evidence
- freeze packet and state-machine behavior before Overlord ports it

Deliverables:

- stable upstream behavior reference
- packet captures / JSONL equivalent
- rollout notes for Overlord porting

### Phase KV6_001.9 — Overlord port

- port the frozen `kad6` model into Overlord crates
- preserve `kad4` oracle parity while adding `kad6`

Deliverables:

- dual-stack agent
- merged distributed search/publish
- explicit family-aware observability

## 19. Feature IDs

Recommended feature IDs under `KV6_001`:

- `KV6_001_A01` dual-stack address abstraction
- `KV6_001_A02` family-aware reachability state
- `KV6_001_R01` dual routing tables
- `KV6_001_R02` contact scoring and replacement policy
- `KV6_001_W01` `kad6` contact encoding
- `KV6_001_W02` `kad6` hello/bootstrap packets
- `KV6_001_W03` `kad6` search packet family
- `KV6_001_W04` `kad6` publish packet family
- `KV6_001_S01` dual-overlay search planner
- `KV6_001_S02` result merge layer
- `KV6_001_P01` dual-overlay publish planner
- `KV6_001_H01` disjoint-path lookups
- `KV6_001_H02` adaptive concurrency
- `KV6_001_H03` local reputation
- `KV6_001_O01` packet JSONL dumps
- `KV6_001_O02` routing/search/publish evidence dumps

## 20. What Improves Kad2 Without Breaking It

The following improvements are explicitly in scope without changing legacy Kad2
wire compatibility:

- adaptive `alpha`
- disjoint-path lookup scheduling
- family-specific contact scoring
- stricter public-table admission
- better stop conditions
- smarter publish retry policy
- result and contact duplicate suppression
- richer observability

These should land even if `kad6` takes longer than expected, because they
improve the existing `kad4` network behavior immediately.

## 21. What Must Not Be Done

The following would create long-term protocol debt:

- storing IPv6 contacts inside classic `uint32` Kad address fields
- merging IPv4 and IPv6 contacts into one routing table
- inventing a centralized relay layer for public search
- changing legacy `kad4` packet bodies in a way old clients cannot parse
- treating eMuleAI or NeoMule peer IPv6 tags as if they already define a full
  Kad IPv6 protocol

## 22. Decision Summary

`KV6_001` should be implemented as:

- one logical Kad service
- two overlays: `kad4` and `kad6`
- unchanged classic Kad2 interoperability on IPv4
- new IPv6-capable packet and contact encoding for `kad6`
- protocol-safe quality improvements shared by both overlays

That is the only path which is technically coherent, preserves Kad2
compatibility, and creates a real IPv6-capable distributed search and sharing
system instead of an IPv6-shaped compatibility illusion.
