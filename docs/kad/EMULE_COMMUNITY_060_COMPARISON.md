# Stock eMule `community-0.60` Comparison

Isolated comparison between the current Rust Kad or ED2K runtime and the local
stock eMule `community-0.60` analysis tree.

Reference anchors used for this review:

- Kad:
  `Kademlia/net/KademliaUDPListener.cpp`,
  `Kademlia/kademlia/Indexed.cpp`,
  `Kademlia/routing/RoutingZone.cpp`,
  `Kademlia/routing/RoutingBin.cpp`,
  `Kademlia/net/PacketTracking.cpp`
- ED2K:
  `BaseClient.cpp`,
  `DownloadClient.cpp`,
  `UploadQueue.cpp`,
  `ServerConnect.cpp`,
  `ServerSocket.cpp`

## Executive Snapshot

| Area | Current status | Stock eMule comparison |
|---|---|---|
| Kad packet families | Close to oracle | Search, source, notes, and publish packet families are aligned closely enough for protocol work. |
| Kad routing | Close to oracle | Split rules and per-bin or per-subnet limits now track `RoutingZone.cpp` and `RoutingBin.cpp` closely. |
| Kad packet tracking | Close to oracle with one local extension | Request budgets match `PacketTracking.cpp`; Overlord keeps a separate relaxed `SearchRes` budget for harvest traffic. |
| Kad passive replay shape | Better than previous docs claimed | The snoop queue now preserves `start_position`, restrictive keyword payloads, and source or notes `size`; the old target-only doc claim was stale. |
| ED2K server session | Partial but credible | Login, keepalive, HighID or LowID handling, keyword search, source search, and callback-aware source decoding are implemented. |
| ED2K downloader | Partially aligned | Startup ordering is much closer to stock eMule, and the Rust runtime now keeps an adaptive rolling block window, but scheduler scope is still materially simpler. |
| ED2K listener or upload queue | Materially different | Verified-range serving and queue ranks exist, and the first score-ranked queue slice is implemented, but durable credits, real file priority, slot rotation, and harness/live queue evidence remain open. |
| ED2K notes | First active slice wired | ED2K-labeled notes search now reuses the stock-aligned Kad notes transport; richer note-author result modeling remains separate backlog work. |

## Kad Protocol And State Machine

Areas that are now close to stock eMule:

- `overlord-kad-proto/src/packet.rs` matches the stock search, source, notes,
  and publish wire families used from
  `Kademlia/net/KademliaUDPListener.cpp`.
- `overlord-kad-routing/src/zone.rs` and `src/bin.rs` now follow the stock
  split predicate from `RoutingZone.cpp CanSplit` plus the per-bin clustering
  limit enforced in `RoutingBin.cpp AddContact`.
- `overlord-kad-net/src/tracker.rs` mirrors the stock per-opcode request budgets
  from `PacketTracking.cpp` for bootstrap, hello, find-node, search, publish,
  firewall, buddy, callback, and ping traffic.
- `overlord-kad-dht/src/traversal.rs` registers peer identity before outbound
  search traffic and caps phase-2 fanout at the closest `K`, which is consistent
  with the stock jump-start search shape.

Intentional or accepted differences:

- `overlord-kad-dht/src/search.rs is_acceptable_keyword_result` is repo policy,
  not a direct port of the stock local keyword filtering in
  `Kademlia/kademlia/Indexed.cpp`.
- `overlord-kad-net/src/tracker.rs` adds a separate relaxed `SearchRes` budget
  so harvest traffic is not clipped by the generic incoming flood bucket.

Remaining Kad parity gaps:

- `overlord-agent-emule/src/agent.rs` records restrictive keyword searches, but
  local store replies still serve only the non-restrictive subset.
- notes search is wired for Kad, but distinct-note-author modeling remains
  lighter than the stock indexer behavior.

## ED2K Protocol And State Machine

Areas that are currently credible against stock eMule:

- `overlord-agent-emule/src/ed2k_server.rs` implements the core long-lived
  server session needed for `OP_LOGINREQUEST`, `OP_OFFERFILES` keepalive,
  `OP_IDCHANGE`, keyword search, source search, and callback-aware source
  decoding, which covers the parts of `ServerConnect.cpp` and `ServerSocket.cpp`
  that matter for the current agent workflow.
- `overlord-agent-emule/src/ed2k_tcp.rs` follows the observed startup order
  `HELLO -> HELLOANSWER -> secure-ident -> REQUESTFILENAME -> SETREQFILEID ->
  HASHSETREQUEST/ANSWER -> STARTUPLOADREQ -> ACCEPTUPLOADREQ -> REQUESTPARTS`,
  which is much closer to the stock `BaseClient.cpp` plus `DownloadClient.cpp`
  path than the earlier minimal implementation.
- secure-ident request, public-key exchange, queue-rank handling, resumed piece
  verification, split part frames, and compressed part frames are all modeled in
  the current Rust runtime.

Verified differences against stock eMule:

- `overlord-agent-emule/src/ed2k_transfer.rs` now has a deterministic
  score-ranked queue slice with friend-slot boost, LowID penalty, duplicate
  reconnect refresh, and a file-priority hook. Stock eMule `UploadQueue.cpp`
  still goes further with durable credit inputs, real file priority, duplicate
  and IP suppression in `AddClientToQueue`, and slot rotation with
  `CheckForTimeOver`.
- `overlord-agent-emule/src/ed2k_tcp.rs` now keeps an adaptive pending-block
  window with rolling refills and safe teardown for malformed or out-of-order
  replies, but stock eMule `DownloadClient.cpp CreateBlockRequests` and
  `SendBlockRequests` couple that scheduler to the wider pending-block list,
  download-rate, and A4AF behavior.
- `overlord-agent-emule/src/ed2k_server.rs` is intentionally narrower than the
  full `ServerSocket.cpp` feature surface. It does not claim full stock eMule
  coverage outside the targeted login, search, and source-search flow.
- active ED2K notes search is wired through the Kad notes transport, but
  note-author result modeling remains file-centric.
- callback coverage remains narrower than stock `BaseClient.cpp TryToConnect`,
  which spans direct TCP, direct UDP callback, server callback, Kad callback,
  and wait or abort branches.

## Current Review Conclusions

- Kad protocol work is no longer the main parity risk. Most remaining Kad
  differences are deliberate repo policy or live-acceptance tuning.
- The biggest stock-eMule delta is now ED2K peer behavior, not Kad wire
  encoding.
- The highest-value ED2K parity upgrade is closing the same-server large-file
  source-discovery blocker for the AICH realnet gate. After that, finish credit
  aware queueing and carry the adaptive downloader window through fuller
  eMule-style A4AF and file-selection parity.
- The doc set previously understated passive Kad replay fidelity. That has been
  corrected in the current tracked docs.
