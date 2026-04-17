# ED2K Parity State Machine

Canonical ED2K parity map for the agent runtime, tests, and scenario tooling.

Use this file as the protocol and scenario inventory for staged ED2K parity
work. The acceptance target is native capability coverage across both roles
where it materially improves live-network acceptance, reachability, or harvest
yield:

The canonical target statement now lives in
[ED2K 0.72a Full Parity Tracker](./ED2K_072A_FULL_PARITY_TRACKER.md): **full
stock eMule `v0.72a` parity, excluding obsolete protocol features only**.
Treat older `community-0.60` comparisons in this doc set as historical context,
not as the current end target.

- downloader and search consumer
- listener and upload server

And across the main live-mode dimensions:

- plaintext and obfuscated
- direct-dialable and callback-mediated
- queue-only and serving
- fresh transfer and resumed transfer
- small-file and large-file or hashset-gated startup

## Current Runtime Map

- `crates/overlord-agent-emule/src/ed2k_server.rs` currently implements the
  focused `ServerConnect` and `ServerSocket` subset needed for
  `OP_LOGINREQUEST`, `OP_OFFERFILES` keepalive, `OP_IDCHANGE`, keyword search,
  source search, and callback-aware source decoding.
- `crates/overlord-agent-emule/src/ed2k_tcp.rs` currently implements the
  downloader and listener handshake surface, including secure-ident, hashset
  startup, queue-rank handling, callback-session reuse, and verified upload
  serving.
- `crates/overlord-agent-emule/src/ed2k_transfer.rs` currently owns resume
  manifests, verified-piece bookkeeping, and the upload queue, but that queue is
  still FIFO and fixed-slot rather than stock-eMule scoring.

## Verified Differences Vs Stock eMule `community-0.60`

- downloader startup is now much closer to stock eMule `BaseClient.cpp` and
  `DownloadClient.cpp` than the earlier minimal flow, but the full seven-path
  `TryToConnect` callback matrix from `BaseClient.cpp` is not implemented end to
  end yet.
- upload queue behavior still diverges materially from `UploadQueue.cpp`: the
  Rust runtime grants fixed slots in FIFO order and reports queue rank as queue
  position, while stock eMule scores by credits, file priority, friend-slot and
  LowID handling, duplicate rejection, and session rotation.
- part scheduling still diverges materially from `DownloadClient.cpp`: the Rust
  downloader now keeps an adaptive pending-block window with rolling refills and
  safe teardown for malformed or out-of-order replies, but stock eMule couples
  that scheduler to broader A4AF, file-selection, and transfer-rate heuristics.
- ED2K server sessions are intentionally partial: they are sufficient for the
  current search and source-search workflow, but they do not yet claim the full
  `ServerSocket.cpp` feature surface.
- active ED2K notes search is still missing from the agent dispatch path.

## Core State Machine Axes

### 1. Source acquisition

Owned primarily by:

- `crates/overlord-agent-emule/src/agent.rs`
- `crates/overlord-agent-emule/src/ed2k_server.rs`

States:

1. candidate selected
2. background server source search started
3. background server source search completed or timed out
4. active one-shot server source search completed
5. Kad fallback completed
6. aggregated sources available
7. direct-dialable sources retained
8. callback-only sources retained for server callback path
9. sources merged into transfer manifest

Acceptance consequences:

- `0` returned sources is a source-search parity failure, not a handshake failure
- callback-only sources are normal and must not be bucketed as broken peers
- direct-dialable filtering must stay explicit in artifacts so callback-only and
  filtered-zero are distinguishable

Current real-network scenario:

- `kad.search-download.emule-harness.agent.realnet.v1`

Current grounded gap:

- the current pinned obfuscated replay reaches source-search start, then ends at
  `agent_source_search_returned_zero`

### 2. Downloader startup handshake

Owned primarily by:

- `crates/overlord-agent-emule/src/ed2k_tcp.rs`

Observed startup model in code:

1. TCP connect
2. `OP_HELLO`
3. `OP_HELLOANSWER`
4. secure-ident probe and completion
5. `OP_REQUESTFILENAME`
6. optional `OP_SETREQFILEID` for large-file startup
7. `OP_REQUESTSOURCES2`
8. `OP_AICHFILEHASHREQ`
9. `OP_HASHSETREQUEST` when required
10. fallback to `OP_STARTUPLOADREQ` if hashset stalls

Acceptance consequences:

- secure-ident gates the startup path for peers that require it
- hashset-first and direct-upload-first peers are both valid
- obfuscation changes readability, not the required ordering

Existing unit coverage in `ed2k_tcp.rs`:

- secure-ident-gated small-file startup
- large-file secure-ident before hashset and upload
- obfuscated packed startup with compressed parts
- hashset stall fallback to upload request

### 3. Queue and upload negotiation

Owned primarily by:

- `crates/overlord-agent-emule/src/ed2k_tcp.rs`
- `crates/overlord-agent-emule/src/agent.rs`

States:

1. upload requested
2. peer stays queued
3. queue ranking updates
4. late `ACCEPTUPLOADREQ`
5. slot granted
6. part requests begin

Acceptance consequences:

- queue-only peers are normal accepted outcomes
- late slot grants must not be treated as read-timeout failures too early
- queue-only sessions should not poison the overall harvest attempt
- stock-eMule parity is not met while queue rank remains FIFO position instead
  of score-driven queue state

Existing unit coverage:

- queue-only peer accepted without failure
- queued peer waits past read timeout for late accept upload

Current verified difference from stock eMule:

- `crates/overlord-agent-emule/src/ed2k_transfer.rs` keeps a FIFO
  `waiting_order`, promotes from the front, expires sessions by fixed timeout
  classes, and now preserves one queue entry per peer across reconnects and
  requested-file switches.
- stock eMule `UploadQueue.cpp` selects the next client with
  `FindBestClientInQueue`, handles LowID reconnect and duplicate suppression in
  `AddClientToQueue`, and rotates slots by payload, time, and score in
  `CheckForTimeOver`.

### 4. Part transfer and verification

Owned primarily by:

- `crates/overlord-agent-emule/src/ed2k_tcp.rs`
- `crates/overlord-agent-emule/src/ed2k_transfer.rs`

States:

1. next missing piece claimed
2. part request sent
3. split or compressed part frames received
4. payload written
5. piece verified
6. manifest completed

Acceptance consequences:

- split part frames and compressed frames are normal
- malformed ranges must release claims safely
- resume manifest is part of the parity surface, not just persistence plumbing
- full stock-eMule parity is not met while the downloader scheduler remains
  single-piece and does not yet expose the wider A4AF/file-switching behavior

Existing unit coverage:

- split sending-part frames
- split compressed-part frames
- malformed ranges release pending piece
- partial piece resume after reconnect

Current verified difference from stock eMule:

- `crates/overlord-agent-emule/src/ed2k_tcp.rs` now keeps an adaptive
  pending-block window and refill thresholds inside one claimed piece, and it
  tears down safely on malformed or out-of-order block replies.
- stock eMule `DownloadClient.cpp CreateBlockRequests` and `SendBlockRequests`
  go further by integrating that window with the broader pending-block list,
  A4AF, and peer/file scheduling behavior.

### 5. Callback path

Owned primarily by:

- `crates/overlord-agent-emule/src/agent.rs`
- `crates/overlord-agent-emule/src/ed2k_tcp.rs`
- `crates/overlord-agent-emule/src/ed2k_server.rs`

States:

1. callback-only source retained
2. callback intent registered
3. server callback request issued
4. callback session connects back
5. completed hello reused or re-established
6. normal upload negotiation resumes

Acceptance consequences:

- callback request and callback completion must be observable separately
- plaintext and obfuscated callback connect mode selection both matter
- real LowID callback completion may require private or controlled validation
- full stock-eMule parity requires direct UDP callback, server callback, and Kad
  callback branches, not only the currently covered subset

Existing coverage:

- callback connect transport selection tests
- callback session with completed hello starts upload flow
- local triplet validation for callback request and failure handling:
  `ed2k.server.triplet.validation.v1`

### 6. Listener and upload serving

Owned primarily by:

- `crates/overlord-agent-emule/src/ed2k_tcp.rs`
- `crates/overlord-agent-emule/src/ed2k_transfer.rs`

States:

1. inbound hello accepted
2. startup tolerates source exchange and AICH probe
3. `STARTUPLOADREQ` accepted
4. queue ranking emitted when serving slot unavailable
5. waiter promoted after disconnect or cancel
6. reconnect matched by hello identity
7. resumed upload serves remaining verified ranges

Acceptance consequences:

- the listener must not look like a dead-end helper socket
- upload queue behavior is part of parity, not just local fairness policy
- reconnect and resume behavior must preserve transfer continuity
- listener parity is still incomplete while the queue policy remains FIFO rather
  than score and credit driven

Existing unit coverage:

- verified-file upload via compressed parts
- startup tolerates source exchange and AICH probe
- queue promotion after disconnect
- queue promotion after cancel
- queue rank refresh before promotion
- reconnect by hello identity
- resumed upload after reconnect

## Scenario Inventory

### Real-network scenarios

| Scenario | Purpose | Current strength | Main gaps |
| --- | --- | --- | --- |
| `kad.search-download.emule-harness.agent.realnet.v1` | Harness vs agent search plus native ED2K download parity | Good for source acquisition and downloader phase evidence in plaintext and obfuscated modes | Listener parity is out of scope; serving-peer availability is live-network dependent |
| `ed2k.server.emule-harness.agent.roundtrip.realnet.v1` | Real-network ED2K server roundtrip from harness to agent and back to harness | Good for server-session visibility and re-offer confidence | Not yet the primary parity matrix for callback, queue-only, or listener queue semantics |

### Private and deterministic scenarios

| Scenario | Purpose | Current strength | Main gaps |
| --- | --- | --- | --- |
| `ed2k.server.emule-harness.agent.private.v1` | Private local harness and agent download through local server | Deterministic server-session and download startup validation | Does not cover full listener queue matrix yet |
| `ed2k.server.triplet.validation.v1` | Focused local triplet validation | Good for multi-source and callback-request coverage | Callback completion remains limited by loopback HighID constraints |
| `kad.emule-harness.ed2k.download.private.v1` | Private harness-to-agent download path | Useful for deterministic transfer checks | Needs expansion into a fuller downloader parity matrix |
| `kad.harness.triplet.local.v1` | Harness and triplet local Kad or ED2K flow coverage | Useful local control path | Not yet the canonical ED2K transfer matrix |

## Recommended Parity Matrix

Every ED2K parity slice should identify the exact cell it advances:

| Role | Transport | Reachability | Peer outcome | Transfer state |
| --- | --- | --- | --- | --- |
| downloader | plaintext | direct | queue-only | fresh |
| downloader | plaintext | direct | serving | fresh |
| downloader | obfuscated | direct | queue-only | fresh |
| downloader | obfuscated | direct | serving | fresh |
| downloader | plaintext | callback | callback-issued | fresh |
| downloader | obfuscated | callback | callback-issued | fresh |
| downloader | plaintext | direct | serving | resume |
| downloader | obfuscated | direct | serving | resume |
| listener | plaintext | inbound | queue-only | fresh |
| listener | plaintext | inbound | serving | fresh |
| listener | obfuscated | inbound | queue-only | fresh |
| listener | obfuscated | inbound | serving | fresh |
| listener | plaintext | inbound | serving | resume |
| listener | obfuscated | inbound | serving | resume |

The matrix is intentionally role-first. Full parity requires both downloader and
listener behavior, not just transfer completion in one direction.

## Acceptance Rules

Treat a parity slice as complete only when all three layers exist:

1. state-machine coverage
   unit tests or deterministic private scenarios hit the branch explicitly
2. scenario evidence
   tooling artifacts make the first divergent stage explicit
3. live confidence where applicable
   at least one real-network or harness-comparison run demonstrates the branch
   in the intended mode

Do not collapse these buckets:

- `returned_zero_sources`
- `filtered_to_zero`
- `callback_only`
- `queued_but_accepted`
- `slot_granted_but_no_part_progress`
- `listener_queue_waiting`
- `resume_reconnected`

## Current Priorities

1. replace FIFO upload queue behavior with stock-eMule-like queue scoring and slot rotation
2. extend the new adaptive pending-block window into fuller eMule-style scheduler and A4AF control flow
3. extend callback parity across direct UDP, server callback, and Kad callback branches
4. wire active ED2K notes search and the remaining targeted server-session surface
5. keep real-network and private-scenario evidence current for both downloader and listener roles

## Code Ownership

- runtime orchestration:
  `p2p-overlord-tooling/orchestration/Invoke-RealnetKadSearchDownloadParityScenario.ps1`
- agent session helpers and deterministic runs:
  `p2p-overlord-tooling/subsystems/agent/helper-agent-*.ps1`
  `p2p-overlord-tooling/orchestration/Invoke-ValidateEd2kServerTriplet.ps1`
- ED2K downloader and listener protocol:
  `crates/overlord-agent-emule/src/ed2k_tcp.rs`
- ED2K server session and source search:
  `crates/overlord-agent-emule/src/ed2k_server.rs`
- transfer state, resume manifest, and upload queue:
  `crates/overlord-agent-emule/src/ed2k_transfer.rs`
- source acquisition and session integration:
  `crates/overlord-agent-emule/src/agent.rs`
