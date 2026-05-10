# ED2K 0.72a Current Protocol Tracker

Canonical tracker for the current ED2K protocol target in
`overlord-agent-emule`.

## Target

The ED2K target for this repo is **latest/current live-network ED2K behavior
only**. Stock eMule `v0.72a` is the main oracle for currently advertised
behavior, but legacy protocol variants and obsolete fallback paths are
out of scope unless the user explicitly re-scopes the work.

This is an explicit hard-scope statement:

- not full historical eMule behavior parity
- not legacy variation coverage
- not old-client compatibility for its own sake
- not community-0.60 parity
- not obsolete fallback implementation

If stock eMule `v0.72a` exposes a current advertised ED2K behavior on the live
network, this repo should treat that behavior as in scope until equivalent
current behavior is reached. If the behavior is a legacy variant, compatibility
fallback, or obsolete surface, it is out of scope by default.

## Out Of Scope By Default

The following ED2K protocol surfaces are legacy or obsolete for the current
target:

- legacy outbound `OP_MULTIPACKET`
- legacy outbound `OP_MULTIPACKETANSWER`
- legacy outbound `OP_MULTIPACKET_EXT`
- legacy standalone `OP_AICHFILEHASHREQ` / `OP_AICHFILEHASHANS` as the primary
  active path once `FileIdentifier` + modern AICH tree parity is implemented
- peer-cache advertisement

Do not add inbound or outbound implementations for deprecated packets unless
the user explicitly re-scopes the work and live-network evidence justifies the
exception.

## Current Scope

The following remain in scope when they use the latest/current live-network
ED2K behavior:

- peer hello and hello-answer behavior
- server login and server-session behavior
- download startup and transfer behavior
- upload queue and serving behavior
- secure-ident and credit-aware behavior
- low-ID buddy and callback behavior
- `FileIdentifier` and `OP_MULTIPACKET_EXT2`
- modern AICH tree behavior
- preview request and answer behavior
- shared-files and shared-directories browsing behavior
- chat and chat-captcha behavior
- active ED2K notes search
- downloader control flow that materially affects stock `v0.72a` behavior

## Current Progress

- [x] Stock `v0.72a`-style `OP_HELLO` / `OP_HELLOANSWER` / `OP_LOGINREQUEST`
      identity and capability profile
- [x] Secure-ident probe, public-key, and signature exchange
- [x] `OP_REQUESTSOURCES2` / `OP_ANSWERSOURCES2` request-answer coverage
- [x] Callback-aware server source acquisition, including manifest-backed
      plaintext and obfuscated callback-only source-acquisition cells
- [x] Listener upload subset with queue-rank and file-description handling
- [x] Verified upload serving and resumable download coverage for the current
      subset
- [x] `FileIdentifier` model plus modern startup `OP_MULTIPACKET_EXT2` /
      `OP_MULTIPACKETANSWER_EXT2` parity on the current downloader and listener
      subset
- [x] Modern `OP_HASHSETREQUEST2` / `OP_HASHSETANSWER2` transport for the
      `FileIdentifier` path with MD4 hashset coverage
- [x] Hash-only native download bootstrap that learns canonical name and file
      size from peer startup metadata on the active `FileIdentifier` path
- [x] Hash-only live source acquisition that resolves metadata via exact
      `ed2k::<hash>` server keyword search and still runs Kad source
      supplementation once size is known
- [x] Large-file live `server.met` validation for the current
      `FileIdentifier` / `OP_MULTIPACKET_EXT2` / `OP_HASHSETREQUEST2` /
      compressed-part transfer path
- [x] Modern AICH transport and verifier acceptance on the active
      `FileIdentifier` / `OP_HASHSETREQUEST2` / `OP_HASHSETANSWER2` path
- [x] Stock-truthful local AICH root + part-hash generation for the tracked
      deterministic tracing-harness fixture and local-ingest path without
      relying on peer-supplied AICH
- [ ] Fresh large-file real-network evidence that the locally generated AICH
      identity remains truthful outside the private harness matrix
- [ ] Stock `UploadQueue.cpp`-style credit, score, LowID, and friend-slot
      behavior; the first score-ranked queue slice is implemented, but durable
      credit inputs and harness/live parity evidence remain open
- [ ] Full buddy / callback matrix and buddy-tag parity for firewalled mode
- [ ] Preview request / answer parity
- [ ] Shared-files and shared-directories browsing if current live peers still
      expose it
- [ ] Chat and chat-captcha if current live peers still expose it
- [x] Active ED2K notes search
- [ ] Broader downloader scheduler parity where stock `v0.72a` behavior depends
      on A4AF / global scheduling decisions
- [ ] Broader `ServerSocket.cpp` parity beyond the current focused subset

## Strong Completion Rule

Do **not** call the ED2K work "done" while any current advertised feature
remains unsupported.

Current example:

- chat and captcha remain backlog candidates only if current live peers still
  expose them, and the hello profile must not advertise unsupported captcha
  support until a truthful challenge/response implementation exists.
- file comments remain backlog candidates only if current live peers still
  expose them, and `CT_EMULE_MISCOPTIONS1` and `OP_EMULEINFO` must not
  advertise comment support until comment exchange and persistence exists.

## Vector Hygiene

Live ED2K hashes, full links, and other real-network test vectors must stay in
gitignored local files and local run artifacts only.

Tracked docs, tests, manifests, and examples should use generic placeholders or
explicitly synthetic fixtures instead of committing live-network vectors.

## Current Next Step

The active next milestone is:

1. fix same-server live source discovery for harness-exported large files so
   `ed2k.cell.modern-aich.plaintext.server-roundtrip.large.realnet.v1` can
   acquire usable sources, bytes, and MD4/AICH hashset evidence
2. keep the network-learned AICH identity authoritative wherever the active
   path has already validated it
3. keep the local AICH builder aligned with the stock tracing harness fixture
   so completed payloads generate the same root and part-hash set without
   peer-supplied AICH
4. keep the deterministic private large-file loopback gates green on the direct
   ED2K and Kad-discovered paths while the builder changes land
5. rerun the dedicated large-file realnet scenario until the stock-truthful
   local generation path also stays green outside the local harness matrix
6. extend the same truthfulness rule to every current advertised ED2K feature
   that remains unimplemented; chat-captcha and file comments remain backlog
   candidates only if they are current live-network behavior, and unsupported
   captcha/comments are no longer advertised in the hello / eMuleInfo profiles

This remains the highest-leverage next step because the downloader and listener
now use the modern `FileIdentifier` + `EXT2` + `HASHSETREQUEST2` transport and
the active-path verifier already accepts truthful AICH there. The current
blocker is not AICH transport or local-generation logic by itself; it is getting
the live same-server source-discovery stage to return the harness-exported large
file so the real-network closure can exercise that logic.

## Current Evidence

As of **April 17, 2026**, the private deterministic harness path confirms the
modern startup flow:

- `cargo test --workspace` passed after the `FileIdentifier` / `EXT2` changes
- `cargo clippy --workspace --all-targets --all-features -- -D warnings -W clippy::all` passed
- the downloader accepts hash-only requests and upgrades the manifest from peer
  `OP_MULTIPACKETANSWER_EXT2` / `OP_REQFILENAMEANSWER` metadata, covered by
  `hash_only_small_file_download_learns_metadata_from_startup_answer` and
  `reconcile_job_metadata_adopts_unknown_size_and_name`
- the private scenario `ed2k.server.emule-harness.agent.private.v1` completed
  successfully and captured inbound `OP_MULTIPACKET_EXT2` plus outbound
  `OP_MULTIPACKETANSWER_EXT2`

As of **April 17, 2026**, live `server.met` validation is green for the current
small-file acceptance gate:

- `ed2k.server.emule-harness.agent.roundtrip.realnet.v1-20260417-172433`
  completed successfully
- the selected live server came from the canonical imported `server.met` bundle
- the run confirmed live server-session establishment, agent download,
  republish, harness download completion, and harness verifier `MD4: OK -
  AICH: OK`

Important limitation:

- that live roundtrip used a `262144` byte file, so it did **not** exercise the
  large-file `OP_HASHSETREQUEST2` / `OP_HASHSETANSWER2` or modern AICH payload
  branch
- the live run is therefore valid evidence for publish/download/re-offer
  acceptance on a real server selected from `server.met`, but **not**
  sufficient evidence for modern AICH transport parity

As of **April 17, 2026**, the dedicated large-file live `server.met` validation
is also green for the modern `FileIdentifier` transport branch:

- `ed2k.server.roundtrip.realnet.large.v1-20260417-182434` completed
  successfully
- the selected live server again came from the canonical imported `server.met`
  bundle
- the seeder-side harness dump shows the agent driving the modern large-file
  startup path with `OP_MULTIPACKET_EXT2`, `OP_MULTIPACKETANSWER_EXT2`,
  `OP_HASHSETREQUEST2`, and `OP_HASHSETANSWER2`
- the seeder-side and downloader-side harness dumps confirm sustained
  compressed-part transfer on the large-file path
- the harness verifier confirms large-file parts as `MD4: OK` while still
  reporting `AICH: Unavailable`, which is the remaining truth gap for this
  branch
- the agent artifacts for this successful run do not contain the prior
  `out_of_order_compressed_part_range` / `out_of_order_part_range` diagnostics

As of **April 17, 2026**, an additional private local-vector probe against the
canonical imported `server.met` pool confirms the hash-only live search path:

- the agent issues exact background ED2K keyword search queries using the
  `ed2k::<hash>` form, reconciles manifest name and size from the matching live
  server result before source acquisition, and then proceeds to `OP_GETSOURCES`
  with the learned size
- Kad source search is executed as a supplement after server-assisted discovery
  once the file size is known
- the tested private vector remained single-source in that run, so this is
  evidence that the search path is truthful and wider than before, but **not**
  yet evidence that live multi-source acquisition is consistently available for
  arbitrary vectors

As of **April 19, 2026**, deterministic local large-file loopback coverage is
also green for the active modern path:

- `ed2k.server.emule-harness.agent.roundtrip.private.large.v1-20260418-211341`
  completed successfully with exported AICH links, stage1/stage2
  `OP_HASHSETREQUEST2` and `OP_HASHSETANSWER2` AICH coverage, compressed parts,
  and harness verifier `AICH: OK`
- `kad.emule-harness.agent.download.private.large.v1-20260418-220231`
  completed successfully in obfuscated mode and confirms Kad-discovered
  large-file transfer with exported AICH sidecar data, `OP_HASHSETREQUEST2` /
  `OP_HASHSETANSWER2` AICH exchange, and compressed parts
- `kad.agent.emule-harness.download.private.large.v1-20260418-235210`
  completed successfully in obfuscated mode after fixing the source-publish
  identity byte order, and the harness confirms `Sending HashSet Request: MD4
  Yes, AICH Yes` plus per-part `MD4: OK - AICH: OK`

This closes the previous reverse-Kad obfuscated transport blocker. The
remaining `ITEM_031` gap is fresh large-file real-network evidence for the
stock-truthful local AICH generation path, not active-path transport, verifier
acceptance, or the deterministic fixture calculation itself.

As of **May 2, 2026**, tracked unit coverage also asserts the local generation
side against the deterministic tracing-harness fixture:

- `build_aich_hashset_matches_stock_tracing_harness_large_roundtrip_fixture`
  checks the expected AICH root and per-part hash set for the 10 MiB large-file
  fixture
- `ingest_local_file_marks_payload_complete_with_stock_aich_identity` confirms
  local ingest persists the same stock AICH identity into the transfer manifest
- `completed_manifest_preserves_remote_aich_identity_over_local_rebuild` keeps
  the network-learned AICH identity authoritative when a modern peer already
  supplied canonical metadata

Also on **May 2, 2026**, the live closure cell
`ed2k.cell.modern-aich.plaintext.server-roundtrip.large.realnet.v1` was added
to make `ITEM_031` evidence runnable through the manifest-backed pytest
catalog. `ed2k.cell.modern-aich.plaintext.server-roundtrip.large.realnet.v1.plaintext-20260502-154313`
resolved the community tracing-harness runtime and reached live execution, but
the AICH gate still failed in stage 1 because the agent acquired no usable
sources, no MD4/AICH hashset, and no bytes for the harness-exported large file.
The live stress cell then passed in bounded mode for all canonical terms, which
supports general network health but does not close `ITEM_031`.

The latest same-server live attempt,
`ed2k.cell.modern-aich.plaintext.server-roundtrip.large.realnet.v1.plaintext-20260502-205635`,
observed the harness login server, prioritized that same endpoint in the agent
stage-1 search, and recorded a same-server background source search without a
source hint. The runner summary reported `sameServerSourceDiscovery.status` as
`no_sources`: the agent log and transfer manifest existed, source search was
attempted, the same-server search path was attempted, and the server still
returned zero usable sources before timeout. Stage 1 therefore again finished
with no MD4/AICH hashset and no bytes. `ITEM_031` remains open as a live
source-discovery blocker rather than an AICH transport or local-generation
failure.

Also on **May 2, 2026**, `supports_captcha` was cleared in the hello
misc-options profile because chat/captcha challenge handling is not yet
implemented. Regression coverage now asserts that file identifiers and source
exchange remain advertised while unsupported chat/captcha is de-advertised.

The same truthfulness pass also cleared comment support in
`CT_EMULE_MISCOPTIONS1` and `OP_EMULEINFO`. Regression coverage now asserts
that AICH, source exchange, secure ident, no-shared-files, and no-preview bits
stay intentional while unsupported comments and preview remain de-advertised.

The server-session advert audit also found that `OP_LOGINREQUEST` truthfully
advertises large-file capability, but the shared-file offer path had still been
saturating large advertised sizes into the legacy low 32-bit file-size tag.
`OP_OFFERFILES` now emits the stock high-size tag for files larger than 4 GiB,
and regression coverage asserts that large shared-file adverts no longer lose
their upper size bits.

The same server-obfuscation audit now has regression coverage for the transport
gate itself: an auxiliary obfuscation port alone is not treated as permission to
use obfuscated ED2K server TCP. The agent requires the matching server
capability flags before selecting DH server transport, while still allowing
plain TCP sessions to request the obfuscated found-sources reply family once
server flags prove that metadata shape.

Also on **May 2, 2026**, `ITEM_033` moved into its first UploadQueue parity
slice. The inbound listener queue no longer ranks and promotes waiters by FIFO
position alone: it now uses a deterministic score path with waiting age,
friend-slot boost, LowID penalty, duplicate reconnect refresh, and a neutral
file-priority hook for the later stock priority field. Focused regression
coverage asserts friend-slot rank promotion, LowID rank penalty, duplicate
reconnect staleness for the replaced handle, file-switch rank preservation, and
listener queue-rank / accept-upload behavior. The manifest-backed e2e cells
`ed2k.cell.downloader.plaintext.direct.queue-only.fresh.private.v1`,
`ed2k.cell.downloader.obfuscated.direct.queue-only.fresh.private.v1`,
`ed2k.cell.listener.plaintext.inbound.queue-only.fresh.private.v1`, and
`ed2k.cell.listener.obfuscated.inbound.queue-only.fresh.private.v1` are now
available and execute the native queue modules, including downloader queue-only
and late accept-upload handling plus obfuscated ED2K TCP queue-rank and late
accept-upload paths. The composed
`ed2k.campaign.queue-and-slot.v1` gate is now runnable over those four cells.
The obfuscated listener serving cell
`ed2k.cell.listener.obfuscated.inbound.serving.fresh.private.v1` now proves
verified upload bytes and compressed-part serving through the real obfuscated
ED2K TCP transport, and
`ed2k.cell.listener.plaintext.inbound.serving.resume.private.v1` now proves
partial upload reconnect and resumed byte-range serving by peer hello identity.
The resume lane now also has runnable manifest-backed cells for downloader
partial-piece resume and listener upload resume across plaintext and obfuscated
ED2K TCP, composed under `ed2k.campaign.resume.v1`.
Durable credit weighting and stock harness/live queue evidence remain open
before this checklist item can be closed.

Also on **May 2, 2026**, `ITEM_034` gained the first runnable obfuscated
callback-source-acquisition coverage. The manifest-backed cell
`ed2k.cell.downloader.obfuscated.callback.callback-issued.fresh.private.v1`
now runs through `ed2k.private.callback-source-acquisition` and is included in
`ed2k.campaign.callback.v1` alongside the plaintext callback cell. The passing
private run proves callback-request issuance, callback-only source observation,
direct-dial suppression, and obfuscated found-sources metadata without treating
the path as completed buddy parity. Full buddy setup/teardown, buddy tags, and
true firewalled callback state transitions remain open.

`ITEM_035` also moved into its first active-notes slice on **May 2, 2026**.
Stock `v0.72a` searches file comments/ratings through Kad notes for ED2K file
hashes, so `Protocol::Ed2k` + `SearchKind::Notes` now uses the same active Kad
notes search path instead of failing as unwired. Result batches preserve the
coordinator-requested protocol label so ED2K notes jobs remain distinguishable
from direct Kad notes jobs. Preview request/answer plus shared-files and
shared-directories browsing remain open.

Later on **May 2, 2026**, the manifest-backed
`ed2k.cell.notes.search.private.v1` gate passed against the private eMule
harness triplet after rebuilding the Rust agent. The run produced active
`KADEMLIA2_SEARCH_NOTES_REQ` evidence, notes-publish evidence, one ED2K-labeled
result batch, and the expected synthetic note record for the deterministic
fixture. That closes the active ED2K notes-search blocker while leaving preview,
shared browsing, chat/captcha truthfulness, and broader note-result modeling as
separate backlog work.

The runnable `ed2k.campaign.surface.v1` campaign now anchors `ITEM_035` with
the notes-search cell as its first required member. Preview and shared-browsing
cells should be added to that campaign as they become runnable.

## Validation Standard

Every milestone on this tracker should be validated with all of:

- focused unit tests for exact packet shape and state transitions
- `cargo test --workspace`
- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings -W clippy::all`
- private harness confirmation where the relevant path is observable
- live-capture confirmation where the relevant path materially affects peer
  acceptance or behavior

## Historical Context

Older docs comparing against stock eMule `community-0.60` remain useful as
historical reference, but they are no longer the canonical ED2K parity target.
This tracker is the current target statement.
