# ED2K 0.72a Full Parity Tracker

Canonical tracker for the current ED2K parity target in `overlord-agent-emule`.

## Target

The ED2K target for this repo is **full stock eMule `v0.72a` parity, excluding
obsolete protocol features only**.

This is an explicit hard-scope statement:

- not "good enough interoperability"
- not "hello/login parity only"
- not "download-only parity"
- not "community-0.60 parity"
- not "firewalled bootstrap parity only"

If stock eMule `v0.72a` still exposes a non-obsolete ED2K behavior on the live
network, this repo should treat that behavior as in scope until parity is
reached or the feature is explicitly reclassified as obsolete.

## Only Accepted Exclusions

The only ED2K protocol surfaces currently treated as obsolete for this target
are:

- legacy outbound `OP_MULTIPACKET`
- legacy outbound `OP_MULTIPACKETANSWER`
- legacy outbound `OP_MULTIPACKET_EXT`
- legacy standalone `OP_AICHFILEHASHREQ` / `OP_AICHFILEHASHANS` as the primary
  active path once `FileIdentifier` + modern AICH tree parity is implemented
- peer-cache advertisement

Deprecated packets may still be parsed inbound where practical for tolerance,
but they are not the target active behavior for "full parity".

## Non-Obsolete Scope That Remains In Scope

The following remain in scope for "full parity":

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
- [x] Callback-aware server source acquisition
- [x] Listener upload subset with queue-rank and file-description handling
- [x] Verified upload serving and resumable download coverage for the current
      subset
- [x] `FileIdentifier` model plus modern startup `OP_MULTIPACKET_EXT2` /
      `OP_MULTIPACKETANSWER_EXT2` parity on the current downloader and listener
      subset
- [x] Modern `OP_HASHSETREQUEST2` / `OP_HASHSETANSWER2` transport for the
      `FileIdentifier` path with MD4 hashset coverage
- [ ] Modern AICH root + part-hash generation, transport, and verification on
      the `FileIdentifier` / `OP_HASHSETANSWER2` path
- [ ] Stock `UploadQueue.cpp`-style credit, score, LowID, and friend-slot
      behavior
- [ ] Full buddy / callback matrix and buddy-tag parity for firewalled mode
- [ ] Preview request / answer parity
- [ ] Shared-files and shared-directories browsing parity
- [ ] Chat and chat-captcha parity
- [ ] Active ED2K notes search parity
- [ ] Broader downloader scheduler parity where stock `v0.72a` behavior depends
      on A4AF / global scheduling decisions
- [ ] Broader `ServerSocket.cpp` parity beyond the current focused subset

## Strong Completion Rule

Do **not** call the ED2K work "done" while any still-advertised non-obsolete
feature remains unsupported.

Current example:

- `supports_captcha=1` is currently advertised in the hello profile, so chat /
  captcha support is part of the parity backlog until the implementation lands
  or the advert is made truthful again.

## Current Next Step

The active next milestone is:

1. persist a truthful AICH root and part-hash set in the transfer/shared-file
   runtime instead of keeping `FileIdentifier.aich_root` empty on the active
   ED2K path
2. answer `OP_HASHSETREQUEST2` with AICH data when the peer requests it and
   validate inbound `OP_HASHSETANSWER2` AICH payloads against the requested
   root
3. confirm that modern AICH transport on the `FileIdentifier` path is visible
   in private dumps and then add a dedicated large-file live scenario so that
   `server.met` realnet evidence covers the same branch
4. extend the same truthfulness rule to every still-advertised non-obsolete
   ED2K feature that remains unimplemented, starting with chat-captcha

This remains the highest-leverage next step because the downloader and listener
now use the modern `FileIdentifier` + `EXT2` + `HASHSETREQUEST2` transport, so
the largest remaining truth gap is the still-modern AICH payload that stock
`v0.72a` drives through that exact path.

## Current Evidence

As of **April 17, 2026**, the private deterministic harness path confirms the
new modern startup flow:

- `cargo test --workspace` passed after the `FileIdentifier` / `EXT2` changes
- `cargo clippy --workspace --all-targets --all-features -- -D warnings -W clippy::all` passed
- the private scenario `ed2k.server.emule-harness.agent.private.v1` completed
  successfully with the harness logging:
  - inbound `OP_MULTIPACKET_EXT2` from the agent at
    [emule-harness-ed2k-tcp-dump-2026.04.17-17.16.54.366-p9544.jsonl](</C:/tmp/p2p-overlord/overlord-tooling/runs/ed2k.server.emule-harness.agent.private.v1/ed2k.server.emule-harness.agent.private.v1-20260417-171635/emule-harness-artifacts/emule-harness-ed2k-tcp-dump-2026.04.17-17.16.54.366-p9544.jsonl>)
  - outbound `OP_MULTIPACKETANSWER_EXT2` back to the agent in the same dump

As of **April 17, 2026**, live `server.met` validation is also green for the
current acceptance gate:

- the real-network scenario
  `ed2k.server.emule-harness.agent.roundtrip.realnet.v1` completed
  successfully on run
  `ed2k.server.emule-harness.agent.roundtrip.realnet.v1-20260417-172433`
- the selected live server came from the canonical imported `server.met` bundle
  and was pinned as `145.239.2.134:4661` in
  [run-manifest.json](</C:/tmp/p2p-overlord/overlord-tooling/runs/ed2k.server.emule-harness.agent.roundtrip.realnet.v1/ed2k.server.emule-harness.agent.roundtrip.realnet.v1-20260417-172433/run-manifest.json>)
- the run summary confirms server-session establishment, agent download,
  republish, and harness download completion in
  [run-summary.json](</C:/tmp/p2p-overlord/overlord-tooling/runs/ed2k.server.emule-harness.agent.roundtrip.realnet.v1/ed2k.server.emule-harness.agent.roundtrip.realnet.v1-20260417-172433/run-summary.json>)
- the agent log shows successful live-server session establishment and native
  download completion against that server in
  [overlord-agent-emule.log](</C:/tmp/p2p-overlord/overlord-tooling/runs/ed2k.server.emule-harness.agent.roundtrip.realnet.v1/ed2k.server.emule-harness.agent.roundtrip.realnet.v1-20260417-172433/agent-stage1-artifacts/overlord-agent-emule.log>)
- the harness downloader log confirms the re-offered file verified as
  `MD4: OK - AICH: OK` in
  [eMule_Verbose.log](</C:/tmp/p2p-overlord/overlord-tooling/runs/ed2k.server.emule-harness.agent.roundtrip.realnet.v1/ed2k.server.emule-harness.agent.roundtrip.realnet.v1-20260417-172433/harness-downloader-artifacts/eMule_Verbose.log>)

Important limitation:

- that live roundtrip used a `262144` byte file, so it did **not** exercise the
  large-file `OP_HASHSETREQUEST2` / `OP_HASHSETANSWER2` or modern AICH payload
  branch
- the live run is therefore valid evidence for publish/download/re-offer
  acceptance on a real server selected from `server.met`, but **not yet**
  sufficient evidence for modern AICH transport parity

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
