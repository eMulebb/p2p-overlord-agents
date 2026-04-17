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
- [ ] `FileIdentifier` model and `OP_MULTIPACKET_EXT2` /
      `OP_MULTIPACKETANSWER_EXT2` parity
- [ ] Modern AICH tree generation, transport, and verification parity
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

1. add a first-class `FileIdentifier` model to the Rust ED2K runtime
2. switch the modern startup path to bundled `OP_MULTIPACKET_EXT2`
3. add `OP_MULTIPACKETANSWER_EXT2` parsing and reply generation
4. move modern AICH handling onto the `FileIdentifier` path instead of keeping
   legacy standalone AICH packets as the primary active behavior

This is the highest-leverage next step because it closes the largest remaining
gap between the current `v0.72a` capability advert and the actual runtime wire
behavior.

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
