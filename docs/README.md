# Agents Docs

Canonical documentation home for `overlord-agents`.

The protocol end goal for this repo is native capability coverage across the
oracle families we target where it materially improves acceptance,
reachability, or harvest yield: Kad for indexing and notes, plus ED2K for
server search, peer search, sharing, upload, and download. Milestones remain
staged, but wire-compatible behavior stays mandatory where interoperability or
traffic shape depends on it.

## Kad

- [Kad Docs Landing Page](./kad/README.md)
- [Implementation Reference](./kad/IMPLEMENTATION_REFERENCE.md)
- [KV6_001 Kad2 IPv6 Design](./kad/KV6_001_KAD2_IPV6_DESIGN.md)
- [Protocol Reference](./kad/PROTOCOL_REFERENCE.md)
- [Parity Notes](./kad/PARITY_NOTES.md)
- [Observations](./kad/OBSERVATIONS.md)
- [Wire Sequences](./kad/WIRE_SEQUENCES.md)
- [Oracle Differences](./kad/PROTOCOL_DIFFS.md)
- [Kad Background Budget Tracker](./kad/KAD_BACKGROUND_BUDGET_TRACKER.md)
- [Stock eMule `community-0.60` Comparison](./kad/EMULE_COMMUNITY_060_COMPARISON.md)

## ED2K

- ED2K runtime and wire work currently lives alongside the Kad docs in the same
  reference set while parity is still being built out.
- The current canonical ED2K target is **latest/current live-network ED2K
  behavior only**. Stock eMule `v0.72a` is an oracle for current advertised
  behavior, not a mandate to implement legacy protocol variants or obsolete
  fallback paths.

ED2K-specific planning and status docs:

- [ED2K 0.72a Full Parity Tracker](./kad/ED2K_072A_FULL_PARITY_TRACKER.md)
- [ED2K Firewalled Parity Matrix](./kad/ED2K_FIREWALLED_PARITY_MATRIX.md)
- [ED2K Parity State Machine](./kad/ED2K_PARITY_STATE_MACHINE.md)
- [ED2K Firewalled Plaintext Parity](./kad/ED2K_FIREWALLED_PARITY.md)
- [ED2K Firewalled Obfuscated Parity](./kad/ED2K_FIREWALLED_OBFUSCATED_PARITY.md)

Shared protocol reference docs currently reused by the ED2K work:

- [Kad Docs Landing Page](./kad/README.md)
- [Implementation Reference](./kad/IMPLEMENTATION_REFERENCE.md)
- [KV6_001 Kad2 IPv6 Design](./kad/KV6_001_KAD2_IPV6_DESIGN.md)
- [Protocol Reference](./kad/PROTOCOL_REFERENCE.md)
- [Observations](./kad/OBSERVATIONS.md)
- [Wire Sequences](./kad/WIRE_SEQUENCES.md)
- [Stock eMule `community-0.60` Comparison](./kad/EMULE_COMMUNITY_060_COMPARISON.md)

### Native Download Acceptance

- For plaintext/native ED2K acceptance runs, keep the capture file external to
  the repo and feed the target hash, file name, and file size through the
  enrich/download path directly.
- Set `OVERLORD_LOG_DIR` for the run so `agent-ed2k-tcp-dump-*.jsonl` captures
  source candidates, per-peer attempts, packet flow, and final completion
  evidence for comparison against the external packet capture.
- Accept the run only when the transfer manifest ends `completed=true`, the
  verified size matches the requested file size, and the final ED2K hash matches
  the requested file hash.

## Repo Guards

- Shared workspace quality and opportunistic-refactoring policy lives in
  `../../p2p-overlord-tooling/docs/WORKSPACE_POLICY.md`; this section keeps the
  Rust-specific guard notes.
- From `../p2p-overlord-tooling`, run
  `python -m overlord_tooling guard-tracked-files --repo-root ../p2p-overlord-agents`
  to validate tracked files for local path leaks and configured personal-name
  filename leaks.
- The required Rust gate promotes `clippy::too_many_arguments`,
  `clippy::type_complexity`, and `clippy::cognitive_complexity` using the
  thresholds in `../clippy.toml`.
- Keep `clippy::too_many_lines` advisory until the existing large session and
  protocol functions are refactored. For local inventory, run
  `cargo clippy --workspace --all-targets --all-features -- -W clippy::all -W clippy::too_many_lines -W clippy::cognitive_complexity -W clippy::too_many_arguments -W clippy::type_complexity`.
