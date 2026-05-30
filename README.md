# p2p-overlord-agents

Rust workspace for the Overlord agents, protocol support crates, and agent-side helper binaries.

Current workspace surfaces:

- `overlord-agent-emule` is the current runtime agent package for Kad and ED2K.
- `overlord-agent-common`, `overlord-agent-nat`, and the `overlord-kad-*` crates provide the shared runtime, NAT, and Kad protocol layers behind that agent.
- `overlord-tools` provides developer/helper binaries.
- `miniupnpc` and `miniupnpc-sys` stay inside the same Cargo workspace intentionally so native wrapper code follows the same versioning, lint, and patch policy as the first-party crates. Under the eMuleBB workspace, the C MiniUPnP source of truth is planned to converge on `repos/third_party/emulebb-miniupnp`.

## eMuleBB Product-Family Contracts

This repo now lives under `https://github.com/emulebb/p2p-overlord-agents`.
When an agent exposes an eMuleBB-compatible REST surface, the canonical contract
is `repos/emulebb-tooling/docs/rest/REST-API-OPENAPI.yaml` from the eMuleBB
workspace. Missing routes are agent implementation gaps, not a separate API
contract.

ED2K server parity scenarios should use the eMuleBB `goed2k-server` fork. The
obsolete `emulebb-ed2k-server` fork and p2p-overlord ED2K server lineage are
historical references only.

## Release Naming

The shared p2p-overlord release policy is owned by
`p2p-overlord-be/docs/RELEASE_POLICY.md` and is available in the combined
workspace as `../p2p-overlord-be/docs/RELEASE_POLICY.md`. The first planned
release candidate is `0.1.1-rc.1`; the non-dotted `0.1.1-rc1` spelling is not
canonical. Keep agent package metadata on dev versions until release mode
explicitly starts and the agents, backend, and tooling versions are bumped
together.

Use [docs/README.md](docs/README.md) for the canonical protocol docs and [AGENTS.md](AGENTS.md) for repo-specific rules and quality gates.
