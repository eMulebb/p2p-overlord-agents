# p2p-overlord-agents

Rust workspace for the Overlord agents, protocol support crates, and agent-side helper binaries.

Current workspace surfaces:

- `overlord-agent-emule` is the current runtime agent package for Kad and ED2K.
- `overlord-agent-common`, `overlord-agent-nat`, and the `overlord-kad-*` crates provide the shared runtime, NAT, and Kad protocol layers behind that agent.
- `overlord-tools` provides developer/helper binaries.
- `miniupnpc` and `miniupnpc-sys` stay inside the same Cargo workspace intentionally so native wrapper code follows the same versioning, lint, and patch policy as the first-party crates. Under the eMuleBB workspace, the C MiniUPnP source of truth is planned to converge on `repos/third_party/eMule-miniupnp`.

## eMuleBB Product-Family Contracts

This repo now lives under `https://github.com/eMulebb/p2p-overlord-agents`.
When an agent exposes an eMuleBB-compatible REST surface, the canonical contract
is `repos/eMule-tooling/docs/rest/REST-API-OPENAPI.yaml` from the eMuleBB
workspace. Missing routes are agent implementation gaps, not a separate API
contract.

ED2K server parity scenarios should use the eMuleBB `goed2k-server` fork. The
obsolete `emulebb-ed2k-server` fork and p2p-overlord ED2K server lineage are
historical references only.

Use [docs/README.md](docs/README.md) for the canonical protocol docs and [AGENTS.md](AGENTS.md) for repo-specific rules and quality gates.
