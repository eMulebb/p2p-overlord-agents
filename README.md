# p2p-overlord-agents

Rust workspace for the Overlord agents, protocol support crates, and agent-side helper binaries.

Current workspace surfaces:

- `overlord-agent-emule` is the current runtime agent package for Kad and ED2K.
- `overlord-agent-common`, `overlord-agent-nat`, and the `overlord-kad-*` crates provide the shared runtime, NAT, and Kad protocol layers behind that agent.
- `overlord-tools` provides developer/helper binaries.
- `miniupnpc` and `miniupnpc-sys` stay inside the same Cargo workspace intentionally so vendored/native support code follows the same versioning, lint, and patch policy as the first-party crates.

Use [docs/README.md](docs/README.md) for the canonical protocol docs and [AGENTS.md](AGENTS.md) for repo-specific rules and quality gates.
