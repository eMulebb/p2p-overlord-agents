# Agents Repo Rules

- Follow the shared workspace policy in
  `../p2p-overlord-tooling/docs/WORKSPACE_POLICY.md`.
- Use `docs/README.md` as the canonical agents docs home.
- Use `../p2p-overlord-be/BACKLOG.md` as the canonical active backlog.
- Use `scripts/windows/rust_quality.ps1` as the canonical local Rust quality
  gate.
- Before finishing Rust changes, run:
  - `cargo fmt --all --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings -W clippy::all`
- Keep public-facing Rust items documented with `///` or `//!`.
- Treat `rustfmt` output as canonical.
- Prefer JSONL dumps for packet-level runtime evidence.
- When launching `overlord-agent-emule` interactively for local runs, ensure no
  dangling agent processes remain and use a hidden window.
- Treat ED2K server/client IPv4 tokens as little-endian wire values unless the
  protocol path clearly proves otherwise.
