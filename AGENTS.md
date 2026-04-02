# Agents Repo Rules

- Follow the shared workspace guidance from `../AGENTS.md` in addition to this file.
- Use `../overlord-be/BACKLOG.md` as the canonical active backlog.
- Use `scripts/windows/rust_quality.ps1` as the canonical local quality gate for this repo.
- Before finishing Rust changes, run:
  - `cargo fmt --all --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings -W clippy::all`
- Keep public-facing Rust items documented with `///` or `//!`.
- Document protocol and stateful Rust code in detail.
  - Every public Kad API must explain protocol role, important inputs, and observable outcomes.
  - Every wire-facing or stateful module must carry `//!` docs that describe the protocol family or runtime state it owns.
  - State transitions, transport-mode choices, and identity semantics must be documented where they are implemented, not only in markdown design notes.
  - When a field name is semantically loaded by the oracle contract, document that meaning explicitly in code comments or doc comments.
- Treat `rustfmt` output as canonical.
- Keep reusable operational tooling in `../overlord-helpers`, not inline in issue-specific commands.
- Respect the workspace line-ending policy:
  - tracked text files use LF by default
  - `.ps1`, `.cmd`, and `.bat` may use CRLF
