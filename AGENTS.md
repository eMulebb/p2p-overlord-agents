# Agents Repo Rules

- Follow the shared workspace guidance from `../AGENTS.md` in addition to this file.
- Use `../overlord-be/BACKLOG.md` as the canonical active backlog.
- Use `scripts/windows/rust_quality.ps1` as the canonical local quality gate for this repo.
- Before finishing Rust changes, run:
  - `cargo fmt --all --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings -W clippy::all`
- Keep public-facing Rust items documented with `///` or `//!`.
- Treat `rustfmt` output as canonical.
- Keep reusable operational tooling in `../overlord-helpers`, not inline in issue-specific commands.
- Respect the workspace line-ending policy:
  - tracked text files use LF by default
  - `.ps1`, `.cmd`, and `.bat` may use CRLF
