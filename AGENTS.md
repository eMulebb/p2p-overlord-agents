# Agents Repo Rules

- Follow the shared workspace policy in
  `../p2p-overlord-tooling/docs/WORKSPACE_POLICY.md`.
- Use `docs/README.md` as the canonical agents docs home.
- Use `../p2p-overlord-be/BACKLOG.md` as the canonical active backlog.
- Implement only latest/current Kad and ED2K protocol behavior by default.
  Do not add legacy variants, obsolete fallbacks, or compatibility branches
  unless explicitly re-scoped by the user.
- Before finishing Rust changes, run:
  - `cargo fmt --all --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings -W clippy::all -W clippy::too_many_arguments -W clippy::type_complexity -W clippy::cognitive_complexity`
- Do not add new oversized tracked source files or grow baselined oversized
  files; the workspace source-size ratchet is enforced from tooling.
- When touching oversized or locally complex Rust, opportunistically split or
  simplify the touched area if the change is behavior-preserving, scoped, and
  covered by targeted checks.
- Keep tracked text files normalized to UTF-8 with LF endings; the workspace
  line-ending guard is enforced from tooling.
- Keep public-facing Rust items documented with `///` or `//!`.
- Treat `rustfmt` output as canonical.
- Keep `#[allow(...)]` attributes narrow and local; remove stale allowances
  during nearby refactors.
- Prefer JSONL dumps for packet-level runtime evidence.
- When launching `overlord-agent-emule` interactively for local runs, ensure no
  dangling agent processes remain and use a hidden window.
- Treat ED2K server/client IPv4 tokens as little-endian wire values unless the
  protocol path clearly proves otherwise.
- Do not add shell wrapper launchers.
