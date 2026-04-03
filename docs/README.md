# Agents Docs

Canonical documentation home for `overlord-agents`.

The protocol end goal for this repo is full native parity with the oracle
families we target: Kad for indexing and notes, plus ED2K for server search,
peer search, sharing, upload, and download. Milestones remain staged, but the
direction is explicit.

## Kad

- [Kad Docs Landing Page](./kad/README.md)
- [Implementation Reference](./kad/IMPLEMENTATION_REFERENCE.md)
- [Protocol Reference](./kad/PROTOCOL_REFERENCE.md)
- [Parity Notes](./kad/PARITY_NOTES.md)
- [Observations](./kad/OBSERVATIONS.md)
- [Wire Sequences](./kad/WIRE_SEQUENCES.md)
- [Oracle Differences](./kad/PROTOCOL_DIFFS.md)

## ED2K

- ED2K runtime and wire work currently lives alongside the Kad docs in the same
  reference set while parity is still being built out.
- [Kad Docs Landing Page](./kad/README.md)
- [Implementation Reference](./kad/IMPLEMENTATION_REFERENCE.md)
- [Protocol Reference](./kad/PROTOCOL_REFERENCE.md)
- [Observations](./kad/OBSERVATIONS.md)
- [Wire Sequences](./kad/WIRE_SEQUENCES.md)

## Repo Guards

- `../scripts/windows/tracked_file_privacy_guard.ps1` validates tracked files
  for local user-profile path leaks and configured personal-name filename leaks.
