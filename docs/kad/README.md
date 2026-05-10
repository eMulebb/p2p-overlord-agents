# Kad Docs

Structured Kad and ED2K protocol documentation for the Rust agent workspace.

This doc set remains Kad-named for historical reasons, but it is also the
current documentation home for ED2K server-session, source-search, and future
transfer-parity work. The long-term repo target is full native Kad and ED2K
parity, including searching, sharing, upload, and download behavior.

The current canonical ED2K target is **latest/current live-network ED2K
behavior only**. Stock eMule `v0.72a` is an oracle for current advertised
behavior, not a mandate to implement legacy protocol variants or obsolete
fallback paths.

## Core Reference

- [Implementation Reference](./IMPLEMENTATION_REFERENCE.md)
- [KV6_001 Kad2 IPv6 Design](./KV6_001_KAD2_IPV6_DESIGN.md)
- [Protocol Reference](./PROTOCOL_REFERENCE.md)
- [Wire Sequences](./WIRE_SEQUENCES.md)

## Parity And Investigation

- [Parity Notes](./PARITY_NOTES.md)
- [Observations](./OBSERVATIONS.md)
- [Oracle Differences](./PROTOCOL_DIFFS.md)
- [Kad Background Budget Tracker](./KAD_BACKGROUND_BUDGET_TRACKER.md)
- [ED2K 0.72a Full Parity Tracker](./ED2K_072A_FULL_PARITY_TRACKER.md)
- [Stock eMule `community-0.60` Comparison](./EMULE_COMMUNITY_060_COMPARISON.md)
- [ED2K Parity State Machine](./ED2K_PARITY_STATE_MACHINE.md)
- [ED2K Firewalled Parity Matrix](./ED2K_FIREWALLED_PARITY_MATRIX.md)
