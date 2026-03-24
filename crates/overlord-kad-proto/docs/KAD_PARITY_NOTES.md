# KAD_PARITY_NOTES

Running note for Kad oracle-parity findings that affect live behavior.

## 2026-03-24

- Passive source replay is an Overlord-only indexing feature.
- eMule remains the oracle for the underlying Kad source-search walk once a replayed query is emitted.
- Verified from eMule `kademlia/kademlia/Search.cpp` and `SearchManager.cpp`:
  - phase-2 source search is not blasted to all tolerated responders at once
  - `StorePacket()` is only triggered by `JumpStart()`
  - `JumpStart()` runs on a 1 second manager tick
  - `JumpStart()` refuses to emit until at least 3 seconds after the last lookup `RES`
  - once stalled, eMule walks the closest responders one at a time on later jump-start ticks
- Overlord parity adjustments landed so far:
  - phase-2 fanout is capped at the oracle's closest `K`
  - zero-sized snooped source requests are skipped instead of replayed
  - phase-2 now uses a jump-start style walk instead of evenly slicing the timeout budget across all contacts
- Live observation after the jump-start change:
  - source replay still sometimes returns `0` results
  - keyword replay and source replay can overlap because they are separate background loops
  - that overlap is not oracle-like for our harvesting scenario and should be serialized
- Remaining live gap:
  - source replay still alternates between non-zero and zero-result runs, so packet cadence/order is closer but not fully equivalent yet
