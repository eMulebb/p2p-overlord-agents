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
- Live observation after serializing passive replays:
  - source replay and keyword replay no longer overlap on the log timeline
  - isolated source replay still varies by target; observed runs included `results=0` and `results=4`
  - overlap was a real confounder, but not the only reason source replay can come back empty
- Remaining live gap:
  - source replay still alternates between non-zero and zero-result runs, so packet cadence/order is closer but not fully equivalent yet
- Live observation after adaptive widening landed:
  - passive source replay now widens as intended from `K` to `2K` to the configured harvest ceiling
  - internal stats now expose tier-by-tier replay telemetry for both passive source and passive keyword loops
  - widening alone is not enough; some source replays still finish `0/0/0` across all widened tiers
  - the next harvest optimization should focus on queue choice and replay backoff, not only on increasing traversal radius
