# Kad Background Budget Tracker

This tracker is the canonical statement for the current Kad runtime-budgeting
work in `overlord-agent-emule`.

## Target

The goal is **not** to disable Kad during ED2K activity.

The goal is to keep the agent explicitly multi-purpose while making Kad
background work cheap, bounded, and truthfully prioritized:

- `interactive` Kad work must stay responsive for user-facing ED2K and Kad flows
- `harvest` must keep making steady indexing progress
- `maintenance` must keep the node healthy without constant chatter
- `publish` must remain active, but only as the lowest-priority background drip

The intended operating shape is:

- low steady-state background CPU during active ED2K work
- no large synthetic fallback publish bursts
- no single blunt Kad budget where background publish can crowd out higher-value work

## Scope

This tracker covers:

- Kad RPC per-class outbound budgeting
- agent scheduling for interactive, harvest, maintenance, and publish work
- synthetic fallback publish behavior
- Kad runtime observability needed to attribute cost by work class

This tracker does **not** claim the work is complete until live runtime evidence
shows the new budgets materially reduce background cost during an active ED2K
session.

## Landed

As of **April 17, 2026**, the following is implemented:

- `RpcManager` now tracks four explicit outbound work classes:
  - `interactive`
  - `harvest`
  - `maintenance`
  - `publish`
- Kad RPC sends now consume both:
  - a global outbound safety limiter
  - a class-specific limiter
- Kad RPC observability now reports:
  - global outbound cap
  - per-class configured pps
  - per-class sent counts
  - per-class delayed counts
  - per-class total wait
  - per-class last-send timestamp
- `DhtNode` search, traversal, bootstrap, and publish paths now carry an explicit
  `RpcWorkClass`
- passive replay and live search paths are split by intent:
  - passive replay runs as `harvest`
  - active search runs as `interactive`
  - routing refresh / bootstrap / hello intro run as `maintenance`
  - seeding and republish run as `publish`
- synthetic fallback publish no longer bursts the whole synthetic set after
  bootstrap or on republish
- synthetic fallback publish now runs as a low-priority rotating drip queue
- coordinator-provided publish remains preferred, but now goes through the same
  low-priority publish class
- agent stats now expose the synthetic drip cadence and queue depth

## Current Defaults

The current default Kad operating profile is:

- global Kad cap: `8 pps`
- `interactive`: `4 pps`
- `harvest`: `1 pps`
- `maintenance`: `1 pps`
- `publish`: `1 pps`
- routing refresh interval: `900s`
- hello-intro interval: `300s`
- hello-intro fanout: `2`
- UDP firewall recheck interval: `1800s`
- general publish fanout: `4`
- synthetic publish drip interval: `120s`
- synthetic publish drip batch size: `1`
- synthetic publish drip contact fanout: `1`

These defaults are intentionally conservative. They prioritize “stay useful and
quiet” over “stay maximally hot”.

ED2K-active runs now also use tighter front-end pressure:

- only `1` ED2K download may run active metadata/source acquisition at once by default
- one file keeps at most `2` direct peers in flight at once
- normal ED2K keyword searches probe at most `3` one-shot servers
- exact `ed2k::<hash>` metadata lookups probe at most `4` one-shot servers
- download source acquisition probes at most `3` one-shot servers
- Kad source supplementation is skipped once ED2K already found more than `2`
  sources for the file

## Evidence

Code-level validation is green:

- `cargo fmt --all --check`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings -W clippy::all`

Important limitation:

- this tracker does **not** yet claim live CPU acceptance
- the implementation is landed and the Rust gates are green, but the next proof
  point is a real ED2K-active runtime sample showing materially reduced
  background Kad cost

## Hard Rules

These rules are intentional and should stay explicit:

- `publish` is the first workload to squeeze
- synthetic fallback publish must not burst
- `interactive` work must outrank `harvest`, `maintenance`, and `publish`
- `harvest` should be preserved ahead of synthetic publish
- the global safety cap stays in place even when per-class budgets exist

## Next Step

The next acceptance gate is live runtime validation during an active ED2K
session:

1. run a real ED2K-active session with Kad enabled
2. inspect CPU, RPC work-class stats, publish queue depth, and harvest progress
3. confirm the node remains healthy and useful while background Kad cost is
   materially lower than the previous bursty behavior
4. if needed, add adaptive pressure controls on top of the fixed budgets
   instead of restoring burst behavior

If the live run still shows too much background cost, the next refactor should
be adaptive scheduling rather than increasing the raw packet budget again.
