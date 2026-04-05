# ED2K Firewalled Parity Matrix

Consolidated comparison of the two firewalled eMule capture profiles:

- plaintext:
  `capture-emule-firewalled-non-obfuscated-more.pcapng`
  `capture-emule-firewalled-non-obfuscated-more1.pcapng`
- obfuscated:
  `capture-emule-firewalled-obfuscated-more.pcapng`
  `capture-emule-firewalled-obfuscated-more1.pcapng`
  `capture-emule-firewalled-obfuscated-more2.pcapng`

Use this file as the primary acceptance matrix for firewalled ED2K parity work.
Keep the profile-specific notes for deeper packet examples and capture-specific
details.

## Shared Baseline

Both captures show the same high-level oracle posture:

- firewalled client behavior in practice
- outbound peer TCP as the main harvest path
- one stable high-volume peer UDP role
- a lighter request/reply UDP role that is visible in plaintext and some
  obfuscated runs, but not mandatory in every obfuscated sample
- tolerance for many dead, empty, or queue-only peers
- occasional large inbound UDP bursts that should not collapse harvesting

## Matrix

| Dimension | Firewalled Plaintext | Firewalled Obfuscated | Implementation Consequence |
| --- | --- | --- | --- |
| Peer TCP direction | Mostly outbound | Mostly outbound | Keep firewalled mode outbound-TCP-first |
| Main UDP role | `61559` high-volume peer UDP | `61559` high-volume peer UDP | Preserve the main peer UDP socket role |
| Secondary UDP role | `61561` short request/reply UDP | Visible in some runs, absent or not visible in others | Keep support for the lightweight ED2K server/request role without assuming every obfuscated run exposes it |
| Hello ordering | Clearly decoded | Still decoded on some peers | Preserve hello and secure-ident order in both modes |
| Secure-ident ordering | Clearly decoded | Clearly decoded on some peers | Do not send upload or part requests before secure-ident completes where required |
| Queue-only peers | Common and normal | Common and normal | Do not treat queue-only peers as broken peers |
| Post-secure-ident negotiation | Hashset-first or direct slot request | Usually direct slot request, sometimes less visible | Keep both valid plaintext negotiation variants compatible |
| Serving peer visibility | Mostly visible in dissector | Partly opaque in dissector | Judge acceptance by progress and logs, not only Wireshark labels |
| Large inbound UDP bursts | Present | Present | Keep receive path and parser burst-tolerant |
| Peer-port diversity | Mixed default and non-default ports | Mixed default and non-default ports | Do not optimize only for `4662` peers |
| Wire readability | Mostly decodable | Many sessions degrade to generic TCP/data | Obfuscation changes observability, not the core handshake model |

## Canonical Observed Flows

### Plaintext

- clearest decoded transfer flow:
  one default-port serving peer on `4662`
- decoded queue and negotiation peers:
  several peers on `4662` that stop after queue negotiation
- denser companion sample:
  multiple concurrent serving peers plus queue-only peers in one run
- observed plaintext negotiation variants:
  both hashset-first and direct slot-request paths after secure-ident
- heavy UDP responders:
  a mix of default Kad ports and random high source ports

### Obfuscated

- clearest decoded transfer flow:
  one default-port serving peer on `4662`
- likely serving or queueing peers with less dissector visibility:
  mixed peers on both default and high ports with reduced dissector visibility
- strong serving peers across the larger companion samples:
  one dominant peer on `4725`
  multiple productive peers on `4661`, `4662`, `6570`, `10000`, `44445`, and `61116`
- heavy UDP responders:
  a mix of default Kad ports and random high source ports

## Repo Ownership

- runtime socket ownership:
  `crates/overlord-agent-emule/src/agent.rs`
- eD2k peer handshake and transfer:
  `crates/overlord-agent-emule/src/ed2k_tcp.rs`
- eD2k server session and UDP search path:
  `crates/overlord-agent-emule/src/ed2k_server.rs`
- Kad UDP transport and obfuscation:
  `crates/overlord-kad-net/src/transport.rs`
  `crates/overlord-kad-net/src/obfuscation.rs`

## Unified Acceptance Checklist

1. Keep firewalled mode outbound-TCP-first in both plaintext and obfuscated
   profiles.
2. Preserve the same hello and secure-ident ordering in both profiles.
3. Do not send `OP_HASHSETREQUEST`, `OP_STARTUPLOADREQ`, or `OP_REQUESTPARTS`
   too early for peers that still require secure-ident completion.
4. Preserve the second, lightweight UDP role for ED2K server and short
   request/reply exchanges, but accept that it may not be externally visible in
   every obfuscated firewalled sample.
5. Keep queue-only peers in the accepted-but-not-serving bucket instead of the
   broken-peer bucket.
6. Keep peer-port handling broad. Successful peers can sit on non-default ports.
7. Keep large inbound UDP burst handling robust on the main peer UDP socket.
8. In obfuscated mode, accept that many sessions will be less readable in
   Wireshark and validate via local wire logs plus transfer progress.

## Validation Guidance

Use native ED2K runs plus `agent-ed2k-tcp-dump-*.jsonl` logging to confirm:

- direct peer attempts are mostly outbound
- decoded successful peers still show the expected hello and secure-ident order
- large-file peers do not receive upload or part requests before the required
  secure-ident phase completes
- queue-only peers do not terminate the overall harvest attempt prematurely
- the transfer manifest reaches `completed=true` when at least one serving peer
  is available

## Detailed Notes

- [ED2K Firewalled Plaintext Parity](./ED2K_FIREWALLED_PARITY.md)
- [ED2K Firewalled Obfuscated Parity](./ED2K_FIREWALLED_OBFUSCATED_PARITY.md)
