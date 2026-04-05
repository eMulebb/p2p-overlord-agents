# ED2K Firewalled Obfuscated Parity

Concrete parity checklist for the firewalled, obfuscated eMule captures:

- `capture-emule-firewalled-obfuscated-more.pcapng`
- `capture-emule-firewalled-obfuscated-more1.pcapng`
- `capture-emule-firewalled-obfuscated-more2.pcapng`

Capture summary:

- host role: firewalled client
- capture durations: about 45 seconds to 399 seconds
- consistently denser than the plaintext companion capture
- primary eD2k peer TCP pattern: outbound connects only
- primary UDP pattern: one stable high-volume peer UDP socket; a lighter
  request/reply UDP role is visible in some runs but not all

## Observed Oracle Shape

### TCP peer download path

The clearest decoded serving peer flow in the capture was:

1. `OP_HELLO`
2. `OP_HELLOANSWER`
3. secure-ident exchange:
   `OP_SECIDENTSTATE`
   `OP_PUBLICKEY`
   `OP_SIGNATURE`
4. queue and upload negotiation:
   `OP_SLOTREQUEST`
   `OP_SLOTGIVEN`
5. part transfer:
   `OP_REQUESTPARTS`
   repeated `OP_SENDINGPART`

Decoded serving examples across the samples include:

- multiple default-port serving peers on `4661` and `4662`
- repeated concurrent outbound transfer sessions with successful slot grants
- both `OP_SENDINGPART` and compressed data transfer paths

Other likely serving or queueing peers were far less visible at the dissector
level and appeared mostly as generic TCP payload. That is expected in this
profile and should not be treated as a capture failure.

The larger companion samples also showed strong serving peers on non-default
ports, including:

- one dominant long-lived serving peer on `4725`
- several productive high-port peers on `6570`, `10000`, `44445`, and `61116`
- multiple simultaneous transfers across mixed default and non-default ports

### UDP shape

- one main UDP port, `61559`, consistently produced many small outbound probes
  and many replies
- a second UDP role handled shorter request/reply exchanges, including ED2K
  server traffic, in some runs, but it was not visible in every obfuscated
  sample
- the firewalled profile still accepted large inbound UDP bursts from a mix of
  default Kad ports and random high source ports

## Differences From Plaintext Firewalled Mode

1. More peer sessions become opaque in packet capture and no longer decode
   cleanly as ED2K message names.
2. Outbound behavior still matters more than dissector visibility. Acceptance
   should be judged by transfer progress and wire shape, not by how many
   messages Wireshark can label.
3. The same hello and secure-ident ordering still appears on the sessions that
   do decode, so obfuscation is not a license to reorder the peer handshake.
4. Peer-port diversity remains normal. Successful peers are not limited to
   `4662`, and some of the strongest serving sessions use non-default ports.

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

## Implementation Checklist

1. Keep firewalled mode outbound-TCP-first. Do not depend on inbound peer TCP
   sessions for harvest progress.
2. Preserve the same hello and secure-ident ordering seen in the plaintext
   profile. Obfuscation changes visibility, not the acceptance-critical order.
3. Keep obfuscated peer sessions valid even when Wireshark mostly shows generic
   TCP payload instead of named ED2K messages.
4. Treat queue-only peers as normal. A peer that accepts the session but never
   grants upload should stay in the accepted-but-not-serving bucket.
5. Preserve the second, lightweight UDP role for short ED2K server request/reply
   exchanges when enabled, but do not assume it will be externally visible in
   every obfuscated firewalled run.
6. Keep large inbound UDP burst handling robust on the main peer UDP socket.
7. Preserve peer-port diversity. Do not special-case only `4662` peers in the
   direct-download path.

## Acceptance Checks

Use native ED2K runs plus `agent-ed2k-tcp-dump-*.jsonl` logging to confirm:

- direct peer attempts are mostly outbound
- decoded successful peers still follow the expected hello and secure-ident order
- obfuscated sessions that are opaque in Wireshark still produce normal
  connect, queue, and transfer progress in local logs
- non-default serving peers remain eligible and productive in the direct
  download path
- queue-only peers do not terminate the overall harvest attempt prematurely
- the transfer manifest reaches `completed=true` when at least one serving peer
  is available
