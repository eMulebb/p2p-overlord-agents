# ED2K Firewalled Plaintext Parity

Concrete parity checklist for the firewalled, non-obfuscated eMule captures:

- `capture-emule-firewalled-non-obfuscated-more.pcapng`
- `capture-emule-firewalled-non-obfuscated-more1.pcapng`

Capture summary:

- host role: firewalled client
- capture durations: about 279 seconds to 298 seconds
- primary eD2k peer TCP pattern: outbound connects only
- primary UDP pattern: one high-volume peer UDP socket plus one lighter
  request/reply UDP role
- the second sample is materially denser and shows several concurrent serving
  peers instead of only one dominant transfer path

## Observed Oracle Shape

### TCP peer download path

The highest-signal successful plaintext peer flow in the capture was:

1. `OP_HELLO`
2. `OP_HELLOANSWER`
3. secure-ident exchange:
   `OP_SECIDENTSTATE`
   `OP_PUBLICKEY`
   `OP_SIGNATURE`
4. queue and upload negotiation:
   either:
   `OP_HASHSETREQUEST`
   `OP_HASHSETANSWER`
   `OP_SLOTREQUEST`
   or:
   `OP_SLOTREQUEST`
   followed by `OP_QUEUERANKING` and/or `OP_SLOTGIVEN`
5. part transfer:
   `OP_REQUESTPARTS`
   repeated compressed or plain part payloads

Other peers stopped earlier after queue negotiation and never granted upload.
That still counted as normal network behavior and should not be treated as a
bad-protocol path by the agent.

The denser companion sample also showed:

- multiple concurrent outbound serving peers in the same run
- repeated queue-only peers that never progressed to upload
- productive peers on both default and non-default TCP ports

### UDP shape

- one main UDP port produced many small outbound probes and many small replies
- a second UDP role handled shorter request/reply exchanges, including ED2K
  server source and status traffic
- the second UDP role again carried ED2K server-style short exchanges including
  `Found Sources` replies
- the firewalled profile still accepted occasional large inbound UDP bursts
  without retreating from harvesting

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
2. Preserve the plaintext peer handshake ordering above. Do not send
   `OP_HASHSETREQUEST`, `OP_STARTUPLOADREQ`, or `OP_REQUESTPARTS` before the
   secure-ident exchange has completed for peers that require it.
3. Accept both post-secure-ident negotiation variants seen on the wire:
   hashset-first peers and direct slot-request peers.
4. Treat queue-only peers as normal. A peer that answers hello and secure-ident
   but never grants upload should stay in the accepted-but-not-serving bucket,
   not the broken-peer bucket.
5. Keep the listener credible on inbound `OP_HELLO`, `OP_HASHSETREQUEST`,
   `OP_STARTUPLOADREQ`, and `OP_REQUESTPARTS` so the port does not look like a
   dead-end helper.
6. Preserve the second, lightweight UDP role for short ED2K server request/reply
   exchanges instead of flattening all UDP traffic onto the main Kad peer socket.
7. Keep non-obfuscated mode plainly decodable on the wire for this profile.
8. Tolerate dead peers, empty peers, and ICMP failures without global backoff.
9. Keep concurrent outbound peer harvesting broad enough to exploit multiple
   serving peers in the same run instead of depending on one winning session.

## Acceptance Checks

Use native ED2K runs plus `agent-ed2k-tcp-dump-*.jsonl` logging to confirm:

- direct peer attempts are mostly outbound
- successful peers follow the expected hello and secure-ident order
- both hashset-first and direct slot-request variants remain accepted after
  secure-ident where peers choose them
- large-file peers do not receive `OP_HASHSETREQUEST` or `OP_STARTUPLOADREQ`
  before secure-ident completes
- queue-only peers do not terminate the overall harvest attempt prematurely
- the plaintext secondary UDP role continues to carry short ED2K server
  exchanges
- the transfer manifest reaches `completed=true` when at least one serving peer
  is available
