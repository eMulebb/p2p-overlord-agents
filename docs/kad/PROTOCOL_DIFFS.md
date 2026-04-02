# Kad Oracle Differences

Comparative implementation report for the two oracle Kad trees used by this workspace.

Authority order for Overlord porting remains:

1. eMule: `c:\prj\p2p\eMule-my\deps-repos\eMule\srchybrid\kademlia\`
2. aMule: `c:\prj\p2p\amule\src\kademlia\`

## Reading Rules

- `Verified structural difference`: code organization or helper layers differ, but no protocol disagreement was confirmed.
- `Equivalent behavior, different implementation`: both trees implement the same Kad behavior with different containers, helpers, or batching style.
- `Verified behavior difference`: observable logic differs between eMule and aMule. When that happens, eMule wins for Overlord porting decisions.

## Structure

- `Verified structural difference`: eMule keeps a dedicated `kademlia/io/` layer with `ByteIO`, `DataIO`, `FileIO`, `BufferedFileIO`, and `IOException`, plus separate helpers such as `utils/LookupHistory.*`, `utils/ThreadName.*`, `utils/MiscUtils.*`, and `kademlia/Tag.h`. aMule removes that split and leans on `CMemFile`, wxWidgets containers, and general tag classes from the wider codebase.
- `Verified structural difference`: eMule search code carries more GUI/history/load surface in `kademlia/Search.cpp`, including `GetGUIName`, `SetGUIName`, `GetNodeLoad`, `UpdateNodeLoad`, and `AddFileID`. aMule keeps the main traversal/search flow but trims much of the extra search bookkeeping.

## UDP Listener / Packet Handling

- `Equivalent behavior, different implementation`: both `net/KademliaUDPListener.cpp` implementations dispatch the same Kad2 families and keep matching handler coverage for bootstrap, HELLO, `REQ/RES`, search, publish, firewall, buddy, callback, and ping/pong.
- `Equivalent behavior, different implementation`: the three Kad2 search request handlers parse the same wire shapes in both trees:
  - keyword: `Process_KADEMLIA2_SEARCH_KEY_REQ` / `Process2SearchKeyRequest`
  - source: `Process_KADEMLIA2_SEARCH_SOURCE_REQ` / `Process2SearchSourceRequest`
  - notes: `Process_KADEMLIA2_SEARCH_NOTES_REQ` / `Process2SearchNotesRequest`
- `Equivalent behavior, different implementation`: both listeners reject legacy unencrypted Kad traffic on UDP port 53 and both thread sender/receiver UDP keys through HELLO and firewall handling in `KademliaUDPListener.cpp`.
- `Verified behavior difference`: inbound packet tracking differs slightly for publish opcodes. eMule `net/PacketTracking.cpp` allows 4/3/2 requests per minute for `KADEMLIA2_PUBLISH_KEY_REQ`, `KADEMLIA2_PUBLISH_SOURCE_REQ`, and `KADEMLIA2_PUBLISH_NOTES_REQ`; aMule uses 3/2/2. Search opcodes remain aligned at 3/3/3.

## Search

- `Equivalent behavior, different implementation`: both `kademlia/Search.cpp CSearch::StorePacket` implementations emit the same Kad2 search request families and keep the same stable send path of `start_position = 0` or `0x8000 + expression blob` when serialized search terms exist.
- `Equivalent behavior, different implementation`: both `kademlia/Indexed.cpp` implementations send `KADEMLIA2_SEARCH_RES` with the same header and per-entry layout for keyword, source, and notes replies.
- `Verified behavior difference`: keyword result post-processing is richer in eMule. `kademlia/Search.cpp ProcessResultKeyword` looks up the answering contact and filters `TAG_PUBLISHINFO` and `TAG_KADAICHHASHRESULT` based on the responder's Kad version. aMule `ProcessResultKeyword` accepts `TAG_PUBLISHINFO` more directly and does not carry the same sender-version gate.
- `Equivalent behavior, different implementation`: both search indexers may emit multiple `KADEMLIA2_SEARCH_RES` packets for one request, but packetization differs. eMule `Indexed.cpp SendValidKeywordResult`, `SendValidSourceResult`, and `SendValidNoteResult` fragment on byte budget (`UDP_KAD_MAXFRAGMENT`). aMule uses fixed 50-result packet chunks in the matching functions.
- `Equivalent behavior, different implementation`: both keyword result senders do a trusted-then-untrusted sweep so hot keywords are not filled entirely by spammy entries. eMule uses `CByteIO` and `TagList`; aMule uses `CMemFile` and `TagPtrList`.

## Routing

- `Equivalent behavior, different implementation`: eMule `routing/RoutingZone.cpp CanSplit` and aMule `routing/RoutingZone.cpp CanSplit` use the same split rule: split only when the bin size is `K`, the level is `< 127`, and `(zone_index < KK || level < KBASE)`.
- `Equivalent behavior, different implementation`: both routing bins enforce the same anti-clustering limits:
  - max 1 contact per IP globally
  - max 10 contacts per `/24` globally
  - max 2 contacts from the same `/24` inside one bin
  - LAN IPs exempt from subnet limits
  Anchors: `routing/RoutingBin.cpp AddContact`, `CheckGlobalIPLimits`, and `ChangeContactIPAddress` in both trees.
- `Equivalent behavior, different implementation`: both routing zones keep verified-contact and sender-key aware update logic in `routing/RoutingZone.cpp AddUnfiltered` and `routing/RoutingBin.cpp ChangeContactIPAddress`. aMule is easier to read; eMule carries more surrounding MFC logging and IP-filter integration.

## Publish / Firewall

- `Equivalent behavior, different implementation`: both trees use the same identity semantics for Kad2 publish requests:
  - source publish writes the publisher client hash in the second 128-bit field
  - notes publish writes the publisher Kad ID in the second 128-bit field
  Anchors: eMule `net/KademliaUDPListener.cpp SendPublishSourcePacket` and `kademlia/Search.cpp CSearch::StorePacket`; aMule `net/KademliaUDPListener.cpp SendPublishSourcePacket` and `kademlia/Search.cpp CSearch::StorePacket`.
- `Equivalent behavior, different implementation`: HELLO, firewall, buddy, and callback flows map closely between the two trees. aMule mainly renames functions for readability, while eMule keeps the original opcode-oriented naming.

## Utilities / IO

- `Verified structural difference`: eMule's separate `ByteIO` / `DataIO` / `CSafeMemFile` stack makes byte-level provenance easier to audit when reverse engineering Kad packets. aMule trades some of that explicit layering for simpler portable control flow through `CMemFile`.
- `Verified structural difference`: eMule's extra helpers such as `LookupHistory`, `ThreadName`, and `MiscUtils` explain why some search and background-loading code is larger there even when the wire behavior is equivalent.

## Implications For Overlord

- Use eMule first for wire format, security filters, and sender-version-dependent behavior.
- Use aMule to understand portable control flow and to confirm whether an eMule quirk is protocol behavior or Windows/MFC scaffolding.
- Treat `KademliaUDPListener.cpp`, `Search.cpp`, `Indexed.cpp`, and `PacketTracking.cpp` as the core quartet whenever a Rust porting question touches search, publish, unsolicited UDP traffic, or packet throttling.
