# Quire on Arkiv: schema

Quire stores each collaborative document as a set of Arkiv entities that share a random 32-byte document id. The normative description, with byte layouts, is in [PROTOCOL.md](../PROTOCOL.md). This file lists the entity types, their attributes and lifetimes, and every query the app runs.

## Attributes (identical on every entity)

| Attribute | Type | Meaning | Why it is public |
|---|---|---|---|
| `qp` | `str` | protocol tag, always `quire1` | lets any reader find Quire entities without us |
| `qd` | `bytes32` | random document id | the only grouping key; derived from nothing, so it reveals nothing |
| `qk` | `str` | kind: `a` `u` `s` `c` `j` `v` | readers ask for one kind at a time |
| `qs` | `u64` | chain height the writer saw before writing | range filter for catch-up (`qs >= base - 60`) |

Everything else (text, titles, member names, timestamps, the member list) is inside an AES-256-GCM payload padded to one of six fixed sizes. Content type: `application/vnd.quire.v1`.

## Entity types

| Kind | `qk` | Creator | Payload (encrypted) | Expiration | Renewal | Flags |
|---|---|---|---|---|---|---|
| Member list (ACL) | `a` | document owner | owner key, epoch, wrapped epoch keys, roster (sealed under the epoch key after a revocation) | 30 days, or the owner's `keepUntil` | extended by any member's session; changed only by the owner with `patchEntity` | `permissionlessExtension` (it holds no text) |
| Update | `u` | a member | Yjs update merging one writer's edits from about one block | as long as a new snapshot (30 days or `keepUntil`) | none: folded into a snapshot before it can expire | none |
| Snapshot | `s` | a member | full Yjs state (first part) | 30 days, or `keepUntil` | its creator extends it, or another member writes a fresh one | none |
| Snapshot chunk | `c` | the snapshot's creator | next part of the state | same as its head | extended together with its head | none |
| Join request | `j` | anyone with the link | requester's public key and chosen name, sealed to the owner's key | 1 hour | none | none |
| Published version | `v` (+ `c`) | a member | frozen Yjs state under its own key | 1 year | anyone holding the link can extend | `readonly`, `permissionlessExtension` |

### Why these lifetimes

- An update lives as long as a new snapshot would, so it can never expire before a snapshot covers it. Writers also compact about two minutes after they stop typing and when they leave the page, so most documents end every session fully folded into one snapshot.
- A snapshot is a lease. A member who opens the document past the halfway mark renews it, by extending their own snapshot or writing a fresh one. If nobody opens it for a month, it expires from Arkiv's state. Nobody outside the member list can extend a snapshot, because snapshots and edits carry no permissionless-extension flag. The member list does carry it, so writers can keep a document open while the owner is away. That also means anyone, strangers included, can extend it. It holds member names and public keys (sealed after a rotation) but no text, so extending it keeps nothing readable alive, and the owner can delete it at any time.
- The owner can keep the document longer (90 days to 3 years). The target is stored in the member list, so every later snapshot honours it. Arkiv only lets an extension move expiry later, so to end a document sooner the owner deletes it, which removes the member list and every entity the owner created in one batch.
- A join request is answered within minutes or not at all, so it expires after an hour.
- A published version is meant to outlive the document, and anyone who holds its link can extend it.

## Ownership and authorship

- Each edit's Yjs client id must equal `clientIdFor($creator, salt)`, with the salt signed by the creator, so no member can write under another member's name.
- Trust comes from `$creator`. The ACL is found with `$creator = owner` (from the link), and updates and snapshots are accepted only if their `$creator` is in the ACL. A copy of a valid ciphertext written by anyone else is never applied (`stats.rejectedWrites` in the app).
- `$owner` controls writes. Only the owner can patch the ACL, and only an entity's own creator can delete it ("Shred my writing").
- Each person uses a fresh key per document, so their `$creator` addresses in two documents cannot be linked.

## Queries the app runs

Opening a document costs three queries. Live edits after that cost none: they arrive as WebSocket events and are fetched by key with `arkiv_getEntity`, which the public RPC does not bill against the query budget. Background work does cost a little: one query for each compaction (at most every two minutes after typing stops) and one for a resync every 15 minutes.

| # | When | Query | Code |
|---|---|---|---|
| 1 | open | `qp = str('quire1') AND qd = bytes32(<doc>) AND qk = str('a') AND $creator = addr(<owner>)` | [`provider.ts` loadAcl](../packages/y-arkiv/src/provider.ts) |
| 2 | open | `… AND qk = str('s') AND ($creator = addr(<m1>) OR …)`, all pages, ordered by `qs` on the client | `provider.ts` loadState |
| 3 | open, before compacting | `… AND qk = str('u') AND qs >= u64(<base − 60>) AND ($creator = addr(<m1>) OR …)`, cursor pages pinned with `atBlock` | `provider.ts` loadState, resync |
| 4 | owner opens, and on resync | `… AND qk = str('j')`, all pages | `provider.ts` loadJoinRequests |
| 5 | shred, delete | `… AND $creator = addr(<me>)` | `provider.ts` shredMine, deleteDocument |
| 6 | history check | queries 1 to 3 with `atBlock = <past block>` | `provider.ts` loadAt |
| 7 | live | `watchEntityEvents` over WebSocket, no `fromBlock`; then `arkiv_getEntity(<key>)` | [`sdk.ts`](../packages/y-arkiv/src/sdk.ts) |

## Batches

| Operation | One atomic `executeBatch` containing |
|---|---|
| Create document | ACL create + snapshot head |
| Compact | chunks first, in transactions of at most 100,000 payload bytes (payloads travel hex-encoded and the RPC refuses requests over about 256 KiB: 120,000 bytes lands, 130,000 does not); then the head, which lists the chunk keys |
| Remove a member | ACL patch (new epoch, re-wrapped keys, sealed roster) + the new snapshot head under the new key |
| Renew lease | extensions for my snapshot and its chunks, and the ACL, only where they move expiry later |
| Shred my edit history | deletes of my updates and join requests |
| Delete document | deletes of the ACL and every entity the owner created |
