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
| Member list (ACL) | `a` | document owner | members, public keys, wrapped epoch keys | 30 days | extended with the snapshot lease; changed only by `patchEntity` | `permissionlessExtension` |
| Update | `u` | a member | Yjs update merging one writer's edits from about one block | 7 days | none: expires once snapshots cover it | none |
| Snapshot | `s` | a member | full Yjs state (first part) | 30 days | Lifetime Extension by any active member past the halfway mark | `permissionlessExtension` |
| Snapshot chunk | `c` | the snapshot's creator | next part of the state | same as its head | extended together with its head | `permissionlessExtension` |
| Join request | `j` | anyone with the link | requester's public key and chosen name | 1 hour | none | none |
| Published version | `v` (+ `c`) | a member | frozen Yjs state under its own key | 1 year | anyone can extend | `readonly`, `permissionlessExtension` |

### Why these lifetimes

- An update only has to live until a snapshot includes it. Seven days covers a collaborator who is offline for a long weekend. Readers who come back later load the snapshot instead.
- A snapshot is a lease. Each session that opens the document renews it once half of its 30 days have passed, so a document stays alive while people use it. If nobody opens it for a month, it fades away on its own. The owner can also set the lifetime directly (1 day to 1 year).
- A join request is answered within minutes or not at all, so it expires after an hour.
- A published version is meant to outlive the document, and anyone who holds its link can extend it.

## Ownership and authorship

- Trust comes from `$creator`. The ACL is found with `$creator = owner` (from the link), and updates and snapshots are accepted only if their `$creator` is in the ACL. A copy of a valid ciphertext written by anyone else is never applied (`stats.rejectedWrites` in the app).
- `$owner` controls writes. Only the owner can patch the ACL, and only an entity's own creator can delete it ("Shred my writing").
- Each person uses a fresh key per document, so their `$creator` addresses in two documents cannot be linked.

## Queries the app runs

Opening a document costs three queries. Live edits after that cost none: they arrive as WebSocket events and are fetched by key with `arkiv_getEntity`, which the public RPC does not bill against the query budget.

| # | When | Query | Code |
|---|---|---|---|
| 1 | open | `qp = str('quire1') AND qd = bytes32(<doc>) AND qk = str('a') AND $creator = addr(<owner>)` | [`provider.ts` loadAcl](../packages/y-arkiv/src/provider.ts) |
| 2 | open | `… AND qk = str('s') AND ($creator = addr(<m1>) OR …)`, limit 20 | `provider.ts` loadState |
| 3 | open, before compacting | `… AND qk = str('u') AND qs >= u64(<base − 60>) AND ($creator = addr(<m1>) OR …)`, cursor pages pinned with `atBlock` | `provider.ts` loadState, resync |
| 4 | owner opens | `… AND qk = str('j')`, limit 50 | `provider.ts` loadJoinRequests |
| 5 | shred | `… AND $creator = addr(<me>)` | `provider.ts` shredMine |
| 6 | history check | queries 1 to 3 with `atBlock = <past block>` | `provider.ts` loadAt |
| – | live | `watchEntityEvents` over WebSocket, no `fromBlock`; then `arkiv_getEntity(<key>)` | [`sdk.ts`](../packages/y-arkiv/src/sdk.ts) |

## Batches

| Operation | One atomic `executeBatch` containing |
|---|---|
| Create document | ACL create + snapshot create(s) |
| Compact | snapshot head + chunks, keys predicted with `predictEntityKeys` |
| Remove a member | ACL patch (new epoch, re-wrapped keys) + new snapshot under the new key |
| Renew lease | extensions for snapshot, its chunks and the ACL |
| Shred my writing | deletes of every entity I created for the document |
