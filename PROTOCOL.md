# Quire protocol, version 1

This document defines how a collaborative Yjs document is stored on Arkiv. Any implementation that follows it can read and write Quire documents without asking us. The reference implementation is `packages/y-arkiv`. The conformance vectors in `spec/vectors/` are generated from it.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Overview

A document is a set of Arkiv entities that share a random 32-byte document id. There are six kinds:

| Kind | `qk` | Created by | Purpose | Lifetime | Flags |
|---|---|---|---|---|---|
| ACL | `a` | owner | member list and wrapped epoch keys | 30 days, extended by any member's session | permissionless extension |
| update | `u` | any member | one writer's edits from about one block, merged | same as a new snapshot (30 days, or the owner's `keepUntil`) | none |
| snapshot | `s` | any member | the full document state | 30 days, or until the owner's `keepUntil` | none |
| chunk | `c` | the snapshot's creator | continuation of a snapshot or version | same as its head | same as its head |
| join request | `j` | anyone with the link | asks the owner to add a public key | 1 hour | none |
| version | `v` | any member | frozen copy with its own key | 1 year | readonly, permissionless extension |

Versions and their chunks are readonly with permissionless extension. The ACL has permissionless extension, so it can be kept alive by anyone, in practice any member's session while the owner is away. It holds member names and public keys but no text, so extending it keeps nothing readable alive, and the owner can still delete it. Every other entity (updates, snapshots and their chunks, join requests) carries no flags and can be extended only by its own creator, so nobody outside the member list can keep a document's content alive.

The link a person shares carries three values in the URL fragment: the document id, a 32-byte link secret, and the owner's address. The fragment is never sent to any server.

```
https://<app>/#/d/<base64url(doc id)>.<base64url(link secret)>.<owner address, 40 hex chars>
```

A published version has its own link, carrying the version head's entity key and the version's 32-byte key:

```
https://<app>/#/v/<base64url(version entity key)>.<base64url(version key)>
```

base64url is unpadded (RFC 4648 section 5).

## 2. Public attributes

Every Quire entity MUST carry exactly these four attributes and no others:

| Name | Type | Value |
|---|---|---|
| `qp` | `str` | `quire1` |
| `qd` | `bytes32` | the document id |
| `qk` | `str` | the kind letter from section 1 |
| `qs` | `u64` | the block height the writer last saw before writing |

Attribute names are lowercase because the chain rejects uppercase names. Values MUST be written with their declared types: a `u64` compared against an untyped number matches nothing.

The content type MUST be `application/vnd.quire.v1`. Titles, names, text, timestamps and member lists MUST NOT appear in attributes.

## 3. Keys

All derivations use HKDF-SHA256 with salt `"quire/v1"` (UTF-8) and a 32-byte output.

| Key | Input key material | Info |
|---|---|---|
| meta key | link secret | `meta` |
| epoch 0 content key | link secret | `epoch/0` |
| wrapping key for epoch *n* | the 32-byte x-coordinate of the secp256k1 ECDH point | `wrap/<n>` |
| join request key | the 32-byte x-coordinate of the secp256k1 ECDH point | `join` |

The meta key encrypts the ACL payload. Content keys encrypt updates, snapshots, chunks and, from epoch 1 on, the ACL roster. A version has its own random 32-byte key, which is used directly.

"Sealing to a public key" means: generate an ephemeral secp256k1 key, take the x-coordinate of ECDH(ephemeral, recipient), derive a key with HKDF and the given info, encrypt with AES-256-GCM, and output `ephemeral public key (65 bytes, uncompressed) || envelope`. Epoch keys are sealed to each member with info `wrap/<n>`. Join requests are sealed to the owner with info `join`.

Only the current epoch's key is wrapped. That is enough, because a revocation writes a snapshot under the new key in the same batch (section 6): everything older is inside that snapshot, so a member never needs an earlier epoch's key.

When a member is removed, the owner MUST start a new epoch *n* + 1 with a random content key, seal it to each remaining member, and store the results in the ACL's `wraps` as an unlabelled list in random order. A member finds their wrap by trying each until one opens. Because the list carries no addresses, a link holder learns only how many members there are, not who they are. From then on the roster is stored only as `roster`: an AES-256-GCM envelope, under the epoch key, of the unpadded UTF-8 JSON object `{doc, epoch, members, revoked}`. Readers MUST check that its `doc` and `epoch` match the entity and the ACL header, so a roster cannot be replayed into another document or epoch. A removed member who still holds the link learns nothing about later membership beyond the member count.

An address "matches" a public key when it is the last 20 bytes of keccak-256 over the 64-byte uncompressed public key without its 0x04 prefix (the Ethereum rule).

## 4. Payload format

```
payload  = outer-header || envelope
outer    = 0x51 'Q' | version 0x01 | epoch (u32, big endian)
envelope = AES-256-GCM: iv (12) || ciphertext || tag (16)
```

The envelope is the arkiv-encryption v0.1.0 layout: AES-256-GCM with a random 12-byte IV and no associated data. Its plaintext is a frame:

```
frame = 'Q' 'F' | version 0x01 | kind (1 ASCII byte) | doc id (32) | epoch (u32 BE)
      | header length (u32 BE) | data length (u32 BE)
      | header (UTF-8 JSON object) | data | random padding
```

The frame MUST be padded with random bytes to the smallest of 256, 1024, 4096, 16384, 65536 or 98304 bytes that fits. Readers MUST check that the frame's kind, doc id and epoch equal the entity's `qk`, `qd` and the outer epoch, and MUST discard the entity otherwise. This stops a ciphertext from being replayed into another document or kind.

ACL and join payloads always use epoch 0 in the outer header and the frame. The content epoch lives in the ACL header's `epoch` field. A join payload's envelope is the sealed form (ephemeral key then envelope) instead of a plain envelope.

Block heights inside headers (`base`, `addedAtBlock`, `atBlock`) are decimal strings.

Headers by kind:

| Kind | Header fields | Data |
|---|---|---|
| ACL | `v` (1), `owner`, `ownerPublicKey`, `epoch`, `keepUntil` (block or null), `wraps` (list of hex, unlabelled); epoch 0: `members[] {address, publicKey, name, role, addedAtBlock}` and `revoked[] {address, atBlock}`; epoch 1+: `roster` (hex envelope of `{doc, epoch, members, revoked}`, see section 3) | empty |
| update | `t`: writer's clock in ms; `salt`: 16 random bytes as 32 hex characters, fixed for the writer's session; `sig`: the writer's signature over the salt (below) | a Yjs v1 update |
| snapshot | `id` (16 random bytes, 32 hex characters without `0x`), `base` (block, decimal string), `t`, `chunks[]` (entity keys), `size`, `authors {clientId: {address, salt, sig}}` | the first part of a Yjs v1 state update |
| chunk | `i` (1-based index), `of` (the snapshot's `id`) | the next part. Its outer epoch MUST equal its head's |
| join | `publicKey` (65-byte hex), `name` | empty |
| version | same as snapshot | same as snapshot |

## 5. Reading a document

1. Query the ACL: `qp = "quire1" AND qd = <doc> AND qk = "a" AND $creator = <owner from link>`. Readers MUST NOT trust an ACL created by any other address.
2. Decrypt it with the meta key. If `epoch` > 0, unwrap your epoch key from `wraps` and open `roster` with it. Without that key you can neither see the members nor read current content.
3. Query all snapshots from members: `qk = "s"` and `$creator` is any member address, following cursors. Order them by `qs`, newest first, breaking ties by `createdAt` and then by entity key, both descending (Arkiv does not promise an order, so every reader must break ties the same way). For each member, take their newest snapshot that can be assembled, and apply all of these. One snapshot per member, not just the newest overall, so one member's empty or stale snapshot cannot hide what another member's holds. A member whose chosen snapshot is refused (see below) contributes no snapshot; readers MUST NOT fall back to that member's older ones. For each `chunks[i]`, fetch the entity by key. The chunk MUST have the same `$creator` and the same creation flags as its head, its `i` MUST be the 1-based position and its `of` MUST equal the head's `id`. The assembled data MUST be exactly `size` bytes; otherwise the snapshot is ignored.
4. Query updates from members with `qs >= oldest base - 60`, where the oldest base is the smallest `base` among the snapshots chosen in step 3 (refused ones included), following cursors. Pin later pages to the first page's block with `atBlock`. Apply them in any order: Yjs updates commute, and the client id check below depends only on each update itself.
5. Subscribe to entity events over WebSocket. On `EntityCreated`, fetch the entity by key and apply it if its creator is a member. On `EntityPatched` of the ACL, reload the ACL and catch up. An entity that cannot be read yet (its epoch key or a chunk has not arrived) SHOULD be retried, not dropped.

Readers MUST ignore updates and snapshots whose `$creator` is not in the ACL, even if they decrypt, with one exception: an update by an address in `revoked` whose `createdAt` is at or before that entry's `atBlock` was written by a member, and readers MUST apply it like a member's. Removing someone does not erase the proof of what they wrote while they belonged; anything they create later is ignored. Step 4 therefore queries updates from current and removed members.

Client ids are derived from addresses. A writer picks a random 16-byte `salt` per session and uses the Yjs client id `clientIdFor(address, salt)`: the first 8 bytes of keccak-256 over the 20 address bytes followed by the 16 salt bytes, read big-endian and masked to 53 bits (a result of 0 becomes 1). Every update carries its `salt` in the header, and `sig`: an EIP-191 personal signature by the writer over the bytes `"quire1:salt:"` (UTF-8) followed by the 32-byte document id and the 16-byte salt. Readers MUST ignore an update whose `sig` does not recover to its `$creator`.

Readers MUST ignore an update unless every client id that has structs in it equals `clientIdFor($creator, salt)`. Client ids are taken from the update's structs at any clock (Yjs `parseUpdateMeta`), not from a state vector derived from the update, which only counts runs that start at clock 0. Readers MUST also ignore an update whose client id is already attributed, by an earlier update or a valid snapshot `authors` entry, to a different address. Together the two rules mean an attacker would have to find a 53-bit collision for a victim's client id before the victim's random salt is published, which they cannot do, since the salt first appears in the victim's own first update. The derivation alone is a 53-bit margin (days of GPU time), which is why the second rule matters. "Has structs" includes Skip structs, exactly as `parseUpdateMeta` reports them. Delete sets are not checked: in a shared document any member may delete any text, as in every collaborative editor, so deletions carry no attribution.

A snapshot's `authors` map lets readers attribute text whose updates have expired. An entry counts only if `clientIdFor(address, salt)` equals its client id and `sig` recovers to `address`, so a compactor cannot invent a client id for someone who never wrote. Even a valid entry only says who owns that client id. The snapshot's content under it is still the compactor's word, so readers SHOULD show such attribution as claimed, naming the snapshot's creator.

An update or snapshot that a writer sent under an older epoch, before it saw a rotation, is still applied. To keep that window small, a writer SHOULD re-read the ACL by key (`arkiv_getEntity`, which is free) before each write, and encrypt under the newest epoch it finds. When a writer sees a new epoch it SHOULD compact straight away under the new key, so everything it wrote is also covered by new-epoch content. A removed member can read what was encrypted under keys they held; rotation protects what comes after.

Readers MUST ignore an update whose `qs` is greater than its `createdAt`, and a snapshot whose `qs` or `base` is greater than its `createdAt`: a writer's view of the chain cannot be ahead of the block its entity landed in. Readers MUST also ignore an update whose `qs` is more than 60 blocks before its `createdAt`. Cold readers fetch updates with `qs >= base - 60` (step 4), so a backdated `qs` would make an edit appear for live readers and vanish for cold ones. A malformed entity MUST be ignored and MUST NOT stop a reader from opening the document. Malformed means undecodable Yjs data, or a header that breaks its JSON Schema in `spec/schema`: a missing or extra field, a wrong type, a pattern that does not match (a malformed `authors` entry makes the whole snapshot malformed). Readers MUST apply these rules whether or not they use a schema library. As in JSON Schema, a number is an integer if its value is whole, however it is written (`1`, `1.0` and `1e0` are all the integer 1), and integers MUST be exact in a 64-bit float (below 2^53). A header MUST be a JSON text as written, with no byte-order mark. Readers in every language then reach the same verdict; `spec/vectors/cases` holds one document per rule. The vectors include one such entity.

When opening a document, readers MUST apply the verified updates before the snapshots. Yjs keeps the first struct it sees for an id, so this order stops a snapshot from overriding a genuine update whose dependencies are already integrated. It does not cover an update still waiting on clocks only a snapshot carries: when the snapshot fills the gap, its own struct at that clock wins (and the Rust engine, yrs, lets the snapshot win in more cases). So readers MUST also refuse a snapshot that holds, at any clock a verified update wrote, an item other than that update's. Compare content clock by clock. A shared type counts as the same item if its kind and node name match, because its children and attributes are items of their own, checked at their own clocks. Deleted items do not count, since deleting is any member's right.

A reader MUST refuse a snapshot that carries structs under the reader's own client id beyond what the reader wrote: that would be someone writing as the reader. If a Yjs implementation re-randomises the local client id after a clash, the writer MUST derive a new id with a fresh salt before writing again.

Text is proven only for clock ranges that arrived as items in verified updates. Take the ranges from the update's structs, not from its overall clock span: a Skip struct proves nothing, so an update with a gap cannot vouch for text that only a snapshot carries. A Yjs item merged from several ranges counts as proven only if its whole range is covered. Anything else that a snapshot carries is claimed, attributed through the snapshot's `authors` map and its creator.

A version uses epoch 0 in its outer header and frames, and its chunks are encrypted with the version key like its head. A version link carries no link secret, so a version's reader can check that the version is readonly and who created it, but not that the creator was a member.

The exact raw query strings, as sent to `arkiv_query`:

```
qp = str('quire1') AND qd = bytes32(0x<doc>) AND qk = str('a') AND $creator = addr(0x<owner>)

qp = str('quire1') AND qd = bytes32(0x<doc>) AND qk = str('u') AND qs >= u64(<from>)
  AND ($creator = addr(0x<member 1>) OR $creator = addr(0x<member 2>))
```

A single entity is fetched with `arkiv_getEntity(<key>)`.

Both methods return entities in this shape. Numbers are hex quantities, and the payload is hex:

```json
{
  "key": "0x…", "owner": "0x…", "creator": "0x…",
  "createdAt": "0x1a2b", "expiresAt": "0x3c4d",
  "creationFlags": { "readonly": false, "permissionlessExtension": true, "raw": 2 },
  "payload": "0x5101…",
  "attributes": [
    { "name": "qp", "type": "str", "value": "quire1" },
    { "name": "qd", "type": "bytes32", "value": "0x…" },
    { "name": "qk", "type": "str", "value": "u" },
    { "name": "qs", "type": "u64", "value": "0x2f" }
  ]
}
```

In `creationFlags.raw`, bit 0 is readonly and bit 1 is permissionless extension. The conformance vectors in `spec/vectors/document.json` use the same shape, including `creationFlags`.

## 6. Writing

- Writers SHOULD merge all local Yjs updates produced within one block (about 2 seconds) into one update entity.
- Any member MAY compact. Before writing a snapshot, a writer MUST re-read updates since the previous snapshot's base minus 60 blocks, so the new snapshot contains everything older than its own base. A writer SHOULD delete its own previous snapshot and chunks in the same transaction as the new head. It MUST NOT delete anyone else's entities; covered updates expire on their own.
- A snapshot's `authors` map SHOULD list only client ids that still have structs in the state. The head's data part MUST leave room for its header, so the head's plaintext stays under 100,000 bytes.
- An update MUST be given at least the lifetime a new snapshot would get, so it never expires before a snapshot covers it. Writers SHOULD compact shortly after they stop typing and before they leave.
- A snapshot larger than one entity is split into chunks. Chunks are written first, in transactions whose payloads total at most 100,000 bytes (payloads travel hex-encoded and the public RPC answers BAD_REQUEST once a request passes about 256 KiB: 120,000 bytes of payload lands, 130,000 does not). The head is written last and lists the chunk keys.
- The lease: when less than half of the newest snapshot's lifetime remains, an active member renews it. If they created it and nothing is uncovered, they extend it and its chunks; otherwise they write a fresh snapshot. Any member extends the ACL the same way. An extension MUST only be sent if it moves expiry later, because Arkiv reverts one that does not.
- The owner MAY set `keepUntil` in the ACL; later snapshots and updates then live at least until that block. The owner MAY end a document by deleting the ACL and their own entities in one batch; without the ACL no reader can verify any edit.
- Membership changes are a `patchEntity` of the ACL by the owner. A revocation's ACL patch and the new-epoch snapshot head MUST be in the same transaction.

## 7. Joining

A new member generates a key pair for this document only and publishes a join request with its public key and chosen name, sealed to `ownerPublicKey` from the ACL. Only the owner can open it. The owner MUST check that the public key hashes to the request's `$creator` before trusting it.

## 8. What is visible on chain

For each entity, anyone can see: the creator and owner addresses, creation and expiry blocks, the four attributes, the flags, and a payload whose length is one of six sizes. Everything else, including how many documents a person writes in, needs the link secret. Each member uses a fresh key per document, so their address in one document does not link to their address in another.

What remains visible: which addresses write to a given document id, and when. Writers flush on block boundaries rather than per keystroke, which blurs typing rhythm, but activity timing is not hidden. Gas is also visible: if one sponsor funds every per-document key, an observer can group those keys as funded by the same sponsor.
