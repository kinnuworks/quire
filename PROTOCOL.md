# Quire protocol, version 1

This document defines how a collaborative Yjs document is stored on Arkiv. Any implementation that follows it can read and write Quire documents without asking us. The reference implementation is `packages/y-arkiv`. The conformance vectors in `spec/vectors/` are generated from it.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Overview

A document is a set of Arkiv entities that share a random 32-byte document id. There are six kinds:

| Kind | `qk` | Created by | Purpose | Lifetime | Flags |
|---|---|---|---|---|---|
| ACL | `a` | owner | member list and wrapped epoch keys | 30 days, renewed | permissionless extension |
| update | `u` | any member | one writer's edits from about one block, merged | 7 days | none |
| snapshot | `s` | any member | the full document state | 30 days, renewed by activity | permissionless extension |
| chunk | `c` | the snapshot's creator | continuation of a snapshot or version | same as its head | same as its head |
| join request | `j` | anyone with the link | asks the owner to add a public key | 1 hour | none |
| version | `v` | any member | frozen copy with its own key | 1 year | readonly, permissionless extension |

The link a person shares carries three values in the URL fragment: the document id, a 32-byte link secret, and the owner's address. The fragment is never sent to any server.

```
https://<app>/#/d/<base64url(doc id)>.<base64url(link secret)>.<owner address, 40 hex chars>
```

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

The meta key encrypts ACL and join request payloads. Content keys encrypt updates, snapshots and chunks. A version has its own random 32-byte key, which is used directly.

Only the current epoch's key is wrapped. That is enough, because a revocation writes a snapshot under the new key in the same batch (section 6): everything older is inside that snapshot, so a member never needs an earlier epoch's key.

When a member is removed, the owner MUST start a new epoch *n* + 1 with a random content key. For each remaining member, the owner computes ECDH between a fresh ephemeral secp256k1 key and the member's public key. The epoch key is then encrypted under the derived wrapping key and stored in the ACL as `ephemeral public key (65 bytes, uncompressed) || envelope`.

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

ACL and join payloads always use epoch 0 in the outer header and the frame, because they are encrypted with the meta key. The content epoch lives in the ACL header's `epoch` field.

Block heights inside headers (`base`, `addedAtBlock`, `atBlock`) are decimal strings.

Headers by kind:

| Kind | Header fields | Data |
|---|---|---|
| ACL | `v` (1), `owner`, `epoch`, `members[] {address, publicKey, name, role, addedAtBlock}`, `wraps {lowercase address: hex}`, `revoked[] {address, atBlock}` | empty |
| update | `t`: writer's clock in ms | a Yjs v1 update |
| snapshot | `base` (block, decimal string), `t`, `chunks[]` (entity keys), `size`, `authors {clientId: address}` | the first part of a Yjs v1 state update |
| chunk | `i` (1-based index), `of` (head entity key) | the next part |
| join | `publicKey` (65-byte hex), `name` | empty |
| version | same as snapshot | same as snapshot |

## 5. Reading a document

1. Query the ACL: `qp = "quire1" AND qd = <doc> AND qk = "a" AND $creator = <owner from link>`. Readers MUST NOT trust an ACL created by any other address.
2. Decrypt it with the meta key. If `epoch` > 0, unwrap your epoch key from `wraps`. Without it you cannot read current content.
3. Query snapshots from members: `qk = "s"` and `$creator` is any member address. Apply the newest snapshot, plus any others whose `base` is within 60 blocks of it. For each `chunks[i]`, fetch the entity by key. The chunk MUST have the same `$creator` as its head, and its header MUST match `i` and `of`.
4. Query updates from members with `qs >= newest base - 60`, following cursors. Pin later pages to the first page's block with `atBlock`. Apply them in any order: Yjs updates commute.
5. Subscribe to entity events over WebSocket. On `EntityCreated` from a member, fetch the entity by key and apply it. On `EntityPatched` of the ACL, reload the ACL.

Readers MUST ignore updates and snapshots whose `$creator` is not in the ACL, even if they decrypt.

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

The conformance vectors in `spec/vectors/document.json` use the same shape.

## 6. Writing

- Writers SHOULD merge all local Yjs updates produced within one block (about 2 seconds) into one update entity.
- Any member MAY compact. Before writing a snapshot, a writer MUST re-read updates since the previous snapshot's base minus 60 blocks, so the new snapshot contains everything older than its own base. Compaction MUST NOT delete other entities; covered updates expire on their own.
- A snapshot larger than one entity is split into chunks. The head and its chunks MUST be created in one atomic batch, with chunk keys predicted in advance.
- A writer that opens a document SHOULD extend the newest snapshot, its chunks and the ACL by a full lifetime once less than half of the snapshot's lifetime remains. These entities carry permissionless extension, so any member can renew the lease.
- Membership changes are a `patchEntity` of the ACL by the owner. A revocation's ACL patch and the new-epoch snapshot MUST be in the same batch.

## 7. Joining

A new member generates a key pair for this document only and publishes a join request with its public key, encrypted with the meta key. The owner MUST check that the public key hashes to the request's `$creator` before trusting it.

## 8. What is visible on chain

For each entity, anyone can see: the creator and owner addresses, creation and expiry blocks, the four attributes, the flags, and a payload whose length is one of six sizes. Everything else, including how many documents a person writes in, needs the link secret. Each member uses a fresh key per document, so their address in one document does not link to their address in another.

What remains visible: which addresses write to a given document id, and when. Writers flush on block boundaries rather than per keystroke, which blurs typing rhythm, but activity timing is not hidden.
