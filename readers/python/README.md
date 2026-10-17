# Quire v1 reader (Python)

An implementation of the Quire protocol v1 written from `PROTOCOL.md`, the
JSON Schemas in `spec/schema/` and the vectors in `spec/vectors/`, without
reference to the TypeScript code.

## Files

- `quire_audit.py`: checks what the public chain exposes for a document.
  Standard library only.
- `quire_read.py`: decrypts and prints a document or a published version, or
  prints a trust report. Needs the packages in `requirements.txt`.
- `test_vectors.py`: unittest suite against `spec/vectors/`.

## Setup

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install jsonschema   # optional, enables schema checks
```

`quire_audit.py` runs with any Python 3.10 or later and no packages.

## Audit

```
python3 quire_audit.py --vectors ../../spec/vectors/document.json
python3 quire_audit.py --doc 0x<64 hex> [--owner 0x<40 hex>] [--rpc URL]
```

Checks, per entity:

- exactly the attributes `qp` (str), `qd` (bytes32), `qk` (str), `qs` (u64)
- payload starts with `51 01`
- payload length minus 6 (outer header) minus 28 (IV and tag), and minus 65
  more for a join request (the ephemeral key), is one of 256, 1024, 4096,
  16384, 65536, 98304
- no run of 12 or more letters and spaces, no run of 24 or more printable
  ASCII bytes, and no frame magic `QF 01` where the ciphertext starts
- flags: ACL, update, snapshot and join entities have none; a version is
  readonly and allows permissionless extension; a chunk has either no flags
  (a snapshot chunk) or both (a version chunk), since it copies its head and
  the head is not visible without decrypting. When `creationFlags.raw` is
  present, bit 0 must equal `readonly`, bit 1 must equal
  `permissionlessExtension`, and no other bit may be set.

The printable-run limits are set so random ciphertext does not trip them.
With any printable byte counted, a 12-byte run appears by chance in about 3%
of 4 KiB payloads and in most 96 KiB ones.

Per document: an ACL exists, and if an owner is known (from `--owner`, or from
the vectors file), an ACL was created by that address.

It also prints counts per kind, lifetimes in days ((expiresAt - createdAt)
times 2 seconds), creation flags, payload sizes and the creator addresses.

Exit status is 0 when all checks pass, 1 when any check fails, 2 on usage or
network errors. The default RPC URL is the Tiramisu testnet; pass `--rpc` for
another node. Requests send their own User-Agent, because the Tiramisu gateway
answers 403 to Python's default one.

## Read

```
.venv/bin/python quire_read.py --vectors ../../spec/vectors/document.json
.venv/bin/python quire_read.py --vectors ../../spec/vectors/document.json \
    --member-key 0x2222222222222222222222222222222222222222222222222222222222222222
.venv/bin/python quire_read.py --link 'https://<app>/#/d/<doc>.<secret>.<owner>' \
    [--member-key 0x<64 hex>] [--rpc URL] [--verify] [--no-schema] [-v]
.venv/bin/python quire_read.py --version-link 'https://<app>/#/v/<key>.<version key>' \
    [--rpc URL] [--verify]
```

Entities come from `--vectors` or, without it, from `--rpc`. With
`--vectors` and no link, the file's own `link` is used.

At epoch 0 anyone with the link can read the members and the content. From
epoch 1 the members are sealed in the ACL `roster` under the epoch key, so
without a member key the reader prints nothing. With a member key it tries
each entry of `wraps` (an unlabelled list) until one opens, then opens the
roster, checks that its `doc` and `epoch` match the ACL, and reads as usual.

`--version-link` reads a published version: it fetches the head by entity
key, requires outer epoch 0, decrypts the head and its chunks with the
version key from the link, and checks the frame against the entity's own
`qd`, since the link carries no document id. It carries no link secret either, so the reader cannot open
the ACL and cannot say whether the version's creator is a member. The
`--verify` report for a version says so.

`-v` logs each ignored entity and the reason to stderr. Output is the
XmlFragment `default`, one line per top-level element, with the text children
of each element concatenated.

`--verify` prints a trust report instead of the text: owner and whether
`ownerPublicKey` hashes to it, epoch, `keepUntil`, the number of wraps (and,
for a member, which one opened), members and revocations when visible,
whether each member's public key hashes to its address, the entities applied
and ignored (grouped by reason), and who each Yjs client id belongs to:
"proven" when an applied update from that address used it, "claimed" when it
comes only from a snapshot's `authors` map. Dropped `authors` entries are
listed. A link holder without a member key sees the
wrap count and nothing that names a member. When the member key is the
owner's, it also opens the join requests and checks that each request's
public key hashes to its creator.

When `jsonschema` is installed, the ACL header, roster, update, snapshot,
chunk and join headers are checked against `spec/schema/` and an entity whose
header fails is ignored. Without it, or with `--no-schema`, these checks are
skipped.

### Rules the reader applies

From section 5:

- the ACL must be created by the owner in the link, and its `owner` must
  match
- snapshots and updates must be created by a member
- snapshots are ordered by `qs`, newest first (ties by block, then key); the
  newest one that assembles is applied, plus others whose `base` is within 60
  blocks of its `base`
- each chunk has the head's creator, the head's outer epoch, the head's
  creation flags, `i` equal to its 1-based position, and `of` equal to the
  head's `id` (the same checks apply to version chunks)
- updates come from `qs >= newest base - 60`
- an update or snapshot in an epoch older than the current one is ignored if
  its `createdAt` block is greater than the largest `atBlock` in `revoked`
- client ids are derived: `clientIdFor(address, salt)` is the first 8 bytes
  of keccak-256 over the 20 address bytes and the 16 salt bytes, big-endian,
  masked to 53 bits, with 0 replaced by 1. An update is ignored unless every
  client id with structs in it equals `clientIdFor($creator, salt)`, where
  `salt` is the update header's. Client ids are read from the struct headers
  of the update, at any clock, Skip structs included (as Yjs
  `parseUpdateMeta` does); client ids that appear only in the delete set are
  not checked. A state vector of the update is not enough,
  because it only reports runs that start at clock 0. The check uses no
  reader state, so updates can be applied in any order
- a snapshot's `authors` entry `{clientId: {address, salt}}` counts only if
  `clientIdFor(address, salt)` equals its client id. A valid entry is shown
  as claimed attribution and binds nothing; an invalid one is dropped and
  listed, and the snapshot is still applied
- a version uses epoch 0 in its outer header and frames; its chunks use the
  version key and the head's epoch

Choices the spec leaves open, made here:

- snapshot ties on `qs` are broken by `createdAt`, then key, so the newest
  snapshot does not depend on query order
- an `authors` key must be a canonical decimal (no leading zeros) to count;
  the schema allows `0123`, which would name the same integer as `123`
- an `authors` entry whose address is not a current member (for example a
  revoked one) still counts as claimed attribution; the report marks it
  "revoked" or "no member"
- updates are sorted by `createdAt`, then key, only so the applied list is
  stable; the result does not depend on it
- a version that is not readonly is reported by `--verify` and failed by the
  audit, but still read
- a chunk whose flags differ from its head's is rejected. Section 1 says a
  chunk has its head's flags, but section 5 does not list this among the
  reader checks

## Tests

```
.venv/bin/python -m unittest -v test_vectors
```

Reader tests are skipped when `cryptography` or `pycrdt` is not installed, and
schema tests when `jsonschema` is not. Besides the expected texts, the tests
build hostile entities with the vector keys:

- a foreign client group holding only a Skip struct, which must still fail
  the check
- `clientIdFor` against every update in the vectors, the 53-bit mask, the
  zero-to-one rule and malformed salts
- an update whose client id is not `clientIdFor(creator, salt)`; a member
  writing under the owner's client id, with her own salt and with the owner's
  salt copied from his headers; one under the revoked member's id; one
  written before every owner update; updates with a missing or malformed
  salt (with schema checks off, so the reader's own check is exercised)
- the vectors' forged update by Mallory, which has a valid salt and her own
  derived id, so only the member filter rejects it
- a valid snapshot `authors` entry (accepted as claimed) and forged ones
  (dropped while the snapshot is still applied), and the same for a version
- `creationFlags.raw` bits in the audit: each combination against the
  booleans, unknown bits, and a mismatch on a vector entity
- old-epoch updates and snapshots after the revocation, and at its block
- a chunked snapshot whose `of` names the entity key instead of the
  snapshot id, whose chunk is in another epoch, or whose chunk has flags
- an ACL whose roster names another document or another epoch
- a version built from a random key, with and without chunks, read from its
  link in memory and through the CLI, plus the audit on it; a version in
  epoch 1 and one whose chunk is in another epoch are rejected

## Notes

- `document.json` carries `creationFlags {readonly, permissionlessExtension,
  raw}` like the RPC. Older vectors with the two booleans at the top level
  are still accepted.
- The vectors contain no chunks and no versions, so those paths are tested
  only with entities the tests build.
