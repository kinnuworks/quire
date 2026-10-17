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
  present, an entity with neither flag must have raw 0. PROTOCOL.md does not
  give raw's bit layout, so raw is not checked otherwise.

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
key, decrypts it and its chunks with the version key from the link, and
checks the frame against the entity's own `qd`, since the link carries no
document id. It carries no link secret either, so the reader cannot open
the ACL and cannot say whether the version's creator is a member. The
`--verify` report for a version says so.

`-v` logs each ignored entity and the reason to stderr. Output is the
XmlFragment `default`, one line per top-level element, with the text children
of each element concatenated.

`--verify` prints a trust report instead of the text: owner and whether
`ownerPublicKey` hashes to it, epoch, `keepUntil`, the number of wraps (and,
for a member, which one opened), members and revocations when visible,
whether each member's public key hashes to its address, the entities applied
and ignored (grouped by reason), and which creator each Yjs client id is
bound to and by which entity. A link holder without a member key sees the
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
- client ids are bound first by the `authors` maps of the applied snapshots,
  newest snapshot first; then each update binds the ids it uses that are
  still unbound. An update is ignored if any of its structs uses a client id
  already bound to another creator. Client ids are read from the struct
  headers of the update, at any clock. A state vector of the update is not
  enough, because it only reports runs that start at clock 0.

Since binding depends on which update comes first, updates are applied in
the order section 5 fixes: `createdAt`, then entity key.

Choices the spec leaves open, made here:

- snapshot ties on `qs` are broken by `createdAt`, then key, so the newest
  snapshot does not depend on query order
- when two applied snapshots map one client id to different addresses, the
  newest snapshot's claim is kept and the disagreement is listed in the
  trust report
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

- updates under another member's client id, including one written before
  any of that member's updates (caught only by the snapshot's `authors`) and
  one under the revoked member's id
- two updates in one block under one fresh client id, to pin the
  `createdAt`, then key order
- old-epoch updates and snapshots after the revocation, and at its block
- a chunked snapshot whose `of` names the entity key instead of the
  snapshot id, whose chunk is in another epoch, or whose chunk has flags
- an ACL whose roster names another document or another epoch
- a version built from a random key, with and without chunks, read from its
  link in memory and through the CLI, plus the audit on it

## Notes

- `document.json` carries `creationFlags {readonly, permissionlessExtension,
  raw}` like the RPC. Older vectors with the two booleans at the top level
  are still accepted.
- The vectors contain no chunks and no versions, so those paths are tested
  only with entities the tests build.
