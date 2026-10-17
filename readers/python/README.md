# Quire v1 reader (Python)

An implementation of the Quire protocol v1 written from `PROTOCOL.md`, the
JSON Schemas in `spec/schema/` and the vectors in `spec/vectors/`, without
reference to the TypeScript code.

## Files

- `quire_audit.py`: checks what the public chain exposes for a document.
  Standard library only.
- `quire_read.py`: decrypts and prints a document, or prints a trust report.
  Needs the packages in `requirements.txt`.
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
  readonly; a chunk has either no flags or the version set (readonly and
  permissionless extension), since it copies its head and the head is not
  visible without decrypting

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
```

At epoch 0 anyone with the link can read the members and the content. From
epoch 1 the members are sealed in the ACL `roster` under the epoch key, so
without a member key the reader prints nothing. With a member key it unwraps
the epoch key from `wraps`, opens the roster and reads as usual.

`-v` logs each ignored entity and the reason to stderr. Output is the
XmlFragment `default`, one line per top-level element, with the text children
of each element concatenated.

`--verify` prints a trust report instead of the text: owner and whether
`ownerPublicKey` hashes to it, epoch, `keepUntil`, members and revocations
when visible, whether each member's public key hashes to its address, the
entities applied and ignored (grouped by reason), and which creator each Yjs
client id is bound to. When the member key is the owner's, it also opens the
join requests and checks that each request's public key hashes to its
creator.

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
- each chunk has the head's creator, `i` equal to its 1-based position, and
  `of` equal to the head's `id`
- updates come from `qs >= newest base - 60`
- an update in an epoch older than the current one is ignored if its
  `createdAt` block is later than the latest `atBlock` in `revoked`
- an update is ignored if any of its structs uses a Yjs client id already
  bound to another creator; the first applied update binds its client ids.
  Client ids are read from the struct headers of the update, at any clock.
  A state vector of the update is not enough, because it only reports runs
  that start at clock 0.

Since binding depends on which update comes first, updates are applied in a
fixed order: creation block, then `qs`, then key.

## Tests

```
.venv/bin/python -m unittest -v test_vectors
```

Reader tests are skipped when `cryptography` or `pycrdt` is not installed, and
schema tests when `jsonschema` is not. Besides the expected texts, the tests
build hostile entities with the vector keys: an update under another member's
client id, an old-epoch update written after the revocation, and a chunked
snapshot whose `of` names the entity key instead of the snapshot id.

## Notes

- `document.json` puts `readonly` and `permissionlessExtension` at the top
  level of each entity. RPC results nest them in `creationFlags`. Both are
  accepted.
- The vectors contain no chunks and no versions, so those paths are tested
  only with entities the tests build.
