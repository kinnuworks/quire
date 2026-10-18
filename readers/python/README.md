# Quire v1 reader (Python)

An implementation of the Quire protocol v1 written from `PROTOCOL.md`, the
JSON Schemas in `spec/schema/` and the vectors in `spec/vectors/`, without
reference to the TypeScript code.

## Files

- `quire_audit.py`: checks what the public chain exposes for a document.
  Standard library only.
- `quire_read.py`: decrypts and prints a document or a published version, or
  prints a trust report. Needs the packages in `requirements.txt`. The
  secp256k1 public key recovery for salt signatures is written out in pure
  Python, since `cryptography` can verify ECDSA but cannot recover a key.
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
- flags: the ACL allows permissionless extension and has no other flag;
  update, snapshot and join entities have none; a version is readonly and
  allows permissionless extension; a chunk has either no flags
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
    [--member-key 0x<64 hex>] [--own-salt <32 hex>] [--rpc URL] [--audit] [--at <block>] [--json] [--verify] [--no-schema] [-v]
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

`--audit` reads every edit still on chain and checks each author against the
member list as it stood at that edit's block. It also prints, to stderr, a
`copied` line for each passage of 24 or more characters that a different
member held first: it replays the verified edits block by block, notes which
member's own contiguous text held each passage (whitespace collapsed), and
flags a passage only if someone else held it before its own author ever did.
With `--json` the same verdicts are in `copied`. `--at <block>` reads the
document as it stood at that block.

`-v` logs each ignored entity and the reason to stderr. Output is the
XmlFragment `default`, one line per top-level element, with the text children
of each element concatenated.

`--own-salt` is for a reader that is also writing: given the session's salt
and the member key, it refuses any snapshot carrying structs under that
session's client id beyond what its verified updates wrote.

`--verify` prints a trust report instead of the text: owner and whether
`ownerPublicKey` hashes to it, epoch, `keepUntil`, the number of wraps (and,
for a member, which one opened), the ACL's flags, members and revocations
when visible, whether each member's public key hashes to its address, the
entities applied and ignored (grouped by reason), and who each Yjs client
id belongs to: "proven" when an applied update from that address used it,
"claimed via <snapshot creator>" when it comes only from a snapshot's
`authors` map. Dropped `authors` entries are listed. A "text ranges"
section then lists, per client id, the clock ranges of the opened
document, each marked proven or claimed (with the creators of the snapshots
that carried it), the content kinds and a text excerpt. A link holder
without a member key sees the wrap count and nothing that names a member. When the member key is the
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
- an update whose `qs` is greater than its `createdAt`, and a snapshot whose
  `qs` or `base` is, is ignored
- a malformed entity (undecodable Yjs data, bad header types, a header that
  is not an object) is ignored, whether or not `jsonschema` is installed,
  and the read goes on. The Yjs data of every update and snapshot is decoded
  here before Yjs sees it, and must decode exactly, with no trailing bytes
- snapshots are ordered by `qs`, newest first (ties by block, then key); the
  newest one that assembles is applied, plus others whose `base` is within 60
  blocks of its `base`
- each chunk has the head's creator, the head's outer epoch, the head's
  creation flags, `i` equal to its 1-based position, and `of` equal to the
  head's `id` (the same checks apply to version chunks)
- updates come from `qs >= newest base - 60`
- updates and snapshots sent under an older epoch are applied (the earlier
  rule that ignored them after a revocation is gone)
- client ids are derived: `clientIdFor(address, salt)` is the first 8 bytes
  of keccak-256 over the 20 address bytes and the 16 salt bytes, big-endian,
  masked to 53 bits, with 0 replaced by 1. An update is ignored unless every
  client id with structs in it equals `clientIdFor($creator, salt)`, where
  `salt` is the update header's. Client ids are read from the struct headers
  of the update, at any clock, Skip structs included (as Yjs
  `parseUpdateMeta` does); client ids that appear only in the delete set are
  not checked. A state vector of the update is not enough,
  because it only reports runs that start at clock 0
- an update's `sig` must recover to its `$creator`. It is an EIP-191
  personal signature: keccak-256 of `"\x19Ethereum Signed Message:\n60"`
  followed by the 60-byte message `"quire1:salt:"`, the 32-byte document
  id and the 16-byte salt. The signature is r, s and v as 130 hex
  characters after `0x`
- an update whose client id is already attributed to a different address,
  by an earlier update or a valid snapshot `authors` entry, is ignored
- a snapshot's `authors` entry `{clientId: {address, salt, sig}}` counts
  only if `clientIdFor(address, salt)` equals its client id and `sig`
  recovers to `address`. A valid entry is shown as claimed, via the
  snapshot's creator; an invalid one is dropped and listed, and the snapshot
  is still applied
- a snapshot with structs under the reader's own client id beyond what the
  reader's updates wrote is refused (with `--own-salt`)
- the verified updates are applied before the snapshots
- text is proven only for clock ranges that came in verified updates. Each
  struct of the opened document is checked clock by clock: it is proven only
  if a verified update carried the same item (content, origin, right origin
  and parent) at every clock of it, so an item Yjs merged from a verified
  range and a snapshot-only range is claimed as a whole
- a version uses epoch 0 in its outer header and frames; its chunks use the
  version key and the head's epoch

Beyond the spec:

- a snapshot that carries, at a clock some verified update wrote, an item
  that differs from that update's is refused, and step 3 falls back to the
  next snapshot. Applying updates first is not enough on its own: an update
  whose dependencies are not integrated yet waits as pending in Yjs, and
  when a snapshot later fills the gap, Yjs integrates the snapshot's struct
  at that clock and drops the genuine one. In the vectors the owner's
  epoch 1 update follows Cal's line, which only the snapshots carry, so it
  is always pending when the snapshots arrive. A deleted or GC struct over a
  verified clock is not a conflict, since any member may delete text

Choices the spec leaves open, made here:

- snapshot ties on `qs` are broken by `createdAt`, then key, so the newest
  snapshot does not depend on query order
- "earlier update" in the attribution rule is ordered by `createdAt`, then
  entity key. Valid snapshot `authors` entries attribute first, whatever
  their block; among snapshots the newest wins, and a valid entry naming a
  different address for an id already attributed is dropped
- only updates that pass every other check attribute a client id; updates
  older than the query window are not seen and attribute nothing
- `v` in a signature may be 27 or 28, or 0 or 1 for the same parities; a
  high `s` is accepted
- an `authors` key must be a canonical decimal (no leading zeros) to count;
  the schema allows `0123`, which would name the same integer as `123`
- an `authors` entry whose address is not a current member (for example a
  revoked one) still counts as claimed attribution; the report marks it
  "revoked" or "no member"
- a snapshot whose `authors` entry lacks `sig` (or any field) breaks the
  header schema, so the whole snapshot is ignored, with or without
  `jsonschema` installed: the built-in checks apply the same rules
- snapshots are applied newest first, so where two snapshots disagree on a
  clock no update wrote, the newest one's struct is kept
- the `qs` and `base` sanity rule is applied to snapshots, not to versions
- a refused snapshot's `authors` entries do not count; the read starts over
  without it
- a version that is not readonly is refused, as the TypeScript reader does
- a chunk whose flags differ from its head's is rejected (section 5)

## Tests

```
.venv/bin/python -m unittest -v test_vectors
```

Reader tests are skipped when `cryptography` or `pycrdt` is not installed, and
schema tests when `jsonschema` is not. The client ids and salts the tests use
are read from the vectors' update headers, so a regenerated vectors file
needs no new constants. Besides the expected texts, the tests build hostile
entities with the vector keys. Signatures are made with `cryptography`,
which gives r and s, and the recovery id is found by recovering both
parities.

- every signature in the vectors (updates and `authors` entries, made by
  another implementation) recovers to its signer; recovery agrees with
  `cryptography` on random keys, for v of 27/28 and 0/1 and for high s, and
  rejects r of 0 or n, s of 0, v of 29 and a short signature;
  `hashMessage("hello world")`
- a valid signature passes; an update whose salt is signed by someone else,
  over another document or over another salt, or whose sig is missing or
  malformed (schema checks off, so the reader's own check rejects it)
- the attribution rule: a member who finds a salt colliding with a revoked
  member's snapshot-attributed id, before and after the snapshot; two
  members on one id, where the earlier update keeps it in any query order;
  one member on one id with two salts, which is kept. The collision is
  forced by patching `clientIdFor`, since nobody can find one on demand
- snapshot `authors` entries signed by someone else, signed for another
  document, with a sig that recovers nothing, or with no sig (dropped
  without schema checks, whole snapshot ignored with them); a valid entry
  for an id another snapshot already gives to someone else
- the ACL flag rule: permissionless extension only, with every other
  combination and a raw value that disagrees failing the audit; update,
  snapshot and join entities with permissionless extension fail
- `qs` after `createdAt` for an update, `qs` or `base` after `createdAt`
  for a snapshot, and equal values accepted
- malformed entities: random Yjs bytes, a string that is not UTF-8,
  trailing bytes, `t` not an integer, a numeric salt, a list as sig, a
  header that is not an object, a snapshot whose `chunks` is not a list,
  one whose data is random, one whose `authors` is a list. The document
  still opens, with and without schema checks
- updates applied before snapshots; a member's snapshot that rewrites the
  owner's verified epoch 1 paragraph is refused, also with his first update
  expired; the same snapshot with the refusal switched off wins, and a
  plain Yjs case shows why (first struct wins only when the update is not
  pending)
- a snapshot under the reader's own id beyond its updates, refused with
  `--own-salt` and applied as claimed text without it
- text ranges: in the vectors Cal's line is claimed and the rest proven; a
  member's two updates that Yjs merges into one item are proven when both
  updates are present and claimed as a whole when the first is only in a
  snapshot; the report shows both
- old-epoch updates and snapshots after the revocation are applied
- a foreign client group holding only a Skip struct, which must still fail
  the check
- `clientIdFor` against every update in the vectors, the 53-bit mask, the
  zero-to-one rule and malformed salts
- an update whose client id is not `clientIdFor(creator, salt)`; a member
  writing under the owner's client id, with her own salt and with the owner's
  salt copied from his headers; one under the revoked member's id; one
  written before every owner update; updates with a missing or malformed
  salt
- the vectors' forged update by Mallory, which has a valid salt, her own
  derived id and a valid signature by her, so only the member filter
  rejects it
- `creationFlags.raw` bits in the audit: each combination against the
  booleans, unknown bits, and a mismatch on a vector entity
- a chunked snapshot whose `of` names the entity key instead of the
  snapshot id, whose chunk is in another epoch, or whose chunk has flags
- an ACL whose roster names another document or another epoch
- a version built from a random key, with and without chunks, read from its
  link in memory and through the CLI, plus the audit on it; a version in
  epoch 1 and one whose chunk is in another epoch are rejected; version
  `authors` entries with a wrong id or someone else's signature are dropped

## Notes

- `document.json` carries `creationFlags {readonly, permissionlessExtension,
  raw}` like the RPC. Older vectors with the two booleans at the top level
  are still accepted.
- The vectors contain no chunks and no versions, so those paths are tested
  only with entities the tests build.
- The per-clock comparison keeps one entry per verified clock in memory,
  which is fine for documents of a few hundred kilobytes.
