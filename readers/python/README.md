# Quire v1 reader (Python)

An implementation of the Quire protocol v1 written from `PROTOCOL.md` and the
vectors in `spec/vectors/`, without reference to the TypeScript code.

## Files

- `quire_audit.py`: checks what the public chain exposes for a document.
  Standard library only.
- `quire_read.py`: decrypts and prints a document. Needs the packages in
  `requirements.txt`.
- `test_vectors.py`: unittest suite against `spec/vectors/`.

## Setup

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
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
- payload length minus 6 (outer header) minus 28 (IV and tag) is one of
  256, 1024, 4096, 16384, 65536, 98304
- no run of 12 or more printable ASCII bytes in the payload

Per document: an ACL exists, and if an owner is known (from `--owner`, or from
the vectors file), an ACL was created by that address.

It also prints counts per kind, lifetimes in days ((expiresAt - createdAt)
times 2 seconds), creation flags, payload sizes and the creator addresses.

Exit status is 0 when all checks pass, 1 when any check fails, 2 on usage or
network errors. The default RPC URL is the Tiramisu testnet; pass `--rpc` for
another node.

## Read

```
.venv/bin/python quire_read.py --vectors ../../spec/vectors/document.json
.venv/bin/python quire_read.py --vectors ../../spec/vectors/document.json \
    --member-key 0x2222222222222222222222222222222222222222222222222222222222222222
.venv/bin/python quire_read.py --link 'https://<app>/#/d/<doc>.<secret>.<owner>' \
    [--member-key 0x<64 hex>] [--rpc URL] [-v]
```

Without `--member-key` it reads only epoch 0 content (what anyone with the
link can read). With a member key it also unwraps the current epoch key from
the ACL. `-v` logs each ignored entity and the reason to stderr.

Output is the XmlFragment `default`, one line per top-level element, with the
text children of each element concatenated.

## Tests

```
.venv/bin/python -m unittest -v test_vectors
```

Reader tests are skipped when `cryptography` or `pycrdt` is not installed.

## Notes

- Epoch key unwrapping uses the 33-byte compressed ECDH shared point as HKDF
  input. `PROTOCOL.md` section 3 says the 32-byte x-coordinate, but the
  vectors only decrypt with the compressed point.
- In the vectors file attributes carry no type, and `qs` is a decimal string.
  The audit reads digit strings there as u64. Live RPC results carry explicit
  types.
