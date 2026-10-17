#!/usr/bin/env python3
"""Read a Quire v1 document, or a published version, and print its text.

Follows PROTOCOL.md sections 1, 3 to 5 and 7. Needs `cryptography` and
`pycrdt` (see requirements.txt). Entities come from a vectors file
(--vectors) or a live Arkiv node (--rpc), and the document is named by a
document link (--link) or a version link (--version-link). With --verify it
prints a trust report instead of the text. If `jsonschema` is installed,
decrypted headers are also checked against spec/schema/*.json.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable, Iterable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pycrdt import Doc, XmlElement, XmlFragment, XmlText

import quire_audit as qa
from quire_audit import Entity

SALT = b"quire/v1"
SNAPSHOT_WINDOW = 60  # blocks, section 5 steps 3 and 4
FRAME_FIXED = 48  # 'QF' | ver | kind | doc(32) | epoch | hlen | dlen
EPHEMERAL = 65  # uncompressed secp256k1 public key in a sealed box
SCHEMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "spec", "schema")


class Rejected(Exception):
    """An entity that a reader MUST discard."""


# ---------------------------------------------------------------- schemas


class Schemas:
    """Optional JSON Schema checks for decrypted headers (spec/schema).

    Skipped cleanly when `jsonschema` is not importable or the directory
    is missing. `status` says which case applies.
    """

    FILES = {
        "acl": "acl-header.json",
        "roster": "acl-roster.json",
        "update": "update-header.json",
        "snapshot": "snapshot-header.json",
        "chunk": "chunk-header.json",
        "join": "join-header.json",
        "entity": "entity.json",
    }

    def __init__(self, directory: str = SCHEMA_DIR, enabled: bool = True) -> None:
        self.validators: dict[str, Any] = {}
        if not enabled:
            self.status = "skipped (disabled)"
            return
        try:
            import jsonschema
        except ImportError:
            self.status = "skipped (jsonschema not installed)"
            return
        if not os.path.isdir(directory):
            self.status = f"skipped ({directory} not found)"
            return
        for name, filename in self.FILES.items():
            path = os.path.join(directory, filename)
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as fh:
                schema = json.load(fh)
            cls = jsonschema.validators.validator_for(schema)
            self.validators[name] = cls(schema)
        self.status = f"checked against {len(self.validators)} schemas in spec/schema"

    def check(self, name: str, obj: Any) -> None:
        v = self.validators.get(name)
        if v is None:
            return
        errors = sorted(v.iter_errors(obj), key=lambda e: list(e.path))
        if errors:
            where = "/".join(str(p) for p in errors[0].path) or "(root)"
            raise Rejected(f"{name} header fails schema at {where}: {errors[0].message[:120]}")


# ---------------------------------------------------------------- keys


def hkdf(ikm: bytes, info: str) -> bytes:
    """HKDF-SHA256, salt "quire/v1", 32-byte output (section 3)."""
    return HKDF(hashes.SHA256(), 32, SALT, info.encode()).derive(ikm)


def meta_key(link_secret: bytes) -> bytes:
    return hkdf(link_secret, "meta")


def epoch0_key(link_secret: bytes) -> bytes:
    return hkdf(link_secret, "epoch/0")


def open_envelope(key: bytes, envelope: bytes) -> bytes:
    """AES-256-GCM: iv (12) || ciphertext || tag (16), no associated data."""
    return AESGCM(key).decrypt(envelope[:12], envelope[12:], None)


def open_sealed(private_key: ec.EllipticCurvePrivateKey, sealed: bytes, info: str) -> bytes:
    """Open `ephemeral pub (65) || envelope` (section 3, "sealing").

    The HKDF input is the 32-byte x-coordinate of the ECDH point, which is
    what `cryptography`'s ECDH exchange returns.
    """
    eph = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), sealed[:EPHEMERAL])
    shared_x = private_key.exchange(ec.ECDH(), eph)
    return open_envelope(hkdf(shared_x, info), sealed[EPHEMERAL:])


def unwrap_epoch_key(private_key: ec.EllipticCurvePrivateKey, wrap: bytes, epoch: int) -> bytes:
    return open_sealed(private_key, wrap, f"wrap/{epoch}")


def public_key_bytes(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def public_key_hex(private_key: ec.EllipticCurvePrivateKey) -> str:
    return "0x" + public_key_bytes(private_key).hex()


# Keccak-256 (the pre-NIST padding Ethereum uses; hashlib.sha3_256 differs).
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def _rol(v: int, n: int) -> int:
    return ((v << n) | (v >> (64 - n))) & _M64 if n else v


def _keccak_f(a: list[int]) -> list[int]:
    for rc in _RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _ROT[x][y])
        a = [
            b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)])
            for i in range(25)
        ]
        a[0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b"\x01" + b"\x00" * ((-len(data) - 1) % rate)
    msg[-1] |= 0x80
    state = [0] * 25
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(msg[off + 8 * i : off + 8 * i + 8], "little")
        state = _keccak_f(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state[:4])


def address_of(public_key: bytes | str) -> str:
    """Ethereum address of an uncompressed secp256k1 public key."""
    raw = qa._hex_bytes(public_key) if isinstance(public_key, str) else public_key
    if len(raw) != 65 or raw[0] != 4:
        raise ValueError("expected a 65-byte uncompressed public key")
    return "0x" + keccak256(raw[1:])[-20:].hex()


# secp256k1 public key recovery, for the EIP-191 salt signatures of section 5.
# `cryptography` can verify ECDSA but cannot recover a key, so the curve
# math is done here with Jacobian coordinates. Only public data goes through
# it, so it makes no attempt at constant time.
_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    1,
)
_Jacobian = tuple[int, int, int] | None  # None is the point at infinity


def _jdouble(p: _Jacobian) -> _Jacobian:
    if p is None or p[1] == 0:
        return None
    x, y, z = p
    yy = y * y % _P
    s = 4 * x * yy % _P
    m = 3 * x * x % _P  # the curve's a is 0
    nx = (m * m - 2 * s) % _P
    ny = (m * (s - nx) - 8 * yy * yy) % _P
    return nx, ny, 2 * y * z % _P


def _jadd(p: _Jacobian, q: _Jacobian) -> _Jacobian:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1z1, z2z2 = z1 * z1 % _P, z2 * z2 % _P
    u1, u2 = x1 * z2z2 % _P, x2 * z1z1 % _P
    s1, s2 = y1 * z2 * z2z2 % _P, y2 * z1 * z1z1 % _P
    if u1 == u2:
        return _jdouble(p) if s1 == s2 else None
    h, r = (u2 - u1) % _P, (s2 - s1) % _P
    hh = h * h % _P
    hhh = h * hh % _P
    nx = (r * r - hhh - 2 * u1 * hh) % _P
    ny = (r * (u1 * hh - nx) - s1 * hhh) % _P
    return nx, ny, h * z1 * z2 % _P


def _jmul(p: _Jacobian, k: int) -> _Jacobian:
    out: _Jacobian = None
    while k:
        if k & 1:
            out = _jadd(out, p)
        p = _jdouble(p)
        k >>= 1
    return out


def _affine(p: _Jacobian) -> tuple[int, int] | None:
    if p is None:
        return None
    x, y, z = p
    zi = pow(z, -1, _P)
    return x * zi * zi % _P, y * zi * zi * zi % _P


SIG_HEX = re.compile(r"^0x[0-9a-fA-F]{130}$")


def recover_public_key(digest: bytes, signature: bytes) -> bytes | None:
    """The 65-byte uncompressed public key that made `signature` over the
    32-byte `digest`, or None if there is none.

    `signature` is r (32) || s (32) || v (1), with v 27 or 28 as
    personal_sign writes it; 0 and 1 are accepted as the same parities.
    r and s must lie in [1, n - 1]. A high s is accepted: EIP-2's low-s rule
    is a transaction rule and section 5 does not ask for it.
    """
    if len(digest) != 32 or len(signature) != 65:
        return None
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    v = signature[64]
    if v in (27, 28):
        v -= 27
    if v not in (0, 1) or not (0 < r < _N and 0 < s < _N):
        return None
    # x = r: v of 27/28 carries one parity bit, not the x >= n overflow bit.
    y2 = (pow(r, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)  # p = 3 mod 4
    if y * y % _P != y2:
        return None
    if y & 1 != v:
        y = _P - y
    z = int.from_bytes(digest, "big") % _N
    ri = pow(r, -1, _N)
    q = _affine(_jadd(_jmul(_G, (-z * ri) % _N), _jmul((r, y, 1), s * ri % _N)))
    if q is None:
        return None
    return b"\x04" + q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")


def eip191_digest(message: bytes) -> bytes:
    """keccak-256("\\x19Ethereum Signed Message:\\n" || decimal length || message)."""
    return keccak256(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode() + message)


def salt_message(doc: str, salt: str) -> bytes:
    """Section 5: "quire1:salt:" (UTF-8) || 32-byte doc id || 16-byte salt."""
    return b"quire1:salt:" + qa._hex_bytes(doc) + bytes.fromhex(salt)


@lru_cache(maxsize=4096)
def _signer(doc: str, salt: str, sig: str) -> str | None:
    pub = recover_public_key(eip191_digest(salt_message(doc, salt)), bytes.fromhex(sig[2:]))
    return address_of(pub) if pub else None


def salt_signer(doc: str, salt: Any, sig: Any) -> str | None:
    """The address whose EIP-191 signature `sig` is over this document's
    salt message, or None if `sig` is malformed or recovers nothing."""
    if not isinstance(salt, str) or not SALT_HEX.match(salt):
        return None
    if not isinstance(sig, str) or not SIG_HEX.match(sig):
        return None
    return _signer(doc.lower(), salt, sig.lower())


def sig_problem(doc: str, address: str, salt: Any, sig: Any) -> str | None:
    """Why `sig` is not `address`'s signature over the salt, or None."""
    if not isinstance(sig, str) or not SIG_HEX.match(sig):
        return "sig is missing or not 0x and 130 hex characters"
    signer = salt_signer(doc, salt, sig)
    if signer is None:
        return "sig recovers no key"
    if signer != address.lower():
        return f"sig recovers to {signer}"
    return None


CLIENT_ID_MASK = (1 << 53) - 1
SALT_HEX = re.compile(r"^[0-9a-f]{32}$")
ADDRESS_HEX = re.compile(r"^0x[0-9a-fA-F]{40}$")


def client_id_for(address: str, salt: str | bytes) -> int:
    """Section 5: the Yjs client id a writer must use.

    The first 8 bytes of keccak-256(20 address bytes || 16 salt bytes),
    big-endian, masked to 53 bits; 0 becomes 1.
    """
    if not isinstance(address, str) or not ADDRESS_HEX.match(address):
        raise ValueError(f"not an address: {address!r}")
    if isinstance(salt, str):
        if not SALT_HEX.match(salt):
            raise ValueError(f"salt must be 32 lowercase hex characters: {salt!r}")
        salt = bytes.fromhex(salt)
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != 16:
        raise ValueError("salt must be 16 bytes")
    cid = int.from_bytes(keccak256(qa._hex_bytes(address) + salt)[:8], "big") & CLIENT_ID_MASK
    return cid or 1


# ---------------------------------------------------------------- link


@dataclass
class Link:
    doc: str  # 0x + 64 hex
    secret: bytes
    owner: str  # 0x + 40 hex


def _b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def parse_link(link: str) -> Link:
    """Accept a full URL, a fragment, or the bare `/d/<doc>.<secret>.<owner>`."""
    m = re.search(r"/d/([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.(?:0x)?([0-9a-fA-F]{40})", link)
    if not m:
        raise ValueError("not a Quire link")
    doc, secret = _b64url(m.group(1)), _b64url(m.group(2))
    if len(doc) != 32 or len(secret) != 32:
        raise ValueError("doc id and link secret must be 32 bytes each")
    return Link("0x" + doc.hex(), secret, "0x" + m.group(3).lower())


@dataclass
class VersionLink:
    key: str  # entity key of the version head, 0x + 64 hex
    secret: bytes  # the version's own 32-byte key


def parse_version_link(link: str) -> VersionLink:
    """Accept a full URL, a fragment, or the bare `/v/<key>.<secret>` (section 1)."""
    m = re.search(r"/v/([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)", link)
    if not m:
        raise ValueError("not a Quire version link")
    key, secret = _b64url(m.group(1)), _b64url(m.group(2))
    if len(key) != 32 or len(secret) != 32:
        raise ValueError("version entity key and version key must be 32 bytes each")
    return VersionLink("0x" + key.hex(), secret)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def format_version_link(entity_key: str, secret: bytes) -> str:
    """The fragment form `#/v/<key>.<secret>`, for tests and tooling."""
    return f"#/v/{_b64url_encode(qa._hex_bytes(entity_key))}.{_b64url_encode(secret)}"


# ---------------------------------------------------------------- frames


@dataclass
class Frame:
    kind: str
    epoch: int
    header: dict[str, Any]
    data: bytes


def outer_epoch(e: Entity) -> int:
    p = e.payload
    if len(p) < 6 or p[:2] != b"\x51\x01":
        raise Rejected("bad outer header")
    return struct.unpack(">I", p[2:6])[0]


def parse_frame(e: Entity, plaintext: bytes, epoch: int, doc: str) -> Frame:
    """Check a decrypted frame against the entity (section 4)."""
    f = plaintext
    if len(f) < FRAME_FIXED or f[:3] != b"QF\x01":
        raise Rejected("bad frame magic")
    kind = chr(f[3])
    f_doc = "0x" + f[4:36].hex()
    f_epoch, hlen, dlen = struct.unpack(">III", f[36:48])
    if kind != e.kind or f_doc != doc.lower() or f_epoch != epoch:
        raise Rejected("frame kind/doc/epoch do not match the entity")
    if e.attr("qd") is None or str(e.attr("qd")).lower() != doc.lower():
        raise Rejected("qd does not match document")
    if FRAME_FIXED + hlen + dlen > len(f):
        raise Rejected("frame lengths exceed plaintext")
    try:
        header = json.loads(f[FRAME_FIXED : FRAME_FIXED + hlen].decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise Rejected("frame header is not JSON") from exc
    if not isinstance(header, dict):
        raise Rejected("frame header is not a JSON object")
    data = f[FRAME_FIXED + hlen : FRAME_FIXED + hlen + dlen]
    return Frame(kind, epoch, header, data)


def decrypt_frame(e: Entity, key: bytes, doc: str) -> Frame:
    """Decrypt a plain-envelope payload and check kind, doc id and epoch."""
    epoch = outer_epoch(e)
    try:
        plaintext = open_envelope(key, e.payload[6:])
    except (InvalidTag, ValueError) as exc:
        raise Rejected("does not decrypt") from exc
    return parse_frame(e, plaintext, epoch, doc)


def open_join(e: Entity, owner_key: ec.EllipticCurvePrivateKey, doc: str) -> Frame:
    """Open a join request sealed to the owner (sections 3, 4 and 7)."""
    epoch = outer_epoch(e)
    if epoch != 0:
        raise Rejected("join payload must use epoch 0")
    sealed = e.payload[6:]
    if len(sealed) < EPHEMERAL + 28:
        raise Rejected("join payload too short")
    try:
        plaintext = open_sealed(owner_key, sealed, "join")
    except (InvalidTag, ValueError) as exc:
        raise Rejected("join request does not open with this key") from exc
    return parse_frame(e, plaintext, epoch, doc)


# ---------------------------------------------------------------- Yjs


class _Cursor:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def u8(self) -> int:
        if self.pos >= len(self.data):
            raise Rejected("Yjs update ends early")
        self.pos += 1
        return self.data[self.pos - 1]

    def uint(self) -> int:
        n = shift = 0
        while True:
            b = self.u8()
            n |= (b & 0x7F) << shift
            shift += 7
            if b < 0x80:
                return n

    def skip_int(self) -> None:  # lib0 signed varint
        while self.u8() & 0x80:
            pass

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise Rejected("Yjs update ends early")
        self.pos += n
        return self.data[self.pos - n : self.pos]

    def string(self) -> str:
        return self.take(self.uint()).decode("utf-8")

    def skip_any(self) -> None:
        t = self.u8()
        if t in (127, 126, 121, 120):  # undefined, null, false, true
            return
        if t == 125:
            self.skip_int()
        elif t == 124:
            self.take(4)
        elif t in (123, 122):
            self.take(8)
        elif t == 119:
            self.string()
        elif t == 118:
            for _ in range(self.uint()):
                self.string()
                self.skip_any()
        elif t == 117:
            for _ in range(self.uint()):
                self.skip_any()
        elif t == 116:
            self.take(self.uint())
        else:
            raise Rejected(f"unknown lib0 any type {t}")


def _content_length(c: _Cursor, ref: int) -> int:
    """Skip one item's content (Yjs v1 encoding) and return its length."""
    if ref == 1:  # deleted
        return c.uint()
    if ref == 2:  # JSON
        n = c.uint()
        for _ in range(n):
            c.string()
        return n
    if ref == 3:  # binary
        c.take(c.uint())
        return 1
    if ref == 4:  # string; length counts UTF-16 code units
        return len(c.string().encode("utf-16-le")) // 2
    if ref == 5:  # embed
        c.string()
        return 1
    if ref == 6:  # format
        c.string()
        c.string()
        return 1
    if ref == 7:  # type
        type_ref = c.uint()
        if type_ref in (3, 5):  # XmlElement name, XmlHook key
            c.string()
        return 1
    if ref == 8:  # any
        n = c.uint()
        for _ in range(n):
            c.skip_any()
        return n
    if ref == 9:  # subdocument
        c.string()
        c.skip_any()
        return 1
    raise Rejected(f"unknown Yjs content ref {ref}")


def update_clients(update: bytes) -> dict[int, list[tuple[int, int]]]:
    """Client ids whose structs a Yjs v1 update carries, at any clock.

    Returns {client: [(start clock, end clock exclusive), ...]}. Every
    client with at least one struct is a key, as in Yjs `parseUpdateMeta`,
    which counts Skip structs too; a Skip adds no range, since it writes
    nothing. A state vector computed from the update is not enough: it only
    covers runs that start at clock 0, so an update continuing a client at
    clock 35 would show no client.
    """
    c = _Cursor(update)
    out: dict[int, list[tuple[int, int]]] = {}
    for _ in range(c.uint()):
        n_structs, client, clock = c.uint(), c.uint(), c.uint()
        for _ in range(n_structs):
            out.setdefault(client, [])
            info = c.u8()
            ref = info & 0x1F
            if ref == 10:  # skip
                clock += c.uint()
                continue
            if ref == 0:  # GC
                length = c.uint()
            else:
                if info & 0x80:  # origin
                    c.uint(), c.uint()
                if info & 0x40:  # right origin
                    c.uint(), c.uint()
                if not info & 0xC0:  # parent info is present
                    if c.uint() == 1:
                        c.string()
                    else:
                        c.uint(), c.uint()
                    if info & 0x20:
                        c.string()
                length = _content_length(c, ref)
            out[client].append((clock, clock + length))
            clock += length
    for _ in range(c.uint()):  # delete set
        c.uint()
        for _ in range(c.uint()):
            c.uint(), c.uint()
    if c.pos != len(update):
        raise Rejected("trailing bytes after Yjs update")
    return out


# ---------------------------------------------------------------- sources


class Source:
    """Where entities come from. Queries mirror section 5."""

    def acl(self, doc: str, owner: str) -> list[Entity]:
        raise NotImplementedError

    def by_kind(
        self, doc: str, kind: str, creators: list[str] | None, min_qs: int = 0
    ) -> list[Entity]:
        """Entities of one kind; `creators=None` means any creator."""
        raise NotImplementedError

    def entity(self, key: str) -> Entity | None:
        raise NotImplementedError


class VectorSource(Source):
    """Applies the section 5 query filters to a vectors file in memory."""

    def __init__(self, entities: list[Entity]) -> None:
        self.entities = entities

    def _match(self, e: Entity, doc: str, kind: str) -> bool:
        return (
            e.attr("qp") == "quire1"
            and str(e.attr("qd")).lower() == doc.lower()
            and e.kind == kind
        )

    def acl(self, doc: str, owner: str) -> list[Entity]:
        return [e for e in self.entities if self._match(e, doc, "a") and e.creator == owner]

    def by_kind(
        self, doc: str, kind: str, creators: list[str] | None, min_qs: int = 0
    ) -> list[Entity]:
        qs: Callable[[Entity], int] = lambda e: e.attr("qs") if isinstance(e.attr("qs"), int) else -1
        return [
            e
            for e in self.entities
            if self._match(e, doc, kind)
            and (creators is None or e.creator in creators)
            and qs(e) >= min_qs
        ]

    def entity(self, key: str) -> Entity | None:
        return next((e for e in self.entities if e.key == key.lower()), None)


class RpcSource(Source):
    """Live Arkiv node, raw query strings as listed in section 5."""

    def __init__(self, url: str) -> None:
        self.url = url

    @staticmethod
    def _base(doc: str, kind: str) -> str:
        return f"qp = str('quire1') AND qd = bytes32({doc.lower()}) AND qk = str('{kind}')"

    def _run(self, query: str) -> list[Entity]:
        return [qa.parse_entity(r) for r in qa.query_all(self.url, query)]

    def acl(self, doc: str, owner: str) -> list[Entity]:
        return self._run(self._base(doc, "a") + f" AND $creator = addr({owner})")

    def by_kind(
        self, doc: str, kind: str, creators: list[str] | None, min_qs: int = 0
    ) -> list[Entity]:
        query = self._base(doc, kind)
        if min_qs:
            query += f" AND qs >= u64({min_qs})"
        if creators is not None:
            if not creators:
                return []
            query += " AND (" + " OR ".join(f"$creator = addr({c})" for c in creators) + ")"
        return self._run(query)

    def entity(self, key: str) -> Entity | None:
        raw = qa.get_entity(self.url, key)
        return qa.parse_entity(raw) if raw else None


# ---------------------------------------------------------------- reader


@dataclass
class JoinRequest:
    key: str
    creator: str
    name: str
    public_key: str
    key_matches_creator: bool


@dataclass
class Author:
    """Who a Yjs client id belongs to (section 5).

    `proven` is True when an applied update by `address` used the id, which
    the reader checked against clientIdFor($creator, salt) and the salt
    signature. It is False for an entry taken from a snapshot's `authors`
    map: the address signed the salt and the salt derives the id, but the
    snapshot's content under it is the word of `via`, the snapshot's creator.
    """

    address: str
    salt: str
    proven: bool
    source: str  # "update <key>" or "snapshot <key>"
    via: str | None = None  # the snapshot's creator, for a claimed entry


@dataclass
class ReadResult:
    text: str
    acl: dict[str, Any]
    epoch: int
    epochs: list[int]  # epochs we hold a content key for
    members: list[dict[str, Any]] | None  # None when the roster is sealed to us
    revoked: list[dict[str, Any]] | None
    applied: list[str]
    ignored: list[tuple[str, str]]  # (entity key, reason)
    authors: dict[int, Author]  # Yjs client id -> who owns it
    newest_snapshot: str | None
    doc: Doc  # the assembled Yjs document
    kinds: dict[str, str] = field(default_factory=dict)  # entity key -> kind
    creators: dict[str, str] = field(default_factory=dict)  # entity key -> creator
    dropped_authors: list[str] = field(default_factory=list)  # snapshot `authors` entries that failed


def author_problem(cid_text: Any, entry: Any, doc: str) -> str | None:
    """Why a snapshot `authors` entry does not count, or None if it does.

    The key must be a canonical decimal client id and the value an object
    {address, salt, sig} whose clientIdFor equals that id and whose sig
    recovers to the address (section 5). `doc` is the document id the salt
    message names: the entity's `qd`.
    """
    text = str(cid_text)
    if not text.isdigit() or str(int(text)) != text:
        return "key is not a decimal client id"
    if not isinstance(entry, dict) or set(entry) != {"address", "salt", "sig"}:
        return "entry is not {address, salt, sig}"
    try:
        derived = client_id_for(str(entry["address"]), entry["salt"])
    except ValueError as exc:
        return str(exc)
    if derived != int(text):
        return f"clientIdFor(address, salt) is {derived}"
    return sig_problem(doc, str(entry["address"]), entry["salt"], entry["sig"])


def _block(value: Any) -> int:
    """Block heights in headers are decimal strings (section 4)."""
    return int(str(value), 10)


class Reader:
    def __init__(
        self,
        link: Link,
        source: Source,
        member_key: ec.EllipticCurvePrivateKey | None = None,
        log: Callable[[str], None] = lambda _m: None,
        schemas: Schemas | None = None,
    ) -> None:
        self.link = link
        self.source = source
        self.member_key = member_key
        self.log = log
        self.schemas = schemas if schemas is not None else Schemas()
        self.keys: dict[int, bytes] = {0: epoch0_key(link.secret)}
        self.unwrapped_index: int | None = None  # which entry of `wraps` opened
        self.applied: list[str] = []
        self.ignored: list[tuple[str, str]] = []
        self.kinds: dict[str, str] = {}
        self.creators: dict[str, str] = {}
        self.authors: dict[int, Author] = {}
        self.dropped_authors: list[str] = []
        self.acl_entity: Entity | None = None

    def _note(self, e: Entity) -> None:
        self.kinds[e.key] = e.kind
        self.creators[e.key] = e.creator

    def _ignore(self, e: Entity, reason: str) -> None:
        if any(k == e.key for k, _r in self.ignored):
            return
        self._note(e)
        self.ignored.append((e.key, reason))
        self.log(f"ignored {e.kind} {e.key} from {e.creator}: {reason}")

    def _content_frame(self, e: Entity) -> Frame:
        epoch = outer_epoch(e)
        key = self.keys.get(epoch)
        if key is None:
            raise Rejected(f"no content key for epoch {epoch}")
        return decrypt_frame(e, key, self.link.doc)

    # Steps 1 and 2: ACL, epoch key, roster.
    def load_acl(self) -> dict[str, Any]:
        mkey = meta_key(self.link.secret)
        for e in self.source.acl(self.link.doc, self.link.owner):
            if e.creator != self.link.owner:  # never trust another creator
                self._ignore(e, "ACL not created by the owner")
                continue
            try:
                header = decrypt_frame(e, mkey, self.link.doc).header
                self.schemas.check("acl", header)
            except Rejected as exc:
                self._ignore(e, str(exc))
                continue
            if str(header.get("owner", "")).lower() != self.link.owner:
                self._ignore(e, "ACL header owner differs from link owner")
                continue
            self._note(e)
            self.applied.append(e.key)
            self.acl_entity = e
            self._unwrap(header)
            return header
        raise RuntimeError("no valid ACL created by the link owner")

    def _unwrap(self, acl: dict[str, Any]) -> None:
        epoch = int(acl.get("epoch", 0))
        if epoch == 0 or self.member_key is None:
            return
        # Section 3: `wraps` is an unlabelled list in random order, so try
        # each entry until one opens with our key.
        wraps = acl.get("wraps") or []
        if not isinstance(wraps, list):
            raise RuntimeError("ACL wraps is not a list")
        for index, wrap in enumerate(wraps):
            try:
                key = unwrap_epoch_key(self.member_key, qa._hex_bytes(str(wrap)), epoch)
            except (InvalidTag, ValueError):
                continue
            if len(key) == 32:
                self.keys[epoch] = key
                self.unwrapped_index = index
                self.log(f"unwrapped epoch {epoch} key from wrap {index + 1} of {len(wraps)}")
                return
        self.log(f"member key opens none of the {len(wraps)} wraps for epoch {epoch}")

    def roster(self, acl: dict[str, Any]) -> dict[str, Any] | None:
        """{doc, epoch, members, revoked}, or None if sealed under a key we lack.

        For epoch 0 the members sit in the ACL header itself; `doc` and
        `epoch` are filled in from the entity so callers see one shape.
        """
        epoch = int(acl.get("epoch", 0))
        if epoch == 0:
            return {
                "doc": self.link.doc, "epoch": 0,
                "members": acl.get("members") or [], "revoked": acl.get("revoked") or [],
            }
        key = self.keys.get(epoch)
        if key is None or not acl.get("roster"):
            return None
        try:
            plain = open_envelope(key, qa._hex_bytes(acl["roster"]))
            roster = json.loads(plain.decode("utf-8"))
        except (InvalidTag, ValueError) as exc:
            raise RuntimeError(f"ACL roster does not open with the epoch {epoch} key") from exc
        if not isinstance(roster, dict):
            raise RuntimeError("ACL roster is not a JSON object")
        try:
            self.schemas.check("roster", roster)
        except Rejected as exc:
            raise RuntimeError(str(exc)) from exc
        # Section 3: the roster is bound to its document and epoch, so one
        # cannot be replayed into another document or an older epoch.
        if str(roster.get("doc", "")).lower() != self.link.doc.lower():
            raise RuntimeError(f"ACL roster names document {roster.get('doc')!r}, not {self.link.doc}")
        if roster.get("epoch") != epoch or isinstance(roster.get("epoch"), bool):
            raise RuntimeError(f"ACL roster names epoch {roster.get('epoch')!r}, ACL header says {epoch}")
        return roster

    # Step 3: snapshots and their chunks.
    def _snapshot_data(self, head: Entity, frame: Frame) -> bytes:
        return assemble(head, frame, self.source, self._content_frame, self.schemas, self._note)

    def _too_old(self, e: Entity, frame: Frame, current_epoch: int, last_revocation: int | None) -> str | None:
        """Section 5: an old-epoch update or snapshot written after the
        latest revocation could have been read by the removed member."""
        if frame.epoch < current_epoch and last_revocation is not None and e.created_at > last_revocation:
            what = "update" if e.kind == "u" else "snapshot"
            return (
                f"epoch {frame.epoch} {what} created at block {e.created_at},"
                f" after the revocation at block {last_revocation}"
            )
        return None

    def load_snapshots(
        self, members: list[str], current_epoch: int = 0, last_revocation: int | None = None
    ) -> tuple[list[tuple[Entity, bytes, Frame]], Entity | None, int | None]:
        decoded: list[tuple[Entity, Frame]] = []
        for e in self.source.by_kind(self.link.doc, "s", members):
            if e.creator not in members:
                self._ignore(e, "creator not in ACL")
                continue
            try:
                frame = self._content_frame(e)
                self.schemas.check("snapshot", frame.header)
                _block(frame.header["base"])
            except (Rejected, KeyError, ValueError) as exc:
                self._ignore(e, f"snapshot header: {exc}")
                continue
            reason = self._too_old(e, frame, current_epoch, last_revocation)
            if reason:
                self._ignore(e, reason)
                continue
            decoded.append((e, frame))
        # Arkiv does not promise an order: newest qs first, ties by block
        # and then key so the choice is deterministic.
        decoded.sort(key=lambda ef: (int(ef[0].attr("qs") or 0), ef[0].created_at, ef[0].key), reverse=True)
        newest: tuple[Entity, Frame, bytes] | None = None
        for e, f in decoded:
            try:
                newest = (e, f, self._snapshot_data(e, f))
                break
            except Rejected as exc:
                self._ignore(e, str(exc))
        if newest is None:
            return [], None, None
        head, head_frame, head_data = newest
        newest_base = _block(head_frame.header["base"])
        out: list[tuple[Entity, bytes, Frame]] = [(head, head_data, head_frame)]
        for e, f in decoded:
            if e is head or any(k == e.key for k, _r in self.ignored):
                continue
            if abs(_block(f.header["base"]) - newest_base) > SNAPSHOT_WINDOW:
                self._ignore(e, "base not within 60 blocks of the newest snapshot")
                continue
            try:
                out.append((e, self._snapshot_data(e, f), f))
            except Rejected as exc:
                self._ignore(e, str(exc))
        return out, head, newest_base

    def snapshot_authors(self, snapshots: list[tuple[Entity, bytes, Frame]]) -> None:
        """Section 5: a snapshot's `authors` entry counts only if
        clientIdFor(address, salt) equals its client id and `sig` recovers
        to `address`. A valid entry says who owns the id; the content under
        it is the snapshot creator's word, so it is shown as claimed, via
        that creator. A valid entry also attributes the id, so a later
        update by another address under it is ignored (load_updates).
        Entries that fail are dropped and listed for the trust report.
        Newest snapshot first, so where two entries agree the newest one is
        named as the source; one naming a different address for an id
        already attributed is dropped."""
        for e, _data, frame in snapshots:
            authors = frame.header.get("authors") or {}
            if not isinstance(authors, dict):
                self.dropped_authors.append(f"snapshot {e.key}: authors is not an object")
                continue
            for cid_text, entry in authors.items():
                problem = author_problem(cid_text, entry, self.link.doc)
                cid = int(cid_text) if problem is None else 0
                held = self.authors.get(cid)
                if problem is None and held is not None and held.address != str(entry["address"]).lower():
                    problem = f"already attributed to {held.address} by {held.source}"
                if problem:
                    self.dropped_authors.append(f"snapshot {e.key}: client id {cid_text}: {problem}")
                    continue
                if held is None:
                    self.authors[cid] = Author(
                        str(entry["address"]).lower(), entry["salt"], False, f"snapshot {e.key}", e.creator
                    )

    # Step 4: updates, with the section 5 rules on epochs and client ids.
    def load_updates(
        self, members: list[str], newest_base: int | None, current_epoch: int, last_revocation: int | None
    ) -> list[tuple[Entity, bytes]]:
        min_qs = max(0, newest_base - SNAPSHOT_WINDOW) if newest_base is not None else 0
        accepted: list[tuple[Entity, bytes, str, list[int]]] = []
        for e in self.source.by_kind(self.link.doc, "u", members, min_qs):
            if e.creator not in members:
                self._ignore(e, "creator not in ACL")
                continue
            try:
                frame = self._content_frame(e)
                self.schemas.check("update", frame.header)
                clients = update_clients(frame.data)
            except Rejected as exc:
                self._ignore(e, str(exc))
                continue
            reason = self._too_old(e, frame, current_epoch, last_revocation)
            if reason:
                self._ignore(e, reason)
                continue
            salt = frame.header.get("salt")
            try:
                own = client_id_for(e.creator, salt)  # type: ignore[arg-type]
            except ValueError as exc:
                self._ignore(e, f"update salt: {exc}")
                continue
            # The salt must be signed by the creator (EIP-191, section 5).
            problem = sig_problem(self.link.doc, e.creator, salt, frame.header.get("sig"))
            if problem:
                self._ignore(e, f"update {problem}, not to its creator")
                continue
            # Every client id with structs must be the creator's own. The
            # check needs no reader state, so query order does not matter.
            foreign = sorted(cid for cid in clients if cid != own)
            if foreign:
                ids = ", ".join(str(cid) for cid in foreign)
                self._ignore(e, f"Yjs client id {ids} is not clientIdFor(creator, salt) = {own}")
                continue
            accepted.append((e, frame.data, str(salt), sorted(clients)))
        # Section 5: an update whose client id is already attributed to a
        # different address, by an earlier update or a valid snapshot
        # `authors` entry, is ignored. The snapshot entries are already in
        # self.authors. "Earlier" is taken as createdAt, then entity key, so
        # the outcome does not depend on query order. Only updates that pass
        # every other check attribute an id.
        accepted.sort(key=lambda u: (u[0].created_at, u[0].key))
        kept: list[tuple[Entity, bytes]] = []
        for e, data, salt, cids in accepted:
            taken = [(cid, self.authors[cid]) for cid in cids
                     if cid in self.authors and self.authors[cid].address != e.creator]
            if taken:
                cid, held = taken[0]
                self._ignore(e, f"Yjs client id {cid} is already attributed to {held.address} by {held.source}")
                continue
            for cid in cids:
                held = self.authors.get(cid)
                if held is None or not held.proven:
                    self.authors[cid] = Author(e.creator, salt, True, f"update {e.key}")
            kept.append((e, data))
        return kept

    def join_requests(self, acl: dict[str, Any]) -> list[JoinRequest]:
        """Open join requests; only works when member_key is the owner's."""
        if self.member_key is None:
            return []
        out: list[JoinRequest] = []
        for e in self.source.by_kind(self.link.doc, "j", None):
            try:
                frame = open_join(e, self.member_key, self.link.doc)
                self.schemas.check("join", frame.header)
            except Rejected as exc:
                self.log(f"join request {e.key}: {exc}")
                continue
            pub = str(frame.header.get("publicKey", ""))
            try:
                matches = address_of(pub) == e.creator
            except ValueError:
                matches = False
            out.append(JoinRequest(e.key, e.creator, str(frame.header.get("name", "")), pub, matches))
        return out

    def read(self) -> ReadResult:
        acl = self.load_acl()
        epoch = int(acl.get("epoch", 0))
        roster = self.roster(acl)
        doc = Doc()
        if roster is None:
            self.log(f"roster of epoch {epoch} is sealed; without a member key nothing is readable")
            return ReadResult(
                "", acl, epoch, sorted(self.keys), None, None, self.applied, self.ignored,
                self.authors, None, doc, self.kinds, self.creators,
            )
        members = sorted({str(m["address"]).lower() for m in roster.get("members", [])})
        revoked = roster.get("revoked") or []
        last_revocation = max((_block(r["atBlock"]) for r in revoked), default=None)

        snapshots, newest, newest_base = self.load_snapshots(members, epoch, last_revocation)
        self.snapshot_authors(snapshots)
        updates = self.load_updates(members, newest_base, epoch, last_revocation)

        # Report entities the member filter excluded (e.g. forged writes).
        if isinstance(self.source, VectorSource):
            for e in self.source.entities:
                if e.kind in ("u", "s") and e.creator not in members:
                    self._ignore(e, "creator not in ACL")

        for e, data in [(s[0], s[1]) for s in snapshots] + updates:
            doc.apply_update(data)
            self._note(e)
            self.applied.append(e.key)
        text = fragment_text(doc.get("default", type=XmlFragment))
        return ReadResult(
            text, acl, epoch, sorted(self.keys), roster.get("members", []), revoked,
            self.applied, self.ignored, self.authors, newest.key if newest else None,
            doc, self.kinds, self.creators, self.dropped_authors,
        )


def assemble(
    head: Entity,
    frame: Frame,
    source: Source,
    open_frame: Callable[[Entity], Frame],
    schemas: Schemas,
    note: Callable[[Entity], None] = lambda _e: None,
) -> bytes:
    """Join a snapshot or version head with its chunks (sections 1, 4, 5).

    Each chunk must have the head's creator, the head's outer epoch, the
    head's creation flags, `i` equal to its 1-based position and `of` equal
    to the head's `id`. The data must add up to the head's `size`.
    """
    parts = [frame.data]
    chunks = frame.header.get("chunks") or []
    head_id = str(frame.header.get("id", "")).lower()
    for i, ckey in enumerate(chunks, start=1):
        chunk = source.entity(ckey)
        if chunk is None:
            raise Rejected(f"chunk {ckey} missing")
        if chunk.creator != head.creator or chunk.kind != "c":
            raise Rejected(f"chunk {ckey} has wrong creator or kind")
        if outer_epoch(chunk) != frame.epoch:
            raise Rejected(f"chunk {ckey} epoch {outer_epoch(chunk)} differs from its head's {frame.epoch}")
        if (chunk.readonly, chunk.permissionless_extension) != (head.readonly, head.permissionless_extension):
            raise Rejected(
                f"chunk {ckey} flags ({qa.flags_text(chunk)}) differ from its head's ({qa.flags_text(head)})"
            )
        cf = open_frame(chunk)
        schemas.check("chunk", cf.header)
        if cf.header.get("i") != i or str(cf.header.get("of", "")).lower() != head_id:
            raise Rejected(f"chunk {ckey} header does not match i/of")
        note(chunk)
        parts.append(cf.data)
    data = b"".join(parts)
    size = frame.header.get("size")
    if size is not None and int(size) != len(data):
        raise Rejected(f"snapshot size {len(data)} != header size {size}")
    return data


# ---------------------------------------------------------------- versions


@dataclass
class VersionResult:
    text: str
    head: Entity
    header: dict[str, Any]
    epoch: int  # outer epoch of the head; chunks must match it
    chunks: list[str]
    doc: Doc


def read_version(link: VersionLink, source: Source, schemas: Schemas | None = None) -> VersionResult:
    """Read a published version from its own link (sections 1, 3 and 4).

    The version key is used directly. The link carries no document id, so
    the frame is checked against the entity's own `qd`. The link also
    carries no link secret, so this reader cannot open the ACL and cannot
    tell whether the version's creator is, or was, a member: that is
    reported, not checked.
    """
    schemas = schemas if schemas is not None else Schemas()
    head = source.entity(link.key)
    if head is None:
        raise RuntimeError(f"version {link.key} not found")
    if head.kind != "v":
        raise RuntimeError(f"entity {link.key} is kind {head.kind!r}, not a version")
    doc_id = head.attr("qd")
    if not isinstance(doc_id, str) or not qa.HEX32.match(doc_id):
        raise RuntimeError("version has no bytes32 qd")
    doc_id = doc_id.lower()

    def open_frame(e: Entity) -> Frame:
        return decrypt_frame(e, link.secret, doc_id)

    try:
        # Section 5: a version uses epoch 0 in its outer header and frames,
        # and its chunks use the version key and, like any chunk, the
        # head's epoch (checked in assemble).
        if outer_epoch(head) != 0:
            raise Rejected(f"version outer epoch is {outer_epoch(head)}, must be 0")
        frame = open_frame(head)
        schemas.check("snapshot", frame.header)
        data = assemble(head, frame, source, open_frame, schemas)
    except Rejected as exc:
        raise RuntimeError(f"version {link.key}: {exc}") from exc
    doc = Doc()
    doc.apply_update(data)
    return VersionResult(
        fragment_text(doc.get("default", type=XmlFragment)), head, frame.header, frame.epoch,
        list(frame.header.get("chunks") or []), doc,
    )


def version_report(result: VersionResult) -> str:
    head, header = result.head, result.header
    lines = ["Quire version report", ""]
    lines.append(f"version      {head.key}")
    lines.append(f"document     {str(head.attr('qd')).lower()}")
    lines.append(f"creator      {head.creator} (membership not checkable without the document link)")
    lines.append(f"flags        {qa.flags_text(head)}  expected readonly, permissionless extension:"
                 f" {_yes(not qa.check_flags(head))}")
    lines.append(f"blocks       created {head.created_at}, expires {head.expires_at}")
    lines.append(f"epoch        {result.epoch} (must be 0; the version key is used directly for head and chunks)")
    lines.append(f"id           {header.get('id')}  base {header.get('base')}  size {header.get('size')}")
    lines.append(f"chunks       {len(result.chunks)} (creator, epoch, flags, i and of checked)")
    authors = header.get("authors") or {}
    if not isinstance(authors, dict):
        authors = {}
    doc_id = str(head.attr("qd")).lower()
    good = {k: v for k, v in authors.items() if author_problem(k, v, doc_id) is None}
    lines.append(
        f"authors      {len(good)} claimed by the version's creator, {len(authors) - len(good)} dropped"
        " (an entry counts only if clientIdFor(address, salt) is its client id"
        " and sig recovers to address)"
    )
    for cid, entry in sorted(authors.items(), key=lambda kv: (len(str(kv[0])), str(kv[0]))):
        problem = author_problem(cid, entry, doc_id)
        who = entry.get("address") if isinstance(entry, dict) else entry
        lines.append(
            f"  {cid:<17} {who}  "
            + (f"claimed via {head.creator}" if problem is None else f"dropped: {problem}")
        )
    return "\n".join(lines)


# ---------------------------------------------------------------- text


def node_text(node: XmlFragment | XmlElement | XmlText) -> str:
    """Concatenate all text below a node, in document order."""
    if isinstance(node, XmlText):
        return str(node.to_py())
    return "".join(node_text(child) for child in node.children)


def fragment_text(fragment: XmlFragment) -> str:
    """One line per top-level element (paragraph) of the fragment."""
    return "\n".join(node_text(child) for child in fragment.children)


# ---------------------------------------------------------------- verify


def _yes(ok: bool) -> str:
    return "yes" if ok else "NO"


def trust_report(reader: Reader, result: ReadResult) -> str:
    """Plain text summary of what was checked and what was set aside."""
    acl = result.acl
    lines = ["Quire trust report", ""]
    lines.append(f"document     {reader.link.doc}")
    lines.append(f"owner        {reader.link.owner} (ACL creator checked against the link)")
    owner_pub = str(acl.get("ownerPublicKey", ""))
    try:
        owner_ok = address_of(owner_pub) == reader.link.owner
    except ValueError:
        owner_ok = False
    lines.append(f"owner key    {owner_pub[:20]}... hashes to owner: {_yes(owner_ok)}")
    keep = acl.get("keepUntil")
    lines.append(f"keepUntil    {'none' if keep is None else 'block ' + str(keep)}")
    wraps = acl.get("wraps") or []
    if reader.unwrapped_index is not None:
        held = f"unwrapped from wrap {reader.unwrapped_index + 1} of {len(wraps)}"
    else:
        held = "derived from the link" if result.epoch == 0 else "not held"
    lines.append(f"epoch        {result.epoch} (content key {held})")
    lines.append(f"wraps        {len(wraps)} (unlabelled; the count is all a link holder learns)")
    if reader.acl_entity is not None:
        ae = reader.acl_entity
        lines.append(f"acl flags    {qa.flags_text(ae)}  expected permissionless extension only:"
                     f" {_yes(not qa.check_flags(ae))}")
    lines.append(f"schemas      {reader.schemas.status}")
    lines.append("")

    if result.members is None:
        lines.append("members      not visible: the roster is sealed under the epoch key")
        lines.append("             and no member key unwrapped it, so no content was read")
    else:
        lines.append(f"members      {len(result.members)}")
        for m in result.members:
            try:
                ok = address_of(str(m.get("publicKey", ""))) == str(m.get("address", "")).lower()
            except ValueError:
                ok = False
            lines.append(
                f"  {m.get('address')}  {m.get('name')!r:<12} {m.get('role'):<7}"
                f" added at {m.get('addedAtBlock')}  key hashes to address: {_yes(ok)}"
            )
        if result.epoch > 0:  # a mismatch would have stopped the read
            lines.append(f"roster       sealed; its doc and epoch match the ACL: yes")
        lines.append(f"revoked      {len(result.revoked or [])}")
        for r in result.revoked or []:
            lines.append(f"  {r.get('address')}  at block {r.get('atBlock')}")
        if result.newest_snapshot:
            lines.append(f"newest snapshot {result.newest_snapshot}")
    lines.append("")

    applied = Counter(qa.KIND_NAMES.get(result.kinds.get(k, "?"), "?") for k in result.applied)
    lines.append(
        f"applied      {len(result.applied)}"
        + (" (" + ", ".join(f"{k} {n}" for k, n in sorted(applied.items())) + ")" if applied else "")
    )
    by_reason: dict[str, list[str]] = defaultdict(list)
    for key, reason in result.ignored:
        by_reason[reason].append(key)
    lines.append(f"ignored      {len(result.ignored)}")
    for reason in sorted(by_reason):
        keys = by_reason[reason]
        lines.append(f"  {len(keys)} x {reason}")
        for k in keys:
            kind = qa.KIND_NAMES.get(result.kinds.get(k, "?"), "?")
            lines.append(f"      {kind} {k} from {result.creators.get(k, '?')}")

    if result.authors or result.dropped_authors:
        lines.append("")
        lines.append("client ids   (each is clientIdFor(address, salt) with the salt signed by the address;")
        lines.append("              proven by an applied update from that address, or claimed by a")
        lines.append("              snapshot's authors map, via that snapshot's creator)")
        names = {str(m["address"]).lower(): m.get("name") for m in result.members or []}
        gone = {str(r.get("address", "")).lower() for r in result.revoked or []}
        for cid, a in sorted(result.authors.items()):
            how = "proven " if a.proven else "claimed"
            src = a.source[: a.source.find(" ") + 11] + "..."
            if not a.proven:
                src = f"via {a.via} ({src})"
            label = names.get(a.address) or ("revoked" if a.address in gone else "no member")
            lines.append(f"  {cid:<17} {a.address} {label:<8} {how} {src}")
        for dropped in result.dropped_authors:
            lines.append(f"  dropped: {dropped}")

    joins = reader.join_requests(acl) if reader.member_key is not None else []
    if reader.member_key is not None and public_key_hex(reader.member_key).lower() == owner_pub.lower():
        lines.append("")
        lines.append(f"join requests {len(joins)} (opened with the owner key)")
        for j in joins:
            lines.append(
                f"  {j.key} from {j.creator}  name {j.name!r}"
                f"  key hashes to creator: {_yes(j.key_matches_creator)}"
            )
    return "\n".join(lines)


# ---------------------------------------------------------------- CLI


def load_private_key(hex_key: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int(hex_key, 16), ec.SECP256K1())


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--vectors", help="vectors JSON file to read entities from instead of --rpc")
    which = ap.add_mutually_exclusive_group()
    which.add_argument("--link", help="Quire document link (default with --vectors: the file's link)")
    which.add_argument("--version-link", help="Quire version link, #/v/<key>.<version key>")
    ap.add_argument("--rpc", default=qa.DEFAULT_RPC, help="Arkiv JSON-RPC URL")
    ap.add_argument("--member-key", help="member private key, 0x + 64 hex")
    ap.add_argument("--verify", action="store_true", help="print a trust report instead of the text")
    ap.add_argument("--no-schema", action="store_true", help="skip JSON Schema checks")
    ap.add_argument("-v", "--verbose", action="store_true", help="log to stderr")
    args = ap.parse_args(list(argv) if argv is not None else None)

    if not args.vectors and not (args.link or args.version_link):
        ap.error("give --vectors, --link or --version-link")
    log = (lambda m: print(m, file=sys.stderr)) if args.verbose else (lambda _m: None)
    try:
        if args.vectors:
            data, entities = qa.load_vectors(args.vectors)
            source: Source = VectorSource(entities)
        else:
            data, source = {}, RpcSource(args.rpc)
        schemas = Schemas(enabled=not args.no_schema)
        if args.version_link:
            vresult = read_version(parse_version_link(args.version_link), source, schemas)
            if args.verify:
                print(version_report(vresult))
            elif vresult.text:
                print(vresult.text)
            return 0
        link = parse_link(args.link or data.get("link") or "")
        key = load_private_key(args.member_key) if args.member_key else None
        reader = Reader(link, source, key, log, schemas)
        result = reader.read()
        if args.verify:
            print(trust_report(reader, result))
            return 0
    except (OSError, ValueError, KeyError, RuntimeError, qa.RpcError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    log(f"epoch keys: {result.epochs}; applied {len(result.applied)} entities")
    if result.text:
        print(result.text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
