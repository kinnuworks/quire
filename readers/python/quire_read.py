#!/usr/bin/env python3
"""Read a Quire v1 document and print its text.

Follows PROTOCOL.md sections 3 to 5. Needs `cryptography` and `pycrdt`
(see requirements.txt). Entities come from a vectors file (--vectors) or a
live Arkiv node (--link with --rpc).
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import struct
import sys
from dataclasses import dataclass
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


class Rejected(Exception):
    """An entity that a reader MUST discard."""


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


def unwrap_epoch_key(private_key: ec.EllipticCurvePrivateKey, wrap: bytes, epoch: int) -> bytes:
    """Unwrap `ephemeral pub (65) || envelope` with ECDH + HKDF wrap/<n>.

    The input key material is the 32-byte x-coordinate of the ECDH point,
    which is exactly what `cryptography` returns (PROTOCOL.md section 3).
    """
    eph = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), wrap[:65])
    shared_x = private_key.exchange(ec.ECDH(), eph)
    return open_envelope(hkdf(shared_x, f"wrap/{epoch}"), wrap[65:])


def public_key_hex(private_key: ec.EllipticCurvePrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return "0x" + raw.hex()


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


def decrypt_frame(e: Entity, key: bytes, doc: str) -> Frame:
    """Decrypt a payload and check kind, doc id and epoch (section 4)."""
    epoch = outer_epoch(e)
    try:
        f = open_envelope(key, e.payload[6:])
    except InvalidTag as exc:
        raise Rejected("does not decrypt") from exc
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
    header = json.loads(f[FRAME_FIXED : FRAME_FIXED + hlen].decode("utf-8"))
    if not isinstance(header, dict):
        raise Rejected("frame header is not a JSON object")
    data = f[FRAME_FIXED + hlen : FRAME_FIXED + hlen + dlen]
    return Frame(kind, epoch, header, data)


# ---------------------------------------------------------------- sources


class Source:
    """Where entities come from. Queries mirror section 5."""

    def acl(self, doc: str, owner: str) -> list[Entity]:
        raise NotImplementedError

    def by_kind(self, doc: str, kind: str, creators: list[str], min_qs: int = 0) -> list[Entity]:
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

    def by_kind(self, doc: str, kind: str, creators: list[str], min_qs: int = 0) -> list[Entity]:
        qs: Callable[[Entity], int] = lambda e: e.attr("qs") if isinstance(e.attr("qs"), int) else -1
        return [
            e
            for e in self.entities
            if self._match(e, doc, kind) and e.creator in creators and qs(e) >= min_qs
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

    def by_kind(self, doc: str, kind: str, creators: list[str], min_qs: int = 0) -> list[Entity]:
        if not creators:
            return []
        who = " OR ".join(f"$creator = addr({c})" for c in creators)
        return self._run(self._base(doc, kind) + f" AND qs >= u64({min_qs}) AND ({who})")

    def entity(self, key: str) -> Entity | None:
        raw = qa.get_entity(self.url, key)
        return qa.parse_entity(raw) if raw else None


# ---------------------------------------------------------------- reader


@dataclass
class ReadResult:
    text: str
    acl: dict[str, Any]
    epochs: list[int]
    applied: list[str]
    ignored: list[tuple[str, str]]  # (entity key, reason)
    doc: Doc  # the assembled Yjs document


class Reader:
    def __init__(
        self,
        link: Link,
        source: Source,
        member_key: ec.EllipticCurvePrivateKey | None = None,
        log: Callable[[str], None] = lambda _m: None,
    ) -> None:
        self.link = link
        self.source = source
        self.member_key = member_key
        self.log = log
        self.keys: dict[int, bytes] = {0: epoch0_key(link.secret)}
        self.applied: list[str] = []
        self.ignored: list[tuple[str, str]] = []

    def _ignore(self, e: Entity, reason: str) -> None:
        self.ignored.append((e.key, reason))
        self.log(f"ignored {e.kind} {e.key} from {e.creator}: {reason}")

    def _content_frame(self, e: Entity) -> Frame:
        epoch = outer_epoch(e)
        key = self.keys.get(epoch)
        if key is None:
            raise Rejected(f"no content key for epoch {epoch}")
        return decrypt_frame(e, key, self.link.doc)

    # Step 1 and 2: ACL and epoch key.
    def load_acl(self) -> dict[str, Any]:
        mkey = meta_key(self.link.secret)
        for e in self.source.acl(self.link.doc, self.link.owner):
            if e.creator != self.link.owner:  # never trust another creator
                self._ignore(e, "ACL not created by the owner")
                continue
            try:
                header = decrypt_frame(e, mkey, self.link.doc).header
            except Rejected as exc:
                self._ignore(e, str(exc))
                continue
            if str(header.get("owner", "")).lower() != self.link.owner:
                self._ignore(e, "ACL header owner differs from link owner")
                continue
            self._unwrap(header)
            return header
        raise RuntimeError("no valid ACL created by the link owner")

    def _unwrap(self, acl: dict[str, Any]) -> None:
        epoch = int(acl.get("epoch", 0))
        if epoch == 0 or self.member_key is None:
            return
        wraps = {k.lower(): v for k, v in (acl.get("wraps") or {}).items()}
        mine = public_key_hex(self.member_key).lower()
        # Find our wrap by matching our public key against the member list,
        # then fall back to trying every wrap.
        candidates = [
            str(m["address"]).lower()
            for m in acl.get("members", [])
            if str(m.get("publicKey", "")).lower() == mine
        ] or list(wraps)
        for address in candidates:
            if address not in wraps:
                continue
            try:
                key = unwrap_epoch_key(self.member_key, qa._hex_bytes(wraps[address]), epoch)
            except (InvalidTag, ValueError):
                continue
            if len(key) == 32:
                self.keys[epoch] = key
                self.log(f"unwrapped epoch {epoch} key as {address}")
                return
        self.log(f"member key does not unwrap epoch {epoch}")

    # Step 3: snapshots and their chunks.
    def _snapshot_data(self, head: Entity, frame: Frame) -> bytes:
        parts = [frame.data]
        chunks = frame.header.get("chunks") or []
        for i, ckey in enumerate(chunks, start=1):
            chunk = self.source.entity(ckey)
            if chunk is None:
                raise Rejected(f"chunk {ckey} missing")
            if chunk.creator != head.creator or chunk.kind != "c":
                raise Rejected(f"chunk {ckey} has wrong creator or kind")
            cf = self._content_frame(chunk)
            if int(cf.header.get("i", -1)) != i or str(cf.header.get("of", "")).lower() != head.key:
                raise Rejected(f"chunk {ckey} header does not match i/of")
            parts.append(cf.data)
        data = b"".join(parts)
        size = frame.header.get("size")
        if size is not None and int(size) != len(data):
            raise Rejected(f"snapshot size {len(data)} != header size {size}")
        return data

    def load_snapshots(self, members: list[str]) -> tuple[list[tuple[Entity, bytes]], int | None]:
        decoded: list[tuple[Entity, Frame]] = []
        for e in self.source.by_kind(self.link.doc, "s", members):
            if e.creator not in members:
                self._ignore(e, "creator not in ACL")
                continue
            try:
                decoded.append((e, self._content_frame(e)))
            except Rejected as exc:
                self._ignore(e, str(exc))
        if not decoded:
            return [], None
        newest = max(int(f.header["base"]) for _e, f in decoded)
        out: list[tuple[Entity, bytes]] = []
        for e, f in decoded:
            if int(f.header["base"]) < newest - SNAPSHOT_WINDOW:
                self._ignore(e, "older than the newest snapshot window")
                continue
            try:
                out.append((e, self._snapshot_data(e, f)))
            except Rejected as exc:
                self._ignore(e, str(exc))
        return out, newest

    # Step 4: updates.
    def load_updates(self, members: list[str], newest_base: int | None) -> list[tuple[Entity, bytes]]:
        min_qs = max(0, newest_base - SNAPSHOT_WINDOW) if newest_base is not None else 0
        out: list[tuple[Entity, bytes]] = []
        for e in self.source.by_kind(self.link.doc, "u", members, min_qs):
            if e.creator not in members:
                self._ignore(e, "creator not in ACL")
                continue
            try:
                out.append((e, self._content_frame(e).data))
            except Rejected as exc:
                self._ignore(e, str(exc))
        return out

    def read(self) -> ReadResult:
        acl = self.load_acl()
        members = sorted({str(m["address"]).lower() for m in acl.get("members", [])})
        snapshots, newest = self.load_snapshots(members)
        updates = self.load_updates(members, newest)

        # Report entities the member filter excluded (e.g. forged writes).
        if isinstance(self.source, VectorSource):
            for e in self.source.entities:
                if e.kind in ("u", "s") and e.creator not in members:
                    self._ignore(e, "creator not in ACL")

        doc = Doc()
        for e, data in snapshots + updates:
            doc.apply_update(data)
            self.applied.append(e.key)
        text = fragment_text(doc.get("default", type=XmlFragment))
        return ReadResult(text, acl, sorted(self.keys), self.applied, self.ignored, doc)


# ---------------------------------------------------------------- text


def node_text(node: XmlFragment | XmlElement | XmlText) -> str:
    """Concatenate all text below a node, in document order."""
    if isinstance(node, XmlText):
        return str(node.to_py())
    return "".join(node_text(child) for child in node.children)


def fragment_text(fragment: XmlFragment) -> str:
    """One line per top-level element (paragraph) of the fragment."""
    return "\n".join(node_text(child) for child in fragment.children)


# ---------------------------------------------------------------- CLI


def load_private_key(hex_key: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int(hex_key, 16), ec.SECP256K1())


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--vectors", help="document vectors JSON file")
    src.add_argument("--link", help="Quire document link")
    ap.add_argument("--rpc", default=qa.DEFAULT_RPC, help="Arkiv JSON-RPC URL")
    ap.add_argument("--member-key", help="member private key, 0x + 64 hex")
    ap.add_argument("-v", "--verbose", action="store_true", help="log to stderr")
    args = ap.parse_args(list(argv) if argv is not None else None)

    log = (lambda m: print(m, file=sys.stderr)) if args.verbose else (lambda _m: None)
    try:
        if args.vectors:
            data, entities = qa.load_vectors(args.vectors)
            link = parse_link(data["link"])
            source: Source = VectorSource(entities)
        else:
            link = parse_link(args.link)
            source = RpcSource(args.rpc)
        key = load_private_key(args.member_key) if args.member_key else None
        result = Reader(link, source, key, log).read()
    except (OSError, ValueError, KeyError, RuntimeError, qa.RpcError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    log(f"epoch keys: {result.epochs}; applied {len(result.applied)} entities")
    print(result.text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
