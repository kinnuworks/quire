#!/usr/bin/env python3
"""Privacy audit of what the public chain exposes for a Quire v1 document.

Standard library only. Works on a conformance vectors file (--vectors) or
against a live Arkiv node (--doc, --rpc). See PROTOCOL.md sections 2, 4 and 8.

Exit status: 0 when every check passes, 1 when any check fails, 2 on usage
or network errors.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

DEFAULT_RPC = "https://rpc.tiramisu.db-chain.testnet.arkiv.network"
BLOCK_SECONDS = 2
OUTER_HEADER = 6  # 'Q' | 0x01 | epoch u32
ENVELOPE_OVERHEAD = 12 + 16  # AES-GCM iv + tag
PADDING_BUCKETS = (256, 1024, 4096, 16384, 65536, 98304)
ATTRIBUTE_TYPES = {"qp": "str", "qd": "bytes32", "qk": "str", "qs": "u64"}
KIND_NAMES = {
    "a": "acl",
    "u": "update",
    "s": "snapshot",
    "c": "chunk",
    "j": "join",
    "v": "version",
}
ASCII_RUN = re.compile(rb"[\x20-\x7e]{12,}")
HEX32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
SELECT_ALL = {
    k: True
    for k in (
        "key",
        "owner",
        "creator",
        "createdAt",
        "expiresAt",
        "creationFlags",
        "payload",
        "attributes",
    )
}


@dataclass
class Attribute:
    """One public attribute with its declared (or inferred) chain type."""

    name: str
    type: str
    value: Any


@dataclass
class Entity:
    """An Arkiv entity, normalized from either vectors JSON or RPC JSON."""

    key: str
    creator: str
    owner: str
    created_at: int
    expires_at: int
    readonly: bool
    permissionless_extension: bool
    attributes: list[Attribute]
    payload: bytes

    def attr(self, name: str) -> Any:
        """Value of the first attribute called `name`, or None."""
        for a in self.attributes:
            if a.name == name:
                return a.value
        return None

    @property
    def kind(self) -> str:
        value = self.attr("qk")
        return value if isinstance(value, str) else "?"


# ---------------------------------------------------------------- parsing


def _int(value: Any) -> int:
    """Accept ints, decimal strings and 0x-hex strings."""
    if isinstance(value, bool):
        raise ValueError("boolean is not a number")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    raise ValueError(f"not a number: {value!r}")


def _hex_bytes(value: str) -> bytes:
    return bytes.fromhex(value[2:] if value.lower().startswith("0x") else value)


def _infer_type(value: Any) -> str:
    """Type of a vectors-file attribute, which carries no explicit type."""
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "u64"
    if isinstance(value, str) and HEX32.match(value):
        return "bytes32"
    if isinstance(value, str):
        return "str"
    return type(value).__name__


def _parse_attributes(raw: Any) -> list[Attribute]:
    # Vectors: {"qp": "quire1", "qs": "12", ...} with no type information;
    # u64 values are written as decimal strings there, so a digit string is
    # read as u64. RPC: [{"name", "type", "value"}, ...] with explicit types.
    if isinstance(raw, dict):
        out_v: list[Attribute] = []
        for k, v in raw.items():
            if isinstance(v, str) and v.isdigit():
                out_v.append(Attribute(k, "u64", int(v)))
            else:
                out_v.append(Attribute(k, _infer_type(v), v))
        return out_v
    out: list[Attribute] = []
    for item in raw or []:
        name = item.get("name", item.get("key"))
        typ = item.get("type") or _infer_type(item.get("value"))
        value = item.get("value")
        if typ == "u64":
            try:
                value = _int(value)
            except ValueError:
                pass
        out.append(Attribute(str(name), str(typ), value))
    return out


def parse_entity(raw: dict[str, Any]) -> Entity:
    """Normalize one entity from a vectors file or an arkiv_query result."""
    flags = raw.get("creationFlags")
    if isinstance(flags, dict):
        readonly = bool(flags.get("readonly"))
        permissionless = bool(flags.get("permissionlessExtension"))
    else:
        readonly = bool(raw.get("readonly"))
        permissionless = bool(raw.get("permissionlessExtension"))
    return Entity(
        key=str(raw["key"]).lower(),
        creator=str(raw.get("creator", "")).lower(),
        owner=str(raw.get("owner", "")).lower(),
        created_at=_int(raw.get("createdAt", 0)),
        expires_at=_int(raw.get("expiresAt", 0)),
        readonly=readonly,
        permissionless_extension=permissionless,
        attributes=_parse_attributes(raw.get("attributes")),
        payload=_hex_bytes(raw.get("payload") or ""),
    )


def load_vectors(path: str) -> tuple[dict[str, Any], list[Entity]]:
    """Read a document vectors file; returns (raw json, entities)."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data, [parse_entity(e) for e in data["entities"]]


# ---------------------------------------------------------------- live RPC


class RpcError(RuntimeError):
    pass


def rpc_call(url: str, method: str, params: list[Any]) -> Any:
    """One JSON-RPC 2.0 call over HTTP POST using urllib."""
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        url,
        data=body,
        # Some gateways reject the default Python-urllib user agent.
        headers={"content-type": "application/json", "user-agent": "quire-reader-python/1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            reply = json.load(resp)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RpcError(f"{method}: {exc}") from exc
    if reply.get("error"):
        raise RpcError(f"{method}: {reply['error'].get('message', reply['error'])}")
    return reply.get("result")


def query_all(url: str, query: str) -> list[dict[str, Any]]:
    """Run arkiv_query, following cursors with atBlock pinned to page one."""
    options: dict[str, Any] = {"select": SELECT_ALL, "limit": "0xc8"}
    rows: list[dict[str, Any]] = []
    while True:
        result = rpc_call(url, "arkiv_query", [query, options]) or {}
        rows.extend(result.get("data") or [])
        cursor = result.get("cursor")
        if not cursor or not result.get("data"):
            return rows
        if "atBlock" not in options and result.get("blockNumber") is not None:
            options["atBlock"] = result["blockNumber"]
        options["cursor"] = cursor


def get_entity(url: str, key: str) -> dict[str, Any] | None:
    return rpc_call(url, "arkiv_getEntity", [key])


def doc_query(doc: str) -> str:
    """Raw query string for every Quire entity of a document (section 5)."""
    return f"qp = str('quire1') AND qd = bytes32({doc.lower()})"


def fetch_document(url: str, doc: str) -> list[Entity]:
    return [parse_entity(e) for e in query_all(url, doc_query(doc))]


# ---------------------------------------------------------------- audit


@dataclass
class Report:
    failures: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)

    def check(self, ok: bool, label: str, detail: str = "") -> None:
        status = "PASS" if ok else "FAIL"
        self.lines.append(f"{status}  {label}" + (f": {detail}" if detail else ""))
        if not ok:
            self.failures.append(label)

    def info(self, text: str) -> None:
        self.lines.append(f"      {text}")


def check_attributes(e: Entity, doc: str | None) -> list[str]:
    """Problems with an entity's public attributes (section 2)."""
    problems: list[str] = []
    names = [a.name for a in e.attributes]
    if sorted(names) != sorted(ATTRIBUTE_TYPES):
        problems.append(f"attributes are {sorted(names)}")
    for a in e.attributes:
        want = ATTRIBUTE_TYPES.get(a.name)
        if want and a.type != want:
            problems.append(f"{a.name} has type {a.type}, expected {want}")
    if e.attr("qp") != "quire1":
        problems.append(f"qp = {e.attr('qp')!r}")
    qd = e.attr("qd")
    if not isinstance(qd, str) or not HEX32.match(qd):
        problems.append(f"qd = {qd!r} is not bytes32")
    elif doc and qd.lower() != doc.lower():
        problems.append(f"qd = {qd} is another document")
    if e.kind not in KIND_NAMES:
        problems.append(f"qk = {e.attr('qk')!r} is not a known kind")
    if not isinstance(e.attr("qs"), int):
        problems.append(f"qs = {e.attr('qs')!r} is not u64")
    return problems


def check_payload(e: Entity) -> list[str]:
    """Problems with an entity's payload framing and size (section 4)."""
    p = e.payload
    problems: list[str] = []
    if p[:2] != b"\x51\x01":
        problems.append(f"payload starts with {p[:2].hex() or 'nothing'}, not 5101")
    frame = len(p) - OUTER_HEADER - ENVELOPE_OVERHEAD
    if frame not in PADDING_BUCKETS:
        problems.append(f"payload {len(p)} bytes gives frame {frame}, not a bucket")
    leaks = ASCII_RUN.findall(p)
    if leaks:
        sample = leaks[0][:40].decode("ascii")
        problems.append(f"{len(leaks)} printable run(s) of 12+ bytes, e.g. {sample!r}")
    return problems


def lifetime_days(e: Entity) -> float:
    return (e.expires_at - e.created_at) * BLOCK_SECONDS / 86400


def flags_text(e: Entity) -> str:
    flags = [
        name
        for name, on in (
            ("readonly", e.readonly),
            ("permissionless extension", e.permissionless_extension),
        )
        if on
    ]
    return ", ".join(flags) or "none"


def audit(entities: list[Entity], doc: str | None, owner: str | None) -> Report:
    """Run every check and collect a printable report."""
    r = Report()
    r.info(f"document {doc or '(any)'}: {len(entities)} entities")
    r.check(bool(entities), "entities found")

    for e in entities:
        tag = f"{KIND_NAMES.get(e.kind, e.kind)} {e.key}"
        problems = check_attributes(e, doc)
        r.check(not problems, f"attributes {tag}", "; ".join(problems))
        problems = check_payload(e)
        r.check(not problems, f"payload {tag}", "; ".join(problems))

    # Per kind counts, lifetimes and flags.
    r.info("")
    r.info("per kind:")
    by_kind: dict[str, list[Entity]] = defaultdict(list)
    for e in entities:
        by_kind[e.kind].append(e)
    for kind in sorted(by_kind):
        group = by_kind[kind]
        lifetimes = sorted({round(lifetime_days(e), 3) for e in group})
        flags = Counter(flags_text(e) for e in group)
        sizes = Counter(len(e.payload) for e in group)
        r.info(
            f"  {KIND_NAMES.get(kind, kind):<9} count={len(group)}"
            f"  lifetime_days={lifetimes}"
            f"  flags={dict(flags)}  payload_bytes={dict(sizes)}"
        )

    # Creator set: the public metadata section 8 says remains visible.
    r.info("")
    r.info("creators (visible to anyone):")
    creators: dict[str, Counter[str]] = defaultdict(Counter)
    for e in entities:
        creators[e.creator][KIND_NAMES.get(e.kind, e.kind)] += 1
    for creator in sorted(creators):
        blocks = sorted(e.created_at for e in entities if e.creator == creator)
        r.info(
            f"  {creator}  {dict(creators[creator])}"
            f"  blocks {blocks[0]}..{blocks[-1]}"
        )
    mismatched = [e.key for e in entities if e.owner and e.owner != e.creator]
    if mismatched:
        r.info(f"  {len(mismatched)} entities whose owner differs from creator")

    # ACL presence and provenance.
    r.info("")
    acls = by_kind.get("a", [])
    if owner:
        owner = owner.lower()
        mine = [e for e in acls if e.creator == owner]
        r.check(bool(mine), "ACL created by claimed owner", owner)
        others = [e.creator for e in acls if e.creator != owner]
        if others:
            r.info(f"  ACL entities from other creators (untrusted): {others}")
    else:
        r.check(bool(acls), "ACL exists", "no --owner given, creator not checked")
    return r


# ---------------------------------------------------------------- CLI


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--vectors", help="document vectors JSON file")
    src.add_argument("--doc", help="document id, 0x + 64 hex chars")
    ap.add_argument("--rpc", default=DEFAULT_RPC, help="Arkiv JSON-RPC URL")
    ap.add_argument("--owner", help="claimed owner address (0x + 40 hex)")
    args = ap.parse_args(list(argv) if argv is not None else None)

    try:
        if args.vectors:
            data, entities = load_vectors(args.vectors)
            doc = data.get("doc")
            owner = args.owner or data.get("owner")
        else:
            if not HEX32.match(args.doc):
                ap.error("--doc must be 0x followed by 64 hex characters")
            doc, owner = args.doc.lower(), args.owner
            entities = fetch_document(args.rpc, doc)
    except (OSError, ValueError, KeyError, RpcError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = audit(entities, doc, owner)
    print("\n".join(report.lines))
    print()
    if report.failures:
        print(f"RESULT: FAIL ({len(report.failures)} failed checks)")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
