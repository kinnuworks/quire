"""Conformance tests against spec/vectors. Run: python -m unittest -v test_vectors"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import random
import struct
import sys
import unittest
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "..", "..", "spec", "vectors")
DOCUMENT = os.path.join(VECTORS, "document.json")
KEYS = os.path.join(VECTORS, "keys.json")
sys.path.insert(0, HERE)

import quire_audit  # noqa: E402

try:
    import quire_read
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from pycrdt import Doc, XmlElement, XmlFragment, XmlText, get_state

    READER_SKIP = ""
except ImportError as exc:  # cryptography or pycrdt missing
    READER_SKIP = f"reader tests need cryptography and pycrdt ({exc}); pip install -r requirements.txt"

try:
    import jsonschema  # noqa: F401

    SCHEMA_SKIP = "" if not READER_SKIP else READER_SKIP
except ImportError:
    SCHEMA_SKIP = "jsonschema not installed"

with open(DOCUMENT, encoding="utf-8") as fh:
    VEC = json.load(fh)

OWNER_KEY = VEC["privateKeys"]["owner"]
BEA_KEY = VEC["privateKeys"]["bea"]
REVOKED_AT = 10  # Cal's atBlock in the sealed roster


def _vector_sessions() -> dict:
    """{creator: (client id, salt)} from the vectors' update headers.

    Read from the file rather than written down, so a regenerated vectors
    file does not need new constants. test_client_id_for_matches_the_vectors
    checks each against the structs.
    """
    data, entities = quire_audit.load_vectors(DOCUMENT)
    reader = quire_read.Reader(
        quire_read.parse_link(data["link"]), quire_read.VectorSource(entities),
        quire_read.load_private_key(BEA_KEY), schemas=quire_read.Schemas(enabled=False),
    )
    reader.roster(reader.load_acl())
    out = {}
    for e in entities:
        if e.kind == "u":
            salt = reader._content_frame(e).header["salt"]
            out[e.creator] = (quire_read.client_id_for(e.creator, salt), salt)
    return out


# Yjs client ids in the vectors, each clientIdFor(address, session salt).
# The owner's salt is visible to every member in his update headers. Cal is
# revoked; his edits live on only in the snapshots.
if not READER_SKIP:
    _SESSIONS = _vector_sessions()
    OWNER_CLIENT, OWNER_SALT = _SESSIONS[VEC["owner"]]
    BEA_CLIENT = _SESSIONS[VEC["members"]["bea"]][0]
    CAL_CLIENT = _SESSIONS[VEC["members"]["cal"]][0]
else:
    OWNER_CLIENT, OWNER_SALT, BEA_CLIENT, CAL_CLIENT = 0, "", 0, 0
KEYS_BY_ADDRESS = {VEC["owner"]: OWNER_KEY, VEC["members"]["bea"]: BEA_KEY}
OTHER_DOC = "0x" + "cd" * 32


def _qs(e) -> int:
    return e.attr("qs")


def newest_snapshot(entities):
    """The vectors' newest snapshot by qs (section 5 step 3)."""
    return max((e for e in entities if e.kind == "s"), key=_qs)


def without_cal_update(entities):
    """The vectors as if Cal's one update had expired: his line then exists
    only in snapshots, which is how these tests reach snapshot-only text.
    (While it lives it counts: he wrote it before his removal block.)"""
    return [e for e in entities if not (e.kind == "u" and e.creator == VEC["members"]["cal"])]


def owner_late_update(entities):
    """The owner's last update; its structs do not start at clock 0."""
    return max((e for e in entities if e.kind == "u" and e.creator == VEC["owner"]), key=lambda e: e.created_at)


def bea_update(entities):
    """Bea's genuine epoch 0 update (her other one, in epoch 1, has a malformed header)."""
    return min((e for e in entities if e.kind == "u" and e.creator == VEC["members"]["bea"]), key=lambda e: e.created_at)


def run_cli(main, *args: str) -> tuple[int, str]:
    """Call a script's main() and capture stdout."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(list(args))
    return code, out.getvalue()


# ---------------------------------------------------------------- writer side
# Just enough of a writer to build hostile entities for the reader rules.


def seal(kind: str, epoch: int, header: dict, data: bytes, key: bytes, frame_epoch: int | None = None) -> bytes:
    h = json.dumps(header, separators=(",", ":")).encode()
    fe = epoch if frame_epoch is None else frame_epoch
    frame = (
        b"QF\x01" + kind.encode() + bytes.fromhex(VEC["doc"][2:])
        + struct.pack(">III", fe, len(h), len(data)) + h + data
    )
    bucket = min(b for b in quire_audit.PADDING_BUCKETS if b >= len(frame))
    frame += os.urandom(bucket - len(frame))
    iv = os.urandom(12)
    return b"\x51\x01" + struct.pack(">I", epoch) + iv + AESGCM(key).encrypt(iv, frame, None)


def make_entity(template, *, key: str, kind: str, creator: str, block: int, payload: bytes,
                readonly: bool = False, permissionless: bool = False):
    attrs = []
    for a in template.attributes:
        value = {"qk": kind, "qs": block}.get(a.name, a.value)
        attrs.append(quire_audit.Attribute(a.name, a.type, value))
    return dataclasses.replace(
        template, key=key, creator=creator, owner=creator, created_at=block,
        expires_at=block + 1296000, attributes=attrs, payload=payload,
        readonly=readonly, permissionless_extension=permissionless,
        flags_raw=quire_audit.raw_flags(readonly, permissionless),
    )


def fake_key(n: int) -> str:
    return "0x" + f"{n:064x}"


def to_raw(e) -> dict:
    """Entity back to the arkiv_query JSON shape the vectors use."""
    flags = {"readonly": e.readonly, "permissionlessExtension": e.permissionless_extension}
    if e.flags_raw is not None:
        flags["raw"] = e.flags_raw
    return {
        "key": e.key, "creator": e.creator, "owner": e.owner,
        "createdAt": hex(e.created_at), "expiresAt": hex(e.expires_at),
        "creationFlags": flags,
        "attributes": [
            {"name": a.name, "type": a.type, "value": hex(a.value) if a.type == "u64" else a.value}
            for a in e.attributes
        ],
        "payload": "0x" + e.payload.hex(),
    }


def sign_salt(private_hex: str, salt: str, doc: str = VEC["doc"]) -> str:
    """EIP-191 signature (r || s || v, v 27 or 28) over the salt message.

    Signs with `cryptography`, which gives r and s but no recovery id, so v
    is found by recovering both parities and keeping the one that matches.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    key = quire_read.load_private_key(private_hex)
    digest = quire_read.eip191_digest(quire_read.salt_message(doc, salt))
    r, s = utils.decode_dss_signature(key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
    s = min(s, quire_read._N - s)  # low s, as personal_sign writes it
    want = quire_read.public_key_bytes(key)
    for v in (27, 28):
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])
        if quire_read.recover_public_key(digest, sig) == want:
            return "0x" + sig.hex()
    raise AssertionError("neither parity recovers the signing key")


def author_entry(address: str, salt: str, signer: str | None = None, doc: str = VEC["doc"]) -> dict:
    """A snapshot `authors` value, signed by `signer` (default: the address's own key)."""
    return {"address": address, "salt": salt, "sig": sign_salt(signer or KEYS_BY_ADDRESS[address], salt, doc)}


@contextlib.contextmanager
def collide(address: str, salt: str, cid: int):
    """Make clientIdFor(address, salt) return `cid`, standing in for a
    53-bit collision nobody can find on demand."""
    real = quire_read.client_id_for

    def fake(a, s):
        text = s if isinstance(s, str) else bytes(s).hex()
        return cid if (str(a).lower(), text) == (address, salt) else real(a, s)

    quire_read.client_id_for = fake
    try:
        yield
    finally:
        quire_read.client_id_for = real


def snapshot_header(data: bytes, base: int, chunks=(), authors=None) -> dict:
    return {
        "id": os.urandom(16).hex(), "base": str(base), "t": 1, "chunks": list(chunks),
        "size": len(data), "authors": authors or {},
    }


class AuditTests(unittest.TestCase):
    def test_audit_passes_on_document(self) -> None:
        code, out = run_cli(
            quire_audit.main, "--vectors", DOCUMENT, "--owner", VEC["owner"]
        )
        self.assertEqual(code, 0, out)
        self.assertIn("RESULT: PASS", out)
        self.assertNotIn("FAIL ", out)

    def test_audit_fails_on_leaky_payload(self) -> None:
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        entities[0].payload = entities[0].payload[:40] + b"plaintext leaked here" + entities[0].payload[61:]
        report = quire_audit.audit(entities, VEC["doc"], VEC["owner"])
        self.assertTrue(any("payload" in f for f in report.failures))

    def test_audit_fails_on_wrong_owner(self) -> None:
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        report = quire_audit.audit(entities, VEC["doc"], VEC["members"]["mallory"])
        self.assertIn("ACL created by claimed owner", report.failures)

    def test_join_payload_size_counts_the_ephemeral_key(self) -> None:
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        joins = [e for e in entities if e.kind == "j"]
        self.assertTrue(joins)
        for e in joins:
            self.assertEqual(len(e.payload), 6 + 65 + 28 + 256)
            self.assertEqual(quire_audit.check_payload(e), [])

    def test_random_printable_run_is_not_a_leak(self) -> None:
        # 13 random printable bytes, like the run in the vectors' ACL.
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        e = entities[0]
        e.payload = e.payload[:100] + b":{^kT%VAE&0JO" + e.payload[113:]
        self.assertEqual(quire_audit.check_payload(e), [])

    def test_permissionless_extension_only_on_versions_and_the_acl(self) -> None:
        for kind in ("u", "s", "j"):
            entities = quire_audit.load_vectors(DOCUMENT)[1]
            e = next(x for x in entities if x.kind == kind)
            e.permissionless_extension, e.flags_raw = True, 2
            report = quire_audit.audit(entities, VEC["doc"], VEC["owner"])
            self.assertIn(f"flags {quire_audit.KIND_NAMES[kind]} {e.key}", report.failures, kind)

    def test_acl_flags_are_permissionless_extension_only(self) -> None:
        # Section 1: the ACL has permissionless extension, so any member's
        # session can extend it, and no other flag.
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        acl = next(e for e in entities if e.kind == "a")
        self.assertEqual((acl.readonly, acl.permissionless_extension, acl.flags_raw), (False, True, 2))
        self.assertEqual(quire_audit.check_flags(acl), [])
        cases = {
            (False, False): ["acl does not allow permissionless extension"],
            (True, True): ["acl is readonly, expected permissionless extension only"],
            (True, False): ["acl does not allow permissionless extension",
                            "acl is readonly, expected permissionless extension only"],
        }
        for (ro, pe), want in cases.items():
            acl.readonly, acl.permissionless_extension = ro, pe
            acl.flags_raw = quire_audit.raw_flags(ro, pe)
            self.assertEqual(quire_audit.check_flags(acl), want, (ro, pe))
            report = quire_audit.audit(entities, VEC["doc"], VEC["owner"])
            self.assertIn(f"flags acl {acl.key}", report.failures)
        # Booleans right, raw wrong: the old rule's raw 0 on a correct ACL.
        acl.readonly, acl.permissionless_extension, acl.flags_raw = False, True, 0
        self.assertIn("bit 1 disagrees", " ".join(quire_audit.check_flags(acl)))

    def test_version_must_be_readonly(self) -> None:
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        template = entities[0]
        version = dataclasses.replace(
            template, attributes=[
                quire_audit.Attribute(a.name, a.type, "v" if a.name == "qk" else a.value)
                for a in template.attributes
            ],
            readonly=False, permissionless_extension=True, flags_raw=None,  # booleans only, no raw
        )
        self.assertEqual(quire_audit.check_flags(version), ["version is not readonly"])
        version.readonly = True
        self.assertEqual(quire_audit.check_flags(version), [])
        # Section 1: a version is readonly and allows permissionless extension.
        version.permissionless_extension = False
        self.assertEqual(
            quire_audit.check_flags(version), ["version does not allow permissionless extension"]
        )

    def test_snapshot_has_no_flags(self) -> None:
        # Section 1: a snapshot carries no flags, readonly included.
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        snap = next(e for e in entities if e.kind == "s")
        snap.readonly, snap.flags_raw = True, 1
        self.assertEqual(quire_audit.check_flags(snap), ["snapshot is readonly, expected no flags"])

    def test_vectors_carry_creation_flags_like_the_rpc(self) -> None:
        for raw in VEC["entities"]:
            acl = quire_audit.parse_entity(raw).kind == "a"
            self.assertEqual(
                raw["creationFlags"], {"readonly": False, "permissionlessExtension": acl, "raw": 2 if acl else 0}
            )
        for e in quire_audit.load_vectors(DOCUMENT)[1]:
            self.assertEqual(e.flags_raw, 2 if e.kind == "a" else 0)

    def test_unknown_raw_flag_fails(self) -> None:
        e = next(x for x in quire_audit.load_vectors(DOCUMENT)[1] if x.kind == "u")
        e.flags_raw = 4
        self.assertTrue(quire_audit.check_flags(e))

    def test_raw_flag_bits(self) -> None:
        # Section 5: in creationFlags.raw, bit 0 is readonly and bit 1 is
        # permissionless extension.
        self.assertEqual(quire_audit.raw_flags(False, False), 0)
        self.assertEqual(quire_audit.raw_flags(True, False), 1)
        self.assertEqual(quire_audit.raw_flags(False, True), 2)
        self.assertEqual(quire_audit.raw_flags(True, True), 3)
        template = quire_audit.load_vectors(DOCUMENT)[1][0]
        version = dataclasses.replace(
            template, attributes=[
                quire_audit.Attribute(a.name, a.type, "v" if a.name == "qk" else a.value)
                for a in template.attributes
            ],
            readonly=True, permissionless_extension=True,
        )
        for raw, ok in ((3, True), (None, True), (0, False), (1, False), (2, False), (7, False), (11, False)):
            version.flags_raw = raw
            self.assertEqual(not quire_audit.check_flags(version), ok, raw)
        update = next(e for e in quire_audit.load_vectors(DOCUMENT)[1] if e.kind == "u")
        for raw, ok in ((0, True), (1, False), (2, False), (3, False), (4, False)):
            update.flags_raw = raw
            self.assertEqual(not quire_audit.check_flags(update), ok, raw)
        # The booleans and raw must agree in both directions.
        update.flags_raw, update.readonly = 0, True
        self.assertIn("bit 0 disagrees", " ".join(quire_audit.check_flags(update)))

    def test_raw_flag_mismatch_fails_audit(self) -> None:
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        e = next(x for x in entities if x.kind == "s")
        e.flags_raw = 2  # says permissionless extension; the booleans say none
        report = quire_audit.audit(entities, VEC["doc"], VEC["owner"])
        self.assertIn(f"flags snapshot {e.key}", report.failures)

    def test_chunk_flags_follow_a_head(self) -> None:
        template = quire_audit.load_vectors(DOCUMENT)[1][0]
        chunk = dataclasses.replace(
            template, attributes=[
                quire_audit.Attribute(a.name, a.type, "c" if a.name == "qk" else a.value)
                for a in template.attributes
            ],
        )
        for ro, pe, ok in ((False, False, True), (True, True, True), (False, True, False), (True, False, False)):
            chunk.readonly, chunk.permissionless_extension = ro, pe
            chunk.flags_raw = quire_audit.raw_flags(ro, pe)
            self.assertEqual(not quire_audit.check_flags(chunk), ok, (ro, pe))


@unittest.skipIf(READER_SKIP, READER_SKIP)
class ReaderTests(unittest.TestCase):
    def test_key_derivation(self) -> None:
        with open(KEYS, encoding="utf-8") as fh:
            keys = json.load(fh)
        secret = bytes.fromhex(keys["linkSecret"])
        self.assertEqual(quire_read.meta_key(secret).hex(), keys["metaKey"])
        self.assertEqual(quire_read.epoch0_key(secret).hex(), keys["epoch0Key"])

    def test_addresses_from_keys(self) -> None:
        for name in ("owner", "bea"):
            key = quire_read.load_private_key(VEC["privateKeys"][name])
            self.assertEqual(
                quire_read.address_of(quire_read.public_key_bytes(key)), VEC["members"][name]
            )

    def test_link_parses(self) -> None:
        link = quire_read.parse_link(VEC["link"])
        self.assertEqual(link.doc, VEC["doc"])
        self.assertEqual(link.owner, VEC["owner"])
        self.assertEqual(link.secret.hex(), VEC["linkSecret"])

    def test_link_holder_text(self) -> None:
        # Epoch 1: the roster is sealed, so a link holder sees nothing.
        code, out = run_cli(quire_read.main, "--vectors", DOCUMENT)
        self.assertEqual(code, 0)
        self.assertEqual(VEC["expected"]["linkHolderText"], "")
        self.assertEqual(out, "")

    def test_member_text(self) -> None:
        code, out = run_cli(quire_read.main, "--vectors", DOCUMENT, "--member-key", BEA_KEY)
        self.assertEqual(code, 0)
        self.assertEqual(out.rstrip("\n"), VEC["expected"]["memberText"])

    def _reader(self, entities=None, key: str | None = BEA_KEY) -> "quire_read.Reader":
        data, loaded = quire_audit.load_vectors(DOCUMENT)
        return quire_read.Reader(
            quire_read.parse_link(data["link"]),
            quire_read.VectorSource(entities if entities is not None else loaded),
            quire_read.load_private_key(key) if key else None,
        )

    def _member_result(self):
        reader = self._reader()
        return reader, reader.read()

    def test_roster_is_sealed_from_link_holders(self) -> None:
        reader = self._reader(key=None)
        result = reader.read()
        self.assertEqual(result.epoch, 1)
        self.assertIsNone(result.members)
        self.assertNotIn("members", result.acl)
        self.assertNotIn("revoked", result.acl)
        self.assertEqual(result.text, "")

    def test_member_opens_roster(self) -> None:
        _reader, result = self._member_result()
        self.assertEqual(
            sorted(m["address"] for m in result.members),
            sorted([VEC["members"]["owner"], VEC["members"]["bea"]]),
        )
        self.assertEqual([r["address"] for r in result.revoked], [VEC["members"]["cal"]])
        self.assertEqual(
            quire_read.address_of(result.acl["ownerPublicKey"]), VEC["owner"]
        )

    def test_forged_entity_is_ignored(self) -> None:
        reader, result = self._member_result()
        rejected = {c.lower() for c in VEC["expected"]["rejectedCreators"]}
        forged = [e for e in reader.source.entities if e.creator in rejected]  # type: ignore[attr-defined]
        self.assertTrue(forged)
        ignored = {key for key, _reason in result.ignored}
        for e in forged:
            self.assertNotIn(e.key, result.applied)
            self.assertIn(e.key, ignored)
        # The forgery is a valid epoch 0 update with new text, written by a
        # link holder who is not a member. It decrypts, so only the creator
        # filter keeps it out: applying it would add a paragraph.
        for e in forged:
            frame = reader._content_frame(e)
            self.assertTrue(frame.data)
            probe = Doc()
            probe.apply_update(result.doc.get_update())
            probe.apply_update(frame.data)
            self.assertIn("MALLORY WAS HERE", quire_read.fragment_text(probe.get("default", type=XmlFragment)))
        self.assertNotIn("MALLORY", result.text)

    def test_acl_from_other_creator_is_not_trusted(self) -> None:
        data, entities = quire_audit.load_vectors(DOCUMENT)
        link = quire_read.parse_link(data["link"])
        link.owner = VEC["members"]["mallory"]
        with self.assertRaises(RuntimeError):
            quire_read.Reader(link, quire_read.VectorSource(entities)).read()

    def test_replayed_frame_is_rejected(self) -> None:
        # An update payload relabelled as a snapshot must fail the kind check.
        data, entities = quire_audit.load_vectors(DOCUMENT)
        link = quire_read.parse_link(data["link"])
        update = next(e for e in entities if e.kind == "u" and e.payload[2:6] == b"\0\0\0\0")
        update.attributes = [
            quire_audit.Attribute(a.name, a.type, "s" if a.name == "qk" else a.value)
            for a in update.attributes
        ]
        with self.assertRaises(quire_read.Rejected):
            quire_read.decrypt_frame(update, quire_read.epoch0_key(link.secret), link.doc)

    # -------------------------------------------------------- join requests

    def test_owner_key_opens_join_requests(self) -> None:
        data, entities = quire_audit.load_vectors(DOCUMENT)
        link = quire_read.parse_link(data["link"])
        owner = quire_read.load_private_key(OWNER_KEY)
        joins = [e for e in entities if e.kind == "j"]
        self.assertEqual(len(joins), 2)
        names = {}
        for e in joins:
            frame = quire_read.open_join(e, owner, link.doc)
            self.assertEqual(frame.kind, "j")
            self.assertEqual(frame.epoch, 0)
            # Section 7: the public key must hash to the request's creator.
            self.assertEqual(quire_read.address_of(frame.header["publicKey"]), e.creator)
            names[e.creator] = frame.header["name"]
        self.assertEqual(names, {VEC["members"]["bea"]: "Bea", VEC["members"]["cal"]: "Cal"})

    def test_meta_key_and_member_key_do_not_open_join_requests(self) -> None:
        data, entities = quire_audit.load_vectors(DOCUMENT)
        link = quire_read.parse_link(data["link"])
        mkey = quire_read.meta_key(link.secret)
        for e in (x for x in entities if x.kind == "j"):
            # Neither as a plain envelope nor with the ephemeral key stripped.
            with self.assertRaises(quire_read.Rejected):
                quire_read.decrypt_frame(e, mkey, link.doc)
            with self.assertRaises(Exception):
                quire_read.open_envelope(mkey, e.payload[6 + 65 :])
            with self.assertRaises(quire_read.Rejected):
                quire_read.open_join(e, quire_read.load_private_key(BEA_KEY), link.doc)

    # -------------------------------------------------------- snapshots

    def test_snapshot_order_does_not_depend_on_query_order(self) -> None:
        _reader, base = self._member_result()
        self.assertEqual(base.newest_snapshot, newest_snapshot(_reader.source.entities).key)  # type: ignore[attr-defined]
        for seed in range(5):
            entities = quire_audit.load_vectors(DOCUMENT)[1]
            random.Random(seed).shuffle(entities)
            result = self._reader(entities).read()
            self.assertEqual(result.newest_snapshot, base.newest_snapshot)
            self.assertEqual(result.text, VEC["expected"]["memberText"])

    def _chunked(self, of_value, chunk_epoch: int = 1, chunk_flags: bool = False):
        """Split the newest snapshot into a head and one chunk."""
        reader, _result = self._member_result()
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        head = newest_snapshot(entities)
        frame = reader._content_frame(head)
        chunk_key = fake_key(0xC1)
        header = dict(frame.header, chunks=[chunk_key])
        new_head = make_entity(
            head, key=fake_key(0x5A), kind="s", creator=head.creator, block=head.created_at,
            payload=seal("s", 1, header, frame.data[:100], reader.keys[1]),
        )
        of = frame.header["id"] if of_value is None else of_value
        chunk = make_entity(
            head, key=chunk_key, kind="c", creator=head.creator, block=head.created_at,
            payload=seal("c", chunk_epoch, {"i": 1, "of": of}, frame.data[100:], reader.keys[chunk_epoch]),
            readonly=chunk_flags, permissionless=chunk_flags,
        )
        entities = [e for e in entities if e is not head] + [chunk, new_head]
        return new_head, self._reader(entities).read()

    def test_chunk_of_matches_snapshot_id(self) -> None:
        head, result = self._chunked(None)
        self.assertEqual(result.newest_snapshot, head.key)
        self.assertEqual(result.text, VEC["expected"]["memberText"])

    def test_chunk_of_naming_the_entity_key_is_rejected(self) -> None:
        # `of` is the snapshot's random id, not the head's entity key.
        head, result = self._chunked(fake_key(0x5A)[2:34])
        reasons = dict(result.ignored)
        self.assertIn(head.key, reasons)
        self.assertIn("i/of", reasons[head.key])
        self.assertNotEqual(result.newest_snapshot, head.key)

    def test_chunk_in_another_epoch_is_rejected(self) -> None:
        # Section 4: a chunk's outer epoch MUST equal its head's. This one is
        # a well-formed epoch 0 chunk (the reader holds that key too).
        head, result = self._chunked(None, chunk_epoch=0)
        reasons = dict(result.ignored)
        self.assertIn("differs from its head's", reasons[head.key])
        self.assertNotEqual(result.newest_snapshot, head.key)

    def test_snapshot_chunk_with_flags_is_rejected(self) -> None:
        # Section 1: a snapshot's chunks carry no flags, like the snapshot.
        head, result = self._chunked(None, chunk_flags=True)
        self.assertIn("flags", dict(result.ignored)[head.key])
        self.assertNotEqual(result.newest_snapshot, head.key)

    def _extra_snapshot(self, *, epoch: int, block: int, text: str, only_owner_snapshot: bool = False):
        """A full-state snapshot by the owner with one more paragraph. Section 5
        step 3 applies only each member's newest snapshot, so with
        only_owner_snapshot the owner's other snapshots are left out."""
        reader, result = self._member_result()
        salt = os.urandom(16).hex()
        cid = quire_read.client_id_for(VEC["owner"], salt)
        d = Doc(client_id=cid)
        d.apply_update(result.doc.get_update())
        d.get("default", type=XmlFragment).children.append(XmlElement("paragraph", None, [XmlText(text)]))
        data = d.get_update()
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        template = newest_snapshot(entities)
        e = make_entity(
            template, key=fake_key(0x5500 + block), kind="s", creator=VEC["owner"], block=block,
            payload=seal("s", epoch, snapshot_header(
                data, block, authors={str(cid): author_entry(VEC["owner"], salt)}), data, reader.keys[epoch]),
        )
        if only_owner_snapshot:
            entities = [x for x in entities if not (x.kind == "s" and x.creator == VEC["owner"])]
        return e, self._reader(entities + [e]).read()

    def test_old_epoch_snapshot_after_revocation_is_applied(self) -> None:
        # Section 5: a snapshot a writer sent under an older epoch, before it
        # saw the rotation, is still applied (the old rule ignored it).
        e, result = self._extra_snapshot(epoch=0, block=REVOKED_AT + 2, text="Old key snapshot.")
        self.assertIn(e.key, result.applied)
        self.assertNotIn(e.key, dict(result.ignored))
        self.assertTrue(result.text.endswith("Old key snapshot."))

    def test_old_epoch_snapshot_at_revocation_block_is_applied(self) -> None:
        # createdAt equal to atBlock is not "greater than", so it stays.
        e, result = self._extra_snapshot(epoch=0, block=REVOKED_AT, text="Same block as the revocation.", only_owner_snapshot=True)
        self.assertIn(e.key, result.applied)
        self.assertIn("Same block as the revocation.", result.text)

    def test_current_epoch_snapshot_after_revocation_is_applied(self) -> None:
        e, result = self._extra_snapshot(epoch=1, block=REVOKED_AT + 2, text="New key snapshot.")
        self.assertEqual(result.newest_snapshot, e.key)
        self.assertTrue(result.text.endswith("New key snapshot."))

    # -------------------------------------------------------- client ids

    def test_update_clients_at_any_clock(self) -> None:
        reader, _result = self._member_result()
        owner_e1 = owner_late_update(reader.source.entities)  # type: ignore[attr-defined]
        data = reader._content_frame(owner_e1).data
        clients = quire_read.update_clients(data)
        self.assertEqual(set(clients), {OWNER_CLIENT})
        self.assertGreater(clients[OWNER_CLIENT][0][0], 0)
        # A state vector of this update is empty: it does not start at clock 0.
        self.assertEqual(get_state(data), b"\x00")

    def _forged_update(self, client_id: int | None, epoch: int, block: int, text: str,
                       creator: str | None = None, key: str | None = None, salt: str | None = None,
                       header: dict | None = None, extra=(), schemas=None, signer: str | None = None):
        """An update by `creator` (Bea by default) adding one paragraph.

        `client_id=None` uses the creator's own clientIdFor(creator, salt).
        The salt is signed with `signer`, by default the creator's own key.
        """
        creator = creator or VEC["members"]["bea"]
        salt = salt or os.urandom(16).hex()
        if header is None:
            header = {"t": 1, "salt": salt, "sig": sign_salt(signer or KEYS_BY_ADDRESS[creator], salt)}
        if client_id is None:
            client_id = quire_read.client_id_for(creator, salt)
        reader, result = self._member_result()
        d = Doc(client_id=client_id)
        d.apply_update(result.doc.get_update())
        frag = d.get("default", type=XmlFragment)
        frag.children.append(XmlElement("paragraph", None, [XmlText(text)]))
        update = d.get_update(result.doc.get_state())
        self.assertIn(client_id, quire_read.update_clients(update))
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        template = bea_update(entities)
        e = make_entity(
            template, key=key or fake_key(0xB0 + block), kind="u", creator=creator, block=block,
            payload=seal("u", epoch, header, update, reader.keys[epoch]),
        )
        data, _ = quire_audit.load_vectors(DOCUMENT)
        out = quire_read.Reader(
            quire_read.parse_link(data["link"]), quire_read.VectorSource(entities + [e] + list(extra)),
            quire_read.load_private_key(BEA_KEY), schemas=schemas,
        ).read()
        return e, out

    def test_client_id_for_matches_the_vectors(self) -> None:
        # Section 5: every update in the vectors uses clientIdFor($creator, salt).
        reader, _result = self._member_result()
        seen = {}
        for e in reader.source.entities:  # type: ignore[attr-defined]
            if e.kind != "u":
                continue
            frame = reader._content_frame(e)
            cid = quire_read.client_id_for(e.creator, frame.header["salt"])
            self.assertEqual(set(quire_read.update_clients(frame.data)), {cid}, e.key)
            self.assertLess(cid, 1 << 53)
            seen[e.creator] = cid
        self.assertEqual(seen[VEC["owner"]], OWNER_CLIENT)
        self.assertEqual(seen[VEC["members"]["bea"]], BEA_CLIENT)
        self.assertEqual(seen[VEC["members"]["cal"]], CAL_CLIENT)
        self.assertEqual(quire_read.client_id_for(VEC["owner"], OWNER_SALT), OWNER_CLIENT)
        # Same answer for mixed-case addresses and for raw salt bytes.
        self.assertEqual(quire_read.client_id_for(VEC["owner"].upper().replace("0X", "0x"),
                                                  bytes.fromhex(OWNER_SALT)), OWNER_CLIENT)

    def test_client_id_for_rules(self) -> None:
        # keccak-256 of "" and the 53-bit mask; a zero result becomes 1.
        self.assertEqual(
            quire_read.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        addr, salt = VEC["owner"], OWNER_SALT
        digest = quire_read.keccak256(bytes.fromhex(addr[2:]) + bytes.fromhex(salt))
        self.assertEqual(OWNER_CLIENT, int.from_bytes(digest[:8], "big") & ((1 << 53) - 1))
        original = quire_read.keccak256
        try:
            quire_read.keccak256 = lambda _data: b"\xff\xe0" + b"\0" * 30  # top 11 bits only: masks to 0
            self.assertEqual(quire_read.client_id_for(addr, salt), 1)
        finally:
            quire_read.keccak256 = original
        for bad in ("", "00" * 15, "AB" * 16, "0x" + "00" * 16, "00" * 17):
            with self.assertRaises(ValueError, msg=bad):
                quire_read.client_id_for(addr, bad)

    def test_update_clients_at_any_clock(self) -> None:
        reader, _result = self._member_result()
        owner_e1 = owner_late_update(reader.source.entities)  # type: ignore[attr-defined]
        data = reader._content_frame(owner_e1).data
        clients = quire_read.update_clients(data)
        self.assertEqual(set(clients), {OWNER_CLIENT})
        self.assertGreater(clients[OWNER_CLIENT][0][0], 0)
        # A state vector of this update is empty: it does not start at clock 0.
        self.assertEqual(get_state(data), b"\x00")

    def test_skip_struct_under_another_client_id_counts(self) -> None:
        # Yjs parseUpdateMeta counts Skip structs, so a group for a foreign
        # client holding only a Skip still fails the check. Without this,
        # readers that do and do not count Skips would disagree.
        reader, _result = self._member_result()
        bea_e = bea_update(reader.source.entities)  # type: ignore[attr-defined]
        frame = reader._content_frame(bea_e)
        data = frame.data
        self.assertEqual(data[0], 1)  # one client group, so the count is one byte
        skip_group = bytes([1]) + bytes([0xB9, 0x60]) + bytes([0]) + bytes([10, 5])  # 1 struct, client 12345, clock 0, skip 5
        forged = bytes([2]) + skip_group + data[1:]
        clients = quire_read.update_clients(forged)
        self.assertEqual(clients[12345], [])
        self.assertIn(BEA_CLIENT, clients)
        e = make_entity(
            bea_e, key=fake_key(0xD1), kind="u", creator=bea_e.creator, block=bea_e.created_at,
            payload=seal("u", 0, frame.header, forged, reader.keys[0]),
        )
        result = self._reader(quire_audit.load_vectors(DOCUMENT)[1] + [e]).read()
        self.assertNotIn(e.key, result.applied)
        self.assertIn("12345 is not clientIdFor", dict(result.ignored)[e.key])

    def test_update_with_client_id_not_derived_from_creator_is_ignored(self) -> None:
        # A fresh client id that is not clientIdFor(creator, salt).
        e, result = self._forged_update(4242, 1, 13, "Bea, under a made-up id.")
        self.assertNotIn(e.key, result.applied)
        self.assertIn("is not clientIdFor(creator, salt)", dict(result.ignored)[e.key])
        self.assertNotIn(4242, result.authors)
        self.assertEqual(result.text, VEC["expected"]["memberText"])

    def test_member_writing_under_the_owners_client_id_is_ignored(self) -> None:
        # Bea copies the owner's client id, with her own salt and with the
        # owner's salt (which every member sees in the owner's headers).
        for salt in (None, OWNER_SALT):
            e, result = self._forged_update(OWNER_CLIENT, 1, 13, "Bea writes as the owner.", salt=salt)
            self.assertNotIn(e.key, result.applied, salt)
            self.assertIn(f"{OWNER_CLIENT} is not clientIdFor", dict(result.ignored)[e.key])
            self.assertEqual(result.authors[OWNER_CLIENT].address, VEC["owner"])
            self.assertEqual(result.text, VEC["expected"]["memberText"])

    def test_member_writing_under_a_revoked_members_client_id_is_ignored(self) -> None:
        # Cal's own update, written before his removal, binds his id; the
        # derivation check alone already keeps Bea from writing as Cal.
        e, result = self._forged_update(CAL_CLIENT, 1, 13, "Bea writes as Cal.")
        self.assertNotIn(e.key, result.applied)
        self.assertEqual(result.authors[CAL_CLIENT].address, VEC["members"]["cal"])
        self.assertTrue(result.authors[CAL_CLIENT].proven)

    def test_removed_members_earlier_edit_counts_and_later_one_does_not(self) -> None:
        # Section 5: Cal was removed at block 10. His update from block 9 was
        # written by a member and stays proven; one he creates at block 13,
        # with a valid salt and signature under the epoch 0 key he still has,
        # is ignored like any outsider's.
        reader, result = self._member_result()
        cal_update = next(e for e in reader.source.entities if e.kind == "u" and e.creator == VEC["members"]["cal"])  # type: ignore[attr-defined]
        self.assertLessEqual(cal_update.created_at, REVOKED_AT)
        self.assertIn(cal_update.key, result.applied)
        self.assertTrue(result.authors[CAL_CLIENT].proven)
        # the member filter decides before any signature check, so a placeholder sig is enough here
        salt = os.urandom(16).hex()
        e, later = self._forged_update(None, 0, 13, "Cal, after removal.", creator=VEC["members"]["cal"], salt=salt,
                                       header={"t": 1, "salt": salt, "sig": "0x" + "11" * 65})
        self.assertNotIn(e.key, later.applied)
        self.assertEqual(dict(later.ignored)[e.key], "creator not in ACL")
        self.assertNotIn("Cal, after removal.", later.text)

    def test_update_under_own_derived_client_id_is_applied(self) -> None:
        e, result = self._forged_update(None, 1, 13, "Bea writes as herself.")
        self.assertIn(e.key, result.applied)
        self.assertTrue(result.text.endswith("Bea writes as herself."))
        cid = next(iter(quire_read.update_clients(self._forged_payload_data(e))))
        self.assertEqual(result.authors[cid].address, VEC["members"]["bea"])
        self.assertTrue(result.authors[cid].proven)
        self.assertEqual(result.authors[cid].source, f"update {e.key}")

    def _forged_payload_data(self, e) -> bytes:
        reader, _result = self._member_result()
        return reader._content_frame(e).data

    def test_update_written_early_under_another_id_is_still_ignored(self) -> None:
        # Under first-come binding an update created before every real owner
        # update could take the owner's id. With derived ids, block order
        # plays no part.
        e, result = self._forged_update(OWNER_CLIENT, 1, 2, "Bea, early, as the owner.")
        self.assertNotIn(e.key, result.applied)
        self.assertIn("is not clientIdFor", dict(result.ignored)[e.key])

    def test_update_without_a_valid_salt_is_ignored(self) -> None:
        # With schema checks off, the reader's own salt check still applies.
        sig = sign_salt(BEA_KEY, "ab" * 16)
        cases = {"missing": {"t": 1, "sig": sig}, "short": {"t": 1, "salt": "ab" * 15, "sig": sig},
                 "upper": {"t": 1, "salt": "AB" * 16, "sig": sig}}
        for name, header in cases.items():
            e, result = self._forged_update(None, 1, 13, f"Salt {name}.", header=header,
                                            schemas=quire_read.Schemas(enabled=False))
            self.assertNotIn(e.key, result.applied, name)
            self.assertIn("update salt", dict(result.ignored)[e.key], name)

    def test_mallorys_update_fails_only_the_member_filter(self) -> None:
        # The vectors' forgery has a valid salt and Mallory's own derived id,
        # so it passes the client id check and only the member list stops it.
        reader, result = self._member_result()
        mallory = VEC["members"]["mallory"]
        forged = [e for e in reader.source.entities if e.creator == mallory]  # type: ignore[attr-defined]
        self.assertEqual(len(forged), 1)
        frame = reader._content_frame(forged[0])
        cid = quire_read.client_id_for(mallory, frame.header["salt"])
        self.assertEqual(set(quire_read.update_clients(frame.data)), {cid})
        # Her salt is signed by her own key, so the signature check passes too.
        self.assertEqual(quire_read.salt_signer(VEC["doc"], frame.header["salt"], frame.header["sig"]), mallory)
        self.assertIsNone(quire_read.sig_problem(VEC["doc"], mallory, frame.header["salt"], frame.header["sig"]))
        self.assertEqual(dict(result.ignored)[forged[0].key], "creator not in ACL")

    # -------------------------------------------------------- salt signatures

    def test_eip191_digest_and_salt_message(self) -> None:
        # hashMessage("hello world"), the usual EIP-191 example.
        self.assertEqual(
            quire_read.eip191_digest(b"hello world").hex(),
            "d9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68",
        )
        msg = quire_read.salt_message(VEC["doc"], OWNER_SALT)
        self.assertEqual(msg, b"quire1:salt:" + bytes.fromhex(VEC["doc"][2:]) + bytes.fromhex(OWNER_SALT))
        self.assertEqual(len(msg), 60)  # so the prefix ends in "\n60"
        self.assertEqual(
            quire_read.eip191_digest(msg),
            quire_read.keccak256(b"\x19Ethereum Signed Message:\n60" + msg),
        )

    def test_vector_signatures_recover_to_their_signers(self) -> None:
        # Every update's sig recovers to its $creator, and every snapshot
        # authors entry's sig to its address. These came from another
        # implementation, so they check the curve math independently.
        reader, _result = self._member_result()
        seen = 0
        for e in reader.source.entities:  # type: ignore[attr-defined]
            if e.kind not in ("u", "s"):
                continue
            h = reader._content_frame(e).header
            if e.kind == "u":
                self.assertEqual(quire_read.salt_signer(VEC["doc"], h["salt"], h["sig"]), e.creator, e.key)
                seen += 1
            for entry in h.get("authors", {}).values():
                self.assertEqual(quire_read.salt_signer(VEC["doc"], entry["salt"], entry["sig"]), entry["address"])
                seen += 1
        updates = sum(1 for e in reader.source.entities if e.kind == "u")  # type: ignore[attr-defined]
        self.assertGreater(seen, updates)

    def test_recovery_agrees_with_cryptography(self) -> None:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils

        n = quire_read._N
        for i in range(8):
            key = ec.generate_private_key(ec.SECP256K1())
            digest = os.urandom(32)
            r, s = utils.decode_dss_signature(key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
            want = quire_read.public_key_bytes(key)
            found = []
            for v in (27, 28, 0, 1):
                pub = quire_read.recover_public_key(digest, r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v]))
                self.assertIsNotNone(pub)
                found.append(pub == want)
                # Whatever key comes back, the signature verifies under it.
                ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub).verify(
                    utils.encode_dss_signature(r, s), digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            self.assertEqual(found[0], found[2], i)  # 27 and 0 are one parity
            self.assertEqual(found.count(True), 2, i)  # exactly one parity is the signer
            # A high s recovers the same key with the other parity.
            hi = r.to_bytes(32, "big") + (n - s).to_bytes(32, "big")
            flip = [quire_read.recover_public_key(digest, hi + bytes([v])) == want for v in (27, 28)]
            self.assertEqual(flip, [found[1], found[0]], i)
        bad_digest = os.urandom(32)
        good = bytes.fromhex(sign_salt(BEA_KEY, OWNER_SALT)[2:])
        for sig in (bytes(32) + good[32:], good[:32] + bytes(32) + good[64:],
                    n.to_bytes(32, "big") + good[32:], good[:64] + bytes([29]), good[:64]):
            self.assertIsNone(quire_read.recover_public_key(bad_digest, sig), sig.hex())

    def test_valid_signature_passes(self) -> None:
        salt = os.urandom(16).hex()
        sig = sign_salt(BEA_KEY, salt)
        self.assertEqual(quire_read.salt_signer(VEC["doc"], salt, sig), VEC["members"]["bea"])
        self.assertEqual(quire_read.salt_signer(VEC["doc"], salt, sig.upper().replace("0X", "0x")),
                         VEC["members"]["bea"])  # the schema allows either case
        e, result = self._forged_update(None, 1, 13, "Bea, signed.", salt=salt)
        self.assertIn(e.key, result.applied)
        self.assertTrue(result.text.endswith("Bea, signed."))

    def test_update_signed_by_someone_else_is_ignored(self) -> None:
        # Bea's update and client id, but the salt signed by the owner's key.
        e, result = self._forged_update(None, 1, 13, "Bea, owner's signature.", signer=OWNER_KEY)
        self.assertNotIn(e.key, result.applied)
        self.assertEqual(dict(result.ignored)[e.key],
                         f"update sig recovers to {VEC['owner']}, not to its creator")
        self.assertEqual(result.text, VEC["expected"]["memberText"])

    def test_update_sig_bound_to_document_and_salt(self) -> None:
        # Bea's own signature, but over another document's id, or another salt.
        salt = os.urandom(16).hex()
        cases = {
            "another document": {"t": 1, "salt": salt, "sig": sign_salt(BEA_KEY, salt, OTHER_DOC)},
            "another salt": {"t": 1, "salt": salt, "sig": sign_salt(BEA_KEY, os.urandom(16).hex())},
        }
        for name, header in cases.items():
            e, result = self._forged_update(None, 1, 13, name, salt=salt, header=header)
            self.assertNotIn(e.key, result.applied, name)
            self.assertIn("update sig recovers to 0x", dict(result.ignored)[e.key], name)
            self.assertNotIn(VEC["members"]["bea"], dict(result.ignored)[e.key], name)

    def test_update_without_a_valid_sig_is_ignored(self) -> None:
        salt = os.urandom(16).hex()
        good = sign_salt(BEA_KEY, salt)
        cases = {
            "missing": ({"t": 1, "salt": salt}, "sig is missing"),
            "short": ({"t": 1, "salt": salt, "sig": good[:-2]}, "sig is missing"),
            "no 0x": ({"t": 1, "salt": salt, "sig": good[2:] + "00"}, "sig is missing"),
            "v 29": ({"t": 1, "salt": salt, "sig": good[:-2] + "1d"}, "sig recovers no key"),
            "r zero": ({"t": 1, "salt": salt, "sig": "0x" + "00" * 32 + good[66:]}, "sig recovers no key"),
        }
        for name, (header, reason) in cases.items():
            # Schema checks off, so the reader's own check is what rejects.
            e, result = self._forged_update(None, 1, 13, f"Sig {name}.", salt=salt, header=header,
                                            schemas=quire_read.Schemas(enabled=False))
            self.assertNotIn(e.key, result.applied, name)
            self.assertIn(reason, dict(result.ignored)[e.key], name)

    @unittest.skipIf(SCHEMA_SKIP, SCHEMA_SKIP)
    def test_update_without_sig_fails_schema(self) -> None:
        salt = os.urandom(16).hex()
        e, result = self._forged_update(None, 1, 13, "No sig.", salt=salt, header={"t": 1, "salt": salt})
        self.assertNotIn(e.key, result.applied)
        self.assertIn("'sig' is a required property", dict(result.ignored)[e.key])

    # -------------------------------------------------------- takeover

    def test_takeover_of_a_snapshot_attributed_id_is_ignored(self) -> None:
        # With Cal's update expired, his id is attributed only by the newest
        # snapshot's authors entry. Bea finds a salt whose clientIdFor
        # collides with it, signs it, and writes under it. The derivation and
        # signature checks pass; the takeover rule does not, even with the
        # update created before the snapshot.
        salt = os.urandom(16).hex()
        for block in (2, 13):
            with collide(VEC["members"]["bea"], salt, CAL_CLIENT):
                e, _full = self._forged_update(None, 1, block, "Bea, under Cal's id.", salt=salt)
                result = self._read(without_cal_update(quire_audit.load_vectors(DOCUMENT)[1]) + [e])
            self.assertNotIn(e.key, result.applied, block)
            self.assertEqual(
                dict(result.ignored)[e.key],
                f"Yjs client id {CAL_CLIENT} is already attributed to {VEC['members']['cal']}"
                f" by snapshot {result.newest_snapshot}",
            )
            self.assertEqual(result.authors[CAL_CLIENT].address, VEC["members"]["cal"])
            self.assertEqual(result.text, VEC["expected"]["memberText"])

    def test_takeover_of_an_update_attributed_id_is_ignored(self) -> None:
        # Two members' updates under one client id: whichever was created
        # first keeps it, and the other is ignored, in any query order.
        bea, owner = VEC["members"]["bea"], VEC["owner"]
        bea_salt, owner_salt = os.urandom(16).hex(), os.urandom(16).hex()
        cid = quire_read.client_id_for(bea, bea_salt)
        for first, second in ((bea, owner), (owner, bea)):
            salts = {bea: bea_salt, owner: owner_salt}
            with collide(owner, owner_salt, cid):
                early, _ = self._forged_update(None, 1, 12, f"{first} first.", creator=first, salt=salts[first])
                late, result = self._forged_update(None, 1, 13, f"{second} second.", creator=second,
                                                   salt=salts[second], extra=[early])
                self.assertIn(early.key, result.applied)
                self.assertNotIn(late.key, result.applied)
                self.assertEqual(dict(result.ignored)[late.key],
                                 f"Yjs client id {cid} is already attributed to {first} by update {early.key}")
                self.assertEqual((result.authors[cid].address, result.authors[cid].proven), (first, True))
                self.assertIn(f"{first} first.", result.text)
                self.assertNotIn(f"{second} second.", result.text)
                for seed in range(3):
                    entities = quire_audit.load_vectors(DOCUMENT)[1] + [late, early]
                    random.Random(seed).shuffle(entities)
                    again = self._reader(entities).read()
                    self.assertEqual(again.applied, result.applied, seed)
                    self.assertEqual(again.text, result.text, seed)

    def test_same_address_with_two_salts_is_not_a_takeover(self) -> None:
        # The rule is about a different address; two sessions of one writer
        # landing on one id (again a collision) are both kept.
        bea = VEC["members"]["bea"]
        s1, s2 = os.urandom(16).hex(), os.urandom(16).hex()
        cid = quire_read.client_id_for(bea, s1)
        with collide(bea, s2, cid):
            first, _ = self._forged_update(None, 1, 12, "Session one.", salt=s1)
            second, result = self._forged_update(None, 1, 13, "Session two.", salt=s2, extra=[first])
        self.assertIn(first.key, result.applied)
        # not a takeover: same address. But both sessions wrote the same
        # clocks from one base, so the later one conflicts and is ignored
        reason = dict(result.ignored)[second.key]
        self.assertNotIn("already attributed", reason)
        self.assertIn("puts different content at client", reason)

    def test_update_check_does_not_depend_on_order(self) -> None:
        good, _ = self._forged_update(None, 1, 13, "Bea, valid.", key=fake_key(0x02))
        bad, _ = self._forged_update(OWNER_CLIENT, 1, 13, "Bea, as owner.", key=fake_key(0x01))
        applied = None
        for seed in range(4):
            entities = quire_audit.load_vectors(DOCUMENT)[1] + [good, bad]
            random.Random(seed).shuffle(entities)
            again = self._reader(entities).read()
            self.assertIn(good.key, again.applied)
            self.assertNotIn(bad.key, again.applied)
            applied = applied or again.applied
            self.assertEqual(again.applied, applied)

    # -------------------------------------------------------- snapshot authors

    def test_vector_snapshot_authors_are_claimed(self) -> None:
        _reader = self._reader(without_cal_update(quire_audit.load_vectors(DOCUMENT)[1]))
        result = _reader.read()
        self.assertEqual(result.dropped_authors, [])
        cal = result.authors[CAL_CLIENT]
        self.assertEqual((cal.address, cal.proven), (VEC["members"]["cal"], False))
        self.assertEqual(cal.source, f"snapshot {result.newest_snapshot}")
        self.assertEqual(cal.via, newest_snapshot(_reader.source.entities).creator)  # type: ignore[attr-defined]
        # The owner's and Bea's ids are also used by applied updates.
        self.assertTrue(result.authors[OWNER_CLIENT].proven)
        self.assertTrue(result.authors[BEA_CLIENT].proven)

    def _snapshot_with_authors(self, authors: dict):
        """A newest snapshot by the owner with a given authors map."""
        reader, result = self._member_result()
        data = result.doc.get_update()
        template = newest_snapshot(quire_audit.load_vectors(DOCUMENT)[1])
        e = make_entity(
            template, key=fake_key(0x5C), kind="s", creator=VEC["owner"], block=13,
            payload=seal("s", 1, snapshot_header(data, 13, authors=authors), data, reader.keys[1]),
        )
        return e, self._reader(quire_audit.load_vectors(DOCUMENT)[1] + [e]).read()

    def test_valid_snapshot_author_is_accepted_as_claimed(self) -> None:
        salt = os.urandom(16).hex()
        cid = quire_read.client_id_for(VEC["members"]["bea"], salt)
        e, result = self._snapshot_with_authors({str(cid): author_entry(VEC["members"]["bea"], salt)})
        self.assertEqual(result.newest_snapshot, e.key)
        self.assertEqual(result.dropped_authors, [])
        a = result.authors[cid]
        self.assertEqual((a.address, a.salt, a.proven, a.source, a.via),
                         (VEC["members"]["bea"], salt, False, f"snapshot {e.key}", VEC["owner"]))

    def test_forged_snapshot_authors_are_dropped(self) -> None:
        # Bea's address under the owner's id, the owner's id with a wrong
        # salt, a non-canonical key and a bare address (the old shape). The
        # snapshot itself is still applied: authors is attribution only.
        bea = VEC["members"]["bea"]
        forged = {
            str(OWNER_CLIENT): author_entry(bea, OWNER_SALT),
            "4242": author_entry(VEC["owner"], "00" * 16),
            "0" + str(BEA_CLIENT): author_entry(bea, "00" * 16),
        }
        e, result = self._snapshot_with_authors(forged)
        self.assertEqual(result.newest_snapshot, e.key)
        self.assertEqual(len([d for d in result.dropped_authors if e.key in d]), 3)
        self.assertNotIn(4242, result.authors)
        self.assertEqual(result.authors[OWNER_CLIENT].address, VEC["owner"])
        self.assertTrue(result.authors[OWNER_CLIENT].proven)
        self.assertEqual(result.text, VEC["expected"]["memberText"])
        # The old {clientId: address} shape fails the schema, which ignores
        # the whole snapshot; without schema checks only the entry is dropped.
        doc = VEC["doc"]
        self.assertEqual(quire_read.author_problem(str(OWNER_CLIENT), VEC["owner"], doc),
                         "entry is not {address, salt, sig}")
        self.assertIsNone(quire_read.author_problem(str(OWNER_CLIENT), author_entry(VEC["owner"], OWNER_SALT), doc))

    def test_snapshot_author_with_missing_or_wrong_sig_is_dropped(self) -> None:
        bea, owner = VEC["members"]["bea"], VEC["owner"]
        salts = [os.urandom(16).hex() for _ in range(4)]
        cids = [quire_read.client_id_for(bea, salt) for salt in salts]
        entries = {
            str(cids[0]): author_entry(bea, salts[0], signer=OWNER_KEY),  # someone else's signature
            str(cids[1]): author_entry(bea, salts[1], doc=OTHER_DOC),  # Bea's, for another document
            str(cids[2]): dict(author_entry(bea, salts[2]), sig="0x" + "11" * 65),  # recovers nothing useful
            str(cids[3]): author_entry(bea, salts[3]),  # valid
        }
        e, result = self._snapshot_with_authors(entries)
        self.assertEqual(result.newest_snapshot, e.key)  # still applied: authors is attribution only
        self.assertEqual(result.text, VEC["expected"]["memberText"])
        dropped = [d for d in result.dropped_authors if e.key in d]
        self.assertEqual(len(dropped), 3)
        self.assertIn(f"client id {cids[0]}: sig recovers to {owner}", " ".join(dropped))
        self.assertIn(f"client id {cids[1]}: sig recovers", " ".join(dropped))
        self.assertIn(f"client id {cids[2]}: sig recovers", " ".join(dropped))
        for cid in cids[:3]:
            self.assertNotIn(cid, result.authors)
        self.assertEqual((result.authors[cids[3]].address, result.authors[cids[3]].via), (bea, owner))
        # A missing sig breaks the header schema, so the whole snapshot is
        # ignored, with schema checks off too: the verdict never depends on
        # whether jsonschema is installed.
        salt = os.urandom(16).hex()
        cid = quire_read.client_id_for(bea, salt)
        reader, base = self._member_result()
        data = base.doc.get_update()
        template = newest_snapshot(quire_audit.load_vectors(DOCUMENT)[1])
        snap = make_entity(
            template, key=fake_key(0x5D), kind="s", creator=owner, block=13,
            payload=seal("s", 1, snapshot_header(data, 13, authors={str(cid): {"address": bea, "salt": salt}}),
                         data, reader.keys[1]),
        )
        data_, loaded = quire_audit.load_vectors(DOCUMENT)
        out = quire_read.Reader(
            quire_read.parse_link(data_["link"]), quire_read.VectorSource(loaded + [snap]),
            quire_read.load_private_key(BEA_KEY), schemas=quire_read.Schemas(enabled=False),
        ).read()
        self.assertNotIn(snap.key, out.applied)
        self.assertIn("does not have exactly address, salt and sig", dict(out.ignored)[snap.key])
        self.assertNotIn(cid, out.authors)
        # With schema checks on, the same header fails the schema and the
        # whole snapshot is ignored.
        if not SCHEMA_SKIP:
            out = self._reader(quire_audit.load_vectors(DOCUMENT)[1] + [snap]).read()
            self.assertNotIn(snap.key, out.applied)
            self.assertIn("'sig' is a required property", dict(out.ignored)[snap.key])

    def test_conflicting_snapshot_author_is_dropped(self) -> None:
        # A valid entry for an id the newest snapshot already gives to
        # someone else (a collision, forced here) is dropped.
        bea, cal = VEC["members"]["bea"], VEC["members"]["cal"]
        salt = os.urandom(16).hex()
        with collide(bea, salt, CAL_CLIENT):
            older = 9
            reader, base = self._member_result()
            data = base.doc.get_update()
            template = newest_snapshot(quire_audit.load_vectors(DOCUMENT)[1])
            snap = make_entity(
                template, key=fake_key(0x5E), kind="s", creator=VEC["owner"], block=older,
                payload=seal("s", 1, snapshot_header(data, older, authors={str(CAL_CLIENT): author_entry(bea, salt)}),
                             data, reader.keys[1]),
            )
            # the owner's newest snapshot, so step 3 applies it (after Bea's newer one)
            others = [x for x in quire_audit.load_vectors(DOCUMENT)[1] if not (x.kind == "s" and x.creator == VEC["owner"])]
            result = self._reader(others + [snap]).read()
        self.assertIn(snap.key, result.applied)
        self.assertEqual(result.authors[CAL_CLIENT].address, cal)
        self.assertIn(f"snapshot {snap.key}: client id {CAL_CLIENT}: already attributed to {cal}",
                      " ".join(result.dropped_authors))

    # -------------------------------------------------------- round 2 rules

    def _snapshot(self, data: bytes, *, creator: str, block: int, key: str, authors=None,
                  base: int | None = None, qs: int | None = None, header: dict | None = None, epoch: int = 1):
        """A snapshot entity holding `data`, created at `block`."""
        reader, _result = self._member_result()
        template = newest_snapshot(quire_audit.load_vectors(DOCUMENT)[1])
        h = header if header is not None else snapshot_header(data, block if base is None else base, authors=authors)
        e = make_entity(template, key=key, kind="s", creator=creator, block=block,
                        payload=seal("s", epoch, h, data, reader.keys[epoch]))
        if qs is not None:
            e.attributes = [quire_audit.Attribute(a.name, a.type, qs if a.name == "qs" else a.value)
                            for a in e.attributes]
        return e

    def _read(self, entities, **kw):
        data, _ = quire_audit.load_vectors(DOCUMENT)
        return quire_read.Reader(
            quire_read.parse_link(data["link"]), quire_read.VectorSource(entities),
            quire_read.load_private_key(kw.pop("key", BEA_KEY)), **kw,
        ).read()

    def test_update_with_qs_after_created_at_is_ignored(self) -> None:
        e, _ = self._forged_update(None, 1, 13, "From the future.")
        for qs, applied in ((14, False), (13, True), (12, True)):
            e.attributes = [quire_audit.Attribute(a.name, a.type, qs if a.name == "qs" else a.value)
                            for a in e.attributes]
            result = self._read(quire_audit.load_vectors(DOCUMENT)[1] + [e])
            self.assertEqual(e.key in result.applied, applied, qs)
            if not applied:
                self.assertEqual(dict(result.ignored)[e.key], "qs 14 is after createdAt 13")

    def test_update_with_qs_backdated_past_the_margin_is_ignored(self) -> None:
        # Section 5: cold readers fetch updates with qs >= base - 60, so an
        # update whose qs is more than 60 blocks before its createdAt would
        # be applied live and missed cold. Every reader ignores it.
        e, _ = self._forged_update(None, 1, 200, "Backdated.")
        for qs, applied in ((139, False), (140, True)):
            e.attributes = [quire_audit.Attribute(a.name, a.type, qs if a.name == "qs" else a.value)
                            for a in e.attributes]
            result = self._read(quire_audit.load_vectors(DOCUMENT)[1] + [e])
            self.assertEqual(e.key in result.applied, applied, qs)
            if not applied:
                self.assertEqual(dict(result.ignored)[e.key], "qs 139 is more than 60 blocks before createdAt 200")

    def test_snapshot_with_qs_or_base_after_created_at_is_ignored(self) -> None:
        _reader, base_result = self._member_result()
        data = base_result.doc.get_update()
        cases = {
            "qs": (dict(qs=14), "qs 14 is after createdAt 13"),
            "base": (dict(base=14), "base 14 is after createdAt 13"),
        }
        for name, (kw, reason) in cases.items():
            e = self._snapshot(data, creator=VEC["owner"], block=13, key=fake_key(0x5F0), **kw)
            result = self._read(quire_audit.load_vectors(DOCUMENT)[1] + [e])
            self.assertNotIn(e.key, result.applied, name)
            self.assertIn(reason, dict(result.ignored)[e.key], name)
            self.assertEqual(result.newest_snapshot, base_result.newest_snapshot, name)
            self.assertEqual(result.text, VEC["expected"]["memberText"], name)
        ok = self._snapshot(data, creator=VEC["owner"], block=13, key=fake_key(0x5F1), base=13, qs=13)
        self.assertEqual(self._read(quire_audit.load_vectors(DOCUMENT)[1] + [ok]).newest_snapshot, ok.key)

    def test_malformed_entities_never_stop_the_read(self) -> None:
        # Section 5: undecodable Yjs data and bad header types are ignored,
        # with and without schema checks, and the document still opens.
        reader, base_result = self._member_result()
        data = base_result.doc.get_update()
        salt = os.urandom(16).hex()
        signed = {"t": 1, "salt": salt, "sig": sign_salt(BEA_KEY, salt)}
        template = bea_update(quire_audit.load_vectors(DOCUMENT)[1])

        def update(n: int, header, body: bytes):
            return make_entity(template, key=fake_key(0xBAD0 + n), kind="u", creator=VEC["members"]["bea"],
                               block=13, payload=seal("u", 1, header, body, reader.keys[1]))

        bad_header = dict(snapshot_header(data, 13), chunks="not a list", size="many")
        hostile = [
            update(1, signed, os.urandom(40)),  # random bytes as Yjs
            update(2, signed, b"\x01\x01\xb9\x60\x00\x04\x01\x01\xff"),  # string that is not UTF-8
            update(3, signed, data + b"\x00"),  # trailing bytes
            update(4, dict(signed, t="noon"), b"\x00\x00"),
            update(5, dict(signed, salt=12345), b"\x00\x00"),
            update(6, dict(signed, sig=["not", "a", "string"]), b"\x00\x00"),
            update(7, [1, 2, 3], b"\x00\x00"),  # header is not an object
            self._snapshot(data, creator=VEC["owner"], block=13, key=fake_key(0xBAD8), header=bad_header),
            self._snapshot(os.urandom(64), creator=VEC["owner"], block=13, key=fake_key(0xBAD9)),
            self._snapshot(data, creator=VEC["owner"], block=13, key=fake_key(0xBADA),
                           header=dict(snapshot_header(data, 13), authors=["x"])),
        ]
        for schemas in (quire_read.Schemas(enabled=False), None):
            result = self._read(quire_audit.load_vectors(DOCUMENT)[1] + hostile, schemas=schemas)
            self.assertEqual(result.text, VEC["expected"]["memberText"])
            ignored = dict(result.ignored)
            for e in hostile:
                self.assertNotIn(e.key, result.applied, e.key)
                self.assertIn(e.key, ignored, e.key)
            # The newest valid snapshot is still found behind the broken ones.
            self.assertEqual(result.newest_snapshot, base_result.newest_snapshot)
        # Each is ignored for its own reason, not a crash in a later step.
        result = self._read(quire_audit.load_vectors(DOCUMENT)[1] + hostile, schemas=quire_read.Schemas(enabled=False))
        reasons = [dict(result.ignored)[e.key] for e in hostile]
        self.assertIn("update header t is not an integer", reasons[3])
        self.assertIn("update salt", reasons[4])
        self.assertIn("sig is missing", reasons[5])
        self.assertIn("frame header is not a JSON object", reasons[6])
        self.assertIn("chunks is not a list", reasons[7])
        self.assertIn("authors is not an object", reasons[9])

    def test_updates_are_applied_before_snapshots(self) -> None:
        _reader, result = self._member_result()
        kinds = [result.kinds[k] for k in result.applied if result.kinds[k] in ("u", "s")]
        self.assertEqual(kinds, sorted(kinds, key=lambda k: k != "u"))
        self.assertIn("s", kinds)
        self.assertIn("u", kinds)

    def _forged_owner_snapshot(self):
        """Bea's snapshot that carries, under the owner's id, a paragraph
        at the clocks of the owner's last (verified) update."""
        reader, _result = self._member_result()
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        late = owner_late_update(entities)
        start = quire_read.update_clients(reader._content_frame(late).data)[OWNER_CLIENT][0][0]
        # The owner's state just before that update: the owner's own snapshot
        # from before it, which holds his clocks up to `start`.
        before = max((e for e in entities if e.kind == "s" and e.creator == VEC["owner"]
                      and e.created_at < late.created_at), key=_qs)
        d = Doc(client_id=OWNER_CLIENT)
        d.apply_update(reader._content_frame(before).data)
        self.assertEqual(quire_read.update_clients(d.get_update())[OWNER_CLIENT][-1][1], start)
        d.get("default", type=XmlFragment).children.append(
            XmlElement("paragraph", None, [XmlText("FORGED: the owner never wrote this.")]))
        forged = self._snapshot(d.get_update(), creator=VEC["members"]["bea"], block=13, key=fake_key(0xF0F))
        return forged, start, entities

    def test_the_vectors_malformed_header_is_ignored(self) -> None:
        # The vectors carry one epoch 1 update by Bea whose header has t as a
        # string. It decrypts and Bea is a member, but section 5 says ignore it.
        result = self._member_result()[1]
        reasons = [r for _k, r in result.ignored if "t is not an integer" in r or "'0' is not of type 'integer'" in r]
        self.assertEqual(len(reasons), 1, result.ignored)
        self.assertNotIn("MALFORMED", result.text)

    def test_edge_cases(self) -> None:
        # spec/vectors/cases: one crafted member entity each, with the text
        # every reader must produce (number forms, BOM, size, ties, qs).
        folder = os.path.join(VECTORS, "cases")
        cases = sorted(f for f in os.listdir(folder) if f.endswith(".json"))
        self.assertGreaterEqual(len(cases), 7)
        for name in cases:
            with self.subTest(case=name):
                data, entities = quire_audit.load_vectors(os.path.join(folder, name))
                result = quire_read.Reader(quire_read.parse_link(data["link"]), quire_read.VectorSource(entities)).read()
                self.assertEqual(result.text, data["expected"]["text"], data["description"])

    def test_an_empty_newer_snapshot_cannot_erase_the_document(self) -> None:
        # Section 5 step 3: each member's newest snapshot is applied, so Bea's
        # empty one, newer than everything, replaces only her own contribution.
        empty = Doc().get_update()
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        e = self._snapshot(empty, creator=VEC["members"]["bea"], block=13, key=fake_key(0xE0E))
        result = self._read(entities + [e])
        self.assertIn(e.key, result.applied)
        self.assertEqual(result.text, VEC["expected"]["memberText"])

    def test_snapshot_conflicting_with_a_verified_update_is_refused(self) -> None:
        forged, start, entities = self._forged_owner_snapshot()
        for drop_first in (False, True):
            # With the owner's first update gone (expired), his last one waits
            # on clocks only the snapshots have: the pending case.
            ents = [e for e in entities if not (drop_first and e.kind == "u" and e.creator == VEC["owner"]
                                                and e is not owner_late_update(entities))]
            result = self._read(ents + [forged])
            self.assertNotIn(forged.key, result.applied, drop_first)
            # The paragraph and text type items match the genuine ones; the
            # first differing item is a character of the text.
            reason = dict(result.ignored)[forged.key]
            self.assertRegex(reason, rf"^snapshot carries an item at client {OWNER_CLIENT} clock (\d+)"
                                     " that differs from a verified update's$")
            self.assertGreaterEqual(int(reason.split(" clock ")[1].split()[0]), start)
            # step 3: Bea's newest snapshot was refused, so she contributes none; the owner's stands
            self.assertNotEqual(result.newest_snapshot, forged.key)
            owner_newest = max((e for e in entities if e.kind == "s" and e.creator == VEC["owner"]), key=_qs)
            self.assertIn(owner_newest.key, result.applied)
            self.assertEqual(result.text, VEC["expected"]["memberText"], drop_first)

    def test_updates_first_alone_does_not_stop_a_pending_override(self) -> None:
        # Why the refusal above exists. Applying updates first protects a
        # genuine update whose dependencies are already integrated, but not
        # one still waiting on items only a snapshot has: when the snapshot
        # fills the gap, Yjs takes the snapshot's struct at the same clock.
        # In the vectors the owner's epoch 1 paragraph follows Cal's line,
        # which only the snapshots carry, so that update is always pending.
        a = Doc(client_id=77)
        frag = a.get("default", type=XmlFragment)
        frag.children.append(XmlElement("paragraph", None, [XmlText("Hello")]))
        sv = a.get_state()
        first = a.get_update()
        frag.children[0].children[0].insert(5, " world")
        genuine = a.get_update(sv)
        f = Doc(client_id=77)
        f.apply_update(first)
        f.get("default", type=XmlFragment).children[0].children[0].insert(5, " fakes")
        forged_state = f.get_update()

        def opened(*updates: bytes) -> str:
            d = Doc()
            for u in updates:
                d.apply_update(u)
            return quire_read.fragment_text(d.get("default", type=XmlFragment))

        self.assertEqual(opened(first, genuine, forged_state), "Hello world")  # dependencies present
        self.assertEqual(opened(genuine, forged_state), "Hello fakes")  # genuine update pending
        # The same happens to the vectors' owner update without the refusal.
        forged, _start, entities = self._forged_owner_snapshot()
        entities = without_cal_update(entities)  # the owner's update waits on Cal's line
        original = quire_read.Reader.refuse
        quire_read.Reader.refuse = lambda self, snapshots, verified: {}
        try:
            result = self._read(entities + [forged])
        finally:
            quire_read.Reader.refuse = original
        self.assertIn("FORGED", result.text)
        self.assertNotIn("Written in epoch 1, after Cal left.", result.text)

    def test_snapshot_under_the_readers_own_id_is_refused(self) -> None:
        # Section 5: a snapshot with structs under the reader's own client id
        # beyond what the reader wrote is someone writing as the reader.
        _reader, base_result = self._member_result()
        bea_salt = _SESSIONS[VEC["members"]["bea"]][1]
        d = Doc(client_id=BEA_CLIENT)
        d.apply_update(base_result.doc.get_update())
        d.get("default", type=XmlFragment).children.append(
            XmlElement("paragraph", None, [XmlText("The owner, writing as Bea.")]))
        snap = self._snapshot(d.get_update(), creator=VEC["owner"], block=13, key=fake_key(0x0E0))
        ents = quire_audit.load_vectors(DOCUMENT)[1] + [snap]
        mine = self._read(ents, own_salt=bea_salt)
        self.assertNotIn(snap.key, mine.applied)
        self.assertIn(f"under this reader's own client id {BEA_CLIENT}", dict(mine.ignored)[snap.key])
        self.assertEqual(mine.text, VEC["expected"]["memberText"])
        # Another reader has no own id to protect: the snapshot is applied,
        # and the new text is claimed, not proven.
        other = self._read(ents)
        self.assertIn(snap.key, other.applied)
        self.assertTrue(other.text.endswith("The owner, writing as Bea."))
        claimed = [r for r in other.ranges if r.client == BEA_CLIENT and not r.proven]
        self.assertEqual(len(claimed), 1)
        self.assertIn("The owner, writing as Bea.", claimed[0].text)
        self.assertEqual(claimed[0].via, [VEC["owner"]])
        # A Bea session with a different salt has a different id: no refusal.
        self.assertIn(snap.key, self._read(ents, own_salt=os.urandom(16).hex()).applied)

    def test_vector_text_ranges(self) -> None:
        _reader = self._reader(without_cal_update(quire_audit.load_vectors(DOCUMENT)[1]))
        result = _reader.read()
        by_client = defaultdict(list)
        for r in result.ranges:
            by_client[r.client].append(r)
        # Owner and Bea: everything arrived in verified updates.
        for cid in (OWNER_CLIENT, BEA_CLIENT):
            self.assertTrue(all(r.proven for r in by_client[cid]), cid)
        # Cal's update has expired here: his line is claimed,
        # through every snapshot that carries it, newest first.
        cal = by_client[CAL_CLIENT]
        self.assertEqual([r.proven for r in cal], [False])
        self.assertIn("Cal adds a line before being removed.", cal[0].text)
        carriers = sorted((e for e in _reader.source.entities if e.kind == "s"  # type: ignore[attr-defined]
                           and e.key in result.applied), key=_qs, reverse=True)
        self.assertEqual(cal[0].via[0], carriers[0].creator)

    def _merged(self, with_first_update: bool):
        """Bea writes "Bea one" (update A), then " two" onto the same text
        (update B). The owner's snapshot holds A. Yjs merges the two runs
        into one item, "Bea one two"."""
        reader, base_result = self._member_result()
        bea = VEC["members"]["bea"]
        salt = os.urandom(16).hex()
        cid = quire_read.client_id_for(bea, salt)
        d = Doc(client_id=cid)
        d.apply_update(base_result.doc.get_update())
        sv0 = d.get_state()
        d.get("default", type=XmlFragment).children.append(XmlElement("paragraph", None, [XmlText("Bea one")]))
        sv1 = d.get_state()
        a_data, after_a = d.get_update(sv0), d.get_update()
        frag = d.get("default", type=XmlFragment)
        text = frag.children[len(frag.children) - 1].children[0]
        text += " two"
        b_data = d.get_update(sv1)
        header = {"t": 1, "salt": salt, "sig": sign_salt(BEA_KEY, salt)}
        template = bea_update(quire_audit.load_vectors(DOCUMENT)[1])
        a = make_entity(template, key=fake_key(0xA1), kind="u", creator=bea, block=12,
                        payload=seal("u", 1, header, a_data, reader.keys[1]))
        b = make_entity(template, key=fake_key(0xA2), kind="u", creator=bea, block=13,
                        payload=seal("u", 1, header, b_data, reader.keys[1]))
        snap = self._snapshot(after_a, creator=VEC["owner"], block=12, key=fake_key(0xA3),
                              authors={str(cid): author_entry(bea, salt)})
        ents = quire_audit.load_vectors(DOCUMENT)[1] + [snap, b] + ([a] if with_first_update else [])
        result = self._read(ents)
        b_range = quire_read.update_clients(b_data)[cid][0]
        return result, cid, b_range

    def test_merged_item_is_proven_only_if_wholly_covered(self) -> None:
        result, cid, b_range = self._merged(with_first_update=True)
        self.assertTrue(result.text.endswith("Bea one two"))
        ranges = [r for r in result.ranges if r.client == cid]
        self.assertTrue(all(r.proven for r in ranges))
        # Without update A, A's clocks came only in the snapshot. B's clocks
        # did arrive verified, but they are part of one merged item with A's,
        # so the whole item is claimed.
        result, cid, b_range = self._merged(with_first_update=False)
        self.assertTrue(result.text.endswith("Bea one two"))
        string = next(s for s in quire_read.update_structs(result.doc.get_update())
                      if s.client == cid and s.text and "two" in s.text)
        self.assertEqual(string.text, "Bea one two")  # one merged item
        self.assertLess(string.clock, b_range[0])
        self.assertEqual(string.end, b_range[1])
        claimed = [r for r in result.ranges if r.client == cid and not r.proven]
        self.assertEqual(len(claimed), 1)
        self.assertIn("Bea one two", claimed[0].text)
        self.assertLessEqual(claimed[0].start, string.clock)
        self.assertEqual(claimed[0].end, b_range[1])
        self.assertEqual(claimed[0].via, [VEC["owner"]])

    def test_merged_ranges_in_the_report(self) -> None:
        result, cid, _b = self._merged(with_first_update=False)
        reader = self._reader()
        out = quire_read.trust_report(reader, result)
        self.assertIn("text ranges", out)
        self.assertRegex(out, rf"{cid}\s+\d+\.\.\d+ claimed {VEC['members']['bea']} via {VEC['owner']}.*'Bea one two'")

    # -------------------------------------------------------- ACL

    def _acl_with_roster(self, change):
        """Re-seal the ACL with a roster edited by `change`."""
        reader, _result = self._member_result()
        data, entities = quire_audit.load_vectors(DOCUMENT)
        link = quire_read.parse_link(data["link"])
        acl = next(e for e in entities if e.kind == "a")
        header = quire_read.decrypt_frame(acl, quire_read.meta_key(link.secret), link.doc).header
        k1 = reader.keys[1]
        roster = json.loads(quire_read.open_envelope(k1, quire_audit._hex_bytes(header["roster"])))
        change(roster)
        iv = os.urandom(12)
        sealed = iv + AESGCM(k1).encrypt(iv, json.dumps(roster, separators=(",", ":")).encode(), None)
        header = dict(header, roster="0x" + sealed.hex())
        acl.payload = seal("a", 0, header, b"", quire_read.meta_key(link.secret))
        return self._reader(entities)

    def test_roster_rebuilt_unchanged_reads(self) -> None:
        result = self._acl_with_roster(lambda r: None).read()
        self.assertEqual(result.text, VEC["expected"]["memberText"])

    def test_roster_for_another_document_is_rejected(self) -> None:
        reader = self._acl_with_roster(lambda r: r.update(doc="0x" + "cd" * 32))
        with self.assertRaisesRegex(RuntimeError, "names document"):
            reader.read()

    def test_roster_for_another_epoch_is_rejected(self) -> None:
        # Schema allows epoch >= 1, so this is caught by the binding check.
        reader = self._acl_with_roster(lambda r: r.update(epoch=2))
        with self.assertRaisesRegex(RuntimeError, "names epoch"):
            reader.read()

    def test_wraps_are_an_unlabelled_list(self) -> None:
        reader, result = self._member_result()
        wraps = result.acl["wraps"]
        self.assertIsInstance(wraps, list)
        self.assertEqual(len(wraps), 2)  # owner and Bea; Cal was removed
        self.assertIsNotNone(reader.unwrapped_index)
        # Either order opens, and the other member's key opens the other entry.
        owner_reader = self._reader(key=OWNER_KEY)
        owner_reader.read()
        self.assertEqual({reader.unwrapped_index, owner_reader.unwrapped_index}, {0, 1})

    # -------------------------------------------------------- epochs

    def test_old_epoch_update_after_revocation_is_applied(self) -> None:
        # Section 5: an update sent under an older epoch is still applied.
        e, result = self._forged_update(None, 0, 12, "Old key, after Cal left.")
        self.assertIn(e.key, result.applied)
        self.assertTrue(result.text.endswith("Old key, after Cal left."))

    def test_old_epoch_update_before_revocation_is_applied(self) -> None:
        e, result = self._forged_update(None, 0, 9, "Old key, before Cal left.")
        self.assertIn(e.key, result.applied)
        self.assertIn("Old key, before Cal left.", result.text)

    # -------------------------------------------------------- verify

    def test_verify_report_as_owner(self) -> None:
        code, out = run_cli(
            quire_read.main, "--vectors", DOCUMENT, "--member-key", OWNER_KEY, "--verify"
        )
        self.assertEqual(code, 0)
        self.assertIn(f"owner        {VEC['owner']}", out)
        self.assertIn("hashes to owner: yes", out)
        self.assertIn("epoch        1", out)
        self.assertIn("members      2", out)
        self.assertIn("1 x creator not in ACL", out)
        self.assertIn("join requests 2", out)
        self.assertIn(f"{OWNER_CLIENT}  {VEC['owner']} Owner    proven", out)
        # Cal was removed, but his line was written before that, so it stays proven
        self.assertIn(f"{CAL_CLIENT}  {VEC['members']['cal']} revoked  proven  update", out)
        self.assertRegex(out, rf"{CAL_CLIENT}\s+0\.\.\d+ proven\s+{VEC['members']['cal']}")
        self.assertIn("129 of 129 clocks proven", out)
        self.assertRegex(out, rf"{OWNER_CLIENT}\s+0\.\.\d+ proven ")
        self.assertIn("acl flags    permissionless extension (raw 2)  expected permissionless extension only: yes", out)
        self.assertNotIn("dropped:", out)
        self.assertNotIn(": NO", out)

    def test_verify_report_as_link_holder(self) -> None:
        code, out = run_cli(quire_read.main, "--vectors", DOCUMENT, "--verify")
        self.assertEqual(code, 0)
        self.assertIn("members      not visible", out)
        self.assertNotIn("join requests", out)
        # Section 3: wraps are unlabelled, so the report gives a count and no
        # member address other than the owner's, which is in the link.
        self.assertIn("wraps        2", out)
        for name in ("bea", "cal"):
            self.assertNotIn(VEC["members"][name], out)
        self.assertNotIn("wrap addresses", out)

    # -------------------------------------------------------- versions

    def _version(self, *, chunks: int = 0, chunk_epoch: int | None = None, chunk_flags: bool = True,
                 epoch: int = 0, head_flags: bool = True, authors: dict | None = None):
        """A published version built in memory from a fresh random key."""
        _reader, result = self._member_result()
        vkey = os.urandom(32)
        data = result.doc.get_update()
        cut = [len(data) * i // (chunks + 1) for i in range(chunks + 2)]
        parts = [data[cut[i]:cut[i + 1]] for i in range(chunks + 1)]
        template = newest_snapshot(quire_audit.load_vectors(DOCUMENT)[1])
        ckeys = [fake_key(0xCC00 + i) for i in range(chunks)]
        if authors is None:
            authors = {str(OWNER_CLIENT): author_entry(VEC["owner"], OWNER_SALT)}
        header = snapshot_header(data, 13, ckeys, authors)
        head = make_entity(
            template, key=fake_key(0xEE), kind="v", creator=VEC["owner"], block=13,
            payload=seal("v", epoch, header, parts[0], vkey), readonly=head_flags, permissionless=head_flags,
        )
        head.expires_at = 13 + 15768000  # one year of 2-second blocks
        out = [head]
        for i, ckey in enumerate(ckeys, start=1):
            ce = epoch if chunk_epoch is None else chunk_epoch
            out.append(make_entity(
                template, key=ckey, kind="c", creator=VEC["owner"], block=13,
                payload=seal("c", ce, {"i": i, "of": header["id"]}, parts[i], vkey),
                readonly=chunk_flags, permissionless=chunk_flags,
            ))
            out[-1].expires_at = head.expires_at
        return quire_read.format_version_link(head.key, vkey), out

    def test_version_link_round_trip(self) -> None:
        key, secret = fake_key(0xEE), bytes(range(32))
        frag = quire_read.format_version_link(key, secret)
        self.assertNotIn("=", frag)
        for form in (frag, "https://quire.example/" + frag, frag[1:]):
            v = quire_read.parse_version_link(form)
            self.assertEqual((v.key, v.secret), (key, secret))
        with self.assertRaises(ValueError):
            quire_read.parse_version_link("#/v/AAAA.AAAA")
        with self.assertRaises(ValueError):
            quire_read.parse_link(frag)  # a version link is not a document link

    def test_version_reads_with_its_own_key(self) -> None:
        for chunks in (0, 2):
            link, entities = self._version(chunks=chunks)
            v = quire_read.read_version(quire_read.parse_version_link(link), quire_read.VectorSource(entities))
            self.assertEqual(v.text, VEC["expected"]["memberText"], chunks)
            self.assertEqual(len(v.chunks), chunks)

    def test_version_authors_are_checked(self) -> None:
        forged = {str(OWNER_CLIENT): author_entry(VEC["members"]["bea"], OWNER_SALT)}
        link, entities = self._version(authors=forged)
        v = quire_read.read_version(quire_read.parse_version_link(link), quire_read.VectorSource(entities))
        report = quire_read.version_report(v)
        self.assertIn("authors      0 claimed by the version's creator, 1 dropped", report)
        self.assertIn("dropped: clientIdFor(address, salt) is", report)
        # A right id whose salt someone else signed is dropped too.
        wrong = {str(OWNER_CLIENT): author_entry(VEC["owner"], OWNER_SALT, signer=BEA_KEY)}
        link, entities = self._version(authors=wrong)
        v = quire_read.read_version(quire_read.parse_version_link(link), quire_read.VectorSource(entities))
        self.assertIn(f"dropped: sig recovers to {VEC['members']['bea']}", quire_read.version_report(v))

    def test_version_with_wrong_key_fails(self) -> None:
        link, entities = self._version()
        v = quire_read.parse_version_link(link)
        v.secret = os.urandom(32)
        with self.assertRaisesRegex(RuntimeError, "does not decrypt"):
            quire_read.read_version(v, quire_read.VectorSource(entities))

    def test_version_link_to_a_snapshot_fails(self) -> None:
        link, entities = self._version()
        entities[0].attributes = [
            quire_audit.Attribute(a.name, a.type, "s" if a.name == "qk" else a.value)
            for a in entities[0].attributes
        ]
        with self.assertRaisesRegex(RuntimeError, "not a version"):
            quire_read.read_version(quire_read.parse_version_link(link), quire_read.VectorSource(entities))

    def test_version_chunk_rules(self) -> None:
        cases = {
            "differs from its head's": dict(chunks=1, chunk_epoch=1),  # section 4
            "must be 0": dict(epoch=1),  # section 5: versions use epoch 0
            "flags": dict(chunks=1, chunk_flags=False),  # section 1: chunk flags follow the head
        }
        for reason, kw in cases.items():
            link, entities = self._version(**kw)
            with self.assertRaisesRegex(RuntimeError, reason):
                quire_read.read_version(quire_read.parse_version_link(link), quire_read.VectorSource(entities))

    def test_version_cli_and_audit(self) -> None:
        import tempfile
        link, entities = self._version(chunks=1)
        body = dict(VEC, entities=VEC["entities"] + [to_raw(e) for e in entities])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "version.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(body, fh)
            code, out = run_cli(quire_read.main, "--vectors", path, "--version-link", link)
            self.assertEqual(code, 0)
            self.assertEqual(out.rstrip("\n"), VEC["expected"]["memberText"])
            code, out = run_cli(quire_read.main, "--vectors", path, "--version-link", link, "--verify")
            self.assertEqual(code, 0)
            self.assertIn("chunks       1", out)
            self.assertIn("permissionless extension: yes", out)
            self.assertIn("membership not checkable", out)
            self.assertIn("epoch        0", out)
            self.assertIn(f"{OWNER_CLIENT}  {VEC['owner']}  claimed via {VEC['owner']}", out)
            code, out = run_cli(quire_audit.main, "--vectors", path)
            self.assertEqual(code, 0, out)
        # A version head without permissionless extension fails the audit.
        _link, entities = self._version(head_flags=False, chunk_flags=False)
        self.assertIn(f"flags version {entities[0].key}", quire_audit.audit(entities, VEC["doc"], None).failures)


@unittest.skipIf(SCHEMA_SKIP, SCHEMA_SKIP)
class SchemaTests(unittest.TestCase):
    def test_vector_entities_match_entity_schema(self) -> None:
        schemas = quire_read.Schemas()
        for raw in VEC["entities"]:
            schemas.check("entity", raw)

    def test_reader_checks_headers(self) -> None:
        data, entities = quire_audit.load_vectors(DOCUMENT)
        reader = quire_read.Reader(
            quire_read.parse_link(data["link"]),
            quire_read.VectorSource(entities),
            quire_read.load_private_key(OWNER_KEY),
        )
        self.assertIn("checked", reader.schemas.status)
        result = reader.read()
        self.assertEqual(result.text, VEC["expected"]["memberText"])
        self.assertEqual(len(reader.join_requests(result.acl)), 2)

    def test_bad_snapshot_id_fails_schema(self) -> None:
        schemas = quire_read.Schemas()
        header = {"id": "0x" + "00" * 16, "base": "1", "t": 0, "chunks": [], "size": 0, "authors": {}}
        with self.assertRaises(quire_read.Rejected):
            schemas.check("snapshot", header)
        header["id"] = "00" * 16
        schemas.check("snapshot", header)

    def test_roster_schema_requires_doc_and_epoch(self) -> None:
        schemas = quire_read.Schemas()
        member = {"address": VEC["owner"], "publicKey": "0x04" + "11" * 64, "name": "O", "role": "owner",
                  "addedAtBlock": "1"}
        roster = {"doc": VEC["doc"], "epoch": 1, "members": [member], "revoked": []}
        schemas.check("roster", roster)
        for missing in ("doc", "epoch"):
            with self.assertRaises(quire_read.Rejected):
                schemas.check("roster", {k: v for k, v in roster.items() if k != missing})

    def test_built_entities_match_entity_schema(self) -> None:
        schemas = quire_read.Schemas()
        for e in quire_audit.load_vectors(DOCUMENT)[1]:
            schemas.check("entity", to_raw(e))


if __name__ == "__main__":
    unittest.main()
