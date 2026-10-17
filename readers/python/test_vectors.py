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
OWNER_CLIENT = 1540505671  # the owner's Yjs client id in the vectors


def run_cli(main, *args: str) -> tuple[int, str]:
    """Call a script's main() and capture stdout."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(list(args))
    return code, out.getvalue()


def by_prefix(entities, prefix: str):
    return next(e for e in entities if e.key.startswith(prefix))


# ---------------------------------------------------------------- writer side
# Just enough of a writer to build hostile entities for the reader rules.


def seal(kind: str, epoch: int, header: dict, data: bytes, key: bytes) -> bytes:
    h = json.dumps(header, separators=(",", ":")).encode()
    frame = (
        b"QF\x01" + kind.encode() + bytes.fromhex(VEC["doc"][2:])
        + struct.pack(">III", epoch, len(h), len(data)) + h + data
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
    )


def fake_key(n: int) -> str:
    return "0x" + f"{n:064x}"


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

    def test_permissionless_extension_only_on_versions(self) -> None:
        for kind in ("a", "u", "s", "j"):
            entities = quire_audit.load_vectors(DOCUMENT)[1]
            e = next(x for x in entities if x.kind == kind)
            e.permissionless_extension = True
            report = quire_audit.audit(entities, VEC["doc"], VEC["owner"])
            self.assertIn(f"flags {quire_audit.KIND_NAMES[kind]} {e.key}", report.failures, kind)

    def test_version_must_be_readonly(self) -> None:
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        template = entities[0]
        version = dataclasses.replace(
            template, attributes=[
                quire_audit.Attribute(a.name, a.type, "v" if a.name == "qk" else a.value)
                for a in template.attributes
            ],
            readonly=False, permissionless_extension=True,
        )
        self.assertEqual(quire_audit.check_flags(version), ["version is not readonly"])
        version.readonly = True
        self.assertEqual(quire_audit.check_flags(version), [])

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
        self.assertTrue(base.newest_snapshot.startswith("0x03b77b47"))
        for seed in range(5):
            entities = quire_audit.load_vectors(DOCUMENT)[1]
            random.Random(seed).shuffle(entities)
            result = self._reader(entities).read()
            self.assertEqual(result.newest_snapshot, base.newest_snapshot)
            self.assertEqual(result.text, VEC["expected"]["memberText"])

    def _chunked(self, of_value):
        """Split the newest snapshot into a head and one chunk."""
        reader, _result = self._member_result()
        k1 = reader.keys[1]
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        head = by_prefix(entities, "0x03b77b47")
        frame = reader._content_frame(head)
        chunk_key = fake_key(0xC1)
        header = dict(frame.header, chunks=[chunk_key])
        new_head = make_entity(
            head, key=fake_key(0x5A), kind="s", creator=head.creator, block=10,
            payload=seal("s", 1, header, frame.data[:100], k1),
        )
        of = frame.header["id"] if of_value is None else of_value
        chunk = make_entity(
            head, key=chunk_key, kind="c", creator=head.creator, block=10,
            payload=seal("c", 1, {"i": 1, "of": of}, frame.data[100:], k1),
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

    # -------------------------------------------------------- client ids

    def test_update_clients_at_any_clock(self) -> None:
        reader, _result = self._member_result()
        owner_e1 = by_prefix(reader.source.entities, "0x2d6e9213")  # type: ignore[attr-defined]
        data = reader._content_frame(owner_e1).data
        clients = quire_read.update_clients(data)
        self.assertEqual(set(clients), {OWNER_CLIENT})
        self.assertEqual(clients[OWNER_CLIENT][0][0], 35)
        # A state vector of this update is empty: it starts at clock 35.
        self.assertEqual(get_state(data), b"\x00")

    def _forged_update(self, client_id: int, epoch: int, block: int, text: str):
        reader, result = self._member_result()
        d = Doc(client_id=client_id)
        d.apply_update(result.doc.get_update())
        frag = d.get("default", type=XmlFragment)
        frag.children.append(XmlElement("paragraph", None, [XmlText(text)]))
        update = d.get_update(result.doc.get_state())
        self.assertIn(client_id, quire_read.update_clients(update))
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        template = by_prefix(entities, "0xbf476ae3")  # Bea's update
        e = make_entity(
            template, key=fake_key(0xB0 + block), kind="u", creator=VEC["members"]["bea"],
            block=block, payload=seal("u", epoch, {"t": 1}, update, reader.keys[epoch]),
        )
        return e, self._reader(entities + [e]).read()

    def test_update_under_another_members_client_id_is_ignored(self) -> None:
        e, result = self._forged_update(OWNER_CLIENT, 1, 13, "Bea writes as the owner.")
        self.assertNotIn(e.key, result.applied)
        self.assertIn("already bound", dict(result.ignored)[e.key])
        self.assertEqual(result.bindings[OWNER_CLIENT], VEC["members"]["owner"])
        self.assertEqual(result.text, VEC["expected"]["memberText"])

    def test_update_under_own_client_id_is_applied(self) -> None:
        e, result = self._forged_update(4242, 1, 13, "Bea writes as herself.")
        self.assertIn(e.key, result.applied)
        self.assertEqual(result.bindings[4242], VEC["members"]["bea"])
        self.assertTrue(result.text.endswith("Bea writes as herself."))

    # -------------------------------------------------------- epochs

    def test_old_epoch_update_after_revocation_is_ignored(self) -> None:
        e, result = self._forged_update(4243, 0, 12, "Old key, after Cal left.")
        self.assertNotIn(e.key, result.applied)
        self.assertIn("after the revocation", dict(result.ignored)[e.key])
        self.assertEqual(result.text, VEC["expected"]["memberText"])

    def test_old_epoch_update_before_revocation_is_applied(self) -> None:
        e, result = self._forged_update(4244, 0, 9, "Old key, before Cal left.")
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
        self.assertIn("2 x creator not in ACL", out)
        self.assertIn("join requests 2", out)
        self.assertNotIn(": NO", out)

    def test_verify_report_as_link_holder(self) -> None:
        code, out = run_cli(quire_read.main, "--vectors", DOCUMENT, "--verify")
        self.assertEqual(code, 0)
        self.assertIn("members      not visible", out)
        self.assertNotIn("join requests", out)


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
        header = {"id": "0x" + "00" * 16, "base": "1", "t": 0, "chunks": [], "size": 0}
        with self.assertRaises(quire_read.Rejected):
            schemas.check("snapshot", header)
        header["id"] = "00" * 16
        schemas.check("snapshot", header)


if __name__ == "__main__":
    unittest.main()
