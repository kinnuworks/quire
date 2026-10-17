"""Conformance tests against spec/vectors. Run: python -m unittest -v test_vectors"""

from __future__ import annotations

import contextlib
import io
import json
import os
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
    from pycrdt import Doc  # noqa: F401

    READER_SKIP = ""
except ImportError as exc:  # cryptography or pycrdt missing
    READER_SKIP = f"reader tests need cryptography and pycrdt ({exc}); pip install -r requirements.txt"

with open(DOCUMENT, encoding="utf-8") as fh:
    VEC = json.load(fh)


def run_cli(main, *args: str) -> tuple[int, str]:
    """Call a script's main() and capture stdout."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(list(args))
    return code, out.getvalue()


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


@unittest.skipIf(READER_SKIP, READER_SKIP)
class ReaderTests(unittest.TestCase):
    def test_key_derivation(self) -> None:
        with open(KEYS, encoding="utf-8") as fh:
            keys = json.load(fh)
        secret = bytes.fromhex(keys["linkSecret"])
        self.assertEqual(quire_read.meta_key(secret).hex(), keys["metaKey"])
        self.assertEqual(quire_read.epoch0_key(secret).hex(), keys["epoch0Key"])

    def test_link_parses(self) -> None:
        link = quire_read.parse_link(VEC["link"])
        self.assertEqual(link.doc, VEC["doc"])
        self.assertEqual(link.owner, VEC["owner"])
        self.assertEqual(link.secret.hex(), VEC["linkSecret"])

    def test_link_holder_text(self) -> None:
        code, out = run_cli(quire_read.main, "--vectors", DOCUMENT)
        self.assertEqual(code, 0)
        self.assertEqual(out.rstrip("\n"), VEC["expected"]["linkHolderText"])

    def test_member_text(self) -> None:
        code, out = run_cli(
            quire_read.main, "--vectors", DOCUMENT, "--member-key", VEC["privateKeys"]["bea"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(out.rstrip("\n"), VEC["expected"]["memberText"])

    def _member_result(self) -> tuple["quire_read.Reader", "quire_read.ReadResult"]:
        data, entities = quire_audit.load_vectors(DOCUMENT)
        reader = quire_read.Reader(
            quire_read.parse_link(data["link"]),
            quire_read.VectorSource(entities),
            quire_read.load_private_key(VEC["privateKeys"]["bea"]),
        )
        return reader, reader.read()

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
        from pycrdt import Doc, XmlFragment
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


if __name__ == "__main__":
    unittest.main()
