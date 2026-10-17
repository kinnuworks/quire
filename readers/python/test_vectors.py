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
OWNER_CLIENT = 3362225433  # the owner's Yjs client id in the vectors
CAL_CLIENT = 1578550643  # Cal's; Cal is revoked, his edits live on only in the snapshot
REVOKED_AT = 10  # Cal's atBlock in the sealed roster


def _qs(e) -> int:
    return e.attr("qs")


def newest_snapshot(entities):
    """The vectors' newest snapshot by qs (section 5 step 3)."""
    return max((e for e in entities if e.kind == "s"), key=_qs)


def owner_late_update(entities):
    """The owner's last update; its structs start at clock 35."""
    return max((e for e in entities if e.kind == "u" and e.creator == VEC["owner"]), key=lambda e: e.created_at)


def bea_update(entities):
    return next(e for e in entities if e.kind == "u" and e.creator == VEC["members"]["bea"])


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
        # PROTOCOL.md does not give raw's bit layout, so only "no flags" has a known raw.
        flags_raw=None if readonly or permissionless else 0,
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
        # Section 1: a version is readonly and allows permissionless extension.
        version.permissionless_extension = False
        self.assertEqual(
            quire_audit.check_flags(version), ["version does not allow permissionless extension"]
        )

    def test_snapshot_has_no_flags(self) -> None:
        # Section 1: a snapshot carries no flags, readonly included.
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        snap = next(e for e in entities if e.kind == "s")
        snap.readonly = True
        self.assertEqual(quire_audit.check_flags(snap), ["snapshot is readonly, expected no flags"])

    def test_vectors_carry_creation_flags_like_the_rpc(self) -> None:
        for raw in VEC["entities"]:
            self.assertEqual(
                raw["creationFlags"], {"readonly": False, "permissionlessExtension": False, "raw": 0}
            )
        for e in quire_audit.load_vectors(DOCUMENT)[1]:
            self.assertEqual(e.flags_raw, 0)

    def test_unknown_raw_flag_fails(self) -> None:
        e = quire_audit.load_vectors(DOCUMENT)[1][0]
        e.flags_raw = 4
        self.assertTrue(quire_audit.check_flags(e))

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
            head, key=fake_key(0x5A), kind="s", creator=head.creator, block=10,
            payload=seal("s", 1, header, frame.data[:100], reader.keys[1]),
        )
        of = frame.header["id"] if of_value is None else of_value
        chunk = make_entity(
            head, key=chunk_key, kind="c", creator=head.creator, block=10,
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

    def _extra_snapshot(self, *, epoch: int, block: int, text: str):
        """A full-state snapshot by the owner with one more paragraph."""
        reader, result = self._member_result()
        d = Doc(client_id=777)
        d.apply_update(result.doc.get_update())
        d.get("default", type=XmlFragment).children.append(XmlElement("paragraph", None, [XmlText(text)]))
        data = d.get_update()
        entities = quire_audit.load_vectors(DOCUMENT)[1]
        template = newest_snapshot(entities)
        e = make_entity(
            template, key=fake_key(0x5500 + block), kind="s", creator=VEC["owner"], block=block,
            payload=seal("s", epoch, snapshot_header(data, block, authors={"777": VEC["owner"]}), data,
                         reader.keys[epoch]),
        )
        return e, self._reader(entities + [e]).read()

    def test_old_epoch_snapshot_after_revocation_is_ignored(self) -> None:
        # Section 5: the old-epoch rule covers snapshots too. Cal still holds
        # the epoch 0 key and could read this one.
        e, result = self._extra_snapshot(epoch=0, block=REVOKED_AT + 2, text="Old key snapshot.")
        self.assertNotIn(e.key, result.applied)
        self.assertIn("snapshot created at block 12, after the revocation", dict(result.ignored)[e.key])
        self.assertEqual(result.text, VEC["expected"]["memberText"])

    def test_old_epoch_snapshot_at_revocation_block_is_applied(self) -> None:
        # createdAt equal to atBlock is not "greater than", so it stays.
        e, result = self._extra_snapshot(epoch=0, block=REVOKED_AT, text="Same block as the revocation.")
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
        self.assertEqual(clients[OWNER_CLIENT][0][0], 35)
        # A state vector of this update is empty: it starts at clock 35.
        self.assertEqual(get_state(data), b"\x00")

    def _forged_update(self, client_id: int, epoch: int, block: int, text: str,
                       creator: str | None = None, key: str | None = None, extra=()):
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
            template, key=key or fake_key(0xB0 + block), kind="u", creator=creator or VEC["members"]["bea"],
            block=block, payload=seal("u", epoch, {"t": 1}, update, reader.keys[epoch]),
        )
        return e, self._reader(entities + [e] + list(extra)).read()

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
        self.assertEqual(result.bound_by[4242], f"update {e.key}")

    def test_snapshot_authors_bind_before_any_update(self) -> None:
        # Section 5: bindings are seeded from the applied snapshot's authors.
        # This update is created at block 5, before every real owner update,
        # so under first-update binding alone it would take the owner's id.
        e, result = self._forged_update(OWNER_CLIENT, 1, 5, "Bea, early, as the owner.")
        self.assertNotIn(e.key, result.applied)
        self.assertIn("already bound", dict(result.ignored)[e.key])
        newest = result.newest_snapshot
        self.assertEqual(result.bound_by[OWNER_CLIENT], f"snapshot {newest}")
        self.assertEqual(result.text, VEC["expected"]["memberText"])

    def test_revoked_members_client_id_stays_bound(self) -> None:
        # Cal's updates are gone from the read (he is not a member any more),
        # but the snapshot's authors still bind his id to him.
        e, result = self._forged_update(CAL_CLIENT, 1, 13, "Bea writes as Cal.")
        self.assertNotIn(e.key, result.applied)
        self.assertEqual(result.bindings[CAL_CLIENT], VEC["members"]["cal"])

    def test_update_order_is_created_at_then_key(self) -> None:
        # Two members use one fresh client id in the same block. Section 5
        # applies by createdAt, then entity key, so the lower key binds it,
        # whatever the qs values say.
        reader, base = self._member_result()
        owner_doc = Doc(client_id=5555)
        owner_doc.apply_update(base.doc.get_update())
        owner_doc.get("default", type=XmlFragment).children.append(
            XmlElement("paragraph", None, [XmlText("Owner first.")])
        )
        upd = owner_doc.get_update(base.doc.get_state())
        template = bea_update(quire_audit.load_vectors(DOCUMENT)[1])
        low = make_entity(
            template, key=fake_key(0x01), kind="u", creator=VEC["owner"], block=13,
            payload=seal("u", 1, {"t": 1}, upd, reader.keys[1]),
        )
        # Give the low key the higher qs: the old (qs, key) order would flip it.
        low.attributes = [quire_audit.Attribute(a.name, a.type, 99 if a.name == "qs" else a.value)
                          for a in low.attributes]
        e, result = self._forged_update(5555, 1, 13, "Bea second.", key=fake_key(0x02), extra=[low])
        self.assertIn(low.key, result.applied)
        self.assertNotIn(e.key, result.applied)
        self.assertEqual(result.bindings[5555], VEC["owner"])
        for seed in range(4):  # and the query order does not matter
            entities = quire_audit.load_vectors(DOCUMENT)[1] + [low, e]
            random.Random(seed).shuffle(entities)
            again = self._reader(entities).read()
            self.assertIn(low.key, again.applied)
            self.assertNotIn(e.key, again.applied)

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
        # Section 3: wraps are unlabelled, so the report gives a count and no
        # member address other than the owner's, which is in the link.
        self.assertIn("wraps        2", out)
        for name in ("bea", "cal"):
            self.assertNotIn(VEC["members"][name], out)
        self.assertNotIn("wrap addresses", out)

    # -------------------------------------------------------- versions

    def _version(self, *, chunks: int = 0, chunk_epoch: int | None = None, chunk_flags: bool = True,
                 epoch: int = 1, head_flags: bool = True):
        """A published version built in memory from a fresh random key."""
        _reader, result = self._member_result()
        vkey = os.urandom(32)
        data = result.doc.get_update()
        cut = [len(data) * i // (chunks + 1) for i in range(chunks + 2)]
        parts = [data[cut[i]:cut[i + 1]] for i in range(chunks + 1)]
        template = newest_snapshot(quire_audit.load_vectors(DOCUMENT)[1])
        ckeys = [fake_key(0xCC00 + i) for i in range(chunks)]
        header = snapshot_header(data, 13, ckeys, {str(OWNER_CLIENT): VEC["owner"]})
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
            "differs from its head's": dict(chunks=1, chunk_epoch=0),  # section 4
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
