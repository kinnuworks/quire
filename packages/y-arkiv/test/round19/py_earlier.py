import json, sys, os
sys.path.insert(0, os.environ["READERS"])
import quire_read, quire_audit
rows = json.load(sys.stdin)
ups = []
for r in rows:
    data = bytes.fromhex(r["update"])
    e = quire_audit.Entity(key=r["entity"], creator=r["author"], owner=r["author"], created_at=int(r["block"]),
                           expires_at=int(r["block"]) + 10**6, readonly=True, permissionless_extension=False,
                           attributes=[], payload=b"")
    ups.append((e, data, quire_read.update_structs(data)))
print(json.dumps([{"address": w.address, "first": w.first, "text": w.text} for w in quire_read.earlier_writers(ups)]))
