"""Mutation check: removes each security rule in turn and confirms at least
one test fails. Restores every file afterwards.

    python3 scripts/mutants.py
"""
import subprocess
import sys

P, A = "src/provider.ts", "src/acl.ts"
MUTANTS = [
    (P, "client id derivation", "if (clients.some((c) => c !== expected)) return false", "if (false) return false"),
    (P, "salt signature", "if (!(await signedBy(this.link.doc, salt, sig, author))) return false", "if (false) return false"),
    (P, "takeover rule", "if (holder && holder !== author.toLowerCase()) return false", "if (false) return false"),
    (P, "update member filter", "if (!this.acl || !isMember(this.acl, entity.creator)) {\n      this.seen.add(entity.key)\n      return this.reject()", "if (!this.acl) {\n      this.seen.add(entity.key)\n      return this.reject()"),
    (P, "future qs on updates", "if (entity.attributes.seq > entity.createdAt) return this.reject()", "if (false) return this.reject()"),
    (P, "own client id in snapshots", "if (this.identity && ours !== undefined && ours >", "if (false && ours !== undefined && ours >"),
    (P, "whole-item provenance", "this.coveredByProven(client, clock, clock + length)", "this.coveredByProven(client, clock, clock + 1)"),
    (P, "updates before snapshots", "const applied = await this.applySnapshotEntity(s, states)", "const applied = await this.applySnapshotEntity(s)"),
    (P, "override detector", "if (JSON.stringify(have) !== JSON.stringify(want[i])) return true", "if (false) return true"),
    (P, "ACL creator check", "if (entity.creator.toLowerCase() !== this.link.owner.toLowerCase()) return", "if (false) return"),
    (P, "chunk creator", "chunk.creator.toLowerCase() === entity.creator.toLowerCase() ?", "true ?"),
    (P, "chunk names its snapshot", "cf.header.of !== frame.header.id", "false"),
    (P, "snapshot base and qs", "base < 0n || base > entity.createdAt || entity.attributes.seq > entity.createdAt", "base < 0n"),
    (P, "frame binding", "frame.kind !== kind || frame.epoch !== epoch || !equalBytes(frame.doc, hexToBytes(this.link.doc))", "false"),
    (P, "chunk epoch", "if (epochHint !== undefined && epoch !== epochHint) return null", "if (false) return null"),
    (P, "snapshot member filter", "if (!this.acl || !isMember(this.acl, entity.creator)) {\n      this.seen.add(entity.key)\n      this.reject()\n      return null", "if (!this.acl) {\n      this.seen.add(entity.key)\n      this.reject()\n      return null"),
    (P, "author claim id", "clientIdFor(entry.address, hexToBytes(entry.salt)) === Number(client) &&", "true &&"),
    (P, "author claim signature", "(await signedBy(this.link.doc, entry.salt, entry.sig, entry.address as Hex))", "true"),
    (P, "join from a member ignored", "if (this.acl && isMember(this.acl, entity.creator)) return", "if (false) return"),
    (P, "join key matches creator", "if (derived.toLowerCase() !== entity.creator.toLowerCase()) return", "if (false) return"),
    (P, "stranger fetch cap", "if (!known && (this.role !== \"owner\" || !this.allowStrangerFetch())) return", "if (!known && this.role !== \"owner\") return"),
    (P, "live document check", "if (entity.attributes.doc !== this.link.doc) return", "if (false) return"),
    (A, "roster bound to doc and epoch", "if (r.doc !== doc.toLowerCase() || r.epoch !== h.epoch) throw", "if (false) throw"),
    (A, "ACL owner matches link", "if (h.owner.toLowerCase() !== owner.toLowerCase()) throw", "if (false) throw"),
    (A, "ACL lists its owner", "if (!rosterHidden && !members.some((m) => m.address.toLowerCase() === owner.toLowerCase() && m.role === \"owner\")) {", "if (false) {"),
]

originals = {path: open(path).read() for path in {P, A}}
survivors = []
try:
    for path, name, find, replace in MUTANTS:
        text = originals[path]
        if text.count(find) != 1:
            print(f"{name:32} pattern found {text.count(find)} times")
            survivors.append(name)
            continue
        open(path, "w").write(text.replace(find, replace, 1))
        result = subprocess.run(["npx", "vitest", "run"], capture_output=True, text=True)
        open(path, "w").write(text)
        killed = result.returncode != 0
        print(f"{name:32} {'caught' if killed else 'SURVIVED'}")
        if not killed:
            survivors.append(name)
finally:
    for path, text in originals.items():
        open(path, "w").write(text)
print(f"{len(MUTANTS) - len(survivors)} of {len(MUTANTS)} caught")
sys.exit(1 if survivors else 0)
