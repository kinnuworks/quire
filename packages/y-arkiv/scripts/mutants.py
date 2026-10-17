"""Mutation check: disables each security rule in src/provider.ts in turn and
confirms at least one test fails. Restores the file afterwards.

    python3 scripts/mutants.py
"""
import shutil
import subprocess
import sys
import tempfile

SRC = "src/provider.ts"
MUTANTS = {
    "client id derivation": ("if (clients.some((c) => c !== expected)) return false", "if (false) return false"),
    "salt signature": ("if (!(await signedBy(this.link.doc, salt, sig, author))) return false", "if (false) return false"),
    "takeover rule": ("if (holder && holder !== author.toLowerCase()) return false", "if (false) return false"),
    "member filter": ("if (!this.acl || !isMember(this.acl, entity.creator)) {\n      this.seen.add(entity.key)\n      return this.reject()", "if (!this.acl) {\n      this.seen.add(entity.key)\n      return this.reject()"),
    "future qs": ("if (entity.attributes.seq > entity.createdAt) return this.reject()", "if (false) return this.reject()"),
    "own client id in snapshots": ("if (this.identity && ours !== undefined && ours >", "if (false && ours !== undefined && ours >"),
    "whole-item provenance": ("this.coveredByProven(client, clock, clock + length)", "this.coveredByProven(client, clock, clock + 1)"),
    "updates before snapshots": ("const applied = await this.applySnapshotEntity(s, states)", "const applied = await this.applySnapshotEntity(s)"),
    "override detector": ("if (JSON.stringify(have) !== JSON.stringify(want[i])) return true", "if (false) return true"),
}

backup = tempfile.mktemp()
shutil.copy(SRC, backup)
survivors = []
try:
    for name, (find, replace) in MUTANTS.items():
        text = open(backup).read()
        if find not in text:
            print(f"{name:28} pattern not found")
            survivors.append(name)
            continue
        open(SRC, "w").write(text.replace(find, replace, 1))
        result = subprocess.run(["npx", "vitest", "run"], capture_output=True, text=True)
        killed = result.returncode != 0
        print(f"{name:28} {'caught' if killed else 'SURVIVED'}")
        if not killed:
            survivors.append(name)
finally:
    shutil.copy(backup, SRC)
sys.exit(1 if survivors else 0)
