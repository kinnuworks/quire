"""Mutation check: removes each security rule in turn and confirms at least
one test fails. Restores every file afterwards.

    python3 packages/y-arkiv/scripts/mutants.py   (from anywhere)
"""
import os
import subprocess
import sys

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

P, A, R = "src/provider.ts", "src/acl.ts", "../../api/rpc.ts"
MUTANTS = [
    (P, "client id derivation", "if (clients.some((c) => c !== expected)) return false", "if (false) return false"),
    (P, "salt signature", "if (!(await signedBy(this.link.doc, salt, sig, author))) return false", "if (false) return false"),
    (P, "takeover rule", "if (holder && holder !== author.toLowerCase()) return false", "if (false) return false"),
    (P, "update member filter", "entity.createdAt < this.aclCreatedAt || !(then ?? wroteAsMember(this.acl, entity.creator, entity.createdAt))) {", "entity.createdAt < this.aclCreatedAt || !(then ?? true)) {"),
    (P, "future qs on updates", "if (entity.attributes.seq > entity.createdAt) return this.reject()", "if (false) return this.reject()"),
    (P, "backdated qs on updates", "if (entity.attributes.seq + CATCH_UP_MARGIN_BLOCKS < entity.createdAt) return this.reject()", "if (false) return this.reject()"),
    (P, "own client id in snapshots", "if (this.identity && ours !== undefined && ours >", "if (false && ours !== undefined && ours >"),
    (P, "whole-item provenance", "this.coveredByProven(client, clock, clock + length)", "this.coveredByProven(client, clock, clock + 1)"),
    (P, "verified clocks checked on load", "const verified = this.history.slice(historyBefore).map((h) => h.update)", "const verified: Uint8Array[] = []"),
    (P, "override detector", "        if (found instanceof Y.Item && !found.deleted && rangesDiffer(doc, found, struct, c, stop)) return true", "        if (false) return true"),
    (P, "override: map key", "k === 0 ? (item.parentSub ?? \"\") : \"\"", "\"\""),
    (P, "override: format value", "id(item.rightOrigin), parent, k === 0 ? (item.parentSub ?? \"\") : \"\", unit(item.content, k)]", "id(item.rightOrigin), parent, k === 0 ? (item.parentSub ?? \"\") : \"\", item.content.getContent()[k] ?? null]"),
    (P, "refused snapshot never commits", "Y.applyUpdate(trial, st.state)\n      if (snapshotConflicts(this.doc, st.state, verified) || overridesVerified(trial, verified)) {\n        this.reject()\n        this.refusedSnapshots.add(st.key)\n        continue", "Y.applyUpdate(trial, st.state)\n      if (snapshotConflicts(this.doc, st.state, verified) || overridesVerified(trial, verified)) {\n        this.reject()\n        st.commit(false)\n        continue"),
    (P, "versions must be readonly", "if (!entity.readonly) throw", "if (false) throw"),
    (P, "proven clocks skip Skip gaps", "        if (!(st instanceof Y.Item)) continue\n", ""),
    (P, "member list re-read before a write", "      if (await this.refreshAcl()) this.enqueue(() => this.loadState())\n", ""),
    (P, "conflicting duplicate edits refused", "    if (this.conflictsWithProven(frame.data)) {", "    if (false) {"),
    (P, "live clash out of order reported", "if (live && this.clashesWithLater(entity, frame.data)) this.emit(\"diverged\", [entity.key])", "if (false) this.emit(\"diverged\", [entity.key])"),
    (P, "member's own snapshot speaks for them", "    const overruled = overruledByOwners(this.doc, states, owners)", "    const overruled = new Set<Hex>()"),
    (P, "own snapshot rule on live snapshots", " || overruledByOwners(this.doc, [st], others).size) {", ") {"),
    (P, "audit page cap", "for (let pages = 1; cursor && pages < AUDIT_PAGES; pages++)", "for (let pages = 1; cursor; pages++)"),
    (A, "names counted in code points", "[...m.name].length > 40", "m.name.length > 40"),
    (P, "qs ceiling on update queries", "...updateFilter(this.acl!, from), seqGte: from, seqLte: this.qsCeiling() }", "...updateFilter(this.acl!, from), seqGte: from }"),
    (P, "expiry ceiling anchored to the entity", "const lease = entity.updatedAt + blocks(LIFETIME.snapshot)", "const lease = this.headSeen + blocks(LIFETIME.snapshot)"),
    (P, "audit reads keepUntil at the entity's block", "if (!then || then === \"unknown\" || entity.expiresAt > this.expiryCeiling(entity, then.keepUntil)) {", "if (true) {"),
    (P, "failed past read is unchecked, not refused", "    if (acl === \"unknown\") {\n      this.auditUnchecked++\n      return undefined\n    }", "    if (acl === \"unknown\") return false"),
    (P, "earliest owner ACL chosen", "    for (const entity of earliest) {", "    for (const entity of [...earliest].reverse()) {"),
    (P, "member list owner-only extension", "lifetimeSeconds: LIFETIME.acl, permissionlessExtension: false }", "lifetimeSeconds: LIFETIME.acl, permissionlessExtension: true }"),
    (P, "only the owner renews the member list", "    const mayExtendAcl = this.role === \"owner\" || this.aclOpenToAll\n    if (mayExtendAcl && due(", "    const mayExtendAcl = true\n    if (mayExtendAcl && due("),
    (A, "removed members bounded at their removal", "const creatorBounds = [...ended].filter(([, at]) => at >= from).map(([address, seqLte]) => ({ address, seqLte }))", "const creatorBounds = [...ended].map(([address]) => ({ address, seqLte: 1n << 62n }))"),
    (P, "audit walks the member list's history", "    const ever = await this.everListed()\n    if (ever) {", "    const ever = null as Hex[] | null\n    if (ever) {"),
    (P, "extension past the ceiling reported live", "      if (e.expiresAt > ceiling) this.emit(\"diverged\", [e.key])", "      if (false) this.emit(\"diverged\", [e.key])"),
    (R, "relay scan reads one page", "if (!query.includes(\" AND qk = \") && (o.cursor !== undefined || o.atBlock !== undefined)) {", "if (false) {"),
    (P, "kept content pinned to keepUntil", "    return until > head + blocks(LIFETIME.snapshot) ? until : undefined", "    return undefined"),
    (P, "readers check members at each edit's block by default", "this.membershipAtBlock = options.membershipAtBlock ?? true", "this.membershipAtBlock = options.membershipAtBlock ?? false"),
    (R, "relay page size checked", "(hex(o.limit, 2) && Number(o.limit) >= 1 && Number(o.limit) <= 200)", "true"),
    (P, "read-only sessions never write", "batch: (spec) => (readOnly ? Promise.reject(new Error(\"this session was opened read-only\")) : inner.batch(spec)),", "batch: (spec) => inner.batch(spec),"),
    (A, "ACL field set checked", "if (fields.some((f) => !keys.includes(f)) || keys.some((k) => !fields.includes(k))) throw", "if (false) throw"),
    (A, "removed members only before removal", "createdAt <= BigInt(r.atBlock) &&", "true &&"),
    (P, "malformed headers ignored", "    if (problem) throw new MalformedHeader(`${kind} header: ${problem}`)", "    if (false) throw new MalformedHeader(\"\")"),
    (P, "ACL creator check", "if (entity.creator.toLowerCase() !== this.link.owner.toLowerCase()) return", "if (false) return"),
    (P, "chunk creator", "chunk.creator.toLowerCase() === entity.creator.toLowerCase() && sameFlags ?", "sameFlags ?"),
    (P, "snapshot size matches header", "if (state.length !== frame.header.size) {", "if (false) {"),
    (P, "snapshot tie-break", "desc(x.attributes.seq, y.attributes.seq) || desc(x.createdAt, y.createdAt) || desc(x.key, y.key)", "desc(x.attributes.seq, y.attributes.seq)"),
    (P, "claimed text names its carrier", "via: this.carrierOf(client, clock) ?? this.claimedVia.get(client)", "via: this.claimedVia.get(client)"),
    (P, "chunk names its snapshot", "cf.header.of !== frame.header.id", "false"),
    (P, "snapshot base and qs", "base < 0n || base > entity.createdAt || entity.attributes.seq > entity.createdAt", "base < 0n"),
    (P, "frame binding", "frame.kind !== kind || frame.epoch !== epoch || !equalBytes(frame.doc, hexToBytes(this.link.doc))", "false"),
    (P, "chunk epoch", "if (epochHint !== undefined && epoch !== epochHint) return null", "if (false) return null"),
    (P, "snapshot member filter", "|| !memberAt(this.acl, entity.creator, entity.createdAt)) {\n      this.seen.add(entity.key)\n      this.reject()\n      return null", ") {\n      this.seen.add(entity.key)\n      this.reject()\n      return null"),
    (P, "content entities must be readonly", "    if (kind !== KIND.acl && !entity.readonly) throw new MalformedHeader(`${kind} entity is not readonly`)\n", ""),
    (P, "snapshot checked struct by struct", "Y.applyUpdate(trial, st.state)\n      if (snapshotConflicts(this.doc, st.state, verified) || overridesVerified(trial, verified)) {", "Y.applyUpdate(trial, st.state)\n      if (overridesVerified(trial, verified)) {"),
    (A, "removal closes one interval", "(r.addedAtBlock === undefined || (/^[0-9]+$/.test(String(r.addedAtBlock)) && createdAt >= BigInt(r.addedAtBlock)))", "true"),
    (A, "member entries checked by hand", "  if (h.epoch === 0) checkRoster(h.members, h.revoked)\n", ""),
    (P, "earlier epoch keys carried forward", "    for (const [n, k] of Object.entries(acl.prior ?? {})) if (!this.epochKeys.has(Number(n))) this.epochKeys.set(Number(n), hexToBytes(k))\n", ""),
    (P, "delete removes all but versions", "e.attributes.kind !== KIND.version && !(e.attributes.kind === KIND.chunk && e.permissionlessExtension)", "!e.readonly"),
    (P, "owner's expiry ceiling enforced", "&& this.acl && entity.expiresAt > this.expiryCeiling(entity, this.acl.keepUntil)) {", "&& false) {"),
    (P, "membership read at each edit's block", "    // the whole section 5 rule against that list: a patch in the edit's own block may already show\n    // the removal, and the removal interval still covers the edit\n    return wroteAsMember(acl, entity.creator, entity.createdAt)", "    return undefined"),
    (A, "members only from their added block", "createdAt >= BigInt(m.addedAtBlock)", "true"),
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

originals = {path: open(path).read() for path in {P, A, R}}
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
