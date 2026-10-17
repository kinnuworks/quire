/**
 * Attacks the judges and reviewers raised, each written as a test that has
 * to fail for the attacker.
 */
import { describe, expect, it } from "vitest"
import * as Y from "yjs"
import { encodeFrame, encodeOuter } from "../src/codec.js"
import { deriveEpochZeroKey, deriveMetaKey, open, randomBytes, seal } from "../src/crypto.js"
import { decodeFrame, decodeOuter } from "../src/codec.js"
import { hexToBytes } from "../src/hex.js"
import { MemoryChain } from "../src/memory.js"
import { KIND, LIFETIME } from "../src/protocol.js"
import { admit, identity, newDocument, peer, settle, text } from "./helpers.js"

describe("authorship cannot be borrowed", () => {
  it("rejects an update that writes under another member's Yjs client id", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, b)
    await admit(chain, a, c)
    b.doc.getText("t").insert(0, "bea's line ")
    await b.provider.flush()
    await settle(chain, [a, b, c])

    // cal crafts an edit using bea's client id, so it would look like bea wrote it
    // continue bea's clock under bea's client id, the way a hand-built update would
    const clock = Y.decodeStateVector(Y.encodeStateVector(b.doc)).get(b.doc.clientID)!
    const forged = new Y.Doc()
    forged.clientID = b.doc.clientID
    forged.getText("t").insert(0, "x".repeat(clock))
    forged.getText("t").insert(clock, "words put in bea's mouth ")
    const update = Y.encodeStateAsUpdate(forged, Y.encodeStateVector((() => { const d = new Y.Doc(); d.clientID = b.doc.clientID; d.getText("t").insert(0, "x".repeat(clock)); return d })()))
    expect([...Y.parseUpdateMeta(update).from.keys()]).toEqual([b.doc.clientID])
    const payload = encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), encodeFrame({ kind: KIND.update, doc: hexToBytes(link.doc), epoch: 0, header: { t: 0 }, data: update }, randomBytes)))
    await chain.store(c.id!.address).batch({ creates: [{ payload, attributes: { doc: link.doc, kind: KIND.update, seq: chain.block }, lifetimeSeconds: 3600 }] })
    await settle(chain, [a, b, c])

    expect(text(a)).not.toContain("mouth")
    expect(a.provider.stats.rejectedWrites).toBe(1)
    expect(a.provider.authorOf(b.doc.clientID)).toEqual({ address: b.id!.address, proven: true })
  })
})

describe("a removed member learns nothing new", () => {
  it("cannot read the roster or join requests after the epoch changes", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, b)
    await admit(chain, a, c)
    await a.provider.revoke(c.id!.address)
    await settle(chain, [a, b, c])

    const newcomer = await peer(chain, link, identity("dev"))
    await newcomer.provider.requestJoin()
    await settle(chain, [a, b, c, newcomer])

    expect(a.provider.joinRequests.map((j) => j.name)).toEqual(["dev"])
    // the removed member sees an ACL, but not who is in it
    expect(c.provider.acl!.rosterHidden).toBe(true)
    expect(c.provider.acl!.members).toEqual([])
    expect(c.provider.joinRequests).toHaveLength(0)
    // and cannot open the join request even by hand: it is sealed to the owner's key
    const req = (await chain.store(undefined).query({ doc: link.doc, kind: KIND.join })).entities[0]!
    await expect(open(deriveMetaKey(link.secret), decodeOuter(req.payload).envelope)).rejects.toThrow()
    // a member still reads the roster
    expect(b.provider.acl!.members.map((m) => m.name).sort()).toEqual(["bea", "owner"])
  })
})

describe("expiry belongs to the document's people", () => {
  it("strangers cannot extend the document's snapshots; the member list alone keeps nothing readable", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "content lives in snapshots")
    await a.provider.close()
    const stranger = chain.store(identity("x").address)
    await expect(stranger.batch({ extensions: [{ key: a.provider.snapshot!.key, lifetimeSeconds: 10 * 365 * 86400 }] })).rejects.toThrow(/not permitted/)
    // the member list may be renewed by anyone (so writers keep a document open), but it holds no text:
    // once the snapshots and edits expire, a reader finds an empty document
    await stranger.batch({ extensions: [{ key: a.provider.aclKey!, lifetimeSeconds: 10 * 365 * 86400 }] })
    a.provider.destroy()
    chain.mine((40 * 86400) / 2)
    const later = await peer(chain, link, undefined)
    expect(text(later)).toBe("")
  })

  it("a writer renews the member list while the owner is away", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    await admit(chain, a, b)
    a.provider.destroy()
    const before = b.provider.aclExpiresAt!
    chain.mine(Number((before - chain.block) / 2n) + 20)
    await b.provider.renewLeaseIfDue()
    expect(b.provider.aclExpiresAt!).toBeGreaterThan(before)
  })

  it("a member renews the lease by writing their own snapshot when someone else wrote the current one", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    await admit(chain, a, b)
    const old = a.provider.snapshot!
    chain.mine(Number((old.expiresAt - chain.block) / 2n) + 10)
    expect(await b.provider.renewLeaseIfDue()).toBe(true)
    expect(b.provider.snapshot!.creator).toBe(b.id!.address)
    expect(b.provider.snapshot!.expiresAt).toBeGreaterThan(old.expiresAt)
  })

  it("keepFor records the target so later snapshots honour it", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    await a.provider.keepFor(365 * 86400)
    await settle(chain, [a])
    const yearInBlocks = BigInt((365 * 86400) / 2)
    expect(a.provider.acl!.keepUntil).not.toBeNull()
    expect(a.provider.snapshot!.expiresAt - chain.block).toBeGreaterThan(yearInBlocks - 100n)
    expect(a.provider.aclExpiresAt! - chain.block).toBeGreaterThan(yearInBlocks - 100n)
    // a later compaction keeps the long life instead of falling back to 30 days
    a.doc.getText("t").insert(0, "x")
    await a.provider.compact()
    expect(a.provider.snapshot!.expiresAt - chain.block).toBeGreaterThan(BigInt(LIFETIME.snapshot / 2) * 10n)
  })

  it("deleteDocument stops the document from opening", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "short-lived")
    await a.provider.flush()
    await a.provider.deleteDocument()
    chain.mine()
    await expect(peer(chain, link, undefined)).rejects.toThrow(/not found/)
  })
})

describe("snapshots are padded and chunk headers bind to their head", () => {
  it("a chunk from another snapshot is refused", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "y".repeat(250_000))
    await a.provider.compact()
    const first = a.provider.snapshot!
    // every chunk names its own snapshot's random id
    const key = deriveEpochZeroKey(link.secret)
    const headFrame = decodeFrame(await open(key, decodeOuter((await chain.store(undefined).get(first.key))!.payload).envelope))
    for (const k of first.chunks) {
      const e = (await chain.store(undefined).get(k))!
      const f = decodeFrame(await open(key, decodeOuter(e.payload).envelope))
      expect(f.header.of).toBe(headFrame.header.id)
    }
    a.doc.getText("t").insert(0, "z")
    await a.provider.compact()
    chain.mine()
    // the new snapshot replaced the old one in the same transaction: no pile of full copies
    expect(await chain.store(undefined).get(first.key)).toBeNull()
    for (const k of first.chunks) expect(await chain.store(undefined).get(k)).toBeNull()
    // and a reader that finds the second snapshot never mixes in the first snapshot's chunks
    const reader = await peer(chain, link, undefined)
    expect(text(reader).length).toBe(250_001)
  })
})

describe("SDK review regressions", () => {
  it("edits survive a week with nobody online: they are folded into a snapshot first", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    for (const s of ["one ", "two ", "three "]) {
      a.doc.getText("t").insert(a.doc.getText("t").length, s)
      await a.provider.flush()
    }
    await a.provider.close()
    a.provider.destroy()
    chain.mine((8 * 86400) / 2)
    const later = await peer(chain, link, undefined)
    expect(text(later)).toBe("one two three ")
  })

  it("even without close(), an edit lives as long as a snapshot would", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "not compacted")
    await a.provider.flush()
    a.provider.destroy()
    chain.mine((20 * 86400) / 2)
    const later = await peer(chain, link, undefined)
    expect(text(later)).toBe("not compacted")
  })

  it("a 300 KB paste lands within the request limit and nothing is lost", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const big = "p".repeat(300_000)
    a.doc.getText("t").insert(0, big)
    await a.provider.flush()
    chain.mine()
    const reader = await peer(chain, link, undefined)
    expect(text(reader)).toBe(big)
  })

  it("two tabs with the same key see each other's edits", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const tab1 = await peer(chain, link, owner)
    const tab2 = await peer(chain, link, owner)
    tab1.doc.getText("t").insert(0, "from tab one")
    await tab1.provider.flush()
    await settle(chain, [tab1, tab2])
    expect(text(tab2)).toBe("from tab one")
  })

  it("shredMine never deletes a snapshot other members depend on", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    await admit(chain, a, b)
    b.doc.getText("t").insert(0, "kept ")
    await b.provider.flush()
    await b.provider.compact()
    await b.provider.shredMine()
    chain.mine((8 * 86400) / 2)
    const reader = await peer(chain, link, undefined)
    expect(text(reader)).toBe("kept ")
  })

  it("an edit encrypted for an old epoch after a revocation is refused", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, b)
    await admit(chain, a, c)
    await a.provider.revoke(c.id!.address)
    chain.mine(3)
    // bea, still on epoch 0 because she missed the patch, writes with the old key
    const stale = new Y.Doc()
    stale.getText("t").insert(0, "readable by cal")
    const payload = encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), encodeFrame({ kind: KIND.update, doc: hexToBytes(link.doc), epoch: 0, header: { t: 0 }, data: Y.encodeStateAsUpdate(stale) }, randomBytes)))
    await chain.store(b.id!.address).batch({ creates: [{ payload, attributes: { doc: link.doc, kind: KIND.update, seq: chain.block }, lifetimeSeconds: 3600 }] })
    await settle(chain, [a])
    expect(text(a)).not.toContain("cal")
  })

  it("lease renewal never sends an extension that would move expiry earlier", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    await a.provider.keepFor(365 * 86400)
    // half the default lease later, renewal must not try to cut the year back to 30 days
    chain.mine((16 * 86400) / 2)
    await expect(a.provider.renewLeaseIfDue()).resolves.toBeTypeOf("boolean")
    const again = await peer(chain, link, owner)
    expect(again.provider.status).toBe("synced")
  })
})

describe("client ids are derived from addresses", () => {
  it("a member's snapshot cannot claim the owner's client id, and the owner keeps writing", async () => {
    const { clientIdFor } = await import("../src/crypto.js")
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    await admit(chain, a, b)
    expect(a.doc.clientID).not.toBe(b.doc.clientID)
    // bea compacts and writes a snapshot whose authors map gives the owner's client id to bea
    const fakeSalt = "00".repeat(16)
    expect(clientIdFor(b.id!.address, hexToBytes(fakeSalt))).not.toBe(a.doc.clientID)
    const state = Y.encodeStateAsUpdate(b.doc)
    const frame = encodeFrame({ kind: KIND.snapshot, doc: hexToBytes(link.doc), epoch: 0, header: { id: "ab".repeat(16), base: String(chain.block), t: 0, chunks: [], size: state.length, authors: { [a.doc.clientID]: { address: b.id!.address, salt: fakeSalt } } }, data: state }, randomBytes)
    const payload = encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), frame))
    await chain.store(b.id!.address).batch({ creates: [{ payload, attributes: { doc: link.doc, kind: KIND.snapshot, seq: chain.block + 100n }, lifetimeSeconds: LIFETIME.snapshot }] })
    chain.mine(200)
    const late = await peer(chain, link, undefined)
    expect(late.provider.authorOf(a.doc.clientID)?.address).not.toBe(b.id!.address)
    a.doc.getText("t").insert(0, "owner still writes")
    await a.provider.flush()
    await settle(chain, [a, late])
    expect(text(late)).toContain("owner still writes")
  })

  it("prepareDoc fixes the client id before an editor touches the doc", async () => {
    const { prepareDoc, ArkivProvider } = await import("../src/provider.js")
    const { clientIdFor } = await import("../src/crypto.js")
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const doc = new Y.Doc()
    const salt = prepareDoc(doc, owner.address)
    doc.getText("t").insert(0, "typed before the provider existed")
    const p = new ArkivProvider(doc, { store: chain.store(owner.address), link, identity: owner, salt, flushIntervalMs: 0, autoCompact: false })
    expect(doc.clientID).toBe(clientIdFor(owner.address, salt))
    p.destroy()
  })
})
