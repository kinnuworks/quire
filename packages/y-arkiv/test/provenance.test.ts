import { privateKeyToAccount } from "viem/accounts"
import { describe, expect, it } from "vitest"
import * as Y from "yjs"
import { blame } from "../src/blame.js"
import { MemoryChain } from "../src/memory.js"
import { KIND, LIFETIME } from "../src/protocol.js"
import { ArkivProvider } from "../src/provider.js"
import { decodeOuter, encodeFrame, encodeOuter } from "../src/codec.js"
import { clientIdFor, deriveEpochZeroKey, randomBytes, seal } from "../src/crypto.js"
import { bytesToHex, hexToBytes } from "../src/hex.js"
import type { DocLink } from "../src/link.js"
import type { ArkivStore, Hex } from "../src/store.js"
import { admit, identity, newDocument, peer, settle, text } from "./helpers.js"

describe("blame", () => {
  it("text compacted long ago is claimed in a normal load and proven with fullHistory", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "first draft")
    await a.provider.flush()
    await settle(chain, [a], 200)
    await a.provider.compact()
    await settle(chain, [a])

    const open = async (fullHistory: boolean) => {
      const doc = new Y.Doc()
      const p = new ArkivProvider(doc, { store: chain.store(undefined), link, flushIntervalMs: 0, autoCompact: false, fullHistory })
      await p.connect()
      return Object.assign(blame(doc, p).flat(), { history: p.history.length })
    }
    const quick = await open(false)
    expect([...quick]).toEqual([{ text: "first draft", address: owner.address, proven: false, via: owner.address }])
    expect(quick.history).toBe(0)
    const full = await open(true)
    expect(full).toHaveLength(1)
    expect(full[0]).toMatchObject({ text: "first draft", address: owner.address, proven: true })
    expect(full[0]!.entity).toMatch(/^0x[0-9a-f]{64}$/)
    // and the History tab lists that edit, though the snapshot covers it
    expect(full.history).toBe(1)
    await a.provider.destroy()
  })
})

describe("join requests", () => {
  it("a request buried under a full page of junk is still found by address", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const joiner = await peer(chain, link, identity("bea"))
    await joiner.provider.requestJoin()
    chain.mine()
    // then a stranger buries it under more junk join requests than one page holds
    const junk = chain.store(identity("junk").address)
    for (let b = 0; b < 4; b++) {
      await junk.batch({
        creates: Array.from({ length: 60 }, () => ({ payload: new Uint8Array(64), attributes: { doc: link.doc, kind: KIND.join, seq: 1n }, lifetimeSeconds: 3600 })),
      })
      chain.mine()
    }
    const o = await peer(chain, link, owner)
    expect(o.provider.joinRequests.some((j) => j.address === joiner.id!.address)).toBe(false)
    const found = await o.provider.findJoinRequest(joiner.id!.address)
    expect(found?.address).toBe(joiner.id!.address)
    await o.provider.approve(joiner.id!.address)
    await settle(chain, [o, joiner])
    expect(joiner.provider.role).toBe("writer")
  })
})

/** A member writes an epoch-0 snapshot entity holding any state they like, under their own address. */
async function forgeSnapshot(chain: MemoryChain, by: Hex, link: DocLink, state: Uint8Array): Promise<Hex> {
  const store = chain.store(by)
  const head = await store.head()
  const header = { id: bytesToHex(randomBytes(16)), base: head.toString(), t: Date.now(), chunks: [], size: state.length, authors: {} }
  const frame = encodeFrame({ kind: KIND.snapshot, doc: hexToBytes(link.doc), epoch: 0, header, data: state }, randomBytes)
  const payload = encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), frame))
  const r = await store.batch({ creates: [{ payload, attributes: { doc: link.doc, kind: KIND.snapshot, seq: head }, lifetimeSeconds: LIFETIME.snapshot }] })
  chain.mine()
  return r.created[0]!
}

/** Owner writes `first`, which leaves the catch-up window behind a compaction; then `second`, which depends on it. */
async function pendingSetup(first: (d: Y.Doc) => void, second: (d: Y.Doc) => void) {
  const chain = new MemoryChain()
  const { owner, link } = await newDocument(chain)
  const a = await peer(chain, link, owner)
  const cal = await peer(chain, link, identity("cal"))
  await admit(chain, a, cal)
  first(a.doc)
  await a.provider.flush()
  await settle(chain, [a, cal], 200)
  await a.provider.compact()
  await settle(chain, [a, cal])
  const base = Y.encodeStateAsUpdate(a.doc)
  second(a.doc)
  await a.provider.flush()
  await settle(chain, [a, cal])
  return { chain, link, owner, a, cal, base, ownerClient: a.doc.clientID }
}

describe("forged snapshots that fill a pending update's gap", () => {
  it("cannot put other text at the owner's verified clocks, and never become the lease", async () => {
    const { chain, link, cal, ownerClient } = await pendingSetup(
      (d) => d.getText("t").insert(0, "A"),
      (d) => d.getText("t").insert(1, "B"),
    )
    const evil = new Y.Doc()
    evil.clientID = ownerClient
    evil.getText("t").insert(0, "A")
    evil.getText("t").insert(1, "X")
    const forged = await forgeSnapshot(chain, cal.id!.address, link, Y.encodeStateAsUpdate(evil))
    const late = await peer(chain, link, undefined)
    expect(text(late)).toBe("AB")
    expect(late.provider.stats.rejectedWrites).toBeGreaterThan(0)
    expect(late.provider.snapshot?.key).not.toBe(forged)
    await cal.provider.destroy()
  })

  it("cannot swap the target of a link the owner added", async () => {
    const { chain, link, cal, ownerClient } = await pendingSetup(
      (d) => d.getText("t").insert(0, "pay here"),
      (d) => d.getText("t").format(4, 4, { link: "https://good.example" }),
    )
    const evil = new Y.Doc()
    evil.clientID = ownerClient
    evil.getText("t").insert(0, "pay here")
    evil.getText("t").format(4, 4, { link: "https://evil.example" })
    await forgeSnapshot(chain, cal.id!.address, link, Y.encodeStateAsUpdate(evil))
    const late = await peer(chain, link, undefined)
    expect(JSON.stringify(late.doc.getText("t").toDelta())).toContain("good.example")
    expect(JSON.stringify(late.doc.getText("t").toDelta())).not.toContain("evil.example")
    await cal.provider.destroy()
  })

  it("the check sees a map key swapped at a verified clock", async () => {
    const { overridesVerified } = await import("../src/provider.js")
    const honest = new Y.Doc()
    honest.clientID = 500
    honest.getMap("m").set("approved", "yes")
    const u = Y.encodeStateAsUpdate(honest)
    const forged = new Y.Doc()
    forged.clientID = 500
    forged.getMap("m").set("rejected", "yes")
    const d = new Y.Doc()
    Y.applyUpdate(d, Y.encodeStateAsUpdate(forged))
    Y.applyUpdate(d, u)
    expect(overridesVerified(d, [u])).toBe(true)
    const clean = new Y.Doc()
    Y.applyUpdate(clean, u)
    expect(overridesVerified(clean, [u])).toBe(false)
  })
})

describe("versions", () => {
  it("a version written without the readonly flag is refused, even after a patch", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const store = chain.store(owner.address)
    const secret = randomBytes(32)
    const make = async (words: string) => {
      const d = new Y.Doc()
      d.getText("t").insert(0, words)
      const frame = encodeFrame({ kind: KIND.version, doc: hexToBytes(link.doc), epoch: 0, header: { id: bytesToHex(randomBytes(16)), base: "1", t: 0, chunks: [], size: 0, authors: {} }, data: Y.encodeStateAsUpdate(d) }, randomBytes)
      return encodeOuter(0, await seal(secret, frame))
    }
    const r = await store.batch({ creates: [{ payload: await make("approved 10,000"), attributes: { doc: link.doc, kind: KIND.version, seq: 1n }, lifetimeSeconds: LIFETIME.version }] })
    chain.mine()
    const version = { key: r.created[0]!, secret }
    await expect(ArkivProvider.openVersion(chain.store(undefined), version)).rejects.toThrow(/not readonly/)
    // the honest path still opens
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "approved 10,000")
    const real = await a.provider.publishVersion()
    chain.mine()
    const opened = await ArkivProvider.openVersion(chain.store(undefined), real)
    expect(opened.doc.getText("t").toString()).toBe("approved 10,000")
  })
})

describe("history", () => {
  it("a cold load lists the edits it read in the catch-up window, even those a snapshot covers", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "one")
    await a.provider.flush()
    await settle(chain, [a])
    a.doc.getText("t").insert(3, " two")
    await a.provider.flush()
    await settle(chain, [a])
    await a.provider.compact()
    await settle(chain, [a])
    const late = await peer(chain, link, undefined)
    expect(text(late)).toBe("one two")
    expect(late.provider.history).toHaveLength(2)
    await a.provider.destroy()
  })
})

describe("lease", () => {
  it("a tab left open renews the lease on its resync timer, without a reload", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const doc = new Y.Doc()
    const p = new ArkivProvider(doc, { store: chain.store(owner.address), link, identity: owner, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 20 })
    await p.connect()
    const before = p.snapshot!.expiresAt
    chain.mine(Number((before - chain.block) / 2n) + 10)
    for (let i = 0; i < 50 && p.snapshot!.expiresAt === before; i++) {
      await new Promise((r) => setTimeout(r, 20))
      chain.mine()
      await p.idle()
    }
    expect(p.snapshot!.expiresAt).toBeGreaterThan(before)
    p.destroy()
  })
})

/** A member writes an update entity with any Yjs bytes, under their own signed salt. */
async function rawUpdate(chain: MemoryChain, who: { address: Hex; privateKey: Hex }, link: DocLink, salt: Uint8Array, data: Uint8Array): Promise<Hex> {
  const store = chain.store(who.address)
  const head = await store.head()
  const sig = await privateKeyToAccount(who.privateKey).signMessage({ message: { raw: new Uint8Array([...new TextEncoder().encode("quire1:salt:"), ...hexToBytes(link.doc), ...salt]) } })
  const frame = encodeFrame({ kind: KIND.update, doc: hexToBytes(link.doc), epoch: 0, header: { t: Date.now(), salt: bytesToHex(salt), sig }, data }, randomBytes)
  const payload = encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), frame))
  const r = await store.batch({ creates: [{ payload, attributes: { doc: link.doc, kind: KIND.update, seq: head }, lifetimeSeconds: LIFETIME.snapshot }] })
  chain.mine()
  return r.created[0]!
}

describe("blame cannot be faked", () => {
  it("an update with a Skip gap does not prove the snapshot text inside the gap", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    // Bea "types" a paste one character at a time, keeping each transaction's bytes
    const salt = randomBytes(16)
    const d = new Y.Doc()
    d.clientID = clientIdFor(bea.id!.address, salt)
    Y.applyUpdate(d, Y.encodeStateAsUpdate(bea.doc))
    const steps: Uint8Array[] = []
    d.on("update", (u: Uint8Array) => steps.push(u))
    const t = d.getText("t")
    const pasted = "PASTED ESSAY, NEVER TYPED"
    for (let i = 0; i < pasted.length; i++) t.insert(i, pasted[i]!)
    // the whole paste goes in a snapshot; the only update carries the first and last characters
    await forgeSnapshot(chain, bea.id!.address, link, Y.encodeStateAsUpdate(d))
    chain.mine(5)
    await rawUpdate(chain, bea.id!, link, salt, Y.mergeUpdates([steps[0]!, steps[steps.length - 1]!]))
    const doc = new Y.Doc()
    const p = new ArkivProvider(doc, { store: chain.store(undefined), link, flushIntervalMs: 0, autoCompact: false, fullHistory: true })
    await p.connect()
    expect(doc.getText("t").toString()).toBe(pasted)
    const proven = blame(doc, p).flat().filter((r) => r.proven).map((r) => r.text).join("")
    expect(proven).toBe("PD")
    await a.provider.destroy()
  })
})

describe("revocation with a dropped socket", () => {
  it("a writer who missed the rotation does not write under the old key", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const cal = await peer(chain, link, identity("cal"))
    await admit(chain, a, cal)
    // Bea's socket is down from the start: her store never delivers events
    const beaId = identity("bea")
    const real = chain.store(beaId.address)
    const muted: ArkivStore = { ...real, address: real.address, head: () => real.head(), batch: (b) => real.batch(b), predictKeys: (n) => real.predictKeys(n), query: (q) => real.query(q), get: (k, bl) => real.get(k, bl), watch: () => () => undefined }
    const bdoc = new Y.Doc()
    const bea = { doc: bdoc, id: beaId, provider: new ArkivProvider(bdoc, { store: muted, link, identity: beaId, flushIntervalMs: 0, autoCompact: false }) }
    await bea.provider.connect()
    await bea.provider.requestJoin()
    await settle(chain, [a, cal])
    await a.provider.approve(beaId.address)
    await settle(chain, [a, cal])
    await bea.provider.resync()
    expect(bea.provider.role).toBe("writer")
    await a.provider.revoke(cal.id!.address)
    await settle(chain, [a, cal])
    expect(bea.provider.acl!.epoch).toBe(0) // she has not heard
    bea.doc.getText("t").insert(0, "after Cal left")
    const info = await bea.provider.flush()
    const entity = await chain.store(undefined).get(info!.entity)
    expect(decodeOuter(entity!.payload).epoch).toBe(1)
    await settle(chain, [a, cal])
    expect(a.doc.getText("t").toString()).toContain("after Cal left")
    expect(cal.doc.getText("t").toString()).not.toContain("after Cal left")
  })
})

describe("keep my proof", () => {
  it("a writer's edits outlive the 30-day lease, so blame still proves them after it", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    bea.doc.getText("t").insert(0, "my own words")
    await bea.provider.flush()
    await settle(chain, [a, bea])
    await a.provider.compact()
    await settle(chain, [a, bea])
    const r = await bea.provider.keepMyProof(365 * 86400)
    expect(r.extended).toBe(2) // Bea's one edit and the member list
    // asking again at once has nothing to move later, so it sends nothing (Arkiv would revert it)
    expect((await bea.provider.keepMyProof(365 * 86400)).extended).toBe(0)
    // 40 days pass with nobody opening the document: the snapshots lapse, Bea's edit and the list do not
    chain.mine((40 * 86400) / 2)
    const doc = new Y.Doc()
    const p = new ArkivProvider(doc, { store: chain.store(undefined), link, flushIntervalMs: 0, autoCompact: false, fullHistory: true })
    await p.connect()
    const runs = blame(doc, p).flat()
    expect(runs.find((x) => x.text.includes("my own words"))).toMatchObject({ proven: true, address: bea.id!.address })
    a.provider.destroy()
    bea.provider.destroy()
  })
})

describe("removed members", () => {
  it("what they wrote before removal stays proven; what they write after never counts", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    bea.doc.getText("t").insert(0, "before ")
    await bea.provider.flush()
    await settle(chain, [a, bea])
    await a.provider.revoke(bea.id!.address)
    await settle(chain, [a, bea])
    // Bea still holds the epoch 0 key and a signed salt: she writes a perfectly valid-looking edit
    const salt = randomBytes(16)
    const d = new Y.Doc()
    d.clientID = clientIdFor(bea.id!.address, salt)
    Y.applyUpdate(d, Y.encodeStateAsUpdate(bea.doc))
    const sv = Y.encodeStateVector(d)
    d.getText("t").insert(d.getText("t").length, "AFTER")
    const late = await rawUpdate(chain, bea.id!, link, salt, Y.encodeStateAsUpdate(d, sv))
    const doc = new Y.Doc()
    const p = new ArkivProvider(doc, { store: chain.store(owner.address), link, identity: owner, flushIntervalMs: 0, autoCompact: false, fullHistory: true })
    await p.connect()
    expect(doc.getText("t").toString()).toBe("before ")
    expect(blame(doc, p).flat()).toEqual([expect.objectContaining({ text: "before ", address: bea.id!.address, proven: true })])
    expect((await p.outsiderEntities()).map((e) => e.key)).toEqual([late])
    a.provider.destroy()
  })
})
