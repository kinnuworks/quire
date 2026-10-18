import { privateKeyToAccount } from "viem/accounts"
import { describe, expect, it } from "vitest"
import * as Y from "yjs"
import { blame } from "../src/blame.js"
import { MemoryChain } from "../src/memory.js"
import { KIND, LIFETIME } from "../src/protocol.js"
import { ArkivProvider } from "../src/provider.js"
import { decodeFrame, decodeOuter, encodeFrame, encodeOuter } from "../src/codec.js"
import { clientIdFor, deriveEpochZeroKey, open, randomBytes, seal } from "../src/crypto.js"
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
        creates: Array.from({ length: 60 }, () => ({ payload: new Uint8Array(64), attributes: { doc: link.doc, kind: KIND.join, seq: 1n }, lifetimeSeconds: 3600, readonly: true })),
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
  const r = await store.batch({ creates: [{ payload, attributes: { doc: link.doc, kind: KIND.snapshot, seq: head }, lifetimeSeconds: LIFETIME.snapshot, readonly: true }] })
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
async function rawUpdate(chain: MemoryChain, who: { address: Hex; privateKey: Hex }, link: DocLink, salt: Uint8Array, data: Uint8Array, seq?: bigint): Promise<Hex> {
  const store = chain.store(who.address)
  const head = seq ?? (await store.head())
  const sig = await privateKeyToAccount(who.privateKey).signMessage({ message: { raw: new Uint8Array([...new TextEncoder().encode("quire1:salt:"), ...hexToBytes(link.doc), ...salt]) } })
  const frame = encodeFrame({ kind: KIND.update, doc: hexToBytes(link.doc), epoch: 0, header: { t: Date.now(), salt: bytesToHex(salt), sig }, data }, randomBytes)
  const payload = encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), frame))
  const r = await store.batch({ creates: [{ payload, attributes: { doc: link.doc, kind: KIND.update, seq: head }, lifetimeSeconds: LIFETIME.snapshot, readonly: true }] })
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
    // the paste is one merged Yjs item whose range the update covers only at its two ends, so all of it
    // is claimed (PROTOCOL section 5: a merged item is proven only if its whole range is covered)
    expect(proven).toBe("")
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
  it("in a real editor document, a writer's words inside someone else's paragraph stay proven after the lease", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    // the owner creates the paragraph (Tiptap's structure); Bea types inside it, so her edit depends on his items
    const p = new Y.XmlElement("paragraph")
    p.insert(0, [new Y.XmlText("Owner opens. ")])
    a.doc.getXmlFragment("default").push([p])
    await a.provider.flush()
    await settle(chain, [a, bea])
    const text = (bea.doc.getXmlFragment("default").get(0) as Y.XmlElement).get(0) as Y.XmlText
    text.insert(text.length, "Bea's own words.")
    await bea.provider.flush()
    await settle(chain, [a, bea])
    await a.provider.compact()
    await settle(chain, [a, bea])
    // proof cannot outlive the document: until the owner keeps it longer, keep-proof refuses
    await expect(bea.provider.keepMyProof(365 * 86400)).rejects.toThrow(/Ask the owner to keep it longer/)
    await a.provider.keepFor(2 * 365 * 86400)
    await settle(chain, [a, bea])
    const r = await bea.provider.keepMyProof(365 * 86400)
    expect(r.extended).toBe(2) // her 30-day edit and a snapshot of hers; the owner already moved the member list out
    // asking again at once has nothing to move later, so it sends nothing (Arkiv would revert it)
    expect((await bea.provider.keepMyProof(365 * 86400)).extended).toBe(0)
    // a later routine compaction by Bea must not shorten her kept snapshot
    text.insert(text.length, " More.")
    await bea.provider.flush()
    await settle(chain, [a, bea])
    await bea.provider.compact()
    await settle(chain, [a, bea])
    // 40 days pass with nobody opening the document: the owner's 30-day pieces lapse, Bea's do not
    chain.mine((40 * 86400) / 2)
    const doc = new Y.Doc()
    const reader = new ArkivProvider(doc, { store: chain.store(undefined), link, flushIntervalMs: 0, autoCompact: false, fullHistory: true })
    await reader.connect()
    const runs = blame(doc, reader).flat()
    expect(runs.map((x) => x.text).join("")).toContain("Owner opens. Bea's own words.")
    expect(runs.find((x) => x.text.includes("Bea's own words."))).toMatchObject({ proven: true, address: bea.id!.address })
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

describe("qs lower bound", () => {
  it("an update whose qs is backdated past the catch-up margin counts for no reader, live or cold", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    chain.mine(200)
    const salt = randomBytes(16)
    const d = new Y.Doc()
    d.clientID = clientIdFor(bea.id!.address, salt)
    d.getText("t").insert(0, "backdated")
    const head = await chain.store(undefined).head()
    await rawUpdate(chain, bea.id!, link, salt, Y.encodeStateAsUpdate(d), head - 61n)
    await settle(chain, [a, bea])
    expect(a.doc.getText("t").toString()).not.toContain("backdated") // live
    const cold = await peer(chain, link, undefined)
    expect(cold.doc.getText("t").toString()).not.toContain("backdated")
    // 60 blocks behind is still within the margin
    const d2 = new Y.Doc()
    const salt2 = randomBytes(16)
    d2.clientID = clientIdFor(bea.id!.address, salt2)
    d2.getText("t").insert(0, "late but fine")
    await rawUpdate(chain, bea.id!, link, salt2, Y.encodeStateAsUpdate(d2), (await chain.store(undefined).head()) - 60n)
    await settle(chain, [a, bea])
    expect(a.doc.getText("t").toString()).toContain("late but fine")
    a.provider.destroy()
  })
})

describe("revocation with shredOldEpoch", () => {
  it("the old link no longer opens the owner's earlier entities; members still read everything", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    const cal = await peer(chain, link, identity("cal"))
    await admit(chain, a, bea)
    await admit(chain, a, cal)
    a.doc.getText("t").insert(0, "owner's early text ")
    await a.provider.flush()
    await settle(chain, [a, bea, cal])
    const r = await a.provider.revoke(cal.id!.address, { shredOldEpoch: true })
    await settle(chain, [a, bea, cal])
    expect(r.shredded).toBeGreaterThanOrEqual(2) // the first snapshot and the early edit at least
    // what is left in state from the owner under the epoch 0 key, which the link alone opens
    const left = (await chain.store(undefined).query({ doc: link.doc, creators: [owner.address] })).entities
    expect(left.filter((e) => e.attributes.kind !== KIND.acl && decodeOuter(e.payload).epoch === 0)).toHaveLength(0)
    // a member opening fresh still reads the whole document from the new-epoch snapshot
    const fresh = await peer(chain, link, bea.id)
    expect(fresh.doc.getText("t").toString()).toContain("owner's early text")
    a.provider.destroy()
  })
})

describe("claimed text names its carrier", () => {
  it("text slipped under another member's client id, with no authors entry, is claimed via the snapshot's writer", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    const mal = await peer(chain, link, identity("mallory"))
    await admit(chain, a, bea)
    await admit(chain, a, mal)
    bea.doc.getText("t").insert(0, "Bea writes.")
    await bea.provider.flush()
    await settle(chain, [a, bea, mal])
    // Mallory continues Bea's client id at clocks Bea never used, and leaves the authors table empty
    const evil = new Y.Doc()
    Y.applyUpdate(evil, Y.encodeStateAsUpdate(mal.doc))
    evil.clientID = bea.doc.clientID // after applying, or Yjs would pick a fresh id on the clash
    evil.getText("t").insert(evil.getText("t").length, " I resign.")
    await forgeSnapshot(chain, mal.id!.address, link, Y.encodeStateAsUpdate(evil))
    const doc = new Y.Doc()
    const p = new ArkivProvider(doc, { store: chain.store(undefined), link, flushIntervalMs: 0, autoCompact: false, fullHistory: true })
    await p.connect()
    const runs = blame(doc, p).flat()
    expect(runs.find((r) => r.text.includes("I resign"))).toMatchObject({ address: bea.id!.address, proven: false, via: mal.id!.address })
    // Bea's genuine words and the forged ones merged into one Yjs item, so under the whole-item rule
    // all of it reads as claimed, carried by Mallory's snapshot: never as Bea's proven text
    expect(runs.find((r) => r.text.includes("Bea writes"))).toMatchObject({ proven: false, via: mal.id!.address })
    // the editor's colored bars ask authorOfItem directly: it must name the carrier too
    type It = { id: { client: number; clock: number }; content: { str?: string }; right: It | null }
    let item = (doc.getText("t") as unknown as { _start: It | null })._start
    while (item && !item.content.str?.includes("resign")) item = item.right
    // Yjs may merge Bea's real text and the forged part into one item: ask about the forged clocks
    const at = item!.id.clock + item!.content.str!.indexOf(" I resign.")
    expect(p.authorOfItem(item!.id.client, at, " I resign.".length)).toMatchObject({ proven: false, via: mal.id!.address })
    a.provider.destroy()
  })
})

describe("member list expiry seen by another tab", () => {
  it("keepMyProof re-reads the list's expiry, so a stale view cannot make the batch revert", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    bea.doc.getText("t").insert(0, "mine")
    await bea.provider.flush()
    await settle(chain, [a, bea])
    // Bea's socket misses it: the owner keeps proof for 3 years, moving the member list far out
    ;(bea.provider as unknown as { unwatch: () => void }).unwatch()
    await a.provider.keepFor(3 * 365 * 86400)
    chain.mine()
    await expect(bea.provider.keepMyProof(365 * 86400)).resolves.toMatchObject({ extended: expect.any(Number) })
    a.provider.destroy()
  })
})

describe("read-only member session", () => {
  it("reads past a rotation with a member key and never writes", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    const cal = await peer(chain, link, identity("cal"))
    await admit(chain, a, bea)
    await admit(chain, a, cal)
    a.doc.getText("t").insert(0, "before and after")
    await a.provider.flush()
    await settle(chain, [a, bea, cal])
    await a.provider.revoke(cal.id!.address)
    await settle(chain, [a, bea, cal])
    // half the lease later a writer's session would renew it; a read-only one must not
    chain.mine((16 * 86400) / 2)
    const batches = { n: 0 }
    const real = chain.store(bea.id!.address)
    const store = { ...real, address: real.address, head: () => real.head(), predictKeys: (n: number) => real.predictKeys(n), query: (q: never) => real.query(q), get: (k: Hex, b?: bigint) => real.get(k, b), watch: () => () => undefined, batch: (s: never) => (batches.n++, real.batch(s)) } as ArkivStore
    const doc = new Y.Doc()
    const p = new ArkivProvider(doc, { store, link, identity: bea.id, readOnly: true, flushIntervalMs: 0, autoCompact: false })
    await p.connect()
    await p.idle()
    expect(p.acl!.rosterHidden).toBe(false)
    expect(doc.getText("t").toString()).toBe("before and after")
    await expect(p.compact()).rejects.toThrow(/read-only/)
    await expect(p.keepMyProof(86400)).rejects.toThrow()
    await expect(p.shredMine()).rejects.toThrow(/read-only/)
    expect(batches.n).toBe(0)
    a.provider.destroy()
  })
})

describe("rotate key", () => {
  it("after a rotation the link alone opens nothing new; members carry on; a link holder can still ask to join", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    a.doc.getText("t").insert(0, "old ")
    await a.provider.flush()
    await settle(chain, [a, bea])
    await a.provider.rotateKey()
    await settle(chain, [a, bea])
    expect(a.provider.acl!.epoch).toBe(1)
    a.doc.getText("t").insert(4, "new")
    await a.provider.flush()
    await settle(chain, [a, bea])
    expect(bea.doc.getText("t").toString()).toBe("old new")
    const outsider = await peer(chain, link, undefined)
    expect(outsider.provider.acl!.rosterHidden).toBe(true)
    expect(outsider.doc.getText("t").toString()).not.toContain("new")
    // someone with the old link asks to join and, once added, reads everything
    const cal = await peer(chain, link, identity("cal"))
    await admit(chain, a, cal)
    const calFresh = await peer(chain, link, cal.id)
    expect(calFresh.doc.getText("t").toString()).toBe("old new")
    a.provider.destroy()
  })
})

describe("composition timeline", () => {
  it("lists each edit in block order with characters added and removed", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const t = a.doc.getText("t")
    t.insert(0, "first draft")
    await a.provider.flush()
    await settle(chain, [a], 30)
    t.delete(0, 6)
    t.insert(0, "second")
    await a.provider.flush()
    await settle(chain, [a], 30)
    await a.provider.compact()
    await settle(chain, [a])
    const doc = new Y.Doc()
    const p = new ArkivProvider(doc, { store: chain.store(undefined), link, flushIntervalMs: 0, autoCompact: false, fullHistory: true, readOnly: true })
    await p.connect()
    const { compositionTimeline } = await import("../src/blame.js")
    const tl = compositionTimeline(p)
    expect(tl.map((e) => [e.added, e.removed])).toEqual([
      [11, 0],
      [6, 6],
    ])
    expect(tl[0]!.block < tl[1]!.block).toBe(true)
    expect(tl.every((e) => e.author === owner.address)).toBe(true)
    a.provider.destroy()
  })
})

describe("conflicting edits from one member", () => {
  it("two updates claiming the same clocks cannot blank the document for cold readers", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    const p0 = new Y.XmlElement("paragraph")
    p0.insert(0, [new Y.XmlText("Owner's long-standing paragraph.")])
    a.doc.getXmlFragment("default").push([p0])
    await a.provider.flush()
    await settle(chain, [a, bea], 200)
    await a.provider.compact()
    await settle(chain, [a, bea])
    // Bea writes two valid updates under one salt from one base: same clocks, different text
    const salt = randomBytes(16)
    for (const words of ["Bea one.", "Bea two."]) {
      const d = new Y.Doc()
      d.clientID = clientIdFor(bea.id!.address, salt)
      Y.applyUpdate(d, Y.encodeStateAsUpdate(bea.doc))
      const sv = Y.encodeStateVector(d)
      const p = new Y.XmlElement("paragraph")
      p.insert(0, [new Y.XmlText(words)])
      d.getXmlFragment("default").push([p])
      await rawUpdate(chain, bea.id!, link, salt, Y.encodeStateAsUpdate(d, sv))
    }
    await settle(chain, [a, bea])
    const cold = new Y.Doc()
    const r = new ArkivProvider(cold, { store: chain.store(undefined), link, flushIntervalMs: 0, autoCompact: false })
    await r.connect()
    const text = cold.getXmlFragment("default").toArray().map((x) => ((x as Y.XmlElement).get(0) as Y.XmlText).toString())
    expect(text).toEqual(["Owner's long-standing paragraph.", "Bea one."])
    expect(r.stats.snapshotsApplied).toBeGreaterThan(0)
    a.provider.destroy()
  })
})

describe("read-only owner session", () => {
  it("refuses owner writes too, at the store, whatever path they take", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const doc = new Y.Doc()
    const p = new ArkivProvider(doc, { store: chain.store(owner.address), link, identity: owner, readOnly: true, flushIntervalMs: 0, autoCompact: false })
    await p.connect()
    const before = (await chain.store(undefined).query({ doc: link.doc })).entities.length
    await expect(p.keepFor(90 * 86400)).rejects.toThrow(/read-only/)
    await expect(p.rotateKey()).rejects.toThrow(/read-only/)
    chain.mine()
    expect((await chain.store(undefined).query({ doc: link.doc })).entities.length).toBe(before)
    p.destroy()
  })
})

describe("membership is tied to time", () => {
  it("an edit written before its creator was added never counts, even after the owner adds them", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const mal = await peer(chain, link, identity("mallory"))
    // Mallory holds the link and writes a valid edit while she is nobody
    const salt = randomBytes(16)
    const d = new Y.Doc()
    d.clientID = clientIdFor(mal.id!.address, salt)
    d.getText("t").insert(0, "EARLY")
    await rawUpdate(chain, mal.id!, link, salt, Y.encodeStateAsUpdate(d))
    await settle(chain, [a, mal])
    // later the owner adds her, and she writes for real
    await admit(chain, a, mal)
    mal.doc.getText("t").insert(0, "after joining ")
    await mal.provider.flush()
    await settle(chain, [a, mal])
    const cold = await peer(chain, link, undefined)
    expect(cold.doc.getText("t").toString()).toBe("after joining ")
    a.provider.destroy()
  })
})

describe("edits cannot be rewritten later", () => {
  it("a writer cannot patch an edit (it is readonly), and an edit that is not readonly never counts", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    bea.doc.getText("t").insert(0, "pay 100")
    const info = await bea.provider.flush()
    await settle(chain, [a, bea])
    // Bea tries to rewrite her edit in place, keeping its block: the chain refuses
    const original = await chain.store(undefined).get(info!.entity)
    expect(original!.readonly).toBe(true)
    await expect(chain.store(bea.id!.address).batch({ patches: [{ key: info!.entity, payload: original!.payload, attributes: original!.attributes }] })).rejects.toThrow(/readonly/)
    // and an update written without the flag is ignored by readers
    const salt = randomBytes(16)
    const d = new Y.Doc()
    d.clientID = clientIdFor(bea.id!.address, salt)
    Y.applyUpdate(d, Y.encodeStateAsUpdate(bea.doc))
    const sv = Y.encodeStateVector(d)
    d.getText("t").insert(d.getText("t").length, " PATCHABLE")
    const store = chain.store(bea.id!.address)
    const sig = await privateKeyToAccount(bea.id!.privateKey).signMessage({ message: { raw: new Uint8Array([...new TextEncoder().encode("quire1:salt:"), ...hexToBytes(link.doc), ...salt]) } })
    const frame = encodeFrame({ kind: KIND.update, doc: hexToBytes(link.doc), epoch: 0, header: { t: 1, salt: bytesToHex(salt), sig }, data: Y.encodeStateAsUpdate(d, sv) }, randomBytes)
    await store.batch({ creates: [{ payload: encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), frame)), attributes: { doc: link.doc, kind: KIND.update, seq: await store.head() }, lifetimeSeconds: 3600 }] })
    await settle(chain, [a, bea])
    const cold = await peer(chain, link, undefined)
    expect(cold.doc.getText("t").toString()).toBe("pay 100")
    a.provider.destroy()
  })
})

describe("membership intervals", () => {
  it("a member removed, re-added and removed again: edits from the gap never count", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    bea.doc.getText("t").insert(0, "first stint. ")
    await bea.provider.flush()
    await settle(chain, [a, bea])
    await a.provider.revoke(bea.id!.address)
    await settle(chain, [a, bea])
    // in the gap, Bea writes a valid edit under the old key she still holds
    const salt = randomBytes(16)
    const d = new Y.Doc()
    Y.applyUpdate(d, Y.encodeStateAsUpdate(bea.doc))
    d.clientID = clientIdFor(bea.id!.address, salt)
    const sv = Y.encodeStateVector(d)
    d.getText("t").insert(d.getText("t").length, "GAP ")
    await rawUpdate(chain, bea.id!, link, salt, Y.encodeStateAsUpdate(d, sv))
    await settle(chain, [a])
    // re-added, she writes again, then is removed a second time
    const bea2 = await peer(chain, link, bea.id)
    await admit(chain, a, bea2)
    bea2.doc.getText("t").insert(bea2.doc.getText("t").length, "second stint.")
    await bea2.provider.flush()
    await settle(chain, [a, bea2])
    await a.provider.revoke(bea.id!.address)
    await settle(chain, [a, bea2])
    const cold = new Y.Doc()
    const p = new ArkivProvider(cold, { store: chain.store(owner.address), link, identity: owner, readOnly: true, flushIntervalMs: 0, autoCompact: false, fullHistory: true })
    await p.connect()
    const proven = blame(cold, p).flat().filter((r) => r.proven).map((r) => r.text).join("")
    expect(proven).toContain("first stint.")
    expect(proven).toContain("second stint.")
    expect(proven).not.toContain("GAP")
    a.provider.destroy()
  })
})

describe("expiry ceiling", () => {
  it("a member who extends their own snapshot past the owner's lifetime gets it ignored by readers", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    bea.doc.getText("t").insert(0, "kept too long")
    await bea.provider.flush()
    await settle(chain, [a, bea])
    await bea.provider.compact()
    await settle(chain, [a, bea])
    const snap = bea.provider.snapshot!
    // another client could do this: three years, though the owner never chose to keep the document
    await chain.store(bea.id!.address).batch({ extensions: [{ key: snap.key, lifetimeSeconds: 3 * 365 * 86400 }] })
    chain.mine()
    const fresh = await peer(chain, link, undefined)
    expect(fresh.provider.appliedKeys.has(snap.key)).toBe(false)
    // once the owner keeps the document that long, the same snapshot counts
    await a.provider.keepFor(3 * 365 * 86400 + 86400)
    await settle(chain, [a, bea])
    const later = await peer(chain, link, undefined)
    expect(later.provider.appliedKeys.has(snap.key) || later.provider.snapshot!.creator !== bea.id!.address).toBe(true)
    a.provider.destroy()
  })
})

describe("membership at each edit's block", () => {
  it("an owner who rewrites the member list's history cannot erase a member's proof or backdate a newcomer", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    const mal = await peer(chain, link, identity("mallory"))
    await admit(chain, a, bea)
    bea.doc.getText("t").insert(0, "Bea wrote this. ")
    await bea.provider.flush()
    await settle(chain, [a, bea, mal])
    // Mallory writes while she is nobody
    const salt = randomBytes(16)
    const d = new Y.Doc()
    Y.applyUpdate(d, Y.encodeStateAsUpdate(bea.doc))
    d.clientID = clientIdFor(mal.id!.address, salt)
    const sv = Y.encodeStateVector(d)
    d.getText("t").insert(d.getText("t").length, "EARLY ")
    await rawUpdate(chain, mal.id!, link, salt, Y.encodeStateAsUpdate(d, sv))
    await settle(chain, [a, bea, mal])
    await a.provider.revoke(bea.id!.address)
    await settle(chain, [a, bea, mal])
    await admit(chain, a, mal)
    // the owner rewrites history: no trace that Bea was ever a member, and Mallory "added" at block 0
    await (a.provider as unknown as { updateAcl: (f: (acl: { revoked: unknown[]; members: { address: string; addedAtBlock: string }[] }) => Promise<object>) => Promise<void> }).updateAcl(async (acl) => {
      acl.revoked = []
      for (const m of acl.members) if (m.address === mal.id!.address) m.addedAtBlock = "0"
      return {}
    })
    await settle(chain, [a, bea, mal])
    const read = async (membershipAtBlock: boolean, fullHistory = true) => {
      const doc = new Y.Doc()
      const p = new ArkivProvider(doc, { store: chain.store(owner.address), link, identity: owner, readOnly: true, flushIntervalMs: 0, autoCompact: false, fullHistory, membershipAtBlock })
      await p.connect()
      const proven = blame(doc, p).flat().filter((r) => r.proven)
      return { bea: proven.filter((r) => r.address === bea.id!.address).map((r) => r.text).join(""), mal: proven.filter((r) => r.address === mal.id!.address).map((r) => r.text).join("") }
    }
    // against today's rewritten list, the forgery works both ways
    expect(await read(false)).toEqual({ bea: "", mal: "EARLY " })
    // against the list as it stood at each edit's block, it does not
    expect(await read(true)).toEqual({ bea: "Bea wrote this. ", mal: "" })
    // a normal session, as the app opens one: the backdated newcomer still proves nothing
    expect((await read(true, false)).mal).toBe("")
    a.provider.destroy()
  })
})

describe("snapshot expiry under keepUntil", () => {
  it("does not creep past the owner's ceiling when each transaction lands after the head the writer read", async () => {
    const chain = new MemoryChain()
    chain.mine(10)
    // on a real chain the head is the last sealed block and a transaction lands in the next one
    const lagging = (address: Hex): ArkivStore => ({ ...chain.store(address), head: async () => chain.block - 1n })
    const owner = identity("Owner")
    const link: DocLink = { doc: `0x${bytesToHex(randomBytes(32))}`, secret: randomBytes(32), owner: owner.address }
    await ArkivProvider.createDocument({ store: lagging(owner.address), link, identity: owner })
    chain.mine()
    const open = async () => {
      const doc = new Y.Doc()
      const p = new ArkivProvider(doc, { store: lagging(owner.address), link, identity: owner, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0 })
      p.on("error", () => undefined)
      await p.connect()
      return { doc, p }
    }
    const first = await open()
    await first.p.keepFor(365 * 86400)
    chain.mine()
    const keepUntil = BigInt(first.p.acl!.keepUntil!)
    first.p.destroy()
    const expiries: bigint[] = []
    for (let i = 0; i < 6; i++) {
      const s = await open()
      const p = new Y.XmlElement("paragraph")
      p.insert(0, [new Y.XmlText(`session ${i}`)])
      s.doc.getXmlFragment("default").push([p])
      await s.p.flush()
      chain.mine()
      await s.p.compact()
      chain.mine()
      expiries.push((await chain.store(owner.address).get(s.p.snapshot!.key))!.expiresAt)
      s.p.destroy()
    }
    // a block or two of landing delay, once, never growing session after session
    for (const e of expiries) expect(e - keepUntil).toBeLessThanOrEqual(3n)
  })
})

describe("audit flood", () => {
  it("an audit reads only addresses some version of the member list named, so junk from strangers never enters it", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "Owner wrote this.")
    await a.provider.flush()
    await settle(chain, [a])
    // anyone can write `u` entities under the public document id; these are not even ciphertext
    const stranger = identity("stranger")
    for (let i = 0; i < 6; i++) {
      await chain.store(stranger.address).batch({
        creates: Array.from({ length: 200 }, () => ({ payload: randomBytes(64), attributes: { doc: link.doc, kind: KIND.update, seq: chain.block }, lifetimeSeconds: 3600, readonly: true })),
      })
      chain.mine()
    }
    const base = chain.store(undefined)
    let queries = 0
    const counting: ArkivStore = { ...base, query: (spec) => (queries++, base.query(spec)) }
    const doc = new Y.Doc()
    const audit = new ArkivProvider(doc, { store: counting, link, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0, readOnly: true, fullHistory: true, membershipAtBlock: true })
    await audit.connect()
    expect(doc.getText("t").toString()).toBe("Owner wrote this.")
    expect(audit.auditNarrowed).toBe(false)
    // ACL, snapshots, one update query for every address the list ever named: no junk page at all
    expect(queries).toBeLessThanOrEqual(3)
    audit.destroy()
  })
})

describe("a member's own snapshot speaks for their client id", () => {
  it("a newer snapshot from another member that rewrites those clocks is refused, on load and live", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    const m = await peer(chain, link, identity("mal"))
    await admit(chain, a, b)
    await admit(chain, a, m)
    const before = Y.encodeStateAsUpdate(b.doc)
    b.doc.getText("t").insert(0, "Bea: I approve a budget of 100.")
    await b.provider.flush()
    await settle(chain, [a, b, m])
    const edit = (await chain.store(undefined).query({ doc: link.doc, kind: KIND.update, creators: [b.id!.address] })).entities[0]!
    const { salt, sig } = decodeFrame(await open(deriveEpochZeroKey(link.secret), decodeOuter(edit.payload).envelope)).header as { salt: string; sig: Hex }
    // Bea's edit leaves the catch-up window; her own snapshot now holds her words
    chain.mine(100)
    await a.provider.compact()
    await b.provider.compact()
    await settle(chain, [a, b, m])
    // a session that loads now has Bea's words from her snapshot only
    const watcher = await peer(chain, link, undefined)
    expect(text(watcher)).toBe("Bea: I approve a budget of 100.")
    const rejectedBefore = watcher.provider.stats.rejectedWrites
    // Mal: the state before Bea's edit, plus other words at Bea's client id and clocks
    const forged = new Y.Doc()
    Y.applyUpdate(forged, before)
    forged.clientID = clientIdFor(b.id!.address, hexToBytes(salt))
    forged.getText("t").insert(0, "Bea: I approve a budget of 900.")
    const state = Y.encodeStateAsUpdate(forged)
    const header = { id: bytesToHex(randomBytes(16)), base: chain.block.toString(), t: 1, chunks: [], size: state.length, authors: { [String(forged.clientID)]: { address: b.id!.address, salt, sig } } }
    const frame = encodeFrame({ kind: KIND.snapshot, doc: hexToBytes(link.doc), epoch: 0, header, data: state }, randomBytes)
    await chain.store(m.id!.address).batch({
      creates: [{ payload: encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), frame)), attributes: { doc: link.doc, kind: KIND.snapshot, seq: chain.block }, lifetimeSeconds: 30 * 86400, readonly: true }],
    })
    await settle(chain, [a, b, m, watcher])
    // live: refused, so it never becomes the lease or the carrier of Bea's words
    expect(watcher.provider.stats.rejectedWrites).toBe(rejectedBefore + 1)
    expect(watcher.provider.snapshot?.creator).not.toBe(m.id!.address)
    // on load: Bea's words, not Mal's, though Mal's snapshot is the newest
    const cold = await peer(chain, link, undefined)
    expect(text(cold)).toBe("Bea: I approve a budget of 100.")
  })
})

describe("far-future qs", () => {
  it("a removed member's junk with a qs far past the head never enters a reader's queries", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const mal = identity("mal")
    const m = await peer(chain, link, mal)
    await admit(chain, a, m)
    await a.provider.revoke(mal.address)
    await settle(chain, [a, m])
    m.provider.destroy()
    a.doc.getText("t").insert(0, "Owner wrote this.")
    await a.provider.flush()
    await settle(chain, [a])
    // valid-looking update entities from a removed member, parked in every future window
    for (let i = 0; i < 5; i++) {
      await chain.store(mal.address).batch({
        creates: Array.from({ length: 200 }, () => ({ payload: randomBytes(64), attributes: { doc: link.doc, kind: KIND.update, seq: 1n << 62n }, lifetimeSeconds: 3600, readonly: true })),
      })
      chain.mine()
    }
    const base = chain.store(owner.address)
    let queries = 0
    const counting: ArkivStore = { ...base, query: (spec) => (queries++, base.query(spec)) }
    const doc = new Y.Doc()
    const reader = new ArkivProvider(doc, { store: counting, link, identity: owner, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0, readOnly: true })
    await reader.connect()
    expect(doc.getText("t").toString()).toBe("Owner wrote this.")
    expect(queries).toBeLessThanOrEqual(4)
    reader.destroy()
  })
})

describe("audit with a failing RPC", () => {
  it("an edit whose past member list cannot be read is counted as unchecked and judged by today's list, not dropped", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "Owner wrote this.")
    await a.provider.flush()
    await settle(chain, [a])
    const base = chain.store(undefined)
    // every read at a past block fails, as a 429 from the free-read limit would
    const failing: ArkivStore = { ...base, get: (key, block) => (block === undefined ? base.get(key) : Promise.reject(new Error("429"))) }
    const doc = new Y.Doc()
    const audit = new ArkivProvider(doc, { store: failing, link, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0, readOnly: true, fullHistory: true, membershipAtBlock: true })
    await audit.connect()
    expect(blame(doc, audit).flat().filter((r) => r.proven).map((r) => r.text).join("")).toBe("Owner wrote this.")
    expect(audit.auditUnchecked).toBeGreaterThan(0)
    audit.destroy()
  })
})

describe("expiry ceiling, anchored to each entity", () => {
  const updateAcl = (p: ArkivProvider, f: (acl: { keepUntil: string | null }) => void) =>
    (p as unknown as { updateAcl: (g: (acl: { keepUntil: string | null }) => Promise<object>) => Promise<void> }).updateAcl(async (acl) => (f(acl), {}))

  it("an edit kept a little past the lease reads the same in a live tab and in a reader that opens later", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    bea.doc.getText("t").insert(0, "HELLO")
    await bea.provider.flush()
    await settle(chain, [a, bea])
    // Bea's own entity, pushed five blocks past a fresh lease plus the slack, from another client
    const mine = (await chain.store(undefined).query({ doc: link.doc, kind: KIND.update, creators: [bea.id!.address] })).entities[0]!
    await chain.store(bea.id!.address).batch({ extensions: [{ key: mine.key, lifetimeSeconds: LIFETIME.snapshot + 300 * 2 + 5 * 2 }] })
    await settle(chain, [a, bea])
    const live = await peer(chain, link, owner)
    chain.mine(10)
    const later = await peer(chain, link, undefined)
    expect(text(later)).toBe(text(live))
  })

  it("an owner who lowers keepUntil drops kept edits for normal readers, but the audit still proves them", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    bea.doc.getText("t").insert(0, "my own essay")
    await bea.provider.flush()
    await settle(chain, [a, bea])
    await a.provider.keepFor(2 * 365 * 86400)
    await settle(chain, [a, bea])
    await bea.provider.keepMyProof(365 * 86400)
    await settle(chain, [a, bea])
    await updateAcl(a.provider, (acl) => {
      acl.keepUntil = null
    })
    await settle(chain, [a, bea])
    const proven = async (audit: boolean) => {
      const doc = new Y.Doc()
      const p = new ArkivProvider(doc, { store: chain.store(undefined), link, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0, readOnly: true, fullHistory: audit, membershipAtBlock: audit })
      await p.connect()
      const out = blame(doc, p).flat().filter((r) => r.proven && r.address === bea.id!.address).map((r) => r.text).join("")
      p.destroy()
      return out
    }
    expect(await proven(false)).toBe("")
    expect(await proven(true)).toBe("my own essay")
  })
})

describe("two member lists from the owner", () => {
  it("every reader uses the earliest, whatever order the node returns them in", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    // a second, later ACL from the owner that does not list Bea
    await ArkivProvider.createDocument({ store: chain.store(owner.address), link, identity: owner })
    chain.mine()
    const reader = await peer(chain, link, undefined)
    expect(reader.provider.acl!.members.map((m) => m.address)).toContain(bea.id!.address)
  })
})

describe("audit against junk and an erased member", () => {
  const junk = async (chain: MemoryChain, link: DocLink, count: number) => {
    const who = identity("junk")
    for (let i = 0; i < count; i += 200) {
      await chain.store(who.address).batch({
        creates: Array.from({ length: Math.min(200, count - i) }, () => ({ payload: randomBytes(64), attributes: { doc: link.doc, kind: KIND.update, seq: chain.block }, lifetimeSeconds: 3600, readonly: true })),
      })
      chain.mine()
    }
  }

  it("a stranger's junk cannot switch the audit off: a member the owner erased is still proven", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    bea.doc.getText("t").insert(0, "bea's essay")
    await bea.provider.flush()
    await settle(chain, [a, bea])
    // the owner erases Bea: removed from the members and from the removals
    await (a.provider as unknown as { updateAcl: (f: (acl: { members: { address: string }[]; revoked: unknown[] }) => Promise<object>) => Promise<void> }).updateAcl(async (acl) => {
      acl.members = acl.members.filter((m) => m.address !== bea.id!.address)
      acl.revoked = []
      return {}
    })
    await settle(chain, [a, bea])
    await junk(chain, link, 1001)
    const doc = new Y.Doc()
    const audit = new ArkivProvider(doc, { store: chain.store(undefined), link, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0, readOnly: true, fullHistory: true })
    await audit.connect()
    expect(blame(doc, audit).flat().filter((r) => r.proven && r.address === bea.id!.address).map((r) => r.text).join("")).toBe("bea's essay")
    expect(audit.auditNarrowed).toBe(false)
    audit.destroy()
  })

  it("if the list's history cannot be read, the wider read stops after five pages and says it narrowed", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "Owner wrote this.")
    await a.provider.flush()
    await settle(chain, [a])
    // a patch, so the list has a past version to walk to
    await a.provider.keepFor(365 * 86400)
    await settle(chain, [a])
    await junk(chain, link, 1200)
    const base = chain.store(undefined)
    let queries = 0
    const failingHistory: ArkivStore = { ...base, query: (spec) => (queries++, base.query(spec)), get: (key, block) => (block === undefined ? base.get(key) : Promise.reject(new Error("429"))) }
    const doc = new Y.Doc()
    const audit = new ArkivProvider(doc, { store: failingHistory, link, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0, readOnly: true, fullHistory: true })
    await audit.connect()
    expect(doc.getText("t").toString()).toBe("Owner wrote this.")
    expect(audit.auditNarrowed).toBe(true)
    expect(queries).toBeLessThanOrEqual(9)
    audit.destroy()
  })
})
