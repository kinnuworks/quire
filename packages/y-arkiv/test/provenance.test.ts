import { describe, expect, it } from "vitest"
import * as Y from "yjs"
import { blame } from "../src/blame.js"
import { MemoryChain } from "../src/memory.js"
import { KIND, LIFETIME } from "../src/protocol.js"
import { ArkivProvider } from "../src/provider.js"
import { encodeFrame, encodeOuter } from "../src/codec.js"
import { deriveEpochZeroKey, randomBytes, seal } from "../src/crypto.js"
import { bytesToHex, hexToBytes } from "../src/hex.js"
import type { DocLink } from "../src/link.js"
import type { Hex } from "../src/store.js"
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
