/**
 * Review round 3 repros. Each `it` asserts the CORRECT behaviour, so a failing
 * test is a live bug.
 */
import { privateKeyToAccount } from "viem/accounts"
import { describe, expect, it } from "vitest"
import * as Y from "yjs"
import { encodeFrame, encodeOuter } from "../src/codec.js"
import { clientIdFor, deriveEpochZeroKey, randomBytes, seal } from "../src/crypto.js"
import { bytesToHex, hexToBytes } from "../src/hex.js"
import type { DocLink } from "../src/link.js"
import { MemoryChain } from "../src/memory.js"
import { KIND, LIFETIME } from "../src/protocol.js"
import { loadAt, type Identity } from "../src/provider.js"
import type { Hex } from "../src/store.js"
import { admit, identity, newDocument, peer, settle, text } from "./helpers.js"

async function signSalt(id: Identity, link: DocLink, salt: Uint8Array): Promise<Hex> {
  const msg = new Uint8Array([...new TextEncoder().encode("quire1:salt:"), ...hexToBytes(link.doc), ...salt])
  return privateKeyToAccount(id.privateKey).signMessage({ message: { raw: msg } })
}

function appendAs(doc: Y.Doc, client: number, s: string): Uint8Array {
  const d = new Y.Doc()
  Y.applyUpdate(d, Y.encodeStateAsUpdate(doc))
  const before = Y.encodeStateVector(d)
  d.clientID = client
  d.getText("t").insert(d.getText("t").length, s)
  return Y.encodeStateAsUpdate(d, before)
}

function verdicts(p: { doc: Y.Doc; provider: { authorOfItem: (c: number, k: number, l: number) => { proven: boolean; address: string } | undefined } }) {
  const out: Record<string, { proven: boolean; address: string } | undefined> = {}
  let item = (p.doc.getText("t") as unknown as { _start: any })._start
  while (item) {
    if (item.content.str && !item.deleted) out[item.content.str] = p.provider.authorOfItem(item.id.client, item.id.clock, item.length)
    item = item.right
  }
  return out
}

describe("R3-1 live snapshot pre-empts a member's future clocks", () => {
  it("a forged snapshot under bea's next clocks must not become 'proven bea' text on live peers", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, b)
    await admit(chain, a, c)
    let diverged = false
    a.provider.on("diverged", () => (diverged = true))
    b.doc.getText("t").insert(0, "bea: ")
    await b.provider.flush()
    await settle(chain, [a, b, c])
    // cal compacts a state that carries text under bea's client id at the clocks bea will use next
    Y.applyUpdate(c.doc, appendAs(c.doc, b.doc.clientID, "I RESIGN"))
    await c.provider.compact()
    await settle(chain, [a, b, c], 2)
    // bea types her real next words (same length is not needed; overlap is enough)
    b.doc.getText("t").insert(b.doc.getText("t").length, "all good")
    await b.provider.flush()
    await settle(chain, [a, b, c], 2)
    // Yjs cannot take a struct back out of a doc, so the owner's live session cannot heal in place.
    // It must (1) never show the forged words as proven bea, (2) report the divergence, and (3) a
    // fresh session, which is what the app opens on that report, must converge with bea.
    const v = verdicts(a)
    const forged = Object.entries(v).find(([k]) => k.includes("RESIGN"))
    if (forged) expect(forged[1]?.proven).toBe(false)
    expect(diverged).toBe(true)
    const healed = await peer(chain, link, owner)
    expect(text(healed)).toBe(text(b))
    expect(text(healed)).not.toContain("RESIGN")
  })
})

describe("R3-2 flush drops edits when head() or sealing fails", () => {
  it("a transient head() failure must not lose the edits or wedge every later edit at peers", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    await admit(chain, a, b)
    const t = a.doc.getText("t")
    t.insert(0, "1")
    await a.provider.flush()
    const head = a.provider.store.head
    let fail = true
    ;(a.provider.store as { head: () => Promise<bigint> }).head = async () => {
      if (fail) {
        fail = false
        throw new Error("rpc hiccup")
      }
      return head()
    }
    t.insert(1, "2")
    await expect(a.provider.flush()).rejects.toThrow(/hiccup/)
    t.insert(2, "3")
    await a.provider.flush()
    await settle(chain, [a, b], 2)
    const late0 = await peer(chain, link, undefined)
    expect(text(b)).toBe("123")
    const late = await peer(chain, link, undefined)
    expect(text(late)).toBe("123")
  })
})

describe("R3-3 the authors table eventually makes compaction impossible", () => {
  it("compaction still works once ~400 sessions have left text in the document", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const p = a.provider as unknown as { authors: Map<number, string>; salts: Map<number, string>; sigs: Map<number, string> }
    // simulate 400 earlier sessions of the owner, each of which left one character
    const sig = await signSalt(owner, link, new Uint8Array(16))
    const n = Number(process.env.N ?? 400)
    for (let i = 0; i < n; i++) {
      const salt = randomBytes(16)
      const id = clientIdFor(owner.address, salt)
      Y.applyUpdate(a.doc, appendAs(a.doc, id, "x"))
      p.authors.set(id, owner.address)
      p.salts.set(id, bytesToHex(salt))
      p.sigs.set(id, sig) // signature validity does not matter for the writer side
    }
    await expect(a.provider.compact()).resolves.toBeTruthy()
  })
})

describe("R3-4 loadAt cannot rebuild a past block whose chunked snapshot was replaced", () => {
  it("loadAt(block) returns the text the chain held at that block", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const big = "p".repeat(150_000)
    a.doc.getText("t").insert(0, big)
    await a.provider.flush() // too big for one update: written as a chunked snapshot
    chain.mine()
    const past = chain.block
    chain.mine(100)
    a.doc.getText("t").insert(0, "new ")
    await a.provider.flush()
    await a.provider.compact() // replaces (deletes) the previous snapshot and its chunks
    chain.mine()
    const doc = await loadAt(chain.store(undefined), link, past)
    expect(doc.getText("t").toString().length).toBe(150_000)
  })
})

describe("R3-5 the 'old epoch is refused' regression test passes for the wrong reason", () => {
  it("a properly signed stale-epoch update from a remaining member is applied (and readable by the removed member)", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, b)
    await admit(chain, a, c)
    await a.provider.revoke(c.id!.address)
    chain.mine(3)
    const salt = randomBytes(16)
    const header = { t: 0, salt: bytesToHex(salt), sig: await signSalt(b.id!, link, salt) }
    const upd = appendAs(new Y.Doc(), clientIdFor(b.id!.address, salt), "readable by cal")
    const payload = encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), encodeFrame({ kind: KIND.update, doc: hexToBytes(link.doc), epoch: 0, header, data: upd }, randomBytes)))
    await chain.store(b.id!.address).batch({ creates: [{ payload, attributes: { doc: link.doc, kind: KIND.update, seq: chain.block }, lifetimeSeconds: 3600 }] })
    await settle(chain, [a])
    // documents current behaviour (PROTOCOL s5 says stale-epoch writes are applied); the existing test
    // "an edit encrypted for an old epoch after a revocation is refused" only passes because it omits the salt
    expect(text(a)).toContain("readable by cal")
  })
})

describe("R3-6 a member's empty snapshot hides older content from late joiners", () => {
  it("late joiner sees the text that live peers see", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, c)
    a.doc.getText("t").insert(0, "the owner's report")
    await a.provider.flush()
    await a.provider.compact()
    chain.mine(200)
    // cal writes two empty snapshots with a high base, straight to the chain (valid in every checked respect)
    for (let i = 0; i < 2; i++) {
      const state = Y.encodeStateAsUpdate(new Y.Doc())
      const frame = encodeFrame({ kind: KIND.snapshot, doc: hexToBytes(link.doc), epoch: 0, header: { id: bytesToHex(randomBytes(16)), base: String(chain.block), t: 0, chunks: [], size: state.length, authors: {} }, data: state }, randomBytes)
      const payload = encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), frame))
      await chain.store(c.id!.address).batch({ creates: [{ payload, attributes: { doc: link.doc, kind: KIND.snapshot, seq: chain.block }, lifetimeSeconds: LIFETIME.snapshot }] })
      chain.mine(100)
    }
    await settle(chain, [a, c])
    const late = await peer(chain, link, undefined)
    expect(text(late)).toBe(text(a))
  })
})

describe("R3-7 anyone who knows the public doc id can make the owner's session burn its query budget", () => {
  it("junk join entities from a stranger (no link needed) do not multiply the owner's queries", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    // a stranger reads qd off any public Quire entity and writes junk with qk = "j": no link, no valid crypto
    const stranger = identity("spam")
    for (let b = 0; b < 40; b++) {
      const creates = Array.from({ length: 100 }, () => ({ payload: new Uint8Array(8), attributes: { doc: link.doc, kind: KIND.join, seq: chain.block }, lifetimeSeconds: 30 * 86400 }))
      await chain.store(stranger.address).batch({ creates })
    }
    chain.mine()
    // a store with a keyless-style budget of 20 queries
    const base = chain.store(owner.address)
    let used = 0
    const budgeted = { ...base, query: async (spec: Parameters<typeof base.query>[0]) => { if (++used > 20) throw new Error("429 query budget"); return base.query(spec) } }
    const { ArkivProvider } = await import("../src/provider.js")
    const p = new ArkivProvider(new Y.Doc(), { store: budgeted, link, identity: owner, flushIntervalMs: 0, autoCompact: false })
    const before = chain.stats.queries
    await p.connect().catch(() => undefined)
    expect(p.status).toBe("synced")
    expect(chain.stats.queries - before).toBeLessThanOrEqual(4)
  })
})

describe("R3-8 revoke() writes its snapshot without the MUST re-read of recent updates", () => {
  it("an edit the owner's session missed live is not lost by a revocation", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, b)
    await admit(chain, a, c)
    // the owner's socket drops for a moment
    ;(a.provider as unknown as { unwatch: () => void }).unwatch()
    b.doc.getText("t").insert(0, "bea's paragraph")
    await b.provider.flush()
    b.provider.destroy() // bea goes offline
    chain.mine(200)
    await a.provider.revoke(c.id!.address)
    chain.mine()
    const again = await peer(chain, link, owner)
    expect(text(again)).toContain("bea's paragraph")
  })
})

describe("R3-9 a missed ACL patch is never re-read by resync()", () => {
  it("a member whose socket missed an approval still ends up with the new member's text", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, c)
    const cp = c.provider as unknown as { unwatch: () => void; enqueue: (f: () => Promise<void>) => void; onChainEvent: (e: unknown) => Promise<void> }
    cp.unwatch() // cal's socket is down while bea is approved
    const b = await peer(chain, link, identity("bea"))
    await admit(chain, a, b)
    // socket back (viem re-subscribes, but the gap's events are gone)
    chain.watch((e) => cp.enqueue(() => cp.onChainEvent(e)))
    b.doc.getText("t").insert(0, "bea writes")
    await b.provider.flush()
    await settle(chain, [a, b, c])
    await c.provider.resync() // the periodic catch-up
    await settle(chain, [a, b, c])
    expect(text(c)).toBe("bea writes")
  })
})

describe("R3-9b a missed revocation keeps a writer on the old key until reload", () => {
  it("after resync, a writer that missed the rotation writes under the current epoch", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, b)
    await admit(chain, a, c)
    ;(b.provider as unknown as { unwatch: () => void }).unwatch() // bea's socket blips
    await a.provider.revoke(c.id!.address)
    chain.mine(3)
    await b.provider.resync()
    b.doc.getText("t").insert(0, "after cal was removed")
    const info = await b.provider.flush()
    chain.mine()
    const seen = await a.provider.inspect(info!.entity)
    expect(seen!.frame?.epoch).toBe(a.provider.acl!.epoch)
  })
})
