/**
 * Attacks from review round 2. Every forged entity here is well formed in all
 * respects except the one rule under test (valid salt, real signature, member
 * key), so each test fails if that rule is removed.
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
import type { Identity } from "../src/provider.js"
import type { Hex } from "../src/store.js"
import { admit, identity, newDocument, peer, settle, text } from "./helpers.js"

async function signSalt(id: Identity, link: DocLink, salt: Uint8Array): Promise<Hex> {
  const msg = new Uint8Array([...new TextEncoder().encode("quire1:salt:"), ...hexToBytes(link.doc), ...salt])
  return privateKeyToAccount(id.privateKey).signMessage({ message: { raw: msg } })
}

/** A correctly signed update by `id`, carrying `update` bytes, with `qs` = `seq`. */
async function writeUpdate(chain: MemoryChain, link: DocLink, id: Identity, salt: Uint8Array, update: Uint8Array, seq = chain.block) {
  const header = { t: 0, salt: bytesToHex(salt), sig: await signSalt(id, link, salt) }
  const payload = encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), encodeFrame({ kind: KIND.update, doc: hexToBytes(link.doc), epoch: 0, header, data: update }, randomBytes)))
  await chain.store(id.address).batch({ creates: [{ payload, attributes: { doc: link.doc, kind: KIND.update, seq }, lifetimeSeconds: LIFETIME.snapshot, readonly: true }] })
}

/** A Yjs update that appends `s` to text "t" under client id `client`, continuing after `doc`'s state. */
function appendAs(doc: Y.Doc, client: number, s: string): Uint8Array {
  const d = new Y.Doc()
  Y.applyUpdate(d, Y.encodeStateAsUpdate(doc))
  const before = Y.encodeStateVector(d)
  d.clientID = client
  d.getText("t").insert(d.getText("t").length, s)
  return Y.encodeStateAsUpdate(d, before)
}

describe("derived client ids", () => {
  it("a member writing under another member's client id is refused, even with her own valid salt and signature", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, b)
    await admit(chain, a, c)
    b.doc.getText("t").insert(0, "bea ")
    await b.provider.flush()
    await settle(chain, [a, b, c])
    // cal signs a perfectly good salt of her own, but writes structs under bea's client id
    const salt = randomBytes(16)
    await writeUpdate(chain, link, c.id!, salt, appendAs(b.doc, b.doc.clientID, "FORGED"))
    await settle(chain, [a, b, c])
    expect(text(a)).toBe("bea ")
  })

  it("an update whose signature is by someone else is refused", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, c)
    const salt = randomBytes(16)
    // cal's client id and salt, but the signature is the owner's (copied from elsewhere): recovers to the wrong address
    const header = { t: 0, salt: bytesToHex(salt), sig: await signSalt(owner, link, salt) }
    const update = appendAs(new Y.Doc(), clientIdFor(c.id!.address, salt), "bad sig")
    const payload = encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), encodeFrame({ kind: KIND.update, doc: hexToBytes(link.doc), epoch: 0, header, data: update }, randomBytes)))
    await chain.store(c.id!.address).batch({ creates: [{ payload, attributes: { doc: link.doc, kind: KIND.update, seq: chain.block }, lifetimeSeconds: 3600, readonly: true }] })
    await settle(chain, [a, c])
    expect(text(a)).toBe("")
  })

  it("the same update with a correct signature is accepted (control for the two tests above)", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, c)
    const salt = randomBytes(16)
    await writeUpdate(chain, link, c.id!, salt, appendAs(new Y.Doc(), clientIdFor(c.id!.address, salt), "good"))
    await settle(chain, [a, c])
    expect(text(a)).toBe("good")
  })
})

describe("robustness", () => {
  it("a malformed update from a member cannot stop anyone from opening the document", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, c)
    a.doc.getText("t").insert(0, "still opens")
    await a.provider.flush()
    // garbage Yjs bytes under a valid frame and signature
    await writeUpdate(chain, link, c.id!, randomBytes(16), randomBytes(64))
    chain.mine()
    const late = await peer(chain, link, undefined)
    expect(text(late)).toBe("still opens")
    const ownerAgain = await peer(chain, link, owner)
    expect(ownerAgain.provider.status).toBe("synced")
  })

  it("a qs a few blocks past its own block is refused by live and cold readers alike", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, c)
    const salt = randomBytes(16)
    // inside every reader's query bound (head + 60), so only the reader-side rule can refuse it
    await writeUpdate(chain, link, c.id!, salt, appendAs(new Y.Doc(), clientIdFor(c.id!.address, salt), "ahead "), chain.block + 10n)
    await settle(chain, [a, c])
    const late = await peer(chain, link, undefined)
    expect(text(late)).toBe("")
    expect(text(a)).toBe("")
  })

  it("a far-future qs is refused, so it cannot hide newer edits from late joiners", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, c)
    const salt = randomBytes(16)
    await writeUpdate(chain, link, c.id!, salt, appendAs(new Y.Doc(), clientIdFor(c.id!.address, salt), "future "), chain.block + 1_000_000n)
    a.doc.getText("t").insert(0, "now ")
    await a.provider.flush()
    chain.mine()
    const late = await peer(chain, link, undefined)
    expect(text(late)).toBe("now ")
  })
})

describe("snapshots", () => {
  it("text that only a snapshot carries is claimed, never proven, even under a real member's client id", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, b)
    await admit(chain, a, c)
    b.doc.getText("t").insert(0, "bea real. ")
    await b.provider.flush()
    await settle(chain, [a, b, c])
    // cal compacts a state where bea's client id carries extra text bea never sent as an update
    const forged = new Y.Doc()
    Y.applyUpdate(forged, Y.encodeStateAsUpdate(c.doc))
    Y.applyUpdate(forged, appendAs(forged, b.doc.clientID, "PUT IN BEA'S MOUTH"))
    Y.applyUpdate(c.doc, Y.encodeStateAsUpdate(forged))
    await c.provider.compact()
    await settle(chain, [a, b, c], 3)
    // a fresh reader sees the text, but the forged clock range is claimed via cal, not proven as bea
    const late = await peer(chain, link, undefined)
    const t = late.doc.getText("t")
    expect(t.toString()).toContain("PUT IN BEA'S MOUTH")
    let item = (t as unknown as { _start: { id: { client: number; clock: number }; length: number; content: { str?: string }; right: unknown } | null })._start
    const verdicts: Record<string, boolean | undefined> = {}
    while (item) {
      const v = late.provider.authorOfItem(item.id.client, item.id.clock, item.length)
      if (item.content.str) verdicts[item.content.str] = v?.proven
      item = item.right as typeof item
    }
    expect(Object.entries(verdicts).find(([k]) => k.includes("MOUTH"))![1]).toBe(false)
  })

  it("a snapshot carrying structs under this session's own client id is refused, so nobody can mute us", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, c)
    const ownerId = a.doc.clientID
    Y.applyUpdate(c.doc, appendAs(c.doc, ownerId, "as the owner"))
    await c.provider.compact()
    await settle(chain, [a, c], 3)
    expect(a.doc.clientID).toBe(ownerId)
    expect(text(a)).not.toContain("as the owner")
    a.doc.getText("t").insert(0, "owner types ")
    await a.provider.flush()
    await settle(chain, [a, c])
    // an honest late reader gets the owner's genuine edit, not cal's forgery at the same clock
    const late = await peer(chain, link, undefined)
    expect(text(late)).toContain("owner types")
    expect(text(late)).not.toContain("as the owner")
  })

  it("compaction keeps working after many sessions: the authors table only holds ids still in the text", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    let last = await peer(chain, link, owner)
    last.doc.getText("t").insert(0, "y".repeat(110_000))
    await last.provider.flush()
    for (let i = 0; i < 30; i++) {
      last.provider.destroy()
      chain.mine()
      last = await peer(chain, link, owner)
      last.doc.getText("t").insert(0, String(i % 10))
      await last.provider.flush()
    }
    await expect(last.provider.compact()).resolves.toBeTruthy()
  })

  it("a paste that fails to write keeps its edits for the next attempt", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const original = a.provider.store.batch
    let fail = true
    a.provider.store.batch = async (spec) => {
      if (fail) {
        fail = false
        throw new Error("network down")
      }
      return original(spec)
    }
    a.doc.getText("t").insert(0, "p".repeat(150_000))
    await expect(a.provider.flush()).rejects.toThrow(/network down/)
    await a.provider.compact()
    chain.mine()
    const reader = await peer(chain, link, undefined)
    expect(text(reader).length).toBe(150_000)
  })
})

describe("defence in depth", () => {
  it("an RPC that ignores the $creator filter still cannot inject a non-member's edit", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "real ")
    await a.provider.flush()
    // mallory holds the link: a perfectly valid, signed update under her own derived client id
    const mallory = identity("mallory")
    const salt = randomBytes(16)
    await writeUpdate(chain, link, mallory, salt, appendAs(new Y.Doc(), clientIdFor(mallory.address, salt), "INJECTED"))
    chain.mine()
    // a dishonest or buggy RPC that drops the creators filter
    const honest = chain.store(undefined)
    const lying = { ...honest, query: (spec: Parameters<typeof honest.query>[0]) => honest.query({ ...spec, creators: undefined, creatorBounds: undefined }) }
    const { ArkivProvider } = await import("../src/provider.js")
    // with the member list as it stood at each edit's block, and with today's list
    for (const membershipAtBlock of [true, false]) {
      const reader = new ArkivProvider(new Y.Doc(), { store: lying, link, flushIntervalMs: 0, autoCompact: false, membershipAtBlock })
      await reader.connect()
      expect(reader.doc.getText("t").toString()).toBe("real ")
      expect(reader.stats.rejectedWrites).toBeGreaterThan(0)
      reader.destroy()
    }
  })

  it("a client id already attributed to one address is not handed to another, even if the hash matched", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, c)
    const salt = randomBytes(16)
    const id = clientIdFor(c.id!.address, salt)
    // simulate a prior attribution of this id to the owner (as a 53-bit collision would produce)
    ;(a.provider as unknown as { claimedAuthors: Map<number, string> }).claimedAuthors.set(id, owner.address)
    await writeUpdate(chain, link, c.id!, salt, appendAs(new Y.Doc(), id, "taken over"))
    await settle(chain, [a, c])
    expect(text(a)).toBe("")
  })
})

describe("pending updates", () => {
  it("the override detector flags a state whose text at a verified clock differs from the update", async () => {
    const { overridesVerified } = await import("../src/provider.js")
    const genuine = new Y.Doc()
    genuine.clientID = 77
    genuine.getText("t").insert(0, "AB")
    const update = Y.encodeStateAsUpdate(genuine)
    // a state that got "AX" under the same client id first: Yjs then skips the genuine structs as duplicates
    const forged = new Y.Doc()
    forged.clientID = 77
    forged.getText("t").insert(0, "AX")
    const doc = new Y.Doc()
    Y.applyUpdate(doc, Y.encodeStateAsUpdate(forged))
    Y.applyUpdate(doc, update)
    expect(overridesVerified(doc, [update])).toBe(true)
    // the honest case passes
    const honest = new Y.Doc()
    Y.applyUpdate(honest, update)
    expect(overridesVerified(honest, [update])).toBe(false)
  })

  it("the override detector passes honest rich text and flags a swapped paragraph", async () => {
    const { overridesVerified } = await import("../src/provider.js")
    const writer = new Y.Doc()
    writer.clientID = 78
    const p = new Y.XmlElement("paragraph")
    p.insert(0, [new Y.XmlText("hello")])
    writer.getXmlFragment("default").push([p])
    const update = Y.encodeStateAsUpdate(writer)
    const doc = new Y.Doc()
    Y.applyUpdate(doc, update)
    expect(overridesVerified(doc, [update])).toBe(false)
    // another member types into the same paragraph: still the same paragraph at the same clock
    const other = new Y.Doc()
    other.clientID = 79
    Y.applyUpdate(other, update)
    ;(other.getXmlFragment("default").get(0) as Y.XmlElement).insert(1, [new Y.XmlText(" world")])
    Y.applyUpdate(doc, Y.encodeStateAsUpdate(other))
    expect(overridesVerified(doc, [update])).toBe(false)
    // a state that put a heading at the paragraph's clock first
    const forged = new Y.Doc()
    forged.clientID = 78
    const h = new Y.XmlElement("heading")
    h.insert(0, [new Y.XmlText("hello")])
    forged.getXmlFragment("default").push([h])
    const clash = new Y.Doc()
    Y.applyUpdate(clash, Y.encodeStateAsUpdate(forged))
    Y.applyUpdate(clash, update)
    expect(overridesVerified(clash, [update])).toBe(true)
  })
  // the end-to-end forged-snapshot cases live in provenance.test.ts
})
