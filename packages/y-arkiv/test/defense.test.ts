/**
 * Defence in depth. Most of these checks are unreachable through an honest RPC,
 * because the $creator filter already keeps the entities out. They exist for a
 * dishonest or buggy RPC, and for parsing hostile payloads, so that is how they
 * are tested. scripts/mutants.py removes each one and expects a failure here.
 */
import { privateKeyToAccount } from "viem/accounts"
import { describe, expect, it } from "vitest"
import * as Y from "yjs"
import { fromHeader } from "../src/acl.js"
import { encodeFrame, encodeOuter } from "../src/codec.js"
import { clientIdFor, deriveEpochZeroKey, deriveMetaKey, randomBytes, seal } from "../src/crypto.js"
import { bytesToHex, hexToBytes } from "../src/hex.js"
import type { DocLink } from "../src/link.js"
import { MemoryChain } from "../src/memory.js"
import { KIND, LIFETIME } from "../src/protocol.js"
import { ArkivProvider, type Identity } from "../src/provider.js"
import type { ArkivStore, Hex, StoredEntity } from "../src/store.js"
import { admit, identity, newDocument, peer, settle, text } from "./helpers.js"

/** An RPC that ignores the creator filter and returns everything for the document. */
function lying(store: ArkivStore): ArkivStore {
  return { ...store, query: (spec) => store.query({ ...spec, creators: undefined }) }
}

async function framePayload(link: DocLink, kind: string, header: Record<string, unknown>, data: Uint8Array, key = deriveEpochZeroKey(link.secret), epoch = 0) {
  return encodeOuter(epoch, await seal(key, encodeFrame({ kind: kind as never, doc: hexToBytes(link.doc), epoch, header, data }, randomBytes)))
}

async function readerOn(store: ArkivStore, link: DocLink) {
  const p = new ArkivProvider(new Y.Doc(), { store, link, flushIntervalMs: 0, autoCompact: false })
  await p.connect()
  return p
}

describe("a lying RPC", () => {
  it("cannot substitute an impostor's ACL", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "real")
    await a.provider.flush()
    const impostor = identity("imp")
    // a newer ACL for the same document and secret, owned by someone else, returned first by the lying RPC
    await ArkivProvider.createDocument({ store: chain.store(impostor.address), link: { ...link, owner: impostor.address }, identity: impostor })
    chain.mine()
    const r = await readerOn(lying(chain.store(undefined)), link)
    expect(r.acl!.owner.toLowerCase()).toBe(owner.address)
    expect(r.doc.getText("t").toString()).toBe("real")
  })

  it("cannot replay the owner's old ACL from another address to undo a revocation", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, c)
    // cal keeps a copy of the epoch 0 ACL payload, in which he is still a member
    const oldAcl = (await chain.store(undefined).query({ doc: link.doc, kind: KIND.acl })).entities[0]!
    await a.provider.revoke(c.id!.address)
    await settle(chain, [a, c])
    // and republishes it from his own address; a lying RPC hands it out first
    await chain.store(c.id!.address).batch({ creates: [{ payload: oldAcl.payload, attributes: { doc: link.doc, kind: KIND.acl, seq: chain.block }, lifetimeSeconds: LIFETIME.acl }] })
    chain.mine()
    const r = await readerOn(lying(chain.store(undefined)), link)
    expect(r.acl!.epoch).toBe(1)
  })

  it("cannot inject a non-member's snapshot", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "real")
    await a.provider.close()
    const mallory = identity("mallory")
    const evil = new Y.Doc()
    evil.getText("t").insert(0, "INJECTED")
    const state = Y.encodeStateAsUpdate(evil)
    const payload = await framePayload(link, KIND.snapshot, { id: "ab".repeat(16), base: String(chain.block), t: 0, chunks: [], size: state.length, authors: {} }, state)
    await chain.store(mallory.address).batch({ creates: [{ payload, attributes: { doc: link.doc, kind: KIND.snapshot, seq: chain.block }, lifetimeSeconds: LIFETIME.snapshot, readonly: true }] })
    chain.mine()
    const r = await readerOn(lying(chain.store(undefined)), link)
    expect(r.doc.getText("t").toString()).toBe("real")
  })
})

describe("snapshot integrity", () => {
  async function memberSnapshot(chain: MemoryChain, link: DocLink, who: Identity, opts: { base?: bigint; chunkOf?: string; chunkCreator?: Identity; chunkEpoch?: number; text: string }) {
    const d = new Y.Doc()
    d.getText("t").insert(0, opts.text)
    const state = Y.encodeStateAsUpdate(d)
    const id = "cd".repeat(16)
    const half = Math.floor(state.length / 2)
    const chunkBy = opts.chunkCreator ?? who
    const chunkPayload = await framePayload(link, KIND.chunk, { i: 1, of: opts.chunkOf ?? id }, state.subarray(half), deriveEpochZeroKey(link.secret), opts.chunkEpoch ?? 0)
    const chunk = await chain.store(chunkBy.address).batch({ creates: [{ payload: chunkPayload, attributes: { doc: link.doc, kind: KIND.chunk, seq: chain.block }, lifetimeSeconds: LIFETIME.snapshot, readonly: true }] })
    const base = opts.base ?? chain.block
    const head = await framePayload(link, KIND.snapshot, { id, base: String(base), t: 0, chunks: chunk.created, size: state.length, authors: {} }, state.subarray(0, half))
    await chain.store(who.address).batch({ creates: [{ payload: head, attributes: { doc: link.doc, kind: KIND.snapshot, seq: chain.block }, lifetimeSeconds: LIFETIME.snapshot, readonly: true }] })
    chain.mine()
  }

  async function setup() {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, c)
    return { chain, owner, link, a, c }
  }

  it("a chunk must name its own snapshot's id", async () => {
    const { chain, link, c } = await setup()
    await memberSnapshot(chain, link, c.id!, { chunkOf: "ef".repeat(16), text: "MIXED-UP-CHUNKS" })
    const r = await readerOn(chain.store(undefined), link)
    expect(r.doc.getText("t").toString()).not.toContain("MIXED")
  })

  it("a chunk must come from the snapshot's own creator", async () => {
    const { chain, link, c, owner } = await setup()
    await memberSnapshot(chain, link, c.id!, { chunkCreator: owner, text: "BORROWED-CHUNK" })
    const r = await readerOn(chain.store(undefined), link)
    expect(r.doc.getText("t").toString()).not.toContain("BORROWED")
  })

  it("a chunk must be in the snapshot's epoch", async () => {
    const { chain, link, c } = await setup()
    await memberSnapshot(chain, link, c.id!, { chunkEpoch: 7, text: "WRONG-EPOCH-CHUNK" })
    const r = await readerOn(chain.store(undefined), link)
    expect(r.doc.getText("t").toString()).not.toContain("WRONG-EPOCH")
  })

  it("a snapshot cannot claim a base after the block it landed in", async () => {
    const { chain, link, c } = await setup()
    await memberSnapshot(chain, link, c.id!, { base: chain.block + 10_000n, text: "FROM-THE-FUTURE" })
    const r = await readerOn(chain.store(undefined), link)
    expect(r.doc.getText("t").toString()).not.toContain("FUTURE")
  })
})

describe("frame binding", () => {
  it("a payload is refused when its frame's kind, document or epoch differs from the entity", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const open = (e: StoredEntity, kind: string, hint?: number) => (a.provider as unknown as { openEntity: (e: StoredEntity, k: string, h?: number) => Promise<unknown> }).openEntity(e, kind, hint)
    const entity = (payload: Uint8Array, kind: string): StoredEntity => ({ key: `0x${"11".repeat(32)}`, creator: owner.address, owner: owner.address, createdAt: 1n, expiresAt: 999n, attributes: { doc: link.doc, kind: kind as never, seq: 1n }, payload, readonly: true, permissionlessExtension: false })
    const good = await framePayload(link, KIND.update, { t: 0, salt: "00".repeat(16), sig: `0x${"11".repeat(65)}` }, new Uint8Array([1]))
    expect(await open(entity(good, KIND.update), KIND.update)).not.toBeNull()
    // kind: an update frame relabelled as a snapshot
    expect(await open(entity(good, KIND.snapshot), KIND.snapshot)).toBeNull()
    // document: a frame from another document under the same key
    const other = encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), encodeFrame({ kind: KIND.update, doc: randomBytes(32), epoch: 0, header: {}, data: new Uint8Array([1]) }, randomBytes)))
    expect(await open(entity(other, KIND.update), KIND.update)).toBeNull()
    // epoch: frame epoch 3 inside an outer epoch 0
    const skew = encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), encodeFrame({ kind: KIND.update, doc: hexToBytes(link.doc), epoch: 3, header: {}, data: new Uint8Array([1]) }, randomBytes)))
    expect(await open(entity(skew, KIND.update), KIND.update)).toBeNull()
    // epoch hint: a chunk read for an epoch-5 head must be in epoch 5
    const chunk = await framePayload(link, KIND.chunk, { i: 1, of: "00".repeat(16) }, new Uint8Array([1]))
    expect(await open(entity(chunk, KIND.chunk), KIND.chunk, 5)).toBeNull()
  })
})

describe("ACL parsing", () => {
  const owner = privateKeyToAccount(`0x${"11".repeat(32)}`)
  const member = { address: owner.address.toLowerCase() as Hex, publicKey: `0x04${"00".repeat(64)}` as Hex, name: "o", role: "owner" as const, addedAtBlock: "1" }
  const doc = `0x${"ab".repeat(32)}` as Hex
  const base = { v: 1, owner: owner.address.toLowerCase(), ownerPublicKey: member.publicKey, epoch: 0, keepUntil: null, wraps: [], members: [member], revoked: [] }

  it("accepts a well-formed ACL", async () => {
    await expect(fromHeader(base, owner.address.toLowerCase() as Hex, () => undefined, doc)).resolves.toBeTruthy()
  })
  it("refuses an ACL whose owner is not the link's owner", async () => {
    await expect(fromHeader({ ...base, owner: `0x${"22".repeat(20)}` }, owner.address.toLowerCase() as Hex, () => undefined, doc)).rejects.toThrow(/owner/)
  })
  it("refuses an ACL that does not list its owner", async () => {
    await expect(fromHeader({ ...base, members: [{ ...member, role: "writer" }] }, owner.address.toLowerCase() as Hex, () => undefined, doc)).rejects.toThrow(/owner/)
  })
  it("refuses an ACL whose member entries break the schema", async () => {
    const b = base as { members: Record<string, unknown>[] }
    const long = { ...base, members: [{ ...b.members[0], name: "x".repeat(41) }] }
    await expect(fromHeader(long, owner.address.toLowerCase() as Hex, () => undefined, doc)).rejects.toThrow(/member entry/)
    const extra = { ...base, members: [{ ...b.members[0], note: 1 }] }
    await expect(fromHeader(extra, owner.address.toLowerCase() as Hex, () => undefined, doc)).rejects.toThrow(/member entry/)
  })

  it("refuses an ACL whose fields do not match its epoch", async () => {
    await expect(fromHeader({ ...base, note: "extra" }, owner.address.toLowerCase() as Hex, () => undefined, doc)).rejects.toThrow(/wrong fields/)
    const { members: _m, ...noMembers } = base as Record<string, unknown>
    await expect(fromHeader(noMembers, owner.address.toLowerCase() as Hex, () => undefined, doc)).rejects.toThrow(/wrong fields/)
    await expect(fromHeader({ ...base, roster: "0x00" }, owner.address.toLowerCase() as Hex, () => undefined, doc)).rejects.toThrow(/wrong fields/)
  })

  it("refuses a roster sealed for another document or epoch", async () => {
    const key = randomBytes(32)
    const roster = await seal(key, new TextEncoder().encode(JSON.stringify({ doc: `0x${"cd".repeat(32)}`, epoch: 1, members: [member], revoked: [] })))
    const { members: _m, revoked: _r, ...rest } = base as Record<string, unknown>
    const header = { ...rest, epoch: 1, roster: `0x${bytesToHex(roster)}` }
    await expect(fromHeader(header, owner.address.toLowerCase() as Hex, () => key, doc)).rejects.toThrow(/another document/)
  })
})

describe("join requests and live events", () => {
  it("a join request from someone already a member is ignored", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    await admit(chain, a, b)
    await b.provider.requestJoin()
    await settle(chain, [a, b])
    expect(a.provider.joinRequests).toHaveLength(0)
    // and an owner session that opens later, reading every join request, ignores it too
    const fresh = await peer(chain, link, owner)
    expect(fresh.provider.joinRequests).toHaveLength(0)
  })

  it("the owner fetches strangers' entities at a capped rate", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const spam = chain.store(identity("spam").address)
    for (let i = 0; i < 300; i++) {
      await spam.batch({ creates: [{ payload: randomBytes(40), attributes: { doc: `0x${"99".repeat(32)}`, kind: KIND.update, seq: 1n }, lifetimeSeconds: 60, readonly: true }] })
    }
    const gets = chain.stats.gets
    await settle(chain, [a])
    expect(chain.stats.gets - gets).toBeLessThanOrEqual(240)
  })

  it("a member's entity for another document is ignored on the live path", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, c)
    await chain.store(c.id!.address).batch({ creates: [{ payload: randomBytes(64), attributes: { doc: `0x${"77".repeat(32)}`, kind: KIND.update, seq: chain.block }, lifetimeSeconds: 60, readonly: true }] })
    await settle(chain, [a, c])
    expect((a.provider as unknown as { deferred: Map<string, unknown> }).deferred.size).toBe(0)
    expect(a.provider.stats.rejectedWrites).toBe(0)
  })
})

describe("snapshot author claims", () => {
  it("a claim counts only with the right client id and a signature by the claimed address", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, c)
    const victim = identity("victim")
    const salt = randomBytes(16)
    const msg = new Uint8Array([...new TextEncoder().encode("quire1:salt:"), ...hexToBytes(link.doc), ...salt])
    const goodSig = await privateKeyToAccount(victim.privateKey).signMessage({ message: { raw: msg } })
    const calSig = await privateKeyToAccount(c.id!.privateKey).signMessage({ message: { raw: msg } })
    const id = clientIdFor(victim.address, salt)
    const d = new Y.Doc()
    d.clientID = id
    d.getText("t").insert(0, "claimed text")
    const state = Y.encodeStateAsUpdate(d)
    const write = async (authors: Record<string, unknown>) => {
      const payload = await framePayload(link, KIND.snapshot, { id: bytesToHex(randomBytes(16)), base: String(chain.block), t: 0, chunks: [], size: state.length, authors }, state)
      await chain.store(c.id!.address).batch({ creates: [{ payload, attributes: { doc: link.doc, kind: KIND.snapshot, seq: chain.block }, lifetimeSeconds: LIFETIME.snapshot, readonly: true }] })
      chain.mine()
      return readerOn(chain.store(undefined), link)
    }
    // wrong client id for the address
    const r1 = await write({ [id + 1]: { address: victim.address, salt: bytesToHex(salt), sig: goodSig } })
    expect(r1.authorOf(id + 1)).toBeUndefined()
    // signature by cal, not the victim
    const r2 = await write({ [id]: { address: victim.address, salt: bytesToHex(salt), sig: calSig } })
    expect(r2.authorOf(id)).toBeUndefined()
    // correct id and the victim's own signature: claimed, via cal
    const r3 = await write({ [id]: { address: victim.address, salt: bytesToHex(salt), sig: goodSig } })
    expect(r3.authorOf(id)).toEqual({ address: victim.address, proven: false, via: c.id!.address })
  })
})
