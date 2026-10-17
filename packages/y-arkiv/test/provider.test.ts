import { describe, expect, it } from "vitest"
import * as Y from "yjs"
import { ArkivProvider } from "../src/provider.js"
import { decodeOuter } from "../src/codec.js"
import { KIND } from "../src/protocol.js"
import { MemoryChain } from "../src/memory.js"
import { admit, identity, newDocument, peer, settle, text } from "./helpers.js"

describe("ArkivProvider", () => {
  it("syncs edits between two members over chain events", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    await admit(chain, a, b)

    a.doc.getText("t").insert(0, "hello ")
    await a.provider.flush()
    await settle(chain, [a, b])
    b.doc.getText("t").insert(6, "world")
    await b.provider.flush()
    await settle(chain, [a, b])

    expect(text(a)).toBe("hello world")
    expect(text(b)).toBe("hello world")
  })

  it("merges a block's worth of keystrokes into one entity", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const before = chain.stats.batches
    for (const ch of "typing fast") a.doc.getText("t").insert(a.doc.getText("t").length, ch)
    await a.provider.flush()
    expect(chain.stats.batches - before).toBe(1)
  })

  it("a late joiner rebuilds the document from snapshot plus updates in three queries", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "first ")
    await a.provider.flush()
    await a.provider.compact()
    a.doc.getText("t").insert(6, "second")
    await a.provider.flush()
    chain.mine()

    const queriesBefore = chain.stats.queries
    const reader = await peer(chain, link, undefined)
    expect(chain.stats.queries - queriesBefore).toBe(3)
    expect(text(reader)).toBe("first second")
  })

  it("ignores updates from addresses outside the ACL, live and on load", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const mallory = identity("mallory")
    // mallory holds the link (and so the keys) but was never approved
    const m = await peer(chain, link, mallory)
    m.doc.getText("t").insert(0, "spam")
    // force a write even though the provider would refuse: talk to the store directly
    const forged = new Y.Doc()
    forged.getText("t").insert(0, "SPAM")
    const store = chain.store(mallory.address)
    const honest = (await a.provider.store.query({ doc: link.doc, kind: KIND.snapshot })).entities[0]!
    await store.batch({
      creates: [{ payload: honest.payload, attributes: { doc: link.doc, kind: KIND.update, seq: chain.block }, lifetimeSeconds: 3600 }],
    })
    await settle(chain, [a, m])
    expect(text(a)).toBe("")
    expect(a.provider.stats.rejectedWrites).toBe(1)

    const late = await peer(chain, link, undefined)
    expect(text(late)).toBe("")
  })

  it("refuses an ACL that was not created by the owner in the link", async () => {
    const chain = new MemoryChain()
    const { link } = await newDocument(chain)
    const impostor = identity("imp")
    // an impostor publishes its own ACL for the same doc id, with the same secret
    await ArkivProvider.createDocument({ store: chain.store(impostor.address), link: { ...link, owner: impostor.address }, identity: impostor })
    chain.mine()
    const reader = await peer(chain, link, undefined)
    expect(reader.provider.acl?.owner.toLowerCase()).toBe(link.owner.toLowerCase())
  })

  it("revocation rotates the content key: the removed member cannot read new edits", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    const c = await peer(chain, link, identity("cal"))
    await admit(chain, a, b)
    await admit(chain, a, c)
    a.doc.getText("t").insert(0, "shared ")
    await a.provider.flush()
    await settle(chain, [a, b, c])

    await a.provider.revoke(c.id!.address)
    await settle(chain, [a, b, c])
    a.doc.getText("t").insert(7, "secret")
    await a.provider.flush()
    await settle(chain, [a, b, c])

    expect(text(b)).toBe("shared secret")
    expect(text(c)).toBe("shared ")
    expect(c.provider.canRead).toBe(false)
    expect(c.provider.role).toBe("reader")
    // even a fresh session using c's old link and key cannot read the new epoch
    const again = await peer(chain, link, c.id)
    expect(text(again)).not.toContain("secret")
  })

  it("splits large snapshots into chunks that fit the RPC's request limit", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const big = "x".repeat(300_000)
    a.doc.getText("t").insert(0, big)
    await a.provider.compact()
    // chunks go first in size-capped transactions, the head last
    expect(a.provider.snapshot!.chunks.length).toBeGreaterThanOrEqual(3)
    chain.mine()
    const reader = await peer(chain, link, undefined)
    expect(text(reader)).toBe(big)
  })

  it("pads every payload to a fixed bucket", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const sizes = new Set<number>()
    for (const s of ["a", "ab", "abc", "a longer sentence of text"]) {
      a.doc.getText("t").insert(0, s)
      await a.provider.flush()
    }
    const ups = await a.provider.store.query({ doc: link.doc, kind: KIND.update })
    for (const e of ups.entities) sizes.add(e.payload.length)
    expect(sizes.size).toBe(1)
    // payloads are opaque: nothing typed appears in them
    for (const e of ups.entities) expect(new TextDecoder().decode(decodeOuter(e.payload).envelope)).not.toContain("sentence")
  })

  it("publishes a readonly version that anyone with its link can open and keep alive", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "v1 text")
    await a.provider.flush()
    const version = await a.provider.publishVersion()
    chain.mine()
    const opened = await ArkivProvider.openVersion(chain.store(undefined), version)
    expect(opened.doc.getText("t").toString()).toBe("v1 text")
    const stranger = identity("s")
    await chain.store(stranger.address).batch({ extensions: [{ key: version.key, lifetimeSeconds: 2 * 365 * 24 * 3600 }] })
    await expect(chain.store(owner.address).batch({ patches: [{ key: version.key, payload: new Uint8Array(40), attributes: { doc: link.doc, kind: KIND.version, seq: 1n } }] })).rejects.toThrow(/readonly/)
  })

  it("shredMine deletes everything the member wrote in one batch", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    await admit(chain, a, b)
    for (const s of ["one ", "two ", "three "]) {
      b.doc.getText("t").insert(0, s)
      await b.provider.flush()
    }
    chain.mine()
    const batches = chain.stats.batches
    const n = await b.provider.shredMine()
    expect(n).toBe(4) // three updates and the join request, never a snapshot
    expect(chain.stats.batches - batches).toBe(1)
    const left = await chain.store(undefined).query({ doc: link.doc, creators: [b.id!.address] })
    expect(left.entities).toHaveLength(0)
  })

  it("renews the snapshot lease only once half its life has passed", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    expect(await a.provider.renewLeaseIfDue()).toBe(false)
    const before = a.provider.snapshot!.expiresAt
    chain.mine(Number((before - chain.block) / 2n) + 10)
    expect(await a.provider.renewLeaseIfDue()).toBe(true)
    expect(a.provider.snapshot!.expiresAt).toBeGreaterThan(before)
  })

  it("a compactor that missed a live update still folds it into the snapshot", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    await admit(chain, a, b)
    // a's socket drops: it stops receiving events
    ;(a.provider as unknown as { unwatch: () => void }).unwatch()
    b.doc.getText("t").insert(0, "missed ")
    await b.provider.flush()
    chain.mine(200)
    a.doc.getText("t").insert(0, "seen ")
    await a.provider.compact()
    chain.mine(200)
    const late = await peer(chain, link, undefined)
    expect(text(late)).toContain("missed")
    expect(text(late)).toContain("seen")
  })

  it("rejects a join request whose public key does not match its creator", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    // b claims c's public key
    const c = identity("cal")
    ;(b.provider as unknown as { identity: typeof c }).identity = { ...b.id!, privateKey: c.privateKey }
    await b.provider.requestJoin()
    await settle(chain, [a, b])
    expect(a.provider.joinRequests).toHaveLength(0)
  })
})

describe("history and authorship", () => {
  it("loadAt rebuilds the document as the chain held it at a past block", async () => {
    const { loadAt } = await import("../src/provider.js")
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    a.doc.getText("t").insert(0, "before")
    await a.provider.flush()
    chain.mine()
    const mark = chain.block
    a.doc.getText("t").insert(6, " after")
    await a.provider.flush()
    chain.mine()
    const past = await loadAt(chain.store(undefined), link, mark - 1n)
    expect(past.getText("t").toString()).toBe("before")
    expect(a.provider.stateAt(mark - 1n).getText("t").toString()).toBe("before")
    expect(a.provider.stateAt(chain.block).getText("t").toString()).toBe("before after")
  })

  it("attributes edits to the on-chain creator, and marks snapshot attributions as claimed", async () => {
    const chain = new MemoryChain()
    const { owner, link } = await newDocument(chain)
    const a = await peer(chain, link, owner)
    const b = await peer(chain, link, identity("bea"))
    await admit(chain, a, b)
    b.doc.getText("t").insert(0, "bea wrote this")
    await b.provider.flush()
    await settle(chain, [a, b])
    expect(a.provider.authorOf(b.doc.clientID)).toEqual({ address: b.id!.address, proven: true })
    // bea's update falls outside the catch-up window, so only the snapshot speaks for her
    chain.mine(100)
    await a.provider.compact()
    chain.mine()
    const late = await peer(chain, link, undefined)
    expect(late.provider.authorOf(b.doc.clientID)).toEqual({ address: b.id!.address, proven: false })
  })
})
