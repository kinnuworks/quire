import * as Y from "yjs"
import { describe, expect, it } from "vitest"
import { earlierWriters } from "../../src/blame.js"
import { KIND } from "../../src/protocol.js"
import { ArkivProvider } from "../../src/provider.js"
import type { ArkivStore } from "../../src/store.js"
import { admit, identity, peer, settle } from "../helpers.js"
import { audit, erase, setup, typeSlowly } from "./common.js"

const finding = "Key finding: taps ran dry on eleven of thirty days."

async function pasteBack(chain: Awaited<ReturnType<typeof setup>>["chain"], a: Awaited<ReturnType<typeof setup>>["a"], bea: Awaited<ReturnType<typeof setup>>["bea"], text: string) {
  const t = a.doc.getText("t")
  t.delete(0, t.length)
  t.insert(0, text)
  await a.provider.flush()
  await settle(chain, [a, bea])
}

describe("round 17 follow-ups", () => {
  it("the copy note still names the first writer when the paste breaks a line where she had a space", async () => {
    const { chain, a, bea, link } = await setup()
    await typeSlowly(chain, bea, [a], finding)
    await erase(chain, a, bea)
    await pasteBack(chain, a, bea, finding.replace(" taps ran", "\ntaps  ran"))
    const { doc, p } = await audit(chain, link)
    expect(earlierWriters(doc, p).map((w) => w.first)).toEqual([bea.id!.address])
    p.destroy()
  })

  it("a cut-short walk still reads the erased member it found when junk overflows the unfiltered read", async () => {
    const { chain, a, owner, link } = await setup()
    // the owner renews the list 2,000 times before Bea ever joins
    const store = chain.store(owner.address)
    const aclKey = a.provider.aclKey!
    let until = (await store.get(aclKey))!.expiresAt
    for (let i = 0; i < 2001; i++) {
      until += 1n
      await store.batch({ extensions: [{ key: aclKey, lifetimeSeconds: 0, expiresAtBlock: until }] })
      chain.mine()
    }
    const bea = await peer(chain, link, identity("bea"))
    await admit(chain, a, bea)
    await typeSlowly(chain, bea, [a], finding)
    await erase(chain, a, bea)
    const junk = chain.store(identity("junk").address)
    for (let i = 0; i < 3; i++) {
      await junk.batch({ creates: Array.from({ length: 400 }, () => ({ payload: new Uint8Array(1), attributes: { doc: link.doc, kind: KIND.update, seq: 0n }, lifetimeSeconds: 86400 })) })
      chain.mine()
    }
    a.provider.destroy()
    bea.provider.destroy()
    const r = await audit(chain, link)
    expect(r.p.listWalkCut).toBe(true)
    expect(r.p.auditNarrowed).toBe(true)
    expect(r.p.history.filter((h) => h.author === bea.id!.address).length).toBeGreaterThan(0)
    r.p.destroy()
  }, 300_000)

  it("a member erased without a key rotation still sees her later words as unproven in her own tab", async () => {
    const { chain, a, bea } = await setup()
    await typeSlowly(chain, bea, [a], "Before. ")
    await erase(chain, a, bea)
    const t = bea.doc.getText("t")
    t.insert(t.length, "Written after she was erased.")
    await bea.provider.flush().catch(() => undefined)
    await settle(chain, [a, bea])
    let item = (t as unknown as { _start: { deleted: boolean; countable: boolean; id: { client: number; clock: number }; length: number; content: { str?: string }; right: unknown } | null })._start
    const after: boolean[] = []
    for (; item; item = item.right as typeof item) {
      if (item.deleted || !item.countable || !item.content.str?.includes("erased")) continue
      after.push(bea.provider.authorOfItem(item.id.client, item.id.clock, item.length)?.proven ?? false)
    }
    expect(after.length).toBeGreaterThan(0)
    expect(after.every((x) => !x)).toBe(true)
  })

  it("if today's member list cannot be read at the start of the walk, the audit reads every edit instead", async () => {
    const { chain, a, bea, link } = await setup()
    await typeSlowly(chain, bea, [a], finding)
    await erase(chain, a, bea)
    const aclKey = a.provider.aclKey!
    a.provider.destroy()
    bea.provider.destroy()
    const base = chain.store(undefined)
    // reads at a past block work; reading the list as it stands now, where the walk starts, fails
    let failed = 0
    const store: ArkivStore = {
      ...base,
      get: async (k, b) => {
        if (k === aclKey && b === undefined) {
          failed++
          throw new Error("429")
        }
        return base.get(k, b)
      },
    }
    const doc = new Y.Doc()
    const p = new ArkivProvider(doc, { store, link, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0, readOnly: true, fullHistory: true })
    await p.connect()
    expect(failed).toBeGreaterThan(0)
    expect(p.history.filter((h) => h.author === bea.id!.address).length).toBeGreaterThan(0)
    p.destroy()
  })
})
