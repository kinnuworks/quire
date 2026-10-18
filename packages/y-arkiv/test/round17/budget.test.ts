import * as Y from "yjs"
import { describe, expect, it } from "vitest"
import { ArkivProvider } from "../../src/provider.js"
import { KIND } from "../../src/protocol.js"
import { identity, settle } from "../helpers.js"
import { counting, setup, typeSlowly } from "./common.js"

/** What `y-arkiv verify` and `blame` spend: the load, the outside-writes page and the recreated check. */
async function verifyCost(chain: Awaited<ReturnType<typeof setup>>["chain"], link: Awaited<ReturnType<typeof setup>>["link"], fullHistory: boolean) {
  const store = counting(chain.store(undefined))
  const doc = new Y.Doc()
  const p = new ArkivProvider(doc, { store, link, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0, readOnly: true, fullHistory })
  await p.connect()
  const load = store.queries
  await p.outsiderEntities()
  const older = await p.predatingEntities()
  const r = { load, total: store.queries, recreatedFound: older.length, truncated: p.predatingTruncated, text: doc.getText("t").toString() }
  p.destroy()
  return r
}

describe("a stranger runs up every verify and blame", () => {
  it("2,000 junk entities stamped qs = 0 add at most eight queries to verify and blame", async () => {
    const { chain, a, bea, link } = await setup()
    await typeSlowly(chain, bea, [a], "Bea's genuine words.")
    a.provider.destroy()
    bea.provider.destroy()
    const clean = { verify: await verifyCost(chain, link, false), blame: await verifyCost(chain, link, true) }

    // a stranger who saw the public document id: 2,000 tiny entities, early qs, in a handful of transactions
    const stranger = identity("stranger")
    const s = chain.store(stranger.address)
    for (const kind of [KIND.update, KIND.snapshot]) {
      for (let i = 0; i < 2; i++) {
        await s.batch({ creates: Array.from({ length: 500 }, () => ({ payload: new Uint8Array(1), attributes: { doc: link.doc, kind, seq: 0n }, lifetimeSeconds: 86400 * 30 })) })
        chain.mine()
      }
    }
    await settle(chain, [])
    const junk = { verify: await verifyCost(chain, link, false), blame: await verifyCost(chain, link, true) }
    // one query lists outside writes; the recreated check is one query for an earlier list and one page each of edits and snapshots
    // one query lists outside writes; the recreated check reads one page each of edits and snapshots,
    // and junk stamped that early stretches it to five pages of each, no further (README, junk and the query budget)
    expect(clean.verify.total - clean.verify.load).toBe(3)
    expect(junk.verify.total - clean.verify.total).toBeLessThanOrEqual(8)
    expect(junk.blame.total - clean.blame.total).toBeLessThanOrEqual(8)
    expect(junk.verify.recreatedFound).toBe(0)
  })
})
