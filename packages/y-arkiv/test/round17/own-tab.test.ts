import { describe, expect, it } from "vitest"
import { blame } from "../../src/blame.js"
import { settle } from "../helpers.js"
import { audit, setup, typeSlowly } from "./common.js"

/** The app's "Who wrote what" (apps/quire/src/authorship.ts blockAuthors) asks authorOfItem for every visible item. */
function appVerdict(p: Awaited<ReturnType<typeof setup>>["bea"]) {
  const out: { text: string; address?: string; proven?: boolean }[] = []
  let item = (p.doc.getText("t") as unknown as { _start: any })._start
  for (; item; item = item.right) {
    if (item.deleted || !item.countable) continue
    const a = p.provider.authorOfItem(item.id.client, item.id.clock, item.length)
    out.push({ text: item.content.str, address: a?.address, proven: a?.proven })
  }
  return out
}

describe("the writer's own tab vs every other reader", () => {
  it("a removed member's tab shows words no reader accepts as proven by her key", async () => {
    const { chain, a, bea, link, owner } = await setup()
    await typeSlowly(chain, bea, [a], "Before removal. ")
    await a.provider.revoke(bea.id!.address)
    await settle(chain, [a, bea])
    // Bea's tab keeps the document; she keeps typing, and her flush still lands on chain
    const t = bea.doc.getText("t")
    t.insert(t.length, "Written after she was removed.")
    await bea.provider.flush().catch(() => undefined)
    await settle(chain, [a, bea])
    const app = appVerdict(bea)
    const cli = blame(bea.provider["doc"], bea.provider).flat()
    const { doc, p } = await audit(chain, link, undefined, owner)
    const cold = blame(doc, p).flat()
    // the bar in Bea's own tab must not say "proven" for text the chain does not prove
    const after = app.filter((x) => x.text.includes("after she was removed"))
    expect(after.every((x) => !x.proven)).toBe(true)
    p.destroy()
  })

  it("a member's own tab shows never-written text as proven", async () => {
    const { a } = await setup()
    a.doc.getText("t").insert(0, "Never flushed: no entity, no block, no proof.")
    // no flush: nothing is on chain (out of gas, tab closed, network down)
    const app = appVerdict(a)
    expect(app.every((x) => !x.proven)).toBe(true)
  })
})
