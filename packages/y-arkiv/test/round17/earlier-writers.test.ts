import { describe, expect, it } from "vitest"
import { blame, earlierWriters } from "../../src/blame.js"
import { settle } from "../helpers.js"
import { audit, erase, setup, typeSlowly } from "./common.js"

const finding = "Key finding: taps ran dry on eleven of thirty days."

describe("earlierWriters: the 'typed first by someone else' note", () => {
  it("control: flags a verbatim paste-back of words Bea typed in order", async () => {
    const { chain, a, bea, owner } = await setup()
    await typeSlowly(chain, bea, [a], finding)
    await erase(chain, a, bea)
    const t = a.doc.getText("t")
    t.delete(0, t.length)
    t.insert(0, finding)
    await a.provider.flush()
    await settle(chain, [a, bea])
    const { doc, p } = await audit(chain, a.provider["link"])
    const found = earlierWriters(doc, p)
    expect(found.map((f) => [f.address, f.first])).toEqual([[owner.address, bea.id!.address]])
    p.destroy()
  })

  it("misses the paste-back when Bea fixed one typo mid-sentence while writing", async () => {
    const { chain, a, bea, owner } = await setup()
    // Bea types "thrity", then goes back and fixes it: an ordinary writing pattern
    await typeSlowly(chain, bea, [a], finding.replace("thirty", "thrity"))
    const bt = bea.doc.getText("t")
    const i = bt.toString().indexOf("thrity")
    bt.delete(i + 2, 2)
    bt.insert(i + 2, "ir")
    await bea.provider.flush()
    await settle(chain, [a, bea])
    expect(bt.toString()).toBe(finding)
    await erase(chain, a, bea)
    const t = a.doc.getText("t")
    t.delete(0, t.length)
    t.insert(0, finding)
    await a.provider.flush()
    await settle(chain, [a, bea])
    const { doc, p } = await audit(chain, a.provider["link"])
    // blame proves the whole finding as the owner's paste
    expect(blame(doc, p).flat().filter((r) => r.proven).map((r) => [r.address, r.text])).toContainEqual([owner.address, finding])
    const found = earlierWriters(doc, p)
    // Bea typed every one of these words first; the note should say so
    expect(found.map((f) => f.first)).toEqual([bea.id!.address])
    p.destroy()
  })

  it("misses the paste-back when the owner types one more character in the same flush", async () => {
    const { chain, a, bea } = await setup()
    await typeSlowly(chain, bea, [a], finding)
    await erase(chain, a, bea)
    const t = a.doc.getText("t")
    t.delete(0, t.length)
    t.insert(0, finding)
    t.insert(t.length, " ") // a trailing space typed within the same 2-4 s flush
    await a.provider.flush()
    await settle(chain, [a, bea])
    const { doc, p } = await audit(chain, a.provider["link"])
    const found = earlierWriters(doc, p)
    expect(found.map((f) => f.first)).toEqual([bea.id!.address])
    p.destroy()
  })

  it("misses a paste-back of words Bea typed in two sittings that end up adjacent out of clock order", async () => {
    const { chain, a, bea } = await setup()
    // Bea writes the second sentence first, then inserts the first sentence before it
    const s1 = "Key finding: taps ran dry on eleven of thirty days. "
    const s2 = "Ward 14 was hit hardest, with nine dry days in a row."
    await typeSlowly(chain, bea, [a], s2)
    await typeSlowly(chain, bea, [a], s1, 0)
    expect(bea.doc.getText("t").toString()).toBe(s1 + s2)
    await erase(chain, a, bea)
    const t = a.doc.getText("t")
    t.delete(0, t.length)
    t.insert(0, s1 + s2)
    await a.provider.flush()
    await settle(chain, [a, bea])
    const { doc, p } = await audit(chain, a.provider["link"])
    const found = earlierWriters(doc, p)
    expect(found.map((f) => f.first)).toEqual([bea.id!.address])
    p.destroy()
  })
})
