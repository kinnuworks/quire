import { describe, expect, it } from "vitest"
import { blame, earlierWriters } from "../../src/blame.js"
import { settle } from "../helpers.js"
import { audit, erase, setup, typeSlowly } from "../round17/common.js"

const finding = "Key finding: taps ran dry on eleven of thirty days."

describe("R18-A: the copy note falsely accuses the real author", () => {
  it("Bea pastes a trimmed copy for one block, then trims Asha's sentence the same way: Asha is named the copier", async () => {
    const { chain, a, bea, owner } = await setup()
    // Asha (the owner) pastes her own sentence from her notes: one edit, one proven run
    const original = "The water tests failed at ward fourteen badly in March."
    a.doc.getText("t").insert(0, original)
    await a.provider.flush()
    await settle(chain, [a, bea])
    const trimmed = original.replace("badly ", "")
    // Bea pastes the trimmed copy at the end (one block)...
    const bt = bea.doc.getText("t")
    bt.insert(bt.length, "\n" + trimmed)
    await bea.provider.flush()
    await settle(chain, [a, bea])
    // ...then deletes her copy and makes the same edit to Asha's sentence: an ordinary copy-edit
    bt.delete(original.length, trimmed.length + 1)
    const at = bt.toString().indexOf("badly ")
    bt.delete(at, "badly ".length)
    await bea.provider.flush()
    await settle(chain, [a, bea])
    expect(bt.toString()).toBe(trimmed)
    const { doc, p } = await audit(chain, a.provider["link"])
    const runs = blame(doc, p).flat().filter((r) => r.proven)
    // blame correctly proves every visible character as Asha's
    expect(runs.map((r) => [r.address, r.text])).toEqual([[owner.address, trimmed]])
    const notes = earlierWriters(doc, p).map((w) => ({ accused: w.address === owner.address ? "asha (typed every character)" : w.address, typedFirst: w.first === bea.id!.address ? "bea (pasted a copy for one block)" : w.first }))
    // Asha typed every character first; there should be no note
    expect(notes).toEqual([])
    p.destroy()
  })
})

describe("R18-B: the copy note misses ordinary copying", () => {
  it("the owner re-types Bea's erased finding at typing speed (12 characters a flush): no note", async () => {
    const { chain, a, bea, owner } = await setup()
    await typeSlowly(chain, bea, [a], finding)
    await erase(chain, a, bea)
    const t = a.doc.getText("t")
    t.delete(0, t.length)
    await a.provider.flush()
    await settle(chain, [a, bea])
    await typeSlowly(chain, a, [bea], finding)
    const { doc, p } = await audit(chain, a.provider["link"])
    expect(doc.getText("t").toString()).toBe(finding)
    expect(blame(doc, p).flat().every((r) => r.proven && r.address === owner.address)).toBe(true)
    expect(await p.erasedMembers()).toEqual([bea.id!.address])
    // Bea typed every word first, in the same 12-character steps
    expect(earlierWriters(doc, p).map((w) => w.first)).toContain(bea.id!.address)
    p.destroy()
  })

  it("the owner pastes Bea's finding in one edit with a zero-width space after each word: no note", async () => {
    const { chain, a, bea } = await setup()
    await typeSlowly(chain, bea, [a], finding)
    await erase(chain, a, bea)
    const t = a.doc.getText("t")
    t.delete(0, t.length)
    t.insert(0, finding.replace(/ /g, " ​"))
    await a.provider.flush()
    await settle(chain, [a, bea])
    const { doc, p } = await audit(chain, a.provider["link"])
    // renders identically to Bea's finding
    expect(doc.getText("t").toString().replace(/​/g, "")).toBe(finding)
    expect(earlierWriters(doc, p).map((w) => w.first)).toEqual([bea.id!.address])
    p.destroy()
  })
  it("the owner slips one zero-width space into Bea's sentence while she is still typing, then pastes it back clean: no note", async () => {
    const { chain, a, bea } = await setup()
    await typeSlowly(chain, bea, [a], finding.slice(0, 24))
    // one invisible character from the owner inside Bea's half-typed sentence
    a.doc.getText("t").insert(12, "\u200b")
    await a.provider.flush()
    await settle(chain, [a, bea])
    await typeSlowly(chain, bea, [a], finding.slice(24))
    expect(bea.doc.getText("t").toString().replace(/\u200b/g, "")).toBe(finding)
    await erase(chain, a, bea)
    const t = a.doc.getText("t")
    t.delete(0, t.length)
    t.insert(0, finding)
    await a.provider.flush()
    await settle(chain, [a, bea])
    const { doc, p } = await audit(chain, a.provider["link"])
    expect(doc.getText("t").toString()).toBe(finding)
    // Bea typed all 51 visible characters first; the owner's only contribution was one invisible character
    expect(earlierWriters(doc, p).map((w) => w.first)).toEqual([bea.id!.address])
    p.destroy()
  })
})


describe("the copy note after round 18", () => {
  it("finds a copy with one word changed", async () => {
    const { chain, a, bea, owner } = await setup()
    await typeSlowly(chain, bea, [a], finding)
    await erase(chain, a, bea)
    const t = a.doc.getText("t")
    t.delete(0, t.length)
    t.insert(0, finding.replace("eleven", "twelve"))
    await a.provider.flush()
    await settle(chain, [a, bea])
    const { doc, p } = await audit(chain, a.provider["link"])
    expect(earlierWriters(doc, p).map((w) => [w.address, w.first])).toEqual([[owner.address, bea.id!.address]])
    p.destroy()
  })

  it("a copy of a sentence its writer is still finishing names the copier, not the writer", async () => {
    const { chain, a, bea, owner } = await setup()
    // Bea copies everything but the last word, which matches the finished sentence within one word
    const half = finding.slice(0, 45)
    await typeSlowly(chain, a, [bea], half)
    const bt = bea.doc.getText("t")
    bt.insert(bt.length, "\n" + half)
    await bea.provider.flush()
    await settle(chain, [a, bea])
    await typeSlowly(chain, a, [bea], finding.slice(45), 45)
    const { doc, p } = await audit(chain, a.provider["link"])
    expect(doc.getText("t").toString()).toBe(finding + "\n" + half)
    expect(earlierWriters(doc, p).map((w) => [w.address, w.first])).toEqual([[bea.id!.address, owner.address]])
    p.destroy()
  })

  it("a copy embedded in a longer paragraph of the copier's own is found sentence by sentence", async () => {
    const { chain, a, bea, owner } = await setup()
    await typeSlowly(chain, bea, [a], finding)
    await erase(chain, a, bea)
    const t = a.doc.getText("t")
    t.delete(0, t.length)
    t.insert(0, "Asha's own opening sentence, written today. ")
    await a.provider.flush()
    await settle(chain, [a, bea])
    await typeSlowly(chain, a, [bea], finding + " And a closing line of her own.")
    const { doc, p } = await audit(chain, a.provider["link"])
    const found = earlierWriters(doc, p)
    expect(found.map((w) => [w.address, w.first, w.text])).toEqual([[owner.address, bea.id!.address, finding]])
    p.destroy()
  })

  it("two typos Bea fixed while typing do not hide her sentence", async () => {
    const { chain, a, bea, owner } = await setup()
    await typeSlowly(chain, bea, [a], finding.replace("thirty", "thrity").replace("eleven", "elevne"))
    const bt = bea.doc.getText("t")
    for (const [wrong, right] of [["thrity", "thirty"], ["elevne", "eleven"]]) {
      // retype only the two swapped letters
      let d = 0
      while (wrong[d] === right[d]) d++
      const i = bt.toString().indexOf(wrong) + d
      bt.delete(i, 2)
      bt.insert(i, right.slice(d, d + 2))
      await bea.provider.flush()
      await settle(chain, [a, bea])
    }
    expect(bt.toString()).toBe(finding)
    await erase(chain, a, bea)
    const t = a.doc.getText("t")
    t.delete(0, t.length)
    t.insert(0, finding)
    await a.provider.flush()
    await settle(chain, [a, bea])
    const { doc, p } = await audit(chain, a.provider["link"])
    expect(earlierWriters(doc, p).map((w) => [w.address, w.first])).toEqual([[owner.address, bea.id!.address]])
    p.destroy()
  })
})
