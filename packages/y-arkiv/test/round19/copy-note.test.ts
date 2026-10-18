import { describe, expect, it } from "vitest"
import { blame, earlierWriters } from "../../src/blame.js"
import { settle } from "../helpers.js"
import { audit, erase, setup, typeSlowly } from "../round17/common.js"
import { pyEarlier } from "./common.js"

const finding = "Key finding: taps ran dry on eleven of thirty days."
const name = (owner: string, bea: string) => (a: string) => (a === owner ? "asha" : a === bea ? "bea" : a)

/** Bea types the finding, the owner erases her, deletes it and pastes `copy` in one edit. */
async function pasteBack(copy: string) {
  const s = await setup()
  await typeSlowly(s.chain, s.bea, [s.a], finding)
  await erase(s.chain, s.a, s.bea)
  const t = s.a.doc.getText("t")
  t.delete(0, t.length)
  t.insert(0, copy)
  await s.a.provider.flush()
  await settle(s.chain, [s.a, s.bea])
  const { doc, p } = await audit(s.chain, s.a.provider["link"])
  return { ...s, doc, p }
}

describe("R19-A: the copy note names the real writer as the copier", () => {
  it("Asha takes one word of Bea's suggested rewording while revising her own sentence", async () => {
    const { chain, a, bea, owner } = await setup()
    const at = a.doc.getText("t")
    // Asha types her sentence at typing speed (12 words, so one word in six is 2)
    const mine = "Pumps at ward fourteen failed on nine of the thirty survey days."
    await typeSlowly(chain, a, [bea], mine)
    // Bea pastes a suggested rewording below it, one word changed ("nine" -> "eleven")
    const bt = bea.doc.getText("t")
    bt.insert(bt.length, "\nSuggest: " + mine.replace("nine", "eleven"))
    await bea.provider.flush()
    await settle(chain, [a, bea])
    // Asha revises her own sentence: takes "eleven", and changes two more words herself ("Pumps" -> "Wells", "failed" -> "broke")
    const revised = mine.replace("nine", "eleven").replace("Pumps", "Wells").replace("failed", "broke")
    // edited in place, word by word, as in the editor; the suggestion paragraph is left alone
    for (const [from, to] of [["nine", "eleven"], ["Pumps", "Wells"], ["failed", "broke"]] as const) {
      const i = at.toString().indexOf(from)
      at.delete(i, from.length)
      at.insert(i, to)
    }
    await a.provider.flush()
    await settle(chain, [a, bea])
    const { doc, p } = await audit(chain, a.provider["link"])
    expect(doc.getText("t").toString().split("\n")[0]).toBe(revised)
    const n = name(owner.address, bea.id!.address)
    const ts = earlierWriters(doc, p).map((w) => `${n(w.address)} copied ${n(w.first)}: ${w.text}`)
    const py = pyEarlier(p)?.map((w) => `${n(w.address)} copied ${n(w.first)}: ${w.text}`)
    // Asha typed 9 of the 12 words before Bea's suggestion existed and 2 more after it before Bea's suggestion existed; Bea supplied one word
    expect(ts).toEqual([])
    if (py) expect(py).toEqual(ts)
    p.destroy()
  })
})

describe("R19-B: the TypeScript and Python readers disagree on the copy verdict", () => {
  it("a paste-back with an invisible TAG character (U+E0020, astral, category Cf) inside each word", async () => {
    const copy = finding.replace(/(\S)(\S*)/g, "$1\u{E0020}$2")
    const { doc, p, bea } = await pasteBack(copy)
    // renders identically: tag characters have no glyph
    expect(doc.getText("t").toString().replace(/\u{E0020}/gu, "")).toBe(finding)
    const ts = earlierWriters(doc, p).map((w) => w.first)
    const py = pyEarlier(p)?.map((w) => w.first)
    // JS walks UTF-16 units, so each half of the surrogate pair is "Cs", not "Cf", and stays in the word;
    // Python walks code points, sees Cf and drops it
    expect(ts).toEqual([bea.id!.address])
    if (py) expect(py).toEqual(ts)
    p.destroy()
  })
})

describe("R19-C: the copy note misses a paste-back that renders identically", () => {
  it("a variation selector (U+FE0E, category Mn, no glyph) after the first letter of each word", async () => {
    const copy = finding.replace(/(\S)(\S*)/g, "$1︎$2")
    const { doc, p, bea } = await pasteBack(copy)
    expect(doc.getText("t").toString().replace(/︎/g, "")).toBe(finding)
    const ts = earlierWriters(doc, p).map((w) => w.first)
    const py = pyEarlier(p)?.map((w) => w.first)
    expect(ts).toEqual([bea.id!.address])
    if (py) expect(py).toEqual(ts)
    p.destroy()
  })
  it("Cyrillic look-alikes for a, e, o, p, c (renders identically in every common font)", async () => {
    const copy = finding.replace(/a/g, "а").replace(/e/g, "е").replace(/o/g, "о").replace(/y/g, "у")
    const { p, doc, bea } = await pasteBack(copy)
    const ts = earlierWriters(doc, p).map((w) => w.first)
    const py = pyEarlier(p)?.map((w) => w.first)
    expect(ts).toEqual([bea.id!.address])
    if (py) expect(py).toEqual(ts)
    p.destroy()
  })
})

describe("R19-D: the copy note misses an ordinary, unmodified paste-back", () => {
  it("Bea's 90-word field log of short sentences, pasted back verbatim in one edit", async () => {
    const log = Array.from({ length: 15 }, (_, i) => `Day ${i + 3}: ward ${i + 9} dry.`).join(" ") + " Pumps failed twice. Crews came late. Ward 14 worst."
    expect(log.split(/\s+/).length).toBeGreaterThan(80)
    const s = await setup()
    await typeSlowly(s.chain, s.bea, [s.a], log)
    await erase(s.chain, s.a, s.bea)
    const t = s.a.doc.getText("t")
    t.delete(0, t.length)
    t.insert(0, log)
    await s.a.provider.flush()
    await settle(s.chain, [s.a, s.bea])
    const { doc, p } = await audit(s.chain, s.a.provider["link"])
    expect(doc.getText("t").toString()).toBe(log)
    // blame proves all 90 words as the owner's
    expect(blame(doc, p).flat().every((r) => r.proven && r.address === s.owner.address)).toBe(true)
    const ts = earlierWriters(doc, p).map((w) => w.first)
    const py = pyEarlier(p)?.map((w) => w.first)
    // whole run > 80 words, the paste (one edit) > 80 words, every sentence < 24 characters: nothing is checked
    expect(ts).toEqual([s.bea.id!.address])
    if (py) expect(py).toEqual(ts)
    p.destroy()
  })
})
