import { describe, expect, it } from "vitest"
import { earlierWriters } from "../../src/blame.js"
import { settle } from "../helpers.js"
import { audit, setup, typeSlowly } from "./common.js"

const para = "Asha's own result: the pumps failed after the third storm."

describe("earlierWriters can be triggered falsely by a member", () => {
  it("names Bea as the first writer of Asha's own paragraph after Asha moves it", async () => {
    const { chain, a, bea, owner, link } = await setup()
    // Asha types her paragraph first, a few words at a time
    await typeSlowly(chain, a, [bea], para)
    // Bea copies it, pastes it as one edit, and deletes the copy at once: nothing visible remains
    const bt = bea.doc.getText("t")
    bt.insert(bt.length, "\n" + para)
    await bea.provider.flush()
    await settle(chain, [a, bea])
    bt.delete(para.length, para.length + 1)
    await bea.provider.flush()
    await settle(chain, [a, bea])
    expect(bt.toString()).toBe(para)
    // later Asha moves her own paragraph (cut and paste) below a new heading
    const t = a.doc.getText("t")
    t.insert(t.length, "\nResults\n")
    await a.provider.flush()
    await settle(chain, [a, bea])
    t.delete(0, para.length)
    t.insert(t.length, para)
    await a.provider.flush()
    await settle(chain, [a, bea])
    expect(t.toString()).toBe("\nResults\n" + para)
    const { doc, p } = await audit(chain, link)
    const found = earlierWriters(doc, p)
    // Asha typed these words first (blocks before Bea's paste). No note should accuse her.
    const name = (x: string) => (x === owner.address ? "asha (who typed it first)" : x === bea.id!.address ? "bea (who pasted a copy and deleted it)" : x)
    expect(found.map((f) => ({ accusedOfCopying: name(f.address), typedFirst: name(f.first) }))).toEqual([])
    // what the app and CLI print instead:
    //   "Typed first by someone else. ... is a single edit by <Asha> ... but <Bea> typed the same words earlier"
    expect(owner.address).toBeTruthy()
    p.destroy()
  })
})
