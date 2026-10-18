import { describe, expect, it } from "vitest"
import { blame, earlierWriters } from "../../src/blame.js"
import { settle } from "../helpers.js"
import { audit, setup } from "../round17/common.js"

/** Milliseconds of CPU this process spent, user and system. */
const cpuMs = (u: NodeJS.CpuUsage) => (u.user + u.system) / 1000

const N = Number(process.env.R18_FLUSHES ?? 1200)
const PASTES = Number(process.env.R18_PASTES ?? 40)

describe("R18-C: the copy note runs on every render of the document page", () => {
  it(`a document of ${N} typed flushes and ${PASTES} pasted paragraphs (an hour or so of writing)`, async () => {
    const { chain, a, bea } = await setup()
    const t = a.doc.getText("t")
    const words = "the survey found that taps in the eastern wards ran dry on most days of the month and ".repeat(4)
    for (let i = 0; i < N; i++) {
      if (i % Math.floor(N / PASTES) === 0) t.insert(t.length, `\nPasted note ${i}: ` + words.slice(0, 240) + "\n")
      else t.insert(t.length, words.slice((i * 12) % 300, ((i * 12) % 300) + 12))
      await a.provider.flush()
      chain.mine()
    }
    await settle(chain, [a, bea])
    const { doc, p } = await audit(chain, a.provider["link"])
    const t0 = performance.now()
    blame(doc, p)
    const blameMs = performance.now() - t0
    // CPU time, the best of three runs: other test files (and other programs) share the machine, and
    // waiting for a core is not the algorithm
    let copyMs = Infinity
    for (let run = 0; run < 3; run++) {
      const t1 = process.cpuUsage()
      earlierWriters(doc, p)
      copyMs = Math.min(copyMs, cpuMs(process.cpuUsage(t1)))
    }
    console.log(JSON.stringify({ chars: doc.getText("t").length, edits: p.history.length, blameMs: Math.round(blameMs), earlierWritersMs: Math.round(copyMs) }))
    p.destroy()
    // DocPage.tsx:118 calls earlierWriters synchronously in render, on every tick, while "Who wrote what" is on
    // or anyone was erased; a frame is 16 ms and a render that takes over 200 ms is a visible freeze
    expect(copyMs).toBeLessThan(200)
  }, 590_000)
})

describe("the copy note on a document two members wrote", () => {
  it(`${N} flushes split between two writers, with shared phrasing and one real copy`, async () => {
    const { chain, a, bea, owner } = await setup()
    const at = a.doc.getText("t")
    const words = "the survey found that taps in the eastern wards ran dry on most days of the month and ".repeat(4)
    for (let i = 0; i < N; i++) {
      const who = i % 2 ? a : bea
      const t = who.doc.getText("t")
      if (i % Math.floor(N / PASTES) === 0) t.insert(t.length, `\nNote ${i} by ${i % 2 ? "asha" : "bea"}: ` + words.slice(i % 40, 200 + (i % 40)) + "\n")
      else t.insert(t.length, words.slice((i * 12) % 300, ((i * 12) % 300) + 12))
      await who.provider.flush()
      await settle(chain, [a, bea])
    }
    // Asha pastes a sentence only Bea wrote
    const mark = "Bea alone measured the pressure at ward fourteen, nine bar at noon."
    const bt = bea.doc.getText("t")
    bt.insert(bt.length, "\n" + mark)
    await bea.provider.flush()
    await settle(chain, [a, bea])
    at.insert(at.length, "\n" + mark.replace("nine", "9"))
    await a.provider.flush()
    await settle(chain, [a, bea])
    const { doc, p } = await audit(chain, a.provider["link"])
    let copyMs = Infinity
    let found: ReturnType<typeof earlierWriters> = []
    for (let run = 0; run < 3; run++) {
      const t1 = process.cpuUsage()
      found = earlierWriters(doc, p)
      copyMs = Math.min(copyMs, cpuMs(process.cpuUsage(t1)))
    }
    console.log(JSON.stringify({ chars: doc.getText("t").length, edits: p.history.length, earlierWritersMs: Math.round(copyMs), found: found.length }))
    p.destroy()
    expect(found.filter((w) => w.address === owner.address && w.first === bea.id!.address && w.text.includes("pressure"))).toHaveLength(1)
    expect(copyMs).toBeLessThan(1500)
  }, 590_000)
})
