import { describe, expect, it } from "vitest"
import { earlierWriters } from "../../src/blame.js"
import { admit, identity, peer, settle } from "../helpers.js"
import { setup } from "../round17/common.js"
import { audit } from "../round17/common.js"

const N = Number(process.env.R19_FLUSHES ?? 2000)
const cpuMs = (u: NodeJS.CpuUsage) => (u.user + u.system) / 1000

/** Deterministic prose: a 1,500-word vocabulary drawn with a Zipf-like skew, sentences of 8 to 22 words. */
function prose(seed: number) {
  let x = seed
  const rnd = () => ((x = (x * 1103515245 + 12345) % 2147483648) / 2147483648)
  const vocab = Array.from({ length: 1500 }, (_, i) => (i < 60 ? ["the", "of", "and", "to", "in", "a", "was", "on", "at", "for"][i % 10] + (i >= 10 ? String.fromCharCode(97 + (i % 26)) : "") : "w" + i.toString(36) + "ard".slice(0, i % 4)))
  return () => {
    const n = 8 + Math.floor(rnd() * 15)
    const ws = Array.from({ length: n }, () => vocab[Math.floor(1500 * rnd() ** 2.2)]!)
    return ws.join(" ") + ". "
  }
}

describe("R19-E: the copy note's cost on a realistic three-author document", () => {
  it(`${N} flushes of 10 to 20 characters from three writers, varied prose, plus ten pasted paragraphs`, async () => {
    const { chain, a, bea, link } = await setup()
    const cai = await peer(chain, link, identity("cai"))
    await admit(chain, a, cai)
    const writers = [a, bea, cai]
    const gens = writers.map((_, i) => prose(7 + i))
    const buffers = writers.map(() => "")
    for (let i = 0; i < N; i++) {
      const w = i % 3
      const p = writers[w]!
      const t = p.doc.getText("t")
      if (i % Math.floor(N / 10) === 0) {
        t.insert(t.length, "\n" + Array.from({ length: 6 }, gens[w]!).join(""))
      } else {
        if (buffers[w]!.length < 20) buffers[w] += gens[w]!()
        const step = 10 + (i % 11)
        t.insert(t.length, buffers[w]!.slice(0, step))
        buffers[w] = buffers[w]!.slice(step)
      }
      await p.provider.flush()
      if (i % 30 === 29) await settle(chain, writers)
      else chain.mine()
    }
    await settle(chain, writers)
    const { doc, p } = await audit(chain, a.provider["link"])
    let copyMs = Infinity
    let found = 0
    for (let run = 0; run < 2; run++) {
      const t1 = process.cpuUsage()
      found = earlierWriters(doc, p).length
      copyMs = Math.min(copyMs, cpuMs(process.cpuUsage(t1)))
    }
    p.destroy()
    // the app runs the note only after editing pauses (DocPage), never on each edit; this bounds the cost of one run
    expect(found).toBeGreaterThanOrEqual(0)
    expect(copyMs).toBeLessThan(2000)
  }, 590_000)
})
