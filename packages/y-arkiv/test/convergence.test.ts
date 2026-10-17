import fc from "fast-check"
import { describe, expect, it } from "vitest"
import { MemoryChain } from "../src/memory.js"
import { admit, identity, newDocument, type Peer, peer, settle, text } from "./helpers.js"

type Op =
  | { t: "insert"; p: number; at: number; s: string }
  | { t: "delete"; p: number; at: number; n: number }
  | { t: "flush"; p: number }
  | { t: "compact"; p: number }
  | { t: "mine" }

const op: fc.Arbitrary<Op> = fc.oneof(
  { weight: 5, arbitrary: fc.record({ t: fc.constant("insert" as const), p: fc.nat(2), at: fc.nat(40), s: fc.string({ minLength: 1, maxLength: 6 }) }) },
  { weight: 2, arbitrary: fc.record({ t: fc.constant("delete" as const), p: fc.nat(2), at: fc.nat(40), n: fc.integer({ min: 1, max: 4 }) }) },
  { weight: 3, arbitrary: fc.record({ t: fc.constant("flush" as const), p: fc.nat(2) }) },
  { weight: 1, arbitrary: fc.record({ t: fc.constant("compact" as const), p: fc.nat(2) }) },
  { weight: 2, arbitrary: fc.record({ t: fc.constant("mine" as const) }) },
)

describe("convergence", () => {
  it("any interleaving of edits, flushes, compactions and blocks converges on every peer and a late joiner", async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(op, { minLength: 5, maxLength: 60 }), async (ops) => {
        const chain = new MemoryChain()
        const { owner, link } = await newDocument(chain)
        const a = await peer(chain, link, owner)
        const b = await peer(chain, link, identity("bea"))
        const c = await peer(chain, link, identity("cal"))
        await admit(chain, a, b)
        await admit(chain, a, c)
        const peers: Peer[] = [a, b, c]

        for (const o of ops) {
          if (o.t === "mine") {
            await settle(chain, peers)
            continue
          }
          const p = peers[o.p]!
          const t = p.doc.getText("t")
          if (o.t === "insert") t.insert(Math.min(o.at, t.length), o.s)
          else if (o.t === "delete") {
            const at = Math.min(o.at, t.length)
            t.delete(at, Math.min(o.n, t.length - at))
          } else if (o.t === "flush") await p.provider.flush()
          else await p.provider.compact()
        }
        for (const p of peers) await p.provider.flush()
        await settle(chain, peers, 2)

        const expected = text(a)
        expect(text(b)).toBe(expected)
        expect(text(c)).toBe(expected)
        const late = await peer(chain, link, undefined)
        expect(text(late)).toBe(expected)
        for (const p of [...peers, late]) p.provider.destroy()
      }),
      { numRuns: 60 },
    )
  }, 120_000)
})
