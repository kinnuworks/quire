import { describe, expect, it } from "vitest"
import * as Y from "yjs"
import { blame, earlierWriters } from "../../src/blame.js"
import { ArkivProvider } from "../../src/provider.js"
import { identity, settle } from "../helpers.js"
import { KIND } from "../../src/protocol.js"
import type { ArkivStore } from "../../src/store.js"
import { audit, erase, setup, typeSlowly } from "./common.js"

const finding = "Key finding: taps ran dry on eleven of thirty days."

/** The owner renews the member list's lease 2,000 times, one block apart: each renewal is a version. */
async function renewMany(chain: Awaited<ReturnType<typeof setup>>["chain"], owner: string, aclKey: `0x${string}`, n: number) {
  const store = chain.store(owner as `0x${string}`)
  let until = (await store.get(aclKey))!.expiresAt
  for (let i = 0; i < n; i++) {
    until += 1n
    await store.batch({ extensions: [{ key: aclKey, lifetimeSeconds: 0, expiresAtBlock: until }] })
    chain.mine()
  }
}

describe("an owner can push an erased member out of the audit by renewing the list", () => {
  it("Bea's proven words and the copy note vanish after 2,000 one-block lease renewals", async () => {
    const { chain, a, bea, owner, link } = await setup()
    await typeSlowly(chain, bea, [a], finding)
    await erase(chain, a, bea)
    const t = a.doc.getText("t")
    t.delete(0, t.length)
    t.insert(0, finding)
    await a.provider.flush()
    await settle(chain, [a, bea])
    const aclKey = a.provider.aclKey!
    bea.provider.destroy()
    a.provider.destroy()

    const before = await audit(chain, link)
    const beaBefore = before.p.history.filter((h) => h.author === bea.id!.address).length
    const notesBefore = earlierWriters(before.doc, before.p).length
    before.p.destroy()

    await renewMany(chain, owner.address, aclKey, 2001)

    const after = await audit(chain, link)
    const beaAfter = after.p.history.filter((h) => h.author === bea.id!.address).length
    const notesAfter = earlierWriters(after.doc, after.p).length
    const proven = blame(after.doc, after.p).flat().filter((r) => r.proven).map((r) => r.address)
    after.p.destroy()
    expect(beaBefore).toBeGreaterThan(0)
    expect(notesBefore).toBe(1)
    // the audit claims to read every address any version of the list named; Bea's seven edits should still be there
    expect(beaAfter).toBe(beaBefore)
    expect(notesAfter).toBe(1)
  }, 300_000)

  it("on the real network (600 reads a minute) a command-line audit waits the limit out; the app says its check was cut short", async () => {
    const { chain, a, bea, owner, link } = await setup()
    await typeSlowly(chain, bea, [a], finding)
    await erase(chain, a, bea)
    const t = a.doc.getText("t")
    t.delete(0, t.length)
    t.insert(0, finding)
    await a.provider.flush()
    await settle(chain, [a, bea])
    const aclKey = a.provider.aclKey!
    bea.provider.destroy()
    a.provider.destroy()
    await renewMany(chain, owner.address, aclKey, 700)
    const junk = chain.store(identity("anyone").address)
    for (let i = 0; i < 2; i++) {
      await junk.batch({ creates: Array.from({ length: 501 }, () => ({ payload: new Uint8Array(1), attributes: { doc: link.doc, kind: KIND.update, seq: 0n }, lifetimeSeconds: 86400 * 30 })) })
      chain.mine()
    }
    // the gateway's measured limit, 600 reads by key a window, with the window shrunk to 40 ms for the test
    const base = chain.store(undefined)
    const limited = (): ArkivStore => {
      let gets = 0
      let window = Date.now()
      return {
        ...base,
        get: async (k, b) => {
          if (Date.now() - window > 40) {
            window = Date.now()
            gets = 0
          }
          if (++gets > 600) throw new Error("429")
          return base.get(k, b)
        },
      }
    }
    // patient, as the CLI is: the walk finishes and Bea's edits are proven
    const doc = new Y.Doc()
    const patient = new ArkivProvider(doc, { store: limited(), link, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0, readOnly: true, fullHistory: true, readPatienceMs: 50 })
    await patient.connect()
    expect(patient.history.filter((h) => h.author === bea.id!.address).length).toBeGreaterThan(0)
    expect(earlierWriters(doc, patient).map((w) => w.first)).toEqual([bea.id!.address])
    expect(await patient.erasedMembers()).toEqual([bea.id!.address])
    patient.destroy()
    // impatient, as the app is: the check is cut short and says so, rather than reading clean
    let gets = 0
    const rushed = await audit(chain, link, { ...base, get: async (k, b) => { if (++gets > 600) throw new Error("429"); return base.get(k, b) } })
    expect(rushed.p.auditNarrowed).toBe(true)
    rushed.p.destroy()
  }, 300_000)
})
