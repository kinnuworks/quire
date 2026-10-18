import { describe, expect, it } from "vitest"
import * as Y from "yjs"
import { ArkivProvider } from "../../src/provider.js"
import type { ArkivStore } from "../../src/store.js"
import { erase, setup, typeSlowly } from "../round17/common.js"

const para = "Bea's paragraph: the pumps at ward fourteen failed on nine days in a row."

async function renewMany(chain: Awaited<ReturnType<typeof setup>>["chain"], owner: string, aclKey: `0x${string}`, n: number) {
  const store = chain.store(owner as `0x${string}`)
  let until = (await store.get(aclKey))!.expiresAt
  for (let i = 0; i < n; i++) {
    until += 1n
    await store.batch({ extensions: [{ key: aclKey, lifetimeSeconds: 0, expiresAtBlock: until }] })
    chain.mine()
  }
}

/** The app's default session, as useDocument.ts:95 opens it before anyone toggles "Who wrote what". */
async function appOpen(store: ArkivStore, link: Parameters<typeof ArkivProvider.createDocument>[0]["link"]) {
  const doc = new Y.Doc()
  const p = new ArkivProvider(doc, { store, link, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0, readOnly: true, fullHistory: false, membershipAtBlock: true })
  await p.connect()
  const erased = await p.erasedMembers() // DocPage.tsx:110; a non-empty answer is what loads full history
  return { text: doc.getText("t").toString(), erased, flags: { auditNarrowed: p.auditNarrowed, auditUnchecked: p.auditUnchecked, listWalkCut: p.listWalkCut, listWalkIncomplete: p.listWalkIncomplete } }
}

describe("R18-E: 700 renewals and the gateway's read limit silence the app's erasure banner", () => {
  it("default view: Bea's paragraph is gone and nothing in the app says anyone was erased", async () => {
    const { chain, a, bea, owner, link } = await setup()
    await typeSlowly(chain, bea, [a], para)
    await erase(chain, a, bea)
    const aclKey = a.provider.aclKey!
    a.provider.destroy()
    bea.provider.destroy()
    await renewMany(chain, owner.address, aclKey, 700)
    const base = chain.store(undefined)
    const clean = await appOpen(base, link)
    // 600 reads by key a minute (friction.md); the whole open happens inside one minute
    let gets = 0
    const limited: ArkivStore = { ...base, get: async (k, b) => { if (++gets > 600) throw new Error("429 Too Many Requests"); return base.get(k, b) } }
    const rushed = await appOpen(limited, link)
    console.log(JSON.stringify({ clean: { erased: clean.erased.length, text: clean.text }, rushed: { erased: rushed.erased.length, text: rushed.text, ...rushed.flags, gets } }))
    // with no limit, the app names Bea and goes on to load her edits
    expect(clean.erased).toEqual([bea.id!.address])
    // under the limit the app should still name her, or set a flag DocPage shows outside full history:
    // listWalkIncomplete, which makes DocPage load every edit and say the check is incomplete
    expect(rushed.erased.length > 0 || rushed.flags.auditNarrowed || rushed.flags.listWalkCut || rushed.flags.listWalkIncomplete).toBe(true)
    expect(rushed.flags.listWalkIncomplete).toBe(true)
    expect(clean.flags.listWalkIncomplete).toBe(false)
  }, 300_000)
})
