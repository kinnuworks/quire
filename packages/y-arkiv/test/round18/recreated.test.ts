import { describe, expect, it } from "vitest"
import * as Y from "yjs"
import { ArkivProvider } from "../../src/provider.js"
import { peer, settle } from "../helpers.js"
import { setup, typeSlowly } from "../round17/common.js"

describe("R18-D: a recreated member list hides the erased writer from the app", () => {
  it("the owner deletes the list and makes a new one without Bea: erasedMembers() and every app signal stay silent", async () => {
    const { chain, a, bea, owner, link } = await setup()
    await typeSlowly(chain, bea, [a], "Bea's whole chapter on ward fourteen, typed over an afternoon.")
    await a.provider.deleteDocument()
    await settle(chain, [a, bea])
    a.provider.destroy()
    bea.provider.destroy()
    await ArkivProvider.createDocument({ store: chain.store(owner.address), link, identity: owner })
    chain.mine()
    const a2 = await peer(chain, link, owner)
    a2.doc.getText("t").insert(0, "Asha's chapter on ward fourteen.")
    await a2.provider.flush()
    chain.mine()
    a2.provider.destroy()
    // the app's session: fullHistory, membershipAtBlock, as useDocument.ts:95 opens it
    const doc = new Y.Doc()
    const app = new ArkivProvider(doc, { store: chain.store(undefined), link, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0, readOnly: true, fullHistory: true, membershipAtBlock: true })
    await app.connect()
    const older = await app.predatingEntities()
    const signals = {
      text: doc.getText("t").toString(),
      erasedMembers: await app.erasedMembers(),
      auditNarrowed: app.auditNarrowed,
      auditUnchecked: app.auditUnchecked,
      listWalkCut: app.listWalkCut,
      predatingWriters: [...new Set(older.map((e) => (e.creator === bea.id!.address ? "bea" : e.creator)))],
    }
    console.log(JSON.stringify(signals))
    // the CLI's verify/blame print "recreated" from predatingEntities, and the app now reads it on open and
    // shows a banner naming the writers (DocPage). erasedMembers() walks only the new list's history, so it
    // cannot name Bea; the older entities are the signal, and they cannot be pushed out of view
    expect(signals.predatingWriters).toContain("bea")
    expect(signals.erasedMembers).toEqual([])
    expect(app.aclCreatedAt).toBeGreaterThan(0n)
    expect(app.predatingTruncated).toBe(false)
    app.destroy()
  })
})
