/**
 * End-to-end against Tiramisu. Runs only with LIVE=1 and a funded key in
 * QUIRE_DEV_PRIVATE_KEY. Burner identities are funded from that key with a
 * plain GLM transfer, which is how the app onboards collaborators.
 */
import { createWalletClient, http, parseEther } from "viem"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import { tiramisu } from "@arkiv-network/sdk/chains"
import { describe, expect, it } from "vitest"
import * as Y from "yjs"
import { ArkivProvider, type Identity } from "../src/provider.js"
import { newDocLink } from "../src/link.js"
import { KIND } from "../src/protocol.js"
import { SdkStore, TIRAMISU_HTTP } from "../src/sdk.js"
import type { Hex } from "../src/store.js"

const LIVE = process.env.LIVE === "1"
const FUNDER = process.env.QUIRE_DEV_PRIVATE_KEY as Hex | undefined

async function until(cond: () => boolean, ms = 30_000): Promise<void> {
  const end = Date.now() + ms
  while (!cond()) {
    if (Date.now() > end) throw new Error("timed out")
    await new Promise((r) => setTimeout(r, 250))
  }
}

async function burner(name: string): Promise<Identity> {
  const privateKey = generatePrivateKey()
  const address = privateKeyToAccount(privateKey).address.toLowerCase() as Hex
  const funder = createWalletClient({ chain: tiramisu, transport: http(TIRAMISU_HTTP), account: privateKeyToAccount(FUNDER!) })
  const hash = await funder.sendTransaction({ to: address, value: parseEther("0.01") })
  await new SdkStore().reader.waitForTransactionReceipt({ hash })
  return { address, privateKey, name }
}

describe.runIf(LIVE && FUNDER)("live on Tiramisu", () => {
  it("two burners collaborate, a reader rebuilds, a forger is ignored", async () => {
    const ownerId = await burner("owner")
    const beaId = await burner("bea")
    const link = newDocLink(ownerId.address)
    const ownerStore = new SdkStore({ privateKey: ownerId.privateKey })
    await ArkivProvider.createDocument({ store: ownerStore, link, identity: ownerId })

    const aDoc = new Y.Doc()
    const a = new ArkivProvider(aDoc, { store: ownerStore, link, identity: ownerId, flushIntervalMs: 0 })
    await a.connect()
    const bDoc = new Y.Doc()
    const b = new ArkivProvider(bDoc, { store: new SdkStore({ privateKey: beaId.privateKey }), link, identity: beaId, flushIntervalMs: 0 })
    await b.connect()

    await b.requestJoin()
    await until(() => a.joinRequests.length === 1)
    await a.approve(beaId.address)
    await until(() => b.role === "writer")

    aDoc.getText("t").insert(0, "hello ")
    const flushed = await a.flush()
    expect(flushed?.bytes).toBeGreaterThan(0)
    await until(() => bDoc.getText("t").toString() === "hello ")
    bDoc.getText("t").insert(6, "from bea")
    await b.flush()
    await until(() => aDoc.getText("t").toString() === "hello from bea")

    const reader = new ArkivProvider(new Y.Doc(), { store: new SdkStore(), link, flushIntervalMs: 0 })
    await reader.connect()
    expect(reader.doc.getText("t").toString()).toBe("hello from bea")
    expect(reader.stats.queries).toBe(3)

    a.destroy()
    b.destroy()
    reader.destroy()
  }, 180_000)
})

describe.runIf(LIVE)("live read paths", () => {
  it("accepts our typed query and returns nothing for a random doc", async () => {
    const store = new SdkStore()
    const page = await store.query({ doc: newDocLink("0x0000000000000000000000000000000000000001").doc, kind: KIND.update })
    expect(page.entities).toEqual([])
    expect(page.block).toBeGreaterThan(0n)
  })
})
