/**
 * Measures what Quire's writes cost on Tiramisu: a fresh key, funded with 0.02 test GLM by
 * QUIRE_DEV_PRIVATE_KEY, creates a document, writes five edits and one snapshot. Each step's fee is
 * the drop in the key's balance. Writes arkiv/probes/cost-<date>.json.
 *
 *   QUIRE_DEV_PRIVATE_KEY=0x… [ARKIV_ACCESS_KEY=…] npx tsx scripts/cost-probe.ts
 */
import { writeFileSync } from "node:fs"
import { tiramisu } from "@arkiv-network/sdk/chains"
import { createPublicClient, createWalletClient, formatEther, http, parseEther } from "viem"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import * as Y from "yjs"
import { ArkivProvider, newDocLink, prepareDoc, SdkStore, TIRAMISU_HTTP } from "../src/index.js"

const funderKey = process.env.QUIRE_DEV_PRIVATE_KEY as `0x${string}` | undefined
if (!funderKey) throw new Error("set QUIRE_DEV_PRIVATE_KEY to a funded Tiramisu key")
const funder = createWalletClient({ chain: tiramisu, transport: http(TIRAMISU_HTTP), account: privateKeyToAccount(funderKey) })
const reader = createPublicClient({ chain: tiramisu, transport: http(TIRAMISU_HTTP) })

const key = generatePrivateKey()
const me = { address: privateKeyToAccount(key).address.toLowerCase() as `0x${string}`, privateKey: key, name: "cost probe" }
await reader.waitForTransactionReceipt({ hash: await funder.sendTransaction({ to: me.address, value: parseEther("0.02") }) })
const start = await reader.getBalance({ address: me.address })
let spentBefore = 0n
const fee = async () => {
  const spent = start - (await reader.getBalance({ address: me.address }))
  const step = spent - spentBefore
  spentBefore = spent
  return step
}

const store = new SdkStore({ privateKey: key, accessKey: process.env.ARKIV_ACCESS_KEY })
const link = newDocLink(me.address)
await ArkivProvider.createDocument({ store, link, identity: me })
const create = await fee()
const doc = new Y.Doc()
const salt = prepareDoc(doc, me.address)
const p = new ArkivProvider(doc, { store, link, identity: me, salt, flushIntervalMs: 0, autoCompact: false })
await p.connect()
const updates: bigint[] = []
for (let i = 0; i < 5; i++) {
  doc.getText("t").insert(doc.getText("t").length, "a typical burst of typing, about forty chars. ")
  await p.flush()
  updates.push(await fee())
}
await p.compact()
const snapshot = await fee()
const gasPrice = await reader.getGasPrice()

const out = {
  probe: "cost per write on Tiramisu, measured as the balance a fresh key spent (scripts/cost-probe.ts)",
  method: "a key funded with 0.02 GLM creates a document, writes five updates of about 47 characters each, then one snapshot; the fee for each step is the drop in its balance",
  measuredAt: new Date().toISOString(),
  gasPriceGwei: Number(gasPrice) / 1e9,
  GLM: { createDocument: formatEther(create), update: formatEther(updates[0]!), snapshot: formatEther(snapshot) },
  updatesMeasured: updates.map((u) => formatEther(u)),
  note: "each update is one entity in one of six padded sizes, so the fee does not depend on how much was typed",
}
const file = new URL(`../../../arkiv/probes/cost-${out.measuredAt.slice(0, 10)}.json`, import.meta.url)
writeFileSync(file, `${JSON.stringify(out, null, 2)}\n`)
console.log(JSON.stringify(out.GLM))
p.destroy()
process.exit(0)
