/**
 * y-arkiv from the outside: everything below uses only the package's public API.
 *
 * Asha creates a document, Bea asks to join and is added, both type at once,
 * a reader with only the link follows along, Asha removes Bea (the key rotates),
 * and `blame` attributes every character to the key that wrote it.
 *
 *   pnpm start          on MemoryChain, an in-memory Arkiv (no network, no gas)
 *   QUIRE_KEY=0x… pnpm live
 *                       on Tiramisu; QUIRE_KEY is a funded key that pays a little
 *                       test GLM to two fresh keys made for this run
 */
import { tiramisu } from "@arkiv-network/sdk/chains"
import { createPublicClient, createWalletClient, http, parseEther } from "viem"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import * as Y from "yjs"
import { type ArkivStore, ArkivProvider, blame, type DocLink, type Hex, type Identity, MemoryChain, newDocLink, prepareDoc, SdkStore, TIRAMISU_HTTP } from "y-arkiv"

const live = process.argv.includes("--live")
const chain = live ? null : new MemoryChain()

function person(name: string): Identity {
  const privateKey = generatePrivateKey()
  return { address: privateKeyToAccount(privateKey).address.toLowerCase() as Hex, privateKey, name }
}
const storeFor = (who?: Identity): ArkivStore => (chain ? chain.store(who?.address) : new SdkStore(who ? { privateKey: who.privateKey } : {}))

/** Lets the chain move on: one block in memory, or a few seconds on Tiramisu. */
async function tick(...providers: ArkivProvider[]) {
  if (chain) chain.mine()
  else await new Promise((r) => setTimeout(r, 4000))
  for (let i = 0; i < 3; i++) await Promise.all(providers.map((p) => p.idle()))
}

async function open(link: DocLink, who?: Identity, extra: { fullHistory?: boolean } = {}) {
  const doc = new Y.Doc()
  const salt = who ? prepareDoc(doc, who.address) : undefined
  const provider = new ArkivProvider(doc, { store: storeFor(who), link, identity: who, salt, flushIntervalMs: 0, autoCompact: false, ...extra })
  await provider.connect()
  return { doc, provider, text: () => doc.getText("t").toString() }
}

const asha = person("Asha")
const bea = person("Bea")

if (live) {
  const key = process.env.QUIRE_KEY as Hex | undefined
  if (!key) throw new Error("set QUIRE_KEY to a funded Tiramisu key")
  const wallet = createWalletClient({ chain: tiramisu, transport: http(TIRAMISU_HTTP), account: privateKeyToAccount(key) })
  const reader = createPublicClient({ chain: tiramisu, transport: http(TIRAMISU_HTTP) })
  for (const p of [asha, bea]) await reader.waitForTransactionReceipt({ hash: await wallet.sendTransaction({ to: p.address, value: parseEther("0.02") }) })
}

// 1. Asha creates the document: the member list and a first snapshot, in one transaction
const link = newDocLink(asha.address)
await ArkivProvider.createDocument({ store: storeFor(asha), link, identity: asha })
await tick()
const a = await open(link, asha)
console.log(`created ${link.doc} (${live ? "Tiramisu" : "MemoryChain"})`)

// 2. Bea opens the link, asks to join (sealed to Asha's key), and Asha adds her
const b = await open(link, bea)
await b.provider.requestJoin()
await tick(a.provider, b.provider)
await a.provider.approve(bea.address)
await tick(a.provider, b.provider)
console.log(`Bea is now a ${b.provider.role}`)

// 3. Both type at the same moment; Yjs merges, Arkiv carries the encrypted edits
a.doc.getText("t").insert(0, "Asha writes the opening. ")
b.doc.getText("t").insert(0, "Bea adds a line. ")
await Promise.all([a.provider.flush(), b.provider.flush()])
await tick(a.provider, b.provider)
console.log(`Asha sees: ${JSON.stringify(a.text())}`)
console.log(`Bea sees:  ${JSON.stringify(b.text())}`)

// 4. Someone with only the link reads it straight from the chain, in three queries
const reader = await open(link)
console.log(`a link holder reads: ${JSON.stringify(reader.text())} (${reader.provider.stats.queries} queries)`)

// 5. Asha removes Bea: the key rotates and the roster is sealed under it
await a.provider.revoke(bea.address)
await tick(a.provider, b.provider, reader.provider)
a.doc.getText("t").insert(a.text().length, "Written after Bea left.")
await a.provider.flush()
await tick(a.provider, b.provider, reader.provider)
console.log(`epoch ${a.provider.acl!.epoch}; Bea still sees ${JSON.stringify(b.text())}`)

// 6. Blame, from a fresh reader that reads every edit still on chain
const auditor = await open(link, asha, { fullHistory: true })
const names = new Map([[asha.address, "Asha"], [bea.address, "Bea"]])
for (const run of blame(auditor.doc, auditor.provider).flat()) {
  console.log(`  ${names.get(run.address ?? "") ?? run.address}  ${run.proven ? `proven by ${run.entity!.slice(0, 10)}… at block ${run.block}` : "claimed"}  ${JSON.stringify(run.text)}`)
}

for (const p of [a, b, reader, auditor]) p.provider.destroy()
process.exit(0)
