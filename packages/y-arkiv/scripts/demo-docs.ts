/**
 * Creates the two public demo documents linked from the README, with
 * synthetic content and throwaway keys funded from QUIRE_DEV_PRIVATE_KEY.
 *
 *   open demo:        three members, readable by anyone holding the link
 *   revocation demo:  one member removed; the link alone sees only a member count
 *
 * Writes the links and addresses to arkiv/demo.json.
 */
import { writeFileSync } from "node:fs"
import { tiramisu } from "@arkiv-network/sdk/chains"
import { createWalletClient, http, parseEther } from "viem"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import * as Y from "yjs"
import { formatDocLink, newDocLink } from "../src/link.js"
import { ArkivProvider, type Identity } from "../src/provider.js"
import { SdkStore, TIRAMISU_HTTP } from "../src/sdk.js"
import type { Hex } from "../src/store.js"

const funder = createWalletClient({ chain: tiramisu, transport: http(TIRAMISU_HTTP), account: privateKeyToAccount(process.env.QUIRE_DEV_PRIVATE_KEY as Hex) })
const reader = new SdkStore({ accessKey: process.env.ARKIV_ACCESS_KEY }).reader

async function burner(name: string): Promise<Identity> {
  const privateKey = generatePrivateKey()
  const address = privateKeyToAccount(privateKey).address.toLowerCase() as Hex
  await reader.waitForTransactionReceipt({ hash: await funder.sendTransaction({ to: address, value: parseEther("0.05") }) })
  return { address, privateKey, name }
}

async function until(cond: () => boolean, ms = 60_000) {
  const end = Date.now() + ms
  while (!cond()) {
    if (Date.now() > end) throw new Error("timed out")
    await new Promise((r) => setTimeout(r, 300))
  }
}

function para(doc: Y.Doc, text: string, heading = false) {
  const el = new Y.XmlElement(heading ? "heading" : "paragraph")
  if (heading) el.setAttribute("level", "2" as never)
  el.insert(0, [new Y.XmlText(text)])
  doc.getXmlFragment("default").push([el])
}

async function session(id: Identity, link: ReturnType<typeof newDocLink>) {
  const doc = new Y.Doc()
  const p = new ArkivProvider(doc, { store: new SdkStore({ accessKey: process.env.ARKIV_ACCESS_KEY, privateKey: id.privateKey }), link, identity: id, flushIntervalMs: 0, autoCompact: false })
  await p.connect()
  return { doc, p }
}

async function makeDoc(title: string, lines: [string, string][], revoke: boolean) {
  const owner = await burner("Asha")
  const bea = await burner("Bea")
  const ravi = await burner("Ravi")
  const link = newDocLink(owner.address)
  await ArkivProvider.createDocument({ store: new SdkStore({ accessKey: process.env.ARKIV_ACCESS_KEY, privateKey: owner.privateKey }), link, identity: owner })
  const sessions = { Asha: await session(owner, link), Bea: await session(bea, link), Ravi: await session(ravi, link) }
  for (const who of [sessions.Bea, sessions.Ravi]) {
    await who.p.requestJoin()
    await until(() => sessions.Asha.p.joinRequests.some((j) => j.address === who.p.identity!.address))
    await sessions.Asha.p.approve(who.p.identity!.address)
    await until(() => who.p.role === "writer")
  }
  para(sessions.Asha.doc, title, true)
  await sessions.Asha.p.flush()
  for (const [who, text] of lines) {
    const s = sessions[who as keyof typeof sessions]
    await until(() => s.doc.getXmlFragment("default").length >= 1)
    para(s.doc, text)
    await s.p.flush()
    await new Promise((r) => setTimeout(r, 3000))
  }
  await sessions.Asha.p.compact()
  if (revoke) {
    await sessions.Asha.p.revoke(ravi.address)
    para(sessions.Asha.doc, "Written after Ravi was removed. The old link cannot read this line.")
    await sessions.Asha.p.flush()
  }
  for (const s of Object.values(sessions)) s.p.destroy()
  return { link: `#${formatDocLink(link)}`, doc: link.doc, owner: owner.address, members: { Asha: owner.address, Bea: bea.address, Ravi: ravi.address }, revoked: revoke ? [ravi.address] : [] }
}

const open = await makeDoc(
  "Ward 14 water log (synthetic demo)",
  [
    ["Asha", "The pump house was locked again on Tuesday. Water came on at 6:40 and stopped before 8."],
    ["Bea", "Residents counted four dry days this month. Two of them are missing from the official roster."],
    ["Ravi", "Next: ask the ward office for the supply schedule in writing, and photograph the notice board."],
  ],
  false,
)
const revoked = await makeDoc(
  "Source notes (synthetic demo)",
  [
    ["Asha", "Background only. Nothing here is attributable."],
    ["Bea", "Second source confirms the dates. Ask about the procurement file."],
  ],
  true,
)
const out = { createdAt: new Date().toISOString(), funder: funder.account.address.toLowerCase(), open, revoked }
writeFileSync(new URL("../../../arkiv/demo.json", import.meta.url), JSON.stringify(out, null, 2))
console.log(JSON.stringify(out, null, 2))
process.exit(0)
