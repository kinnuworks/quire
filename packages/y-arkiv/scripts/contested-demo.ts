/**
 * Creates the contested-authorship demo linked from the README: two co-authors, a disputed passage,
 * and an owner who tries to take it. Synthetic content; throwaway keys funded from QUIRE_DEV_PRIVATE_KEY.
 *
 *   1. Asha (owner) and Bea co-write a short proposal. Bea writes the key finding, a few words at a time.
 *   2. Asha erases Bea from the member list: no trace that she was ever a member.
 *   3. Asha deletes Bea's passage and pastes the same words back as one edit of her own.
 *
 * Today the passage reads as Asha's. The chain still shows who wrote it first: `y-arkiv timeline`
 * lists Bea's edits minutes before Asha's single paste, and `y-arkiv blame --at <block>` proves Bea
 * wrote it while she was a member, checked against the member list as it stood then.
 *
 * Adds the link, addresses and blocks to arkiv/demo.json as `contested`.
 */
import { readFileSync, writeFileSync } from "node:fs"
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

// the gateway caps WebSocket connections per IP, so a session can miss events; resync by query meanwhile
const live: ArkivProvider[] = []
async function until(cond: () => boolean, ms = 120_000) {
  const end = Date.now() + ms
  let last = Date.now()
  while (!cond()) {
    if (Date.now() > end) throw new Error("timed out")
    if (Date.now() - last > 5000) {
      last = Date.now()
      await Promise.all(live.map((p) => p.resync({ joins: true }).catch(() => 0)))
    }
    await new Promise((r) => setTimeout(r, 300))
  }
}
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms))

function para(doc: Y.Doc, text: string, heading = false) {
  const el = new Y.XmlElement(heading ? "heading" : "paragraph")
  if (heading) el.setAttribute("level", "2" as never)
  el.insert(0, [new Y.XmlText(text)])
  doc.getXmlFragment("default").push([el])
}

type Session = { doc: Y.Doc; p: ArkivProvider }
async function session(id: Identity, link: ReturnType<typeof newDocLink>): Promise<Session> {
  const doc = new Y.Doc()
  const p = new ArkivProvider(doc, { store: new SdkStore({ accessKey: process.env.ARKIV_ACCESS_KEY, privateKey: id.privateKey }), link, identity: id, flushIntervalMs: 0, autoCompact: false })
  await p.connect()
  live.push(p)
  return { doc, p }
}
const textOf = (s: Session, i: number) => (s.doc.getXmlFragment("default").get(i) as Y.XmlElement).get(0) as Y.XmlText
const paragraphs = (s: Session) => s.doc.getXmlFragment("default").length

async function typeBursts(s: Session, i: number, words: string, perBurst = 3) {
  const parts = words.split(" ")
  for (let k = 0; k < parts.length; k += perBurst) {
    const t = textOf(s, i)
    t.insert(t.length, (t.length ? " " : "") + parts.slice(k, k + perBurst).join(" "))
    await s.p.flush()
    await pause(3500 + Math.random() * 3000)
  }
}

const ashaId = await burner("Asha")
const beaId = await burner("Bea")
const link = newDocLink(ashaId.address)
await ArkivProvider.createDocument({ store: new SdkStore({ accessKey: process.env.ARKIV_ACCESS_KEY, privateKey: ashaId.privateKey }), link, identity: ashaId })
const asha = await session(ashaId, link)
const bea = await session(beaId, link)
await bea.p.requestJoin()
// look the request up directly by its creator: with the socket refused, events can be missed
for (let tries = 0; !(await asha.p.findJoinRequest(beaId.address as Hex)); tries++) {
  if (tries > 40) throw new Error("the join request never arrived")
  await pause(3000)
}
await asha.p.approve(beaId.address)
await until(() => bea.p.role === "writer")

para(asha.doc, "Water access study, section 3 (synthetic demo)", true)
await asha.p.flush()
para(asha.doc, "")
await typeBursts(asha, 1, "We surveyed forty households in Ward 14 over thirty days, twice a day.")
await until(() => paragraphs(bea) >= 2)
const finding = "Key finding: taps ran dry on eleven of thirty days, three times the figure in the city's own report."
para(bea.doc, "")
const beaStarted = await reader.getBlockNumber()
await typeBursts(bea, 2, finding)
const beaFinished = await reader.getBlockNumber()
await until(() => paragraphs(asha) >= 3 && textOf(asha, 2).toString() === finding)
para(asha.doc, "")
await typeBursts(asha, 3, "We recommend the city publish its supply log every week.")
await pause(6000)
await asha.p.compact()

// the dispute: Asha erases Bea from the member list, then takes her passage
await (asha.p as unknown as { updateAcl: (f: (acl: { members: { address: string }[]; revoked: unknown[] }) => Promise<object>) => Promise<void> }).updateAcl(async (acl) => {
  acl.members = acl.members.filter((m) => m.address !== beaId.address)
  acl.revoked = []
  return {}
})
await pause(4000)
const t = textOf(asha, 2)
const words = t.toString()
t.delete(0, t.length)
t.insert(0, words)
const pasted = await asha.p.flush()
await pause(6000)
await asha.p.compact()
for (const p of live) p.destroy()

const path = new URL("../../../arkiv/demo.json", import.meta.url)
const demo = JSON.parse(readFileSync(path, "utf8"))
demo.contested = {
  link: `#${formatDocLink(link)}`,
  doc: link.doc,
  owner: ashaId.address,
  members: { Asha: ashaId.address, Bea: beaId.address },
  beaWroteBetween: [beaStarted.toString(), beaFinished.toString()],
  ashaPastedAt: pasted?.block.toString(),
  createdAt: new Date().toISOString(),
}
writeFileSync(path, JSON.stringify(demo, null, 2))
console.log(JSON.stringify(demo.contested, null, 2))
process.exit(0)
