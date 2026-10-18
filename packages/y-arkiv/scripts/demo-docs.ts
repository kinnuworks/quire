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

// sessions to nudge while waiting: the gateway rate-limits WebSocket handshakes per IP, so a fresh
// socket can miss events; a resync every few seconds catches up by query instead
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
  live.push(p)
  return { doc, p }
}

type Session = { doc: Y.Doc; p: ArkivProvider }
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** The XmlText inside paragraph `i` (0 is the heading). */
const textOf = (s: Session, i: number) => (s.doc.getXmlFragment("default").get(i) as Y.XmlElement).get(0) as Y.XmlText
const plain = (s: Session) => s.doc.getXmlFragment("default").toArray().map((x) => ((x as Y.XmlElement).get(0) as Y.XmlText)?.toString() ?? "").join("\n")

/** Types `words` into paragraph `i` a few words at a time, flushing each burst, the way a person writes. */
async function typeBursts(s: Session, i: number, words: string, perBurst = 3) {
  const parts = words.split(" ")
  for (let k = 0; k < parts.length; k += perBurst) {
    const t = textOf(s, i)
    t.insert(t.length, (t.length ? " " : "") + parts.slice(k, k + perBurst).join(" "))
    await s.p.flush()
    await pause(3500 + Math.random() * 3000)
  }
}

async function makeDoc(title: string, script: (s: Record<"Asha" | "Bea" | "Ravi", Session>) => Promise<void>, revoke: boolean) {
  live.length = 0
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
  await script(sessions)
  await pause(6000)
  await sessions.Asha.p.compact()
  if (revoke) {
    // the app's default: rotate, and delete the owner's own earlier entities so the old link cannot open them
    await sessions.Asha.p.revoke(ravi.address, { shredOldEpoch: true })
    para(sessions.Asha.doc, "")
    await typeBursts(sessions.Asha, sessions.Asha.doc.getXmlFragment("default").length - 1, "Written after Ravi was removed. The old link cannot read this line.")
    await pause(4000)
  }
  for (const s of Object.values(sessions)) s.p.destroy()
  return { link: `#${formatDocLink(link)}`, doc: link.doc, owner: owner.address, members: { Asha: owner.address, Bea: bea.address, Ravi: ravi.address }, revoked: revoke ? [ravi.address] : [] }
}

/** Waits until every session shows paragraph count `n`. */
const synced = (all: Session[], n: number) => until(() => all.every((x) => x.doc.getXmlFragment("default").length >= n), 90_000)

const open = await makeDoc(
  "Ward 14 water log (synthetic demo)",
  async ({ Asha, Bea, Ravi }) => {
    const all = [Asha, Bea, Ravi]
    para(Asha.doc, "")
    await typeBursts(Asha, 1, "The pump house was locked again on Tuesday. Water came on at 6:40 and stopped before 8.")
    await synced(all, 2)
    para(Bea.doc, "")
    await typeBursts(Bea, 2, "Residents counted four dry days this month. Two of them are missing from the official roster.")
    await synced(all, 3)
    await until(() => plain(Ravi).includes("before 8."), 90_000)
    // Ravi corrects Asha's sentence in place, so one paragraph has two authors
    const t = textOf(Ravi, 1)
    const at = t.toString().indexOf(" on Tuesday")
    t.insert(at, " (by the ward office)")
    await Ravi.p.flush()
    await pause(4000)
    para(Ravi.doc, "")
    await typeBursts(Ravi, 3, "Next: ask the ward office for the supply schedule in writing, and photograph the notice board.")
    await synced(all, 4)
    await until(() => plain(Bea).includes("notice board."), 90_000)
    // Bea tightens Ravi's line
    const r = textOf(Bea, 3)
    const w = r.toString().indexOf("photograph")
    r.insert(w, "date and ")
    await Bea.p.flush()
  },
  false,
)
const revoked = await makeDoc(
  "Source notes (synthetic demo)",
  async ({ Asha, Bea }) => {
    para(Asha.doc, "")
    await typeBursts(Asha, 1, "Background only. Nothing here is attributable.")
    await synced([Asha, Bea], 2)
    para(Bea.doc, "")
    await typeBursts(Bea, 2, "Second source confirms the dates. Ask about the procurement file.")
  },
  true,
)
const out = { createdAt: new Date().toISOString(), funder: funder.account.address.toLowerCase(), open, revoked }
writeFileSync(new URL("../../../arkiv/demo.json", import.meta.url), JSON.stringify(out, null, 2))
console.log(JSON.stringify(out, null, 2))
process.exit(0)
