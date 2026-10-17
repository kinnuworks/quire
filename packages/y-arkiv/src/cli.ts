#!/usr/bin/env node
/**
 * quire: read, watch and verify a Quire document from a terminal, straight
 * from Arkiv. Needs only the document link; never writes.
 *
 *   quire read   '<link>'          print the document text
 *   quire watch  '<link>'          print each edit as it lands
 *   quire verify '<link>'          show members, lease, and writes that were ignored
 *   quire blame  '<link>'          who wrote each piece of text, with the entity and block that prove it
 *   quire extend '<version link>'  keep a published version alive (needs QUIRE_KEY, a funded key)
 *   quire check-signature <address> '<message>' <signature>
 *                                  check a "Prove this key is yours" signature from the app
 *
 *   --rpc <url> --ws <url>         use your own Arkiv node instead of the public endpoint
 *   ARKIV_ACCESS_KEY=…             raise the public endpoint's query budget
 */
import { verifyMessage } from "viem"
import * as Y from "yjs"
import { blame } from "./blame.js"
import { ArkivProvider, extendVersion } from "./provider.js"
import { parseDocLink, parseVersionLink } from "./link.js"
import { SdkStore } from "./sdk.js"

function text(doc: Y.Doc): string {
  const walk = (n: unknown): string => {
    if (n instanceof Y.XmlText) return (n.toDelta() as { insert: unknown }[]).map((d) => (typeof d.insert === "string" ? d.insert : "")).join("")
    if (n instanceof Y.XmlElement) return n.toArray().map(walk).join("")
    return ""
  }
  const blocks = doc.getXmlFragment("default").toArray().map(walk)
  const plain = doc.getText("t").toString()
  return [...blocks, plain].filter(Boolean).join("\n")
}

function fail(msg: string): never {
  console.error(msg)
  process.exit(1)
}

async function main() {
  const args = process.argv.slice(2)
  const flag = (name: string) => {
    const i = args.indexOf(name)
    if (i < 0) return undefined
    const v = args[i + 1]
    args.splice(i, 2)
    return v
  }
  const httpUrl = flag("--rpc")
  const wsUrl = flag("--ws")
  // half a custom node would still send document ids to the public WebSocket endpoint
  if (!!httpUrl !== !!wsUrl) fail("pass --rpc and --ws together, so every request goes to the node you chose")
  const [cmd, raw] = args
  if (!cmd || !raw) fail("usage: quire <read|watch|verify|blame|extend|check-signature> '<link>' [--rpc url --ws url]")
  if (cmd === "check-signature") {
    const [, address, message, signature] = args
    if (!address || !message || !signature) fail("usage: quire check-signature <address> '<message>' <signature>")
    if (!message.startsWith("quire1:prove:")) fail("not a Quire proof: the message must start with quire1:prove:")
    const ok = await verifyMessage({ address: address as `0x${string}`, message, signature: signature as `0x${string}` }).catch(() => false)
    console.log(ok ? `valid: ${address} signed this message` : "INVALID: that address did not sign this message")
    process.exit(ok ? 0 : 1)
  }
  const fragment = raw.includes("#") ? raw.slice(raw.indexOf("#")) : raw
  if (cmd === "extend") {
    const version = parseVersionLink(fragment)
    if (!version) fail("that is not a Quire version link")
    const key = process.env.QUIRE_KEY as `0x${string}` | undefined
    if (!key) fail("set QUIRE_KEY to a funded Tiramisu key; any key works, versions allow anyone to extend them")
    const until = await extendVersion(new SdkStore({ privateKey: key, httpUrl, wsUrl, accessKey: process.env.ARKIV_ACCESS_KEY }), version, 3 * 365 * 86400)
    console.log(`version ${version.key} now lives until block ${until}`)
    process.exit(0)
  }
  const link = parseDocLink(fragment)
  if (!link) fail("that is not a Quire document link")
  const store = new SdkStore({ httpUrl, wsUrl, accessKey: process.env.ARKIV_ACCESS_KEY })
  const doc = new Y.Doc()
  // blame reads every update still on chain, not only those after the newest snapshot
  const provider = new ArkivProvider(doc, { store, link, flushIntervalMs: 0, autoCompact: false, fullHistory: cmd === "blame" })
  await provider.connect()

  if (cmd === "read") {
    console.log(text(doc))
    process.exit(0)
  }
  if (cmd === "verify") {
    const acl = provider.acl!
    const head = await store.head()
    console.log(`document   ${link.doc}`)
    console.log(`owner      ${acl.owner} (ACL entity ${provider.aclKey}, found by $creator)`)
    console.log(`epoch      ${acl.epoch}${provider.canRead ? "" : " (this link cannot read the current epoch)"}`)
    if (acl.rosterHidden) console.log(`members    sealed under epoch ${acl.epoch}; this link sees only a count (${acl.wraps.length})`)
    for (const m of acl.members) console.log(`member     ${m.address}  ${m.role}`)
    for (const r of acl.revoked) console.log(`removed    ${r.address}  at block ${r.atBlock}`)
    if (acl.keepUntil) console.log(`keep until block ${acl.keepUntil}`)
    if (provider.snapshot) {
      const left = Number(provider.snapshot.expiresAt - head) * 2
      console.log(`snapshot   ${provider.snapshot.key}, lease ${(left / 86400).toFixed(1)} days left, ${provider.snapshot.chunks.length} chunks`)
    }
    console.log(`applied    ${provider.stats.snapshotsApplied} snapshots, ${provider.stats.updatesApplied} updates`)
    console.log(`ignored    ${provider.stats.rejectedWrites} entities (outside the member list, or writing under another member's client id)`)
    console.log(`cost       ${store.calls.query} queries, ${store.calls.getEntity} entity reads`)
    // the load above asks only for members' entities; one more query lists everyone else's
    if (!acl.rosterHidden) {
      const outsiders = await provider.scanOutsiders()
      const by = [...new Set(outsiders)]
      const n = (k: number, one: string, many: string) => `${k} ${k === 1 ? one : many}`
      console.log(`outside    ${n(outsiders.length, "entity", "entities")} by ${n(by.length, "non-member", "non-members")}, never fetched or applied${by.length ? `: ${by.join(", ")}` : ""} (1 more query)`)
    }
    process.exit(0)
  }
  if (cmd === "blame") {
    if (provider.acl?.rosterHidden) fail("the roster is sealed under a newer key; this link cannot attribute anything")
    const short = (a: string | null | undefined) => (a ? `${a.slice(0, 8)}…${a.slice(-4)}` : "unknown")
    const total = new Map<string, { proven: number; claimed: number }>()
    blame(doc, provider).forEach((runs, i) => {
      console.log(`paragraph ${i + 1}`)
      for (const r of runs) {
        const t = total.get(r.address ?? "unknown") ?? { proven: 0, claimed: 0 }
        if (r.proven) t.proven += r.text.length
        else t.claimed += r.text.length
        total.set(r.address ?? "unknown", t)
        const where = r.proven ? `proven   block ${r.block} entity ${short(r.entity)}` : `claimed  carried in a snapshot by ${short(r.via)}`
        console.log(`  ${short(r.address)}  ${where}  ${JSON.stringify(r.text)}`)
      }
    })
    console.log("")
    for (const [a, t] of total) console.log(`${a}  ${t.proven} characters proven, ${t.claimed} claimed`)
    console.log(`cost       ${store.calls.query} queries, ${store.calls.getEntity} entity reads`)
    process.exit(0)
  }
  if (cmd === "watch") {
    console.log(text(doc))
    console.log("--- watching for edits (ctrl-c to stop)")
    provider.on("remote-edit", (e: { author: string; block: bigint; latencyMs?: number }) => {
      console.log(`--- block ${e.block} by ${e.author}${e.latencyMs !== undefined ? `, ${(e.latencyMs / 1000).toFixed(1)}s after it was written` : ""}`)
      console.log(text(doc))
    })
    return
  }
  fail(`unknown command ${cmd}`)
}

main().catch((e: Error) => fail(e.message))
