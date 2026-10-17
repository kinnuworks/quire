#!/usr/bin/env node
/**
 * quire: read, watch and verify a Quire document from a terminal, straight
 * from Arkiv. Needs only the document link; never writes.
 *
 *   quire read   '<link>'      print the document text
 *   quire watch  '<link>'      print each edit as it lands
 *   quire verify '<link>'      show members, lease, and writes that were ignored
 */
import * as Y from "yjs"
import { ArkivProvider } from "./provider.js"
import { parseDocLink } from "./link.js"
import { SdkStore } from "./sdk.js"

function text(doc: Y.Doc): string {
  const walk = (n: unknown): string => {
    if (n instanceof Y.XmlText) return n.toString().replace(/<[^>]+>/g, "")
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
  const [cmd, raw] = process.argv.slice(2)
  if (!cmd || !raw) fail("usage: quire <read|watch|verify> '<document link>'")
  const link = parseDocLink(raw.includes("#") ? raw.slice(raw.indexOf("#")) : raw)
  if (!link) fail("that is not a Quire document link")
  const store = new SdkStore()
  const doc = new Y.Doc()
  const provider = new ArkivProvider(doc, { store, link, flushIntervalMs: 0, autoCompact: false })
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
