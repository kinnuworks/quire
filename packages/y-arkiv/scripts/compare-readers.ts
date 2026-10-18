/**
 * Runs the TypeScript reader and the Python reader (readers/python, written
 * as a second implementation of PROTOCOL.md) on the same documents and diffs
 * their verdicts: the text, the entities applied, and the outside writes
 * rejected. Cases: both live demo documents on Tiramisu (arkiv/demo.json), read
 * normally and (the open one) as an audit that checks membership at each edit's block, the
 * conformance vectors as a member and as a link holder, and every edge case in
 * spec/vectors/cases.
 *
 *   PYTHON=<python with readers/python/requirements.txt> npx tsx scripts/compare-readers.ts [--offline]
 *
 * --offline skips the live demos. ARKIV_ACCESS_KEY, if set, is used by both
 * readers. Exits 1 if any case disagrees.
 */
import { execFileSync } from "node:child_process"
import { readdirSync, readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { privateKeyToAccount } from "viem/accounts"
import * as Y from "yjs"
import { blame } from "../src/blame.js"
import { parseDocLink } from "../src/link.js"
import { ArkivProvider } from "../src/provider.js"
import { SdkStore } from "../src/sdk.js"
import type { ArkivStore, Hex } from "../src/store.js"
import { vectorStore } from "../src/vectors.js"

const root = fileURLToPath(new URL("../../../", import.meta.url))
const python = process.env.PYTHON ?? "python3"
const offline = process.argv.includes("--offline")
const demo = JSON.parse(readFileSync(`${root}arkiv/demo.json`, "utf8"))
const vectorsPath = `${root}spec/vectors/document.json`
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"))

type Verdict = { text: string; applied: string[]; outsiders: string[]; proven: Record<string, number> }

function plain(doc: Y.Doc): string {
  const walk = (n: unknown): string =>
    n instanceof Y.XmlText
      ? (n.toDelta() as { insert: unknown }[]).map((d) => (typeof d.insert === "string" ? d.insert : "")).join("")
      : n instanceof Y.XmlElement
        ? n.toArray().map(walk).join("")
        : ""
  return doc.getXmlFragment("default").toArray().map(walk).join("\n")
}

async function typescript(store: ArkivStore, link: string, memberKey?: Hex, audit = false): Promise<Verdict> {
  const doc = new Y.Doc()
  const identity = memberKey ? { address: privateKeyToAccount(memberKey).address.toLowerCase() as Hex, privateKey: memberKey, name: "member" } : undefined
  const p = new ArkivProvider(doc, { store, link: parseDocLink(link)!, identity, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0, fullHistory: audit })
  p.on("error", () => undefined) // a member session may try to renew a lease on a read-only store
  await p.connect()
  const outsiders = (await p.outsiderEntities()).map((e) => e.key)
  // characters proven per address, from blame: who wrote what, as each reader would testify
  const proven: Record<string, number> = {}
  for (const run of blame(doc, p).flat()) if (run.proven && run.address) proven[run.address] = (proven[run.address] ?? 0) + run.text.length
  p.destroy()
  return { text: plain(doc), applied: [...p.appliedKeys].sort(), outsiders: outsiders.sort(), proven: Object.fromEntries(Object.entries(proven).sort()) }
}

function pythonReader(args: string[]): Verdict {
  const out = execFileSync(python, [`${root}readers/python/quire_read.py`, "--json", ...args], { encoding: "utf8", env: process.env })
  const v = JSON.parse(out) as { text: string; applied: string[]; ignored: [string, string][]; proven: Record<string, number> }
  return { text: v.text, applied: v.applied.sort(), outsiders: v.ignored.filter(([, r]) => r === "creator not in ACL").map(([k]) => k).sort(), proven: v.proven }
}

const cases: { name: string; ts: () => Promise<Verdict>; py: () => Verdict }[] = [
  { name: "vectors, member (Bea)", ts: () => typescript(vectorStore(vectors), vectors.link, vectors.privateKeys.bea), py: () => pythonReader(["--vectors", vectorsPath, "--member-key", vectors.privateKeys.bea]) },
  { name: "vectors, link holder", ts: () => typescript(vectorStore(vectors), vectors.link), py: () => pythonReader(["--vectors", vectorsPath]) },
]
// each edge case: one crafted member entity, read with the link alone
const casesDir = `${root}spec/vectors/cases/`
for (const f of readdirSync(casesDir).filter((x) => x.endsWith(".json")).sort()) {
  const c = JSON.parse(readFileSync(casesDir + f, "utf8"))
  const member = c.memberKey ? ["--member-key", c.memberKey] : []
  cases.push({ name: `case ${f.replace(/\.json$/, "")}`, ts: () => typescript(vectorStore(c), c.link, c.memberKey), py: () => pythonReader(["--vectors", casesDir + f, ...member]) })
}
if (!offline) {
  const live = () => new SdkStore({ accessKey: process.env.ARKIV_ACCESS_KEY })
  cases.push(
    { name: "live open demo", ts: () => typescript(live(), demo.open.link), py: () => pythonReader(["--link", demo.open.link]) },
    { name: "live revocation demo", ts: () => typescript(live(), demo.revoked.link), py: () => pythonReader(["--link", demo.revoked.link]) },
    // the audit: every update, each author checked against the member list as it stood at that edit's block
    { name: "live open demo, audit", ts: () => typescript(live(), demo.open.link, undefined, true), py: () => pythonReader(["--link", demo.open.link, "--audit"]) },
  )
}

let failed = 0
for (const c of cases) {
  const [ts, py] = [await c.ts(), c.py()]
  const diffs: string[] = []
  if (ts.text !== py.text) diffs.push(`text\n    ts: ${JSON.stringify(ts.text)}\n    py: ${JSON.stringify(py.text)}`)
  if (JSON.stringify(ts.proven) !== JSON.stringify(py.proven)) diffs.push(`proven characters per address\n    ts: ${JSON.stringify(ts.proven)}\n    py: ${JSON.stringify(py.proven)}`)
  for (const field of ["applied", "outsiders"] as const) {
    const only = (a: string[], b: string[]) => a.filter((k) => !b.includes(k))
    const tsOnly = only(ts[field], py[field])
    const pyOnly = only(py[field], ts[field])
    if (tsOnly.length || pyOnly.length) diffs.push(`${field}: only ts ${JSON.stringify(tsOnly)}, only py ${JSON.stringify(pyOnly)}`)
  }
  console.log(`${diffs.length ? "DIFFER" : "agree "}  ${c.name}: ${ts.text.split("\n").filter(Boolean).length} lines, ${ts.applied.length} applied, ${ts.outsiders.length} outside writes rejected`)
  for (const d of diffs) console.log(`    ${d}`)
  if (diffs.length) failed++
}
console.log(failed ? `${failed} of ${cases.length} cases differ` : `both readers agree on all ${cases.length} cases`)
process.exit(failed ? 1 : 0)
