/**
 * Runs the TypeScript reader and the Python reader (readers/python, written
 * as a second implementation of PROTOCOL.md) on the same documents and diffs
 * their verdicts: the text, the entities applied, and the outside writes
 * rejected. Cases: both live demo documents on Tiramisu (arkiv/demo.json) and
 * the conformance vectors as a member and as a link holder.
 *
 *   PYTHON=<python with readers/python/requirements.txt> npx tsx scripts/compare-readers.ts [--offline]
 *
 * --offline skips the live demos. ARKIV_ACCESS_KEY, if set, is used by both
 * readers. Exits 1 if any case disagrees.
 */
import { execFileSync } from "node:child_process"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { privateKeyToAccount } from "viem/accounts"
import * as Y from "yjs"
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

type Verdict = { text: string; applied: string[]; outsiders: string[] }

function plain(doc: Y.Doc): string {
  const walk = (n: unknown): string =>
    n instanceof Y.XmlText
      ? (n.toDelta() as { insert: unknown }[]).map((d) => (typeof d.insert === "string" ? d.insert : "")).join("")
      : n instanceof Y.XmlElement
        ? n.toArray().map(walk).join("")
        : ""
  return doc.getXmlFragment("default").toArray().map(walk).join("\n")
}

async function typescript(store: ArkivStore, link: string, memberKey?: Hex): Promise<Verdict> {
  const doc = new Y.Doc()
  const identity = memberKey ? { address: privateKeyToAccount(memberKey).address.toLowerCase() as Hex, privateKey: memberKey, name: "member" } : undefined
  const p = new ArkivProvider(doc, { store, link: parseDocLink(link)!, identity, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0 })
  p.on("error", () => undefined) // a member session may try to renew a lease on a read-only store
  await p.connect()
  const outsiders = (await p.outsiderEntities()).map((e) => e.key)
  p.destroy()
  return { text: plain(doc), applied: [...p.appliedKeys].sort(), outsiders: outsiders.sort() }
}

function pythonReader(args: string[]): Verdict {
  const out = execFileSync(python, [`${root}readers/python/quire_read.py`, "--json", ...args], { encoding: "utf8", env: process.env })
  const v = JSON.parse(out) as { text: string; applied: string[]; ignored: [string, string][] }
  return { text: v.text, applied: v.applied.sort(), outsiders: v.ignored.filter(([, r]) => r === "creator not in ACL").map(([k]) => k).sort() }
}

const cases: { name: string; ts: () => Promise<Verdict>; py: () => Verdict }[] = [
  { name: "vectors, member (Bea)", ts: () => typescript(vectorStore(vectors), vectors.link, vectors.privateKeys.bea), py: () => pythonReader(["--vectors", vectorsPath, "--member-key", vectors.privateKeys.bea]) },
  { name: "vectors, link holder", ts: () => typescript(vectorStore(vectors), vectors.link), py: () => pythonReader(["--vectors", vectorsPath]) },
]
if (!offline) {
  const live = () => new SdkStore({ accessKey: process.env.ARKIV_ACCESS_KEY })
  cases.push(
    { name: "live open demo", ts: () => typescript(live(), demo.open.link), py: () => pythonReader(["--link", demo.open.link]) },
    { name: "live revocation demo", ts: () => typescript(live(), demo.revoked.link), py: () => pythonReader(["--link", demo.revoked.link]) },
  )
}

let failed = 0
for (const c of cases) {
  const [ts, py] = [await c.ts(), c.py()]
  const diffs: string[] = []
  if (ts.text !== py.text) diffs.push(`text\n    ts: ${JSON.stringify(ts.text)}\n    py: ${JSON.stringify(py.text)}`)
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
