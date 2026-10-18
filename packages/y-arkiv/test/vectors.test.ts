/**
 * The committed conformance vectors must say what this implementation reads.
 * Other implementations test against spec/vectors/document.json, so a stale
 * `expected` there would send them chasing the wrong answer.
 */
import { readdirSync, readFileSync } from "node:fs"
import { privateKeyToAccount } from "viem/accounts"
import { describe, expect, it } from "vitest"
import * as Y from "yjs"
import { parseDocLink } from "../src/link.js"
import { ArkivProvider } from "../src/provider.js"
import { fromRpcEntity, type RpcEntity } from "../src/sdk.js"
import type { Hex, StoredEntity } from "../src/store.js"
import { vectorStore } from "../src/vectors.js"

const VEC = JSON.parse(readFileSync(new URL("../../../spec/vectors/document.json", import.meta.url), "utf8"))
const entities = (VEC.entities as RpcEntity[]).map(fromRpcEntity).filter((e): e is StoredEntity => e !== null)
const store = vectorStore(VEC)

const text = (d: Y.Doc) =>
  d
    .getXmlFragment("default")
    .toArray()
    .map((x) => (x as Y.XmlElement).toArray().map((t) => t.toString()).join(""))
    .join("\n")

async function read(privateKey?: Hex) {
  const doc = new Y.Doc()
  const identity = privateKey ? { address: privateKeyToAccount(privateKey).address.toLowerCase() as Hex, privateKey, name: "bea" } : undefined
  const p = new ArkivProvider(doc, { store, link: parseDocLink(VEC.link)!, identity, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0 })
  p.on("error", () => undefined) // a member session may try to renew the lease; the vectors refuse writes
  await p.connect()
  return { doc, p }
}

describe("conformance vectors", () => {
  it("a current member reads expected.memberText", async () => {
    const { doc } = await read(VEC.privateKeys.bea)
    expect(text(doc)).toBe(VEC.expected.memberText)
  })

  it("a link holder reads expected.linkHolderText", async () => {
    const { doc } = await read()
    expect(text(doc)).toBe(VEC.expected.linkHolderText)
  })

  it("the rejected creators' entities are never applied", async () => {
    const { doc } = await read(VEC.privateKeys.bea)
    expect(text(doc)).not.toMatch(/mallory/i)
    // and Bea's update with a malformed header, though she is a member and it decrypts
    expect(text(doc)).not.toContain("MALFORMED")
    const forged = entities.filter((e) => VEC.expected.rejectedCreators.includes(e.creator))
    expect(forged.length).toBeGreaterThan(0)
  })
})

describe("edge cases (spec/vectors/cases)", () => {
  const dir = new URL("../../../spec/vectors/cases/", import.meta.url)
  const files = readdirSync(dir).filter((f) => f.endsWith(".json"))
  it("there are cases to run", () => expect(files.length).toBeGreaterThanOrEqual(7))
  for (const f of files) {
    it(f, async () => {
      const c = JSON.parse(readFileSync(new URL(f, dir), "utf8"))
      const doc = new Y.Doc()
      const identity = c.memberKey ? { address: privateKeyToAccount(c.memberKey).address.toLowerCase() as Hex, privateKey: c.memberKey, name: "reader" } : undefined
      const p = new ArkivProvider(doc, { store: vectorStore(c), link: parseDocLink(c.link)!, identity, readOnly: true, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0 })
      await p.connect()
      expect(text(doc), c.description).toBe(c.expected.text)
      expect([...p.appliedKeys].sort(), c.description).toEqual(c.expected.applied)
      p.destroy()
    })
  }
})
