/**
 * The committed conformance vectors must say what this implementation reads.
 * Other implementations test against spec/vectors/document.json, so a stale
 * `expected` there would send them chasing the wrong answer.
 */
import { readFileSync } from "node:fs"
import { privateKeyToAccount } from "viem/accounts"
import { describe, expect, it } from "vitest"
import * as Y from "yjs"
import { parseDocLink } from "../src/link.js"
import { ArkivProvider } from "../src/provider.js"
import { fromRpcEntity, type RpcEntity } from "../src/sdk.js"
import type { ArkivStore, Hex, StoredEntity } from "../src/store.js"

const VEC = JSON.parse(readFileSync(new URL("../../../spec/vectors/document.json", import.meta.url), "utf8"))
const entities = (VEC.entities as RpcEntity[]).map(fromRpcEntity).filter((e): e is StoredEntity => e !== null)

/** The vector file as a read-only chain frozen at its head block. */
const store: ArkivStore = {
  address: undefined,
  head: async () => BigInt(VEC.head),
  batch: async () => {
    throw new Error("the vectors are read-only")
  },
  predictKeys: async () => [],
  query: async (spec) => ({
    entities: entities.filter(
      (e) =>
        e.attributes.doc === spec.doc &&
        (!spec.kind || e.attributes.kind === spec.kind) &&
        (spec.seqGte === undefined || e.attributes.seq >= spec.seqGte) &&
        (!spec.creators || spec.creators.some((c) => c.toLowerCase() === e.creator)),
    ),
    block: BigInt(VEC.head),
  }),
  get: async (key) => entities.find((e) => e.key === key.toLowerCase()) ?? null,
  watch: () => () => undefined,
}

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
