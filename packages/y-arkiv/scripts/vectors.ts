/**
 * Writes spec/vectors/*.json: conformance data for other implementations.
 *
 *   keys.json      HKDF derivations from a fixed link secret
 *   document.json  every entity of a small document (with an epoch rotation and
 *                  a forged write), plus the text a correct reader must produce
 *
 * Run: npx tsx scripts/vectors.ts
 */
import { mkdirSync, writeFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import * as Y from "yjs"
import { ArkivProvider } from "../src/provider.js"
import { deriveEpochZeroKey, deriveMetaKey } from "../src/crypto.js"
import { bytesToHex, hexToBytes } from "../src/hex.js"
import { formatDocLink, type DocLink } from "../src/link.js"
import { MemoryChain } from "../src/memory.js"
import { KIND } from "../src/protocol.js"
import type { Hex } from "../src/store.js"

const out = resolve(dirname(fileURLToPath(import.meta.url)), "../../../spec/vectors")
mkdirSync(out, { recursive: true })

// fixed, obviously synthetic keys so the vectors are stable to read
const OWNER_KEY = `0x${"11".repeat(32)}` as Hex
const BEA_KEY = `0x${"22".repeat(32)}` as Hex
const CAL_KEY = `0x${"33".repeat(32)}` as Hex
const MALLORY_KEY = `0x${"44".repeat(32)}` as Hex
const SECRET = hexToBytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
const DOC = `0x${"ab".repeat(32)}` as Hex

const { privateKeyToAccount } = await import("viem/accounts")
const id = (k: Hex, name: string) => ({ address: privateKeyToAccount(k).address.toLowerCase() as Hex, privateKey: k, name })
const owner = id(OWNER_KEY, "Owner")
const bea = id(BEA_KEY, "Bea")
const cal = id(CAL_KEY, "Cal")
const mallory = id(MALLORY_KEY, "Mallory")

writeFileSync(
  `${out}/keys.json`,
  JSON.stringify(
    {
      description: "HKDF-SHA256, salt 'quire/v1', 32-byte output",
      linkSecret: bytesToHex(SECRET),
      metaKey: bytesToHex(deriveMetaKey(SECRET)),
      epoch0Key: bytesToHex(deriveEpochZeroKey(SECRET)),
    },
    null,
    2,
  ),
)

const chain = new MemoryChain()
const link: DocLink = { doc: DOC, secret: SECRET, owner: owner.address }
await ArkivProvider.createDocument({ store: chain.store(owner.address), link, identity: owner })
chain.mine()

async function open(who: typeof owner) {
  const doc = new Y.Doc()
  const p = new ArkivProvider(doc, { store: chain.store(who.address), link, identity: who, flushIntervalMs: 0, autoCompact: false })
  await p.connect()
  return { doc, p }
}
const settle = async (...ps: ArkivProvider[]) => {
  chain.mine()
  for (let i = 0; i < 3; i++) await Promise.all(ps.map((p) => p.idle()))
}
const para = (doc: Y.Doc, text: string) => {
  const p = new Y.XmlElement("paragraph")
  p.insert(0, [new Y.XmlText(text)])
  doc.getXmlFragment("default").push([p])
}

const a = await open(owner)
const b = await open(bea)
const c = await open(cal)
for (const who of [b, c]) {
  await who.p.requestJoin()
  await settle(a.p, b.p, c.p)
  await a.p.approve(who.p.identity!.address)
  await settle(a.p, b.p, c.p)
}
para(a.doc, "Minutes, synthetic test document.")
await a.p.flush()
await settle(a.p, b.p, c.p)
para(b.doc, "Bea adds a line.")
await b.p.flush()
await settle(a.p, b.p, c.p)
await a.p.compact()
await settle(a.p, b.p, c.p)
para(c.doc, "Cal adds a line before being removed.")
await c.p.flush()
await settle(a.p, b.p, c.p)
const reader0 = { doc: new Y.Doc() }
Y.applyUpdate(reader0.doc, Y.encodeStateAsUpdate(a.doc))
await a.p.revoke(cal.address)
await settle(a.p, b.p, c.p)
para(a.doc, "Written in epoch 1, after Cal left.")
await a.p.flush()
await settle(a.p, b.p, c.p)
// a forged update: Mallory holds the link, so she can encrypt a perfectly valid
// epoch 0 update with new text. Only the $creator filter keeps it out.
{
  const forged = new Y.Doc()
  Y.applyUpdate(forged, Y.encodeStateAsUpdate(reader0.doc))
  const before = Y.encodeStateVector(forged)
  para(forged, "MALLORY WAS HERE")
  const update = Y.encodeStateAsUpdate(forged, before)
  const { encodeFrame, encodeOuter } = await import("../src/codec.js")
  const { randomBytes, seal } = await import("../src/crypto.js")
  const frame = encodeFrame({ kind: KIND.update, doc: hexToBytes(DOC), epoch: 0, header: { t: 0 }, data: update }, randomBytes)
  const payload = encodeOuter(0, await seal(deriveEpochZeroKey(SECRET), frame))
  await chain.store(mallory.address).batch({
    creates: [{ payload, attributes: { doc: DOC, kind: KIND.update, seq: chain.block }, lifetimeSeconds: 3600 }],
  })
  chain.mine()
}

const all = []
for (const kind of Object.values(KIND)) {
  const page = await chain.store(undefined).query({ doc: DOC, kind })
  for (const e of page.entities) {
    all.push({
      key: e.key,
      creator: e.creator,
      owner: e.owner,
      createdAt: `0x${e.createdAt.toString(16)}`,
      expiresAt: `0x${e.expiresAt.toString(16)}`,
      readonly: e.readonly,
      permissionlessExtension: e.permissionlessExtension,
      attributes: [
        { name: "qp", type: "str", value: "quire1" },
        { name: "qd", type: "bytes32", value: e.attributes.doc },
        { name: "qk", type: "str", value: e.attributes.kind },
        { name: "qs", type: "u64", value: `0x${e.attributes.seq.toString(16)}` },
      ],
      payload: `0x${bytesToHex(e.payload)}`,
    })
  }
}

const reader = new ArkivProvider(new Y.Doc(), { store: chain.store(undefined), link, flushIntervalMs: 0 })
await reader.connect()
const beaView = await open(bea)
const text = (d: Y.Doc) => d.getXmlFragment("default").toArray().map((x) => (x as Y.XmlElement).toArray().map((t) => t.toString()).join("")).join("\n")

writeFileSync(
  `${out}/document.json`,
  JSON.stringify(
    {
      description:
        "A Quire document: owner adds Bea and Cal, everyone writes, the owner compacts, removes Cal (epoch 1) and writes again; Mallory, who holds the link but is not a member, writes a valid encrypted epoch 0 update with new text. Keys are synthetic test values. Entities use the arkiv_query JSON shape: attributes as [{name, type, value}], u64 as 0x hex.",
      link: formatDocLink(link),
      linkSecret: bytesToHex(SECRET),
      doc: DOC,
      owner: owner.address,
      members: { owner: owner.address, bea: bea.address, cal: cal.address, mallory: mallory.address },
      privateKeys: { bea: BEA_KEY, note: "Bea's key unwraps epoch 1. Never use these keys anywhere real." },
      head: chain.block.toString(),
      entities: all,
      expected: {
        // a link holder without a member key reads only epoch 0 content
        linkHolderText: text(reader.doc),
        // a current member (Bea) reads everything
        memberText: text(beaView.doc),
        rejectedCreators: [mallory.address],
      },
    },
    null,
    2,
  ),
)
console.log(`wrote ${all.length} entities to ${out}`)
console.log("link holder sees:\n" + text(reader.doc))
console.log("member sees:\n" + text(beaView.doc))
process.exit(0)
