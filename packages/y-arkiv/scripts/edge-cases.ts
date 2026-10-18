/**
 * Writes spec/vectors/cases/*.json: small documents, each with one crafted
 * entity from a member, and the text every correct reader must produce. They
 * pin down the rules where readers in different languages could drift: JSON
 * number forms, a byte-order mark, a snapshot's size, ties between snapshots,
 * a backdated qs. Every case is readable with its link alone (epoch 0).
 *
 * Run: npx tsx scripts/edge-cases.ts
 */
import { mkdirSync, writeFileSync } from "node:fs"
import * as encoding from "lib0/encoding"
import { privateKeyToAccount } from "viem/accounts"
import * as Y from "yjs"
import { bucketFor, encodeOuter } from "../src/codec.js"
import { clientIdFor, deriveEpochZeroKey, randomBytes, seal } from "../src/crypto.js"
import { bytesToHex, hexToBytes } from "../src/hex.js"
import { type DocLink, formatDocLink, parseDocLink } from "../src/link.js"
import { MemoryChain } from "../src/memory.js"
import { KIND, type Kind } from "../src/protocol.js"
import { ArkivProvider } from "../src/provider.js"
import type { Hex, StoredEntity } from "../src/store.js"
import { vectorStore } from "../src/vectors.js"

const out = new URL("../../../spec/vectors/cases/", import.meta.url)
mkdirSync(out, { recursive: true })

// synthetic keys, the same ones as spec/vectors/document.json
const OWNER_KEY = `0x${"11".repeat(32)}` as Hex
const BEA_KEY = `0x${"22".repeat(32)}` as Hex
const person = (k: Hex, name: string) => ({ address: privateKeyToAccount(k).address.toLowerCase() as Hex, privateKey: k, name })
const owner = person(OWNER_KEY, "Owner")
const bea = person(BEA_KEY, "Bea")

/** A frame with the header given as raw JSON text, so cases can use number forms and a BOM. */
function rawFrame(kind: Kind, doc: Hex, epoch: number, headerJson: string, data: Uint8Array, bom = false): Uint8Array {
  let h = new TextEncoder().encode(headerJson)
  if (bom) h = new Uint8Array([0xef, 0xbb, 0xbf, ...h])
  const frame = new Uint8Array(bucketFor(48 + h.length + data.length))
  const v = new DataView(frame.buffer)
  frame.set([0x51, 0x46, 1, kind.charCodeAt(0)], 0)
  frame.set(hexToBytes(doc), 4)
  v.setUint32(36, epoch)
  v.setUint32(40, h.length)
  v.setUint32(44, data.length)
  frame.set(h, 48)
  frame.set(data, 48 + h.length)
  return frame
}
const para = (d: Y.Doc, t: string) => {
  const p = new Y.XmlElement("paragraph")
  p.insert(0, [new Y.XmlText(t)])
  d.getXmlFragment("default").push([p])
}
const text = (d: Y.Doc) => d.getXmlFragment("default").toArray().map((x) => (x as Y.XmlElement).toArray().map((t) => (t as Y.XmlText).toString()).join("")).join("\n")
const sigFor = (doc: Hex, salt: Uint8Array) => privateKeyToAccount(BEA_KEY).signMessage({ message: { raw: new Uint8Array([...new TextEncoder().encode("quire1:salt:"), ...hexToBytes(doc), ...salt]) } })

/** A document with the owner's line and Bea as a member, who has synced it. */
async function setup() {
  const chain = new MemoryChain()
  const link: DocLink = { doc: `0x${bytesToHex(randomBytes(32))}`, secret: randomBytes(32), owner: owner.address }
  await ArkivProvider.createDocument({ store: chain.store(owner.address), link, identity: owner })
  chain.mine()
  const open = async (who: typeof owner) => {
    const doc = new Y.Doc()
    const p = new ArkivProvider(doc, { store: chain.store(who.address), link, identity: who, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0 })
    await p.connect()
    return { doc, p }
  }
  const a = await open(owner)
  const b = await open(bea)
  const settle = async () => {
    chain.mine()
    for (let i = 0; i < 3; i++) await Promise.all([a.p.idle(), b.p.idle()])
  }
  await b.p.requestJoin()
  await settle()
  await a.p.approve(bea.address)
  await settle()
  para(a.doc, "Owner line.")
  await a.p.flush()
  await settle()
  return { chain, link, b, a, settle, open }
}

/** The owner's raw snapshot holding any state the case builds. */
async function ownerSnapshot(chain: MemoryChain, link: DocLink, state: Uint8Array): Promise<Hex> {
  const qs = chain.block
  const header = JSON.stringify({ id: bytesToHex(randomBytes(16)), base: qs.toString(), t: 0, chunks: [], size: state.length, authors: {} })
  const r = await chain.store(owner.address).batch({
    creates: [{ payload: encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), rawFrame(KIND.snapshot, link.doc, 0, header, state))), attributes: { doc: link.doc, kind: KIND.snapshot, seq: qs }, lifetimeSeconds: 3600, readonly: true }],
  })
  chain.mine()
  return r.created[0]!
}

const anyBytes = (v: number, asFloat: boolean) => {
  const e = encoding.createEncoder()
  if (asFloat) {
    encoding.writeUint8(e, 123)
    encoding.writeFloat64(e, v)
  } else encoding.writeAny(e, v)
  return encoding.toUint8Array(e)
}
function replaceOnce(hay: Uint8Array, needle: Uint8Array, by: Uint8Array): Uint8Array {
  const at: number[] = []
  for (let i = 0; i + needle.length <= hay.length; i++) if (needle.every((x, j) => hay[i + j] === x)) at.push(i)
  if (at.length !== 1) throw new Error(`expected one occurrence, found ${at.length}`)
  return new Uint8Array([...hay.subarray(0, at[0]!), ...by, ...hay.subarray(at[0]! + needle.length)])
}

/** Bea's raw entity: an update or snapshot whose frame the case controls. */
async function beaWrites(chain: MemoryChain, link: DocLink, kind: Kind, frame: Uint8Array, seq: bigint, readonly = true): Promise<Hex> {
  const r = await chain.store(bea.address).batch({
    creates: [{ payload: encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), frame)), attributes: { doc: link.doc, kind, seq }, lifetimeSeconds: 3600, readonly }],
  })
  chain.mine()
  return r.created[0]!
}

async function beaUpdate(chain: MemoryChain, link: DocLink, base: Y.Doc, line: string, header: (salt: Uint8Array, sig: string) => string, opts: { bom?: boolean; seq?: bigint; salt?: Uint8Array; readonly?: boolean } = {}): Promise<Hex> {
  const salt = opts.salt ?? randomBytes(16)
  const d = new Y.Doc()
  d.clientID = clientIdFor(bea.address, salt)
  Y.applyUpdate(d, Y.encodeStateAsUpdate(base))
  const sv = Y.encodeStateVector(d)
  para(d, line)
  const frame = rawFrame(KIND.update, link.doc, 0, header(salt, await sigFor(link.doc, salt)), Y.encodeStateAsUpdate(d, sv), opts.bom)
  return beaWrites(chain, link, KIND.update, frame, opts.seq ?? chain.block, opts.readonly ?? true)
}

async function beaSnapshot(chain: MemoryChain, link: DocLink, base: Y.Doc, line: string | null, opts: { sizeDelta?: number; qs?: bigint; id?: string } = {}): Promise<Hex> {
  const salt = randomBytes(16)
  const d = new Y.Doc()
  d.clientID = clientIdFor(bea.address, salt)
  Y.applyUpdate(d, Y.encodeStateAsUpdate(base))
  if (line) para(d, line)
  const state = Y.encodeStateAsUpdate(d)
  const qs = opts.qs ?? chain.block
  const header = JSON.stringify({ id: opts.id ?? bytesToHex(randomBytes(16)), base: qs.toString(), t: 0, chunks: [], size: state.length + (opts.sizeDelta ?? 0), authors: {} })
  return beaWrites(chain, link, KIND.snapshot, rawFrame(KIND.snapshot, link.doc, 0, header, state), qs)
}

/** Rewrites one exported entity's attributes, for cases about the attributes themselves. */
function withAttributes(vec: ReturnType<typeof exportCase>, key: Hex, change: (attrs: { name: string; type: string; value: string }[]) => { name: string; type: string; value: string }[]) {
  return { ...vec, entities: vec.entities.map((e) => (e.key === key ? { ...e, attributes: change(e.attributes) } : e)) }
}

function exportCase(chain: MemoryChain, link: DocLink, order?: (es: StoredEntity[]) => StoredEntity[]) {
  let all: StoredEntity[] = []
  for (const kind of Object.values(KIND)) all.push(...(chain as unknown as { query: (s: { doc: Hex; kind: Kind }) => { entities: StoredEntity[] } }).query({ doc: link.doc, kind }).entities)
  if (order) all = order(all)
  return {
    link: formatDocLink(link),
    head: chain.block.toString(),
    entities: all.map((e) => ({
      key: e.key,
      creator: e.creator,
      owner: e.owner,
      createdAt: `0x${e.createdAt.toString(16)}`,
      updatedAt: `0x${e.updatedAt.toString(16)}`,
      expiresAt: `0x${e.expiresAt.toString(16)}`,
      creationFlags: { readonly: e.readonly, permissionlessExtension: e.permissionlessExtension, raw: (e.readonly ? 1 : 0) | (e.permissionlessExtension ? 2 : 0) },
      attributes: [
        { name: "qp", type: "str", value: "quire1" },
        { name: "qd", type: "bytes32", value: e.attributes.doc },
        { name: "qk", type: "str", value: e.attributes.kind },
        { name: "qs", type: "u64", value: `0x${e.attributes.seq.toString(16)}` },
      ],
      payload: `0x${bytesToHex(e.payload)}`,
    })),
  }
}

async function write(name: string, rule: string, vec: ReturnType<typeof exportCase>, memberKey?: Hex) {
  const doc = new Y.Doc()
  const identity = memberKey ? person(memberKey, "reader") : undefined
  const p = new ArkivProvider(doc, { store: vectorStore(vec), link: parseDocLink(vec.link)!, identity, readOnly: true, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0 })
  await p.connect()
  const applied = [...p.appliedKeys].sort()
  writeFileSync(new URL(`${name}.json`, out), JSON.stringify({ description: rule, ...vec, ...(memberKey ? { memberKey } : {}), expected: { text: text(doc), applied } }, null, 2))
  console.log(`${name}: ${JSON.stringify(text(doc))}`)
  p.destroy()
}

const header = (t: string) => (salt: Uint8Array, sig: string) => `{"t":${t},"salt":"${bytesToHex(salt)}","sig":"${sig}"}`

{
  const { chain, link, b } = await setup()
  await beaUpdate(chain, link, b.doc, "Bea, t written as 1.0.", header("1.0"))
  await write("update-t-float", "JSON has one number type: t written as 1.0 is the integer 1, so the update is applied.", exportCase(chain, link))
}
{
  const { chain, link, b } = await setup()
  await beaUpdate(chain, link, b.doc, "Bea, t written as 1e3.", header("1e3"))
  await write("update-t-exponent", "t written as 1e3 is the integer 1000, so the update is applied.", exportCase(chain, link))
}
{
  const { chain, link, b } = await setup()
  await beaUpdate(chain, link, b.doc, "Bea, t as a string.", header('"1"'))
  await write("update-t-string", "t as a string breaks the header schema, so the update is ignored.", exportCase(chain, link))
}
{
  const { chain, link, b } = await setup()
  await beaUpdate(chain, link, b.doc, "Bea, header behind a BOM.", header("1"), { bom: true })
  await write("update-header-bom", "A header that starts with a UTF-8 byte-order mark is not a JSON text, so the update is ignored.", exportCase(chain, link))
}
{
  const { chain, link, b } = await setup()
  chain.mine(100)
  await beaUpdate(chain, link, b.doc, "Bea, qs backdated.", header("1"), { seq: chain.block - 61n })
  await write("update-qs-backdated", "An update whose qs is more than 60 blocks before its createdAt is ignored, live and cold alike.", exportCase(chain, link))
}
{
  const { chain, link, b } = await setup()
  await beaSnapshot(chain, link, b.doc, "Bea, snapshot with a wrong size.", { sizeDelta: 7 })
  await write("snapshot-size-mismatch", "A snapshot whose header size differs from its assembled data is ignored.", exportCase(chain, link))
}
{
  const { chain, link, b } = await setup()
  const qs = chain.block
  await beaSnapshot(chain, link, b.doc, null, { qs })
  await beaSnapshot(chain, link, b.doc, "Bea, the later of two snapshots with one qs.", { qs })
  // listed older first, as a node may return them
  await write(
    "snapshot-qs-tie",
    "Two snapshots from one member with the same qs: the later createdAt wins (then the higher key), whatever order the node lists them in.",
    exportCase(chain, link, (es) => [...es].sort((x, y) => (x.createdAt < y.createdAt ? -1 : 1))),
  )
}
{
  const { chain, link, b } = await setup()
  await beaUpdate(chain, link, b.doc, "Bea, salt with a newline.", (salt, sig) => `{"t":1,"salt":"${bytesToHex(salt)}\\n","sig":"${sig}"}`)
  await write("update-salt-newline", "A salt with a trailing newline is not 32 hex characters, so the update is ignored.", exportCase(chain, link))
}
{
  const { chain, link, b } = await setup()
  await beaUpdate(chain, link, b.doc, "Bea, sig with a newline.", (salt, sig) => `{"t":1,"salt":"${bytesToHex(salt)}","sig":"${sig}\\n"}`)
  await write("update-sig-newline", "A signature with a trailing newline is not a 65-byte hex string, so the update is ignored.", exportCase(chain, link))
}
{
  const { chain, link, b } = await setup()
  await beaSnapshot(chain, link, b.doc, "Bea, snapshot id with a newline.", { id: `${bytesToHex(randomBytes(16))}\n` })
  await write("snapshot-id-newline", "A snapshot id with a trailing newline is not 32 hex characters, so the snapshot is ignored.", exportCase(chain, link))
}
{
  const { chain, link, b } = await setup()
  const key = await beaSnapshot(chain, link, b.doc, "Bea, snapshot without qs.")
  await write("snapshot-no-qs", "An entity without its qs attribute is not a Quire entity, so the snapshot is ignored.", withAttributes(exportCase(chain, link), key, (a) => a.filter((x) => x.name !== "qs")))
}
{
  const { chain, link, b } = await setup()
  const key = await beaSnapshot(chain, link, b.doc, "Bea, snapshot with qs as a string.")
  await write("snapshot-qs-string", "qs must be a u64; as a str the entity is not a Quire entity, so the snapshot is ignored.", withAttributes(exportCase(chain, link), key, (a) => a.map((x) => (x.name === "qs" ? { ...x, type: "str", value: "5" } : x))))
}
{
  const { chain, link, b } = await setup()
  const key = await beaSnapshot(chain, link, b.doc, "Bea, snapshot with a fifth attribute.")
  await write("snapshot-extra-attribute", "An entity with a fifth attribute is not a Quire entity, so the snapshot is ignored.", withAttributes(exportCase(chain, link), key, (a) => [...a, { name: "note", type: "str", value: "hi" }]))
}
{
  const { chain, link, b } = await setup()
  // two valid updates under one salt, from one base: they claim the same clocks with different text
  const salt = randomBytes(16)
  await beaUpdate(chain, link, b.doc, "Bea one.", header("1"), { salt })
  await beaUpdate(chain, link, b.doc, "Bea two.", header("1"), { salt })
  await write("update-duplicate-clocks", "Two updates that put different content at the same clocks: the earlier one (by createdAt, then key) stands and the later is ignored.", exportCase(chain, link))
}
{
  const { chain, link, b } = await setup()
  // Bea's verified update writes a paragraph; the owner's snapshot holds other text at her clocks,
  // plus a paragraph of his own. The whole snapshot is refused, not just the clashing part.
  const salt = randomBytes(16)
  await beaUpdate(chain, link, b.doc, "Bea genuine.", header("1"), { salt })
  const forged = new Y.Doc()
  Y.applyUpdate(forged, Y.encodeStateAsUpdate(b.doc))
  forged.clientID = clientIdFor(bea.address, salt)
  para(forged, "Bea forged!!")
  forged.clientID = 424242
  para(forged, "Owner extra paragraph.")
  await ownerSnapshot(chain, link, Y.encodeStateAsUpdate(forged))
  await write("snapshot-differs-at-verified-clock", "A snapshot that holds other content at a clock a verified update wrote is refused whole, even where the update is already integrated and Yjs would quietly keep the update's struct.", exportCase(chain, link))
}
{
  const { chain, link, b } = await setup()
  // Bea's update pushes 12345 to an array; the owner's snapshot carries the same item with the number
  // encoded as a float64. Same value, so no conflict: the snapshot and its extra paragraph apply.
  const salt = randomBytes(16)
  const d = new Y.Doc()
  d.clientID = clientIdFor(bea.address, salt)
  Y.applyUpdate(d, Y.encodeStateAsUpdate(b.doc))
  const sv = Y.encodeStateVector(d)
  d.getArray("a").push([12345])
  const update = Y.encodeStateAsUpdate(d, sv)
  const frame = rawFrame(KIND.update, link.doc, 0, header("1")(salt, await sigFor(link.doc, salt)), update)
  await beaWrites(chain, link, KIND.update, frame, chain.block)
  const full = new Y.Doc()
  Y.applyUpdate(full, Y.encodeStateAsUpdate(d))
  full.clientID = 424243
  para(full, "Owner extra paragraph.")
  await ownerSnapshot(chain, link, replaceOnce(Y.encodeStateAsUpdate(full), anyBytes(12345, false), anyBytes(12345, true)))
  await write("snapshot-number-encoding", "Content is compared by value: 12345 written as an integer and as a float64 is the same item, so the snapshot applies.", exportCase(chain, link))
}
{
  const { chain, link, b } = await setup()
  await beaUpdate(chain, link, b.doc, "Bea, an update that is not readonly.", header("1"), { readonly: false })
  await write("update-not-readonly", "An update created without the readonly flag could be patched later under its original block, so it is ignored.", exportCase(chain, link))
}
{
  // Bea compacts, then extends her snapshot (which holds the whole text) for three years, though the
  // owner never chose to keep the document. Readers ignore it; the text still comes from the edits.
  const { chain, link, b, settle } = await setup()
  para(b.doc, "Bea, in a snapshot she kept too long.")
  await b.p.flush()
  await settle()
  await b.p.compact()
  await settle()
  await chain.store(bea.address).batch({ extensions: [{ key: b.p.snapshot!.key, lifetimeSeconds: 3 * 365 * 86400 }] })
  chain.mine()
  await write("snapshot-past-owner-lifetime", "A snapshot extended past the larger of the owner's keepUntil and a fresh 30-day lease is ignored: no member can keep a readable copy past the owner's ceiling.", exportCase(chain, link))
}
{
  // Bea writes "Hello" under salt S, deletes it, then writes other text at the same clocks under the same
  // salt. Deleting does not free the clocks: the third update conflicts with the first and is ignored.
  const { chain, link, b } = await setup()
  const salt = randomBytes(16)
  const sig = await sigFor(link.doc, salt)
  const base = new Y.Doc()
  Y.applyUpdate(base, Y.encodeStateAsUpdate(b.doc))
  const d = new Y.Doc()
  Y.applyUpdate(d, Y.encodeStateAsUpdate(base))
  d.clientID = clientIdFor(bea.address, salt)
  let sv = Y.encodeStateVector(d)
  para(d, "Hello")
  const u1 = Y.encodeStateAsUpdate(d, sv)
  sv = Y.encodeStateVector(d)
  const t = (d.getXmlFragment("default").get(d.getXmlFragment("default").length - 1) as Y.XmlElement).get(0) as Y.XmlText
  t.delete(0, 5)
  const u2 = Y.encodeStateAsUpdate(d, sv)
  const e = new Y.Doc()
  Y.applyUpdate(e, Y.encodeStateAsUpdate(base))
  e.clientID = clientIdFor(bea.address, salt)
  const sv0 = Y.encodeStateVector(e)
  para(e, "Jello SMUGGLED")
  const u3 = Y.encodeStateAsUpdate(e, sv0)
  for (const u of [u1, u2, u3]) await beaWrites(chain, link, KIND.update, rawFrame(KIND.update, link.doc, 0, `{"t":1,"salt":"${bytesToHex(salt)}","sig":"${sig}"}`, u), chain.block)
  await write("update-reuses-deleted-clocks", "An update that puts other content at clocks an earlier update wrote is ignored even if that text was deleted since: deleting does not free the clocks.", exportCase(chain, link))
}
{
  // Bea writes, is removed, asks again and is added back, writes again. Both stints stay proven.
  const { chain, link, a, b, settle } = await setup()
  para(b.doc, "Bea, first stint.")
  await b.p.flush()
  await settle()
  await a.p.revoke(bea.address)
  await settle()
  await b.p.requestJoin()
  await settle()
  await a.p.approve(bea.address)
  await settle()
  await b.p.resync({ joins: true })
  para(b.doc, "Bea, second stint.")
  await b.p.flush()
  await settle()
  await write("member-readded", "A member removed and added again keeps the proof of both stints: each removal entry closes one interval. Read with memberKey (the owner's).", exportCase(chain, link), OWNER_KEY)
}
{
  // two rotations: Bea writes under epoch 1, then a second removal moves the key to epoch 2. A fresh
  // session of Bea's opens epoch 2 from her wrap and epoch 1 from the roster's prior keys, so her
  // epoch 1 edit is applied (and proven), not just carried by a snapshot.
  const { chain, link, a, b, settle, open } = await setup()
  const cal = person(`0x${"33".repeat(32)}`, "Cal")
  const dan = person(`0x${"55".repeat(32)}`, "Dan")
  for (const who of [cal, dan]) {
    const s = await open(who)
    await s.p.requestJoin()
    await settle()
    await a.p.approve(who.address)
    await settle()
  }
  await a.p.revoke(cal.address)
  await settle()
  para(b.doc, "Bea, written under epoch 1.")
  await b.p.flush()
  await settle()
  await a.p.revoke(dan.address)
  await settle()
  await write("two-rotations-prior-keys", "After two rotations a current member still reads edits from the earlier epoch: the roster carries earlier epoch keys in prior. Read with memberKey.", exportCase(chain, link), BEA_KEY)
}
{
  // Bea's own snapshot holds her paragraph under her client id, with a valid authors entry for it; her
  // update has expired. The owner's newer snapshot puts other words at those clocks. A member speaks
  // for their own client ids, so the owner's snapshot is refused whole, however new it is.
  const { chain, link, b } = await setup()
  const salt = randomBytes(16)
  const mine = new Y.Doc()
  mine.clientID = clientIdFor(bea.address, salt)
  Y.applyUpdate(mine, Y.encodeStateAsUpdate(b.doc))
  para(mine, "Bea: I approve a budget of 100.")
  const state = Y.encodeStateAsUpdate(mine)
  const authors = { [String(mine.clientID)]: { address: bea.address, salt: bytesToHex(salt), sig: await sigFor(link.doc, salt) } }
  const qs = chain.block
  const head = JSON.stringify({ id: bytesToHex(randomBytes(16)), base: qs.toString(), t: 0, chunks: [], size: state.length, authors })
  await beaWrites(chain, link, KIND.snapshot, rawFrame(KIND.snapshot, link.doc, 0, head, state), qs)
  chain.mine(5)
  const forged = new Y.Doc()
  Y.applyUpdate(forged, Y.encodeStateAsUpdate(b.doc))
  forged.clientID = clientIdFor(bea.address, salt)
  para(forged, "Bea: I approve a budget of 900.")
  await ownerSnapshot(chain, link, Y.encodeStateAsUpdate(forged))
  await write("snapshot-rewrites-member-client", "A newer snapshot that holds other content under a client id another member's own snapshot speaks for (through a valid authors entry for that member) is refused: no one can rewrite what a member's own snapshot says they wrote.", exportCase(chain, link))
}
{
  // the owner's name is 30 emoji: 30 characters as JSON Schema counts them (code points), 60 UTF-16 units
  const chain = new MemoryChain()
  const named = { ...owner, name: "\u{1F600}".repeat(30) }
  const link: DocLink = { doc: `0x${bytesToHex(randomBytes(32))}`, secret: randomBytes(32), owner: owner.address }
  await ArkivProvider.createDocument({ store: chain.store(owner.address), link, identity: named })
  chain.mine()
  const doc = new Y.Doc()
  const p = new ArkivProvider(doc, { store: chain.store(owner.address), link, identity: named, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0 })
  await p.connect()
  para(doc, "Owner line.")
  await p.flush()
  chain.mine()
  await p.idle()
  p.destroy()
  await write("acl-name-code-points", "A member name is limited to 40 characters counted as code points, as JSON Schema counts them: 30 emoji (60 UTF-16 units) is within the limit, so the document opens.", exportCase(chain, link))
}
process.exit(0)
