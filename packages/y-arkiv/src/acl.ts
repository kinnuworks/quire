/**
 * The member list.
 *
 * One ACL entity per document, created and owned by the document owner and
 * changed only with patchEntity. Readers find it with `$creator = owner`, so a
 * forged ACL written by anyone else is never even returned by the query.
 *
 * The ACL payload is encrypted with the meta key, which every link holder
 * can derive. In epoch 0 the roster sits there directly. From epoch 1 on, the
 * roster is sealed again under the current epoch key, so a removed member
 * (who still has the link) learns nothing about who joined or left after them.
 */
import { open, seal } from "./crypto.js"
import { bytesToHex, hexToBytes } from "./hex.js"
import type { Hex } from "./store.js"

export type Member = {
  address: Hex
  /** Uncompressed secp256k1 public key, hex. Needed to wrap epoch keys for this member. */
  publicKey: Hex
  /** A display name the member picked. Synthetic in the demo; never real personal data. */
  name: string
  role: "owner" | "writer"
  addedAtBlock: string
}

export type Revoked = { address: Hex; atBlock: string; addedAtBlock?: string }

/** The ACL as a session understands it. */
export type Acl = {
  v: 1
  owner: Hex
  /** The owner's public key: join requests are encrypted to it. */
  ownerPublicKey: Hex
  /** Current content epoch. Edits are encrypted with this epoch's key. */
  epoch: number
  /** Block height until which the owner wants the document kept, or null for the default lease. */
  keepUntil: string | null
  members: Member[]
  revoked: Revoked[]
  /**
   * Keys of earlier epochs above 0, by epoch, carried in the sealed roster so a current member's
   * fresh session can still read, and prove, edits written before the latest rotation.
   */
  prior?: Record<string, Hex>
  /**
   * For epochs above 0: the epoch key sealed to each member, in random order and
   * without labels. A member finds theirs by trying each; nobody else learns who they are for.
   */
  wraps: Hex[]
  /** True when the roster is sealed under an epoch key this session does not hold. */
  rosterHidden: boolean
}

/** The ACL as stored in the frame header. */
export type AclHeader = {
  v: 1
  owner: Hex
  ownerPublicKey: Hex
  epoch: number
  keepUntil: string | null
  wraps: Hex[]
  /** Epoch 0 only. */
  members?: Member[]
  revoked?: Revoked[]
  /** Epoch 1 and later: AES-GCM envelope of `{members, revoked}` under the epoch key. */
  roster?: Hex
}

export function emptyAcl(owner: Member): Acl {
  return { v: 1, owner: owner.address, ownerPublicKey: owner.publicKey, epoch: 0, keepUntil: null, members: [owner], wraps: [], revoked: [], rosterHidden: false }
}

export function isMember(acl: Acl, address: Hex | undefined): boolean {
  if (!address) return false
  const a = address.toLowerCase()
  return acl.members.some((m) => m.address.toLowerCase() === a)
}

/**
 * A current member whose entity landed at or after the block they were added: an edit from before
 * someone joined does not become theirs, even if the owner adds them later.
 */
export function memberAt(acl: Acl, address: Hex | undefined, createdAt: bigint): boolean {
  const a = address?.toLowerCase()
  const m = acl.members.find((x) => x.address.toLowerCase() === a)
  return !!m && /^[0-9]+$/.test(String(m.addedAtBlock)) && createdAt >= BigInt(m.addedAtBlock)
}

export function memberAddresses(acl: Acl): Hex[] {
  return acl.members.map((m) => m.address.toLowerCase() as Hex)
}

/**
 * Whether an entity created at `createdAt` by `address` was written by a member: a current member,
 * or a removed one whose entity landed at or before their removal block. Removing someone must not
 * erase the proof of what they wrote while they belonged; anything they create later still does not count.
 */
export function wroteAsMember(acl: Acl, address: Hex | undefined, createdAt: bigint): boolean {
  if (memberAt(acl, address, createdAt)) return true
  const a = address?.toLowerCase()
  // each removal closes one membership interval: [addedAtBlock, atBlock]. Older entries without
  // addedAtBlock start at 0. Edits from a gap between two memberships never count.
  return acl.revoked.some(
    (r) =>
      r.address.toLowerCase() === a &&
      /^[0-9]+$/.test(String(r.atBlock)) &&
      createdAt <= BigInt(r.atBlock) &&
      (r.addedAtBlock === undefined || (/^[0-9]+$/.test(String(r.addedAtBlock)) && createdAt >= BigInt(r.addedAtBlock))),
  )
}

/** Everyone whose updates can count: members, and removed members for what they wrote before removal. */
export function updateAuthors(acl: Acl): Hex[] {
  return [...new Set([...memberAddresses(acl), ...acl.revoked.map((r) => r.address.toLowerCase() as Hex)])]
}

const enc = new TextEncoder()
const dec = new TextDecoder()

export async function toHeader(acl: Acl, epochKey: Uint8Array | undefined, doc: Hex): Promise<AclHeader> {
  const base = { v: 1 as const, owner: acl.owner, ownerPublicKey: acl.ownerPublicKey, epoch: acl.epoch, keepUntil: acl.keepUntil, wraps: acl.wraps }
  if (acl.epoch === 0) return { ...base, members: acl.members, revoked: acl.revoked }
  if (!epochKey) throw new Error("sealing the roster needs the current epoch key")
  // the roster names its document and epoch, so it cannot be replayed into another ACL
  const body = { doc: doc.toLowerCase(), epoch: acl.epoch, members: acl.members, revoked: acl.revoked, ...(acl.prior && Object.keys(acl.prior).length ? { prior: acl.prior } : {}) }
  const roster = await seal(epochKey, enc.encode(JSON.stringify(body)))
  return { ...base, roster: `0x${bytesToHex(roster)}` }
}

/**
 * Validates a header and opens its roster. `epochKey` is the current epoch's
 * key if this session holds it; without it an epoch 1+ roster stays hidden.
 */
/** Member and removal entries as spec/schema/acl-header.json describes them, checked by hand so no schema library is needed. */
function checkRoster(members: unknown, revoked: unknown): void {
  const ok = (v: unknown, re: RegExp) => typeof v === "string" && re.test(v)
  if (!Array.isArray(members) || members.length === 0 || !Array.isArray(revoked)) throw new Error("malformed ACL: members or revoked")
  for (const m of members as Record<string, unknown>[]) {
    const keys = Object.keys(m ?? {}).sort().join()
    if (keys !== "addedAtBlock,address,name,publicKey,role") throw new Error("malformed ACL: a member entry has the wrong fields")
    if (!ok(m.address, /^0x[0-9a-f]{40}$/) || !ok(m.publicKey, /^0x04[0-9a-f]{128}$/) || typeof m.name !== "string" || m.name.length > 40 || (m.role !== "owner" && m.role !== "writer") || !ok(m.addedAtBlock, /^[0-9]+$/)) {
      throw new Error("malformed ACL: a member entry has a malformed field")
    }
  }
  for (const r of revoked as Record<string, unknown>[]) {
    if (!r || !ok(r.address, /^0x[0-9a-f]{40}$/) || !ok(r.atBlock, /^[0-9]+$/) || (r.addedAtBlock !== undefined && !ok(r.addedAtBlock, /^[0-9]+$/))) throw new Error("malformed ACL: a removal entry")
  }
}

export async function fromHeader(header: Record<string, unknown>, owner: Hex, epochKey: (epoch: number) => Uint8Array | undefined, doc: Hex): Promise<Acl> {
  const h = header as unknown as AclHeader
  if (h.v !== 1 || typeof h.epoch !== "number" || typeof h.owner !== "string" || typeof h.ownerPublicKey !== "string") throw new Error("malformed ACL")
  // the field set of spec/schema/acl-header.json: members and revoked at epoch 0, a sealed roster after
  const fields = h.epoch === 0 ? ["v", "owner", "ownerPublicKey", "epoch", "keepUntil", "wraps", "members", "revoked"] : ["v", "owner", "ownerPublicKey", "epoch", "keepUntil", "wraps", "roster"]
  const keys = Object.keys(header)
  if (fields.some((f) => !keys.includes(f)) || keys.some((k) => !fields.includes(k))) throw new Error("malformed ACL: wrong fields for its epoch")
  if (h.epoch === 0) checkRoster(h.members, h.revoked)
  if (h.owner.toLowerCase() !== owner.toLowerCase()) throw new Error("ACL owner does not match the link")
  let members: Member[] = []
  let revoked: Revoked[] = []
  let rosterHidden = false
  let prior: Record<string, Hex> | undefined
  if (h.epoch === 0) {
    members = h.members ?? []
    revoked = h.revoked ?? []
  } else {
    const key = epochKey(h.epoch)
    if (key && h.roster) {
      const r = JSON.parse(dec.decode(await open(key, hexToBytes(h.roster)))) as { doc: string; epoch: number; members: Member[]; revoked: Revoked[]; prior?: Record<string, Hex> }
      const rk = Object.keys(r).filter((k) => k !== "prior").sort().join()
      if (rk !== "doc,epoch,members,revoked") throw new Error("malformed ACL roster: wrong fields")
      if (r.prior !== undefined) {
        const ok = typeof r.prior === "object" && r.prior !== null && Object.entries(r.prior).every(([n, k]) => /^[1-9][0-9]*$/.test(n) && Number(n) < h.epoch && typeof k === "string" && /^0x[0-9a-f]{64}$/.test(k))
        if (!ok) throw new Error("malformed ACL roster: prior keys")
        prior = r.prior
      }
      checkRoster(r.members, r.revoked)
      if (r.doc !== doc.toLowerCase() || r.epoch !== h.epoch) throw new Error("ACL roster belongs to another document or epoch")
      members = r.members
      revoked = r.revoked
    } else rosterHidden = true
  }
  if (!rosterHidden && !members.some((m) => m.address.toLowerCase() === owner.toLowerCase() && m.role === "owner")) {
    throw new Error("ACL does not list its owner")
  }
  return { v: 1, owner: h.owner, ownerPublicKey: h.ownerPublicKey, epoch: h.epoch, keepUntil: h.keepUntil ?? null, wraps: Array.isArray(h.wraps) ? h.wraps : [], members, revoked, rosterHidden, ...(prior ? { prior } : {}) }
}
