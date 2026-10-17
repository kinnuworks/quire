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

export type Revoked = { address: Hex; atBlock: string }

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

export function memberAddresses(acl: Acl): Hex[] {
  return acl.members.map((m) => m.address.toLowerCase() as Hex)
}

const enc = new TextEncoder()
const dec = new TextDecoder()

export async function toHeader(acl: Acl, epochKey: Uint8Array | undefined, doc: Hex): Promise<AclHeader> {
  const base = { v: 1 as const, owner: acl.owner, ownerPublicKey: acl.ownerPublicKey, epoch: acl.epoch, keepUntil: acl.keepUntil, wraps: acl.wraps }
  if (acl.epoch === 0) return { ...base, members: acl.members, revoked: acl.revoked }
  if (!epochKey) throw new Error("sealing the roster needs the current epoch key")
  // the roster names its document and epoch, so it cannot be replayed into another ACL
  const roster = await seal(epochKey, enc.encode(JSON.stringify({ doc: doc.toLowerCase(), epoch: acl.epoch, members: acl.members, revoked: acl.revoked })))
  return { ...base, roster: `0x${bytesToHex(roster)}` }
}

/**
 * Validates a header and opens its roster. `epochKey` is the current epoch's
 * key if this session holds it; without it an epoch 1+ roster stays hidden.
 */
export async function fromHeader(header: Record<string, unknown>, owner: Hex, epochKey: (epoch: number) => Uint8Array | undefined, doc: Hex): Promise<Acl> {
  const h = header as unknown as AclHeader
  if (h.v !== 1 || typeof h.epoch !== "number" || typeof h.owner !== "string" || typeof h.ownerPublicKey !== "string") throw new Error("malformed ACL")
  if (h.owner.toLowerCase() !== owner.toLowerCase()) throw new Error("ACL owner does not match the link")
  let members: Member[] = []
  let revoked: Revoked[] = []
  let rosterHidden = false
  if (h.epoch === 0) {
    members = h.members ?? []
    revoked = h.revoked ?? []
  } else {
    const key = epochKey(h.epoch)
    if (key && h.roster) {
      const r = JSON.parse(dec.decode(await open(key, hexToBytes(h.roster)))) as { doc: string; epoch: number; members: Member[]; revoked: Revoked[] }
      if (r.doc !== doc.toLowerCase() || r.epoch !== h.epoch) throw new Error("ACL roster belongs to another document or epoch")
      members = r.members
      revoked = r.revoked
    } else rosterHidden = true
  }
  if (!rosterHidden && !members.some((m) => m.address.toLowerCase() === owner.toLowerCase() && m.role === "owner")) {
    throw new Error("ACL does not list its owner")
  }
  return { v: 1, owner: h.owner, ownerPublicKey: h.ownerPublicKey, epoch: h.epoch, keepUntil: h.keepUntil ?? null, wraps: Array.isArray(h.wraps) ? h.wraps : [], members, revoked, rosterHidden }
}
