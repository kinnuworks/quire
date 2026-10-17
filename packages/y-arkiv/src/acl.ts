/**
 * The member list.
 *
 * One ACL entity per document, created and owned by the document owner and
 * changed only with patchEntity. Readers find it with `$creator = owner`, so a
 * forged ACL written by anyone else is never even returned by the query.
 *
 * The ACL is encrypted with the meta key: the member list is visible to link
 * holders, not to the explorer.
 */
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

export type Acl = {
  v: 1
  owner: Hex
  /** Current content epoch. Edits are encrypted with this epoch's key. */
  epoch: number
  members: Member[]
  /**
   * For epochs above 0: the epoch key wrapped for each member, by lowercase address.
   * Epoch 0's key comes from the link secret and is never wrapped.
   */
  wraps: Record<string, Hex>
  revoked: { address: Hex; atBlock: string }[]
}

export function emptyAcl(owner: Member): Acl {
  return { v: 1, owner: owner.address, epoch: 0, members: [owner], wraps: {}, revoked: [] }
}

export function isMember(acl: Acl, address: Hex | undefined): boolean {
  if (!address) return false
  const a = address.toLowerCase()
  return acl.members.some((m) => m.address.toLowerCase() === a)
}

export function memberAddresses(acl: Acl): Hex[] {
  return acl.members.map((m) => m.address.toLowerCase() as Hex)
}

export function parseAcl(header: Record<string, unknown>, owner: Hex): Acl {
  const acl = header as unknown as Acl
  if (acl.v !== 1 || typeof acl.epoch !== "number" || !Array.isArray(acl.members)) {
    throw new Error("malformed ACL")
  }
  if (acl.owner.toLowerCase() !== owner.toLowerCase()) throw new Error("ACL owner does not match the link")
  if (!acl.members.some((m) => m.address.toLowerCase() === owner.toLowerCase() && m.role === "owner")) {
    throw new Error("ACL does not list its owner")
  }
  return acl
}
