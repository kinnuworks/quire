/**
 * A document link carries everything a reader needs and nothing a server ever sees:
 *
 *   https://app/#/d/<doc>.<secret>.<owner>
 *
 * The part after `#` is the URL fragment. Browsers never send it in a request,
 * so the host serving the page cannot learn the secret. Apps should still move
 * it out of the address bar after reading it (see stripFragment), so it stays
 * out of browser history and screenshots.
 */
import { randomBytes } from "./crypto.js"
import { bytesToHex, fromBase64Url, hexToBytes, toBase64Url } from "./hex.js"
import type { Hex } from "./store.js"

export type DocLink = {
  /** 32-byte random document id, stored on chain as the `qd` attribute. */
  doc: Hex
  /** 32-byte link secret. Never stored anywhere on chain. */
  secret: Uint8Array
  /** The document owner's address: the trust anchor for the member list. */
  owner: Hex
}

export function newDocLink(owner: Hex): DocLink {
  return { doc: `0x${bytesToHex(randomBytes(32))}`, secret: randomBytes(32), owner }
}

export function formatDocLink(link: DocLink): string {
  return `/d/${toBase64Url(hexToBytes(link.doc))}.${toBase64Url(link.secret)}.${link.owner.slice(2).toLowerCase()}`
}

export function parseDocLink(fragment: string): DocLink | null {
  const m = /^#?\/d\/([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})\.([0-9a-fA-F]{40})$/.exec(fragment.trim())
  if (!m) return null
  const doc = fromBase64Url(m[1]!)
  const secret = fromBase64Url(m[2]!)
  if (doc.length !== 32 || secret.length !== 32) return null
  return { doc: `0x${bytesToHex(doc)}`, secret, owner: `0x${m[3]!.toLowerCase()}` }
}

export type VersionLink = { key: Hex; secret: Uint8Array }

export function formatVersionLink(link: VersionLink): string {
  return `/v/${toBase64Url(hexToBytes(link.key))}.${toBase64Url(link.secret)}`
}

export function parseVersionLink(fragment: string): VersionLink | null {
  const m = /^#?\/v\/([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})$/.exec(fragment.trim())
  if (!m) return null
  return { key: `0x${bytesToHex(fromBase64Url(m[1]!))}`, secret: fromBase64Url(m[2]!) }
}
