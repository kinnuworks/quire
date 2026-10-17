/**
 * Per-document identities and saved links, kept in this browser only.
 *
 * Each document gets its own fresh key. Two documents opened by the same
 * person show two unrelated addresses on the explorer, so nobody can map who
 * works with whom across documents. The key is a throwaway: it holds a few
 * cents of testnet gas and the right to write to one document.
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import { type DocLink, formatDocLink, type Hex, type Identity, parseDocLink } from "y-arkiv"

const ID = "quire:id:"
const LINK = "quire:link:"
const NAME = "quire:name"

function read(key: string): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

function write(key: string, value: string): void {
  try {
    localStorage.setItem(key, value)
  } catch {
    // private windows: the session still works, it just will not survive a reload
  }
}

export function preferredName(): string {
  return read(NAME) ?? ""
}

export function setPreferredName(name: string): void {
  write(NAME, name)
}

export function newIdentity(name: string): Identity {
  const privateKey = generatePrivateKey()
  return { address: privateKeyToAccount(privateKey).address.toLowerCase() as Hex, privateKey, name }
}

export function identityFor(doc: Hex): Identity | undefined {
  const raw = read(ID + doc)
  if (!raw) return undefined
  try {
    const v = JSON.parse(raw) as { privateKey: Hex; name: string }
    return { address: privateKeyToAccount(v.privateKey).address.toLowerCase() as Hex, privateKey: v.privateKey, name: v.name }
  } catch {
    return undefined
  }
}

export function saveIdentity(doc: Hex, id: Identity): void {
  write(ID + doc, JSON.stringify({ privateKey: id.privateKey, name: id.name }))
}

export function saveLink(link: DocLink): void {
  write(LINK + link.doc, formatDocLink(link))
}

export function linkFor(doc: Hex): DocLink | null {
  const raw = read(LINK + doc)
  return raw ? parseDocLink(raw) : null
}

export function knownDocuments(): { doc: Hex; link: DocLink }[] {
  const out: { doc: Hex; link: DocLink }[] = []
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)
      if (!k?.startsWith(LINK)) continue
      const link = parseDocLink(localStorage.getItem(k) ?? "")
      if (link) out.push({ doc: link.doc, link })
    }
  } catch {
    // no storage, no list
  }
  return out
}

export function shareUrl(link: DocLink): string {
  return `${location.origin}${location.pathname}#${formatDocLink(link)}`
}
