/**
 * Per-document identities and saved links, kept in this browser only.
 *
 * Each document gets its own fresh key. Two documents opened by the same
 * person show two unrelated addresses on the explorer, so nobody can map who
 * works with whom across documents. The key is a throwaway: it holds a few
 * cents of testnet gas and the right to write to one document.
 */
import { tiramisu } from "@arkiv-network/sdk/chains"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import { type DocLink, formatDocLink, type Hex, type Identity, parseDocLink } from "y-arkiv"

const ID = "quire:id:"
const LINK = "quire:link:"
const NAME = "quire:name"
const NODE = "quire:node"

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

/** Removes a document's saved link and key from this browser. */
export function forgetDocument(doc: Hex): void {
  try {
    localStorage.removeItem(LINK + doc)
    localStorage.removeItem(ID + doc)
  } catch {
    // nothing stored
  }
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

// ------------------------------------------------------------------ Arkiv node

/**
 * The Arkiv node this browser reads and writes through, if the visitor chose one. Whoever runs the node
 * sees the visitor's IP address, the document ids they open and the members' addresses, so they may want
 * their own, or their newsroom's, instead of Arkiv's public endpoint. Saving reloads the page, so every
 * store is created after the choice.
 */
export type ArkivNode = { httpUrl: string; wsUrl: string }

const LOCAL = new Set(["localhost", "127.0.0.1", "[::1]"])

/** The WebSocket URL on the same host: https becomes wss, http becomes ws. */
export function wsFor(httpUrl: string): string {
  return httpUrl.replace(/^http/, "ws")
}

// https and wss only, plus plain http and ws on this machine for development
function checkUrl(raw: string, secure: string, plain: string): string | null {
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    return null
  }
  if (u.username || u.password) return null
  if (u.protocol === secure || (u.protocol === plain && LOCAL.has(u.hostname))) return u.href.replace(/\/$/, "")
  return null
}

export function customNode(): ArkivNode | null {
  const raw = read(NODE)
  if (!raw) return null
  try {
    const v = JSON.parse(raw) as Partial<ArkivNode>
    const httpUrl = checkUrl(v.httpUrl ?? "", "https:", "http:")
    const wsUrl = checkUrl(v.wsUrl ?? "", "wss:", "ws:")
    return httpUrl && wsUrl ? { httpUrl, wsUrl } : null
  } catch {
    return null
  }
}

/** Options for every SdkStore the app creates: empty for Arkiv's public endpoint. */
export function nodeOptions(): { httpUrl?: string; wsUrl?: string } {
  return customNode() ?? {}
}

/**
 * Checks the URLs and that the node serves Tiramisu, then saves them. Returns what went wrong, or null.
 * Both URLs are saved together: half a custom node would still send document ids to the public endpoint.
 */
export async function saveNode(http: string, ws: string): Promise<string | null> {
  const httpUrl = checkUrl(http.trim(), "https:", "http:")
  if (!httpUrl) return "The RPC URL must start with https:// (http:// only for localhost)."
  const wsUrl = checkUrl(ws.trim() || wsFor(httpUrl), "wss:", "ws:")
  if (!wsUrl) return "The WebSocket URL must start with wss:// (ws:// only for localhost)."
  let chainId: number
  try {
    const res = await fetch(httpUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
      signal: AbortSignal.timeout(10_000),
    })
    const body = (await res.json()) as { result?: string }
    chainId = Number(body.result)
  } catch {
    return "That node did not answer. Check the URL, and that it accepts requests from this site (CORS)."
  }
  if (chainId !== tiramisu.id) {
    return `That node serves chain ${Number.isFinite(chainId) ? chainId : "unknown"}, not Arkiv's Tiramisu testnet (${tiramisu.id}), where Quire documents live.`
  }
  write(NODE, JSON.stringify({ httpUrl, wsUrl }))
  return customNode() ? null : "This browser could not save the setting (storage is blocked)."
}

export function resetNode(): void {
  try {
    localStorage.removeItem(NODE)
  } catch {
    // nothing stored
  }
}
