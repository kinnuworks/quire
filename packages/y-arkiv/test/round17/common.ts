import * as Y from "yjs"
import { MemoryChain } from "../../src/memory.js"
import { ArkivProvider } from "../../src/provider.js"
import type { DocLink } from "../../src/link.js"
import type { ArkivStore, Hex } from "../../src/store.js"
import { admit, identity, newDocument, peer, settle, type Peer } from "../helpers.js"

export type AclLike = { members: { address: string }[]; revoked: unknown[] }
/** The owner erases a member from the list (no removal entry), as the contested demo does. */
export async function erase(chain: MemoryChain, owner: Peer, who: Peer, others: Peer[] = []): Promise<void> {
  await (owner.provider as unknown as { updateAcl: (f: (acl: AclLike) => Promise<object>) => Promise<void> }).updateAcl(async (acl) => {
    acl.members = acl.members.filter((m) => m.address !== who.id!.address)
    acl.revoked = []
    return {}
  })
  await settle(chain, [owner, who, ...others])
}

export async function typeSlowly(chain: MemoryChain, p: Peer, others: Peer[], s: string, at?: number): Promise<void> {
  let pos = at ?? p.doc.getText("t").length
  for (const words of s.match(/.{1,12}/gs)!) {
    p.doc.getText("t").insert(pos, words)
    pos += words.length
    await p.provider.flush()
    await settle(chain, [p, ...others])
  }
}

export function counting(store: ArkivStore): ArkivStore & { queries: number } {
  const s = { ...store, queries: 0 } as ArkivStore & { queries: number }
  s.query = async (q) => {
    s.queries++
    return store.query(q)
  }
  return s
}

export async function audit(chain: MemoryChain, link: DocLink, store?: ArkivStore, identity?: import("../../src/provider.js").Identity): Promise<{ doc: Y.Doc; p: ArkivProvider }> {
  const doc = new Y.Doc()
  const p = new ArkivProvider(doc, { store: store ?? chain.store(undefined), link, flushIntervalMs: 0, autoCompact: false, resyncIntervalMs: 0, readOnly: true, fullHistory: true, identity })
  await p.connect()
  return { doc, p }
}

export async function setup() {
  const chain = new MemoryChain()
  const { owner, link } = await newDocument(chain)
  const a = await peer(chain, link, owner)
  const bea = await peer(chain, link, identity("bea"))
  await admit(chain, a, bea)
  return { chain, owner, link, a, bea }
}
export type { Hex }
