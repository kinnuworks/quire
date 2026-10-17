import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import * as Y from "yjs"
import { ArkivProvider, type Identity } from "../src/provider.js"
import { type DocLink, newDocLink } from "../src/link.js"
import { MemoryChain } from "../src/memory.js"
import type { Hex } from "../src/store.js"

export function identity(name: string): Identity {
  const privateKey = generatePrivateKey()
  return { address: privateKeyToAccount(privateKey).address.toLowerCase() as Hex, privateKey, name }
}

export type Peer = { doc: Y.Doc; provider: ArkivProvider; id: Identity | undefined }

export async function peer(chain: MemoryChain, link: DocLink, id: Identity | undefined): Promise<Peer> {
  const doc = new Y.Doc()
  const provider = new ArkivProvider(doc, { store: chain.store(id?.address), link, identity: id, flushIntervalMs: 0, autoCompact: false })
  await provider.connect()
  return { doc, provider, id }
}

/** Seals a block and waits until every peer has processed the events. */
export async function settle(chain: MemoryChain, peers: Peer[], blocks = 1): Promise<void> {
  chain.mine(blocks)
  for (let i = 0; i < 3; i++) await Promise.all(peers.map((p) => p.provider.idle()))
}

export async function newDocument(chain: MemoryChain, ownerName = "owner") {
  const owner = identity(ownerName)
  const link = newDocLink(owner.address)
  await ArkivProvider.createDocument({ store: chain.store(owner.address), link, identity: owner })
  chain.mine()
  return { owner, link }
}

/** Owner approves `who` after it requests to join. */
export async function admit(chain: MemoryChain, owner: Peer, who: Peer): Promise<void> {
  await who.provider.requestJoin()
  await settle(chain, [owner, who])
  await owner.provider.approve(who.id!.address)
  await settle(chain, [owner, who])
}

export function text(p: Peer): string {
  return p.doc.getText("t").toString()
}
