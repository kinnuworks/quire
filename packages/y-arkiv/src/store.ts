/**
 * The narrow slice of Arkiv the provider needs.
 *
 * The provider talks to this interface, never to the SDK directly. That keeps
 * the sync logic testable against an in-memory chain (MemoryChain) and lets
 * the same code run against Tiramisu through SdkStore.
 */
import type { Kind } from "./protocol.js"

export type Hex = `0x${string}`

export type QuireAttributes = {
  doc: Hex
  kind: Kind
  seq: bigint
}

export type StoredEntity = {
  key: Hex
  creator: Hex
  owner: Hex
  createdAt: bigint
  /** the block of the last change: creation, extension or patch (Arkiv's updatedAt) */
  updatedAt: bigint
  expiresAt: bigint
  attributes: QuireAttributes
  payload: Uint8Array
  readonly: boolean
  permissionlessExtension: boolean
}

export type CreateSpec = {
  payload: Uint8Array
  attributes: QuireAttributes
  lifetimeSeconds: number
  /** An absolute deadline instead (Arkiv's ExpirationTime.atBlock): the entity expires at exactly this block, wherever the write lands. */
  expiresAtBlock?: bigint
  readonly?: boolean
  permissionlessExtension?: boolean
  /** Lets one batch reference keys it is about to mint (see predictKeys). */
  salt?: bigint
}

export type BatchSpec = {
  creates?: CreateSpec[]
  patches?: { key: Hex; payload: Uint8Array; attributes: QuireAttributes }[]
  extensions?: { key: Hex; lifetimeSeconds: number; expiresAtBlock?: bigint }[]
  deletes?: Hex[]
  ownershipChanges?: { key: Hex; newOwner: Hex }[]
}

export type BatchResult = { txHash: Hex; created: Hex[]; block: bigint }

export type QuerySpec = {
  doc: Hex
  kind?: Kind
  /** Inclusive lower bound on the `qs` attribute. */
  seqGte?: bigint
  /** Inclusive upper bound on the `qs` attribute. */
  seqLte?: bigint
  /** Only entities whose on-chain `$creator` is one of these. */
  creators?: Hex[]
  /** Also entities from these creators, but only with `qs` at most the bound (a removed member's edits end at their removal). */
  creatorBounds?: { address: Hex; seqLte: bigint }[]
  atBlock?: bigint
  limit?: number
  cursor?: string
}

export type QueryPage = { entities: StoredEntity[]; cursor?: string; block: bigint }

export type ChainEvent =
  | { type: "created"; key: Hex; owner: Hex; block: bigint }
  | { type: "patched"; key: Hex; owner: Hex; block: bigint }
  | { type: "extended"; key: Hex; owner: Hex; block: bigint; expiresAt: bigint }
  | { type: "deleted"; key: Hex; owner: Hex; block: bigint }
  | { type: "ownership"; key: Hex; previousOwner: Hex; newOwner: Hex; block: bigint }

export interface ArkivStore {
  /** The account this store writes as. Undefined for a read-only store. */
  readonly address: Hex | undefined
  head(): Promise<bigint>
  batch(spec: BatchSpec): Promise<BatchResult>
  predictKeys(count: number): Promise<{ key: Hex; salt: bigint }[]>
  query(spec: QuerySpec): Promise<QueryPage>
  /** One entity by key, or null if it is gone (at `block`, if given). Uses the cheapest read the network offers. */
  get(key: Hex, block?: bigint): Promise<StoredEntity | null>
  /** Live events. Must push (no polling loop) where the transport allows it. */
  watch(onEvent: (event: ChainEvent) => void, onError?: (error: Error) => void): () => void
}

/** Whether an entity passes a query's creator filter, bounded creators included (for in-memory stores). */
export function creatorMatches(spec: QuerySpec, e: StoredEntity): boolean {
  if ((spec.creators ?? []).some((c) => c.toLowerCase() === e.creator)) return true
  return (spec.creatorBounds ?? []).some((b) => b.address.toLowerCase() === e.creator && e.attributes.seq <= b.seqLte)
}

/**
 * Every page of a query, following cursors.
 *
 * A cursor is bound to the block its first page was read at, and the head
 * moves every 2 seconds. So the first page fixes the block and every later
 * page is read `atBlock` that height.
 */
export async function queryAll(store: ArkivStore, spec: QuerySpec): Promise<{ entities: StoredEntity[]; block: bigint }> {
  const first = await store.query(spec)
  const out = [...first.entities]
  let cursor = first.cursor
  while (cursor) {
    const page = await store.query({ ...spec, atBlock: spec.atBlock ?? first.block, cursor })
    out.push(...page.entities)
    cursor = page.cursor
  }
  return { entities: out, block: first.block }
}
