/**
 * ArkivStore on a real Arkiv network, through @arkiv-network/sdk 0.8.
 *
 * Reads that the app makes on every keystroke from a peer go through the raw
 * `arkiv_getEntity` method, which the public RPC does not bill against the
 * keyless query budget. The SDK's getEntity() goes through `arkiv_query`
 * and would be billed (see /arkiv/friction.md).
 *
 * Live events need a WebSocket transport and no `fromBlock`: anything else
 * makes watchEntityEvents fall back to polling without saying so.
 */
import {
  createPublicClient,
  createWalletClient,
  type Entity,
  ExpirationTime,
  type PublicArkivClient,
  type WalletArkivClient,
} from "@arkiv-network/sdk"
import { addr, bytes32, str, u64 } from "@arkiv-network/sdk/attr"
import { tiramisu } from "@arkiv-network/sdk/chains"
import { and, eq, type Expression, gte, or } from "@arkiv-network/sdk/query"
import { type Account, type Chain, type EIP1193Provider, custom, http, type Transport, webSocket } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { hexToBytes } from "./hex.js"
import { CONTENT_TYPE, KIND, type Kind, PROTOCOL_TAG } from "./protocol.js"
import type { ArkivStore, BatchResult, BatchSpec, ChainEvent, CreateSpec, Hex, QueryPage, QuerySpec, StoredEntity } from "./store.js"

export const TIRAMISU_HTTP = "https://rpc.tiramisu.db-chain.testnet.arkiv.network"
export const TIRAMISU_WS = "wss://rpc.tiramisu.db-chain.testnet.arkiv.network"

/** The keyless query budget ran out. Thrown at once, instead of waiting out a long Retry-After in silence. */
export class QueryBudgetError extends Error {
  constructor(readonly retryAfterSeconds: number) {
    super(`Arkiv's free query budget for this address ran out. It refills in about ${Math.ceil(retryAfterSeconds / 60)} minutes, or use an access key.`)
    this.name = "QueryBudgetError"
  }
}

/**
 * fetch for viem's http transport: adds the access key, and turns a 429 into
 * QueryBudgetError. Without this, viem honours a Retry-After of up to half an
 * hour without a word, and the app looks frozen (see friction.md).
 */
function arkivFetch(accessKey: string | undefined): typeof fetch {
  return async (input, init) => {
    const headers = new Headers(init?.headers)
    if (accessKey) headers.set("x-api-key", accessKey)
    const res = await fetch(input, { ...init, headers })
    if (res.status === 429) throw new QueryBudgetError(Number(res.headers.get("retry-after") ?? "60"))
    return res
  }
}

export type SdkStoreOptions = {
  chain?: Chain
  httpUrl?: string
  wsUrl?: string
  /** Writes as this key. Omit for a read-only store. */
  privateKey?: Hex
  /** Or write through an injected wallet such as MetaMask. */
  injected?: { provider: EIP1193Provider; address: Hex }
  /** An Arkiv access key, for scripts and servers. Never ship one in browser code: it would be public. */
  accessKey?: string
}

type RpcEntity = {
  key: Hex
  owner: Hex
  creator: Hex
  createdAt: Hex
  expiresAt: Hex
  creationFlags?: { readonly?: boolean; permissionlessExtension?: boolean } | number
  payload?: Hex
  attributes?: { name: string; type: string; value: unknown }[]
}

const KINDS = new Set<string>(Object.values(KIND))

export class SdkStore implements ArkivStore {
  readonly address: Hex | undefined
  readonly reader: PublicArkivClient<Transport, Chain>
  readonly socket: PublicArkivClient<Transport, Chain>
  readonly wallet: WalletArkivClient<Transport, Chain, Account> | undefined
  /** Every network call by kind, for the in-app "what this cost" panel. */
  readonly calls = { query: 0, getEntity: 0, write: 0 }

  constructor(options: SdkStoreOptions = {}) {
    const chain = options.chain ?? tiramisu
    const transport = () => http(options.httpUrl ?? TIRAMISU_HTTP, { fetchFn: arkivFetch(options.accessKey), retryCount: 0 })
    this.reader = createPublicClient({ chain, transport: transport() }) as PublicArkivClient<Transport, Chain>
    this.socket = createPublicClient({
      chain,
      transport: webSocket(options.wsUrl ?? TIRAMISU_WS, { reconnect: { attempts: 1_000, delay: 1_000 }, keepAlive: { interval: 20_000 } }),
    }) as PublicArkivClient<Transport, Chain>
    if (options.privateKey) {
      const account = privateKeyToAccount(options.privateKey)
      this.address = account.address.toLowerCase() as Hex
      this.wallet = createWalletClient({ chain, transport: transport(), account }) as unknown as WalletArkivClient<Transport, Chain, Account>
    } else if (options.injected) {
      this.address = options.injected.address.toLowerCase() as Hex
      this.wallet = createWalletClient({
        chain,
        transport: custom(options.injected.provider),
        account: options.injected.address,
      }) as unknown as WalletArkivClient<Transport, Chain, Account>
    }
  }

  async head(): Promise<bigint> {
    return this.reader.getBlockNumber()
  }

  async predictKeys(count: number): Promise<{ key: Hex; salt: bigint }[]> {
    if (!this.address) throw new Error("read-only store")
    const keys = await this.reader.predictEntityKeys({ owner: this.address, count })
    return keys.map((k) => ({ key: k.key.toLowerCase() as Hex, salt: k.salt as bigint }))
  }

  async batch(spec: BatchSpec): Promise<BatchResult> {
    if (!this.wallet) throw new Error("read-only store")
    this.calls.write++
    const result = await this.wallet.executeBatch({
      creates: spec.creates?.map(toCreate),
      patches: spec.patches?.map((p) => ({ entityKey: p.key, payload: p.payload, contentType: CONTENT_TYPE, set: toAttributes(p.attributes) })),
      extensions: spec.extensions?.map((x) => ({ entityKey: x.key, expires: ExpirationTime.fromSeconds(x.lifetimeSeconds) })),
      deletes: spec.deletes?.map((k) => ({ entityKey: k })),
      ownershipChanges: spec.ownershipChanges?.map((o) => ({ entityKey: o.key, newOwner: o.newOwner })),
    })
    const receipt = await this.reader.getTransactionReceipt({ hash: result.txHash })
    return {
      txHash: result.txHash,
      created: result.createdEntities.map((k) => k.toLowerCase() as Hex),
      block: receipt.blockNumber,
    }
  }

  async query(spec: QuerySpec): Promise<QueryPage> {
    this.calls.query++
    const page = await this.reader.query(toExpression(spec), {
      select: "*",
      limit: spec.limit ?? 200,
      cursor: spec.cursor,
      atBlock: spec.atBlock,
    })
    const entities: StoredEntity[] = []
    for (const e of page.entities) {
      const s = fromSdkEntity(e)
      if (s) entities.push(s)
    }
    return { entities, cursor: page.cursor, block: page.blockNumber }
  }

  async get(key: Hex): Promise<StoredEntity | null> {
    this.calls.getEntity++
    const raw = (await this.reader.request({ method: "arkiv_getEntity", params: [key] } as never)) as RpcEntity | null
    return raw ? fromRpcEntity(raw) : null
  }

  watch(onEvent: (event: ChainEvent) => void, onError?: (error: Error) => void): () => void {
    // WebSocket transport and no fromBlock: one eth_subscribe, no polling loop
    return this.socket.watchEntityEvents({
      onEvent: (e) => {
        switch (e.type) {
          case "EntityCreated":
            return onEvent({ type: "created", key: lower(e.entityKey), owner: lower(e.owner), block: e.blockNumber })
          case "EntityPatched":
            return onEvent({ type: "patched", key: lower(e.entityKey), owner: lower(e.owner), block: e.blockNumber })
          case "ExpiryExtended":
            return onEvent({ type: "extended", key: lower(e.entityKey), owner: lower(e.owner), block: e.blockNumber, expiresAt: e.expiresAt })
          case "EntityDeleted":
            return onEvent({ type: "deleted", key: lower(e.entityKey), owner: lower(e.owner), block: e.blockNumber })
          case "OwnershipTransferred":
            return onEvent({ type: "ownership", key: lower(e.entityKey), previousOwner: lower(e.previousOwner), newOwner: lower(e.newOwner), block: e.blockNumber })
        }
      },
      onError: (err) => onError?.(err),
    })
  }
}

function lower(h: string): Hex {
  return h.toLowerCase() as Hex
}

function toAttributes(a: { doc: Hex; kind: Kind; seq: bigint }) {
  return { qp: str(PROTOCOL_TAG), qd: bytes32(a.doc), qk: str(a.kind), qs: u64(a.seq) }
}

function toCreate(c: CreateSpec) {
  return {
    payload: c.payload,
    contentType: CONTENT_TYPE,
    attributes: toAttributes(c.attributes),
    expires: ExpirationTime.fromSeconds(c.lifetimeSeconds),
    flags: { readonly: !!c.readonly, permissionlessExtension: !!c.permissionlessExtension },
    ...(c.salt !== undefined ? { salt: c.salt } : {}),
  }
}

/** Typed predicates only: a bare value compared with a typed attribute silently matches nothing. */
export function toExpression(spec: QuerySpec): Expression {
  const parts: Expression[] = [eq("qp", str(PROTOCOL_TAG)), eq("qd", bytes32(spec.doc))]
  if (spec.kind) parts.push(eq("qk", str(spec.kind)))
  if (spec.seqGte !== undefined) parts.push(gte("qs", u64(spec.seqGte)))
  if (spec.creators?.length) {
    const byCreator = spec.creators.map((c) => eq("$creator", addr(c)))
    parts.push(byCreator.length === 1 ? byCreator[0]! : or(byCreator))
  }
  return and(parts)
}

function fromSdkEntity(e: Entity): StoredEntity | null {
  const a = e.attributes ?? {}
  const qd = a.qd?.value
  const qk = a.qk?.value
  const qs = a.qs?.value
  if (!e.key || !e.creator || !e.owner || typeof qd !== "string" || typeof qk !== "string" || !KINDS.has(qk)) return null
  return {
    key: lower(e.key),
    creator: lower(e.creator),
    owner: lower(e.owner),
    createdAt: e.createdAt ?? 0n,
    expiresAt: e.expiresAt ?? 0n,
    attributes: { doc: lower(qd), kind: qk as Kind, seq: typeof qs === "bigint" ? qs : 0n },
    payload: e.payload ?? new Uint8Array(),
    readonly: !!e.creationFlags?.readonly,
    permissionlessExtension: !!e.creationFlags?.permissionlessExtension,
  }
}

function fromRpcEntity(e: RpcEntity): StoredEntity | null {
  const attrs = new Map((e.attributes ?? []).map((a) => [a.name, a.value]))
  const qd = attrs.get("qd")
  const qk = attrs.get("qk")
  const qs = attrs.get("qs")
  if (typeof qd !== "string" || typeof qk !== "string" || !KINDS.has(qk)) return null
  const flags = typeof e.creationFlags === "number" ? { readonly: !!(e.creationFlags & 1), permissionlessExtension: !!(e.creationFlags & 2) } : (e.creationFlags ?? {})
  return {
    key: lower(e.key),
    creator: lower(e.creator),
    owner: lower(e.owner),
    createdAt: BigInt(e.createdAt),
    expiresAt: BigInt(e.expiresAt),
    attributes: { doc: lower(qd), kind: qk as Kind, seq: typeof qs === "string" ? BigInt(qs) : 0n },
    payload: e.payload ? hexToBytes(e.payload) : new Uint8Array(),
    readonly: !!flags.readonly,
    permissionlessExtension: !!flags.permissionlessExtension,
  }
}
