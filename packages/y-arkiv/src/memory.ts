/**
 * An in-memory Arkiv chain for tests and offline demos.
 *
 * It models the parts of Arkiv that Quire's correctness depends on: block
 * heights, immutable `$creator`, mutable `$owner`, expiry by block, readonly
 * and permissionless-extension flags, atomic batches, history for `atBlock`
 * reads, and events delivered after the block is sealed.
 */
import { randomBytes } from "./crypto.js"
import { bytesToHex } from "./hex.js"
import type {
  ArkivStore,
  BatchResult,
  BatchSpec,
  ChainEvent,
  Hex,
  QueryPage,
  QuerySpec,
  StoredEntity,
} from "./store.js"

const BLOCK_SECONDS = 2
const REQUEST_BODY_LIMIT = 256 * 1024
const PAGE = 200

type Version = { from: bigint; to: bigint | null; entity: StoredEntity }

export class ChainError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "ChainError"
  }
}

export class MemoryChain {
  block = 1n
  private versions = new Map<Hex, Version[]>()
  private listeners = new Set<(e: ChainEvent) => void>()
  private pending: ChainEvent[] = []
  /** Count of reads by kind, so tests can assert on query budgets. */
  readonly stats = { queries: 0, gets: 0, batches: 0 }

  /** Seals the current block: delivers its events and advances the height. */
  mine(blocks = 1): void {
    for (let i = 0; i < blocks; i++) {
      const events = this.pending
      this.pending = []
      this.block += 1n
      for (const e of events) for (const l of this.listeners) l(e)
    }
  }

  private live(key: Hex, at: bigint): StoredEntity | null {
    const vs = this.versions.get(key)
    if (!vs) return null
    for (const v of vs) {
      if (v.from <= at && (v.to === null || at < v.to) && v.entity.expiresAt > at) return v.entity
    }
    return null
  }

  private put(key: Hex, entity: StoredEntity): void {
    const vs = this.versions.get(key) ?? []
    const last = vs[vs.length - 1]
    if (last && last.to === null) last.to = this.block
    vs.push({ from: this.block, to: null, entity })
    this.versions.set(key, vs)
  }

  private remove(key: Hex): void {
    const last = this.versions.get(key)?.at(-1)
    if (last && last.to === null) last.to = this.block
  }

  batch(sender: Hex, spec: BatchSpec): BatchResult {
    this.stats.batches++
    // the public RPC refuses request bodies over about 256 KiB, and payloads travel hex-encoded
    const body = [...(spec.creates ?? []), ...(spec.patches ?? [])].reduce((n, c) => n + c.payload.length * 2 + 600, 0)
    if (body > REQUEST_BODY_LIMIT) throw new ChainError(`request body of ${body} bytes exceeds the RPC limit`)
    // validate everything first so the batch is atomic
    const now = this.block
    for (const p of spec.patches ?? []) {
      const e = this.live(p.key, now)
      if (!e) throw new ChainError(`patch: no entity ${p.key}`)
      if (e.owner !== sender) throw new ChainError("patch: not the owner")
      if (e.readonly) throw new ChainError("patch: entity is readonly")
    }
    for (const x of spec.extensions ?? []) {
      const e = this.live(x.key, now)
      if (!e) throw new ChainError(`extend: no entity ${x.key}`)
      if (e.owner !== sender && !e.permissionlessExtension) throw new ChainError("extend: not permitted")
      if (now + blocksOf(x.lifetimeSeconds) < e.expiresAt) throw new ChainError("extend: new expiry is earlier")
    }
    for (const k of spec.deletes ?? []) {
      const e = this.live(k, now)
      if (!e) throw new ChainError(`delete: no entity ${k}`)
      if (e.owner !== sender) throw new ChainError("delete: not the owner")
    }
    for (const o of spec.ownershipChanges ?? []) {
      const e = this.live(o.key, now)
      if (!e) throw new ChainError(`ownership: no entity ${o.key}`)
      if (e.owner !== sender) throw new ChainError("ownership: not the owner")
    }

    const created: Hex[] = []
    for (const c of spec.creates ?? []) {
      const key = (c.salt ? keyFor(sender, c.salt) : `0x${bytesToHex(randomBytes(32))}`) as Hex
      if (this.live(key, now)) throw new ChainError("create: key collision")
      this.put(key, {
        key,
        creator: sender,
        owner: sender,
        createdAt: now,
        expiresAt: now + blocksOf(c.lifetimeSeconds),
        attributes: { ...c.attributes },
        payload: c.payload.slice(),
        readonly: !!c.readonly,
        permissionlessExtension: !!c.permissionlessExtension,
      })
      created.push(key)
      this.pending.push({ type: "created", key, owner: sender, block: now })
    }
    for (const p of spec.patches ?? []) {
      const e = this.live(p.key, now)!
      this.put(p.key, { ...e, payload: p.payload.slice(), attributes: { ...p.attributes } })
      this.pending.push({ type: "patched", key: p.key, owner: e.owner, block: now })
    }
    for (const x of spec.extensions ?? []) {
      const e = this.live(x.key, now)!
      const expiresAt = now + blocksOf(x.lifetimeSeconds)
      this.put(x.key, { ...e, expiresAt })
      this.pending.push({ type: "extended", key: x.key, owner: e.owner, block: now, expiresAt })
    }
    for (const k of spec.deletes ?? []) {
      const e = this.live(k, now)!
      this.remove(k)
      this.pending.push({ type: "deleted", key: k, owner: e.owner, block: now })
    }
    for (const o of spec.ownershipChanges ?? []) {
      const e = this.live(o.key, now)!
      this.put(o.key, { ...e, owner: o.newOwner })
      this.pending.push({ type: "ownership", key: o.key, previousOwner: e.owner, newOwner: o.newOwner, block: now })
    }
    return { txHash: `0x${bytesToHex(randomBytes(32))}`, created, block: now }
  }

  query(spec: QuerySpec): QueryPage {
    this.stats.queries++
    const at = spec.atBlock ?? this.block
    const creators = spec.creators?.map((c) => c.toLowerCase())
    const all: StoredEntity[] = []
    for (const key of this.versions.keys()) {
      const e = this.live(key, at)
      if (!e) continue
      if (e.attributes.doc !== spec.doc) continue
      if (spec.kind && e.attributes.kind !== spec.kind) continue
      if (spec.seqGte !== undefined && e.attributes.seq < spec.seqGte) continue
      if (creators && !creators.includes(e.creator.toLowerCase())) continue
      all.push(e)
    }
    // Arkiv returns newest first and offers no ordering control
    all.sort((a, b) => (a.createdAt === b.createdAt ? 0 : a.createdAt > b.createdAt ? -1 : 1))
    const offset = spec.cursor ? Number(spec.cursor) : 0
    const limit = Math.min(spec.limit ?? PAGE, PAGE)
    const page = all.slice(offset, offset + limit)
    const next = offset + limit < all.length ? String(offset + limit) : undefined
    return { entities: page, cursor: next, block: at }
  }

  get(key: Hex): StoredEntity | null {
    this.stats.gets++
    return this.live(key, this.block)
  }

  watch(listener: (e: ChainEvent) => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  /** A store that writes as `address`. */
  store(address: Hex | undefined): ArkivStore {
    const chain = this
    return {
      address,
      head: async () => chain.block,
      batch: async (spec) => {
        if (!address) throw new ChainError("read-only store")
        return chain.batch(address, spec)
      },
      predictKeys: async (count) => {
        if (!address) throw new ChainError("read-only store")
        return Array.from({ length: count }, () => {
          const salt = BigInt(`0x${bytesToHex(randomBytes(16))}`)
          return { key: keyFor(address, salt), salt }
        })
      },
      query: async (spec) => chain.query(spec),
      get: async (key) => chain.get(key),
      watch: (onEvent) => chain.watch(onEvent),
    }
  }
}

function blocksOf(seconds: number): bigint {
  return BigInt(Math.ceil(seconds / BLOCK_SECONDS))
}

function keyFor(sender: Hex, salt: bigint): Hex {
  // deterministic and collision-free enough for a test chain
  return `0x${(sender.slice(2, 26).toLowerCase() + salt.toString(16).padStart(32, "0")).padEnd(64, "0").slice(0, 64)}` as Hex
}
