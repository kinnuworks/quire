/**
 * ArkivProvider: a Yjs provider whose only backend is Arkiv.
 *
 * Edits made during one block are merged into a single encrypted update
 * entity. Peers receive it over a WebSocket subscription and fetch it by key.
 * Joining a document costs three queries: the ACL, the newest snapshots, and
 * the updates written since. A snapshot is a lease that every active session
 * renews; updates expire once snapshots make them redundant.
 */
import * as Y from "yjs"
import { recoverMessageAddress } from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { Observable } from "lib0/observable"
import { type Acl, emptyAcl, fromHeader, isMember, type Member, memberAddresses, toHeader } from "./acl.js"
import { decodeFrame, decodeOuter, encodeFrame, encodeOuter, equalBytes, type Frame } from "./codec.js"
import {
  addressOfPublicKey,
  deriveEpochZeroKey,
  deriveMetaKey,
  open,
  clientIdFor,
  openWith,
  publicKeyOf,
  randomBytes,
  seal,
  sealTo,
  unwrapAsMember,
  wrapForMember,
} from "./crypto.js"
import { bytesToHex, fromBase64Url, hexToBytes, toBase64Url } from "./hex.js"
import type { DocLink, VersionLink } from "./link.js"
import {
  CATCH_UP_MARGIN_BLOCKS,
  COMPACT_AFTER_BYTES,
  COMPACT_AFTER_UPDATES,
  FLUSH_INTERVAL_MS,
  KIND,
  type Kind,
  LEASE_RENEW_FRACTION,
  LIFETIME,
  MAX_BATCH_PAYLOAD_BYTES,
  MAX_CHUNK_PLAINTEXT,
  STRANGER_FETCHES_PER_MINUTE,
} from "./protocol.js"
import { type ArkivStore, type BatchResult, type BatchSpec, type ChainEvent, type CreateSpec, type Hex, queryAll, type StoredEntity } from "./store.js"

export type Identity = {
  address: Hex
  privateKey: Hex
  /** Display name shown to collaborators. Pick a pseudonym; it is encrypted, but still yours. */
  name: string
}

export type Role = "owner" | "writer" | "pending" | "reader"

export type ProviderStatus = "connecting" | "synced" | "error" | "destroyed"

export type JoinRequest = { key: Hex; address: Hex; publicKey: Hex; name: string; block: bigint }

export type RemoteEdit = {
  author: Hex
  entity: Hex
  block: bigint
  bytes: number
  /** Wall-clock time from the writer's flush to this peer applying it, if both clocks agree. */
  latencyMs: number | undefined
}

export type HistoryEntry = { block: bigint; author: Hex; update: Uint8Array; entity: Hex }

/** `via`: for claimed authorship, the member whose snapshot carried it. */
export type Authorship = { address: Hex; proven: boolean; via?: Hex }

export type FlushInfo = { txHash: Hex; block: bigint; bytes: number; entity: Hex }

export type ProviderStats = {
  queries: number
  gets: number
  writes: number
  updatesApplied: number
  snapshotsApplied: number
  /** Entities for this document from addresses outside the ACL. Never applied. */
  rejectedWrites: number
}

/** A snapshot that decoded and passed its own checks, waiting on the verified-clock check before it counts. */
type PendingSnapshot = { state: Uint8Array; commit: () => void }

export type ProviderOptions = {
  store: ArkivStore
  link: DocLink
  identity?: Identity
  /** Milliseconds between automatic flushes. 0 disables the timer; call flush() yourself. */
  flushIntervalMs?: number
  /** Compact automatically once enough updates pile up, and after typing stops. Default true. */
  autoCompact?: boolean
  /**
   * Read every live update when opening, not only those after the newest snapshot. Costs the same
   * one query plus more pages; every edit still on chain then counts as proven. For audits.
   */
  fullHistory?: boolean
  /** Re-read recent updates this often, to cover a dropped socket. 0 disables. Default 15 minutes. */
  resyncIntervalMs?: number
  /** Compact this long after the last flush if anything is uncovered. Default 2 minutes. */
  idleCompactMs?: number
  /** Up to this many extra milliseconds, at random, before each flush. Default 2 s. */
  flushJitterMs?: number
  now?: () => number
  /**
   * The client id salt. Pass the one used with prepareDoc() when an editor binds
   * to the doc before the provider exists; otherwise a fresh one is made here.
   */
  salt?: Uint8Array
}

/**
 * Gives a Y.Doc the client id derived from `address` before anything edits it.
 * Use when an editor is attached to the doc before the provider is created,
 * and pass the returned salt to the provider.
 */
export function prepareDoc(doc: Y.Doc, address: string): Uint8Array {
  const salt = randomBytes(16)
  doc.clientID = clientIdFor(address, salt)
  return salt
}



export class ArkivProvider extends Observable<string> {
  readonly doc: Y.Doc
  readonly link: DocLink
  readonly store: ArkivStore
  readonly identity: Identity | undefined
  readonly stats: ProviderStats = { queries: 0, gets: 0, writes: 0, updatesApplied: 0, snapshotsApplied: 0, rejectedWrites: 0 }

  status: ProviderStatus = "connecting"
  acl: Acl | null = null
  aclKey: Hex | null = null
  joinRequests: JoinRequest[] = []
  /** Newest snapshot we know of: the lease the document lives on. */
  snapshot: { key: Hex; base: bigint; expiresAt: bigint; chunks: Hex[]; creator: Hex } | null = null
  /** Expiry block of the ACL entity. */
  aclExpiresAt: bigint | null = null
  /** `qs` of the ACL version we applied: a patch always writes a newer one. */
  private aclSeq: bigint | null = null

  private readonly metaKey: Uint8Array
  private readonly epochKeys = new Map<number, Uint8Array>()
  private readonly seen = new Set<string>()
  private readonly authors = new Map<number, Hex>()
  /** Authorship carried inside snapshots: the address matches the client id, but the content is the compactor's word. */
  private readonly claimedAuthors = new Map<number, Hex>()
  /** This session's client id salt, sent with every edit so readers can check the id against our address. */
  private salt: Uint8Array
  /** Salt and signature for every client id we can attribute, carried forward into snapshot headers. */
  private readonly salts = new Map<number, string>()
  private readonly sigs = new Map<number, Hex>()
  /** For text attributed only through a snapshot: who wrote that snapshot. */
  private readonly claimedVia = new Map<number, Hex>()
  /** Our signature over (document, salt): proof that this client id is ours, for later snapshots to carry. */
  private saltSig: Hex | null = null
  /** Every edit applied since the newest snapshot, oldest first, for time travel. */
  readonly history: HistoryEntry[] = []
  /** The newest snapshot's state: the starting point for time travel. */
  baseState: Uint8Array | null = null
  private pending: Uint8Array[] = []
  private updatesSinceSnapshot = 0
  private bytesSinceSnapshot = 0
  private writeQueue: Promise<unknown> = Promise.resolve()
  private work: Promise<unknown> = Promise.resolve()
  private unwatch: (() => void) | null = null
  private timer: ReturnType<typeof setTimeout> | null = null
  private readonly flushJitterMs: number
  private resyncTimer: ReturnType<typeof setInterval> | null = null
  private idleTimer: ReturnType<typeof setTimeout> | null = null
  private readonly resyncInterval: number
  private readonly idleCompactMs: number
  /** Entities that could not be read yet (key not unwrapped, chunk not visible); retried later. */
  private deferred = new Map<Hex, StoredEntity>()
  private readonly now: () => number
  private readonly autoCompact: boolean
  private readonly fullHistory: boolean
  private readonly onDocUpdate: (update: Uint8Array, origin: unknown) => void

  constructor(doc: Y.Doc, options: ProviderOptions) {
    super()
    this.doc = doc
    this.link = options.link
    this.store = options.store
    this.identity = options.identity
    this.now = options.now ?? Date.now
    this.autoCompact = options.autoCompact ?? true
    this.fullHistory = options.fullHistory ?? false
    // each resync and each compaction costs one query from the keyless budget (about 100 per IP per window)
    this.resyncInterval = options.resyncIntervalMs ?? 15 * 60_000
    this.idleCompactMs = options.idleCompactMs ?? 120_000
    this.flushJitterMs = options.flushJitterMs ?? 2_000
    this.metaKey = deriveMetaKey(this.link.secret)
    this.epochKeys.set(0, deriveEpochZeroKey(this.link.secret))
    this.salt = options.salt ?? randomBytes(16)
    if (this.identity) {
      // our Yjs client id is derived from our address, so nobody else can write under it
      const id = clientIdFor(this.identity.address, this.salt)
      if (doc.clientID !== id && doc.store.clients.has(doc.clientID)) {
        throw new Error("the doc was edited before the provider set its client id; use prepareDoc()")
      }
      doc.clientID = id
      this.authors.set(doc.clientID, this.identity.address.toLowerCase() as Hex)
      this.salts.set(doc.clientID, bytesToHex(this.salt))
    }

    this.onDocUpdate = (update, origin) => {
      if (origin === this) return
      if (this.role !== "owner" && this.role !== "writer") return
      this.pending.push(update)
    }
    doc.on("update", this.onDocUpdate)

    const interval = options.flushIntervalMs ?? FLUSH_INTERVAL_MS
    if (interval > 0) {
      // a random delay on each flush, so write times on chain say less about when someone typed
      const tick = () => {
        this.timer = setTimeout(() => {
          if (this.pending.length) void this.flush().catch((e) => this.emit("error", [e]))
          if (this.status !== "destroyed") tick()
        }, interval + Math.floor(Math.random() * (this.flushJitterMs + 1)))
      }
      tick()
    }
  }

  // ---------------------------------------------------------------- creation

  /**
   * Creates a new document owned by `identity`: the ACL and a first snapshot
   * land in one atomic batch, so a document never exists without its member list.
   */
  static async createDocument(options: { store: ArkivStore; link: DocLink; identity: Identity; doc?: Y.Doc }): Promise<{ aclKey: Hex; snapshotKey: Hex }> {
    const { store, link, identity } = options
    if (identity.address.toLowerCase() !== link.owner.toLowerCase()) throw new Error("the link owner must be the creating identity")
    const head = await store.head()
    const owner: Member = {
      address: identity.address.toLowerCase() as Hex,
      publicKey: `0x${bytesToHex(publicKeyOf(identity.privateKey))}`,
      name: identity.name,
      role: "owner",
      addedAtBlock: head.toString(),
    }
    const acl = emptyAcl(owner)
    const metaKey = deriveMetaKey(link.secret)
    const contentKey = deriveEpochZeroKey(link.secret)
    const state = Y.encodeStateAsUpdate(options.doc ?? new Y.Doc())
    // the member list and the first snapshot land in the same transaction
    const w = await writeSnapshotEntities(store, link.doc, 0, contentKey, state, head, Date.now(), KIND.snapshot, {}, LIFETIME.snapshot, {
      creates: [await aclSpec(link.doc, metaKey, acl, undefined, head)],
    })
    return { aclKey: w.result.created[0]!, snapshotKey: w.headKey }
  }

  // ---------------------------------------------------------------- roles

  get role(): Role {
    if (!this.acl || !this.identity) return "reader"
    const me = this.identity.address.toLowerCase()
    if (me === this.acl.owner.toLowerCase()) return "owner"
    if (isMember(this.acl, this.identity.address)) return "writer"
    if (this.joinRequests.some((j) => j.address.toLowerCase() === me)) return "pending"
    return "reader"
  }

  /** Can this session decrypt current edits? Readers with an old link lose access after a revocation. */
  get canRead(): boolean {
    return !!this.acl && !this.acl.rosterHidden && this.epochKeys.has(this.acl.epoch)
  }

  /**
   * Who wrote a Yjs client's edits. `proven` means we applied that client's
   * update from an entity whose on-chain `$creator` is this address. Otherwise
   * the name came from a snapshot header and is only as good as its compactor.
   */
  authorOf(clientId: number): Authorship | undefined {
    const proven = this.authors.get(clientId)
    if (proven) return { address: proven, proven: true }
    const claimed = this.claimedAuthors.get(clientId)
    return claimed ? { address: claimed, proven: false, via: this.claimedVia.get(clientId) } : undefined
  }

  members(): Member[] {
    return this.acl?.members ?? []
  }

  // ---------------------------------------------------------------- sync

  async connect(): Promise<void> {
    this.setStatus("connecting")
    if (this.identity && !this.saltSig) {
      this.saltSig = await privateKeyToAccount(this.identity.privateKey).signMessage({ message: { raw: saltMessage(this.link.doc, this.salt) } })
      this.sigs.set(this.doc.clientID, this.saltSig)
    }
    try {
      this.unwatch = this.store.watch(
        (e) => this.enqueue(() => this.onChainEvent(e)),
        (err) => this.emit("error", [err]),
      )
      await this.loadAcl()
      await this.loadState()
      if (this.role === "owner") await this.loadJoinRequests()
      this.setStatus("synced")
    } catch (e) {
      this.setStatus("error")
      throw e
    }
    // housekeeping never fails the connection: a lost race with another member is fine
    this.renewLeaseIfDue().catch((e) => this.emit("error", [e]))
    if (this.resyncInterval > 0) {
      this.resyncTimer = setInterval(() => void this.resync({ joins: true }).catch((e) => this.emit("error", [e])), this.resyncInterval)
    }
  }

  private setStatus(s: ProviderStatus): void {
    this.status = s
    this.emit("status", [s])
  }

  private async loadAcl(): Promise<void> {
    this.stats.queries++
    const page = await this.store.query({ doc: this.link.doc, kind: KIND.acl, creators: [this.link.owner], limit: 20 })
    // the first entity that is really the owner's ACL; an RPC that ignores the creator filter cannot slip in another
    for (const entity of page.entities) {
      try {
        await this.applyAclEntity(entity)
      } catch {
        continue
      }
      if (this.aclKey === entity.key) return
    }
    throw new Error("document not found: no ACL from the owner in the link")
  }

  private async applyAclEntity(entity: StoredEntity): Promise<void> {
    if (entity.creator.toLowerCase() !== this.link.owner.toLowerCase()) return
    const frame = await this.openEntity(entity, KIND.acl)
    if (!frame) return
    // unwrap the current epoch key first if this session is a member: it opens the sealed roster
    const epoch = typeof frame.header.epoch === "number" ? frame.header.epoch : 0
    const wraps = (Array.isArray(frame.header.wraps) ? frame.header.wraps : []) as Hex[]
    if (epoch > 0 && !this.epochKeys.has(epoch) && this.identity) {
      // wraps carry no labels: try each, and the one sealed to us opens
      for (const w of wraps) {
        try {
          this.epochKeys.set(epoch, await unwrapAsMember(hexToBytes(w), this.identity.privateKey, epoch))
          break
        } catch {
          // sealed to someone else
        }
      }
    }
    const acl = await fromHeader(frame.header, this.link.owner, (n) => this.epochKeys.get(n), this.link.doc)
    this.acl = acl
    this.aclKey = entity.key
    this.aclSeq = entity.attributes.seq
    this.aclExpiresAt = entity.expiresAt
    this.joinRequests = this.joinRequests.filter((j) => !isMember(acl, j.address))
    this.emit("acl", [acl])
  }

  private async loadState(): Promise<void> {
    // without the roster we do not know whose entities to trust, and could not decrypt them anyway
    if (!this.acl || this.acl.rosterHidden) return
    const writers = memberAddresses(this.acl)
    this.stats.queries++
    const snaps = await queryAll(this.store, { doc: this.link.doc, kind: KIND.snapshot, creators: writers })
    // order by the writer's block height (qs), newest first; Arkiv does not promise any order.
    // Apply every snapshot close to the newest base, which covers concurrent compactions.
    const ordered = [...snaps.entities].sort((x, y) => (x.attributes.seq === y.attributes.seq ? 0 : x.attributes.seq > y.attributes.seq ? -1 : 1))
    // Apply the newest readable snapshot of EACH member, not just the newest overall: one member's
    // (possibly empty or stale) snapshot must not hide what another member's snapshot holds.
    // Updates are read from the oldest of those bases, so nothing between them is skipped.
    const states: PendingSnapshot[] = []
    const covered = new Set<string>()
    let oldestBase: bigint | null = null
    for (const s of ordered) {
      const creator = s.creator.toLowerCase()
      if (covered.has(creator)) continue
      const applied = await this.applySnapshotEntity(s, states)
      if (applied === null) continue
      covered.add(creator)
      if (oldestBase === null || applied < oldestBase) oldestBase = applied
    }
    const from = !this.fullHistory && oldestBase !== null && oldestBase > CATCH_UP_MARGIN_BLOCKS ? oldestBase - CATCH_UP_MARGIN_BLOCKS : 0n
    this.stats.queries++
    const updates = await queryAll(this.store, { doc: this.link.doc, kind: KIND.update, creators: writers, seqGte: from })
    // oldest first is not required by Yjs, but it keeps intermediate states sensible
    // binding depends on order, so every reader uses the same one: creation block, then key
    const byAge = [...updates.entities].sort((x, y) => (x.createdAt !== y.createdAt ? (x.createdAt < y.createdAt ? -1 : 1) : x.key < y.key ? -1 : x.key > y.key ? 1 : 0))
    const historyBefore = this.history.length
    for (const u of byAge) await this.applyUpdateEntity(u, false)
    const verified = this.history.slice(historyBefore).map((h) => h.update)
    for (const st of states) {
      // A verified update can be pending, waiting on text only a snapshot holds. When the snapshot fills the
      // gap, Yjs keeps the snapshot's struct at that clock. So try each snapshot on a scratch copy first, and
      // refuse it if any verified clock would end up with different content.
      const trial = new Y.Doc()
      Y.applyUpdate(trial, Y.encodeStateAsUpdate(this.doc))
      Y.applyUpdate(trial, st.state)
      if (overridesVerified(trial, verified)) {
        this.reject()
        continue
      }
      this.applyRemote(st.state)
      st.commit()
    }
    this.updatesSinceSnapshot = updates.entities.length
  }

  /**
   * One page of join requests (up to 200). The document id is public, so anyone can write junk
   * `j` entities; following every page would let them drain the owner's query budget.
   */
  private async loadJoinRequests(): Promise<void> {
    this.stats.queries++
    const page = await this.store.query({ doc: this.link.doc, kind: KIND.join, limit: 200 })
    for (const e of page.entities) await this.applyJoinEntity(e)
  }

  /**
   * Owner: looks up one address's join request directly, with a `$creator` filter. Junk requests
   * can push a real one out of the first page, but they cannot hide it from this query.
   */
  async findJoinRequest(address: Hex): Promise<JoinRequest | null> {
    if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return null
    this.stats.queries++
    const page = await this.store.query({ doc: this.link.doc, kind: KIND.join, creators: [address], limit: 20 })
    for (const e of page.entities) await this.applyJoinEntity(e)
    return this.joinRequests.find((j) => j.address === address.toLowerCase()) ?? null
  }

  private enqueue(fn: () => Promise<void>): void {
    this.work = this.work.then(fn).catch((e) => this.emit("error", [e]))
  }

  /** Resolves once every queued event and write has been processed. */
  async idle(): Promise<void> {
    let before: Promise<unknown>
    do {
      before = this.work
      await Promise.all([this.work, this.writeQueue])
    } while (before !== this.work)
  }

  private async onChainEvent(e: ChainEvent): Promise<void> {
    if (this.status === "destroyed" || !this.acl) return
    if (e.type === "patched" && e.key === this.aclKey) {
      const entity = await this.fetch(e.key)
      if (entity) {
        const before = this.acl.epoch
        const writersBefore = memberAddresses(this.acl).join()
        await this.applyAclEntity(entity)
        // a new epoch brings a new snapshot; a new member may already have edits waiting
        if (this.acl.epoch !== before || memberAddresses(this.acl).join() !== writersBefore) await this.loadState()
        await this.retryDeferred()
        // after a key rotation, a writer folds its state under the new key straight away, so anything it
        // wrote under the old key before seeing the rotation is covered by new-epoch content
        if (this.acl.epoch !== before && (this.role === "writer" || this.role === "owner") && this.canRead && this.role !== "owner") {
          void this.compact().catch((err) => this.emit("error", [err]))
        }
      }
      return
    }
    if (e.type === "extended" && this.snapshot && e.key === this.snapshot.key) {
      this.snapshot.expiresAt = e.expiresAt
      this.emit("lease", [this.snapshot])
      return
    }
    if (e.type !== "created" || this.seen.has(e.key)) return
    // dedupe by entity key, not by creator: two tabs with the same key must still see each other
    const creator = e.owner.toLowerCase() as Hex
    const known = memberAddresses(this.acl).includes(creator)
    // non-members can only matter to the owner (join requests); everyone else skips the fetch.
    // The owner fetches strangers' entities at a capped rate, so a flood elsewhere on the chain costs little.
    if (!known && (this.role !== "owner" || !this.allowStrangerFetch())) return
    const entity = await this.fetch(e.key)
    if (!entity) {
      // a node behind the one that sent the event: retry once a block later, outside the queue
      if (!this.retried.has(e.key)) {
        this.retried.add(e.key)
        setTimeout(() => this.enqueue(() => this.onChainEvent(e)), 2500)
      }
      return
    }
    if (entity.attributes.doc !== this.link.doc) return
    if (!known) {
      if (entity.attributes.kind === KIND.join) await this.applyJoinEntity(entity)
      else this.reject()
      return
    }
    if (entity.attributes.kind === KIND.update) await this.applyUpdateEntity(entity, true)
    else if (entity.attributes.kind === KIND.snapshot) await this.applyLiveSnapshot(entity)
  }

  /** Clock ranges per client id that arrived in verified live updates: the only text we call proven. */
  private readonly proven = new Map<number, [number, number][]>()
  private readonly provenAt = new Map<number, { from: number; to: number; block: bigint; entity: Hex }[]>()

  private markProven(meta: { from: Map<number, number>; to: Map<number, number> }, block: bigint, entity: Hex): void {
    for (const [client, from] of meta.from) {
      const to = meta.to.get(client) ?? from
      const list = this.proven.get(client) ?? []
      list.push([from, to])
      this.proven.set(client, list)
      const where = this.provenAt.get(client) ?? []
      where.push({ from, to, block, entity })
      this.provenAt.set(client, where)
    }
  }

  /** The update entity, and its block, that proved this clock; undefined if a snapshot alone carried it. */
  provenanceOf(client: number, clock: number): { block: bigint; entity: Hex } | undefined {
    const hit = (this.provenAt.get(client) ?? []).find((r) => r.from <= clock && clock < r.to)
    return hit && { block: hit.block, entity: hit.entity }
  }

  /**
   * Who wrote one Yjs item. Proven only if the item's clock came in a verified
   * live update; text that exists only inside a snapshot is claimed, naming
   * the member whose snapshot carried it, even if the same client id also
   * has proven edits elsewhere.
   */
  authorOfItem(client: number, clock: number, length = 1): Authorship | undefined {
    const mine = client === this.doc.clientID && this.identity
    // Yjs merges adjacent items from one client, so check the item's whole clock range
    const inRange = mine || this.coveredByProven(client, clock, clock + length)
    const address = this.authors.get(client) ?? this.claimedAuthors.get(client)
    if (!address) return undefined
    return inRange ? { address, proven: true } : { address, proven: false, via: this.claimedVia.get(client) }
  }

  private coveredByProven(client: number, from: number, to: number): boolean {
    const ranges = [...(this.proven.get(client) ?? [])].sort((x, y) => x[0] - y[0])
    let reach = from
    for (const [a, b] of ranges) {
      if (a > reach) break
      if (b > reach) reach = b
      if (reach >= to) return true
    }
    return reach >= to
  }

  /**
   * Applies remote bytes. If Yjs decides our client id clashes with incoming
   * structs it silently picks a random one, which readers would then reject:
   * re-derive a fresh id from our address before anything else is typed.
   */
  private applyRemote(update: Uint8Array): void {
    const before = this.doc.clientID
    Y.applyUpdate(this.doc, update, this)
    if (this.identity && this.doc.clientID !== before) void this.rekey()
  }

  private async rekey(): Promise<void> {
    if (!this.identity) return
    const salt = randomBytes(16)
    this.salt = salt
    this.doc.clientID = clientIdFor(this.identity.address, salt)
    this.saltSig = await privateKeyToAccount(this.identity.privateKey).signMessage({ message: { raw: saltMessage(this.link.doc, salt) } })
    this.authors.set(this.doc.clientID, this.identity.address.toLowerCase() as Hex)
    this.salts.set(this.doc.clientID, bytesToHex(salt))
    this.sigs.set(this.doc.clientID, this.saltSig)
    this.emit("rekey", [this.doc.clientID])
  }

  private async retryDeferred(): Promise<void> {
    for (const e of [...this.deferred.values()]) {
      if (e.attributes.kind === KIND.update) await this.applyUpdateEntity(e, false)
      else if (e.attributes.kind === KIND.snapshot) await this.applyLiveSnapshot(e)
    }
  }

  private readonly retried = new Set<string>()
  private strangerFetches: number[] = []
  private allowStrangerFetch(): boolean {
    const now = this.now()
    this.strangerFetches = this.strangerFetches.filter((t) => now - t < 60_000)
    if (this.strangerFetches.length >= STRANGER_FETCHES_PER_MINUTE) return false
    this.strangerFetches.push(now)
    return true
  }

  private reject(): void {
    this.stats.rejectedWrites++
    this.emit("rejected", [this.stats.rejectedWrites])
  }

  private async fetch(key: Hex): Promise<StoredEntity | null> {
    this.stats.gets++
    return this.store.get(key)
  }

  /** Applies one update. Never throws: a malformed entity from any member is ignored, not fatal. */
  private async applyUpdateEntity(entity: StoredEntity, live: boolean): Promise<void> {
    try {
      await this.applyUpdateEntityInner(entity, live)
    } catch {
      this.seen.add(entity.key)
      this.deferred.delete(entity.key)
      this.reject()
    }
  }

  private async applyUpdateEntityInner(entity: StoredEntity, live: boolean): Promise<void> {
    if (this.seen.has(entity.key)) return
    if (!this.acl || !isMember(this.acl, entity.creator)) {
      this.seen.add(entity.key)
      return this.reject()
    }
    const frame = await this.openEntity(entity, KIND.update)
    if (!frame) {
      // most often a newer epoch whose key arrives with the next ACL patch
      this.deferred.set(entity.key, entity)
      return
    }
    this.seen.add(entity.key)
    this.deferred.delete(entity.key)
    // qs is the writer's view of the chain head; it cannot be later than the block the entity landed in.
    // A far-future qs would otherwise push the edit into every catch-up window forever.
    if (entity.attributes.seq > entity.createdAt) return this.reject()
    // the edit's client id must derive from its creator's address with a salt the creator signed
    if (!(await this.checkAuthors(frame.data, entity.creator, frame.header.salt, frame.header.sig))) return this.reject()
    const meta = Y.parseUpdateMeta(frame.data)
    const svBefore = Y.decodeStateVector(Y.encodeStateVector(this.doc))
    this.applyRemote(frame.data)
    if (overridesVerified(this.doc, [frame.data])) {
      // a snapshot already put different text at this edit's clocks: this session has diverged from
      // the chain's genuine edits. Nothing here is proven; a fresh load (updates before snapshots) heals it.
      this.emit("diverged", [entity.key])
    } else {
      // proven: only clocks this update actually integrated, not ones a snapshot had already filled
      const fresh = { from: new Map<number, number>(), to: meta.to }
      for (const [c, from] of meta.from) fresh.from.set(c, Math.max(from, svBefore.get(c) ?? 0))
      this.markProven(fresh, entity.createdAt, entity.key)
    }
    this.pushHistory({ block: entity.createdAt, author: entity.creator.toLowerCase() as Hex, update: frame.data, entity: entity.key })
    this.stats.updatesApplied++
    this.updatesSinceSnapshot++
    this.bytesSinceSnapshot += frame.data.length
    if (live) {
      const t = typeof frame.header.t === "number" ? frame.header.t : undefined
      const edit: RemoteEdit = {
        author: entity.creator.toLowerCase() as Hex,
        entity: entity.key,
        block: entity.createdAt,
        bytes: entity.payload.length,
        latencyMs: t === undefined ? undefined : Math.max(0, this.now() - t),
      }
      this.emit("remote-edit", [edit])
    }
  }

  /** Applies a snapshot and returns its base block, or null if it could not be read. Never throws. */
  private async applySnapshotEntity(entity: StoredEntity, collect: PendingSnapshot[]): Promise<bigint | null> {
    try {
      return await this.applySnapshotEntityInner(entity, collect)
    } catch {
      this.seen.add(entity.key)
      this.deferred.delete(entity.key)
      this.reject()
      return null
    }
  }

  private async applySnapshotEntityInner(entity: StoredEntity, collect: PendingSnapshot[]): Promise<bigint | null> {
    if (this.seen.has(entity.key)) return this.snapshot?.key === entity.key ? this.snapshot.base : null
    if (!this.acl || !isMember(this.acl, entity.creator)) {
      this.seen.add(entity.key)
      this.reject()
      return null
    }
    const frame = await this.openEntity(entity, KIND.snapshot)
    if (!frame) {
      this.deferred.set(entity.key, entity)
      return null
    }
    const base = BigInt(String(frame.header.base ?? "x").replace(/[^0-9]/g, "") || "-1")
    if (base < 0n || base > entity.createdAt || entity.attributes.seq > entity.createdAt) {
      // a snapshot cannot cover blocks after the one it landed in
      this.seen.add(entity.key)
      this.reject()
      return null
    }
    const chunks = Array.isArray(frame.header.chunks) ? (frame.header.chunks as Hex[]) : []
    const parts = [frame.data]
    for (const [i, key] of chunks.entries()) {
      const chunk = await this.fetch(key)
      if (!chunk) {
        // not visible yet on this node; try again later rather than lose the snapshot
        this.deferred.set(entity.key, entity)
        return null
      }
      // a chunk must come from the snapshot's own creator and name its snapshot id, or the snapshot is discarded
      const cf = chunk.creator.toLowerCase() === entity.creator.toLowerCase() ? await this.openEntity(chunk, KIND.chunk, frame.epoch) : null
      if (!cf || cf.header.i !== i + 1 || cf.header.of !== frame.header.id) {
        this.seen.add(entity.key)
        return null
      }
      parts.push(cf.data)
    }
    this.seen.add(entity.key)
    this.deferred.delete(entity.key)
    const state = concat(parts)
    // a snapshot must not carry structs under this session's own client id beyond what we wrote:
    // that would be someone writing as us, and Yjs would then re-randomise our id and mute us
    const ours = Y.parseUpdateMeta(state).to.get(this.doc.clientID)
    if (this.identity && ours !== undefined && ours > (Y.decodeStateVector(Y.encodeStateVector(this.doc)).get(this.doc.clientID) ?? 0)) {
      this.reject()
      return null
    }
    const claims: { client: number; address: Hex; salt: string; sig: Hex }[] = []
    const claimed = frame.header.authors
    if (claimed && typeof claimed === "object") {
      for (const [client, entry] of Object.entries(claimed as Record<string, { address?: string; salt?: string; sig?: string }>)) {
        // a claim counts only if the address and salt derive that client id and the address signed the salt;
        // a compactor cannot invent a client id for someone who never wrote
        if (
          typeof entry?.address === "string" &&
          typeof entry.salt === "string" &&
          /^[0-9a-f]{32}$/.test(entry.salt) &&
          clientIdFor(entry.address, hexToBytes(entry.salt)) === Number(client) &&
          (await signedBy(this.link.doc, entry.salt, entry.sig, entry.address as Hex))
        ) {
          claims.push({ client: Number(client), address: entry.address.toLowerCase() as Hex, salt: entry.salt, sig: entry.sig as Hex })
        }
      }
    }
    // nothing about this snapshot is kept yet: the caller first checks it against the verified edits
    // (see overridesVerified) and commits it only if it passes, so a refused snapshot never becomes
    // the lease, the history base or a source of claimed authors
    collect.push({ state, commit: () => this.commitSnapshot(entity, base, chunks, state, claims) })
    return base
  }

  private commitSnapshot(entity: StoredEntity, base: bigint, chunks: Hex[], state: Uint8Array, claims: { client: number; address: Hex; salt: string; sig: Hex }[]): void {
    for (const c of claims) {
      this.claimedAuthors.set(c.client, c.address)
      this.claimedVia.set(c.client, entity.creator.toLowerCase() as Hex)
      this.salts.set(c.client, c.salt)
      this.sigs.set(c.client, c.sig)
    }
    this.stats.snapshotsApplied++
    if (!this.snapshot || base >= this.snapshot.base) {
      this.baseState = state
      this.history.splice(0, this.history.length, ...this.history.filter((h) => h.block >= base))
      this.snapshot = { key: entity.key, base, expiresAt: entity.expiresAt, chunks, creator: entity.creator.toLowerCase() as Hex }
      this.updatesSinceSnapshot = 0
      this.bytesSinceSnapshot = 0
      this.emit("lease", [this.snapshot])
    }
  }

  /** A snapshot that arrives after load gets the same check as on load before it counts for anything. */
  private async applyLiveSnapshot(entity: StoredEntity): Promise<void> {
    const pending: PendingSnapshot[] = []
    await this.applySnapshotEntity(entity, pending)
    for (const st of pending) {
      const trial = new Y.Doc()
      Y.applyUpdate(trial, Y.encodeStateAsUpdate(this.doc))
      Y.applyUpdate(trial, st.state)
      if (overridesVerified(trial, this.history.map((h) => h.update))) {
        this.reject()
        continue
      }
      this.applyRemote(st.state)
      st.commit()
    }
  }

  private async applyJoinEntity(entity: StoredEntity): Promise<void> {
    if (this.joinRequests.some((j) => j.key === entity.key)) return
    const frame = await this.openEntity(entity, KIND.join)
    if (!frame) return
    const publicKey = String(frame.header.publicKey ?? "") as Hex
    // the request must be signed by the key it asks us to trust
    let derived: Hex
    try {
      derived = addressOfPublicKey(hexToBytes(publicKey))
    } catch {
      return
    }
    if (derived.toLowerCase() !== entity.creator.toLowerCase()) return
    if (this.acl && isMember(this.acl, entity.creator)) return
    const request: JoinRequest = {
      key: entity.key,
      address: entity.creator.toLowerCase() as Hex,
      publicKey,
      name: String(frame.header.name ?? "").slice(0, 40),
      block: entity.createdAt,
    }
    this.joinRequests.push(request)
    this.emit("join-request", [request])
  }

  /**
   * An edit may only carry structs under the client id its creator derives
   * from the salt in the edit's header: clientIdFor(creator, salt). Anything
   * else is someone writing under another member's name.
   */
  private async checkAuthors(update: Uint8Array, author: Hex, salt: unknown, sig: unknown): Promise<boolean> {
    if (typeof salt !== "string" || !/^[0-9a-f]{32}$/.test(salt)) return false
    // the writer signed (document, salt), so a later snapshot can carry this attribution with proof
    if (!(await signedBy(this.link.doc, salt, sig, author))) return false
    const expected = clientIdFor(author, hexToBytes(salt))
    // parseUpdateMeta covers structs at any clock; encodeStateVectorFromUpdate only counts
    // runs that start at clock 0, so it misses every update after a writer's first
    const clients = [...Y.parseUpdateMeta(update).from.keys()]
    if (clients.some((c) => c !== expected)) return false
    // and a client id already in use by one address cannot be taken over by another: a collision
    // would have to be found before the victim's random salt was ever published
    const holder = this.authors.get(expected) ?? this.claimedAuthors.get(expected)
    if (holder && holder !== author.toLowerCase()) return false
    this.authors.set(expected, author.toLowerCase() as Hex)
    this.salts.set(expected, salt)
    this.sigs.set(expected, sig as Hex)
    return true
  }

  // ---------------------------------------------------------------- crypto plumbing

  private keyFor(kind: Kind, epoch: number): Uint8Array | undefined {
    if (kind === KIND.acl) return this.metaKey
    return this.epochKeys.get(epoch)
  }

  private async openEntity(entity: StoredEntity, kind: Kind, epochHint?: number): Promise<Frame | null> {
    if (entity.attributes.kind !== kind || entity.attributes.doc !== this.link.doc) return null
    try {
      const { epoch, envelope } = decodeOuter(entity.payload)
      if (epochHint !== undefined && epoch !== epochHint) return null
      let plain: Uint8Array
      if (kind === KIND.join) {
        // join requests are sealed to the owner's public key; only the owner opens them
        if (this.role !== "owner" || !this.identity) return null
        plain = await openWith(this.identity.privateKey, envelope, "join")
      } else {
        const key = this.keyFor(kind, epoch)
        if (!key) return null
        plain = await open(key, envelope)
      }
      const frame = decodeFrame(plain)
      if (frame.kind !== kind || frame.epoch !== epoch || !equalBytes(frame.doc, hexToBytes(this.link.doc))) return null
      return frame
    } catch {
      return null
    }
  }

  private currentContentKey(): { epoch: number; key: Uint8Array } {
    if (!this.acl) throw new Error("not connected")
    const key = this.epochKeys.get(this.acl.epoch)
    if (!key) throw new Error(`no key for epoch ${this.acl.epoch}`)
    return { epoch: this.acl.epoch, key }
  }

  // ---------------------------------------------------------------- writes

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.writeQueue.then(fn, fn)
    this.writeQueue = next.catch(() => undefined)
    return next
  }

  private assertWriter(): void {
    if (this.role !== "owner" && this.role !== "writer") throw new Error("this session is not a member of the document")
  }

  /** Writes everything typed since the last flush as one update entity. */
  async flush(): Promise<FlushInfo | null> {
    return this.serial(async () => {
      if (!this.pending.length) return null
      this.assertWriter()
      const updates = this.pending
      this.pending = []
      try {
        return await this.flushUpdates(updates)
      } catch (e) {
        // nothing landed: put the edits back in front of anything typed meanwhile
        this.pending = [...updates, ...this.pending]
        throw e
      }
    })
  }

  private async flushUpdates(updates: Uint8Array[]): Promise<FlushInfo | null> {
    {
      const merged = Y.mergeUpdates(updates)
      if (merged.length > MAX_CHUNK_PLAINTEXT - 256) {
        // too big for one update: fold everything into a snapshot instead (the state already holds these edits)
        return this.writeSnapshot()
      }
      const { epoch, key } = this.currentContentKey()
      const head = await this.store.head()
      const header = { t: this.now(), salt: bytesToHex(this.salt), sig: this.saltSig }
      const payload = encodeOuter(epoch, await seal(key, encodeFrame({ kind: KIND.update, doc: hexToBytes(this.link.doc), epoch, header, data: merged }, randomBytes)))
      const result = await this.store.batch({
        // an edit lives as long as a snapshot would: it must never expire before one covers it
        creates: [{ payload, attributes: { doc: this.link.doc, kind: KIND.update, seq: head }, lifetimeSeconds: this.snapshotLifetime(head) }],
      })
      this.stats.writes++
      const entity = result.created[0]!
      this.seen.add(entity)
      if (this.identity) this.pushHistory({ block: result.block, author: this.identity.address.toLowerCase() as Hex, update: merged, entity })
      this.updatesSinceSnapshot++
      this.bytesSinceSnapshot += merged.length
      const info: FlushInfo = { txHash: result.txHash, block: result.block, bytes: payload.length, entity }
      this.emit("flush", [info])
      if (this.autoCompact && this.idleCompactMs > 0) {
        // once typing stops, fold everything into a snapshot so no edit outlives its cover
        if (this.idleTimer) clearTimeout(this.idleTimer)
        this.idleTimer = setTimeout(() => {
          if (this.updatesSinceSnapshot > 0 && !this.pending.length) void this.compact().catch((e) => this.emit("error", [e]))
        }, this.idleCompactMs)
      }
      if (this.autoCompact && (this.updatesSinceSnapshot >= COMPACT_AFTER_UPDATES || this.bytesSinceSnapshot >= COMPACT_AFTER_BYTES)) {
        void this.compact().catch((e) => this.emit("error", [e]))
      }
      return info
    }
  }

  /**
   * Folds the whole document into a new snapshot. Safe to run on several
   * peers at once: Yjs merges are idempotent, so readers apply every recent
   * snapshot and converge. Nothing is deleted; covered updates simply expire.
   */
  async compact(): Promise<FlushInfo> {
    return this.serial(() => this.writeSnapshot())
  }

  /**
   * Re-reads every update since the newest snapshot's base. A snapshot must
   * contain all updates older than its own base (minus the in-flight margin),
   * or a late joiner would never see an edit this session missed live.
   */
  async resync(options: { joins?: boolean } = {}): Promise<number> {
    if (!this.acl) return 0
    // a member-list change missed during a socket gap: re-read the ACL by key (not billed as a query)
    if (this.aclKey) {
      const acl = await this.fetch(this.aclKey)
      if (acl && (acl.attributes.seq !== this.aclSeq || this.acl.rosterHidden)) {
        const before = this.acl.epoch
        await this.applyAclEntity(acl)
        if (this.acl.epoch !== before) await this.loadState()
      }
    }
    if (this.acl.rosterHidden) return 0
    const base = this.snapshot?.base ?? 0n
    const from = base > CATCH_UP_MARGIN_BLOCKS ? base - CATCH_UP_MARGIN_BLOCKS : 0n
    this.stats.queries++
    const updates = await queryAll(this.store, { doc: this.link.doc, kind: KIND.update, creators: memberAddresses(this.acl), seqGte: from })
    const before = this.stats.updatesApplied
    const byAge = [...updates.entities].sort((x, y) => (x.createdAt !== y.createdAt ? (x.createdAt < y.createdAt ? -1 : 1) : x.key < y.key ? -1 : x.key > y.key ? 1 : 0))
    for (const u of byAge) await this.applyUpdateEntity(u, false)
    // a join request missed live (socket gap, stranger-fetch cap) is picked up on the periodic resync
    if (options.joins && this.role === "owner") await this.loadJoinRequests()
    return this.stats.updatesApplied - before
  }

  private async writeSnapshot(extra: BatchSpec = {}): Promise<FlushInfo> {
    this.assertWriter()
    const { epoch, key } = this.currentContentKey()
    await this.resync()
    const head = await this.store.head()
    // anything still buffered is already in the doc state, so the snapshot covers it;
    // keep it aside in case the write fails
    const held = this.pending
    this.pending = []
    const state = Y.encodeStateAsUpdate(this.doc)
    const lifetime = this.snapshotLifetime(head)
    // replace my previous snapshot rather than pile up a new full copy every session
    const previous = this.snapshot && this.snapshot.creator === this.identity!.address.toLowerCase() ? [this.snapshot.key, ...this.snapshot.chunks] : []
    let written
    try {
      written = await writeSnapshotEntities(this.store, this.link.doc, epoch, key, state, head, this.now(), KIND.snapshot, this.authorTable(state), lifetime, {
        ...extra,
        deletes: [...(extra.deletes ?? []), ...previous],
      })
    } catch (e) {
      this.pending = [...held, ...this.pending]
      throw e
    }
    const { result, headKey: snapKey, chunks, bytes } = written
    this.stats.writes += written.transactions
    for (const k of [snapKey, ...chunks]) this.seen.add(k)
    this.snapshot = {
      key: snapKey,
      base: head,
      expiresAt: head + blocks(lifetime),
      chunks,
      creator: this.identity!.address.toLowerCase() as Hex,
    }
    this.updatesSinceSnapshot = 0
    this.bytesSinceSnapshot = 0
    this.baseState = state
    this.history.length = 0
    this.emit("lease", [this.snapshot])
    const info: FlushInfo = { txHash: result.txHash, block: result.block, bytes, entity: snapKey }
    this.emit("compact", [info])
    return info
  }

  /**
   * The lifetime a new snapshot gets: the default 30-day lease, or longer if
   * the owner asked to keep the document until a later block.
   */
  private snapshotLifetime(head: bigint): number {
    const until = this.acl?.keepUntil ? BigInt(this.acl.keepUntil) : 0n
    return Math.max(LIFETIME.snapshot, Number(until - head) * BLOCK_SECONDS)
  }

  /**
   * The lease. Once less than half of the newest snapshot's life is left, an
   * active member renews it: by extending it if they created it, or by writing
   * a fresh snapshot of their own if someone else did. Only a snapshot's own
   * creator can extend it, so nobody outside the member list can keep the text
   * alive. The member list allows anyone to extend it, so members renew it too.
   * A document nobody opens for a month expires.
   */
  async renewLeaseIfDue(): Promise<boolean> {
    if (!this.snapshot || !this.identity || !this.acl) return false
    if (this.role !== "owner" && this.role !== "writer") return false
    const head = await this.store.head()
    const life = blocks(LIFETIME.snapshot)
    const due = (expiresAt: bigint | null) => expiresAt !== null && expiresAt - head < BigInt(Math.floor(Number(life) * LEASE_RENEW_FRACTION))
    const me = this.identity.address.toLowerCase()
    const snapshotDue = due(this.snapshot.expiresAt)
    const aclDue = due(this.aclExpiresAt)
    if (!snapshotDue && !aclDue) return false
    if (snapshotDue && (this.snapshot.creator !== me || this.updatesSinceSnapshot > 0)) {
      // a fresh snapshot renews the lease and folds in every uncovered edit at once
      await this.compact()
      if (!aclDue) return true
    }
    await this.serial(async () => {
      const extensions: { key: Hex; lifetimeSeconds: number }[] = []
      // Arkiv reverts an extension that does not move expiry later, so only send ones that do
      const later = (current: bigint | null, seconds: number) => current === null || head + blocks(seconds) > current
      if (snapshotDue && this.snapshot!.creator === me && later(this.snapshot!.expiresAt, LIFETIME.snapshot)) {
        for (const k of [this.snapshot!.key, ...this.snapshot!.chunks]) extensions.push({ key: k, lifetimeSeconds: LIFETIME.snapshot })
      }
      if (aclDue && this.aclKey && later(this.aclExpiresAt, LIFETIME.acl)) extensions.push({ key: this.aclKey, lifetimeSeconds: LIFETIME.acl })
      if (!extensions.length) return
      await this.store.batch({ extensions })
      this.stats.writes++
      if (snapshotDue && this.snapshot!.creator === me) this.snapshot!.expiresAt = head + life
      if (aclDue) this.aclExpiresAt = head + blocks(LIFETIME.acl)
      this.emit("lease", [this.snapshot])
    })
    return true
  }

  /**
   * Owner: keep the document for at least `seconds` from now. The target is
   * recorded in the member list, so every later compaction honours it; the
   * member list itself is extended, and a fresh snapshot is written with the
   * longer life. Arkiv only lets an extension move expiry later, so shortening
   * is done with deleteDocument instead.
   */
  async keepFor(seconds: number): Promise<void> {
    if (this.role !== "owner" || !this.aclKey) throw new Error("only the owner sets the document lifetime")
    const head = await this.store.head()
    const keepUntil = head + blocks(seconds)
    if (this.aclExpiresAt !== null && keepUntil <= this.aclExpiresAt) throw new Error("the document already lives longer than that; use delete to end it sooner")
    await this.updateAcl(async (acl) => {
      acl.keepUntil = keepUntil.toString()
      return {}
    })
    await this.serial(async () => {
      if (this.aclExpiresAt === null || this.aclExpiresAt < keepUntil) {
        await this.store.batch({ extensions: [{ key: this.aclKey!, lifetimeSeconds: seconds }] })
        this.stats.writes++
        this.aclExpiresAt = keepUntil
      }
    })
    await this.compact()
  }

  /**
   * Owner: ends the document now. Deletes the member list and every entity the
   * owner created, in one batch. Without the member list no reader can verify
   * any edit, so the document stops opening immediately; members' remaining
   * encrypted entities run out on their own expiry (30 days, or the keepUntil date).
   */
  async deleteDocument(): Promise<number> {
    if (this.role !== "owner" || !this.identity) throw new Error("only the owner deletes the document")
    const me = this.identity.address
    return this.serial(async () => {
      this.stats.queries++
      const mine = await queryAll(this.store, { doc: this.link.doc, creators: [me] })
      const keys = mine.entities.filter((e) => e.owner.toLowerCase() === me.toLowerCase() && !e.readonly).map((e) => e.key)
      await this.store.batch({ deletes: keys })
      this.stats.writes++
      this.emit("deleted", [keys.length])
      return keys.length
    })
  }

  // ---------------------------------------------------------------- membership

  /** Asks the owner to add this session. The request carries our public key and expires in an hour. */
  async requestJoin(): Promise<Hex> {
    if (!this.identity) throw new Error("joining needs an identity")
    return this.serial(async () => {
      const head = await this.store.head()
      const header = { publicKey: `0x${bytesToHex(publicKeyOf(this.identity!.privateKey))}`, name: this.identity!.name }
      if (!this.acl) throw new Error("not connected")
      // sealed to the owner's public key: other link holders, including removed members, cannot read it
      const frame = encodeFrame({ kind: KIND.join, doc: hexToBytes(this.link.doc), epoch: 0, header, data: new Uint8Array() }, randomBytes)
      const payload = encodeOuter(0, await sealTo(hexToBytes(this.acl.ownerPublicKey), frame, "join"))
      const result = await this.store.batch({
        creates: [{ payload, attributes: { doc: this.link.doc, kind: KIND.join, seq: head }, lifetimeSeconds: LIFETIME.join }],
      })
      this.stats.writes++
      const key = result.created[0]!
      this.joinRequests.push({ key, address: this.identity!.address.toLowerCase() as Hex, publicKey: header.publicKey as Hex, name: header.name, block: head })
      this.emit("acl", [this.acl])
      return key
    })
  }

  /** Owner: adds the member behind a join request. */
  async approve(address: Hex): Promise<void> {
    const req = this.joinRequests.find((j) => j.address.toLowerCase() === address.toLowerCase())
    if (!req) throw new Error("no join request from that address")
    await this.updateAcl(async (acl, head) => {
      acl.members.push({ address: req.address, publicKey: req.publicKey, name: req.name, role: "writer", addedAtBlock: head.toString() })
      if (acl.epoch > 0) {
        const epochKey = this.epochKeys.get(acl.epoch)!
        acl.wraps = shuffle([...acl.wraps, `0x${bytesToHex(await wrapForMember(epochKey, hexToBytes(req.publicKey), acl.epoch))}` as Hex])
      }
      return {}
    })
    this.joinRequests = this.joinRequests.filter((j) => j !== req)
  }

  /**
   * Owner: removes a member and starts a new epoch. The new content key is
   * wrapped only for the members who remain, and a fresh snapshot under that
   * key is written in the same atomic batch as the ACL change.
   */
  async revoke(address: Hex): Promise<void> {
    const target = address.toLowerCase()
    if (target === this.link.owner.toLowerCase()) throw new Error("the owner cannot be revoked")
    const epochKey = randomBytes(32)
    await this.updateAcl(async (acl, head) => {
      acl.members = acl.members.filter((m) => m.address.toLowerCase() !== target)
      acl.revoked.push({ address: target as Hex, atBlock: head.toString() })
      acl.epoch += 1
      const wraps: Hex[] = []
      for (const m of acl.members) wraps.push(`0x${bytesToHex(await wrapForMember(epochKey, hexToBytes(m.publicKey), acl.epoch))}`)
      acl.wraps = shuffle(wraps)
      this.epochKeys.set(acl.epoch, epochKey)
      return { snapshot: { epoch: acl.epoch, key: epochKey } }
    })
  }

  private async updateAcl(change: (acl: Acl, head: bigint) => Promise<{ snapshot?: { epoch: number; key: Uint8Array } }>): Promise<void> {
    if (this.role !== "owner" || !this.acl || !this.aclKey) throw new Error("only the owner changes membership")
    await this.serial(async () => {
      const acl: Acl = structuredClone(this.acl!)
      const head = await this.store.head()
      const { snapshot } = await change(acl, head)
      const payload = (await aclSpec(this.link.doc, this.metaKey, acl, this.epochKeys.get(acl.epoch), head)).payload
      const patch = { patches: [{ key: this.aclKey!, payload, attributes: { doc: this.link.doc, kind: KIND.acl, seq: head } }] }
      if (!snapshot) {
        await this.store.batch(patch)
        this.stats.writes++
      } else {
        // PROTOCOL section 6: re-read recent updates so the new-epoch snapshot holds every edit
        await this.resync()
        // the new member list and a snapshot under the new key land in the same transaction
        const lifetime = this.snapshotLifetime(head)
        const w = await writeSnapshotEntities(this.store, this.link.doc, snapshot.epoch, snapshot.key, Y.encodeStateAsUpdate(this.doc), head, this.now(), KIND.snapshot, this.authorTable(Y.encodeStateAsUpdate(this.doc)), lifetime, patch)
        this.stats.writes += w.transactions
        for (const k of [w.headKey, ...w.chunks]) this.seen.add(k)
        this.snapshot = { key: w.headKey, base: head, expiresAt: head + blocks(lifetime), chunks: w.chunks, creator: this.identity!.address.toLowerCase() as Hex }
        this.updatesSinceSnapshot = 0
        this.bytesSinceSnapshot = 0
      }
      this.acl = acl
      this.emit("acl", [acl])
    })
  }

  // ---------------------------------------------------------------- versions, shredding

  /**
   * Freezes the current text as a readonly version with its own key. The
   * version has permissionless extension: anyone holding the link can keep it alive.
   */
  async publishVersion(): Promise<VersionLink> {
    this.assertWriter()
    return this.serial(async () => {
      const secret = randomBytes(32)
      const head = await this.store.head()
      const state = Y.encodeStateAsUpdate(this.doc)
      const w = await writeSnapshotEntities(this.store, this.link.doc, 0, secret, state, head, this.now(), KIND.version, {}, LIFETIME.version, {}, true)
      this.stats.writes += w.transactions
      return { key: w.headKey, secret }
    })
  }

  /**
   * Deletes your edit history and your join request for the document, in one
   * batch. It compacts first, so the shared text (yours included) lives on in a
   * snapshot you created; snapshots stay, since they carry everyone's text.
   * Your words remain in the shared text until someone removes them. Afterwards
   * they read as claimed, not proven, and old ciphertext stays in block history.
   */
  async shredMine(): Promise<number> {
    if (!this.identity) return 0
    const me = this.identity.address
    // fold everything into a snapshot first, so deleting my edits never removes words nobody else has captured
    if (this.role === "owner" || this.role === "writer") await this.compact()
    return this.serial(async () => {
      const mine = await queryAll(this.store, { doc: this.link.doc, creators: [me] })
      this.stats.queries++
      // only your own edits and join requests: snapshots you wrote carry everyone's text and stay
      const keys = mine.entities
        .filter((e) => e.owner.toLowerCase() === me.toLowerCase() && (e.attributes.kind === KIND.update || e.attributes.kind === KIND.join))
        .map((e) => e.key)
      if (!keys.length) return 0
      await this.store.batch({ deletes: keys })
      this.stats.writes++
      return keys.length
    })
  }

  /**
   * Lists the creators of every entity for this document that came from outside
   * the member list (join requests aside, which strangers send by design). One
   * query without the creator filter: what the normal reads never even fetch.
   */
  async scanOutsiders(): Promise<Hex[]> {
    if (!this.acl || this.acl.rosterHidden) return []
    this.stats.queries++
    const all = await queryAll(this.store, { doc: this.link.doc })
    const members = new Set(memberAddresses(this.acl))
    return all.entities.filter((e) => e.attributes.kind !== KIND.join && !members.has(e.creator.toLowerCase() as Hex)).map((e) => e.creator.toLowerCase() as Hex)
  }

  /**
   * Fetches one of this document's entities and decrypts it locally, so the
   * UI can show the public view and the private view side by side.
   */
  async inspect(key: Hex): Promise<{ entity: StoredEntity; frame: Frame | null } | null> {
    const entity = await this.fetch(key)
    if (!entity) return null
    const frame = await this.openEntity(entity, entity.attributes.kind, undefined)
    return { entity, frame }
  }

  private pushHistory(entry: HistoryEntry): void {
    this.history.push(entry)
    this.history.sort((a, b) => (a.block < b.block ? -1 : a.block > b.block ? 1 : 0))
    this.emit("history", [this.history])
  }

  /** client id to address, proven entries first. Stored in snapshot headers. */
  private authorTable(state?: Uint8Array): Record<string, { address: Hex; salt: string; sig: Hex }> {
    const out: Record<string, { address: Hex; salt: string; sig: Hex }> = {}
    // at most this many entries (about 250 bytes each), so the head always fits under the 100,000 byte limit
    const cap = 240
    // only client ids that still have structs in the state: the table does not grow with every session
    const present = state ? new Set(Y.parseUpdateMeta(state).from.keys()) : null
    for (const [c, a] of [...this.claimedAuthors, ...this.authors]) {
      if (present && !present.has(c)) continue
      const salt = this.salts.get(c)
      const sig = this.sigs.get(c)
      if (salt && sig) out[String(c)] = { address: a, salt, sig }
    }
    // keep the client ids that hold the most text when there are too many to carry
    const keys = Object.keys(out)
    if (keys.length <= cap || !state) return out
    const sizes = Y.parseUpdateMeta(state)
    const weight = (c: string) => (sizes.to.get(Number(c)) ?? 0) - (sizes.from.get(Number(c)) ?? 0)
    const keep = new Set(keys.sort((x, y) => weight(y) - weight(x)).slice(0, cap))
    for (const k of keys) if (!keep.has(k)) delete out[k]
    return out
  }

  /** The document as it stood at `block`, rebuilt locally from the snapshot and the edit log. */
  stateAt(block: bigint): Y.Doc {
    const doc = new Y.Doc()
    if (this.baseState) Y.applyUpdate(doc, this.baseState)
    for (const h of this.history) if (h.block <= block) Y.applyUpdate(doc, h.update)
    return doc
  }

  /** Flushes anything typed and folds uncovered edits into a snapshot. Call before leaving the page. */
  async close(): Promise<void> {
    if (this.role !== "owner" && this.role !== "writer") return
    await this.flush()
    if (this.updatesSinceSnapshot > 0) await this.compact()
  }

  destroy(): void {
    this.doc.off("update", this.onDocUpdate)
    if (this.timer) clearTimeout(this.timer)
    if (this.resyncTimer) clearInterval(this.resyncTimer)
    if (this.idleTimer) clearTimeout(this.idleTimer)
    this.unwatch?.()
    this.unwatch = null
    this.setStatus("destroyed")
    super.destroy()
  }

  // ---------------------------------------------------------------- read-only helpers

  /** Opens a published version from its link. Needs no identity and writes nothing. */
  static async openVersion(store: ArkivStore, link: VersionLink): Promise<{ doc: Y.Doc; creator: Hex; block: bigint }> {
    const entity = await store.get(link.key)
    if (!entity || entity.attributes.kind !== KIND.version) throw new Error("version not found")
    // a version is a promise that nobody can change it: one written without the readonly flag could be patched later
    if (!entity.readonly) throw new Error("this version is not readonly on chain, so its creator could still change it")
    const docId = entity.attributes.doc
    const read = async (e: StoredEntity, kind: Kind): Promise<Frame> => {
      const { envelope } = decodeOuter(e.payload)
      const frame = decodeFrame(await open(link.secret, envelope))
      if (frame.kind !== kind || !equalBytes(frame.doc, hexToBytes(docId))) throw new Error("version payload does not match its entity")
      return frame
    }
    const first = await read(entity, KIND.version)
    const parts = [first.data]
    const chunks = Array.isArray(first.header.chunks) ? (first.header.chunks as Hex[]) : []
    for (const [i, key] of chunks.entries()) {
      const c = await store.get(key)
      if (!c || c.creator.toLowerCase() !== entity.creator.toLowerCase()) throw new Error("version chunk missing")
      if (!c.readonly) throw new Error("a chunk of this version is not readonly on chain, so its creator could still change it")
      const cf = await read(c, KIND.chunk)
      if (cf.header.i !== i + 1 || cf.header.of !== first.header.id) throw new Error("version chunk does not belong to this version")
      parts.push(cf.data)
    }
    const doc = new Y.Doc()
    Y.applyUpdate(doc, concat(parts))
    return { doc, creator: entity.creator, block: entity.createdAt }
  }
}

// ------------------------------------------------------------------ versions

/**
 * Keeps a published version alive: extends its head and every chunk by
 * `seconds` in one batch. Versions carry permissionless extension, so any
 * funded key can do this, member or not. Returns the new expiry block.
 */
export async function extendVersion(store: ArkivStore, link: VersionLink, seconds: number): Promise<bigint> {
  const head = await store.get(link.key)
  if (!head || head.attributes.kind !== KIND.version) throw new Error("version not found")
  const { envelope } = decodeOuter(head.payload)
  const frame = decodeFrame(await open(link.secret, envelope))
  const chunks = Array.isArray(frame.header.chunks) ? (frame.header.chunks as Hex[]) : []
  const now = await store.head()
  const target = now + blocks(seconds)
  if (target <= head.expiresAt) throw new Error("the version already lives longer than that")
  await store.batch({ extensions: [link.key, ...chunks].map((key) => ({ key, lifetimeSeconds: seconds })) })
  return target
}

// ------------------------------------------------------------------ time travel

/**
 * Rebuilds a document exactly as Arkiv held it at a past block, using
 * `atBlock` reads for the ACL, snapshots and updates. Nothing local is used,
 * so it doubles as an independent check of what the editor shows.
 */
export async function loadAt(store: ArkivStore, link: DocLink, block: bigint, identity?: Identity): Promise<Y.Doc> {
  const historical: ArkivStore = {
    ...store,
    address: undefined,
    query: (spec) => store.query({ ...spec, atBlock: spec.atBlock ?? block }),
    watch: () => () => undefined,
    head: async () => block,
    get: (key, b) => store.get(key, b ?? block),
    batch: () => Promise.reject(new Error("read-only")),
    predictKeys: () => Promise.reject(new Error("read-only")),
  }
  const doc = new Y.Doc()
  const p = new ArkivProvider(doc, { store: historical, link, identity, flushIntervalMs: 0, autoCompact: false })
  await p.connect()
  p.destroy()
  return doc
}

// ------------------------------------------------------------------ helpers

const BLOCK_SECONDS = 2

/** Seconds to whole blocks, rounding up. */
function blocks(seconds: number): bigint {
  return BigInt(Math.ceil(seconds / BLOCK_SECONDS))
}

async function aclSpec(doc: Hex, metaKey: Uint8Array, acl: Acl, epochKey: Uint8Array | undefined, head: bigint): Promise<CreateSpec> {
  const header = (await toHeader(acl, epochKey, doc)) as unknown as Record<string, unknown>
  const payload = encodeOuter(0, await seal(metaKey, encodeFrame({ kind: KIND.acl, doc: hexToBytes(doc), epoch: 0, header, data: new Uint8Array() }, randomBytes)))
  // anyone can extend the member list, so writers keep a document open while the owner is away.
  // It holds names and public keys but no text, so a stranger extending it keeps nothing readable
  // alive: the snapshots still expire on their own, and the owner can delete the list at any time.
  return { payload, attributes: { doc, kind: KIND.acl, seq: head }, lifetimeSeconds: LIFETIME.acl, permissionlessExtension: true }
}

/**
 * Writes one snapshot (or version): chunk entities first, in transactions
 * that stay under the RPC's request size limit, then the head, which lists
 * the chunk keys. Each chunk names the snapshot's random id, so a chunk can
 * only be read as part of the snapshot it was written for. `extra` (for
 * example an ACL patch) rides in the same transaction as the head.
 */
async function writeSnapshotEntities(
  store: ArkivStore,
  doc: Hex,
  epoch: number,
  key: Uint8Array,
  state: Uint8Array,
  head: bigint,
  now: number,
  kind: Kind,
  authors: Record<string, { address: Hex; salt: string; sig: Hex }>,
  lifetime: number,
  extra: BatchSpec,
  readonly = false,
): Promise<{ result: BatchResult; headKey: Hex; chunks: Hex[]; bytes: number; transactions: number }> {
  const size = MAX_CHUNK_PLAINTEXT - 1024
  // the head carries the header (authors table, chunk keys) as well as data, so its data part is
  // smaller by the header's size; otherwise a long authors table pushes it over the 100,000 byte limit
  const authorsBytes = new TextEncoder().encode(JSON.stringify(authors)).length
  const estimatedChunks = Math.ceil(state.length / size)
  const headSize = Math.max(1024, size - authorsBytes - 80 * estimatedChunks - 512)
  const parts: Uint8Array[] = [state.subarray(0, headSize)]
  for (let i = headSize; i < state.length; i += size) parts.push(state.subarray(i, i + size))
  const id = bytesToHex(randomBytes(16))
  const docBytes = hexToBytes(doc)
  // only published versions may be kept alive by anyone; a document's own entities are not
  const flags = { readonly, permissionlessExtension: kind === KIND.version }
  const spec = async (frame: Frame, k: Kind): Promise<CreateSpec> => ({
    payload: encodeOuter(epoch, await seal(key, encodeFrame(frame, randomBytes))),
    attributes: { doc, kind: k, seq: head },
    lifetimeSeconds: lifetime,
    ...flags,
  })
  const chunkSpecs: CreateSpec[] = []
  for (let i = 1; i < parts.length; i++) chunkSpecs.push(await spec({ kind: KIND.chunk, doc: docBytes, epoch, header: { i, of: id }, data: parts[i]! }, KIND.chunk))
  const chunks: Hex[] = []
  let transactions = 0
  let bytes = 0
  for (let i = 0; i < chunkSpecs.length; ) {
    const batch: CreateSpec[] = []
    let size = 0
    while (i < chunkSpecs.length && (batch.length === 0 || size + chunkSpecs[i]!.payload.length <= MAX_BATCH_PAYLOAD_BYTES)) {
      size += chunkSpecs[i]!.payload.length
      batch.push(chunkSpecs[i++]!)
    }
    const r = await store.batch({ creates: batch })
    chunks.push(...r.created)
    transactions++
    bytes += size
  }
  const headSpec = await spec({ kind, doc: docBytes, epoch, header: { id, base: head.toString(), t: now, chunks, size: state.length, authors }, data: parts[0]! }, kind)
  const result = await store.batch({ ...extra, creates: [...(extra.creates ?? []), headSpec] })
  transactions++
  bytes += headSpec.payload.length
  return { result, headKey: result.created[(extra.creates ?? []).length]!, chunks, bytes, transactions }
}

/**
 * True if `doc` holds, at any clock a verified update wrote, an item other than that update's.
 * Deleted text does not count: deleting is any member's right. JS Yjs already lets a pending
 * update win such a clash, but the Rust engine (yrs) lets the snapshot win, so the protocol
 * requires the check and every implementation runs it.
 *
 * "The same item" means the same identity, clock by clock: content kind and value (a format's
 * key and value, a type's kind and node name), origin, right origin, parent and map key. Those
 * are fixed when an item is created, so they match whether the item arrives alone, split or merged.
 */
export function overridesVerified(doc: Y.Doc, updates: Uint8Array[]): boolean {
  for (const u of updates) {
    for (const struct of Y.decodeUpdate(u).structs) {
      if (!(struct instanceof Y.Item)) continue
      // clock by clock: later edits split items, so one struct may now span several items
      for (let i = 0; i < struct.length; i++) {
        let found: Y.Item | Y.GC
        try {
          found = Y.getItem(doc.store, Y.createID(struct.id.client, struct.id.clock + i)) as Y.Item | Y.GC
        } catch {
          break // still pending: nothing has replaced it
        }
        if (!(found instanceof Y.Item) || found.deleted) continue
        if (unitKey(doc, found, struct.id.clock + i - found.id.clock) !== unitKey(doc, struct, i)) return true
      }
    }
  }
  return false
}

/** A canonical description of the item at clock `item.id.clock + k`; see overridesVerified. */
function unitKey(doc: Y.Doc, item: Y.Item, k: number): string {
  const id = (x: Y.ID | null) => (x ? `${x.client}:${x.clock}` : "-")
  const origin = k === 0 ? id(item.origin) : `${item.id.client}:${item.id.clock + k - 1}`
  // a decoded struct names its parent only when it has no origins; an integrated item always
  // has one, so the parent is compared only where both sides carry it
  const parent = k === 0 && !item.origin && !item.rightOrigin ? parentName(doc, item.parent) : ""
  return JSON.stringify([item.content.getRef(), origin, id(item.rightOrigin), parent, k === 0 ? (item.parentSub ?? "") : "", unit(item.content, k)])
}

function parentName(doc: Y.Doc, parent: Y.Item["parent"]): string {
  if (typeof parent === "string") return `root:${parent}`
  if (parent instanceof Y.ID) return `item:${parent.client}:${parent.clock}`
  if (parent instanceof Y.AbstractType) {
    if (parent._item) return `item:${parent._item.id.client}:${parent._item.id.clock}`
    for (const [name, type] of doc.share) if (type === parent) return `root:${name}`
  }
  return "?"
}

/** One clock's content value. A type's children and attributes are items of their own, checked at their own clocks. */
function unit(content: Y.Item["content"], k: number): unknown {
  if (content instanceof Y.ContentFormat) return [content.key, content.value]
  if (content instanceof Y.ContentType) {
    const t = content.type
    // subclasses before their bases: XmlText extends Text, XmlHook extends Map, XmlElement extends XmlFragment
    if (t instanceof Y.XmlText) return ["xmltext"]
    if (t instanceof Y.Text) return ["text"]
    if (t instanceof Y.XmlHook) return ["xmlhook", t.hookName]
    if (t instanceof Y.XmlElement) return ["xmlelement", t.nodeName]
    if (t instanceof Y.XmlFragment) return ["xmlfragment"]
    if (t instanceof Y.Map) return ["map"]
    if (t instanceof Y.Array) return ["array"]
    return ["type"]
  }
  if (content instanceof Y.ContentBinary) return [...content.content]
  if (content instanceof Y.ContentDoc) return content.doc?.guid ?? null
  return content.getContent()[k] ?? null
}

/** What a writer signs to prove a client id salt is theirs: "quire1:salt:" || document id (32) || salt (16). */
function saltMessage(doc: Hex, salt: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode("quire1:salt:")
  const out = new Uint8Array(prefix.length + 48)
  out.set(prefix, 0)
  out.set(hexToBytes(doc), prefix.length)
  out.set(salt, prefix.length + 32)
  return out
}

/** True if `sig` is an EIP-191 signature by `address` over saltMessage(doc, salt). */
async function signedBy(doc: Hex, salt: string, sig: unknown, address: Hex): Promise<boolean> {
  if (typeof sig !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(sig)) return false
  try {
    const signer = await recoverMessageAddress({ message: { raw: saltMessage(doc, hexToBytes(salt)) }, signature: sig as Hex })
    return signer.toLowerCase() === address.toLowerCase()
  } catch {
    return false
  }
}

function shuffle<T>(xs: T[]): T[] {
  const out = [...xs]
  const r = randomBytes(out.length * 4)
  for (let i = out.length - 1; i > 0; i--) {
    const j = new DataView(r.buffer).getUint32(i * 4) % (i + 1)
    ;[out[i], out[j]] = [out[j]!, out[i]!]
  }
  return out
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

export { fromBase64Url, toBase64Url }
