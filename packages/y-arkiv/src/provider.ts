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
import { Observable } from "lib0/observable"
import { type Acl, emptyAcl, isMember, type Member, memberAddresses, parseAcl } from "./acl.js"
import { decodeFrame, decodeOuter, encodeFrame, encodeOuter, equalBytes, type Frame } from "./codec.js"
import {
  addressOfPublicKey,
  deriveEpochZeroKey,
  deriveMetaKey,
  open,
  publicKeyOf,
  randomBytes,
  seal,
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
  MAX_CHUNK_PLAINTEXT,
} from "./protocol.js"
import { type ArkivStore, type BatchSpec, type ChainEvent, type CreateSpec, type Hex, queryAll, type StoredEntity } from "./store.js"

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

export type Authorship = { address: Hex; proven: boolean }

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

export type ProviderOptions = {
  store: ArkivStore
  link: DocLink
  identity?: Identity
  /** Milliseconds between automatic flushes. 0 disables the timer; call flush() yourself. */
  flushIntervalMs?: number
  /** Compact automatically once enough updates pile up. Default true. */
  autoCompact?: boolean
  now?: () => number
}

type Lifetimes = typeof LIFETIME

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
  snapshot: { key: Hex; base: bigint; expiresAt: bigint; chunks: Hex[] } | null = null

  private readonly metaKey: Uint8Array
  private readonly epochKeys = new Map<number, Uint8Array>()
  private readonly seen = new Set<string>()
  private readonly authors = new Map<number, Hex>()
  /** Authorship carried inside snapshots: asserted by whoever compacted, not proven on chain. */
  private readonly claimedAuthors = new Map<number, Hex>()
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
  private timer: ReturnType<typeof setInterval> | null = null
  private readonly now: () => number
  private readonly autoCompact: boolean
  private readonly onDocUpdate: (update: Uint8Array, origin: unknown) => void

  constructor(doc: Y.Doc, options: ProviderOptions) {
    super()
    this.doc = doc
    this.link = options.link
    this.store = options.store
    this.identity = options.identity
    this.now = options.now ?? Date.now
    this.autoCompact = options.autoCompact ?? true
    this.metaKey = deriveMetaKey(this.link.secret)
    this.epochKeys.set(0, deriveEpochZeroKey(this.link.secret))
    if (this.identity) this.authors.set(doc.clientID, this.identity.address.toLowerCase() as Hex)

    this.onDocUpdate = (update, origin) => {
      if (origin === this) return
      if (this.role !== "owner" && this.role !== "writer") return
      this.pending.push(update)
    }
    doc.on("update", this.onDocUpdate)

    const interval = options.flushIntervalMs ?? FLUSH_INTERVAL_MS
    if (interval > 0) {
      this.timer = setInterval(() => {
        if (this.pending.length) void this.flush().catch((e) => this.emit("error", [e]))
      }, interval)
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
    const snapshotCreates = await snapshotSpecs(store, link.doc, 0, contentKey, state, head, Date.now())
    const result = await store.batch({
      creates: [
        await aclSpec(link.doc, metaKey, acl, head),
        ...snapshotCreates,
      ],
    })
    return { aclKey: result.created[0]!, snapshotKey: result.created[1]! }
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
    return !!this.acl && this.epochKeys.has(this.acl.epoch)
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
    return claimed ? { address: claimed, proven: false } : undefined
  }

  members(): Member[] {
    return this.acl?.members ?? []
  }

  // ---------------------------------------------------------------- sync

  async connect(): Promise<void> {
    this.setStatus("connecting")
    try {
      this.unwatch = this.store.watch(
        (e) => this.enqueue(() => this.onChainEvent(e)),
        (err) => this.emit("error", [err]),
      )
      await this.loadAcl()
      await this.loadState()
      if (this.role === "owner") await this.loadJoinRequests()
      this.setStatus("synced")
      await this.renewLeaseIfDue()
    } catch (e) {
      this.setStatus("error")
      throw e
    }
  }

  private setStatus(s: ProviderStatus): void {
    this.status = s
    this.emit("status", [s])
  }

  private async loadAcl(): Promise<void> {
    this.stats.queries++
    const page = await this.store.query({ doc: this.link.doc, kind: KIND.acl, creators: [this.link.owner], limit: 5 })
    const entity = page.entities[0]
    if (!entity) throw new Error("document not found: no ACL from the owner in the link")
    await this.applyAclEntity(entity)
  }

  private async applyAclEntity(entity: StoredEntity): Promise<void> {
    if (entity.creator.toLowerCase() !== this.link.owner.toLowerCase()) return
    const frame = await this.openEntity(entity, KIND.acl)
    if (!frame) return
    const acl = parseAcl(frame.header, this.link.owner)
    this.acl = acl
    this.aclKey = entity.key
    // unwrap the current epoch key if this session is a member
    if (acl.epoch > 0 && !this.epochKeys.has(acl.epoch) && this.identity) {
      const wrapped = acl.wraps[this.identity.address.toLowerCase()]
      if (wrapped) {
        this.epochKeys.set(acl.epoch, await unwrapAsMember(hexToBytes(wrapped), this.identity.privateKey, acl.epoch))
      }
    }
    this.joinRequests = this.joinRequests.filter((j) => !isMember(acl, j.address))
    this.emit("acl", [acl])
  }

  private async loadState(): Promise<void> {
    if (!this.acl) return
    const writers = memberAddresses(this.acl)
    this.stats.queries++
    const snaps = await this.store.query({ doc: this.link.doc, kind: KIND.snapshot, creators: writers, limit: 20 })
    // newest first; apply every snapshot close to the newest base, which covers concurrent compactions
    let newestBase = -1n
    for (const s of snaps.entities) {
      const applied = await this.applySnapshotEntity(s)
      if (applied !== null && applied > newestBase) newestBase = applied
      if (newestBase >= 0n && applied !== null && applied < newestBase - CATCH_UP_MARGIN_BLOCKS) break
    }
    const from = newestBase > CATCH_UP_MARGIN_BLOCKS ? newestBase - CATCH_UP_MARGIN_BLOCKS : 0n
    this.stats.queries++
    const updates = await queryAll(this.store, { doc: this.link.doc, kind: KIND.update, creators: writers, seqGte: from })
    // oldest first is not required by Yjs, but it keeps intermediate states sensible
    for (const u of [...updates.entities].reverse()) await this.applyUpdateEntity(u, false)
    this.updatesSinceSnapshot = updates.entities.length
  }

  private async loadJoinRequests(): Promise<void> {
    this.stats.queries++
    const page = await this.store.query({ doc: this.link.doc, kind: KIND.join, limit: 50 })
    for (const e of page.entities) await this.applyJoinEntity(e)
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
        await this.applyAclEntity(entity)
        // a membership change can widen the set of writers: catch up on their edits
        if (this.acl.epoch !== before) await this.loadState()
      }
      return
    }
    if (e.type === "extended" && this.snapshot && e.key === this.snapshot.key) {
      this.snapshot.expiresAt = e.expiresAt
      this.emit("lease", [this.snapshot])
      return
    }
    if (e.type !== "created") return
    const me = this.identity?.address.toLowerCase()
    const creator = e.owner.toLowerCase() as Hex
    if (creator === me) return
    const known = memberAddresses(this.acl).includes(creator)
    // non-members can only matter to the owner (join requests); everyone else skips the fetch
    if (!known && this.role !== "owner") return
    const entity = await this.fetch(e.key)
    if (!entity || entity.attributes.doc !== this.link.doc) return
    if (!known) {
      if (entity.attributes.kind === KIND.join) await this.applyJoinEntity(entity)
      else this.reject()
      return
    }
    if (entity.attributes.kind === KIND.update) await this.applyUpdateEntity(entity, true)
    else if (entity.attributes.kind === KIND.snapshot) await this.applySnapshotEntity(entity)
  }

  private reject(): void {
    this.stats.rejectedWrites++
    this.emit("rejected", [this.stats.rejectedWrites])
  }

  private async fetch(key: Hex): Promise<StoredEntity | null> {
    this.stats.gets++
    return this.store.get(key)
  }

  private async applyUpdateEntity(entity: StoredEntity, live: boolean): Promise<void> {
    if (this.seen.has(entity.key)) return
    this.seen.add(entity.key)
    if (!this.acl || !isMember(this.acl, entity.creator)) return this.reject()
    const frame = await this.openEntity(entity, KIND.update)
    if (!frame) return
    this.recordAuthors(frame.data, entity.creator)
    Y.applyUpdate(this.doc, frame.data, this)
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

  /** Applies a snapshot and returns its base block, or null if it could not be read. */
  private async applySnapshotEntity(entity: StoredEntity): Promise<bigint | null> {
    if (this.seen.has(entity.key)) return this.snapshot?.key === entity.key ? this.snapshot.base : null
    this.seen.add(entity.key)
    if (!this.acl || !isMember(this.acl, entity.creator)) {
      this.reject()
      return null
    }
    const frame = await this.openEntity(entity, KIND.snapshot)
    if (!frame) return null
    const chunks = Array.isArray(frame.header.chunks) ? (frame.header.chunks as Hex[]) : []
    const parts = [frame.data]
    for (const [i, key] of chunks.entries()) {
      const chunk = await this.fetch(key)
      // a chunk must come from the snapshot's own creator, or the snapshot is discarded
      if (!chunk || chunk.creator.toLowerCase() !== entity.creator.toLowerCase()) return null
      const cf = await this.openEntity(chunk, KIND.chunk, frame.epoch)
      if (!cf || cf.header.i !== i + 1 || cf.header.of !== entity.key.toLowerCase()) return null
      parts.push(cf.data)
    }
    const state = concat(parts)
    const claimed = frame.header.authors
    if (claimed && typeof claimed === "object") {
      for (const [client, address] of Object.entries(claimed as Record<string, string>)) {
        if (/^0x[0-9a-f]{40}$/.test(address)) this.claimedAuthors.set(Number(client), address as Hex)
      }
    }
    Y.applyUpdate(this.doc, state, this)
    this.stats.snapshotsApplied++
    const base = BigInt(String(frame.header.base ?? "0"))
    if (!this.snapshot || base >= this.snapshot.base) {
      this.baseState = state
      this.history.splice(0, this.history.length, ...this.history.filter((h) => h.block >= base))
      this.snapshot = { key: entity.key, base, expiresAt: entity.expiresAt, chunks }
      this.updatesSinceSnapshot = 0
      this.bytesSinceSnapshot = 0
      this.emit("lease", [this.snapshot])
    }
    return base
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

  /** Records which address wrote each Yjs client id found in an update. */
  private recordAuthors(update: Uint8Array, author: Hex | undefined): void {
    if (!author) return
    const a = author.toLowerCase() as Hex
    for (const client of Y.decodeStateVector(Y.encodeStateVectorFromUpdate(update)).keys()) {
      if (!this.authors.has(client)) this.authors.set(client, a)
    }
  }

  // ---------------------------------------------------------------- crypto plumbing

  private keyFor(kind: Kind, epoch: number): Uint8Array | undefined {
    if (kind === KIND.acl || kind === KIND.join) return this.metaKey
    return this.epochKeys.get(epoch)
  }

  private async openEntity(entity: StoredEntity, kind: Kind, epochHint?: number): Promise<Frame | null> {
    if (entity.attributes.kind !== kind || entity.attributes.doc !== this.link.doc) return null
    try {
      const { epoch, envelope } = decodeOuter(entity.payload)
      if (epochHint !== undefined && epoch !== epochHint) return null
      const key = this.keyFor(kind, epoch)
      if (!key) return null
      const frame = decodeFrame(await open(key, envelope))
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
      const merged = Y.mergeUpdates(updates)
      if (merged.length > MAX_CHUNK_PLAINTEXT - 256) {
        // too big for one update: fold everything into a snapshot instead
        const info = await this.writeSnapshot()
        return info
      }
      const { epoch, key } = this.currentContentKey()
      const head = await this.store.head()
      const payload = encodeOuter(
        epoch,
        await seal(key, encodeFrame({ kind: KIND.update, doc: hexToBytes(this.link.doc), epoch, header: { t: this.now() }, data: merged }, randomBytes)),
      )
      let result
      try {
        result = await this.store.batch({
          creates: [{ payload, attributes: { doc: this.link.doc, kind: KIND.update, seq: head }, lifetimeSeconds: LIFETIME.update }],
        })
      } catch (e) {
        // keep the edits: they go out with the next flush
        this.pending.unshift(merged)
        throw e
      }
      this.stats.writes++
      const entity = result.created[0]!
      this.seen.add(entity)
      if (this.identity) this.pushHistory({ block: result.block, author: this.identity.address.toLowerCase() as Hex, update: merged, entity })
      this.updatesSinceSnapshot++
      this.bytesSinceSnapshot += merged.length
      const info: FlushInfo = { txHash: result.txHash, block: result.block, bytes: payload.length, entity }
      this.emit("flush", [info])
      if (this.autoCompact && (this.updatesSinceSnapshot >= COMPACT_AFTER_UPDATES || this.bytesSinceSnapshot >= COMPACT_AFTER_BYTES)) {
        void this.compact().catch((e) => this.emit("error", [e]))
      }
      return info
    })
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
  async resync(): Promise<number> {
    if (!this.acl) return 0
    const base = this.snapshot?.base ?? 0n
    const from = base > CATCH_UP_MARGIN_BLOCKS ? base - CATCH_UP_MARGIN_BLOCKS : 0n
    this.stats.queries++
    const updates = await queryAll(this.store, { doc: this.link.doc, kind: KIND.update, creators: memberAddresses(this.acl), seqGte: from })
    const before = this.stats.updatesApplied
    for (const u of [...updates.entities].reverse()) await this.applyUpdateEntity(u, false)
    return this.stats.updatesApplied - before
  }

  private async writeSnapshot(extra: BatchSpec = {}): Promise<FlushInfo> {
    this.assertWriter()
    const { epoch, key } = this.currentContentKey()
    await this.resync()
    const head = await this.store.head()
    // anything still buffered is already in the doc state, so the snapshot covers it
    this.pending = []
    const state = Y.encodeStateAsUpdate(this.doc)
    const creates = await snapshotSpecs(this.store, this.link.doc, epoch, key, state, head, this.now(), KIND.snapshot, this.authorTable())
    const result = await this.store.batch({ ...extra, creates: [...(extra.creates ?? []), ...creates] })
    this.stats.writes++
    const offset = extra.creates?.length ?? 0
    const snapKey = result.created[offset]!
    for (const k of result.created) this.seen.add(k)
    this.snapshot = {
      key: snapKey,
      base: head,
      expiresAt: head + BigInt(Math.ceil(LIFETIME.snapshot / 2)),
      chunks: result.created.slice(offset + 1),
    }
    this.updatesSinceSnapshot = 0
    this.bytesSinceSnapshot = 0
    this.baseState = state
    this.history.length = 0
    this.emit("lease", [this.snapshot])
    const info: FlushInfo = { txHash: result.txHash, block: result.block, bytes: creates.reduce((n, c) => n + c.payload.length, 0), entity: snapKey }
    this.emit("compact", [info])
    return info
  }

  /**
   * Lifetime Extension as a lease: an active session pushes the newest
   * snapshot (and its chunks and the ACL) out by another full lifetime once
   * half of it has passed. A document nobody opens for a month fades away.
   */
  async renewLeaseIfDue(lifetimes: Lifetimes = LIFETIME): Promise<boolean> {
    if (!this.snapshot || !this.identity || !this.acl) return false
    if (this.role !== "owner" && this.role !== "writer") return false
    const head = await this.store.head()
    const life = BigInt(Math.ceil(lifetimes.snapshot / 2))
    const left = this.snapshot.expiresAt - head
    if (left > BigInt(Math.floor(Number(life) * LEASE_RENEW_FRACTION))) return false
    await this.serial(async () => {
      const extensions = [this.snapshot!.key, ...this.snapshot!.chunks].map((k) => ({ key: k, lifetimeSeconds: lifetimes.snapshot }))
      if (this.aclKey) extensions.push({ key: this.aclKey, lifetimeSeconds: lifetimes.acl })
      await this.store.batch({ extensions })
      this.stats.writes++
      this.snapshot!.expiresAt = head + life
      this.emit("lease", [this.snapshot])
    })
    return true
  }

  /** Sets the document's remaining lifetime. Owner only: expiry the user controls. */
  async setLifetime(seconds: number): Promise<void> {
    if (this.role !== "owner" || !this.snapshot || !this.aclKey) throw new Error("only the owner sets the document lifetime")
    await this.serial(async () => {
      const keys = [this.snapshot!.key, ...this.snapshot!.chunks, this.aclKey!]
      await this.store.batch({ extensions: keys.map((key) => ({ key, lifetimeSeconds: seconds })) })
      this.stats.writes++
      this.snapshot!.expiresAt = (await this.store.head()) + BigInt(Math.ceil(seconds / 2))
      this.emit("lease", [this.snapshot])
    })
  }

  // ---------------------------------------------------------------- membership

  /** Asks the owner to add this session. The request carries our public key and expires in an hour. */
  async requestJoin(): Promise<Hex> {
    if (!this.identity) throw new Error("joining needs an identity")
    return this.serial(async () => {
      const head = await this.store.head()
      const header = { publicKey: `0x${bytesToHex(publicKeyOf(this.identity!.privateKey))}`, name: this.identity!.name }
      const payload = encodeOuter(0, await seal(this.metaKey, encodeFrame({ kind: KIND.join, doc: hexToBytes(this.link.doc), epoch: 0, header, data: new Uint8Array() }, randomBytes)))
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
        acl.wraps[req.address] = `0x${bytesToHex(await wrapForMember(epochKey, hexToBytes(req.publicKey), acl.epoch))}`
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
      acl.wraps = {}
      for (const m of acl.members) {
        acl.wraps[m.address.toLowerCase()] = `0x${bytesToHex(await wrapForMember(epochKey, hexToBytes(m.publicKey), acl.epoch))}`
      }
      this.epochKeys.set(acl.epoch, epochKey)
      const state = Y.encodeStateAsUpdate(this.doc)
      return { creates: await snapshotSpecs(this.store, this.link.doc, acl.epoch, epochKey, state, head, this.now()) }
    })
  }

  private async updateAcl(change: (acl: Acl, head: bigint) => Promise<BatchSpec>): Promise<void> {
    if (this.role !== "owner" || !this.acl || !this.aclKey) throw new Error("only the owner changes membership")
    await this.serial(async () => {
      const acl: Acl = structuredClone(this.acl!)
      const head = await this.store.head()
      const extra = await change(acl, head)
      const payload = (await aclSpec(this.link.doc, this.metaKey, acl, head)).payload
      const result = await this.store.batch({
        ...extra,
        patches: [{ key: this.aclKey!, payload, attributes: { doc: this.link.doc, kind: KIND.acl, seq: head } }],
      })
      this.stats.writes++
      for (const k of result.created) this.seen.add(k)
      this.acl = acl
      if (extra.creates?.length) {
        this.snapshot = { key: result.created[0]!, base: head, expiresAt: head + BigInt(Math.ceil(LIFETIME.snapshot / 2)), chunks: result.created.slice(1) }
        this.updatesSinceSnapshot = 0
        this.bytesSinceSnapshot = 0
      }
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
      const creates = await snapshotSpecs(this.store, this.link.doc, 0, secret, state, head, this.now(), KIND.version)
      for (const c of creates) {
        c.readonly = true
        c.permissionlessExtension = true
        c.lifetimeSeconds = LIFETIME.version
      }
      const result = await this.store.batch({ creates })
      this.stats.writes++
      return { key: result.created[0]!, secret }
    })
  }

  /**
   * Deletes every entity this session created for the document, in one batch.
   * The text you wrote stays in the shared document (it is part of everyone's
   * state); what goes is your raw edit history and anything only you hold up.
   */
  async shredMine(): Promise<number> {
    if (!this.identity) return 0
    const me = this.identity.address
    return this.serial(async () => {
      const mine = await queryAll(this.store, { doc: this.link.doc, creators: [me] })
      this.stats.queries++
      const keys = mine.entities.filter((e) => e.owner.toLowerCase() === me.toLowerCase() && !e.readonly).map((e) => e.key)
      if (!keys.length) return 0
      await this.store.batch({ deletes: keys })
      this.stats.writes++
      return keys.length
    })
  }

  private pushHistory(entry: HistoryEntry): void {
    this.history.push(entry)
    this.history.sort((a, b) => (a.block < b.block ? -1 : a.block > b.block ? 1 : 0))
    this.emit("history", [this.history])
  }

  /** client id to address, proven entries first. Stored in snapshot headers. */
  private authorTable(): Record<string, Hex> {
    const out: Record<string, Hex> = {}
    for (const [c, a] of this.claimedAuthors) out[String(c)] = a
    for (const [c, a] of this.authors) out[String(c)] = a
    return out
  }

  /** The document as it stood at `block`, rebuilt locally from the snapshot and the edit log. */
  stateAt(block: bigint): Y.Doc {
    const doc = new Y.Doc()
    if (this.baseState) Y.applyUpdate(doc, this.baseState)
    for (const h of this.history) if (h.block <= block) Y.applyUpdate(doc, h.update)
    return doc
  }

  destroy(): void {
    this.doc.off("update", this.onDocUpdate)
    if (this.timer) clearInterval(this.timer)
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
      const cf = await read(c, KIND.chunk)
      if (cf.header.i !== i + 1) throw new Error("version chunk out of order")
      parts.push(cf.data)
    }
    const doc = new Y.Doc()
    Y.applyUpdate(doc, concat(parts))
    return { doc, creator: entity.creator, block: entity.createdAt }
  }
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
    get: (key) => store.get(key),
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

async function aclSpec(doc: Hex, metaKey: Uint8Array, acl: Acl, head: bigint): Promise<CreateSpec> {
  const payload = encodeOuter(0, await seal(metaKey, encodeFrame({ kind: KIND.acl, doc: hexToBytes(doc), epoch: 0, header: acl as unknown as Record<string, unknown>, data: new Uint8Array() }, randomBytes)))
  return { payload, attributes: { doc, kind: KIND.acl, seq: head }, lifetimeSeconds: LIFETIME.acl, permissionlessExtension: true }
}

/**
 * Builds the creates for one snapshot (or version): the head entity plus as
 * many chunk entities as the state needs. Chunk keys are predicted up front so
 * the head can list them, and everything goes into one atomic batch.
 */
async function snapshotSpecs(
  store: ArkivStore,
  doc: Hex,
  epoch: number,
  key: Uint8Array,
  state: Uint8Array,
  head: bigint,
  now: number,
  kind: Kind = KIND.snapshot,
  authors: Record<string, Hex> = {},
): Promise<CreateSpec[]> {
  const size = MAX_CHUNK_PLAINTEXT - 1024
  const parts: Uint8Array[] = []
  for (let i = 0; i < state.length || i === 0; i += size) parts.push(state.subarray(i, i + size))
  const predicted = await store.predictKeys(parts.length)
  const headKey = predicted[0]!.key.toLowerCase()
  const lifetime = kind === KIND.version ? LIFETIME.version : LIFETIME.snapshot
  const docBytes = hexToBytes(doc)
  const specs: CreateSpec[] = []
  for (const [i, part] of parts.entries()) {
    const frame =
      i === 0
        ? { kind, doc: docBytes, epoch, header: { base: head.toString(), t: now, chunks: predicted.slice(1).map((p) => p.key.toLowerCase()), size: state.length, authors }, data: part }
        : { kind: KIND.chunk, doc: docBytes, epoch, header: { i, of: headKey }, data: part }
    specs.push({
      payload: encodeOuter(epoch, await seal(key, encodeFrame(frame, randomBytes))),
      attributes: { doc, kind: i === 0 ? kind : KIND.chunk, seq: head },
      lifetimeSeconds: lifetime,
      permissionlessExtension: true,
      salt: predicted[i]!.salt,
    })
  }
  return specs
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
