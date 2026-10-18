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
import { type Acl, clipName, emptyAcl, fromHeader, isMember, type Member, memberAddresses, memberAt, toHeader, updateAuthors, updateFilter, wroteAsMember } from "./acl.js"
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
import { headerProblem, MalformedHeader } from "./headers.js"
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
type PendingSnapshot = {
  key: Hex
  state: Uint8Array
  /** the snapshot's creator, and the client ids its valid `authors` entries give to that creator */
  creator: Hex
  own: Set<number>
  commit: (trimHistory: boolean) => void
  registerClaims: () => void
}

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
  /**
   * Never write: no lease renewal, no compaction. For audits that read as a member (an identity
   * unwraps the current key) without touching the document.
   */
  readOnly?: boolean
  /**
   * Check each update's author against the member list as it stood at that update's block, and each
   * entity's expiry against the keepUntil in force when it was last extended, both read by key with
   * atBlock, instead of against today's list. The owner can rewrite the current list; nobody can
   * rewrite past state. Costs one free read by key per distinct block. Default true; false applies
   * today's list.
   */
  membershipAtBlock?: boolean
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
  /** Clock ranges per client id that applied snapshots carried, and whose snapshot: newest first. */
  private readonly carried = new Map<number, { from: number; to: number; via: Hex }[]>()
  /** True if the last outsider scan read one full page and stopped (there may be more). */
  outsidersTruncated = false
  /** An audit found more update entities than AUDIT_PAGES pages and read only those from today's list (see queryUpdates). */
  /** Whether anyone may extend the member list: true only for documents made before owner-only lists. */
  private aclOpenToAll = false
  auditNarrowed = false
  /** Edits whose member list (or keepUntil) at their block could not be read after retries, so today's list decided. */
  auditUnchecked = 0
  /** Every entity this session applied (member list, updates, snapshots), for audits and reader comparisons. */
  readonly appliedKeys = new Set<Hex>()
  /**
   * Whether `entity`'s creator was listed as a member in the member list as it stood at the entity's
   * block, read with atBlock. False if the list did not exist yet; undefined if that past list is sealed
   * under a key this session does not hold.
   */
  private async memberAtBlock(entity: StoredEntity): Promise<boolean | undefined> {
    if (!this.aclKey) return undefined
    const acl = await this.aclAtBlock(entity.createdAt)
    // the past list could not be read (the RPC kept failing): today's list decides, and the edit is
    // counted as unchecked rather than silently refused
    if (acl === "unknown") {
      this.auditUnchecked++
      return undefined
    }
    if (!acl) return false
    // a past roster sealed under a key this session never held: today's list decides, and it is counted
    if (acl.rosterHidden) {
      this.auditUnchecked++
      return undefined
    }
    // the whole section 5 rule against that list: a patch in the edit's own block may already show
    // the removal, and the removal interval still covers the edit
    return wroteAsMember(acl, entity.creator, entity.createdAt)
  }

  /** The owner's member list as it stood at `block`, read by key with atBlock (free); null if there was none then. */
  private async aclAtBlock(block: bigint): Promise<Acl | null | "unknown"> {
    if (!this.aclKey) return null
    if (!this.aclAt.has(block)) {
      const past = await this.pastAclEntity(block)
      if (past === undefined) return "unknown"
      this.aclAt.set(block, await this.openPastAcl(past))
    }
    return this.aclAt.get(block) ?? null
  }

  /**
   * The member list entity as it stood at `block`. A read that fails (a 429 from the free-read limit,
   * a dropped connection) is retried, then reported as undefined; only an answer from the chain says
   * whether the list existed then (null if it did not).
   */
  private async pastAclEntity(block?: bigint): Promise<StoredEntity | null | undefined> {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        return await this.store.get(this.aclKey!, block)
      } catch {
        if (attempt < 2) await new Promise((r) => setTimeout(r, 500 * 2 ** attempt))
      }
    }
    return undefined
  }

  private async openPastAcl(past: StoredEntity | null): Promise<Acl | null> {
    try {
      const frame = past && past.creator.toLowerCase() === this.link.owner.toLowerCase() ? await this.decryptEntity(past, KIND.acl) : null
      return frame ? await fromHeader(frame.header, this.link.owner, (n) => this.epochKeys.get(n), this.link.doc) : null
    } catch {
      return null
    }
  }

  /**
   * Every address any version of the member list named, as a member or a removal, found by walking the
   * list's own history: the version before one last changed at block B is the list as it stood at B - 1,
   * read by key with atBlock (free). An owner who erases someone from the current list cannot erase them
   * from these past versions. Null if some version could not be read or opened.
   */
  private async everListed(): Promise<Hex[] | null> {
    if (!this.aclKey || !this.acl) return null
    const out = new Set<Hex>(updateAuthors(this.acl).map((a) => a.toLowerCase() as Hex))
    let version = await this.pastAclEntity()
    let reads = 1
    while (version) {
      // a history too long to walk within the read limit: keep every address found so far, and say so
      if (reads >= 2000) {
        this.auditNarrowed = true
        return [...out]
      }
      if (version.updatedAt <= version.createdAt) return [...out]
      // Extensions move updatedAt without touching the list, and anyone can extend the list of a document
      // made before owner-only lists. Each patch stamps qs with the owner's head, and its fresh encryption
      // makes the payload unique, so if the list held these exact bytes 61 blocks after that stamp, no
      // patch landed in between: skip the extensions and keep walking from there.
      const stamp = version.attributes.seq
      if (version.updatedAt > stamp + 61n) {
        const settled = await this.pastAclEntity(stamp + 61n)
        reads++
        if (settled === undefined) return null
        if (settled && settled.updatedAt < version.updatedAt && bytesEqual(settled.payload, version.payload)) {
          version = settled
          continue
        }
      }
      const before = await this.pastAclEntity(version.updatedAt - 1n)
      reads++
      if (before === undefined) return null
      if (before === null) return [...out]
      // a store without history answers with today's version again: the walk cannot go back
      if (before.updatedAt >= version.updatedAt) return null
      const acl = await this.openPastAcl(before)
      if (!acl || acl.rosterHidden) return null
      for (const a of updateAuthors(acl)) out.add(a.toLowerCase() as Hex)
      version = before
    }
    return [...out]
  }

  /** What each applied update wrote, per client:clock, so a later conflicting update can be refused. */
  private readonly verifiedUnits = new StructIndex()
  /** Base block of every snapshot this session applied, so a reload knows them without re-reading. */
  private readonly snapshotBases = new Map<Hex, bigint>()
  /** Snapshots refused by a rule (not merely unreadable): their creator gets no fallback on load. */
  private readonly refusedSnapshots = new Set<Hex>()
  /** each member's applied snapshot, which speaks for the client ids its authors table gives that member */
  private readonly ownSnapshots = new Map<Hex, { creator: Hex; state: Uint8Array; own: Set<number> }>()
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
  private readonly readOnly: boolean
  private readonly membershipAtBlock: boolean
  /** Member lists as they stood at past blocks, read with atBlock (membershipAtBlock). */
  private readonly aclAt = new Map<bigint, Acl | null>()
  private readonly onDocUpdate: (update: Uint8Array, origin: unknown) => void

  constructor(doc: Y.Doc, options: ProviderOptions) {
    super()
    this.doc = doc
    this.link = options.link
    // every query page is counted here, so stats.queries is what the RPC billed, cursor pages included
    const inner = options.store
    const stats = () => this.stats
    // read-only sessions refuse every write at the one place all writes pass through
    const readOnly = options.readOnly ?? false
    this.store = {
      get address() {
        return inner.address
      },
      head: () => inner.head(),
      batch: (spec) => (readOnly ? Promise.reject(new Error("this session was opened read-only")) : inner.batch(spec)),
      predictKeys: (n) => inner.predictKeys(n),
      query: (spec) => (stats().queries++, inner.query(spec)),
      get: (key, block) => inner.get(key, block),
      watch: (onEvent, onError) => inner.watch(onEvent, onError),
    }
    this.identity = options.identity
    this.now = options.now ?? Date.now
    this.autoCompact = options.autoCompact ?? true
    this.fullHistory = options.fullHistory ?? false
    this.readOnly = options.readOnly ?? false
    this.membershipAtBlock = options.membershipAtBlock ?? true
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
      name: clipName(identity.name), // the schema's limit, so every reader accepts the list
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
        (e) => {
          this.socketHealthy()
          this.enqueue(() => this.onChainEvent(e))
        },
        (err) => {
          // the gateway rate-limits WebSocket handshakes per IP; while the socket is down, poll instead
          this.socketFailed()
          this.emit("error", [err])
        },
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
    if (!this.readOnly) this.renewLeaseIfDue().catch((e) => this.emit("error", [e]))
    if (this.resyncInterval > 0) {
      // a tab left open for days must renew the lease too, not only a fresh load
      this.resyncTimer = setInterval(
        () =>
          void this.resync({ joins: true })
            .then(() => (this.readOnly ? false : this.renewLeaseIfDue()))
            .catch((e) => this.emit("error", [e])),
        this.resyncInterval,
      )
    }
  }

  private setStatus(s: ProviderStatus): void {
    this.status = s
    this.emit("status", [s])
  }

  private async loadAcl(): Promise<void> {
    // every page: the earliest valid list wins, and an owner who publishes more lists must not push it off the first page
    const page = await queryAll(this.store, { doc: this.link.doc, kind: KIND.acl, creators: [this.link.owner] })
    this.sawHead(page.block)
    // the earliest entity that is really the owner's ACL (by creation block, then key, so every reader picks
    // the same one whatever order the RPC returns); an RPC that ignores the creator filter cannot slip in another
    const earliest = [...page.entities].sort((x, y) => (x.createdAt !== y.createdAt ? (x.createdAt < y.createdAt ? -1 : 1) : x.key < y.key ? -1 : x.key > y.key ? 1 : 0))
    for (const entity of earliest) {
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
    // earlier epochs' keys, carried in the sealed roster: a fresh member session reads all of the history
    for (const [n, k] of Object.entries(acl.prior ?? {})) if (!this.epochKeys.has(Number(n))) this.epochKeys.set(Number(n), hexToBytes(k))
    this.acl = acl
    this.aclKey = entity.key
    this.appliedKeys.add(entity.key)
    this.aclSeq = entity.attributes.seq
    this.aclExpiresAt = entity.expiresAt
    this.aclOpenToAll = entity.permissionlessExtension
    this.joinRequests = this.joinRequests.filter((j) => !isMember(acl, j.address))
    this.emit("acl", [acl])
  }

  private async loadState(): Promise<void> {
    // without the roster we do not know whose entities to trust, and could not decrypt them anyway
    if (!this.acl || this.acl.rosterHidden) return
    const writers = memberAddresses(this.acl)
    const snaps = await queryAll(this.store, { doc: this.link.doc, kind: KIND.snapshot, creators: writers, seqLte: this.qsCeiling() })
    this.sawHead(snaps.block)
    // order by the writer's block height (qs), newest first; Arkiv does not promise any order.
    // Apply every snapshot close to the newest base, which covers concurrent compactions.
    // ties broken by creation block, then key, both descending, so every reader picks the same one
    const desc = (x: bigint | string, y: bigint | string) => (x === y ? 0 : x > y ? -1 : 1)
    const ordered = [...snaps.entities].sort((x, y) => desc(x.attributes.seq, y.attributes.seq) || desc(x.createdAt, y.createdAt) || desc(x.key, y.key))
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
      if (applied === null) {
        // refused, as opposed to not assemblable: that member contributes no snapshot (no fallback)
        if (this.refusedSnapshots.has(s.key)) covered.add(creator)
        continue
      }
      covered.add(creator)
      if (oldestBase === null || applied < oldestBase) oldestBase = applied
    }
    const from = !this.fullHistory && oldestBase !== null && oldestBase > CATCH_UP_MARGIN_BLOCKS ? oldestBase - CATCH_UP_MARGIN_BLOCKS : 0n
    // Section 5: an update under a client id that a valid snapshot authors entry gives to another
    // address is ignored, so the candidates' claims go in before any update. Claims from a snapshot
    // the verified-clock check then refuses are taken back below.
    const before = { authors: new Map(this.claimedAuthors), via: new Map(this.claimedVia) }
    for (const st of states) st.registerClaims()
    // removed members too: what they wrote while they belonged still counts (wroteAsMember)
    // an audit reads every update, not only those of today's list: someone the owner erased from the
    // list's history still wrote what they wrote, and the member list at each edit's block decides
    const updates = await this.queryUpdates(from)
    // oldest first is not required by Yjs, but it keeps intermediate states sensible
    // binding depends on order, so every reader uses the same one: creation block, then key
    const byAge = [...updates.entities].sort((x, y) => (x.createdAt !== y.createdAt ? (x.createdAt < y.createdAt ? -1 : 1) : x.key < y.key ? -1 : x.key > y.key ? 1 : 0))
    const historyBefore = this.history.length
    for (const u of byAge) await this.applyUpdateEntity(u, false)
    const verified = this.history.slice(historyBefore).map((h) => h.update)
    // back to the claims from before this load; each snapshot that passes registers its own on commit.
    // (Salts and signatures a refused snapshot carried stay: they are valid signatures, and verified
    // updates set theirs in the same maps during the loop.)
    const restore = <K, V>(target: Map<K, V>, from: Map<K, V>) => (target.clear(), from.forEach((v, k) => target.set(k, v)))
    restore(this.claimedAuthors, before.authors)
    restore(this.claimedVia, before.via)
    // a member speaks for their own client ids: judge only by snapshots that pass the verified-clock check
    const owners = states.filter((st) => !snapshotConflicts(this.doc, st.state, verified))
    const overruled = overruledByOwners(this.doc, states, owners)
    for (const st of states) {
      if (overruled.has(st.key)) {
        this.reject()
        this.refusedSnapshots.add(st.key)
        continue
      }
      // A verified update can be pending, waiting on text only a snapshot holds. When the snapshot fills the
      // gap, Yjs keeps the snapshot's struct at that clock. So try each snapshot on a scratch copy first, and
      // refuse it if any verified clock would end up with different content.
      const trial = new Y.Doc()
      Y.applyUpdate(trial, Y.encodeStateAsUpdate(this.doc))
      Y.applyUpdate(trial, st.state)
      if (snapshotConflicts(this.doc, st.state, verified) || overridesVerified(trial, verified)) {
        this.reject()
        this.refusedSnapshots.add(st.key)
        continue
      }
      this.applyRemote(st.state)
      st.commit(false)
      this.ownSnapshots.set(st.creator, st)
    }
    this.updatesSinceSnapshot = updates.entities.length
  }

  /**
   * Updates from `from` on. Normally only from today's members and removed members (the `$creator`
   * filter). An audit reads the edits of every address any version of the list ever named (see
   * everListed), so an author the owner erased from the current list still shows up and the list as
   * it stood at each edit's block decides. If the list's history cannot be walked, it drops the filter
   * instead; anyone can write junk `u` entities under the public document id, so that read stops after
   * AUDIT_PAGES pages and falls back to the filter, and `auditNarrowed` says so.
   */
  private async queryUpdates(from: bigint): Promise<{ entities: StoredEntity[]; block: bigint }> {
    const filtered = { doc: this.link.doc, kind: KIND.update, ...updateFilter(this.acl!, from), seqGte: from, seqLte: this.qsCeiling() }
    // the wider read is for full audits only; a normal session still checks each fetched edit at its block
    if (!this.membershipAtBlock || !this.fullHistory) return queryAll(this.store, filtered)
    // an audit reads the edits of everyone any version of the list ever named, 64 addresses a query:
    // junk from strangers never enters, and nobody the owner erased is left out
    const ever = await this.everListed()
    if (ever) {
      const entities: StoredEntity[] = []
      let block = 0n
      for (let i = 0; i < ever.length; i += 64) {
        const page = await queryAll(this.store, { ...filtered, creators: ever.slice(i, i + 64), creatorBounds: undefined })
        entities.push(...page.entities)
        block = page.block
      }
      return { entities, block }
    }
    const spec = { doc: this.link.doc, kind: KIND.update, seqGte: from, seqLte: this.qsCeiling() }
    const first = await this.store.query(spec)
    const out = [...first.entities]
    let cursor = first.cursor
    for (let pages = 1; cursor && pages < AUDIT_PAGES; pages++) {
      const page = await this.store.query({ ...spec, atBlock: first.block, cursor })
      out.push(...page.entities)
      cursor = page.cursor
    }
    if (!cursor) return { entities: out, block: first.block }
    this.auditNarrowed = true
    return queryAll(this.store, filtered)
  }

  /**
   * One page of join requests (up to 200). The document id is public, so anyone can write junk
   * `j` entities; following every page would let them drain the owner's query budget.
   */
  private async loadJoinRequests(): Promise<void> {
    const page = await this.store.query({ doc: this.link.doc, kind: KIND.join, limit: 200 })
    for (const e of page.entities) await this.applyJoinEntity(e)
  }

  /**
   * Owner: looks up one address's join request directly, with a `$creator` filter. Junk requests
   * can push a real one out of the first page, but they cannot hide it from this query.
   */
  async findJoinRequest(address: Hex): Promise<JoinRequest | null> {
    if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return null
    const page = await this.store.query({ doc: this.link.doc, kind: KIND.join, creators: [address], limit: 20 })
    for (const e of page.entities) await this.applyJoinEntity(e)
    return this.joinRequests.find((j) => j.address === address.toLowerCase()) ?? null
  }

  private enqueue(fn: () => Promise<void>): void {
    this.work = this.work.then(fn).catch((e) => this.emit("error", [e]))
  }

  private pollTimer: ReturnType<typeof setTimeout> | null = null
  /** The newest block this session has seen, from query results and live events. */
  private headSeen = 0n

  /**
   * The largest `qs` worth fetching: a valid entity's qs is at most the block it landed in, so anything
   * above the head (plus the catch-up margin, for writes landing while this load runs) is junk, and
   * leaving it out of the query stops anyone, a removed member included, from parking far-future
   * entities in every reader's window.
   */
  qsCeiling(): bigint | undefined {
    return this.headSeen > 0n ? this.headSeen + CATCH_UP_MARGIN_BLOCKS : undefined
  }

  private sawHead(block: bigint): void {
    if (block > this.headSeen) this.headSeen = block
  }

  /**
   * The latest expiry a content entity may have: the owner's keepUntil, or a 30-day lease from the block
   * the entity last changed (its creation or its latest extension, Arkiv's updatedAt), plus ten minutes.
   * Anchored to the entity, not to this reader's head, so a live tab and a later cold reader agree.
   */
  private expiryCeiling(entity: { updatedAt: bigint }, keepUntil: string | null | undefined): bigint {
    const lease = entity.updatedAt + blocks(LIFETIME.snapshot)
    const keep = keepUntil ? BigInt(keepUntil) : 0n
    return (keep > lease ? keep : lease) + EXPIRY_SLACK_BLOCKS
  }

  /** True while the live socket is down and this session catches up by polling instead. */
  get livePaused(): boolean {
    return this.pollTimer !== null
  }

  /**
   * The socket errored: catch up by polling until a live event arrives again. For the first two
   * minutes it checks every 20 seconds, as someone waiting on a reply would want; after that each check
   * waits twice as long, up to five minutes, so a tab left open with a refused socket does not spend
   * its whole query budget. Emits `live` (false, then true).
   */
  private socketFailed(): void {
    if (this.pollTimer || this.resyncInterval === 0) return
    let delay = POLL_WHILE_SOCKET_DOWN_MS
    let polls = 0
    const next = () => {
      this.pollTimer = setTimeout(() => {
        void this.resync({ joins: true })
          .catch((e) => this.emit("error", [e]))
          .finally(() => {
            if (this.pollTimer === null || this.status === "destroyed") return
            if (++polls >= 6) delay = Math.min(delay * 2, POLL_MAX_MS)
            next()
          })
      }, delay)
    }
    next()
    this.emit("live", [false])
  }

  private socketHealthy(): void {
    if (!this.pollTimer) return
    clearTimeout(this.pollTimer)
    this.pollTimer = null
    this.emit("live", [true])
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
    if (e.type === "extended" && e.key === this.aclKey) {
      if (this.aclExpiresAt === null || e.expiresAt > this.aclExpiresAt) this.aclExpiresAt = e.expiresAt
      return
    }
    if (e.type === "extended" && this.snapshot && e.key === this.snapshot.key) {
      this.snapshot.expiresAt = e.expiresAt
      this.emit("lease", [this.snapshot])
    }
    // an entity this session already applied, now extended past the owner's ceiling: every cold reader
    // ignores it from here on, so this session no longer matches them, and says so
    if (e.type === "extended" && this.appliedKeys.has(e.key) && e.key !== this.aclKey && this.acl) {
      const ceiling = this.expiryCeiling({ updatedAt: e.block }, this.acl.keepUntil)
      if (e.expiresAt > ceiling) this.emit("diverged", [e.key])
      return
    }
    if (e.type === "extended" && this.snapshot && e.key === this.snapshot.key) return
    this.sawHead(e.block)
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

  private markProven(ranges: [client: number, from: number, to: number][], block: bigint, entity: Hex): void {
    for (const [client, from, to] of ranges) {
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
    return inRange ? { address, proven: true } : { address, proven: false, via: this.carrierOf(client, clock) ?? this.claimedVia.get(client) }
  }

  /**
   * Which member's snapshot carried this clock: the newest applied snapshot holding an item there.
   * Claimed text always names its carrier, whether or not that snapshot listed an authors entry.
   */
  carrierOf(client: number, clock: number): Hex | undefined {
    return (this.carried.get(client) ?? []).find((r) => r.from <= clock && clock < r.to)?.via
  }

  /** True if the update carries, at a clock an applied update already proved, an item other than that one. */
  private conflictsWithProven(update: Uint8Array): boolean {
    // struct against struct, as each applied update wrote it: whether that item was deleted since does
    // not matter, or a writer could delete their text and reuse its clocks for something else
    for (const st of Y.decodeUpdate(update).structs) {
      if (st instanceof Y.Item && !(st.content instanceof Y.ContentDeleted) && this.verifiedUnits.conflicts(this.doc, st)) return true
    }
    return false
  }

  /** True if an applied update that section 5 orders after `entity` (later block, or same block and larger key) wrote other content at its clocks. */
  private clashesWithLater(entity: StoredEntity, update: Uint8Array): boolean {
    const structs = Y.decodeUpdate(update).structs.filter((st): st is Y.Item => st instanceof Y.Item && !(st.content instanceof Y.ContentDeleted))
    for (const h of this.history) {
      if (h.block < entity.createdAt || (h.block === entity.createdAt && h.entity <= entity.key)) continue
      const index = new StructIndex()
      index.add(h.update)
      if (structs.some((st) => index.conflicts(this.doc, st))) return true
    }
    return false
  }

  /** Records what an applied update wrote (see conflictsWithProven). */
  private recordUnits(update: Uint8Array): void {
    this.verifiedUnits.add(update)
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
    // in audits, the member list as it stood at the edit's block decides; it falls back to today's list
    // only where that past state cannot be opened (an epoch whose key this session never held)
    const then = this.membershipAtBlock ? await this.memberAtBlock(entity) : undefined
    if (!this.acl || !(then ?? wroteAsMember(this.acl, entity.creator, entity.createdAt))) {
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
    // nor more than the catch-up margin behind it: a backdated qs would put the edit outside every cold
    // reader's window (qs >= base - 60) while live readers apply it, so the two would show different text
    if (entity.attributes.seq + CATCH_UP_MARGIN_BLOCKS < entity.createdAt) return this.reject()
    // the edit's client id must derive from its creator's address with a salt the creator signed
    if (!(await this.checkAuthors(frame.data, entity.creator, frame.header.salt, frame.header.sig))) return this.reject()
    // a writer's two edits that claim the same clocks with different content cannot both count: the
    // earlier one (by creation block, then key) stands and this one is ignored. Live, edits can arrive
    // out of that order; if the one already applied is the later one, this session no longer matches a
    // cold load, so it says so and a fresh load (which keeps the earlier edit) heals it
    if (this.conflictsWithProven(frame.data)) {
      if (live && this.clashesWithLater(entity, frame.data)) this.emit("diverged", [entity.key])
      return this.reject()
    }
    const svBefore = Y.decodeStateVector(Y.encodeStateVector(this.doc))
    this.applyRemote(frame.data)
    if (overridesVerified(this.doc, [frame.data])) {
      // a snapshot already put different text at this edit's clocks: this session has diverged from
      // the chain's genuine edits. Nothing here is proven; a fresh load (updates before snapshots) heals it.
      this.emit("diverged", [entity.key])
    } else {
      // proven: only clocks this update carries as items, struct by struct. parseUpdateMeta's from..to
      // would also span Skip gaps, letting a crafted update vouch for text only a snapshot holds.
      // And only clocks it integrated itself, not ones a snapshot had already filled.
      const ranges: [number, number, number][] = []
      for (const st of Y.decodeUpdate(frame.data).structs) {
        if (!(st instanceof Y.Item)) continue
        const from = Math.max(st.id.clock, svBefore.get(st.id.client) ?? 0)
        if (from < st.id.clock + st.length) ranges.push([st.id.client, from, st.id.clock + st.length])
      }
      this.markProven(ranges, entity.createdAt, entity.key)
      this.recordUnits(frame.data)
    }
    this.pushHistory({ block: entity.createdAt, author: entity.creator.toLowerCase() as Hex, update: frame.data, entity: entity.key })
    this.appliedKeys.add(entity.key)
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
    // seen before: an applied one still counts as this member's choice (with its base), so a reload
    // after an ACL patch does not fall back to an older one; anything else stays as it was
    if (this.seen.has(entity.key)) return this.snapshotBases.get(entity.key) ?? null
    if (!this.acl || !memberAt(this.acl, entity.creator, entity.createdAt)) {
      this.seen.add(entity.key)
      this.reject()
      return null
    }
    const frame = await this.openEntity(entity, KIND.snapshot)
    if (!frame) {
      this.deferred.set(entity.key, entity)
      return null
    }
    const base = BigInt(frame.header.base as string) // a decimal string: openEntity checked the header
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
      // and carry the same flags as its head
      const sameFlags = chunk.readonly === entity.readonly && chunk.permissionlessExtension === entity.permissionlessExtension
      const cf = chunk.creator.toLowerCase() === entity.creator.toLowerCase() && sameFlags ? await this.openEntity(chunk, KIND.chunk, frame.epoch) : null
      if (!cf || cf.header.i !== i + 1 || cf.header.of !== frame.header.id) {
        this.seen.add(entity.key)
        return null
      }
      parts.push(cf.data)
    }
    this.seen.add(entity.key)
    this.deferred.delete(entity.key)
    const state = concat(parts)
    // the header names the assembled size; a mismatch means a missing, extra or swapped part
    if (state.length !== frame.header.size) {
      this.reject()
      return null
    }
    // a snapshot must not carry structs under this session's own client id beyond what we wrote:
    // that would be someone writing as us, and Yjs would then re-randomise our id and mute us
    const ours = Y.parseUpdateMeta(state).to.get(this.doc.clientID)
    if (this.identity && ours !== undefined && ours > (Y.decodeStateVector(Y.encodeStateVector(this.doc)).get(this.doc.clientID) ?? 0)) {
      this.reject()
      this.refusedSnapshots.add(entity.key)
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
          String(Number(client)) === client && // a canonical decimal: "0123" would name 123 twice
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
    const creator = entity.creator.toLowerCase() as Hex
    collect.push({
      key: entity.key,
      state,
      creator,
      own: new Set(claims.filter((c) => c.address === creator).map((c) => c.client)),
      commit: (trimHistory) => this.commitSnapshot(entity, base, chunks, state, claims, trimHistory),
      registerClaims: () => this.registerClaims(entity, claims),
    })
    return base
  }

  /**
   * Makes a checked snapshot count: its authors table, the lease, the history base. A snapshot that
   * arrives live trims history to edits after its base; on load the edits were just read for the
   * catch-up window, so they all stay listed.
   */
  private commitSnapshot(entity: StoredEntity, base: bigint, chunks: Hex[], state: Uint8Array, claims: { client: number; address: Hex; salt: string; sig: Hex }[], trimHistory: boolean): void {
    this.registerClaims(entity, claims)
    this.snapshotBases.set(entity.key, base)
    // remember what this snapshot carried, struct by struct; snapshots commit newest first on load,
    // and a live one is newer than all of them, so it goes to the front
    const via = entity.creator.toLowerCase() as Hex
    for (const st of Y.decodeUpdate(state).structs) {
      if (!(st instanceof Y.Item)) continue
      const list = this.carried.get(st.id.client) ?? []
      const range = { from: st.id.clock, to: st.id.clock + st.length, via }
      if (trimHistory) list.unshift(range)
      else list.push(range)
      this.carried.set(st.id.client, list)
    }
    this.appliedKeys.add(entity.key)
    this.stats.snapshotsApplied++
    if (!this.snapshot || base >= this.snapshot.base) {
      this.baseState = state
      if (trimHistory && !this.fullHistory) this.history.splice(0, this.history.length, ...this.history.filter((h) => h.block >= base))
      this.snapshot = { key: entity.key, base, expiresAt: entity.expiresAt, chunks, creator: entity.creator.toLowerCase() as Hex }
      this.updatesSinceSnapshot = 0
      this.bytesSinceSnapshot = 0
      this.emit("lease", [this.snapshot])
    }
  }

  private registerClaims(entity: StoredEntity, claims: { client: number; address: Hex; salt: string; sig: Hex }[]): void {
    for (const c of claims) {
      this.claimedAuthors.set(c.client, c.address)
      this.claimedVia.set(c.client, entity.creator.toLowerCase() as Hex)
      this.salts.set(c.client, c.salt)
      this.sigs.set(c.client, c.sig)
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
      const verified = this.history.map((h) => h.update)
      const others = [...this.ownSnapshots.values()].filter((o) => o.creator !== st.creator)
      if (snapshotConflicts(this.doc, st.state, verified) || overridesVerified(trial, verified) || overruledByOwners(this.doc, [st], others).size) {
        this.reject()
        this.refusedSnapshots.add(st.key)
        continue
      }
      this.applyRemote(st.state)
      st.commit(true)
      this.ownSnapshots.set(st.creator, st)
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
      name: clipName(String(frame.header.name ?? "")),
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
    // edits, snapshots, chunks and join requests MUST be readonly: a patchable one could be rewritten
    // after the fact while keeping its original creation block
    if (kind !== KIND.acl && !entity.readonly) throw new MalformedHeader(`${kind} entity is not readonly`)
    // and no edit, snapshot or chunk may outlive what the owner chose: the larger of keepUntil and a fresh
    // 30-day lease from now. Otherwise any member could keep a readable copy alive past the owner's ceiling.
    if ((kind === KIND.update || kind === KIND.snapshot || kind === KIND.chunk) && this.acl && entity.expiresAt > this.expiryCeiling(entity, this.acl.keepUntil)) {
      // an audit asks what the owner had chosen when the entity was last extended: lowering keepUntil
      // afterwards cannot take back a member's kept proof
      const then = this.membershipAtBlock ? await this.aclAtBlock(entity.updatedAt) : null
      if (then === "unknown") this.auditUnchecked++
      if (!then || then === "unknown" || entity.expiresAt > this.expiryCeiling(entity, then.keepUntil)) {
        throw new MalformedHeader(`${kind} entity expires after the owner's lifetime for the document`)
      }
    }
    const frame = await this.decryptEntity(entity, kind, epochHint)
    // a frame that decrypts but breaks its header schema is ignored for good (callers count it as rejected)
    const problem = frame && headerProblem(kind, frame.header)
    if (problem) throw new MalformedHeader(`${kind} header: ${problem}`)
    return frame
  }

  /** Decrypts and decodes one entity; null if this session cannot open it (yet). */
  private async decryptEntity(entity: StoredEntity, kind: Kind, epochHint?: number): Promise<Frame | null> {
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
    if (this.readOnly) throw new Error("this session was opened read-only")
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

  /**
   * Re-reads the member list by key (arkiv_getEntity, not billed as a query) in case a patch was
   * missed during a socket gap. True if the epoch moved.
   */
  private async refreshAclExpiry(): Promise<void> {
    if (!this.aclKey) return
    const acl = await this.fetch(this.aclKey)
    if (acl) this.aclExpiresAt = acl.expiresAt
  }

  private async refreshAcl(): Promise<boolean> {
    if (!this.acl || !this.aclKey) return false
    const acl = await this.fetch(this.aclKey)
    if (!acl || (acl.attributes.seq === this.aclSeq && !this.acl.rosterHidden)) return false
    const before = this.acl.epoch
    await this.applyAclEntity(acl)
    return this.acl.epoch !== before
  }

  private async flushUpdates(updates: Uint8Array[]): Promise<FlushInfo | null> {
    {
      // a writer whose socket missed a rotation would keep encrypting under the old key, which the
      // removed member still holds. One free read by key before each write closes that window.
      if (await this.refreshAcl()) this.enqueue(() => this.loadState())
      this.assertWriter()
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
        // readonly: an edit can never be patched later, so what readers prove is what was written
        creates: [{ payload, attributes: { doc: this.link.doc, kind: KIND.update, seq: head }, lifetimeSeconds: this.snapshotLifetime(head), ...this.keepUntilExpiry(head), readonly: true }],
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
    if (await this.refreshAcl()) await this.loadState()
    if (this.acl.rosterHidden) return 0
    const base = this.snapshot?.base ?? 0n
    const from = base > CATCH_UP_MARGIN_BLOCKS ? base - CATCH_UP_MARGIN_BLOCKS : 0n
    // an audit reads every update, not only those of today's list: someone the owner erased from the
    // list's history still wrote what they wrote, and the member list at each edit's block decides
    const updates = await this.queryUpdates(from)
    const before = this.stats.updatesApplied
    const byAge = [...updates.entities].sort((x, y) => (x.createdAt !== y.createdAt ? (x.createdAt < y.createdAt ? -1 : 1) : x.key < y.key ? -1 : x.key > y.key ? 1 : 0))
    for (const u of byAge) await this.applyUpdateEntity(u, false)
    // a join request missed live (socket gap, stranger-fetch cap) is picked up on the periodic resync
    if (options.joins && this.role === "owner") await this.loadJoinRequests()
    return this.stats.updatesApplied - before
  }

  private async writeSnapshot(extra: BatchSpec = {}, minLifetimeSeconds = 0): Promise<FlushInfo> {
    this.assertWriter()
    const { epoch, key } = this.currentContentKey()
    await this.resync()
    const head = await this.store.head()
    // anything still buffered is already in the doc state, so the snapshot covers it;
    // keep it aside in case the write fails
    const held = this.pending
    this.pending = []
    const state = Y.encodeStateAsUpdate(this.doc)
    // replace my previous snapshot rather than pile up a new full copy every session
    const mineBefore = this.snapshot && this.snapshot.creator === this.identity!.address.toLowerCase() ? this.snapshot : null
    const previous = mineBefore ? [mineBefore.key, ...mineBefore.chunks] : []
    // The owner's lifetime, computed afresh from keepUntil: it already covers a snapshot kept for proof
    // (keepMyProof never goes past keepUntil). Carrying the old snapshot's expiry forward instead would
    // creep past the ceiling, since a transaction lands a block or more after `head`, until readers
    // refuse the snapshot.
    const lifetime = Math.max(this.snapshotLifetime(head), Math.min(minLifetimeSeconds, this.snapshotLifetime(head)))
    let written
    try {
      written = await writeSnapshotEntities(
        this.store,
        this.link.doc,
        epoch,
        key,
        state,
        head,
        this.now(),
        KIND.snapshot,
        this.authorTable(state),
        lifetime,
        { ...extra, deletes: [...(extra.deletes ?? []), ...previous] },
        this.keepDeadline(head),
      )
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
  /**
   * When the owner keeps the document past a fresh lease, its keepUntil block, so content written for
   * it expires at exactly that block (Arkiv's ExpirationTime.atBlock) wherever the transaction lands.
   */
  private keepDeadline(head: bigint): bigint | undefined {
    const until = this.acl?.keepUntil ? BigInt(this.acl.keepUntil) : 0n
    return until > head + blocks(LIFETIME.snapshot) ? until : undefined
  }

  private keepUntilExpiry(head: bigint): { expiresAtBlock?: bigint } {
    const at = this.keepDeadline(head)
    return at === undefined ? {} : { expiresAtBlock: at }
  }

  private snapshotLifetime(head: bigint): number {
    const until = this.acl?.keepUntil ? BigInt(this.acl.keepUntil) : 0n
    return Math.max(LIFETIME.snapshot, Number(until - head) * BLOCK_SECONDS)
  }

  /**
   * The lease. Once less than half of the newest snapshot's life is left, an
   * active member renews it: by extending it if they created it, or by writing
   * a fresh snapshot of their own if someone else did. Only a snapshot's own
   * creator can extend it, so nobody outside the member list can keep the text
   * alive. Only the owner renews the member list (90 days from each visit).
   * A document nobody opens for a month expires.
   */
  async renewLeaseIfDue(): Promise<boolean> {
    if (!this.snapshot || !this.identity || !this.acl) return false
    if (this.role !== "owner" && this.role !== "writer") return false
    const head = await this.store.head()
    const life = blocks(LIFETIME.snapshot)
    const due = (expiresAt: bigint | null, lifetime = life) => expiresAt !== null && expiresAt - head < BigInt(Math.floor(Number(lifetime) * LEASE_RENEW_FRACTION))
    const aclLife = blocks(LIFETIME.acl)
    const me = this.identity.address.toLowerCase()
    const snapshotDue = due(this.snapshot.expiresAt)
    // only the owner renews the member list (documents made before 18 Oct 2026 let any member do it);
    // re-read its expiry only when it looks due: someone may have extended it already
    const mayExtendAcl = this.role === "owner" || this.aclOpenToAll
    if (mayExtendAcl && due(this.aclExpiresAt, aclLife)) await this.refreshAclExpiry()
    const aclDue = mayExtendAcl && due(this.aclExpiresAt, aclLife)
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
        await this.store.batch({ extensions: [{ key: this.aclKey!, lifetimeSeconds: seconds, expiresAtBlock: keepUntil }] })
        this.stats.writes++
        this.aclExpiresAt = keepUntil
      }
    })
    await this.compact()
  }

  /**
   * Any member: keeps the proof of what you wrote for as long as the owner keeps the document
   * (`keepUntil`, set with keepFor), or for `seconds` if that is sooner. Your edits are entities only
   * you can extend, and readers prove authorship from them, so this extends every one of yours still
   * on chain, the member list they are checked against, and a snapshot of yours (your edits sit on
   * text others wrote). The owner's lifetime is the ceiling: no member can keep the document readable
   * for longer than the owner chose. Only extensions that move expiry later are sent: Arkiv reverts
   * the others.
   */
  async keepMyProof(seconds: number): Promise<{ extended: number; until: bigint }> {
    if (!this.identity || !this.acl || !this.aclKey) throw new Error("open the document with your key first")
    const me = this.identity.address.toLowerCase()
    return this.serial(async () => {
      // the owner's keepUntil may have changed while this tab's socket was away: re-read the list (free)
      await this.refreshAcl()
      await this.refreshAclExpiry()
      const head = await this.store.head()
      const ceiling = this.acl!.keepUntil ? BigInt(this.acl!.keepUntil) : 0n
      if (ceiling <= head + blocks(LIFETIME.snapshot)) {
        throw new Error("The owner keeps this document for its 30-day lease only, and proof cannot outlive the document. Ask the owner to keep it longer (Lifetime tab), then keep your proof.")
      }
      let until = head + blocks(Math.min(seconds, 3 * 365 * 86400)) < ceiling ? head + blocks(Math.min(seconds, 3 * 365 * 86400)) : ceiling
      // only the owner can extend the member list, and proof cannot outlive it: keepFor extends it to
      // keepUntil, so this cap matters only if the list has somehow fallen behind
      const mayExtendAcl = this.role === "owner" || this.aclOpenToAll
      if (!mayExtendAcl && this.aclExpiresAt !== null && this.aclExpiresAt < until) until = this.aclExpiresAt
      const seconds_ = Number(until - head) * BLOCK_SECONDS
      const mine = await queryAll(this.store, { doc: this.link.doc, kind: KIND.update, creators: [me as Hex] })
      const keys = mine.entities.filter((e) => e.owner.toLowerCase() === me && e.expiresAt < until).map((e) => e.key)
      // the list's expiry was just re-read: an extension that would move it earlier reverts the whole batch
      if (mayExtendAcl && this.aclExpiresAt !== null && this.aclExpiresAt < until) keys.push(this.aclKey!)
      // extensions carry no payload; a hundred per transaction keeps each one small
      for (let i = 0; i < keys.length; i += 100) {
        await this.store.batch({ extensions: keys.slice(i, i + 100).map((key) => ({ key, lifetimeSeconds: seconds_, expiresAtBlock: until })) })
        this.stats.writes++
      }
      if (keys.includes(this.aclKey!)) this.aclExpiresAt = until
      // your edits sit on text others wrote, which lapses with the 30-day lease; without it they could
      // not be rebuilt. So a snapshot of yours, holding the whole document, lives as long as they do.
      if ((this.role === "owner" || this.role === "writer") && (!this.snapshot || this.snapshot.creator !== me || this.snapshot.expiresAt < until)) {
        await this.writeSnapshot({}, seconds_)
        keys.push(this.snapshot!.key)
      }
      return { extended: keys.length, until }
    })
  }

  /**
   * Owner: ends the document now. Deletes the member list and every entity the
   * owner created, a hundred per transaction with the member list in the first,
   * so a long-lived document fits the gas limit. Without the member list no reader can verify
   * any edit, so the document stops opening immediately; members' remaining
   * encrypted entities run out on their own expiry (30 days, or the keepUntil date).
   */
  async deleteDocument(): Promise<number> {
    if (this.role !== "owner" || !this.identity) throw new Error("only the owner deletes the document")
    const me = this.identity.address
    return this.serial(async () => {
      const mine = await queryAll(this.store, { doc: this.link.doc, creators: [me] })
      // everything the owner wrote for this document except published versions and their chunks
      // (the only chunks anyone may extend), which are meant to outlive it
      const keys = mine.entities
        .filter((e) => e.owner.toLowerCase() === me.toLowerCase() && e.attributes.kind !== KIND.version && !(e.attributes.kind === KIND.chunk && e.permissionlessExtension))
        .sort((x, y) => Number(y.attributes.kind === KIND.acl) - Number(x.attributes.kind === KIND.acl))
        .map((e) => e.key)
      await this.deleteInBatches(keys)
      this.emit("deleted", [keys.length])
      return keys.length
    })
  }

  /** Deletes a hundred entities per transaction, as rotate and keepMyProof batch theirs, so no transaction outgrows the gas limit. */
  private async deleteInBatches(keys: Hex[]): Promise<void> {
    for (let i = 0; i < keys.length; i += 100) {
      await this.store.batch({ deletes: keys.slice(i, i + 100) })
      this.stats.writes++
    }
  }

  // ---------------------------------------------------------------- membership

  /** Asks the owner to add this session. The request carries our public key and expires in an hour. */
  async requestJoin(): Promise<Hex> {
    if (!this.identity) throw new Error("joining needs an identity")
    return this.serial(async () => {
      const head = await this.store.head()
      const header = { publicKey: `0x${bytesToHex(publicKeyOf(this.identity!.privateKey))}`, name: clipName(this.identity!.name) }
      if (!this.acl) throw new Error("not connected")
      // sealed to the owner's public key: other link holders, including removed members, cannot read it
      const frame = encodeFrame({ kind: KIND.join, doc: hexToBytes(this.link.doc), epoch: 0, header, data: new Uint8Array() }, randomBytes)
      const payload = encodeOuter(0, await sealTo(hexToBytes(this.acl.ownerPublicKey), frame, "join"))
      const result = await this.store.batch({
        creates: [{ payload, attributes: { doc: this.link.doc, kind: KIND.join, seq: head }, lifetimeSeconds: LIFETIME.join, readonly: true }],
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
      // updateAcl works on the latest list: a second approve that raced the first must not add a duplicate
      if (isMember(acl, req.address)) return {}
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
  /**
   * Owner: removes a member. The key rotates and the roster is sealed under it, in one transaction
   * with a snapshot under the new key. With `shredOldEpoch`, the owner's own entities from earlier
   * epochs are then deleted, so the old link no longer opens the owner's earlier text from Arkiv's
   * state (block history keeps it). The owner's earlier text is then vouched for by the new snapshot
   * rather than proven edit by edit. Other members' earlier entities stay until they expire or those
   * members shred them.
   */
  async revoke(address: Hex, options: { shredOldEpoch?: boolean } = {}): Promise<{ shredded: number }> {
    const target = address.toLowerCase()
    if (target === this.link.owner.toLowerCase()) throw new Error("the owner cannot be revoked")
    // a removal records the interval it closes; for someone who never joined there is none, and an entry
    // without one would read as membership from block 0
    if (!this.acl || !isMember(this.acl, target as Hex)) throw new Error("that address is not a member")
    return this.rotate(target as Hex, options)
  }

  /**
   * Owner: starts a new epoch without removing anyone. Members get the new key in their wraps; the
   * document link, which carries only the epoch 0 key, then opens nothing written from here on. Use it
   * when a link may have leaked: people holding it can still ask to join, and the owner decides.
   */
  async rotateKey(options: { shredOldEpoch?: boolean } = {}): Promise<{ shredded: number }> {
    return this.rotate(null, options)
  }

  private async rotate(target: Hex | null, options: { shredOldEpoch?: boolean }): Promise<{ shredded: number }> {
    const epochKey = randomBytes(32)
    await this.updateAcl(async (acl, head) => {
      if (target) {
        const leaving = acl.members.find((m) => m.address.toLowerCase() === target)
        acl.members = acl.members.filter((m) => m.address.toLowerCase() !== target)
        // the interval this removal closes, so edits from any later gap never count
        acl.revoked.push({ address: target, atBlock: head.toString(), ...(leaving ? { addedAtBlock: leaving.addedAtBlock } : {}) })
      }
      // carry every earlier epoch key above 0 forward, sealed under the new key with the roster
      const prior: Record<string, Hex> = { ...(acl.prior ?? {}) }
      for (let n = 1; n <= acl.epoch; n++) {
        const k = this.epochKeys.get(n)
        if (k) prior[String(n)] = `0x${bytesToHex(k)}`
      }
      acl.prior = prior
      acl.epoch += 1
      const wraps: Hex[] = []
      for (const m of acl.members) wraps.push(`0x${bytesToHex(await wrapForMember(epochKey, hexToBytes(m.publicKey), acl.epoch))}`)
      acl.wraps = shuffle(wraps)
      this.epochKeys.set(acl.epoch, epochKey)
      return { snapshot: { epoch: acl.epoch, key: epochKey } }
    })
    if (!options.shredOldEpoch || !this.identity || !this.acl) return { shredded: 0 }
    const epoch = this.acl.epoch
    const me = this.identity.address.toLowerCase()
    return this.serial(async () => {
      const mine = await queryAll(this.store, { doc: this.link.doc, creators: [me as Hex] })
      // updates, snapshots and chunks written under an older key; never the member list or a published version
      const old = mine.entities.filter((e) => {
        if (e.owner.toLowerCase() !== me || !([KIND.update, KIND.snapshot, KIND.chunk] as Kind[]).includes(e.attributes.kind)) return false
        try {
          return decodeOuter(e.payload).epoch < epoch
        } catch {
          return false
        }
      })
      for (let i = 0; i < old.length; i += 100) {
        await this.store.batch({ deletes: old.slice(i, i + 100).map((e) => e.key) })
        this.stats.writes++
      }
      return { shredded: old.length }
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
        const w = await writeSnapshotEntities(this.store, this.link.doc, snapshot.epoch, snapshot.key, Y.encodeStateAsUpdate(this.doc), head, this.now(), KIND.snapshot, this.authorTable(Y.encodeStateAsUpdate(this.doc)), lifetime, patch, this.keepDeadline(head))
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
      const w = await writeSnapshotEntities(this.store, this.link.doc, 0, secret, state, head, this.now(), KIND.version, {}, LIFETIME.version, {})
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
      // only your own edits and join requests: snapshots you wrote carry everyone's text and stay
      const keys = mine.entities
        .filter((e) => e.owner.toLowerCase() === me.toLowerCase() && (e.attributes.kind === KIND.update || e.attributes.kind === KIND.join))
        .map((e) => e.key)
      if (!keys.length) return 0
      await this.deleteInBatches(keys)
      return keys.length
    })
  }

  /**
   * Lists the creators of every entity for this document that came from outside
   * the member list (join requests aside, which strangers send by design). One
   * query without the creator filter: what the normal reads never even fetch.
   */
  async scanOutsiders(): Promise<Hex[]> {
    return (await this.outsiderEntities()).map((e) => e.creator.toLowerCase() as Hex)
  }

  /**
   * The entities behind scanOutsiders(), for tools that need their keys. One page of up to 200 and
   * no more: the document id is public, so anyone can pile junk on it, and following every page would
   * spend every reader's query budget. `outsidersTruncated` says when the page was full.
   */
  async outsiderEntities(): Promise<StoredEntity[]> {
    if (!this.acl || this.acl.rosterHidden) return []
    const all = await this.store.query({ doc: this.link.doc, limit: 200 })
    this.outsidersTruncated = !!all.cursor
    const members = new Set(memberAddresses(this.acl))
    const acl = this.acl
    return all.entities.filter(
      (e) =>
        e.attributes.kind !== KIND.join &&
        !members.has(e.creator.toLowerCase() as Hex) &&
        // a removed member's edits from before their removal count, so they are not outside writes
        !(e.attributes.kind === KIND.update && wroteAsMember(acl, e.creator, e.createdAt)),
    )
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
    if (this.pollTimer) clearTimeout(this.pollTimer)
    this.pollTimer = null
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
    const problem = headerProblem(KIND.version, first.header)
    if (problem) throw new Error(`version header: ${problem}`)
    const parts = [first.data]
    const chunks = Array.isArray(first.header.chunks) ? (first.header.chunks as Hex[]) : []
    for (const [i, key] of chunks.entries()) {
      const c = await store.get(key)
      if (!c || c.creator.toLowerCase() !== entity.creator.toLowerCase()) throw new Error("version chunk missing")
      if (!c.readonly) throw new Error("a chunk of this version is not readonly on chain, so its creator could still change it")
      const cf = await read(c, KIND.chunk)
      if (headerProblem(KIND.chunk, cf.header)) throw new Error("version chunk header is malformed")
      if (cf.header.i !== i + 1 || cf.header.of !== first.header.id) throw new Error("version chunk does not belong to this version")
      parts.push(cf.data)
    }
    const state = concat(parts)
    if (state.length !== first.header.size) throw new Error("version size does not match its header")
    const doc = new Y.Doc()
    Y.applyUpdate(doc, state)
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
  const doc = new Y.Doc()
  const p = new ArkivProvider(doc, { store: atBlockStore(store, block), link, identity, flushIntervalMs: 0, autoCompact: false })
  await p.connect()
  p.destroy()
  return doc
}

/**
 * A read-only view of the chain as it stood at `block`: every query and read by key is pinned there
 * with atBlock, and nothing live. Entities deleted since are still there, so a member's proof outlives
 * an owner who deletes the member list, for as long as the node keeps past state.
 */
export function atBlockStore(store: ArkivStore, block: bigint): ArkivStore {
  return {
    address: undefined,
    query: (spec) => store.query({ ...spec, atBlock: spec.atBlock ?? block }),
    watch: () => () => undefined,
    head: async () => block,
    get: (key, b) => store.get(key, b ?? block),
    batch: () => Promise.reject(new Error("read-only")),
    predictKeys: () => Promise.reject(new Error("read-only")),
  }
}

// ------------------------------------------------------------------ helpers

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i])
}

const BLOCK_SECONDS = 2
/** Slack on the expiry ceiling, for the gap between a writer's head and a reader's (ten minutes of blocks). */
const EXPIRY_SLACK_BLOCKS = 300n
/** How many pages (200 entities each) an audit reads without the `$creator` filter before it narrows to today's list. */
const AUDIT_PAGES = 5
/** How often a session catches up by query while its WebSocket is failing (one query each time). */
const POLL_WHILE_SOCKET_DOWN_MS = 20_000
const POLL_MAX_MS = 300_000

/** Seconds to whole blocks, rounding up. */
function blocks(seconds: number): bigint {
  return BigInt(Math.ceil(seconds / BLOCK_SECONDS))
}

async function aclSpec(doc: Hex, metaKey: Uint8Array, acl: Acl, epochKey: Uint8Array | undefined, head: bigint): Promise<CreateSpec> {
  const header = (await toHeader(acl, epochKey, doc)) as unknown as Record<string, unknown>
  const payload = encodeOuter(0, await seal(metaKey, encodeFrame({ kind: KIND.acl, doc: hexToBytes(doc), epoch: 0, header, data: new Uint8Array() }, randomBytes)))
  // owner-only extension: a stranger cannot keep the member list (names, public keys) alive
  return { payload, attributes: { doc, kind: KIND.acl, seq: head }, lifetimeSeconds: LIFETIME.acl, permissionlessExtension: false }
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
  expiresAtBlock?: bigint,
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
  // every snapshot, version and chunk is readonly: its creator could otherwise patch the content later
  // and keep the original block. Only published versions may be kept alive by anyone.
  const flags = { readonly: true, permissionlessExtension: kind === KIND.version }
  const spec = async (frame: Frame, k: Kind): Promise<CreateSpec> => ({
    payload: encodeOuter(epoch, await seal(key, encodeFrame(frame, randomBytes))),
    attributes: { doc, kind: k, seq: head },
    lifetimeSeconds: lifetime,
    ...(expiresAtBlock !== undefined ? { expiresAtBlock } : {}),
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
      // run by run: later edits split items, so one struct may now span several integrated items
      const end = struct.id.clock + struct.length
      for (let c = struct.id.clock; c < end; ) {
        let found: Y.Item | Y.GC
        try {
          found = Y.getItem(doc.store, Y.createID(struct.id.client, c)) as Y.Item | Y.GC
        } catch {
          break // still pending: nothing has replaced it
        }
        const stop = Math.min(found.id.clock + found.length, end)
        if (found instanceof Y.Item && !found.deleted && rangesDiffer(doc, found, struct, c, stop)) return true
        c = stop
      }
    }
  }
  return false
}

/**
 * True if items `x` and `y` differ anywhere in the clocks [a, b) they both cover. The full key is compared
 * at `a`; past it, origins are implied by the clock and right origins, parent and kind were just compared,
 * so only the content can differ, and a run of text is compared as one slice instead of clock by clock.
 */
function rangesDiffer(doc: Y.Doc, x: Y.Item, y: Y.Item, a: number, b: number): boolean {
  if (unitKey(doc, x, a - x.id.clock) !== unitKey(doc, y, a - y.id.clock)) return true
  if (b - a <= 1) return false
  if (x.content instanceof Y.ContentString && y.content instanceof Y.ContentString) {
    return x.content.str.slice(a + 1 - x.id.clock, b - x.id.clock) !== y.content.str.slice(a + 1 - y.id.clock, b - y.id.clock)
  }
  for (let c = a + 1; c < b; c++) if (unitKey(doc, x, c - x.id.clock) !== unitKey(doc, y, c - y.id.clock)) return true
  return false
}

/** Decoded items by client, sorted by clock, for finding the ones that overlap a clock range. */
class StructIndex {
  private readonly byClient = new Map<number, Y.Item[]>()

  add(update: Uint8Array, clients?: Set<number>): void {
    for (const st of Y.decodeUpdate(update).structs) {
      if (!(st instanceof Y.Item) || st.content instanceof Y.ContentDeleted) continue
      if (clients && !clients.has(st.id.client)) continue
      const list = this.byClient.get(st.id.client) ?? []
      // keep clock order; structs of one client arrive almost always in order, so this is usually a push
      let i = list.length
      while (i > 0 && list[i - 1]!.id.clock > st.id.clock) i--
      list.splice(i, 0, st)
      this.byClient.set(st.id.client, list)
    }
  }

  /** True if `st` differs from any indexed item at a clock both cover. */
  conflicts(doc: Y.Doc, st: Y.Item): boolean {
    const list = this.byClient.get(st.id.client)
    if (!list) return false
    const from = st.id.clock
    const to = st.id.clock + st.length
    // first item that ends after `from`
    let lo = 0
    let hi = list.length
    while (lo < hi) {
      const mid = (lo + hi) >> 1
      if (list[mid]!.id.clock + list[mid]!.length <= from) lo = mid + 1
      else hi = mid
    }
    for (let i = lo; i < list.length && list[i]!.id.clock < to; i++) {
      const v = list[i]!
      const a = Math.max(from, v.id.clock)
      const b = Math.min(to, v.id.clock + v.length)
      if (a < b && rangesDiffer(doc, v, st, a, b)) return true
    }
    return false
  }
}

/**
 * True if the snapshot itself carries, at a clock a verified update wrote, an item other than that
 * update's: struct against struct, before anything is merged. Merging alone hides this when the
 * update is already integrated, because Yjs then drops the snapshot's struct and applies the rest.
 */
export function snapshotConflicts(doc: Y.Doc, state: Uint8Array, updates: Uint8Array[]): boolean {
  const verified = new StructIndex()
  for (const u of updates) verified.add(u)
  for (const st of Y.decodeUpdate(state).structs) {
    if (st instanceof Y.Item && !(st.content instanceof Y.ContentDeleted) && verified.conflicts(doc, st)) return true
  }
  return false
}

/**
 * Section 5: a member speaks for their own client ids. Returns the snapshots in `candidates` that
 * carry, under a client id an owner snapshot's valid `authors` entry gives to that snapshot's own
 * creator, an item other than the one the owner's snapshot holds at that clock. Age does not matter:
 * a newer snapshot from someone else cannot rewrite what a member's own snapshot says they wrote.
 */
function overruledByOwners(doc: Y.Doc, candidates: PendingSnapshot[], owners: { creator: Hex; state: Uint8Array; own: Set<number> }[]): Set<Hex> {
  const out = new Set<Hex>()
  for (const owner of owners) {
    if (!owner.own.size) continue
    const index = new StructIndex()
    index.add(owner.state, owner.own)
    for (const st of candidates) {
      if (st.creator === owner.creator || out.has(st.key)) continue
      for (const s of Y.decodeUpdate(st.state).structs) {
        if (s instanceof Y.Item && owner.own.has(s.id.client) && !(s.content instanceof Y.ContentDeleted) && index.conflicts(doc, s)) {
          out.add(st.key)
          break
        }
      }
    }
  }
  return out
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
