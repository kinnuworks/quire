/**
 * Quire protocol v1: how a Yjs document lives on Arkiv.
 *
 * Every Quire entity carries exactly four public attributes. Everything else,
 * including the document id's meaning, member names and all text, sits inside
 * an encrypted payload. See PROTOCOL.md for the normative description.
 */

/** Protocol tag stored in `qp`. Lets any reader find Quire entities without our servers. */
export const PROTOCOL_TAG = "quire1"

/** Public attribute names. Lowercase on purpose: the chain rejects uppercase names. */
export const ATTR = {
  /** str: protocol tag, always {@link PROTOCOL_TAG}. */
  protocol: "qp",
  /** bytes32: random document id. Not derived from the title, so it reveals nothing. */
  doc: "qd",
  /** str: entity kind, one of {@link KIND}. */
  kind: "qk",
  /** u64: the writer's view of the chain head when it wrote. Used for range catch-up. */
  seq: "qs",
} as const

export const KIND = {
  /** A merged batch of Yjs updates from one writer. */
  update: "u",
  /** A full document state, possibly split across chunk entities. */
  snapshot: "s",
  /** A continuation chunk of a snapshot or published version. */
  chunk: "c",
  /** The member list and wrapped epoch keys. One per document, owned by the document owner. */
  acl: "a",
  /** A request from a new device to join, carrying its public key. */
  join: "j",
  /** A frozen, readonly version that anyone can keep alive. */
  version: "v",
} as const

export type Kind = (typeof KIND)[keyof typeof KIND]

/** Seconds. Each kind lives as long as the product needs it, and no longer. */
export const LIFETIME = {
  /** Updates only need to survive until a snapshot covers them. */
  update: 7 * 24 * 3600,
  /** Snapshots are a lease: every active session extends the newest one. */
  snapshot: 30 * 24 * 3600,
  /** The ACL follows the document. Extended together with the snapshot. */
  acl: 30 * 24 * 3600,
  /** A join request is answered within minutes or dropped. */
  join: 3600,
  /** Published versions start at a year; any reader can extend them. */
  version: 365 * 24 * 3600,
} as const

/** How far before the snapshot's base we start reading updates, in blocks. Covers in-flight writes. */
export const CATCH_UP_MARGIN_BLOCKS = 60n

/** Compact once this many updates or bytes have piled up since the newest snapshot. */
export const COMPACT_AFTER_UPDATES = 120
export const COMPACT_AFTER_BYTES = 48 * 1024

/** Extend the snapshot lease when less than this fraction of its life is left. */
export const LEASE_RENEW_FRACTION = 0.5

/** Content type for every Quire payload. */
export const CONTENT_TYPE = "application/vnd.quire.v1"

/**
 * Plaintext is padded to one of these sizes before encryption, so ciphertext
 * length says little about how much was typed. The top bucket stays under
 * arkiv-encryption's 100,000 byte plaintext limit.
 */
export const PAD_BUCKETS = [256, 1024, 4096, 16384, 65536, 98304] as const

/** Largest plaintext one entity carries; bigger states are chunked. */
export const MAX_CHUNK_PLAINTEXT = PAD_BUCKETS[PAD_BUCKETS.length - 1]! - 64

/** Writers flush buffered edits at most once per this many milliseconds (about one block). */
export const FLUSH_INTERVAL_MS = 2000

/** How many entities from non-members an owner's session fetches per minute, looking for join requests. */
export const STRANGER_FETCHES_PER_MINUTE = 30

/**
 * Payload bytes per transaction. Payloads travel hex-encoded in the
 * transaction, and the public RPC gateway answers BAD_REQUEST once a request
 * passes about 256 KiB. Measured (arkiv/probes): payloads totalling 120,000
 * bytes land, 130,000 do not, and the SDK reports it only as "Execution error
 * without revert data" (see friction.md).
 */
export const MAX_BATCH_PAYLOAD_BYTES = 100_000
