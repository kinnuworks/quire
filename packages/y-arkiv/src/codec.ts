/**
 * Binary framing for Quire payloads.
 *
 * On chain:   [ 'Q' | version | epoch:u32be ] [ arkiv-encryption envelope ]
 * Inside:     [ 'QF' | version | kind | doc:32 | epoch:u32be | hlen:u32be | dlen:u32be ]
 *             [ header (UTF-8 JSON) ] [ data ] [ random padding up to a bucket ]
 *
 * The inner frame repeats the doc id, kind and epoch so a ciphertext copied
 * into another document or kind fails to decode, even though the envelope
 * itself carries no associated data.
 */
import { PAD_BUCKETS, type Kind } from "./protocol.js"

export const OUTER_MAGIC = 0x51 // 'Q'
export const FRAME_MAGIC = [0x51, 0x46] as const // 'QF'
export const FORMAT_VERSION = 1
const OUTER_HEADER = 6
const FRAME_HEADER = 2 + 1 + 1 + 32 + 4 + 4 + 4

export class FrameError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "FrameError"
  }
}

export type Frame = {
  kind: Kind
  doc: Uint8Array
  epoch: number
  header: Record<string, unknown>
  data: Uint8Array
}

const enc = new TextEncoder()
const dec = new TextDecoder("utf-8", { fatal: true })

/** Smallest bucket that fits `n` bytes, or `n` itself if it is larger than every bucket. */
export function bucketFor(n: number): number {
  for (const b of PAD_BUCKETS) if (n <= b) return b
  return n
}

export function encodeFrame(frame: Frame, random: (n: number) => Uint8Array): Uint8Array {
  if (frame.doc.length !== 32) throw new FrameError("doc id must be 32 bytes")
  const header = enc.encode(JSON.stringify(frame.header))
  const used = FRAME_HEADER + header.length + frame.data.length
  const out = new Uint8Array(bucketFor(used))
  const view = new DataView(out.buffer)
  out[0] = FRAME_MAGIC[0]
  out[1] = FRAME_MAGIC[1]
  out[2] = FORMAT_VERSION
  out[3] = frame.kind.charCodeAt(0)
  out.set(frame.doc, 4)
  view.setUint32(36, frame.epoch)
  view.setUint32(40, header.length)
  view.setUint32(44, frame.data.length)
  out.set(header, FRAME_HEADER)
  out.set(frame.data, FRAME_HEADER + header.length)
  if (out.length > used) out.set(random(out.length - used), used)
  return out
}

export function decodeFrame(bytes: Uint8Array): Frame {
  if (bytes.length < FRAME_HEADER) throw new FrameError("frame too short")
  if (bytes[0] !== FRAME_MAGIC[0] || bytes[1] !== FRAME_MAGIC[1]) throw new FrameError("bad frame magic")
  if (bytes[2] !== FORMAT_VERSION) throw new FrameError(`unsupported frame version ${bytes[2]}`)
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const hlen = view.getUint32(40)
  const dlen = view.getUint32(44)
  if (FRAME_HEADER + hlen + dlen > bytes.length) throw new FrameError("frame lengths overflow payload")
  let header: Record<string, unknown>
  try {
    header = JSON.parse(dec.decode(bytes.subarray(FRAME_HEADER, FRAME_HEADER + hlen)))
  } catch {
    throw new FrameError("frame header is not valid JSON")
  }
  if (header === null || typeof header !== "object" || Array.isArray(header)) {
    throw new FrameError("frame header must be an object")
  }
  return {
    kind: String.fromCharCode(bytes[3]!) as Kind,
    doc: bytes.slice(4, 36),
    epoch: view.getUint32(36),
    header,
    data: bytes.slice(FRAME_HEADER + hlen, FRAME_HEADER + hlen + dlen),
  }
}

export function encodeOuter(epoch: number, envelope: Uint8Array): Uint8Array {
  const out = new Uint8Array(OUTER_HEADER + envelope.length)
  out[0] = OUTER_MAGIC
  out[1] = FORMAT_VERSION
  new DataView(out.buffer).setUint32(2, epoch)
  out.set(envelope, OUTER_HEADER)
  return out
}

export function decodeOuter(payload: Uint8Array): { epoch: number; envelope: Uint8Array } {
  if (payload.length < OUTER_HEADER + 28) throw new FrameError("payload too short")
  if (payload[0] !== OUTER_MAGIC) throw new FrameError("not a Quire payload")
  if (payload[1] !== FORMAT_VERSION) throw new FrameError(`unsupported payload version ${payload[1]}`)
  const epoch = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(2)
  return { epoch, envelope: payload.subarray(OUTER_HEADER) }
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}
