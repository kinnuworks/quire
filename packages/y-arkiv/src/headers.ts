/**
 * Frame header checks, written to match spec/schema exactly (the field set,
 * types and patterns), so every reader ignores the same malformed entities.
 * The Python reader runs the same rules whether or not jsonschema is installed.
 */
import { KIND, type Kind } from "./protocol.js"

const HEX16 = /^[0-9a-f]{32}$/
const KEY = /^0x[0-9a-f]{64}$/
const SIG = /^0x[0-9a-fA-F]{130}$/
const ADDRESS = /^0x[0-9a-f]{40}$/
const DECIMAL = /^[0-9]+$/

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v)
const isInt = (v: unknown, min = Number.MIN_SAFE_INTEGER) => typeof v === "number" && Number.isSafeInteger(v) && v >= min
const str = (v: unknown, re: RegExp) => typeof v === "string" && re.test(v)

function fields(h: Record<string, unknown>, allowed: string[]): string | null {
  for (const k of allowed) if (!(k in h)) return `missing ${k}`
  for (const k of Object.keys(h)) if (!allowed.includes(k)) return `unexpected field ${k}`
  return null
}

/** Why a header breaks its schema, or null if it is well formed. Kinds without a content header pass. */
export function headerProblem(kind: Kind, h: unknown): string | null {
  if (!isObject(h)) return "header is not an object"
  if (kind === KIND.update) {
    return fields(h, ["t", "salt", "sig"]) ?? (!isInt(h.t) ? "t is not an integer" : !str(h.salt, HEX16) ? "salt is not 32 hex characters" : !str(h.sig, SIG) ? "sig is not a 65-byte hex signature" : null)
  }
  if (kind === KIND.snapshot || kind === KIND.version) {
    const missing = fields(h, ["id", "base", "t", "chunks", "size", "authors"])
    if (missing) return missing
    if (!str(h.id, HEX16)) return "id is not 32 hex characters"
    if (!str(h.base, DECIMAL)) return "base is not a decimal string"
    if (!isInt(h.t)) return "t is not an integer"
    if (!Array.isArray(h.chunks) || !h.chunks.every((k) => str(k, KEY))) return "chunks is not a list of entity keys"
    if (!isInt(h.size, 0)) return "size is not a non-negative integer"
    if (!isObject(h.authors)) return "authors is not an object"
    for (const [client, entry] of Object.entries(h.authors)) {
      if (!DECIMAL.test(client)) return `authors key ${client} is not a decimal client id`
      if (!isObject(entry) || fields(entry, ["address", "salt", "sig"])) return `authors entry ${client} does not have exactly address, salt and sig`
      if (!str(entry.address, ADDRESS) || !str(entry.salt, HEX16) || !str(entry.sig, SIG)) return `authors entry ${client} has a malformed field`
    }
    return null
  }
  if (kind === KIND.chunk) {
    return fields(h, ["i", "of"]) ?? (!isInt(h.i, 1) ? "i is not a positive integer" : !str(h.of, HEX16) ? "of is not 32 hex characters" : null)
  }
  return null
}

/** Thrown for a decrypted frame whose header breaks the schema: the entity is ignored, never retried. */
export class MalformedHeader extends Error {}
