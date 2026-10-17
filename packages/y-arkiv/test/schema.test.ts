import { readFileSync } from "node:fs"
import Ajv2020 from "ajv/dist/2020.js"
import { describe, expect, it } from "vitest"
import { decodeFrame, decodeOuter } from "../src/codec.js"
import { deriveEpochZeroKey, deriveMetaKey, open, unwrapAsMember } from "../src/crypto.js"
import { hexToBytes } from "../src/hex.js"

const root = new URL("../../../spec/", import.meta.url)
const load = (p: string) => JSON.parse(readFileSync(new URL(p, root), "utf8"))
const ajv = new Ajv2020({ allErrors: true, strict: false })
const compiled = new Map<string, ReturnType<typeof ajv.compile>>()
const schema = (name: string) => compiled.get(name) ?? (compiled.set(name, ajv.compile(load(`schema/${name}.json`))), compiled.get(name)!)
const vec = load("vectors/document.json")

describe("JSON Schema matches the reference implementation", () => {
  it("every vector entity matches entity.json", () => {
    const check = schema("entity")
    for (const e of vec.entities) expect(check(e), JSON.stringify(check.errors)).toBe(true)
  })

  it("every decrypted header matches its kind's schema", async () => {
    const secret = hexToBytes(vec.linkSecret)
    const keys = new Map<number, Uint8Array>([[0, deriveEpochZeroKey(secret)]])
    const meta = deriveMetaKey(secret)
    const byKind: Record<string, ReturnType<typeof schema>> = {
      a: schema("acl-header"), u: schema("update-header"), s: schema("snapshot-header"),
      v: schema("snapshot-header"), c: schema("chunk-header"), j: schema("join-header"),
    }
    const kind = (e: { attributes: { name: string; value: string }[] }) => e.attributes.find((a) => a.name === "qk")!.value
    // the ACL first, so later epochs can be unwrapped with Bea's synthetic key
    const ordered = [...vec.entities].sort((a, b) => (kind(a) === "a" ? -1 : kind(b) === "a" ? 1 : 0))
    let checked = 0
    for (const e of ordered) {
      const k = kind(e)
      const { epoch, envelope } = decodeOuter(hexToBytes(e.payload))
      const key = k === "a" || k === "j" ? meta : keys.get(epoch)
      if (!key) continue
      const frame = decodeFrame(await open(key, envelope))
      expect(byKind[k]!(frame.header), `${k}: ${JSON.stringify(byKind[k]!.errors)}`).toBe(true)
      checked++
      if (k === "a" && frame.header.epoch) {
        const wrap = (frame.header.wraps as Record<string, string>)[vec.members.bea]
        keys.set(frame.header.epoch as number, await unwrapAsMember(hexToBytes(wrap!), vec.privateKeys.bea, frame.header.epoch as number))
      }
    }
    expect(checked).toBe(vec.entities.length)
  })
})
