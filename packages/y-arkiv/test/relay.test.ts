import { afterEach, describe, expect, it, vi } from "vitest"
import { SdkStore } from "../src/sdk.js"

describe("relay", () => {
  afterEach(() => vi.unstubAllGlobals())

  it("sends only arkiv_query through the relay; reads by key and block numbers go straight to Arkiv", async () => {
    const seen: { url: string; method: string }[] = []
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body))
      seen.push({ url: String(input), method: body.method })
      const result = body.method === "eth_blockNumber" ? "0x10" : body.method === "arkiv_query" ? { data: [], blockNumber: "0x10" } : null
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }), { headers: { "content-type": "application/json" } })
    })
    const store = new SdkStore({ relayUrl: "/api/rpc" })
    await store.head()
    await store.query({ doc: `0x${"ab".repeat(32)}` })
    await store.get(`0x${"cd".repeat(32)}`)
    expect(seen.map((s) => [s.method, s.url === "/api/rpc"])).toEqual([
      ["eth_blockNumber", false],
      ["arkiv_query", true],
      ["arkiv_getEntity", false],
    ])
  })

  it("forwards only the option values the SDK sends, rebuilt from the checked fields", async () => {
    process.env.ARKIV_ACCESS_KEY = "test-key"
    // the deployed relay lives outside this package, so it is loaded by URL rather than imported
    const relay = new URL("../../../api/rpc.ts", import.meta.url).href
    const { default: handler } = (await import(relay)) as { default: (req: unknown, res: unknown) => Promise<void> }
    const sent: unknown[] = []
    vi.stubGlobal("fetch", async (_input: RequestInfo | URL, init?: RequestInit) => {
      sent.push(JSON.parse(String(init?.body)))
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { data: [], blockNumber: "0x10" } }))
    })
    const query = `qp = str('quire1') AND qd = bytes32(0x${"ab".repeat(32)})`
    const call = async (opts: unknown, ip: string) => {
      let status = 200
      const res = { status: (n: number) => ((status = n), res), json: () => undefined, setHeader: () => undefined }
      await handler({ method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "arkiv_query", params: [query, opts] }), headers: { "x-forwarded-for": ip } }, res)
      return status
    }
    expect(await call({ select: { key: true, payload: true }, limit: "0xc8", cursor: "abc", atBlock: "0x10" }, "1.1.1.1")).toBe(200)
    for (const bad of [{ limit: -5 }, { limit: 1.5 }, { limit: "0xc9" }, { limit: "0x0" }, { atBlock: -1 }, { atBlock: "latest" }, { cursor: 7 }, { cursor: "a b" }, { select: "*" }, { select: ["key"] }, { select: { secret: true } }, { select: { key: 1 } }, { extra: 1 }]) {
      expect(await call(bad, "1.1.1.2")).toBe(400)
    }
    expect(sent).toEqual([{ jsonrpc: "2.0", id: 1, method: "arkiv_query", params: [query, { select: { key: true, payload: true }, limit: "0xc8", cursor: "abc", atBlock: "0x10" }] }])
  })

  it("accepts every query shape the provider sends, bounds on qs included, and nothing appended", async () => {
    const { QUIRE_QUERY } = (await import(new URL("../../../api/rpc.ts", import.meta.url).href)) as { QUIRE_QUERY: RegExp }
    const doc = `qp = str('quire1') AND qd = bytes32(0x${"ab".repeat(32)})`
    const two = `($creator = addr(0x${"cd".repeat(20)}) OR $creator = addr(0x${"ef".repeat(20)}))`
    expect(QUIRE_QUERY.test(`${doc} AND qk = str('u') AND qs >= u64(5) AND qs <= u64(9) AND ${two}`)).toBe(true)
    expect(QUIRE_QUERY.test(`${doc} AND qk = str('s') AND qs <= u64(9) AND $creator = addr(0x${"cd".repeat(20)})`)).toBe(true)
    expect(QUIRE_QUERY.test(`${doc} AND qk = str('u') AND qs <= u64(9) OR qk = str('a')`)).toBe(false)
  })

  it("the SDK's own requests pass the relay end to end, cursor pages included", async () => {
    process.env.ARKIV_ACCESS_KEY = "test-key"
    const { default: handler } = (await import(new URL("../../../api/rpc.ts", import.meta.url).href)) as { default: (req: unknown, res: unknown) => Promise<void> }
    const upstream: unknown[] = []
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) !== "/api/rpc") {
        // the relay calling Arkiv
        const body = JSON.parse(String(init?.body))
        upstream.push(body.params[1])
        const page = body.params[1]?.cursor ? { data: [], blockNumber: "0x10" } : { data: [], blockNumber: "0x10", cursor: "next" }
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: page }))
      }
      // the browser calling the relay: run the real handler
      let status = 200
      let json: unknown
      const res = { status: (n: number) => ((status = n), res), json: (v: unknown) => void (json = v), setHeader: () => undefined }
      await handler({ method: "POST", body: String(init?.body), headers: { "x-forwarded-for": "9.9.9.9" } }, res)
      return new Response(JSON.stringify(json), { status })
    })
    const store = new SdkStore({ relayUrl: "/api/rpc" })
    const page1 = await store.query({ doc: `0x${"ab".repeat(32)}`, kind: "u", seqGte: 1n, seqLte: 99n, creators: [`0x${"cd".repeat(20)}`] })
    expect(page1.cursor).toBe("next")
    await store.query({ doc: `0x${"ab".repeat(32)}`, kind: "u", cursor: page1.cursor, atBlock: 16n })
    expect(upstream.length).toBe(2)
  })
})
