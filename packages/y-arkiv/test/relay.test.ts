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
    expect(await call({ select: "*", limit: "0xc8", cursor: "abc", atBlock: "0x10" }, "1.1.1.1")).toBe(200)
    for (const bad of [{ limit: -5 }, { limit: 1.5 }, { limit: "0xc9" }, { limit: "0x0" }, { atBlock: -1 }, { atBlock: "latest" }, { cursor: 7 }, { cursor: "a b" }, { select: ["*"] }, { extra: 1 }]) {
      expect(await call(bad, "1.1.1.2")).toBe(400)
    }
    expect(sent).toEqual([{ jsonrpc: "2.0", id: 1, method: "arkiv_query", params: [query, { select: "*", limit: "0xc8", cursor: "abc", atBlock: "0x10" }] }])
  })
})
