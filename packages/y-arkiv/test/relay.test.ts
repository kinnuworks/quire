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
})
