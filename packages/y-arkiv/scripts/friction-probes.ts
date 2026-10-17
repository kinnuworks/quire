/**
 * Reproducible probes behind arkiv/friction.md. Each probe prints what we
 * expected, what happened, and the raw numbers. Run against Tiramisu:
 *
 *   QUIRE_DEV_PRIVATE_KEY=0x… npx tsx scripts/friction-probes.ts [probe…]
 *
 * Writes cost a little test GLM. Results are also written to
 * arkiv/probes/<date>.json so the report can cite them.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { createPublicClient, createWalletClient, ExpirationTime } from "@arkiv-network/sdk"
import { str, u64 } from "@arkiv-network/sdk/attr"
import { tiramisu } from "@arkiv-network/sdk/chains"
import { eq } from "@arkiv-network/sdk/query"
import { http, parseEther, webSocket } from "viem"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"

const RPC = "https://rpc.tiramisu.db-chain.testnet.arkiv.network"
const WS = "wss://rpc.tiramisu.db-chain.testnet.arkiv.network"
const key = process.env.QUIRE_DEV_PRIVATE_KEY as `0x${string}`
if (!key) throw new Error("set QUIRE_DEV_PRIVATE_KEY")
const account = privateKeyToAccount(key)
const reader = createPublicClient({ chain: tiramisu, transport: http(RPC) })
const wallet = createWalletClient({ chain: tiramisu, transport: http(RPC), account })
const sdkVersion = JSON.parse(readFileSync(new URL("../node_modules/@arkiv-network/sdk/package.json", import.meta.url), "utf8")).version as string
const tag = `probe-${Date.now().toString(36)}`
const results: Record<string, unknown> = { sdk: sdkVersion, chainId: tiramisu.id, startedAt: new Date().toISOString(), tag }

async function rpc(method: string, params: unknown[], headers: Record<string, string> = {}) {
  const res = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) })
  const text = await res.text()
  return { status: res.status, cost: res.headers.get("arkiv-cost"), quota: res.headers.get("arkiv-quota-used-percent"), rateLimit: res.headers.get("ratelimit"), body: text.slice(0, 400) }
}

function payload(n: number): Uint8Array {
  const out = new Uint8Array(n)
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)))
  return out
}

const attrs = { qp: str(tag), qk: str("p"), qs: u64(1) }

const probes: Record<string, () => Promise<unknown>> = {
  /** Which methods are billed against the keyless query budget, by response header. */
  async costHeaders() {
    const { entityKey } = await wallet.createEntity({ payload: payload(32), contentType: "application/octet-stream", attributes: attrs, expires: ExpirationTime.fromHours(1) })
    return {
      expected: "arkiv_getEntity cheaper than arkiv_query, per docs on access keys",
      arkiv_query: await rpc("arkiv_query", [`qp = str('${tag}')`, { limit: "0x1" }]),
      arkiv_getEntity: await rpc("arkiv_getEntity", [entityKey]),
      arkiv_getEntityCount: await rpc("arkiv_getEntityCount", []),
      eth_blockNumber: await rpc("eth_blockNumber", []),
      pythonUserAgent: (await rpc("eth_blockNumber", [], { "user-agent": "Python-urllib/3.15" })).status,
    }
  },

  /** Largest payload one createEntity can carry through the public RPC. */
  async payloadLimit() {
    const sizes = [100_000, 120_000, 126_000, 128_000, 131_072]
    const out: Record<string, string> = {}
    for (const n of sizes) {
      try {
        await wallet.createEntity({ payload: payload(n), contentType: "application/octet-stream", attributes: attrs, expires: ExpirationTime.fromMinutes(30) })
        out[n] = "ok"
      } catch (e) {
        out[n] = (e as Error).message.split("\n")[0]!.slice(0, 160)
      }
    }
    return { expected: "documented maximum payload is 128 KiB (131,072 bytes)", out }
  },

  /** How many 30 KB creates fit in one executeBatch before the request is refused. */
  async batchBodyLimit() {
    const out: Record<string, string> = {}
    for (const count of [4, 6, 8, 9]) {
      try {
        await wallet.executeBatch({ creates: Array.from({ length: count }, () => ({ payload: payload(30_000), contentType: "application/octet-stream", attributes: attrs, expires: ExpirationTime.fromMinutes(30) })) })
        out[`${count} x 30000 B`] = "ok"
      } catch (e) {
        out[`${count} x 30000 B`] = (e as Error).message.split("\n")[0]!.slice(0, 160)
      }
    }
    return { expected: "batch limited by gas or entity count, as documented", out }
  },

  /** Extending to the same or an earlier expiry. */
  async extensionRules() {
    const { entityKey } = await wallet.createEntity({ payload: payload(32), contentType: "application/octet-stream", attributes: attrs, expires: ExpirationTime.fromDays(2) })
    const tryExtend = async (label: string, expires: ReturnType<typeof ExpirationTime.fromDays>) => {
      try {
        const r = await wallet.extendEntity({ entityKey, expires })
        return `${label}: ok, expiresAt ${r.expiresAt}`
      } catch (e) {
        return `${label}: ${(e as Error).message.split("\n")[0]!.slice(0, 160)}`
      }
    }
    return {
      expected: "an extension that does not move expiry later fails clearly before sending",
      shorter: await tryExtend("1 day (earlier)", ExpirationTime.fromDays(1)),
      longer: await tryExtend("3 days (later)", ExpirationTime.fromDays(3)),
    }
  },

  /** A patch and an extension of the same entity in one batch. */
  async patchAndExtendSameEntity() {
    const { entityKey } = await wallet.createEntity({ payload: payload(32), contentType: "application/octet-stream", attributes: attrs, expires: ExpirationTime.fromDays(1) })
    try {
      await wallet.executeBatch({ patches: [{ entityKey, payload: payload(40), contentType: "application/octet-stream" }], extensions: [{ entityKey, expires: ExpirationTime.fromDays(3) }] })
      const e = await reader.getEntity(entityKey)
      return { expected: "allowed, or rejected with a clear error", result: "ok", expiresAt: String(e.expiresAt), payloadBytes: e.payload?.length }
    } catch (e) {
      return { expected: "allowed, or rejected with a clear error", result: (e as Error).message.split("\n")[0]!.slice(0, 200) }
    }
  },

  /** How far back atBlock reads reach. */
  async atBlockRetention() {
    const head = await reader.getBlockNumber()
    const out: Record<string, string> = {}
    for (const back of [10n, 1_000n, 50_000n, 300_000n, head - 1n]) {
      const r = await rpc("arkiv_query", [`qp = str('${tag}')`, { limit: "0x1", atBlock: `0x${(head - back).toString(16)}` }])
      out[`head-${back}`] = `${r.status} ${r.body.slice(0, 90)}`
    }
    return { expected: "documented: within the node's retained range (range not stated)", head: String(head), out }
  },

  /** WebSocket push: when the event arrives relative to the SDK's createEntity returning. */
  async wsLatency() {
    const socket = createPublicClient({ chain: tiramisu, transport: webSocket(WS) })
    const heard = new Map<string, number>()
    const unwatch = socket.watchEntityEvents({ onEntityCreated: (e) => { if (!heard.has(e.entityKey)) heard.set(e.entityKey, Date.now()) } })
    await new Promise((r) => setTimeout(r, 1500))
    const runs = []
    for (let i = 0; i < 3; i++) {
      const sentAt = Date.now()
      const { entityKey, txHash } = await wallet.createEntity({ payload: payload(64), contentType: "application/octet-stream", attributes: attrs, expires: ExpirationTime.fromMinutes(30) })
      const returnedAt = Date.now()
      for (let j = 0; j < 40 && !heard.has(entityKey); j++) await new Promise((r) => setTimeout(r, 250))
      const eventAt = heard.get(entityKey)
      runs.push({ txHash, sendToEventMs: eventAt ? eventAt - sentAt : null, sendToReturnMs: returnedAt - sentAt })
    }
    unwatch()
    return { expected: "event within a block or two of sending", runs }
  },

  /** Whether atBlock reaches back to blocks long ago: read an entity that existed early in the chain. */
  async atBlockRetentionOld() {
    const head = await reader.getBlockNumber()
    const out: Record<string, string> = {}
    for (const at of [head - 100n, head - 10_000n, head - 100_000n, head - 400_000n, 1_000n]) {
      const r = await rpc("arkiv_query", ["*", { limit: "0x1", atBlock: `0x${at.toString(16)}`, select: { key: true, createdAt: true } }])
      out[`block ${at}`] = `${r.status} ${r.body.slice(0, 120)}`
    }
    return { expected: "documented: atBlock must be within the node's retained range (range not stated)", head: String(head), out }
  },

  /** Where between 4 and 6 creates of 30 KB the batch starts failing, and what the error says. */
  async batchBoundary() {
    const out: Record<string, string> = {}
    const gasPrice = await reader.getGasPrice()
    out.gasPrice = `${gasPrice} wei`
    for (const bytes of [120_000, 130_000, 150_000]) {
      const count = 5
      try {
        await wallet.executeBatch({ creates: Array.from({ length: count }, () => ({ payload: payload(bytes / count), contentType: "application/octet-stream", attributes: attrs, expires: ExpirationTime.fromMinutes(30) })) })
        out[`${bytes} B total`] = "ok"
      } catch (e) {
        // the SDK's message hides the cause; walk the error chain for the RPC's own details
        let cause: unknown = e
        const chain: string[] = []
        while (cause && chain.length < 8) {
          const c = cause as { details?: string; shortMessage?: string; message?: string; cause?: unknown }
          if (c.details) chain.push(c.details)
          cause = c.cause
        }
        out[`${bytes} B total`] = `${(e as Error).message.split("\n")[0]!.slice(0, 80)} | rpc said: ${[...new Set(chain)].join(" / ").slice(0, 160)}`
      }
    }
    return { expected: "a clear error naming the limit", out }
  },

  /** The event for a create carries owner but not creator. */
  async eventFields() {
    const socket = createPublicClient({ chain: tiramisu, transport: webSocket(WS) })
    let sample: unknown = null
    const unwatch = socket.watchEntityEvents({ onEntityCreated: (e) => { sample ??= Object.keys(e) } })
    await wallet.createEntity({ payload: payload(16), contentType: "application/octet-stream", attributes: attrs, expires: ExpirationTime.fromMinutes(30) })
    for (let i = 0; i < 20 && !sample; i++) await new Promise((r) => setTimeout(r, 250))
    unwatch()
    return { expected: "creator available on EntityCreated", fields: sample }
  },

  /** A typed query versus an untyped one against a u64 attribute. */
  async untypedPredicate() {
    await wallet.createEntity({ payload: payload(16), contentType: "application/octet-stream", attributes: { qp: str(tag), qk: str("t"), qs: u64(7) }, expires: ExpirationTime.fromMinutes(30) })
    const typed = await reader.query(eq("qp", str(tag)), { limit: 50 })
    const untyped = await rpc("arkiv_query", [`qp = str('${tag}') AND qs = 7`, { limit: "0xa" }])
    return { expected: "untyped 7 compared to u64 7 either matches or errors", typedCount: typed.entities.length, untyped: untyped.body.slice(0, 160) }
  },

  /** Funding a burner with a plain transfer, as Quire's drip does. */
  async burnerFunding() {
    const burner = privateKeyToAccount(generatePrivateKey())
    const hash = await wallet.sendTransaction({ to: burner.address, value: parseEther("0.001") })
    const r = await reader.waitForTransactionReceipt({ hash })
    return { expected: "plain value transfer works", gasUsed: String(r.gasUsed), status: r.status }
  },
}

const wanted = process.argv.slice(2)
for (const [name, fn] of Object.entries(probes)) {
  if (wanted.length && !wanted.includes(name)) continue
  process.stdout.write(`${name} … `)
  try {
    results[name] = await fn()
    console.log("done")
  } catch (e) {
    results[name] = { error: (e as Error).message.slice(0, 300) }
    console.log("error")
  }
}
mkdirSync(new URL("../../../arkiv/probes/", import.meta.url), { recursive: true })
const file = new URL(`../../../arkiv/probes/${new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-")}.json`, import.meta.url)
writeFileSync(file, JSON.stringify(results, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2))
console.log(JSON.stringify(results, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2))
process.exit(0)
