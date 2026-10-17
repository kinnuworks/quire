/**
 * Query relay: forwards Quire's `arkiv_query` calls to the Arkiv RPC with our
 * access key, for a visitor whose free per-IP query budget is used up.
 *
 * The browser uses it only after the visitor presses "Use Quire's relay" on
 * the budget notice, and only for arkiv_query: reads by key, block numbers,
 * live events and writes still go straight to Arkiv.
 *
 * What it sees, the same as the Arkiv RPC operator: the visitor's IP address,
 * the document id and the member addresses in each query. It never sees text,
 * names, keys or the link secret: those are not in queries, and the payloads
 * it passes back are ciphertext. It keeps nothing; Vercel logs each request's
 * path, time, status and IP address, never the body.
 */

const RPC = "https://rpc.tiramisu.db-chain.testnet.arkiv.network"
// only queries for one Quire document: the relay is not a general way to spend our key
const QUIRE_QUERY = /^qp = str\('quire1'\) AND qd = bytes32\(0x[0-9a-fA-F]{64}\)/
const MAX_BODY = 8_192
// per-instance memory, like the drip: a soft limit, not a guarantee across cold starts
const PER_IP = 120 // queries per IP per 10 minutes: opening a document costs 3
const GLOBAL = 2_000 // queries per instance per 10 minutes
const recent = new Map<string, number[]>()
const all: number[] = []

type Req = { method?: string; body?: unknown; headers: Record<string, string | string[] | undefined> }
type Res = { status: (n: number) => Res; json: (v: unknown) => void; setHeader?: (k: string, v: string) => void }

export default async function handler(req: Req, res: Res) {
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" })
  const key = process.env.ARKIV_ACCESS_KEY
  if (!key) return res.status(503).json({ error: "The relay is not configured on this deployment." })

  const raw = typeof req.body === "string" ? req.body : JSON.stringify(req.body ?? null)
  if (raw.length > MAX_BODY) return res.status(413).json({ error: "Request too large for the relay." })
  let call: { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown }
  try {
    call = JSON.parse(raw)
  } catch {
    return res.status(400).json({ error: "Send one JSON-RPC request." })
  }
  const query = Array.isArray(call?.params) ? call.params[0] : undefined
  if (call?.method !== "arkiv_query" || typeof query !== "string" || !QUIRE_QUERY.test(query)) {
    return res.status(400).json({ error: "The relay forwards only arkiv_query calls for a Quire document." })
  }

  const ip = String(req.headers["x-forwarded-for"] ?? "").split(",")[0]!.trim() || "unknown"
  const now = Date.now()
  const window = (list: number[]) => {
    while (list.length && list[0]! < now - 600_000) list.shift()
    return list
  }
  const mine = window(recent.get(ip) ?? [])
  if (mine.length >= PER_IP || window(all).length >= GLOBAL) {
    res.setHeader?.("retry-after", "600")
    return res.status(429).json({ error: "The relay is busy too. Try again in a few minutes." })
  }
  mine.push(now)
  recent.set(ip, mine)
  all.push(now)

  try {
    const upstream = await fetch(RPC, {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": key, "user-agent": "quire-relay/1" },
      body: raw,
    })
    const text = await upstream.text()
    const retry = upstream.headers.get("retry-after")
    if (retry) res.setHeader?.("retry-after", retry)
    let body: unknown
    try {
      body = JSON.parse(text)
    } catch {
      body = { jsonrpc: "2.0", id: call.id ?? null, error: { code: -32603, message: "Arkiv returned something that is not JSON." } }
    }
    return res.status(upstream.status).json(body)
  } catch {
    return res.status(502).json({ jsonrpc: "2.0", id: call.id ?? null, error: { code: -32603, message: "The relay could not reach Arkiv." } })
  }
}
