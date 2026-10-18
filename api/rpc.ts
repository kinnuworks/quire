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
// exactly the query shapes Quire sends (toExpression in y-arkiv), matched whole: one document, an
// optional kind, optional qs bounds, an optional set of creators. Nothing can be appended.
const ADDR = "addr\\(0x[0-9a-fA-F]{40}\\)"
export const QUIRE_QUERY = new RegExp(
  "^qp = str\\('quire1'\\) AND qd = bytes32\\(0x[0-9a-fA-F]{64}\\)" +
    "( AND qk = str\\('[ausjcv]'\\))?" +
    "( AND qs >= u64\\([0-9]{1,20}\\))?" +
    "( AND qs <= u64\\([0-9]{1,20}\\))?" +
    `( AND (\\$creator = ${ADDR}|\\(\\$creator = ${ADDR}( OR \\$creator = ${ADDR}){1,63}\\)))?$`,
)
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
  // and only the options Quire sends: what to select, a page of at most 200, a cursor, a block
  const opts = Array.isArray(call.params) ? call.params[1] : undefined
  const allowed = ["select", "limit", "cursor", "atBlock"]
  // exactly what the SDK sends: select "*", a page of 1 to 200 and a block as hex quantities, an opaque cursor
  const o = (opts && typeof opts === "object" ? opts : {}) as { select?: unknown; limit?: unknown; cursor?: unknown; atBlock?: unknown }
  const hex = (v: unknown, digits: number) => typeof v === "string" && new RegExp(`^0x[0-9a-fA-F]{1,${digits}}$`).test(v)
  const pageOk =
    (o.select === undefined || o.select === "*") &&
    (o.limit === undefined || (hex(o.limit, 2) && Number(o.limit) >= 1 && Number(o.limit) <= 200)) &&
    (o.atBlock === undefined || hex(o.atBlock, 16)) &&
    (o.cursor === undefined || (typeof o.cursor === "string" && /^[\x21-\x7e]{1,1024}$/.test(o.cursor)))
  if ((call.params as unknown[]).length > 2 || (opts !== undefined && (typeof opts !== "object" || opts === null || Object.keys(opts).some((k) => !allowed.includes(k)) || !pageOk))) {
    return res.status(400).json({ error: "The relay forwards only Quire's own query options." })
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
    // forward the request rebuilt from the checked values, never the raw bytes: a body that also carries
    // "Method" or "Params" would pass these checks, and a case-insensitive JSON decoder upstream could
    // take those instead
    const request = JSON.stringify({ jsonrpc: "2.0", id: typeof call.id === "number" || typeof call.id === "string" ? call.id : 1, method: "arkiv_query", params: opts === undefined ? [query] : [query, Object.fromEntries(allowed.filter((k) => o[k as keyof typeof o] !== undefined).map((k) => [k, o[k as keyof typeof o]]))] })
    const upstream = await fetch(RPC, {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": key, "user-agent": "quire-relay/1" },
      body: request,
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
