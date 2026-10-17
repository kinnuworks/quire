/**
 * Gas drip: sends a small amount of test GLM to a fresh document key.
 *
 * This is the only server Quire runs, and it never touches document data. It
 * receives an address, checks the balance is near zero, and sends one
 * transfer. Reading documents never involves it; writers can also fund
 * their key from their own wallet instead.
 *
 * Privacy note, also stated in the README: every key it funds shares this
 * sponsor as the source of its first transfer, so an observer can tell those
 * keys were funded by Quire. It cannot tell who holds them.
 */
import { createHash } from "node:crypto"
import { tiramisu } from "@arkiv-network/sdk/chains"
import { createPublicClient, createWalletClient, formatEther, http, isAddress, parseEther } from "viem"
import { privateKeyToAccount } from "viem/accounts"

const RPC = "https://rpc.tiramisu.db-chain.testnet.arkiv.network"
const AMOUNT = parseEther("0.05")
const ONLY_BELOW = parseEther("0.005")
// per-instance memory: a soft limit, not a guarantee across cold starts
const recent = new Map<string, number>()
// at most this many transfers per instance per 10 minutes, whatever the IPs
const GLOBAL_CAP = 40
const sent: number[] = []
/**
 * Proof of work: sha256("quire-drip:" + address + ":" + minute + ":" + nonce) must start with
 * DIFFICULTY zero bits. About a million hashes, two seconds in a browser, and one hash to check here,
 * so draining the sponsor costs CPU time per key instead of one loop of requests.
 */
const DIFFICULTY = 20

function zeroBits(hash: Uint8Array): number {
  let n = 0
  for (const byte of hash) {
    if (byte === 0) {
      n += 8
      continue
    }
    return n + Math.clz32(byte) - 24
  }
  return n
}

function workDone(address: string, minute: unknown, nonce: unknown): boolean {
  const now = Math.floor(Date.now() / 60_000)
  if (typeof minute !== "number" || !Number.isInteger(minute) || minute < now - 3 || minute > now + 1) return false
  if (typeof nonce !== "number" || !Number.isSafeInteger(nonce) || nonce < 0) return false
  const hash = createHash("sha256").update(`quire-drip:${address.toLowerCase()}:${minute}:${nonce}`).digest()
  return zeroBits(hash) >= DIFFICULTY
}

type Req = { method?: string; body?: unknown; headers: Record<string, string | string[] | undefined> }
type Res = { status: (n: number) => Res; json: (v: unknown) => void }

export default async function handler(req: Req, res: Res) {
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" })
  const key = process.env.QUIRE_SPONSOR_KEY as `0x${string}` | undefined
  if (!key) return res.status(503).json({ error: "The gas drip is not configured on this deployment." })
  let body: { address?: string; minute?: unknown; nonce?: unknown } | undefined
  try {
    body = (typeof req.body === "string" ? JSON.parse(req.body) : req.body) as typeof body
  } catch {
    return res.status(400).json({ error: "Send JSON: {\"address\": \"0x…\", \"minute\": n, \"nonce\": n}" })
  }
  const address = body?.address
  if (!address || !isAddress(address)) return res.status(400).json({ error: "That is not an address." })
  if (!workDone(address, body?.minute, body?.nonce)) return res.status(400).json({ error: "The proof of work is missing or stale. Reload the page and try again." })

  const ip = String(req.headers["x-forwarded-for"] ?? "").split(",")[0]!.trim() || "unknown"
  const now = Date.now()
  // IPs are held for a minute; addresses for five, longer than a proof of work stays fresh, so one proof cannot be replayed
  for (const [k, t] of recent) if (now - t > (k.startsWith("0x") ? 300_000 : 60_000)) recent.delete(k)
  if ((recent.get(ip) ?? 0) > now - 10_000 || recent.has(address.toLowerCase())) {
    return res.status(429).json({ error: "One request every 10 seconds, please." })
  }
  while (sent.length && sent[0]! < now - 600_000) sent.shift()
  if (sent.length >= GLOBAL_CAP) {
    return res.status(429).json({ error: "The drip is busy. Try again in a few minutes, or fund this key from your own wallet or the faucet at https://hub.arkiv.network/faucet." })
  }
  // reserve the slot before any await, so parallel requests cannot all pass the checks above
  recent.set(ip, now)
  recent.set(address.toLowerCase(), now)
  sent.push(now)
  const release = () => {
    const i = sent.indexOf(now)
    if (i >= 0) sent.splice(i, 1)
  }

  try {
    const reader = createPublicClient({ chain: tiramisu, transport: http(RPC) })
    if ((await reader.getBalance({ address })) >= ONLY_BELOW) {
      release()
      return res.status(200).json({ skipped: "already funded" })
    }
    const account = privateKeyToAccount(key)
    const left = await reader.getBalance({ address: account.address })
    if (left < AMOUNT * 2n) {
      release()
      return res.status(503).json({ error: `The drip is out of test GLM (${formatEther(left)} left). Fund this key from your own wallet or the faucet at https://hub.arkiv.network/faucet.`, sponsor: account.address })
    }
    const wallet = createWalletClient({ chain: tiramisu, transport: http(RPC), account })
    const hash = await wallet.sendTransaction({ to: address as `0x${string}`, value: AMOUNT })
    return res.status(200).json({ hash })
  } catch (e) {
    release()
    return res.status(502).json({ error: `The testnet did not accept the transfer: ${(e as Error).message.split("\n")[0]}` })
  }
}
