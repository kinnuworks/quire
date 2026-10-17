/**
 * Gas drip: sends a small amount of test GLM to a fresh document key.
 *
 * This is the only server Quire runs, and it never touches document data. It
 * receives an address, checks the balance is near zero, and sends one
 * transfer. Reading documents never involves it; writers can also fund
 * their key from their own wallet instead.
 */
import { tiramisu } from "@arkiv-network/sdk/chains"
import { createPublicClient, createWalletClient, http, isAddress, parseEther } from "viem"
import { privateKeyToAccount } from "viem/accounts"

const RPC = "https://rpc.tiramisu.db-chain.testnet.arkiv.network"
const AMOUNT = parseEther("0.03")
const ONLY_BELOW = parseEther("0.005")
const recent = new Map<string, number>()

type Req = { method?: string; body?: unknown; headers: Record<string, string | string[] | undefined> }
type Res = { status: (n: number) => Res; json: (v: unknown) => void }

export default async function handler(req: Req, res: Res) {
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" })
  const key = process.env.QUIRE_SPONSOR_KEY as `0x${string}` | undefined
  if (!key) return res.status(503).json({ error: "drip not configured" })
  const body = (typeof req.body === "string" ? JSON.parse(req.body) : req.body) as { address?: string } | undefined
  const address = body?.address
  if (!address || !isAddress(address)) return res.status(400).json({ error: "bad address" })

  const ip = String(req.headers["x-forwarded-for"] ?? "").split(",")[0]!.trim() || "unknown"
  const now = Date.now()
  for (const [k, t] of recent) if (now - t > 60_000) recent.delete(k)
  if ((recent.get(ip) ?? 0) > now - 10_000 || recent.has(address.toLowerCase())) return res.status(429).json({ error: "slow down" })

  const reader = createPublicClient({ chain: tiramisu, transport: http(RPC) })
  if ((await reader.getBalance({ address })) >= ONLY_BELOW) return res.status(200).json({ skipped: "already funded" })
  const wallet = createWalletClient({ chain: tiramisu, transport: http(RPC), account: privateKeyToAccount(key) })
  const hash = await wallet.sendTransaction({ to: address, value: AMOUNT })
  recent.set(ip, now)
  recent.set(address.toLowerCase(), now)
  return res.status(200).json({ hash })
}
