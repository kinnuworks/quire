/**
 * Getting a fresh document key enough testnet gas to write.
 *
 * Writes cost gas, and a new key has none. We try, in order:
 *   1. the drip at /api/drip, which sends a small amount of test GLM and
 *      never sees anything but the address;
 *   2. the visitor's own wallet (MetaMask or similar), with one transfer.
 * Reading a document never needs either.
 */
import { tiramisu } from "@arkiv-network/sdk/chains"
import { createPublicClient, createWalletClient, custom, formatEther, http, parseEther } from "viem"
import { type Hex, TIRAMISU_HTTP } from "y-arkiv"

const MIN_BALANCE = parseEther("0.002")
const reader = createPublicClient({ chain: tiramisu, transport: http(TIRAMISU_HTTP) })

export async function balanceOf(address: Hex): Promise<bigint> {
  return reader.getBalance({ address })
}

export function formatGlm(wei: bigint): string {
  return Number(formatEther(wei)).toFixed(4)
}

async function waitForBalance(address: Hex, ms = 40_000): Promise<boolean> {
  const end = Date.now() + ms
  while (Date.now() < end) {
    if ((await balanceOf(address)) >= MIN_BALANCE) return true
    await new Promise((r) => setTimeout(r, 1500))
  }
  return false
}

export type GasResult = { ok: true; via: "balance" | "drip" | "wallet" } | { ok: false; reason: string }

export async function ensureGas(address: Hex): Promise<GasResult> {
  if ((await balanceOf(address)) >= MIN_BALANCE) return { ok: true, via: "balance" }
  try {
    const res = await fetch("/api/drip", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ address }),
    })
    if (res.ok && (await waitForBalance(address))) return { ok: true, via: "drip" }
  } catch {
    // no drip deployed here: fall through to the wallet
  }
  return { ok: false, reason: "The gas drip is unavailable. Fund this key from your own wallet instead." }
}

type Injected = { request: (args: { method: string; params?: unknown[] }) => Promise<unknown> }

export function hasWallet(): boolean {
  return typeof window !== "undefined" && !!(window as unknown as { ethereum?: Injected }).ethereum
}

/** One transfer from the visitor's wallet to the document key. */
export async function fundFromWallet(address: Hex, amount = "0.02"): Promise<GasResult> {
  const eth = (window as unknown as { ethereum?: Injected }).ethereum
  if (!eth) return { ok: false, reason: "No browser wallet found." }
  const [from] = (await eth.request({ method: "eth_requestAccounts" })) as Hex[]
  if (!from) return { ok: false, reason: "The wallet returned no account." }
  try {
    await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: `0x${tiramisu.id.toString(16)}` }] })
  } catch {
    await eth.request({
      method: "wallet_addEthereumChain",
      params: [
        {
          chainId: `0x${tiramisu.id.toString(16)}`,
          chainName: "Arkiv Tiramisu",
          nativeCurrency: { name: "GLM", symbol: "GLM", decimals: 18 },
          rpcUrls: [TIRAMISU_HTTP],
          blockExplorerUrls: ["https://tiramisu.explorer.arkiv.network"],
        },
      ],
    })
  }
  const wallet = createWalletClient({ chain: tiramisu, transport: custom(eth), account: from })
  const hash = await wallet.sendTransaction({ to: address, value: parseEther(amount) })
  await reader.waitForTransactionReceipt({ hash })
  return { ok: true, via: "wallet" }
}
