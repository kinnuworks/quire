/**
 * Getting a fresh document key enough testnet gas to write.
 *
 * Writes cost gas, and a new key has none. We try, in order:
 *   1. the drip at /api/drip, which sends a small amount of test GLM and
 *      never sees anything but the address;
 *   2. the visitor's own wallet, with one transfer. That transfer links the
 *      visitor's wallet to this document key on chain, and the UI says so;
 *   3. the owner, who sends gas from the document's own key to a joiner who
 *      passed on their address. The drip and its IP log never see the joiner.
 * Reading a document never needs either.
 */
import { sha256 } from "@noble/hashes/sha2.js"
import { tiramisu } from "@arkiv-network/sdk/chains"
import { createPublicClient, createWalletClient, custom, formatEther, http, parseEther } from "viem"
import { privateKeyToAccount } from "viem/accounts"
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

/**
 * The drip's proof of work (api/drip.ts): a nonce whose sha256 over
 * "quire-drip:<address>:<minute>:<nonce>" starts with 20 zero bits. About a
 * million hashes; yields to the page every few thousand so typing stays smooth.
 */
async function dripWork(address: Hex): Promise<{ minute: number; nonce: number }> {
  const minute = Math.floor(Date.now() / 60_000)
  const prefix = `quire-drip:${address.toLowerCase()}:${minute}:`
  const enc = new TextEncoder()
  for (let nonce = 0; ; nonce++) {
    const h = sha256(enc.encode(prefix + nonce))
    if (h[0] === 0 && h[1] === 0 && (h[2]! & 0xf0) === 0) return { minute, nonce }
    if (nonce % 20_000 === 0) await new Promise((r) => setTimeout(r, 0))
  }
}

export async function ensureGas(address: Hex): Promise<GasResult> {
  if ((await balanceOf(address)) >= MIN_BALANCE) return { ok: true, via: "balance" }
  let reason = "The gas drip did not answer."
  try {
    const work = await dripWork(address)
    const res = await fetch("/api/drip", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ address, ...work }),
    })
    const body = (await res.json().catch(() => ({}))) as { error?: string }
    if (res.ok) {
      if (await waitForBalance(address)) return { ok: true, via: "drip" }
      reason = "The drip sent gas, but it has not arrived yet. Try again in a few seconds."
    } else if (body.error) reason = body.error
  } catch {
    // no drip on this host: fall through
  }
  return { ok: false, reason }
}

type Injected = { request: (args: { method: string; params?: unknown[] }) => Promise<unknown> }

export function hasWallet(): boolean {
  return typeof window !== "undefined" && !!(window as unknown as { ethereum?: Injected }).ethereum
}

/** One transfer from the visitor's wallet to the document key. The caller must warn about linkability first. */
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

/** Waits for gas someone else sends (the owner, from the document's key), checking every five seconds. */
export async function waitForGas(address: Hex, cancelled: () => boolean): Promise<boolean> {
  while (!cancelled()) {
    if ((await balanceOf(address).catch(() => 0n)) >= MIN_BALANCE) return true
    await new Promise((r) => setTimeout(r, 5000))
  }
  return false
}

/**
 * One transfer from this document's key to a joiner's key. The joiner's key writes its join request to
 * this document anyway, so the transfer links nothing that the document's own entities do not.
 */
export async function sendGas(privateKey: Hex, to: Hex, amount = "0.02"): Promise<void> {
  const wallet = createWalletClient({ chain: tiramisu, transport: http(TIRAMISU_HTTP), account: privateKeyToAccount(privateKey) })
  const hash = await wallet.sendTransaction({ to, value: parseEther(amount) })
  await reader.waitForTransactionReceipt({ hash })
}

export const WALLET_WARNING =
  "Funding from your own wallet puts a transfer from that wallet to this document's key on chain, so anyone can link the two. Use a wallet you don't mind being linked."
