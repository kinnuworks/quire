// Counts every entity event a subscriber receives in 60 s, unfiltered.
import { createPublicClient } from "@arkiv-network/sdk"
import { tiramisu } from "@arkiv-network/sdk/chains"
import { webSocket } from "viem"
const client = createPublicClient({ chain: tiramisu, transport: webSocket("wss://rpc.tiramisu.db-chain.testnet.arkiv.network") })
const counts: Record<string, number> = {}
const owners = new Set<string>()
const start = await client.getBlockNumber()
const stop = client.watchEntityEvents({ onEvent: (e) => { counts[e.type] = (counts[e.type] ?? 0) + 1; if ("owner" in e) owners.add(e.owner) }, onError: (e) => console.error("error", e.message) })
await new Promise((r) => setTimeout(r, 60_000))
stop()
const end = await client.getBlockNumber()
const result = { probe: "firehose", at: new Date().toISOString(), seconds: 60, blocks: Number(end - start), counts, distinctOwners: owners.size, sdk: "0.8.1" }
const { writeFileSync, mkdirSync } = await import("node:fs")
mkdirSync(new URL("../../../arkiv/probes/", import.meta.url), { recursive: true })
writeFileSync(new URL(`../../../arkiv/probes/firehose-${result.at.slice(0, 16).replace(/[:T]/g, "-")}.json`, import.meta.url), JSON.stringify(result, null, 2))
console.log(JSON.stringify(result))
process.exit(0)
