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
console.log(JSON.stringify({ seconds: 60, blocks: Number(end - start), counts, distinctOwners: owners.size, sdk: "0.8.1" }))
process.exit(0)
