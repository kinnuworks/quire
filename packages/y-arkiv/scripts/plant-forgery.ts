/**
 * Plants one forged write in the open demo document, so the app's
 * "Check the chain for outside writes" and the readers have something to
 * reject. "Mallory" holds the link, so she can encrypt a perfectly valid
 * edit with her own signed salt and derived client id. Only the member list
 * keeps it out. Records her address in arkiv/demo.json.
 */
import { readFileSync, writeFileSync } from "node:fs"
import { tiramisu } from "@arkiv-network/sdk/chains"
import { createWalletClient, http, parseEther } from "viem"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import * as Y from "yjs"
import { encodeFrame, encodeOuter } from "../src/codec.js"
import { clientIdFor, deriveEpochZeroKey, randomBytes, seal } from "../src/crypto.js"
import { bytesToHex, hexToBytes } from "../src/hex.js"
import { parseDocLink } from "../src/link.js"
import { KIND, LIFETIME } from "../src/protocol.js"
import { SdkStore, TIRAMISU_HTTP } from "../src/sdk.js"
import type { Hex } from "../src/store.js"

const demoPath = new URL("../../../arkiv/demo.json", import.meta.url)
const demo = JSON.parse(readFileSync(demoPath, "utf8"))
const link = parseDocLink(demo.open.link)!
const funder = createWalletClient({ chain: tiramisu, transport: http(TIRAMISU_HTTP), account: privateKeyToAccount(process.env.QUIRE_DEV_PRIVATE_KEY as Hex) })
const store = new SdkStore()

const malloryKey = generatePrivateKey()
const mallory = privateKeyToAccount(malloryKey)
await store.reader.waitForTransactionReceipt({ hash: await funder.sendTransaction({ to: mallory.address, value: parseEther("0.01") }) })

const salt = randomBytes(16)
const sig = await mallory.signMessage({ message: { raw: new Uint8Array([...new TextEncoder().encode("quire1:salt:"), ...hexToBytes(link.doc), ...salt]) } })
const doc = new Y.Doc()
doc.clientID = clientIdFor(mallory.address, salt)
const p = new Y.XmlElement("paragraph")
p.insert(0, [new Y.XmlText("FORGED: the ward office confirmed the supply is normal. (Written by someone outside the member list; readers never apply it.)")])
doc.getXmlFragment("default").push([p])
const frame = encodeFrame({ kind: KIND.update, doc: hexToBytes(link.doc), epoch: 0, header: { t: Date.now(), salt: bytesToHex(salt), sig }, data: Y.encodeStateAsUpdate(doc) }, randomBytes)
const payload = encodeOuter(0, await seal(deriveEpochZeroKey(link.secret), frame))
const head = await store.head()
const result = await new SdkStore({ privateKey: malloryKey }).batch({
  creates: [{ payload, attributes: { doc: link.doc, kind: KIND.update, seq: head }, lifetimeSeconds: LIFETIME.snapshot }],
})
demo.open.forgery = { by: mallory.address.toLowerCase(), entity: result.created[0], tx: result.txHash }
writeFileSync(demoPath, JSON.stringify(demo, null, 2))
console.log(JSON.stringify(demo.open.forgery))
process.exit(0)
