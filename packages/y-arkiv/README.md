# y-arkiv

A Yjs provider whose only backend is [Arkiv](https://arkiv.network). Every edit is encrypted in the browser and stored as an Arkiv entity, and peers receive it over a WebSocket subscription. There is no sync server. The data format is specified in [PROTOCOL.md](https://github.com/kinnuworks/quire/blob/main/PROTOCOL.md).

Testnet only (Arkiv Tiramisu). MIT.

## Swap it in for y-websocket

```ts
import * as Y from "yjs"
import { ArkivProvider, newDocLink, prepareDoc, SdkStore } from "y-arkiv"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"

// a key made for this document only; fund it with a little test GLM
const privateKey = generatePrivateKey()
const identity = { address: privateKeyToAccount(privateKey).address, privateKey, name: "Asha" }
const store = new SdkStore({ privateKey })

// create a document: the member list and first snapshot land in one transaction
const link = newDocLink(identity.address)
await ArkivProvider.createDocument({ store, link, identity })

// open it: before   new WebsocketProvider(url, room, ydoc)
//          after    new ArkivProvider(ydoc, { store, link, identity, salt })
const ydoc = new Y.Doc()
const salt = prepareDoc(ydoc, identity.address) // call before an editor binds to ydoc
const provider = new ArkivProvider(ydoc, { store, link, identity, salt })
await provider.connect()

ydoc.getText("t").insert(0, "hello") // goes out about one block later
```

Bind any Yjs editor to `ydoc` as usual: Tiptap's `Collaboration` extension, BlockNote, `y-codemirror.next`, `y-prosemirror`. The provider syncs the document only, with no awareness (cursors, presence), and edits land in about three to seven seconds.

Share `formatDocLink(link)` inside a URL fragment. Whoever opens it can read the document, and can ask to join:

```ts
const reader = new ArkivProvider(new Y.Doc(), { store: new SdkStore(), link: parseDocLink(fragment)! })
await reader.connect() // three queries, then live over WebSocket
```

## What you get

- End-to-end encryption (AES-256-GCM, payloads padded to six fixed sizes), with a fresh key per member per document.
- Membership by `$creator`: edits from outside the member list are never applied. Each edit's Yjs client id derives from its creator's address with a salt the creator signs.
- Join requests sealed to the owner, approval, and revocation that rotates the key and seals the roster.
- Snapshots as a 30-day lease renewed by members, published readonly versions anyone can keep alive, `keepFor`, `deleteDocument` and `shredMine`.
- Time travel with `loadAt(store, link, block)`, which uses `atBlock` reads.
- `blame(doc, provider)`: every visible run of text with its author, proven by an update entity or claimed through a snapshot. Open with `fullHistory: true` to count every edit still on chain; the provider checks each author against the member list as it stood at that edit's block by default (`membershipAtBlock`).
- `MemoryChain`, an in-memory Arkiv for tests: blocks, `$creator`, expiry, flags, atomic batches, and the RPC's request size limit.

## CLI

```bash
npx y-arkiv verify '<document link>'   # members, epoch, lease, ignored writes, query cost
npx y-arkiv read '<document link>'
npx y-arkiv blame '<document link>'    # who wrote each run of text, with the entity and block that prove it
npx y-arkiv timeline '<document link>' # every edit in order, with characters added and removed
npx y-arkiv watch '<document link>'
QUIRE_KEY=0x… npx y-arkiv extend '<version link>'
npx y-arkiv check-signature <address> '<message>' <signature>   # a "Prove this key is yours" signature
```

All of them take `--rpc <url> --ws <url>`, to read through your own node.
