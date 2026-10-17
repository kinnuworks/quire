# Quire

Quire is a collaborative document editor that keeps no copy of your documents. Every edit is encrypted in the browser and written to [Arkiv](https://arkiv.network) as an entity. Collaborators receive it over a WebSocket subscription a block or two later. The link you share is the key.

Under the editor is `y-arkiv`, a Yjs provider. Any Yjs app (Tiptap, BlockNote, CodeMirror) can swap `y-websocket` for it and get end-to-end encrypted sync with no sync server.

- Live app: **https://quire-five.vercel.app**
- Protocol: [PROTOCOL.md](PROTOCOL.md), with [JSON Schema](spec/schema) and [test vectors](spec/vectors)
- Arkiv schema and queries: [arkiv/schema.md](arkiv/schema.md)
- Friction report: [arkiv/friction.md](arkiv/friction.md)

Built for Arkiv: Global Tour Stop, in the Privacy, Open Source and Security tracks. Testnet only; all demo data is synthetic.

## Who is exposed today

A newsroom drafts a story in a hosted editor. The drafts, the comments and the list of who worked on them sit on the provider's servers in a form the provider can read. Whoever can compel the provider can get them without the newsroom knowing.

This is not hypothetical. On 5 January 2021 the US Justice Department obtained a court order requiring Google, which ran the New York Times' email, to hand over email logs for four Times reporters. A gag order kept Times executives from telling even their own executive editor. Google pushed back and the order was withdrawn in June 2021, but only because the provider chose to resist. The data was there to take.

Providers also read private files on their own initiative:

- On 31 October 2017 Google Docs locked journalists out of their own drafts with a mistaken "terms of service" flag, and Google confirmed it scans document content with automated pattern matching.
- Google Drive restricts private files that its classifiers flag, including a user's screenshot of a film still in 2022.

What changes with Quire from the first document: there is no provider copy to demand, scan or restrict. Quire runs no server that sees text. Arkiv holds only ciphertext, padded to fixed sizes, under four attributes that name nothing. A court order to us would get an empty answer, and an order to Arkiv would get encrypted blobs and a list of throwaway addresses. Only the people holding the link can read the document, and only current members can read what was written after a revocation.

## Why Arkiv, and what stays off it

Every existing way to sync a Yjs document breaks one of the properties above:

| Option | What breaks |
|---|---|
| y-websocket or a hosted provider (Liveblocks, Hocuspocus) | An operator stores every update and can be compelled, can read unencrypted documents, and can delete or lock them. It is exactly the newsroom problem. |
| y-webrtc | Needs signalling servers, and the document vanishes when every peer is offline. Nobody can open it later. |
| IPFS or a pinning service | No live push and no queries. Someone has to pin, and unpinned data disappears without warning. Finding "the updates since block N by these members" means running our own index, so our own server again. |
| A subgraph | It indexes contract events. Tiramisu runs no contracts, and an indexer is one more operator in the path. |
| Postgres behind our API | Everything in the first row, plus we become the party a court order goes to. |

What Arkiv gives that the product depends on:

- Ordered, durable storage with nobody running a server for us.
- `$creator` that nobody can forge. The member list is trusted only from the owner's address, and edits only from members.
- Typed range queries (`qs >= base - 60`), so a late joiner fetches exactly what it needs in three queries.
- Push over WebSocket, with free reads by key.
- Expiration as the garbage collector, and the lease as the rule that keeps an unused document from living forever.

Take any one of those away and Quire needs a server again.

Kept off Arkiv on purpose:

| Kept off | Why |
|---|---|
| Text, titles, names, the member list | Encrypted inside the payload; never in attributes |
| The link secret | Only in the URL fragment, which browsers never send, and in the reader's browser |
| Private keys | Stay in the browser that made them; the user can save a key file |
| Cursors and presence | High-frequency and worthless after a second. Writing them to a chain would cost gas and leak typing rhythm |
| Gas | The drip is a separate function that sees only an address |

## Try it

1. Open the live app and press **New document**. The page creates a key for this document only, gets it a little test gas, and writes the member list and first snapshot in one transaction.
2. Press **Copy invite link** and open it in a private window. That window can read the document.
3. In the private window, press **Ask to join**. The request is sealed to the owner's key, and the owner's window shows it live. Press **Add**.
4. Type in either window. The other updates a block or two later. The **Live** tab shows each transaction and the measured delay.
5. Turn on **Who wrote what**. Each paragraph gets a bar in the colors of the wallets that wrote it, taken from the on-chain creator of each edit.
6. Open **Explorer** to see an entity as the public sees it next to what your browser decrypts.
7. In the owner's window, remove the second member. The key rotates and the roster is sealed under the new key. The removed window keeps what it saw and gets nothing new, even with the old link.

To check a document without the app:

```bash
pnpm install
pnpm --dir packages/y-arkiv exec tsx src/cli.ts verify '<document link>'
pnpm --dir packages/y-arkiv exec tsx src/cli.ts read '<document link>'
python3 readers/python/quire_audit.py --doc <0x document id>
```

The Python reader was written from PROTOCOL.md and the test vectors alone, without reading the TypeScript.

## How it uses Arkiv

| Arkiv feature | What Quire does with it | Where you see it |
|---|---|---|
| Typed attributes vs payload | Four attributes (`qp`, `qd`, `qk`, and `qs` as `u64`); everything else is encrypted payload | Explorer tab |
| Queries | Compound predicates, a `u64` range on `qs`, `$creator` OR filters, cursor pages pinned with `atBlock` | Opening a document: three queries in the Live tab counter |
| `$creator` | The member list is found by the owner's address. Edits are applied only from members, and a Yjs client id stays bound to the first creator that used it | People tab: "Ignored writes" |
| Entity Expiration | Edits and snapshots live 30 days (or until the owner's chosen date), join requests 1 hour, versions 1 year | Lifetime tab |
| Lifetime Extension | The newest snapshot is a lease. A member renews it by extending their own snapshot or writing a fresh one, and only when the new expiry is later | Lifetime tab countdown |
| Creation flags | Only published versions allow permissionless extension, and they are readonly. A document's own entities can be extended only by their creator | Explorer tab, Publish version |
| Ownership | The owner patches the member list; only an entity's owner can delete it (Shred, Delete document) | Lifetime tab |
| WebSocket events | `watchEntityEvents` over WebSocket with no `fromBlock`; each new entity is fetched with `arkiv_getEntity`, which the RPC does not bill | Live tab latency |
| Batches | Create document (ACL and snapshot), key rotation (ACL patch and new snapshot), lease renewal, shred, delete | Live tab: one transaction each |
| `atBlock` | Rebuild the document exactly as the chain held it at a past block | History tab: "Check against Arkiv" |

## Privacy model

What the explorer sees for every entity: creator and owner address, creation and expiry block, the four attributes, the flags, and a payload in one of six fixed sizes.

What it does not see: text, titles, member names, the member list, or who an address belongs to. Each member gets a fresh key per document, so their addresses in two documents are unrelated. After a revocation, even the link no longer reveals the roster or new join requests.

What still leaks, stated plainly:

- Which addresses write to a document id, and when. Edits go out on block boundaries, which blurs typing rhythm but does not hide activity.
- On this testnet deployment the drip funds every key from one sponsor address, so an observer can tell that those keys were funded by Quire. Funding from your own wallet instead links that wallet to the document key, and the app warns before it does.
- The app is JavaScript served by Vercel. A malicious build could read the link from the fragment. The Content Security Policy only lets the page talk to itself and the Arkiv RPC, and the readers in this repository let you verify a document without our page at all.
- Keys live in browser storage. Anyone with access to the browser profile has them. The app offers a key file so that clearing site data does not lose ownership.

## Repository

| Path | What it is |
|---|---|
| `packages/y-arkiv` | the Yjs provider, the Arkiv adapter, an in-memory chain for tests, the CLI |
| `apps/quire` | the editor (Vite, React, Tiptap) |
| `api/drip.ts` | the only server: sends a little test GLM to a new document key and sees nothing else |
| `readers/python` | independent reader and a standard-library privacy audit |
| `spec` | JSON Schema for every entity and header, and conformance vectors with a forged write |

## Run it locally

```bash
pnpm install
pnpm --dir packages/y-arkiv test
pnpm --dir apps/quire dev
```

Put a funded Tiramisu key in `.env` as `QUIRE_DEV_PRIVATE_KEY` to enable the local gas drip and the live tests (`pnpm --dir packages/y-arkiv test:live`).

## License

MIT
