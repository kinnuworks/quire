# Quire

Quire is a collaborative document editor with no server holding your documents. Every edit is encrypted in the browser and written to [Arkiv](https://arkiv.network) as an entity. Collaborators receive it over a WebSocket subscription within a block or two. The link you share is the key.

Under the editor is `y-arkiv`, a Yjs provider. Any Yjs app (Tiptap, BlockNote, CodeMirror, Excalidraw-style canvases) can swap `y-websocket` for it and get serverless, end-to-end encrypted sync.

- Live app: **LIVE_URL**
- Protocol: [PROTOCOL.md](PROTOCOL.md)
- Arkiv schema and queries: [arkiv/schema.md](arkiv/schema.md)
- Friction report: [arkiv/friction.md](arkiv/friction.md)

Built for Arkiv: Global Tour Stop (Privacy, Open Source and Security tracks). Testnet only; all demo data is synthetic.

## Who this is for

A shared document normally lives on one company's server. That company can read it, lock it and cut off access. This has happened to real people:

- On 31 October 2017, Google Docs locked journalists out of their own drafts with a "terms of service" flag caused by a faulty code push. Google's explanation confirmed it scans document content automatically.
- In July 2019, GitHub restricted private repositories and Pages sites for developers in Iran, Syria and Crimea to comply with US sanctions.
- On 9 September 2024, Notion cut off its users in Russia, also citing sanctions, and told them to export their data.

In each case the provider held the only copy and the only right to write. With Quire there is no copy anyone but the members can read. The data stays readable and writable as long as Arkiv runs, and no Quire server is involved in reading or writing it.

## Try it

1. Open the live app and press **New document**. The page creates a fresh key for this document, gets it a little test gas, and writes the member list and first snapshot in one transaction.
2. Press **Copy invite link** and open it in a private window. That window can read the document.
3. In the private window, press **Ask to join**. The owner's window shows the request live. Approve it.
4. Type in either window. The other one updates within a block or two. The **Live** tab shows each transaction and the measured delay.
5. Turn on **Show who wrote what**. Each paragraph gets a bar in the color of the wallets that wrote it, taken from the on-chain creator of each edit.
6. Open **Explorer view** to see an entity as the public sees it (four attributes, padded ciphertext) next to what your browser decrypts.
7. In the owner's window, remove the second member. The key rotates. New edits stop reaching the removed window, even though it still holds the old link.

To check everything without our app, run the reader from the terminal:

```bash
pnpm install
pnpm --dir packages/y-arkiv exec tsx src/cli.ts read '<document link>'
pnpm --dir packages/y-arkiv exec tsx src/cli.ts verify '<document link>'
```

Or use the Python reader in `readers/python`, which was written from the spec alone.

## How it uses Arkiv

| Arkiv feature | What Quire does with it | Where you see it |
|---|---|---|
| Typed attributes vs payload | Four attributes (`qp`, `qd`, `qk`, `qs` as `u64`); everything else is encrypted payload | Explorer view |
| Queries | Compound predicates, a `u64` range on `qs`, `$creator` filters, cursor paging pinned with `atBlock` | Opening a document costs exactly three queries |
| `$creator` | The member list is found by the owner's address; edits from anyone else are never applied | People tab: "Ignored writes" |
| Entity Expiration | Edits live 7 days, snapshots 30, join requests 1 hour, versions 1 year | Lifetime tab |
| Lifetime Extension | The newest snapshot is a lease that active members renew | Lifetime tab countdown |
| Creation flags | Snapshots and the ACL allow permissionless extension; published versions are readonly | Explorer view, Publish version |
| WebSocket events | `watchEntityEvents` over WebSocket with no `fromBlock`; edits are then fetched with the free `arkiv_getEntity` | Live tab latency |
| Atomic batches | Create document, compaction with chunks, key rotation with its snapshot, lease renewal, shredding | Live tab: one transaction each |
| `atBlock` | Rebuild the document exactly as the chain held it at a past block | History tab: "Check against Arkiv" |

## Privacy model

What the explorer sees for every entity: creator and owner address, creation and expiry block, the four attributes, the flags and a payload in one of six fixed sizes.

What it does not see: text, titles, member names, the member list, how many documents a person is in, or who a person is. Each member gets a fresh key per document, so their addresses in two documents are unrelated.

What still leaks: which addresses write to a given document id, and when. Edits are flushed on block boundaries instead of per keystroke, which blurs typing rhythm.

The link secret lives in the URL fragment. Browsers never send the fragment to a server. After reading it, the app replaces it in the address bar with a short form, so it does not sit in history or screenshots.

## Repository

| Path | What it is |
|---|---|
| `packages/y-arkiv` | the Yjs provider, Arkiv adapter, in-memory chain for tests, CLI |
| `apps/quire` | the editor (Vite, React, Tiptap) |
| `api/drip.ts` | the only server: sends a little test GLM to a new document key. It sees an address and nothing else |
| `readers/python` | independent reader and a standard-library privacy audit |
| `spec/vectors` | conformance data generated by the reference implementation |

## Run it locally

```bash
pnpm install
pnpm --dir packages/y-arkiv test
pnpm --dir apps/quire dev
```

Put a funded Tiramisu key in `.env` as `QUIRE_DEV_PRIVATE_KEY` to enable the local gas drip and the live tests (`pnpm --dir packages/y-arkiv test:live`).

## License

MIT
