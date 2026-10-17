# Quire

Quire is a collaborative document editor that keeps no copy of your documents. Every edit is encrypted in the browser and written to [Arkiv](https://arkiv.network) as an entity. Collaborators receive it over a WebSocket subscription a block or two later. The link you share is the key.

Under the editor is `y-arkiv`, a Yjs provider. A Yjs app (Tiptap, BlockNote, CodeMirror) can swap `y-websocket` for it to get end-to-end encrypted document sync with no sync server. It syncs the document only: there are no shared cursors or presence, each writer needs a key with a little test gas, and edits arrive in three to seven seconds rather than instantly.

- Live app: **https://quire-five.vercel.app**
- Protocol: [PROTOCOL.md](PROTOCOL.md), with [JSON Schema](spec/schema) and [test vectors](spec/vectors)
- Arkiv schema and queries: [arkiv/schema.md](arkiv/schema.md)
- Friction report: [arkiv/friction.md](arkiv/friction.md)

Built for Arkiv: Global Tour Stop, in the Privacy, Open Source and Security tracks. Testnet only; all demo data is synthetic.

## Who is harmed today

**Privacy: people whose drafts sit on someone else's server.** A newsroom drafting in a hosted editor leaves its drafts, comments and contributor list on the provider's servers, readable by the provider and by anyone who can compel it. Providers read those files themselves: on 31 October 2017 Google Docs locked journalists out of their own drafts with a mistaken abuse flag, and Google confirmed it scans documents with automated pattern matching ([Fortune](https://fortune.com/2017/11/01/google-docs-bug-patch)). And the provider is where a court order goes. On 5 January 2021 the US Justice Department obtained a court order requiring Google, which ran the New York Times' email, to hand over email logs for four Times reporters, under a gag order that kept the paper's own executive editor from being told ([Boston Globe](https://www.bostonglobe.com/2021/06/08/business/new-york-times-requests-disclosure-court-filings-seeking-reporters-email-data-gag-order), [Freedom of the Press Foundation tracker](https://pressfreedomtracker.us/all-incidents/justice-department-attempts-to-seize-email-records-of-four-new-york-times-reporters/)). Google resisted and the order was withdrawn, which is the only reason nothing was handed over. That order was for email logs, which are metadata. A hosted editor holds the content as well.

With Quire, there is no provider copy. Quire runs no server that sees text, and Arkiv holds only ciphertext padded to fixed sizes. An order served on us, or on Arkiv, gets ciphertext and throwaway addresses. To read a document, it would have to reach someone who holds the link, which means the people writing it, and they would know. Quire removes the content copy, not every trace: whoever runs the Arkiv RPC endpoint sees which document ids an IP address opens (see [What still leaks](#privacy-model)).

**Open Source: teams locked into a collaboration vendor.** On 15 February 2024 Atlassian ended support for Confluence Server and its other Server products, leaving customers its Cloud service or a Data Center licence as the only supported options ([Atlassian](https://www.atlassian.com/licensing/server-end-of-support)). Teams building collaborative features on Yjs face the same choice in small. They can rent a hosted provider, or self-host `y-websocket` or Hocuspocus. Both are open source, but whoever runs the server still holds every update and decides how long it lives. `y-arkiv` is a third option with no server to run or rent. The data format is a published protocol with a JSON Schema and conformance vectors. A second implementation in Python (`readers/python`) reads the same documents and is tested against the same vectors, so another team can build a compatible client from the spec without using our code.

**Security: people who have to prove who wrote what.** In 2023 William Quarterman, a UC Davis student, was given a zero and referred for academic dishonesty after a detector flagged his history essay as written by ChatGPT. He was cleared because he had written it in Google Docs and could show its edit history ([Tech & Learning](https://www.techlearning.com/news/he-was-falsely-accused-of-using-ai-heres-what-he-wishes-his-professor-did-instead), [The Aggie](https://theaggie.org/2023/03/15/student-faculty-discuss-the-use-of-ai-detectors-at-universities-after-reports-of-false-academic-dishonesty-accusations/)). That history was evidence only because Google says so: it lives on Google's servers, a reviewer cannot check it independently, and it exists only as long as the account does. In Quire, each edit is an entity whose on-chain creator nobody can forge, timestamped by the block it landed in. A reader accepts an edit only if its creator is a member and its Yjs client id derives from that creator's address with a salt the creator signed. A student can hand a reviewer the document link. The reviewer runs `y-arkiv blame '<link>'`, which reads every edit still on chain and prints each run of text with the address that wrote it, the block and the entity. To show an address is theirs, the student signs a phrase the reviewer picks (People tab, "Prove this key is yours"), and the reviewer runs `y-arkiv check-signature`. The key never leaves the student's browser, and neither step involves us.

This proves which key wrote the text, not which person: an address is a key made for one document, and the signature ties it to whoever holds it. Edits live 30 days unless the owner keeps the document longer (up to three years). After that, text survives only in snapshots and reads as claimed, vouched for by whoever wrote the snapshot, not proven.

## Why Arkiv, and what stays off it

| Option | What breaks for Quire |
|---|---|
| y-websocket, Hocuspocus, Liveblocks | An operator stores every update. It can be compelled, can read unencrypted documents, and can delete or lock them |
| y-webrtc | Needs signalling servers, and the document is gone when every peer is offline |
| IPFS or a pinning service | No live push, no queries, and unpinned data disappears. Finding "updates since block N by these members" means running our own index, which means our own server again |
| Nostr relays | Signed events and live push, but each relay decides what to keep and returns what it has. A document assembled from relays depends on which relays kept which events, nothing makes two writes land together (key rotation needs the new member list and the new snapshot at once), and there is no lease: data lives until a relay drops it |
| Ciphertext in EVM contract logs | Contracts are not available on Tiramisu, logs cannot be queried by typed range or expire, and reading them back needs an indexer, which is an operator again |
| Postgres behind our API | Every problem in the first row, and we become the party a court order goes to |

What Arkiv gives us that the product depends on:

- Durable storage that nobody runs for us, with every entity stamped by the block it landed in.
- `$creator` that nobody can forge. The member list is trusted only from the owner's address, and edits only from members.
- Typed range queries (`qs >= base - 60`), so a late joiner fetches exactly what it needs in three queries.
- Push over WebSocket, with free reads by key.
- Atomic batches, so a key rotation and its new snapshot land together.
- Expiration as the garbage collector, and the lease as the rule that lets an unused document lapse.

Kept off Arkiv on purpose:

| Kept off | Why |
|---|---|
| Text, titles, names, the member list | Encrypted inside the payload; never in attributes |
| The link secret | Only in the URL fragment, which browsers never send, and in the reader's browser |
| Private keys | Stay in the browser that made them; the user can save a key file |
| Cursors and presence | High-frequency and worthless a second later. On chain they would cost gas and leak typing rhythm |
| Gas | A separate drip function. It sees the new key's address and the visitor's IP address, never document data |

## Try it

The fastest check uses the public demo documents listed under [Submission evidence](#submission-evidence). To try the full flow:

1. Open the live app and press **New document**. The page creates a key for this document only, funds it with a little test gas, and writes the member list and first snapshot in one transaction. Before asking the drip, the page spends a second or two on a proof of work, so a script cannot drain the sponsor with a loop of requests.
2. Press **Copy invite link** and open it in a private window. That window can read the document.
3. In the private window, press **Ask to join**. The request is sealed to the owner's key, and the owner's window shows it live. Press **Add**.
4. Type in either window. The other updates a block or two later, and the **Live** tab shows each transaction and the measured delay.
5. Turn on **Who wrote what**. Each paragraph gets a bar in the colors of the wallets that wrote it.
6. Open **Explorer** to see an entity as the public sees it next to what your browser decrypts.
7. In the owner's window, remove the second member. The key rotates and the roster is sealed under the new key. The removed window keeps what it saw and gets nothing new.

To check a document without our app:

```bash
pnpm install
pnpm --dir packages/y-arkiv exec tsx src/cli.ts verify '<document link>'
python3 readers/python/quire_audit.py --doc <0x document id>
```

The Python reader was written against PROTOCOL.md and the vectors, as a separate implementation rather than a port. Writing it found ten places where the spec and the TypeScript disagreed, and each was settled in the spec. It has 94 tests of its own, covering forged writes, forged snapshots, swapped authorship and malformed headers. Its full reader needs `cryptography` and `pycrdt` (`pip install -r readers/python/requirements.txt`); without them most of its tests skip. The audit needs only the standard library.

The TypeScript suite has 88 tests (plus 2 that run only against Tiramisu), including a property-based convergence check, forged writes and forged snapshots, and a check that the committed vectors say what the reference reads. `python3 packages/y-arkiv/scripts/mutants.py` removes each of 32 security rules in turn and shows that a test fails every time.

## How it uses Arkiv

| Arkiv feature | What Quire does with it | Where you see it |
|---|---|---|
| Typed attributes vs payload | Four attributes (`qp`, `qd`, `qk`, and `qs` as `u64`); everything else is encrypted payload | Explorer tab |
| Queries | Compound predicates, a `u64` range on `qs`, `$creator` OR filters, cursor pages pinned with `atBlock` | Opening a document: three queries in the Live tab counter (the owner pays one more, for join requests) |
| `$creator` | The member list is found by the owner's address. Edits are applied only from members, and only if their client id is `clientIdFor($creator, salt)` with a salt the creator signed. The owner can find one person's join request with a `$creator` filter, however many junk requests there are | People tab: "Ignored writes", "Expecting someone?"; `y-arkiv blame` |
| Entity Expiration | Edits and snapshots live 30 days (or until the owner's chosen date), join requests 1 hour, versions 1 year | Lifetime tab |
| Lifetime Extension | The newest snapshot is a lease. A member renews it by extending their own snapshot or writing a fresh one, and only when the new expiry is later | Lifetime tab countdown |
| Creation flags | Published versions are readonly and anyone can extend them (the version page has a "Keep this version alive" button; the CLI has `extend`). The member list allows permissionless extension too, so a document stays open while its writers use it. Anyone can extend it, strangers included, but it holds no text, so that keeps nothing readable alive, and the owner can still delete it. Edits and snapshots carry no flags, so only their creator can extend them | Explorer tab, version page |
| Ownership | The owner patches the member list; only an entity's owner can delete it (Shred, Delete document) | Lifetime tab |
| WebSocket events | `watchEntityEvents` over WebSocket with no `fromBlock`; each new entity is fetched with `arkiv_getEntity`, which is not billed | Live tab latency |
| Batches | Create document (ACL and snapshot), key rotation (ACL patch and new snapshot), lease renewal, shred, delete | Live tab: one transaction each |
| `atBlock` | Rebuild the document exactly as the chain held it at a past block | History tab: "Rebuild from Arkiv at this block" |

## Privacy model

**What the explorer shows for every entity:**
- creator and owner address
- creation and expiry block
- the four attributes and the flags
- the epoch number at the front of each payload, so anyone can count how many times a document's key was rotated, and when
- a payload in one of six fixed sizes (join requests, sealed to the owner's key, are 65 bytes longer)

**What it does not show:** text, titles, member names, the member list (after the first revocation, link holders see only a member count), or who an address belongs to. Each member gets a fresh key per document, so their addresses in two documents are unrelated on chain.

**What still leaks:**

- **Activity:** which addresses write to a document id, and when. Each flush waits a random extra delay of up to two seconds on top of the block interval, which blurs typing rhythm but does not hide activity.
- **The RPC operator:** every query names the document id and member addresses, and every read comes from your IP address. Whoever runs the RPC endpoint can link your IP to the documents you open, and could also leave entities out of its answers. Use a VPN or Tor if the first matters to you. The CLI takes `--rpc` and `--ws`, so you can read through your own node or a second endpoint and compare.
- **The drip:** it sees your IP address and the new key it funds, and Vercel logs requests. On this testnet deployment it also funds every key from one sponsor address, so an observer can tell those keys were funded by Quire. Funding from your own wallet instead links that wallet to the document key, and the app warns before it does that.
- **Old ciphertext:** expiry, deletion and Shred remove entities from Arkiv's state, but the transactions that wrote them, encrypted payloads included, stay in block history for good. Anyone who has the link and an archive of old blocks can decrypt what was written under keys the link opens. Removing a member rotates the key, which protects everything written afterwards. A leaked link is the one thing Quire cannot take back: start a new document.
- **The app itself:** it is JavaScript served by Vercel, so a malicious build could read the link from the fragment. The Content Security Policy only lets the page talk to itself and the Arkiv RPC, and the readers in this repository let you verify a document without our page.
- **Keys in the browser:** keys live in browser storage, so anyone with access to the browser profile has them. The app offers a key file, so clearing site data does not lose ownership.

## Submission evidence

Two public demo documents live on Tiramisu. Their content is synthetic, and their keys were made for this demo only.

**Open demo**: three members, readable by anyone with the link.
https://quire-five.vercel.app/#/d/YPp1ObuyhC5aL5SstUY3bLPHWx2B8CZMCuT0ry_AdXg.hRKbkuO9SOb9g_T_JRhTMdrbK-k8eeKWwipQIZ1gw_Q.a3ed39176d6e55cd4b58134c7894b42615e16283

**Revocation demo**: Ravi was removed, so the key rotated. With the link alone you can open the member list, but it is sealed under the new key, so you learn only that there are two members, and you can read none of the text. The addresses that wrote entities are still public on chain, as for any document.
https://quire-five.vercel.app/#/d/YFZ77xJiujpF5XCqAqxxPB9PKni2xN6AulVCuzdxl10.aGbgHFjUlo6olDeJ4SHcJo8YKTssnwZzuBLB7UBSQUo.0ea55b2eeecddc4e701417001460b596c12a2ada

Addresses that create Quire's entities:

| Address | Role |
|---|---|
| `0x7ad475ff24a9d6d06b69f460005300fa914d8e11` | gas drip sponsor; funded every key below with a plain transfer |
| `0xa3ed39176d6e55cd4b58134c7894b42615e16283` | open demo: owner (Asha); created the ACL, snapshots and edits |
| `0xe03ca1f7480b05da8928270fc5a79413025ef6be` | open demo: writer (Bea); join request and edits |
| `0xba964589a3bd9363c102dc9eabdd8863a90f109d` | open demo: writer (Ravi); join request and edits |
| `0x0ea55b2eeecddc4e701417001460b596c12a2ada` | revocation demo: owner; created the ACL, rotated the key |
| `0xbc9375026f9818a3ad5216509a8cd111527cee1a` | revocation demo: writer who stayed; wrote a snapshot under the new key |
| `0x64e51df3dd1ef6cddccfe1b0ba7cad1fbbccb375` | revocation demo: removed member; his join request has since expired (1 hour), its transaction remains in block history |
| `0x42885193a50ab941ea8ea6fd180397c46a59041d` | open demo: planted forgery. Holds the link, wrote one valid encrypted edit, is not a member, so no reader applies it (`scripts/plant-forgery.ts`) |

Document ids: open demo `0x60fa7539bbb2842e5a2f94acb546376cb3c75b1d81f0264c0ae4f4af2fc07578`, revocation demo `0x60567bef1262ba3a45e570aa02ac713c1f4f2a78b6c4de80ba5542bb3771975d`. Every entity carries `qd` equal to its document id, so this query lists them all:

```
qp = str('quire1') AND qd = bytes32(0x60fa7539bbb2842e5a2f94acb546376cb3c75b1d81f0264c0ae4f4af2fc07578)
```

Paste it into the [Data Explorer](https://data.arkiv.network), or look up any address above in the [block explorer](https://tiramisu.explorer.arkiv.network) to see the creating transactions.

To reproduce what the app shows, without the app:

```bash
pnpm install
pnpm --dir packages/y-arkiv exec tsx src/cli.ts verify '#/d/YPp1ObuyhC5aL5SstUY3bLPHWx2B8CZMCuT0ry_AdXg.hRKbkuO9SOb9g_T_JRhTMdrbK-k8eeKWwipQIZ1gw_Q.a3ed39176d6e55cd4b58134c7894b42615e16283'
pnpm --dir packages/y-arkiv exec tsx src/cli.ts read '#/d/YPp1ObuyhC5aL5SstUY3bLPHWx2B8CZMCuT0ry_AdXg.hRKbkuO9SOb9g_T_JRhTMdrbK-k8eeKWwipQIZ1gw_Q.a3ed39176d6e55cd4b58134c7894b42615e16283'
pnpm --dir packages/y-arkiv exec tsx src/cli.ts blame '#/d/YPp1ObuyhC5aL5SstUY3bLPHWx2B8CZMCuT0ry_AdXg.hRKbkuO9SOb9g_T_JRhTMdrbK-k8eeKWwipQIZ1gw_Q.a3ed39176d6e55cd4b58134c7894b42615e16283'
python3 readers/python/quire_audit.py --doc 0x60fa7539bbb2842e5a2f94acb546376cb3c75b1d81f0264c0ae4f4af2fc07578 --owner 0xa3ed39176d6e55cd4b58134c7894b42615e16283
```

The public endpoint gives each IP address about 100 free queries per window; if a run stops with a budget message, wait the minutes it names or set `ARKIV_ACCESS_KEY`. `quire_read.py --link '<link>' --verify` prints the Python reader's own trust report, including the same outside write.

Expected: `verify` reports the owner found by `$creator`, epoch 0, three members, 1 snapshot and 4 updates applied, 0 ignored, and 3 queries, then one more query listing the planted forgery: one entity by `0x42885193a50ab941ea8ea6fd180397c46a59041d`, never fetched or applied. `read` prints the four lines of the Ward 14 log. `blame` attributes all four paragraphs, every character proven, to Asha, Bea and Ravi, each with the block and entity of the edit. The audit ends with `RESULT: PASS`. For the revocation demo, `verify` reports epoch 1 with the roster sealed ("this link sees only a count (2)"), and `read` prints nothing.

The full live suite (`pnpm --dir packages/y-arkiv test:live`) passed on Tiramisu. It covers two keys collaborating, a cold reader opening the document in exactly 3 queries, a 250 KB paste written as chunks, a revocation and a published version.

## Repository

| Path | What it is |
|---|---|
| `packages/y-arkiv` | the Yjs provider, the Arkiv adapter, an in-memory chain for tests, the CLI |
| `apps/quire` | the editor (Vite, React, Tiptap) |
| `api/drip.ts` | the only server: sends a little test GLM to a new document key |
| `readers/python` | independent reader and a standard-library privacy audit |
| `spec` | JSON Schema for every entity and header, and conformance vectors with a forged write |
| `arkiv/probes` | raw results behind the friction report |

## How this was built

Everything here was written during the challenge window, in one long working session on 17 and 18 October 2026. No code predates the challenge. The first seven commits were re-authored once, to use a GitHub no-reply address instead of a personal email, and that rewrite reset their timestamps to the same minute; every later commit carries its real time. The libraries used are Yjs, Tiptap, viem, `@arkiv-network/sdk`, `arkiv-encryption`, noble curves and hashes, React and Vite.

## Run it locally

```bash
pnpm install
pnpm --dir packages/y-arkiv test
pnpm --dir apps/quire dev
```

Put a funded Tiramisu key in `.env` as `QUIRE_DEV_PRIVATE_KEY` to enable the local gas drip and the live tests (`pnpm --dir packages/y-arkiv test:live`). An `ARKIV_ACCESS_KEY` in the same file raises the query budget for scripts and tests.

## License

MIT
