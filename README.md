# Quire

Quire is a collaborative document editor that keeps no copy of your documents. Every edit is encrypted in the browser and written to [Arkiv](https://arkiv.network) as an entity. Collaborators receive it over a WebSocket subscription, usually three to seven seconds later. The link you share is the key.

Under the editor is `y-arkiv`, a Yjs provider. A Yjs app (Tiptap, BlockNote, CodeMirror) can use it in place of `y-websocket` to get end-to-end encrypted document sync with no sync server. It takes three more arguments than `y-websocket` (a store, the writer's key and a salt from `prepareDoc`), and it syncs the document only: there are no shared cursors or presence, each writer needs a key with a little test gas, and edits arrive in three to seven seconds rather than instantly.

- Live app: **https://quire-five.vercel.app**
- Protocol: [PROTOCOL.md](PROTOCOL.md), with [JSON Schema](spec/schema) and [test vectors](spec/vectors)
- Arkiv schema and queries: [arkiv/schema.md](arkiv/schema.md)
- Friction report: [arkiv/friction.md](arkiv/friction.md)

Built for Arkiv: Global Tour Stop, in the Privacy, Open Source and Security tracks. Testnet only; all demo data is synthetic.

- **Privacy:** text is encrypted in the browser and padded before it leaves, and the key travels only in the link, so no server, RPC operator or Arkiv node can read, scan or hand over a document's words. [Who is harmed today](#who-is-harmed-today), [what still leaks](#privacy-model).
- **Open Source:** a published protocol with JSON Schema, conformance vectors and 23 edge cases, two independent readers (TypeScript and Python) diffed against each other, and a Yjs provider any Yjs editor can use in place of `y-websocket`. [PROTOCOL.md](PROTOCOL.md).
- **Security:** every edit is a readonly entity whose `$creator` nobody can forge, so `y-arkiv blame` proves which key wrote each passage, checked against the member list as it stood at that block, without trusting us. The [contested demo](#who-is-harmed-today) shows an owner trying to take a co-author's paragraph, and the chain showing who wrote it.

## Five minutes, for judges

1. **Drag the scrubber** (1 minute). On the [home page](https://quire-five.vercel.app/#proof), "Someone took the credit" replays a real document on Arkiv block by block: Bea types the key finding, then Asha, the owner, erases her from the member list and pastes the finding back as her own. The member list, the chain's verdict and the edit rhythm change as you drag.
2. **Open that document in the app** (1 minute). Open the [contested study](https://quire-five.vercel.app/#/d/DqGiOcF4WHKgOkfcBcEansmEdytSLBHDv5EkQf6YNFQ.EBkcdL5buH73K8vSpkP_8akeH1w-npysYnwdf3SzokY.b83063cf00de65f09187c9600b0b3fd951f60fb0). With no toggles on, the app walks the member list's history, says the owner erased Bea, loads every edit still on chain and says "Typed first by someone else": the finding is one paste by Asha's key, and Bea's key typed the same words first, at blocks 734926 to 734961.
3. **Check it without our app** (2 minutes). With Node 20 or later, nothing to clone ([y-arkiv on npm](https://www.npmjs.com/package/y-arkiv)):

   ```bash
   npx y-arkiv timeline '#/d/DqGiOcF4WHKgOkfcBcEansmEdytSLBHDv5EkQf6YNFQ.EBkcdL5buH73K8vSpkP_8akeH1w-npysYnwdf3SzokY.b83063cf00de65f09187c9600b0b3fd951f60fb0'
   npx y-arkiv blame '#/d/DqGiOcF4WHKgOkfcBcEansmEdytSLBHDv5EkQf6YNFQ.EBkcdL5buH73K8vSpkP_8akeH1w-npysYnwdf3SzokY.b83063cf00de65f09187c9600b0b3fd951f60fb0' --at 734966
   ```

   `timeline` lists Bea's seven edits and Asha's single paste that removed 100 characters and added the same 100. `blame --at` proves every word of the finding was Bea's, checked against the member list as it stood at each of her blocks. The independent Python reader gives the same counts (see [the contested demo](#who-is-harmed-today)). On a shared network whose free queries are spent, add `--relay` to send queries through Quire's relay.
4. **See what the chain sees** (1 minute). In the [shared water log](https://quire-five.vercel.app/#/d/cGY4Lxdu7yBatU75t4TxoyiHNJOtyVA3npCI1WcHL2c.OPYzqRUr9D1b_T_O3-7fsA0layOo0LcNOlMaphGxpSE.a7da7e4e17101ad0b4832c7cce0f87bf6e84b546), the **Explorer** tab puts each public entity (four attributes and a block of ciphertext) next to what your browser decrypts, and the **People** tab lists the one forged write from outside the member list that no reader applies.

Contents: [who is harmed today](#who-is-harmed-today) · [why Arkiv](#why-arkiv-and-what-stays-off-it) · [try it](#try-it) · [how it uses Arkiv](#how-it-uses-arkiv) · [cost](#what-it-costs) · [what still leaks](#privacy-model) · [submission evidence](#submission-evidence) · [repository](#repository) · [run it locally](#run-it-locally)

## Who is harmed today

**Privacy: reporters whose drafts name their sources.** A newsroom drafting in a hosted editor leaves the plaintext of every draft, comment and contributor list with the provider, which can read it, scan it, lock it and hand it over. For a reporter, that draft is where a source's name sits before anything is published. On 31 October 2017 Google Docs locked users out of their own drafts with a mistaken abuse flag, and Google confirmed that it scans documents with automated pattern matching ([Fortune](https://fortune.com/2017/11/01/google-docs-bug-patch)). A court order goes to the provider too: in January 2021 the US Justice Department ordered Google to hand over email logs for four New York Times reporters, under a gag order ([Boston Globe](https://www.bostonglobe.com/2021/06/08/business/new-york-times-requests-disclosure-court-filings-seeking-reporters-email-data-gag-order), [Freedom of the Press Foundation](https://pressfreedomtracker.us/all-incidents/justice-department-attempts-to-seize-email-records-of-four-new-york-times-reporters/)). That order was for metadata and was withdrawn after Google pushed back; a hosted editor holds the content as well.

Quire removes the readable copy. Text is encrypted in the browser before it leaves, padded to fixed sizes, and the only key travels in the link, so nothing that stores or serves a document can read its words, scan them or hand them over: not Vercel, not the RPC operator, not Arkiv's nodes, not us. An order served on any of them gets ciphertext and throwaway addresses. On day one a reporter presses New document, sends the link to an editor over Signal, and drafts. When a freelancer leaves the story, removing them rotates the key, and nothing written afterwards opens with the old link. Reading through their own Arkiv node (the CLI takes `--rpc` and `--ws`) keeps even which document an IP address opens away from the public endpoint; the web app uses the public one. No host holds the only copy either, and the one person who can end a document is its owner, by deleting the member list.

What Quire does not hide is metadata. Anyone who learns a document id can see, for good, how many keys write to it and when each edit landed, to within a few seconds. Where the fact that two people are working together is itself the secret, Quire does not protect it. Some gates remain too: the app is served by Vercel, today's network has one public endpoint, and new keys get gas from our sponsor. The drip sees the IP address that asks for gas, and Vercel logs it with the time; matched with the sponsor's transfer on chain and that key's first write, it ties an IP address to a document id. A key funded from your own wallet avoids that (the app offers it when a browser wallet is present), but links the key to that wallet instead. People who join need not touch the drip at all: **Get gas from the owner** shows the joiner's address to pass on over the same channel as the link, and the owner sends gas from the document's own key, which links nothing the document's entities do not already show. The readers in this repository work without our page, and any Arkiv node can serve the data. Two limits matter. Whoever runs the RPC endpoint sees which document ids an IP address opens. And ciphertext is permanent: block history keeps every payload, so a link that leaks opens everything written under its key, even after expiry or deletion. **Rotate the key** stops an old link from opening anything written afterwards, and the owner can have it rotate by itself every 30 days. Rotation runs when the owner opens the document in the browser where they turned it on, so a link that leaks opens writing only up to the owner's next visit after the month is up. See [What still leaks](#privacy-model).

**Open Source: teams whose collaboration layer someone else controls.** A collaboration vendor sets the format and the exit: when Atlassian ended Confluence Server on 15 February 2024, customers were left with its Cloud service or a Data Center licence ([Atlassian](https://www.atlassian.com/licensing/server-end-of-support)). A team adding live editing to its own app faces the same choice in small. A hosted Yjs service keeps its users' documents in that service's storage behind its API. Self-hosting `y-websocket` or Hocuspocus avoids the vendor but makes the team the operator that holds every update. `y-arkiv` needs neither: install the package, replace one provider with another (three more arguments), and the documents live on Arkiv in a format anyone can read from the spec (see [examples/two-writers](examples/two-writers)). The data format is a published protocol with a JSON Schema and conformance vectors. A second implementation in Python (`readers/python`) reads the same documents and is tested against the same vectors, so another team can build a compatible client from the spec without using our code.

**Security: people who have to prove who wrote what.** In 2023 William Quarterman, a UC Davis student, was given a zero and referred for academic dishonesty after a detector flagged his history essay as written by ChatGPT. He was cleared because he had written it in Google Docs and could show its edit history ([Tech & Learning](https://www.techlearning.com/news/he-was-falsely-accused-of-using-ai-heres-what-he-wishes-his-professor-did-instead), [The Aggie](https://theaggie.org/2023/03/15/student-faculty-discuss-the-use-of-ai-detectors-at-universities-after-reports-of-false-academic-dishonesty-accusations/)). That history was evidence only because Google says so. It lives on Google's servers, a reviewer cannot check it independently, and it exists only as long as the account does. And it holds only what the host chose to keep: in Dunbar v. Google (N.D. Cal., 2 April 2013), Google told the court that earlier versions of continuously edited documents were not saved, because each new version overwrote the last ([eDiscovery Law](https://www.ediscoverylaw.com/?p=8999), [Sedona Conference](https://www.thesedonaconference.org/node/5677)). The same gap hurts co-authors who disagree about who wrote a passage, a clause or a finding: the only record is the provider's.

**See it settle a dispute.** The [contested demo](https://quire-five.vercel.app/#/d/DqGiOcF4WHKgOkfcBcEansmEdytSLBHDv5EkQf6YNFQ.EBkcdL5buH73K8vSpkP_8akeH1w-npysYnwdf3SzokY.b83063cf00de65f09187c9600b0b3fd951f60fb0) is a short study co-written by Asha (the owner) and Bea. Bea typed the key finding, a few words at a time. Then Asha erased Bea from the member list, deleted her paragraph and pasted the same words back as one edit of her own. Today's text of the finding is Asha's paste. Open the link and the app says so before you touch anything: it walks the member list's history, finds that Bea was erased, checks every edit still on chain and shows that Bea's key typed the finding first. Three commands, run by anyone, show the same without our page:

```bash
npx y-arkiv timeline '#/d/DqGiOcF4WHKgOkfcBcEansmEdytSLBHDv5EkQf6YNFQ.EBkcdL5buH73K8vSpkP_8akeH1w-npysYnwdf3SzokY.b83063cf00de65f09187c9600b0b3fd951f60fb0'
npx y-arkiv blame '#/d/DqGiOcF4WHKgOkfcBcEansmEdytSLBHDv5EkQf6YNFQ.EBkcdL5buH73K8vSpkP_8akeH1w-npysYnwdf3SzokY.b83063cf00de65f09187c9600b0b3fd951f60fb0' --at 734966
pip install -r readers/python/requirements.txt
python3 readers/python/quire_read.py --link '#/d/DqGiOcF4WHKgOkfcBcEansmEdytSLBHDv5EkQf6YNFQ.EBkcdL5buH73K8vSpkP_8akeH1w-npysYnwdf3SzokY.b83063cf00de65f09187c9600b0b3fd951f60fb0' --at 734966 --audit --json
```

`timeline` lists Bea's seven edits typing 100 characters between blocks 734926 and 734961, then Asha's single edit at block 735002 that removed 100 characters and added the same 100. `blame --at` proves every word of the finding was Bea's, written while she was a member, checked against the member list as it stood at each of her blocks, which Asha's later rewrite cannot reach. The Python reader's `proven` counts agree with it exactly: 100 characters for Bea, 116 for Asha. `verify` names Bea as erased from the member list.

In Quire each edit is an entity whose on-chain creator nobody can forge, stamped with the block it landed in. Between co-authors who each hold their own key, that settles exactly the question they disagree on: which key wrote this passage, and when. For a single author facing an accusation, it proves which key typed the text and the rhythm it arrived in, which is evidence to weigh rather than proof that a person composed it. A reader accepts an edit only if its creator was a member when it landed, and its Yjs client id derives from that creator's address with a salt the creator signed. A student hands a reviewer the document link, and the reviewer runs three commands, none of which involve us:

- `y-arkiv blame '<link>'` prints each run of text with the address that wrote it, the block and the entity. It checks every author against the member list as it stood at that edit's block, read with `atBlock`, so a later rewrite of the list changes nothing. The Python reader does the same with `--audit`, and on the open demo both give each address the same count of proven characters.
- `y-arkiv timeline '<link>'` lists every edit in order with the characters it added and removed. A long run of small edits over hours is what writing looks like; one large edit is a paste. Edits go out every two to four seconds, so it shows rhythm at that grain, not keystrokes, and rhythm can be scripted: the timeline is evidence to weigh, not proof that a person typed.
- `y-arkiv check-signature` checks a phrase the reviewer chose, signed in the student's browser (People tab, "Prove this key is yours"), so the reviewer knows the address is the student's. The key never leaves the browser.

What this does and does not prove:

- **Which key, not which person.** An address is a key made for one document, and the signed phrase ties it to whoever holds it.
- **For as long as the owner keeps the document.** Edits live 30 days by default; a document created as an **authorship record** (a switch under New document) keeps everything a year from the first transaction, so proof does not lapse while nobody opens it. Any writer can press **Keep my proof as long as the document** to extend their own edits to the lifetime the owner chose (up to three years); proof cannot outlive the document. Both readers enforce that ceiling, not just our app: an edit or snapshot that some other client extended past the owner's lifetime, or more than 30 days past its own last extension, is ignored. The ceiling is anchored to each entity's own `updatedAt`, so a live tab and a reader opening the document a week later reach the same verdict.
- **Removal does not erase it.** Edits a removed member wrote before the removal still count, and `blame` and `--audit` prove them. Everyday readers show what today's members' snapshots and the recent edits hold, so once a removed member's edits leave the read window, their words there rest on another member's snapshot; an owner who compacts without them leaves those words to the audit.
- **The owner cannot rewrite it.** The owner can patch the member list to change who was added when or who was removed, or lower `keepUntil`, but every reader (the app, `read`, `verify`, `blame`, `timeline` and the Python reader) checks each edit's author against the list as it stood at that edit's block with `atBlock`, past state nobody can rewrite, so a backdated newcomer proves nothing anywhere. Erasing someone from the list stops a plain read from fetching their edits, but it cannot hide the erasure: the app walks the list's history whenever a document opens and, if anyone was erased, says who and checks every edit still on chain, so their writing still counts in the default view. `verify` names them too, and `blame`, `timeline` and `quire_read.py --audit` prove it. The owner can still delete the member list, which stops readers from opening the document today, but not from reading it as it stood before: `y-arkiv blame '<link>' --at <block>` (or `quire_read.py --at <block>`) pins every read to that block, and our probe found `atBlock` reads reaching back to the chain's first block. An owner who deletes the list and makes a new one under the same link gets a document whose earlier writing counts for nobody, and `verify` and `blame` say `recreated`, name the earlier writers and give the `--at` block to read the original.
- **Where the audit stops.** Reading the member list's history costs one read per version, and an owner can add versions cheaply by renewing the list once a block. An audit reads up to 2,000 versions. Past that, or when the gateway's limit of about 600 reads a minute cuts the walk short, it reads every edit under the document instead; if strangers' junk makes even that too large, it reads every address the walk did find and says the check is incomplete. The app shows a banner, `blame` prints `narrowed`, and the Python reader prints `audit narrowed`. The CLI waits out the read limit instead of giving up. The "typed first by someone else" note comes from the TypeScript reader (the app and `blame`); the Python reader proves the same characters but does not print the note.
- **Your own tab is held to the same rule.** Text you typed shows as pending until its edit lands, and stays unproven if it landed after you were removed, exactly as every other reader sees it.
- **Expired edits become claims.** Text whose edits have expired survives only in snapshots and reads as claimed, vouched for by whoever wrote the snapshot, not proven.

## Why Arkiv, and what stays off it

Take Arkiv away and three things Quire promises are gone, whoever the replacement host is:

1. **No provider can take the document away.** It lives in network state rather than on one company's server. No provider can delete it, lock an account or shut down and take the only copy with it. The one person who can end it is its owner: by deleting the member list, or by staying away, since only the owner renews the list, 90 days from each visit or to the date the owner chose. Even then the chain keeps its past state, so `y-arkiv blame '<link>' --at <block>` still proves who wrote what as of any earlier block. (Today's testnet is run by one operator with one public endpoint, which could refuse to serve it; the data and both readers do not depend on that endpoint, and any Arkiv node can serve them.)
2. **Anyone can check who wrote what.** Every edit is its own entity, created `readonly`, whose `$creator` nobody can forge, stamped with the block it landed in. A reviewer rebuilds the document and its authorship from the chain with either of two independent readers, without trusting us or any server. A hosted editor's history, encrypted or not, is only as good as the host's word.
3. **Expiry is enforced, not promised.** Every entity carries the lifetime the owner chose, and the network drops it when that runs out. Readers ignore any copy extended past the owner's lifetime, or more than a 30-day lease past its own last extension. A writer can still renew their own pieces a month at a time, as the lease does, but once the owner deletes the member list no reader opens any of them.

Why not the alternatives:

| Option | What breaks for Quire |
|---|---|
| y-websocket, Hocuspocus, Liveblocks | An operator stores every update. It can be compelled, can read unencrypted documents, and can delete or lock them |
| y-webrtc | Needs signalling servers, and the document is gone when every peer is offline |
| IPFS or a pinning service | No live push, no queries, and unpinned data disappears. Finding "updates since block N by these members" means running our own index, which means our own server again |
| Nostr relays | Signed events and live push, but each relay decides what to keep and returns what it has. A document assembled from relays depends on which relays kept which events, nothing makes two writes land together (key rotation needs the new member list and the new snapshot at once), and there is no lease: data lives until a relay drops it |
| Ciphertext in EVM contract logs | Logs cannot be queried by typed attribute or range, cannot be read as they stood at a past block without replaying the chain, and never expire. Reading them back means running an indexer, which is an operator again, and nobody's indexer can prove it returned every log. Arkiv's node answers typed queries, `atBlock` reads and expiry itself |
| Postgres behind our API | Every problem in the first row, and we become the party a court order goes to |
| CryptPad, Proton Docs | Hosted end-to-end encrypted editors keep content from the host, and they are faster and have presence. They fail points 1 and 2: the host decides whether your document exists, and its edit history is unverifiable from outside |

The Arkiv features each of those rests on:

- Storage we do not run: the network keeps every entity, stamped by the block it landed in, until it expires. Today that network is Tiramisu, a testnet the Arkiv team operates.
- `$creator` that nobody can forge. The member list is trusted only from the owner's address, and edits only from members.
- Typed range queries (`qs >= base - 60`, and per-creator bounds), so a late joiner fetches exactly what it needs in three queries.
- `atBlock` reads by key and by query: each edit's author is checked against the member list as it stood at that block, and a deleted document can still be read as it was.
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

1. Open the live app and press **New document**. The page creates a key for this document only, funds it with a little test gas, and writes the member list and first snapshot in one transaction. Before asking the drip, the page spends a second or two on a proof of work. That slows a script down rather than stopping it: the drip's caps (three keys per IP and 40 in total per ten minutes, 0.04 to 0.06 test GLM each, a random amount sent after a random wait of up to six seconds) live in each server instance's memory, so a script spread over many addresses can still use up the total for a while, and new documents then wait for it to refill. Testnet gas is all it can take.
2. Press **Copy invite link** and open it in a private window. That window can read the document.
3. In the private window, press **Ask to join**. The request is sealed to the owner's key, and the owner's window shows it live. Press **Add**.
4. Type in either window. The other updates a few seconds later, and the **Live** tab shows each transaction and the measured delay.
5. Turn on **Who wrote what**. Each paragraph gets a bar in the colors of the wallets that wrote it.
6. Open **Explorer** to see an entity as the public sees it next to what your browser decrypts.
7. In the owner's window, remove the second member. The key rotates and the roster is sealed under the new key. The removed window keeps what it saw and gets nothing new.

To check a document without our app:

```bash
npx y-arkiv verify '<document link>'
python3 readers/python/quire_audit.py --doc <0x document id>
```

The Python reader was written against PROTOCOL.md and the vectors, as a separate implementation rather than a port. Writing it found ten places where the spec and the TypeScript disagreed, and each was settled in the spec. It has 101 tests of its own, covering forged writes, forged snapshots, swapped authorship and malformed headers. Its full reader needs `cryptography` and `pycrdt` (`pip install -r readers/python/requirements.txt`); without them most of its tests skip. The audit needs only the standard library. `pnpm --dir packages/y-arkiv compare-readers` runs both readers on the live demos (the open one also as an audit and as of 100 blocks ago, the contested one as an audit and as it stood when Bea finished) and on the vectors (as a member and as a link holder) and diffs their verdicts: the text, every entity applied, every outside write rejected, and how many characters each address has proven. They also run every edge case in `spec/vectors/cases` (23 so far: JSON number forms, a byte-order mark, trailing newlines, malformed attributes, a wrong snapshot size, tied snapshots, a backdated `qs`, one writer's conflicting edits, a snapshot that clashes with an applied edit, a number encoded two ways, an edit that is not readonly, a snapshot kept past the owner's lifetime, deleted clocks reused, a member removed and re-added, history across two rotations, a newer snapshot that rewrites another member's own words, a name of 30 emoji), each a document with one crafted entity and the text a correct reader must produce. They agree on all of them.

The TypeScript suite has 177 tests (plus 2 that run only against Tiramisu), including a property-based convergence check, forged writes and forged snapshots, and a check that the committed vectors say what the reference reads. `python3 packages/y-arkiv/scripts/mutants.py` removes each of 82 security rules in turn and shows that a test fails every time.

## How it uses Arkiv

| Arkiv feature | What Quire does with it | Where you see it |
|---|---|---|
| Typed attributes vs payload | Four attributes (`qp`, `qd`, `qk`, and `qs` as `u64`); everything else is encrypted payload | Explorer tab |
| Queries | Compound predicates, a `u64` range on `qs`, `$creator` OR filters, cursor pages pinned with `atBlock` | Opening a document: three queries in the Live tab counter, plus one page listing outside writes (the owner pays one more, for join requests) |
| `$creator` | The member list is found by the owner's address. Edits are applied only from members, and only if their client id is `clientIdFor($creator, salt)` with a salt the creator signed. The owner can find one person's join request with a `$creator` filter, however many junk requests there are | People tab: "Writes kept out", "Expecting someone?"; `y-arkiv blame` |
| Entity Expiration | Edits and snapshots live 30 days (or until the owner's chosen date), join requests 1 hour, versions 1 year | Lifetime tab |
| Lifetime Extension | The newest snapshot is a lease. A member renews it by extending their own snapshot or writing a fresh one, and only when the new expiry is later. A writer keeps proof of their text by extending their own edit entities for up to three years | Lifetime tab: countdown, "Keep proof of what I wrote" |
| Creation flags | Published versions are readonly and anyone can extend them (the version page has a "Keep this version alive" button; the CLI has `extend`). The member list has no permissionless extension: only the owner can extend it, so no stranger can keep member names and public keys alive. It lives 90 days from the owner's last visit, or until the owner's `keepUntil`, and the owner can delete it at any time. (The two original demo documents were created at 00:32 UTC on 18 October, before this rule landed at 03:07 UTC the same day, so they still carry the flag; both readers accept either.) Edits and snapshots are readonly (nobody, their creator included, can patch them, so an edit's block really is when it was written) without permissionless extension, so only their creator can extend them | Explorer tab, version page |
| Ownership | The owner patches the member list; only an entity's owner can delete it (Shred, Delete document) | Lifetime tab |
| WebSocket events | `watchEntityEvents` over WebSocket with no `fromBlock`; each new entity is fetched with `arkiv_getEntity`, which is not billed | Live tab latency |
| Batches | Create document (ACL and snapshot), key rotation on removal or on request (ACL patch and new snapshot), lease renewal, keep-proof extensions, shred, delete | Live tab: one transaction each |
| `atBlock` | Rebuild the document exactly as the chain held it at a past block; read the member list as it stood at each edit's block, which no later patch can change | History tab: "Rebuild from Arkiv at this block"; `y-arkiv blame` and `timeline` |

## What it costs

Measured on Tiramisu at its 1 gwei gas price ([probe](arkiv/probes/cost-2026-10-17.json), from `scripts/cost-probe.ts`): creating a document costs 0.00022 GLM, each edit 0.00012 GLM and each snapshot 0.00013 GLM. Every edit is one padded entity, so the fee does not depend on how much was typed. A writer typing without pause flushes about every three seconds, which is at most 1,200 edits, about 0.14 GLM, an hour; real sessions type in bursts and cost far less. The drip's 0.04 to 0.06 GLM covers about 400 edits. Reading costs nothing but queries. On testnet a sponsor pays; on a mainnet the same numbers would be multiplied by the gas price there, and a team running Quire for others would sponsor keys the way the drip does, or batch more typing into each edit by raising the flush interval (`flushIntervalMs`).

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
- **The relay, if you choose it:** when your network's free Arkiv queries run out, the page offers Quire's relay for that tab. It forwards only `arkiv_query` calls for Quire documents, adding our access key, so it sees exactly what the RPC operator sees: your IP address, the document id and the members' addresses in each query. It never sees text, names, keys or the link, and keeps nothing; Vercel logs each request's path, time, status and IP address. Live edits, reads by key and writes never go through it, and the header shows "via relay" while it is on.
- **The link itself:** it is the key, so whatever carries it can read the document. Email, a work chat or a cloud document would hand the key to the very providers this design avoids; send it over an end-to-end encrypted channel such as Signal, or in person. The Copy invite link button says so.
- **Shared networks:** the public RPC gives each IP address about 100 queries per window. Opening a document costs 3 or 4, so an office behind one address can open roughly 25 documents per window before it waits, uses its own access key, or opts into the relay.
- **The drip:** it sees your IP address and the new key it funds, and Vercel logs requests. On this testnet deployment it also funds every key from one sponsor address, so an observer can tell those keys were funded by Quire. Each transfer is a random amount, sent after a random wait, so neither the amount nor the exact block gives a transfer away, but the sponsor address still does. Funding from your own wallet instead links that wallet to the document key, and the app warns before it does that. A joiner can skip the drip by getting gas from the owner's key; only the owner's own key then ever asks the drip.
- **Old ciphertext:** expiry, deletion and Shred remove entities from Arkiv's state, but the transactions that wrote them, encrypted payloads included, stay in block history for good. Anyone who has the link and an archive of old blocks can decrypt what was written under keys the link opens. Removing a member rotates the key, which protects everything written afterwards. A leaked link is the one thing Quire cannot take back: start a new document.
- **The app itself:** it is JavaScript served by Vercel, so a malicious build could read the link from the fragment. The Content Security Policy only lets the page talk to itself and the Arkiv RPC, and the readers in this repository let you verify a document without our page.
- **Junk and the query budget:** anyone can write entities under a public document id. Everyday reads never fetch a stranger's, nor anything stamped with a future `qs`, and a removed member's only up to their removal block (`verify` and `blame` add three queries: one to list outside writes and one each for edits and snapshots stamped before the member list, the recreated check. Junk stamped that early can stretch the check to five pages of each kind, ten queries, and past that `verify` says it stopped). A removed member can still write new entities stamped at exactly that block. Readers fetch and refuse them while the removal is inside the read window (and an audit, which reads all of history, always), so about 4,000 of them add some nine queries to each open. Once a later snapshot moves the window past the removal, they cost nothing. A current member can do the same with snapshots of their own; the owner's answer is to remove them. Honest snapshots add up too: a writer replaces only its own latest snapshot, so co-authors who take turns compacting leave older ones to expire, about one extra query per 200 sessions on a document kept for a year.
- **Quire's own tag:** every Quire entity carries `qp = "quire1"`, so one query lists every Quire member list on the network: how many documents exist, how many members each has, and, with the sponsor's transfers, which key writes to which. The tag only saves a scan: the attribute names and the six padded sizes would single out Quire entities in any block-by-block index anyway, so dropping it would not hide this. What stays hidden is everything inside: text, names, titles, and which person holds which key.
- **Browser history:** the link sits in the address bar until the page moves the key out of the URL, so the browser's history, and anything that syncs it, may keep a copy. Open documents in a private window on a shared or synced browser.
- **Keys in the browser:** keys live in browser storage, so anyone with access to the browser profile has them. The app offers a key file, so clearing site data does not lose ownership.

## Submission evidence

Three public demo documents live on Tiramisu. Their content is synthetic, and their keys were made for this demo only.

**Open demo**: three members, readable by anyone with the link.
https://quire-five.vercel.app/#/d/cGY4Lxdu7yBatU75t4TxoyiHNJOtyVA3npCI1WcHL2c.OPYzqRUr9D1b_T_O3-7fsA0layOo0LcNOlMaphGxpSE.a7da7e4e17101ad0b4832c7cce0f87bf6e84b546

**Revocation demo**: Ravi was removed, so the key rotated. With the link alone you can open the member list, but it is sealed under the new key, so you learn only that there are two members, and nothing written after the removal. When removing Ravi, the owner also deleted their own earlier entities, so the original link no longer opens the owner's line from Arkiv's state. Bea's earlier line, encrypted under the key the link carries, stays readable to that link until it expires (30 days) or she shreds it, and block history keeps every old payload. The addresses that wrote entities are still public on chain, as for any document.
https://quire-five.vercel.app/#/d/38iji_av5iFTQ384cAD2XqqzcgABk9QtpxkDFgC-9sQ.bMlwm5r4BfQ6t00oSjyzBKvXC0BaaaTl2rTr_bYkbW8.17ef1625ee116713e75c7877bbf639297b1acffa

Addresses behind the demos:

| Address | Role |
|---|---|
| `0x7ad475ff24a9d6d06b69f460005300fa914d8e11` | gas drip sponsor; funded every key below with a plain transfer. As the development key it also created the friction probes' entities (`qp = probe-…`) and funded the live-test keys |
| `0xa7da7e4e17101ad0b4832c7cce0f87bf6e84b546` | open demo: owner (Asha); created the ACL, snapshots and edits |
| `0xd947e727fe2dbb93a1b5c966090e9463565c00a4` | open demo: writer (Bea); join request and edits |
| `0x2a776803c552eebdc8bbbcf86fe10991bdce4b8b` | open demo: writer (Ravi); join request and edits |
| `0x17ef1625ee116713e75c7877bbf639297b1acffa` | revocation demo: owner; created the ACL, rotated the key |
| `0xf7ffae901984c2c05807cbc4542080e2339ba466` | revocation demo: writer who stayed; wrote a snapshot under the new key |
| `0x8dc3011f5a1ac8dd68ab3980c072436862b11feb` | revocation demo: removed member; their join request has since expired (1 hour), its transaction remains in block history |
| `0x443ac73b7ca5af51f8171770c42324d4c3c589a9` | open demo: planted forgery. Holds the link, wrote one valid encrypted edit, is not a member, so no reader applies it (`scripts/plant-forgery.ts`) |
| `0xb83063cf00de65f09187c9600b0b3fd951f60fb0` | contested demo: owner (Asha); created the ACL, erased Bea from it, pasted the finding as her own |
| `0xa1a15fbf2c460e9aab1f92b008782d7430c44ec4` | contested demo: co-author (Bea); join request and the seven edits that wrote the finding |

Document ids: open demo `0x7066382f176eef205ab54ef9b784f1a328873493adc950379e9088d567072f67`, revocation demo `0xdfc8a38bf6afe62153437f387000f65eaab372000193d42da719031600bef6c4`, contested demo `0x0ea1a239c1785872a03a47dc05c11a9ec984772b522c11c3bf912441fe983454`. Every entity carries `qd` equal to its document id, so this query lists them all:

```
qp = str('quire1') AND qd = bytes32(0x7066382f176eef205ab54ef9b784f1a328873493adc950379e9088d567072f67)
qp = str('quire1') AND qd = bytes32(0x0ea1a239c1785872a03a47dc05c11a9ec984772b522c11c3bf912441fe983454)
```

Paste it into the [Data Explorer](https://data.arkiv.network), or look up any address above in the [block explorer](https://tiramisu.explorer.arkiv.network) to see the creating transactions.

To reproduce what the app shows, without the app (the Python lines need a clone):

```bash
npx y-arkiv verify '#/d/cGY4Lxdu7yBatU75t4TxoyiHNJOtyVA3npCI1WcHL2c.OPYzqRUr9D1b_T_O3-7fsA0layOo0LcNOlMaphGxpSE.a7da7e4e17101ad0b4832c7cce0f87bf6e84b546'
npx y-arkiv read '#/d/cGY4Lxdu7yBatU75t4TxoyiHNJOtyVA3npCI1WcHL2c.OPYzqRUr9D1b_T_O3-7fsA0layOo0LcNOlMaphGxpSE.a7da7e4e17101ad0b4832c7cce0f87bf6e84b546'
npx y-arkiv blame '#/d/cGY4Lxdu7yBatU75t4TxoyiHNJOtyVA3npCI1WcHL2c.OPYzqRUr9D1b_T_O3-7fsA0layOo0LcNOlMaphGxpSE.a7da7e4e17101ad0b4832c7cce0f87bf6e84b546'
npx y-arkiv timeline '#/d/cGY4Lxdu7yBatU75t4TxoyiHNJOtyVA3npCI1WcHL2c.OPYzqRUr9D1b_T_O3-7fsA0layOo0LcNOlMaphGxpSE.a7da7e4e17101ad0b4832c7cce0f87bf6e84b546'
python3 readers/python/quire_audit.py --doc 0x7066382f176eef205ab54ef9b784f1a328873493adc950379e9088d567072f67 --owner 0xa7da7e4e17101ad0b4832c7cce0f87bf6e84b546
```

The public endpoint gives each IP address about 100 free queries per window; if a run stops with a budget message, wait the minutes it names, set `ARKIV_ACCESS_KEY`, or add `--relay` to send queries through Quire's relay (it sees the document id and member addresses, as the RPC operator does). `quire_read.py --link '<link>' --verify` prints the Python reader's own trust report, including the same outside write.

Expected: `verify` reports the owner found by `$creator`, epoch 0, three members, 1 snapshot and 10 updates applied (the edits since the snapshot's catch-up window; `blame` and `timeline` read all of them), 0 ignored, and 3 queries, then one more query listing the planted forgery: one entity by `0x443ac73b7ca5af51f8171770c42324d4c3c589a9`, never fetched or applied. `read` prints the four lines of the Ward 14 log. `blame` proves every character, run by run: Ravi's correction sits inside Asha's paragraph and Bea's edit inside Ravi's, each with the block and entity of the edit. `timeline` lists 21 edits from three writers over three and a half minutes, a few words at a time. The demo was written by a script (`scripts/demo-docs.ts`), which is exactly why a timeline is evidence to weigh rather than proof. The audit ends with `RESULT: PASS`. For the revocation demo, `verify` reports epoch 1 with the roster sealed ("this link sees only a count (2)"), and `read` prints nothing.

The full live suite (`pnpm --dir packages/y-arkiv test:live`) passed on Tiramisu. It covers two keys collaborating, a cold reader opening the document in exactly 3 queries, a 250 KB paste written as chunks, a revocation and a published version.

## Repository

| Path | What it is |
|---|---|
| `packages/y-arkiv` | the Yjs provider, the Arkiv adapter, an in-memory chain for tests, the CLI |
| `examples/two-writers` | a second program on the package's public API: two writers, a link reader, a removal and `blame`, in one file |
| `apps/quire` | the editor (Vite, React, Tiptap) |
| `api/drip.ts` | sends a little test GLM to a new document key |
| `api/rpc.ts` | the optional query relay, used only after a visitor's free query budget runs out and they choose it |
| `readers/python` | a second implementation, written against the spec and vectors, and a standard-library privacy audit |
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
