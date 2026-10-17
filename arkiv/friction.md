# Friction report

What got in our way while building Quire on Arkiv, and what worked well. Every item below happened to us during the build or was measured on purpose. Raw results are in [`arkiv/probes/`](probes), produced by [`scripts/friction-probes.ts`](../packages/y-arkiv/scripts/friction-probes.ts).

Versions for everything below unless stated: `@arkiv-network/sdk` 0.8.1, viem 2.57.7, Node 26.5, `arkiv-encryption` 0.1.0, Tiramisu (chain 7738577), public RPC `https://rpc.tiramisu.db-chain.testnet.arkiv.network`, 17 October 2026.

To rerun the probes: `QUIRE_DEV_PRIVATE_KEY=0x… pnpm --dir packages/y-arkiv exec tsx scripts/friction-probes.ts [probe names]`. Writes cost a few cents of test GLM.

## Summary

| # | Surface | Issue | Severity for us |
|---|---|---|---|
| 1 | RPC + viem | Keyless query budget runs out and the SDK waits out the Retry-After in silence | High: our demo script froze |
| 2 | SDK errors | Oversized batches and low balances both surface as "Execution error without revert data" | High: cost us an hour |
| 3 | RPC / docs | The real per-transaction payload limit is about 128 KB total, not 128 KiB per entity | Medium |
| 4 | `watchEntityEvents` | No server-side filter: every client receives every entity event on the network | Medium |
| 5 | SDK `getEntity` | Billed as a query (cost 100); the raw `arkiv_getEntity` is free but missing from the SDK's RPC types; free still counts against an undocumented 600 requests per minute | Medium |
| 6 | SDK writes | `createEntity` resolves about 3 s after the WebSocket event for the same entity | Low |
| 7 | Queries | An untyped literal compared with a typed attribute silently matches nothing | Low |
| 8 | Events | `EntityCreated` has `owner` but no `creator` | Low |
| 9 | RPC gateway | Python's default user agent gets HTTP 403 | Low |
| 10 | `arkiv-encryption` | No associated data; plaintext cap below the payload cap; key-in-URL guidance | Low |
| 11 | Docs | `atBlock` retention range is not stated | Low |
| 12 | Worked well | Extension errors, patch plus extend in one batch, plain transfers, WebSocket push, atBlock history | none |

## 1. Keyless query budget: the SDK hangs on 429 without saying so

**What happened.** Partway through creating our public demo documents, the script stopped printing anything. Ten minutes later it was still silent. A direct request explained it:

```bash
curl -s -D - -X POST https://rpc.tiramisu.db-chain.testnet.arkiv.network \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"arkiv_query","params":["qp = str('"'"'quire1'"'"')",{"limit":"0x1"}]}'
```

```
HTTP/2 429
ratelimit: limit=10000, remaining=0, reset=1086
retry-after: 1086
{"error":"ANON_COST_LIMITED","message":"unauthenticated query budget exhausted; get an API key at https://hub.arkiv.network for a monthly quota"}
```

Each `arkiv_query` costs 100 units (`arkiv-cost: 100` header), so the keyless budget is 100 queries per window. viem's HTTP transport honours `Retry-After`, so our script simply stopped: no error, no event, no log. We saw `retry-after: 1086` (18 minutes) the first time; a later saved capture shows 243 seconds, since the value is the time left in the window.

**Expected.** A thrown error (or at least a callback) naming the budget and the reset time, so an app can tell the user.

**Steps to reproduce.** Run about 100 `client.query(...)` calls from one IP without an access key, then call `client.query` again and time it. The raw 429 is saved by probe `budget429` in [probes/2026-10-17-18-28.json](probes/2026-10-17-18-28.json).

**Suggested fix.** In the SDK's default transport, turn a 429 with `ANON_COST_LIMITED` into a typed error carrying `retryAfter`, and expose the `RateLimit` and `Arkiv-Quota-Used-Percent` headers. This extends [Arkiv-Network/reported-issues#17](https://github.com/Arkiv-Network/reported-issues/issues/17) with the exact budget (10,000 units, 100 queries) and the 18-minute wait we measured.

**What we did.** `SdkStore` passes its own `fetchFn` to viem's `http()` transport. It adds an access key when one is configured and throws `QueryBudgetError` on 429 ([sdk.ts](../packages/y-arkiv/src/sdk.ts)). The editor shows that message instead of freezing. Opening a document costs three queries, and live edits cost none (see 5), so one browser rarely gets near the budget.

## 2. Two different failures, one opaque message

**What happened.** Our live test failed on a 250 KB paste with:

```
EntityMutationError: Transaction failed: Execution error without revert data
```

The cause sat five levels down the error chain: `details: 'out of gas: gas required exceeds: 2848103'`. The test key had been funded with 0.01 GLM, and the gas estimate was capped by its balance.

Separately, our batch probe failed on large batches with the **same** top-level message. That time the cause in the chain was the RPC answering `"BAD_REQUEST"` (see 3).

**Expected.** The top-level message says "insufficient balance for gas" or "request too large", which is what actually happened.

**Steps to reproduce.**
- Fund a fresh key with 0.0005 GLM and call `createEntity` with a 100,000-byte payload. Probe `lowBalanceError` ([probes/2026-10-17-18-28.json](probes/2026-10-17-18-28.json)) got the top-level "Execution error without revert data", with the cause "out of gas: gas required exceeds: 499999" only in the error chain.
- Or call `executeBatch` with five creates of 26,000 bytes each.
- In both cases print `error.message`, then walk `error.cause` and print each `details`.

Probe `batchBoundary`, result in [probes/2026-10-17-18-00.json](probes).

**Suggested fix.** In `EntityMutationError`, surface the deepest `details` from the viem error chain, and check the sender's balance against `gas × gasPrice` before sending.

## 3. The payload limit that matters is per transaction, about 128 KB

The docs say an entity payload can be up to 128 KiB (131,072 bytes). What we measured on the public RPC:

| Probe | Payload | Result |
|---|---|---|
| `payloadLimit` | one entity, 128,000 B | lands |
| `payloadLimit` | one entity, 131,072 B | "Execution error without revert data" |
| `batchBodyLimit` | 4 creates × 30,000 B (120,000 total) | lands |
| `batchBoundary` | 5 creates, 130,000 B total | RPC: `BAD_REQUEST` |
| `batchBodyLimit` | 6 creates × 30,000 B (180,000 total) | fails |

Payloads travel hex-encoded inside the transaction, and the RPC gateway refuses large requests. Probe `requestBodyLimit` measured it directly with padded JSON-RPC bodies: 255 KiB returns 200 and 257 KiB returns HTTP 413. So the limit is 256 KiB per request, it applies to the whole transaction rather than each entity, and it caps a transaction's payloads at a little under 128 KB.

**Expected.** Docs that state the per-transaction limit, and an error that names it.

**Suggested fix.** Document "total payload per transaction ≤ about 128 KB on the public RPC" next to the per-entity limit. Ideally the SDK splits or rejects an oversized `executeBatch` before sending.

**What we did.** Snapshots larger than one entity are written as chunk entities in transactions of at most 100,000 payload bytes, followed by the head that lists them ([provider.ts `writeSnapshotEntities`](../packages/y-arkiv/src/provider.ts)). Our in-memory test chain enforces the same limit, so tests catch an oversized batch before Tiramisu does.

## 4. `watchEntityEvents` has no filter

**What happened.** Quire needs to hear about new entities in one document. `watchEntityEvents` takes no owner, creator or attribute filter, so every client receives every entity event on the network. Over WebSocket with no `fromBlock` it is a single `eth_subscribe`, which is good, but the stream is the whole chain.

**Measured** with `scripts/firehose-probe.ts`, two runs of 60 seconds (30 blocks each) on 17 October:

| Run (UTC) | EntityCreated | EntityDeleted | ExpiryExtended | OwnershipTransferred | Distinct owners |
|---|---|---|---|---|---|
| 15:5x | 44 | 13 | 3 | 1 | 8 |
| 18:30 ([saved](probes/firehose-2026-10-17-18-30.json)) | 47 | 15 | 2 | 0 | 5 |

That is fine today, but it grows linearly with the network. A client also has to fetch an entity just to learn it was not for them.

**Expected.** A filter, for example `watchEntityEvents({ owners: [...], onEntityCreated })`, matched on the indexed `owner` topic server-side.

**Suggested fix.** Accept `owner` (and ideally attribute equality) filters and pass the owner as a log topic filter in the subscription.

**What we did.** We drop events whose `owner` is not in the document's member list before fetching anything. The owner's session, which needs to see join requests from strangers, fetches non-member entities at a capped 240 per minute and also re-reads join requests on every resync ([provider.ts `allowStrangerFetch`](../packages/y-arkiv/src/provider.ts)).

## 5. `getEntity` is billed as a query; the free method is missing from the SDK types

**Measured** (probe `costHeaders`):

| Method | `arkiv-cost` header |
|---|---|
| `arkiv_query` | 100 |
| `arkiv_getEntity` | none |
| `arkiv_getEntityCount` | none |
| `eth_blockNumber` | none |

The SDK's `client.getEntity(key)` is documented in its own JSDoc as using `arkiv_query`, so each call costs 100 units, while `arkiv_getEntity` returns the same entity at no cost. `arkiv_getEntity` is also not in the SDK's `ArkivRpcSchema`, so calling it needs a type cast: `client.request({ method: "arkiv_getEntity", params: [key] } as never)`.

**Expected.** `getEntity` uses the cheapest method, and every documented RPC method is typed.

**Suggested fix.** Route `getEntity` through `arkiv_getEntity`, and add `arkiv_getEntity(key, block?)` to `ArkivRpcSchema`. This is related to [reported-issues#18](https://github.com/Arkiv-Network/reported-issues/issues/18), with the cost headers measured.

**What we did.** Every live edit is fetched with raw `arkiv_getEntity`, so live collaboration costs no query budget at all ([sdk.ts `get`](../packages/y-arkiv/src/sdk.ts)).

**Free is not unlimited.** Every response in the same probe, `arkiv_getEntity` included, carries a second header: `ratelimit: limit=600, remaining=588, reset=57`. That is a request-rate limit per minute, separate from the cost budget, and the docs do not mention it. We stay under it by design: an owner's session fetches at most 240 entities per minute from addresses outside the member list (the cap that stops a flood of junk join requests), and a writer typing without pause flushes every two to four seconds, about 20 edits a minute. The docs should state both limits and say which one a 429 refers to.

## 6. `createEntity` resolves seconds after the chain announced the entity

**Measured** (probe `wsLatency`, three runs):

| Run | Send to WebSocket event | Send to `createEntity` resolving |
|---|---|---|
| 1 | 3,894 ms | 4,009 ms |
| 2 | 3,855 ms | 6,729 ms |
| 3 | 3,121 ms | 6,706 ms |

The SDK waits for the receipt by polling, so it resolves up to 3.6 seconds after the entity is already live and pushed to subscribers.

**Expected.** Resolution within about one block of the event.

**Suggested fix.** Expose `pollingInterval` for receipt waits, or wait on the WebSocket client when one is available.

**What we did.** Quire never waits on its own writes to update the screen. Local edits show instantly, and other members see them about one block after they land. Our echo handling dedupes by entity key, because the event usually arrives before the write call returns.

## 7. Untyped literal against a typed attribute: silent empty result

**Measured** (probe `untypedPredicate`): entities with `qs = u64(7)` exist. The raw query `qp = str('<tag>') AND qs = 7` returns `data: []`, with no error. The same query with `qs = u64(7)` matches.

**Expected.** An error saying the types differ, as the SDK's typed builder implies.

**Suggested fix.** Reject comparisons between mismatched types in the node, or coerce integer literals. This is related to [arkiv-sdk-js#113](https://github.com/Arkiv-Network/arkiv-sdk-js/issues/113).

**What we did.** Every predicate is built with typed helpers (`str`, `bytes32`, `u64`, `addr`), and the exact query strings are in PROTOCOL.md so other implementations type them too.

## 8. `EntityCreated` carries `owner`, not `creator`

**Measured** (probe `eventFields`): the event has `type, blockNumber, transactionHash, logIndex, entityKey, owner, expiresAt, creationFlags`.

**Expected.** The creator, which is what readers trust, available on the creation event.

Quire trusts `$creator`, not `$owner`. At creation the two are equal, so we use `owner` from the event as the creator for a cheap pre-filter, then confirm with `creator` from `arkiv_getEntity`. That equality is not written down anywhere.

**Suggested fix.** Add `creator` to `EntityCreatedEvent`, or document that `owner == creator` at creation.

## 9. Python's default user agent gets 403

**Measured:**

```bash
curl -s -o /dev/null -w "%{http_code}\n" -A "Python-urllib/3.15" -X POST https://rpc.tiramisu.db-chain.testnet.arkiv.network -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'
```

This returns `403`. The same request with curl's or node's user agent returns `200`.

**Expected.** The same answer for any client; JSON-RPC is used from every language.

Our independent Python reader hit this on its first run. It now sends its own `User-Agent` ([readers/python](../readers/python)).

**Suggested fix.** Allow standard library user agents, or say in the JSON-RPC docs that a custom user agent is required.

## 10. `arkiv-encryption` 0.1.0

We used it for every payload, and it did exactly what it says. Three gaps came up:

- **No associated data.** `encryptPayload(key, plaintext)` takes no additional data, so a ciphertext copied from one document or entity kind into another still decrypts. We repeat the document id, kind and epoch inside the plaintext frame and check them after decrypting ([codec.ts](../packages/y-arkiv/src/codec.ts)). *Suggested fix:* an optional `additionalData` parameter passed to WebCrypto's AES-GCM.
- **Plaintext cap below the payload cap.** *Measured:* `encryptPayload` on 100,000 bytes returns a 100,028-byte envelope; on 100,001 bytes it throws `EncryptionError: Expected Uint8Array with at most 100000 bytes.` An entity can carry about 128 KB, so the envelope cap, not the chain, is what limits a single payload. *Expected:* the cap stated in the Arkiv docs next to the entity size limit (it is only in the package's `MAX_PLAINTEXT_BYTES`). *Steps:* `const key = await importKey(crypto.getRandomValues(new Uint8Array(32)))`, then `encryptPayload(key, new Uint8Array(100_001))`. *Suggested fix:* document `MAX_PLAINTEXT_BYTES` in the encryption guide, with the 28 bytes of envelope overhead. *What we did:* our largest padding bucket is 98,304 bytes, and anything bigger is split into chunks.
- **"Never put the key in a URL."** The package's type docs say so ("Back it up privately; never put it in an entity or URL", `dist/index.d.ts`) and its AGENTS.md repeats it. For a link-sharing app the URL fragment is the standard place, because browsers do not send it to the server: a request for `/#/d/<secret>` reaches the server as `/`. *Expected:* guidance that separates the fragment from the path and query string. *Suggested fix:* a short note on fragments as the exception, and on removing them from the address bar after reading. *What we did:* the key lives only in the fragment, and the app replaces it with `#/doc/<id>` as soon as it has read it ([App.tsx](../apps/quire/src/App.tsx)).

## 11. `atBlock` retention is not documented

The docs say `atBlock` must be "within the node's retained range" without giving the range.

**Expected.** A stated retention window, so an app can promise its users how far back history goes.

**Measured** (probe `atBlockRetentionOld`, head 705,036): queries at blocks 704,936, 695,036, 605,036, 305,036 and 1,000 all succeeded and returned data. The probe did not check that each answer matched the state at that height, so this shows the node accepts heights back to the start of the chain, not that its state there is complete.

Quire's History tab rebuilds a document as of any past block with `atBlock` reads, so this matters to us.

**Suggested fix.** State the retention policy, and say whether it will shrink on mainnet.

## Paths we tested that worked well

| What | Expected | What happened | Probe |
|---|---|---|---|
| Extending to an earlier expiry | a clear refusal | "entity 0x182f…0ba472 already expires at block 791378, so extending it to 748179 would shorten its life". This is a model error message | `extensionRules` |
| Patch and extend the same entity in one `executeBatch` | allowed or refused clearly | allowed: new payload and new expiry both applied | `patchAndExtendSameEntity` |
| ACL patch plus snapshot create in one batch | atomic | atomic; our key rotation depends on it | live test |
| Plain value transfer to fund a fresh key | works | 21,000 gas, success | `burnerFunding` |
| `watchEntityEvents` over WebSocket with no `fromBlock` | push, no polling | push; events arrived 3.1 to 3.9 s after sending | `wsLatency` |
| Cursor paging pinned with `atBlock` | stable pages while the head moves | stable | `store.ts queryAll` |
| End-to-end collaboration on Tiramisu | two keys edit, a cold reader rebuilds | passed in 154 s, including a 250 KB chunked paste, a revocation and a published version | `test/live.test.ts` |

## One thing to fix first

A server-side filter for `watchEntityEvents` (item 4). Every real-time app on Arkiv pays for the whole network's event stream today, and that cost grows with every new project on the chain.
