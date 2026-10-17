/**
 * Blame from the chain: every visible run of text with the address that wrote
 * it. A run is proven when its clocks arrived in an update entity whose
 * `$creator` is that address (the run names the entity and its block), and
 * claimed when only a snapshot carried it (the run names the snapshot's
 * creator). Open the provider with `fullHistory: true` so every edit still on
 * chain counts.
 */
import * as Y from "yjs"
import type { ArkivProvider } from "./provider.js"
import type { Hex } from "./store.js"

export type BlameRun = {
  text: string
  address: Hex | null
  proven: boolean
  /** proven runs: the update entity and its block */
  entity?: Hex
  block?: bigint
  /** claimed runs: whose snapshot carried the text */
  via?: Hex
}

type Item = {
  deleted: boolean
  countable: boolean
  length: number
  id: { client: number; clock: number }
  content: { str?: string }
  right: Item | null
}

/** One list of runs per paragraph (top-level block), in document order; plain `t` text comes last. */
export function blame(doc: Y.Doc, provider: ArkivProvider): BlameRun[][] {
  const out: BlameRun[][] = []
  for (const block of doc.getXmlFragment("default").toArray()) {
    const items: Item[] = []
    collect(block, items)
    out.push(runs(items, provider))
  }
  const plain: Item[] = []
  walk((doc.getText("t") as unknown as { _start: Item | null })._start, plain)
  if (plain.length) out.push(runs(plain, provider))
  return out.filter((r) => r.length)
}

function collect(node: unknown, into: Item[]): void {
  if (node instanceof Y.XmlText) walk((node as unknown as { _start: Item | null })._start, into)
  else if (node instanceof Y.XmlElement) for (const child of node.toArray()) collect(child, into)
}

function walk(start: Item | null, into: Item[]): void {
  for (let item = start; item; item = item.right) if (!item.deleted && item.countable && typeof item.content.str === "string") into.push(item)
}

/** Splits items clock by clock, since Yjs merges adjacent edits from one client even when two entities wrote them. */
function runs(items: Item[], provider: ArkivProvider): BlameRun[] {
  const out: BlameRun[] = []
  for (const it of items) {
    const str = it.content.str!
    for (let i = 0; i < str.length; i++) {
      const clock = it.id.clock + i
      const where = provider.provenanceOf(it.id.client, clock)
      const who = provider.authorOfItem(it.id.client, clock)
      const run: BlameRun = where
        ? { text: str[i]!, address: who?.address ?? null, proven: true, entity: where.entity, block: where.block }
        : { text: str[i]!, address: who?.address ?? null, proven: false, via: who?.via ?? provider.carrierOf(it.id.client, clock) }
      const last = out[out.length - 1]
      if (last && last.address === run.address && last.proven === run.proven && last.entity === run.entity && last.via === run.via) last.text += run.text
      else out.push(run)
    }
  }
  return out
}

export type TimelineEntry = { block: bigint; author: Hex; entity: Hex; added: number; removed: number }

/**
 * How the text grew: every verified edit the provider applied, in block order, with how many
 * characters it added and removed. With `fullHistory` that is every edit still on chain. A long run
 * of small edits over hours is what a person typing looks like; one large edit is a paste. Edits are
 * flushed every two to four seconds, so the timeline shows rhythm at that grain, not keystrokes.
 */
export function compositionTimeline(provider: ArkivProvider): TimelineEntry[] {
  return [...provider.history]
    .sort((a, b) => (a.block === b.block ? 0 : a.block < b.block ? -1 : 1))
    .map((h) => {
      const u = Y.decodeUpdate(h.update)
      let added = 0
      for (const st of u.structs) if (st instanceof Y.Item && st.content instanceof Y.ContentString) added += st.length
      let removed = 0
      for (const ranges of u.ds.clients.values()) for (const r of ranges) removed += r.len
      return { block: h.block, author: h.author, entity: h.entity, added, removed }
    })
}
