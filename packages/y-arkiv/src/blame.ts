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
    // PROTOCOL section 5: a Yjs item merged from several ranges is proven only if its whole range is
    // covered by verified updates; otherwise all of it is claimed, as the Python reader and the editor see it
    const whole = provider.authorOfItem(it.id.client, it.id.clock, it.length)?.proven ?? false
    for (let i = 0; i < str.length; i++) {
      const clock = it.id.clock + i
      const where = whole ? provider.provenanceOf(it.id.client, clock) : undefined
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

export type EarlierWriter = {
  /** the passage as it reads now, and who proves it, from which block */
  text: string
  address: Hex
  block: bigint
  /** someone else who typed exactly these words earlier, and over which blocks */
  first: Hex
  from: bigint
  to: bigint
}

/**
 * Passages whose words a different member held first. A member can delete someone else's paragraph
 * and paste the same words back as their own edit; blame then proves the copy, correctly, as theirs.
 * This replays every applied edit (open the provider with `fullHistory`) in block order and, after
 * each block, notes which member's own contiguous text held each passage, comparing with whitespace
 * collapsed. The paste is flagged only if someone else held the words before its own author ever did,
 * so a writer who fixed a typo, wrote the sentences out of order or added a space is still found, and a
 * member who pastes a copy of someone's words and deletes it at once cannot make the real author look
 * like the copier. Only passages of 24 characters or more are checked, so short phrases do not match.
 */
export function earlierWriters(doc: Y.Doc, provider: ArkivProvider): EarlierWriter[] {
  const targets = blame(doc, provider)
    .flat()
    .filter((r) => r.proven && r.address && r.block !== undefined && norm(r.text).text.length >= 24)
  if (!targets.length) return []
  const blocks = new Map<bigint, Uint8Array[]>()
  const authorOf = new Map<number, Hex>()
  for (const h of [...provider.history].sort((x, y) => (x.block === y.block ? 0 : x.block < y.block ? -1 : 1))) {
    blocks.set(h.block, [...(blocks.get(h.block) ?? []), h.update])
    // an edit carries only its writer's own client ids (the provider refuses anything else)
    for (const st of Y.decodeUpdate(h.update).structs) authorOf.set(st.id.client, h.author)
  }
  // for each passage: the first block each member held it, and the earliest block among those characters
  const held = targets.map(() => new Map<Hex, { at: bigint; from: bigint }>())
  const keys = targets.map((r) => norm(r.text).text)
  const replay = new Y.Doc()
  for (const [block, updates] of blocks) {
    Y.transact(replay, () => updates.forEach((u) => Y.applyUpdate(replay, u)))
    for (const segment of segments(replay, authorOf)) {
      const n = norm(segment.chars.map((c) => c.ch).join(""))
      keys.forEach((key, i) => {
        if (held[i]!.has(segment.author)) return
        const at = n.text.indexOf(key)
        if (at < 0) return
        let from = block
        for (let k = at; k < at + key.length; k++) {
          const c = segment.chars[n.index[k]!]!
          const b = provider.provenanceOf(c.client, c.clock)?.block
          if (b !== undefined && b < from) from = b
        }
        held[i]!.set(segment.author, { at: block, from })
      })
    }
  }
  const out: EarlierWriter[] = []
  targets.forEach((run, i) => {
    const own = held[i]!.get(run.address!)?.at ?? run.block!
    let first: [Hex, { at: bigint; from: bigint }] | undefined
    for (const [who, h] of held[i]!) if (who !== run.address && h.at < own && (!first || h.at < first[1].at)) first = [who, h]
    if (first) out.push({ text: run.text, address: run.address!, block: run.block!, first: first[0], from: first[1].from, to: first[1].at })
  })
  return out
}

/** Text with whitespace runs collapsed to one space and trimmed, and where each kept character came from. */
function norm(s: string): { text: string; index: number[] } {
  let text = ""
  const index: number[] = []
  for (let i = 0; i < s.length; i++) {
    const space = /\s/.test(s[i]!)
    if (space && (text === "" || text.endsWith(" "))) continue
    text += space ? " " : s[i]
    index.push(i)
  }
  if (text.endsWith(" ")) {
    text = text.slice(0, -1)
    index.pop()
  }
  return { text, index }
}

type Char = { ch: string; client: number; clock: number }
/** Each paragraph's visible text cut into runs of one member's characters, in document order. */
function segments(doc: Y.Doc, authorOf: Map<number, Hex>): { author: Hex; chars: Char[] }[] {
  const paragraphs: Item[][] = []
  for (const block of doc.getXmlFragment("default").toArray()) {
    const items: Item[] = []
    collect(block, items)
    paragraphs.push(items)
  }
  const plain: Item[] = []
  walk((doc.getText("t") as unknown as { _start: Item | null })._start, plain)
  paragraphs.push(plain)
  const out: { author: Hex; chars: Char[] }[] = []
  for (const items of paragraphs) {
    let current: { author: Hex; chars: Char[] } | undefined
    for (const it of items) {
      const author = authorOf.get(it.id.client)
      if (!author) {
        current = undefined
        continue
      }
      if (!current || current.author !== author) out.push((current = { author, chars: [] }))
      for (let i = 0; i < it.content.str!.length; i++) current.chars.push({ ch: it.content.str![i]!, client: it.id.client, clock: it.id.clock + i })
    }
  }
  return out
}
