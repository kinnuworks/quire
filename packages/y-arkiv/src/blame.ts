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
  /** the passage as it reads now, its writer, and the block that writer finished it */
  text: string
  address: Hex
  block: bigint
  /** someone else who typed the same words (within the threshold) earlier, and over which blocks */
  first: Hex
  from: bigint
  to: bigint
}

/**
 * Passages whose words a different member typed first. A member can delete someone else's paragraph
 * and paste or re-type the same words as their own edits; blame then proves the copy, correctly, as
 * theirs. This replays every applied edit (open the provider with `fullHistory`) once, keeping deleted
 * characters, so each member's text can be read in document order as they typed it, deletions and
 * all, with every word dated by the block its characters arrived in.
 *
 * Each passage someone holds now (their whole run of text in a paragraph, each single edit inside it,
 * and each sentence) is compared word by word with every member's typed text. Characters that draw
 * nothing are dropped, compatibility forms and case are folded, Cyrillic and Greek look-alikes become
 * Latin, and whitespace only separates words. A passage of n words matches a stretch of someone's text
 * if at most n/6 words differ (inserted, dropped or changed), and a match is dated by its newest word.
 * The passage is flagged only if another member's match is older than the passage itself (dated by
 * its words less the n/6 newest), and that other member's stretch is not itself a copy of what the
 * writer had typed before it existed. Passages under 24 characters are skipped, and
 * passages over 80 words are checked in 40-word windows.
 *
 * This is a pointer, not a verdict: it compares text, and text can be reworded past any threshold.
 * What proves authorship is blame at a block, which checks every edit's key against the member list.
 */
export function earlierWriters(doc: Y.Doc, provider: ArkivProvider): EarlierWriter[] {
  void doc
  const history = [...provider.history].sort((x, y) => (x.block === y.block ? 0 : x.block < y.block ? -1 : 1))
  if (!history.length) return []
  const authorOf = new Map<number, Hex>()
  const proof = new Map<number, [number, number, number, Hex][]>()
  const decoded = history.map((h) => Y.decodeUpdate(h.update))
  history.forEach((h, n) => {
    // an edit carries only its writer's own client ids (the provider refuses anything else)
    for (const st of decoded[n]!.structs) {
      if (st instanceof Y.Skip || st instanceof Y.GC) continue
      authorOf.set(st.id.client, h.author)
      const list = proof.get(st.id.client) ?? []
      list.push([st.id.clock, st.id.clock + st.length, Number(h.block), h.entity])
      proof.set(st.id.client, list)
    }
  })
  // characters their own writer deleted: a writer's typo fixes are not part of what they typed
  const selfDeleted = new Map<number, [number, number][]>()
  history.forEach((h, n) => {
    for (const [client, ranges] of decoded[n]!.ds.clients) {
      if (authorOf.get(client) !== h.author) continue
      const list = selfDeleted.get(client) ?? []
      for (const r of ranges) list.push([r.clock, r.clock + r.len])
      selfDeleted.set(client, list)
    }
  })
  for (const list of proof.values()) list.sort((x, y) => x[0] - y[0])
  const proofOf = (client: number, clock: number) => {
    const list = proof.get(client)
    if (!list) return undefined
    let lo = 0
    let hi = list.length - 1
    while (lo <= hi) {
      const mid = (lo + hi) >> 1
      const r = list[mid]!
      if (clock < r[0]) hi = mid - 1
      else if (clock >= r[1]) lo = mid + 1
      else return r
    }
    return undefined
  }
  const replay = new Y.Doc({ gc: false })
  for (const h of history) Y.applyUpdate(replay, h.update)

  // every text node's characters in document order, deleted ones included
  const nodes: TypedChar[][] = []
  const visit = (start: Item | null) => {
    const chars: TypedChar[] = []
    for (let item = start; item; item = item.right) {
      const content = item.content as { str?: string; type?: unknown }
      if (typeof content.str === "string") {
        // by code point, as the Python reader walks text; clocks still count UTF-16 units
        let i = 0
        for (const ch of content.str) {
          const clock = item.id.clock + i
          i += ch.length
          const p = proofOf(item.id.client, clock)
          const author = authorOf.get(item.id.client)
          chars.push({
            ch,
            author,
            block: p?.[2] ?? Infinity,
            entity: p?.[3],
            deleted: item.deleted,
            self: !!author && (selfDeleted.get(item.id.client) ?? []).some(([a, b]) => a <= clock && clock < b),
          })
        }
      } else if (content.type) {
        const type = content.type as { _start: Item | null }
        if (content.type instanceof Y.XmlText) nodes.push(visit(type._start))
        else visit(type._start)
      }
    }
    return chars
  }
  visit((replay.getXmlFragment("default") as unknown as { _start: Item | null })._start)
  nodes.push(visit((replay.getText("t") as unknown as { _start: Item | null })._start))

  // each member's typed text, all of it and without their own deletions, one stream per member
  const streams = new Map<Hex, { all: Word[]; kept: Word[] }>()
  for (const chars of nodes) {
    const authors = new Set(chars.map((c) => c.author).filter((a): a is Hex => !!a))
    for (const a of authors) {
      const s = streams.get(a) ?? { all: [], kept: [] }
      if (s.all.length) s.all.push(BARRIER)
      if (s.kept.length) s.kept.push(BARRIER)
      s.all.push(...words(chars.filter((c) => c.author === a)))
      s.kept.push(...words(chars.filter((c) => c.author === a && !c.self)))
      streams.set(a, s)
    }
  }
  const earliest = (p: string[], s: { all: Word[]; kept: Word[] } | undefined, k: number) => {
    if (!s) return undefined
    const x = match(p, s.all, k)
    const y = match(p, s.kept, k)
    return !x ? y : !y ? x : y.t < x.t || (y.t === x.t && y.f < x.f) ? y : x
  }

  // a member's typed text from before block `t` only
  const typedBefore = (who: Hex, t: number): Word[] => {
    const out: Word[] = []
    for (const chars of nodes) {
      const ws = words(chars.filter((c) => c.author === who && c.block < t))
      if (!ws.length) continue
      if (out.length) out.push(BARRIER)
      out.push(...ws)
    }
    return out
  }

  const out: EarlierWriter[] = []
  for (const chars of nodes) {
    // the passages each member holds now: runs of one member's visible characters
    const runs: { author: Hex; chars: TypedChar[] }[] = []
    let current: { author: Hex; chars: TypedChar[] } | undefined
    for (const c of chars) {
      if (c.deleted || INVISIBLE.test(c.ch)) continue
      if (!c.author) current = undefined
      else if (current?.author === c.author) current.chars.push(c)
      else runs.push((current = { author: c.author, chars: [c] }))
    }
    for (const run of runs) {
      const ws = words(run.chars)
      const flagged: { i: number; j: number; first: Hex; t: number; f: number }[] = []
      for (const [i, j] of passages(ws)) {
        const p = ws.slice(i, j).map((w) => w.w)
        const k = Math.floor(p.length / 6)
        let best: { who: Hex; t: number; f: number; q: string[] } | undefined
        for (const [who, s] of [...streams].sort((x, y) => (x[0] < y[0] ? -1 : 1))) {
          if (who === run.author) continue
          const m = earliest(p, s, k)
          if (m && (!best || m.t < best.t)) best = { who, ...m }
        }
        if (!best) continue
        // the other member's words may themselves be a copy of this writer's earlier text (a suggested
        // rewording of her sentence, or a paste of it): read her text as she had typed it before their
        // words existed, deleted characters included, and if it holds their words she had them first
        if (match(best.q, typedBefore(run.author, best.t), Math.floor(best.q.length / 6))) continue
        // the writer's own passage dates from its words less the k newest
        const own = ws.slice(i, j).map((w) => w.t).sort((x, y) => y - x)[k]!
        if (best.t < own) flagged.push({ i, j, first: best.who, t: best.t, f: best.f })
      }
      // report each flagged stretch once: overlapping passages (a run, its sentences, its windows) that
      // name the same earlier writer merge into one
      const kept: typeof flagged = []
      for (const f of [...flagged].sort((x, y) => x.i - y.i || y.j - x.j)) {
        const last = kept[kept.length - 1]
        if (last && last.first === f.first && f.i < last.j) {
          last.j = Math.max(last.j, f.j)
          last.t = Math.max(last.t, f.t)
          last.f = Math.min(last.f, f.f)
        } else kept.push({ ...f })
      }
      for (const f of kept) {
        const span = run.chars.slice(ws[f.i]!.a, ws[f.j - 1]!.b)
        out.push({
          text: span.map((c) => c.ch).join(""),
          address: run.author,
          block: BigInt(Math.max(...span.map((c) => c.block))),
          first: f.first,
          from: BigInt(f.f),
          to: BigInt(f.t),
        })
      }
    }
  }
  return out
}

type TypedChar = { ch: string; author: Hex | undefined; block: number; entity: Hex | undefined; deleted: boolean; self: boolean }
/** A word: its text, the newest and oldest block among its characters, where it sits, and whether a sentence ends after it. */
type Word = { w: string; t: number; f: number; a: number; b: number; end: boolean; entity: Hex | undefined | null }

/**
 * Characters that draw nothing: format characters (zero-width spaces, joiners, direction marks, tags),
 * variation selectors, the combining grapheme joiner and the Hangul and Mongolian fillers.
 */
const INVISIBLE = /[\p{Cf}\u034F\u115F\u1160\u17B4\u17B5\u180B-\u180F\u3164\uFE00-\uFE0F\uFFA0\u{E0100}-\u{E01EF}]/u
/** Cyrillic and Greek letters that look like Latin ones, folded to them before words are compared. */
const LOOKALIKE: Record<string, string> = { а: "a", в: "b", е: "e", к: "k", м: "m", н: "h", о: "o", р: "p", с: "c", т: "t", у: "y", х: "x", і: "i", ј: "j", ѕ: "s", ԁ: "d", һ: "h", ӏ: "l", α: "a", β: "b", ε: "e", ι: "i", κ: "k", ν: "v", ο: "o", ρ: "p", τ: "t", υ: "u", χ: "x" }
/** A word as it is compared: compatibility forms folded (NFKC), lower case, look-alike letters folded. */
export function foldWord(w: string): string {
  return [...w.normalize("NFKC").toLowerCase()].map((c) => LOOKALIKE[c] ?? c).join("")
}
const SPACE = /[\s\x1c-\x1f\x85]/u
/** Stands between two text nodes in a stream; never matches and is never older than anything. */
const BARRIER: Word = { w: "\u0000", t: Infinity, f: Infinity, a: 0, b: 0, end: true, entity: null }

/** Characters cut into words at whitespace, with invisible characters dropped. */
function words(chars: TypedChar[]): Word[] {
  const out: Word[] = []
  let w: Word | undefined
  chars.forEach((c, n) => {
    if (INVISIBLE.test(c.ch)) return
    if (SPACE.test(c.ch)) {
      if (w && c.ch === "\n") w.end = true
      w = undefined
      return
    }
    if (!w) out.push((w = { w: "", t: -Infinity, f: Infinity, a: n, b: n, end: false, entity: c.entity }))
    w.w += c.ch
    w.t = Math.max(w.t, c.block)
    w.f = Math.min(w.f, c.block)
    w.b = n + 1
    if (w.entity !== c.entity) w.entity = null
  })
  for (const x of out) {
    if (/[.!?]["')\]]*$/.test(x.w)) x.end = true
    x.w = foldWord(x.w)
  }
  return out
}

/** The passages of a run to check, as word ranges: the whole run, each single edit's words, and each sentence. */
function passages(ws: Word[]): [number, number][] {
  const out = new Map<string, [number, number]>()
  const add = (i: number, j: number) => {
    if (j <= i) return
    // a long passage is also checked in 40-word windows, 20 words apart
    if (j - i > 80) {
      for (let a = i; a < j; a += 20) add(a, Math.min(a + 40, j))
      return
    }
    let chars = j - i - 1
    for (let n = i; n < j; n++) chars += ws[n]!.w.length
    if (chars >= 24) out.set(`${i}:${j}`, [i, j])
  }
  add(0, ws.length)
  for (let i = 0, n = 0; n < ws.length; n++) {
    if (ws[n]!.end || n === ws.length - 1) {
      add(i, n + 1)
      i = n + 1
    }
  }
  for (let i = 0, n = 1; n <= ws.length; n++) {
    if (n === ws.length || !ws[n]!.entity || ws[n]!.entity !== ws[i]!.entity) {
      if (ws[i]!.entity) add(i, n)
      i = n
    }
  }
  return [...out.values()].sort((x, y) => x[0] - y[0] || x[1] - y[1])
}

/**
 * The oldest stretch of `s` within k word edits of `p` (insert, drop or change a word), dated by its
 * newest word (t) and its oldest (f). Stretches that share too few words with `p` are skipped before
 * the edit distance is worked out.
 */
function match(p: string[], s: Word[], k: number): { t: number; f: number; q: string[] } | undefined {
  const n = p.length
  if (s.length < n - k) return undefined
  const want = new Map<string, number>()
  for (const w of p) want.set(w, (want.get(w) ?? 0) + 1)
  const width = Math.min(n + k, s.length)
  const have = new Map<string, number>()
  let common = 0
  const add = (w: string, d: number) => {
    const c = want.get(w)
    if (c === undefined) return
    const h = have.get(w) ?? 0
    if (d > 0 && h < c) common++
    if (d < 0 && h <= c) common--
    have.set(w, h + d)
  }
  const slices: [number, number][] = []
  for (let a = 0; a < width; a++) add(s[a]!.w, 1)
  for (let a = 0; a + width <= s.length; a++) {
    if (a > 0) {
      add(s[a - 1]!.w, -1)
      add(s[a + width - 1]!.w, 1)
    }
    if (common < n - k) continue
    const last = slices[slices.length - 1]
    if (last && a <= last[1]) last[1] = a + width
    else slices.push([a, a + width])
  }
  let best: { t: number; f: number; q: string[] } | undefined
  for (const [lo, hi] of slices) {
    const m = align(p, s.slice(lo, hi), k)
    if (m && (!best || m.t < best.t || (m.t === best.t && m.f < best.f))) best = m
  }
  return best
}

/** Semi-global word alignment: the stretch of `s` within k edits of all of `p` whose newest word is oldest. */
function align(p: string[], s: Word[], k: number): { t: number; f: number; q: string[] } | undefined {
  const n = p.length
  const L = s.length
  // value: the newest block among the words of s used so far; start: where in s the stretch began
  let prevV = Array.from({ length: k + 1 }, () => new Float64Array(L + 1).fill(-Infinity))
  let prevS = Array.from({ length: k + 1 }, () => Int32Array.from({ length: L + 1 }, (_, j) => j))
  for (let i = 1; i <= n; i++) {
    const curV = Array.from({ length: k + 1 }, () => new Float64Array(L + 1).fill(Infinity))
    const curS = Array.from({ length: k + 1 }, () => new Int32Array(L + 1).fill(-1))
    for (let d = 0; d <= k; d++) {
      for (let j = 0; j <= L; j++) {
        let v = Infinity
        let st = -1
        const take = (cv: number, cs: number) => {
          if (cv < v || (cv === v && cs > st)) {
            v = cv
            st = cs
          }
        }
        const t = j > 0 ? s[j - 1]!.t : 0
        if (j > 0 && s[j - 1]!.w === p[i - 1]) take(Math.max(prevV[d]![j - 1]!, t), prevS[d]![j - 1]!)
        if (d > 0) {
          take(curV[d - 1]![j]!, curS[d - 1]![j]!)
          take(prevV[d - 1]![j]!, prevS[d - 1]![j]!)
          if (j > 0) {
            take(Math.max(prevV[d - 1]![j - 1]!, t), prevS[d - 1]![j - 1]!)
            take(Math.max(curV[d - 1]![j - 1]!, t), curS[d - 1]![j - 1]!)
          }
        }
        curV[d]![j] = v
        curS[d]![j] = st
      }
    }
    prevV = curV
    prevS = curS
  }
  let best: { t: number; f: number; q: string[] } | undefined
  for (let j = 0; j <= L; j++) {
    const t = prevV[k]![j]!
    if (t === Infinity || t === -Infinity) continue
    const a = prevS[k]![j]!
    let f = Infinity
    for (let x = a; x < j; x++) f = Math.min(f, s[x]!.f)
    if (!best || t < best.t || (t === best.t && f < best.f)) best = { t, f, q: s.slice(a, j).map((w) => w.w) }
  }
  return best
}
