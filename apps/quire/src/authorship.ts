/**
 * Blame by wallet: a colored bar beside each paragraph, one color per address
 * that wrote text still visible in it.
 *
 * The mapping from a Yjs client id to an address comes from the provider. It
 * is "proven" when we applied that client's update from an entity whose
 * on-chain `$creator` is the address, and "claimed" when it only arrived in a
 * snapshot header. Claimed authors get a dashed bar.
 */
import { Extension } from "@tiptap/react"
import { Plugin, PluginKey } from "@tiptap/pm/state"
import { Decoration, DecorationSet } from "@tiptap/pm/view"
import * as Y from "yjs"
import type { ArkivProvider, Authorship } from "y-arkiv"

/** Members get distinct colors from this palette, in member-list order, so two writers never look alike. */
const PALETTE = ["#E8743B", "#2F7DE1", "#7B5CD6", "#1F9D6B", "#D6455D", "#C9A227", "#1AA3B8", "#8C6D46"]
const assigned = new Map<string, string>()

export function setMembers(addresses: string[]): void {
  assigned.clear()
  addresses.forEach((a, i) => assigned.set(a.toLowerCase(), PALETTE[i % PALETTE.length]!))
}

/** Palette color for a member; for anyone else a stable hash color (FNV-1a, then the golden angle). */
export function colorOf(address: string): string {
  const known = assigned.get(address.toLowerCase())
  if (known) return known
  let h = 0x811c9dc5
  for (let i = 2; i < address.length; i++) {
    h ^= address.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  const hue = Math.round(((h % 1000) * 137.508) % 360)
  return `hsl(${hue} 64% 50%)`
}

type Item = { deleted: boolean; countable: boolean; length: number; id: { client: number; clock: number }; right: Item | null }

/** Every visible text item under a node, with its clock range: provenance is per range, not per client. */
function collectItems(node: Y.XmlElement | Y.XmlText | Y.XmlHook, into: Item[]): void {
  if (node instanceof Y.XmlText) {
    let item = (node as unknown as { _start: Item | null })._start
    while (item) {
      if (!item.deleted && item.countable) into.push(item)
      item = item.right
    }
  } else if (node instanceof Y.XmlElement) {
    for (const child of node.toArray()) collectItems(child, into)
  }
}

/** Authors of each top-level block, in document order. */
export function blockAuthors(doc: Y.Doc, provider: ArkivProvider | null): Authorship[][] {
  const fragment = doc.getXmlFragment("default")
  return fragment.toArray().map((block) => {
    const items: Item[] = []
    collectItems(block as Y.XmlElement, items)
    // one entry per address; it stays proven only if every item it wrote here is proven
    const seen = new Map<string, Authorship>()
    for (const it of items) {
      const a = provider?.authorOfItem(it.id.client, it.id.clock, it.length)
      if (!a) continue
      const prev = seen.get(a.address)
      if (!prev) seen.set(a.address, a)
      else if (prev.proven && !a.proven) seen.set(a.address, a)
    }
    return [...seen.values()]
  })
}

const key = new PluginKey("quire-authorship")

export const AuthorshipBars = Extension.create<{ doc: Y.Doc; provider: () => ArkivProvider | null; enabled: () => boolean }>({
  name: "authorshipBars",
  addOptions() {
    return { doc: new Y.Doc(), provider: () => null, enabled: () => false }
  },
  addProseMirrorPlugins() {
    const { doc, provider, enabled } = this.options
    return [
      new Plugin({
        key,
        props: {
          decorations(state) {
            if (!enabled()) return DecorationSet.empty
            const authors = blockAuthors(doc, provider())
            const decos: Decoration[] = []
            state.doc.forEach((node, offset, index) => {
              const list = authors[index] ?? []
              if (!list.length) return
              const stops = list.map((a, i) => `${colorOf(a.address)} ${(i / list.length) * 100}% ${((i + 1) / list.length) * 100}%`)
              decos.push(
                Decoration.node(offset, offset + node.nodeSize, {
                  class: list.some((a) => !a.proven) ? "authored claimed" : "authored",
                  style: `--author-bar: linear-gradient(to bottom, ${stops.join(", ")})`,
                  title: list.map((a) => `${a.address}${a.proven ? " (checked live)" : ` (claimed in a snapshot by ${a.via ?? "a member"})`}`).join("\n"),
                }),
              )
            })
            return DecorationSet.create(state.doc, decos)
          },
        },
      }),
    ]
  },
})
