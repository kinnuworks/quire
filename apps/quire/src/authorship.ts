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

export function colorOf(address: string): string {
  let h = 0
  for (let i = 2; i < address.length; i++) h = (h * 31 + address.charCodeAt(i)) >>> 0
  return `hsl(${h % 360} 62% 52%)`
}

type Item = { deleted: boolean; countable: boolean; id: { client: number }; right: Item | null }

function collectClients(node: Y.XmlElement | Y.XmlText | Y.XmlHook, into: Set<number>): void {
  if (node instanceof Y.XmlText) {
    let item = (node as unknown as { _start: Item | null })._start
    while (item) {
      if (!item.deleted && item.countable) into.add(item.id.client)
      item = item.right
    }
  } else if (node instanceof Y.XmlElement) {
    for (const child of node.toArray()) collectClients(child, into)
  }
}

/** Authors of each top-level block, in document order. */
export function blockAuthors(doc: Y.Doc, provider: ArkivProvider | null): Authorship[][] {
  const fragment = doc.getXmlFragment("default")
  return fragment.toArray().map((block) => {
    const clients = new Set<number>()
    collectClients(block as Y.XmlElement, clients)
    const seen = new Map<string, Authorship>()
    for (const c of clients) {
      const a = provider?.authorOf(c)
      if (a && !seen.has(a.address)) seen.set(a.address, a)
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
