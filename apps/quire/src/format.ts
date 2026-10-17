import * as Y from "yjs"

export const DATA_EXPLORER = "https://data.arkiv.network"
export const BLOCK_EXPLORER = "https://tiramisu.explorer.arkiv.network"

export function short(hex: string, n = 4): string {
  return hex.length > 2 + n * 2 ? `${hex.slice(0, 2 + n)}…${hex.slice(-n)}` : hex
}

export function entityUrl(key: string): string {
  return `${DATA_EXPLORER}/entity/${key}`
}

export function txUrl(hash: string): string {
  return `${BLOCK_EXPLORER}/tx/${hash}`
}

export function addressUrl(address: string): string {
  return `${DATA_EXPLORER}/owner/${address}`
}

/** Blocks from now as a human duration (2 s blocks). */
export function blocksToDuration(blocks: bigint): string {
  const s = Number(blocks) * 2
  if (s <= 0) return "expired"
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  if (d > 0) return `${d}d ${h}h`
  const m = Math.floor((s % 3600) / 60)
  return h > 0 ? `${h}h ${m}m` : `${m}m`
}

/** Plain text of a Tiptap document, one line per block. */
export function plainText(doc: Y.Doc): string {
  const lines: string[] = []
  const walk = (n: Y.XmlElement | Y.XmlText | Y.XmlHook): string => {
    if (n instanceof Y.XmlText) return n.toString().replace(/<[^>]+>/g, "")
    if (n instanceof Y.XmlElement) return n.toArray().map(walk).join("")
    return ""
  }
  for (const block of doc.getXmlFragment("default").toArray()) lines.push(walk(block as Y.XmlElement))
  return lines.join("\n")
}

export function hexPreview(bytes: Uint8Array, max = 96): string {
  let out = ""
  for (let i = 0; i < Math.min(bytes.length, max); i++) out += bytes[i]!.toString(16).padStart(2, "0")
  return bytes.length > max ? `${out}…` : out
}
