import { execFileSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import type { ArkivProvider } from "../../src/provider.js"

const here = fileURLToPath(new URL(".", import.meta.url))
const PY = process.env.PYTHON ?? "python3"
const READERS = here + "../../../../readers/python"
/** Whether a Python with readers/python/requirements.txt is available; the Python half of each test skips without one. */
let hasPy: boolean | undefined
function pythonReady(): boolean {
  if (hasPy === undefined) {
    try {
      execFileSync(PY, ["-c", "import pycrdt, cryptography"], { stdio: "ignore" })
      hasPy = true
    } catch {
      hasPy = false
    }
  }
  return hasPy
}
/** The Python port's earlier_writers on exactly the edits the TypeScript audit applied. */
export function pyEarlier(p: ArkivProvider): { address: string; first: string; text: string }[] | undefined {
  if (!pythonReady()) return undefined
  const rows = p.history.map((h) => ({ author: h.author, block: h.block.toString(), entity: h.entity, update: Buffer.from(h.update).toString("hex") }))
  const out = execFileSync(PY, [here + "py_earlier.py"], { input: JSON.stringify(rows), encoding: "utf8", env: { ...process.env, READERS } })
  return JSON.parse(out)
}
