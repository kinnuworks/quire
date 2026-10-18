/**
 * Scheduled key rotation, kept in the owner's browser: when it is on, the owner's session rotates the
 * document key on opening it once the period has passed since the last rotation. A link that leaks
 * then opens at most one period of writing. Nothing about it is on chain; another browser of the
 * owner's does not know the setting.
 */
const KEY = (doc: string) => `quire.autorotate.${doc}`
export const ROTATE_EVERY_DAYS = 30

type Setting = { on: boolean; lastAt: number }

export function autoRotateSetting(doc: string): Setting {
  try {
    const raw = localStorage.getItem(KEY(doc))
    const v = raw ? (JSON.parse(raw) as Partial<Setting>) : null
    return { on: !!v?.on, lastAt: typeof v?.lastAt === "number" ? v.lastAt : Date.now() }
  } catch {
    return { on: false, lastAt: Date.now() }
  }
}

export function setAutoRotate(doc: string, on: boolean): void {
  try {
    localStorage.setItem(KEY(doc), JSON.stringify({ on, lastAt: Date.now() }))
  } catch {
    // private window or blocked storage: the setting simply does not stick
  }
}

export function rotatedNow(doc: string): void {
  const s = autoRotateSetting(doc)
  try {
    localStorage.setItem(KEY(doc), JSON.stringify({ on: s.on, lastAt: Date.now() }))
  } catch {
    // as above
  }
}

/** True when the setting is on and a full period has passed since the last rotation. */
export function rotationDue(doc: string, now = Date.now()): boolean {
  const s = autoRotateSetting(doc)
  return s.on && now - s.lastAt >= ROTATE_EVERY_DAYS * 86_400_000
}
