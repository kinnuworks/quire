import { useEffect, useMemo, useReducer, useRef, useState } from "react"
import * as Y from "yjs"
import { ArkivProvider, type DocLink, type FlushInfo, type Identity, type JoinRequest, prepareDoc, type RemoteEdit, SdkStore } from "y-arkiv"
import { type ArkivNode, customNode } from "./session"

export type Activity = {
  id: number
  at: number
  kind: "flush" | "remote" | "compact" | "lease" | "rejected" | "join" | "acl" | "error" | "status"
  text: string
  entity?: string
  tx?: string
  latencyMs?: number
  author?: string
}

export type SessionError = { kind: "budget"; retryAt: number } | { kind: "other"; message: string }

/** Plain words for a connection error: the query budget gets its own card, anything else one short line. */
export function describeError(e: unknown): SessionError {
  // viem wraps whatever our fetch throws, so look through the chain and the message text
  let cause: unknown = e
  for (let i = 0; i < 8 && cause; i++) {
    const c = cause as { name?: string; retryAfterSeconds?: number; message?: string; cause?: unknown }
    if (c.name === "QueryBudgetError") return { kind: "budget", retryAt: Date.now() + (c.retryAfterSeconds ?? 60) * 1000 }
    const m = /free query budget[^]*?about (\d+) minutes/.exec(c.message ?? "")
    if (m) return { kind: "budget", retryAt: Date.now() + Number(m[1]) * 60_000 }
    cause = c.cause
  }
  const err = e as { shortMessage?: string; message?: string; type?: string }
  // a refused WebSocket arrives as a bare error event: the browser hides the gateway's reason
  // (a per-IP cap on live connections), so say what it almost always is
  if (!err.shortMessage && !err.message && err.type === "error") {
    return { kind: "other", message: "Arkiv refused the live connection, most likely its limit on live connections per network. Checking by query instead." }
  }
  return { kind: "other", message: (err.shortMessage ?? err.message ?? "Something went wrong").split("\n")[0]!.slice(0, 200) }
}

export type DocumentSession = {
  doc: Y.Doc
  provider: ArkivProvider | null
  store: SdkStore | null
  activity: Activity[]
  error: SessionError | null
  /** Bumps on every provider event, so components re-read provider state. */
  tick: number
  latencies: number[]
  /** True once the session was reopened reading every edit still on chain. */
  fullHistory: boolean
  /** Reopens with every edit still on chain, so text older than the newest snapshot is proven too. */
  loadFullHistory: () => void
  /** True while queries go through Quire's relay (see api/rpc.ts). */
  relay: boolean
  /** The visitor chose the relay on the budget notice: reconnect with it, for this tab only. */
  useRelay: () => void
  /** The Arkiv node the visitor chose instead of the public endpoint, or null. */
  node: ArkivNode | null
}

const RELAY_FLAG = "quire.relay"
function relayChosen(): boolean {
  try {
    return sessionStorage.getItem(RELAY_FLAG) === "1"
  } catch {
    return false
  }
}

let nextId = 1

const rebuilds: number[] = []

export function useDocument(link: DocLink | null, identity: Identity | undefined): DocumentSession {
  // bumping this reconnects with a fresh doc: after a budget wait, or to heal a divergence
  const [attempt, setAttempt] = useState(0)
  // opt in: a long-edited document can have many edits still on chain, and each page costs a query
  const [fullHistory, setFullHistory] = useState(false)
  // read once: saving a different node reloads the page
  const [node] = useState(customNode)
  // off unless the visitor opts in after their free budget runs out; remembered for this tab only.
  // Never with a node the visitor chose: the relay forwards to Arkiv's public endpoint, not to theirs
  const [relay, setRelay] = useState(() => !node && relayChosen())
  useEffect(() => setFullHistory(false), [link?.doc])
  // the client id is derived from our address before the editor binds to the doc
  const { doc, salt } = useMemo(() => {
    const d = new Y.Doc()
    return { doc: d, salt: identity ? prepareDoc(d, identity.address) : undefined }
  }, [link?.doc, identity?.address, attempt, fullHistory, relay])
  const [provider, setProvider] = useState<ArkivProvider | null>(null)
  const [store, setStore] = useState<SdkStore | null>(null)
  const [error, setError] = useState<SessionError | null>(null)
  const [tick, bump] = useReducer((n: number) => n + 1, 0)
  const activity = useRef<Activity[]>([])
  const latencies = useRef<number[]>([])

  useEffect(() => {
    if (!link) return
    const s = new SdkStore({ ...(identity ? { privateKey: identity.privateKey } : {}), ...(node ?? {}), ...(relay ? { relayUrl: "/api/rpc" } : {}) })
    // "who wrote what" checks each edit's author against the member list as it stood at that edit's
    // block (one free read by key per block), so an owner who rewrites the list cannot forge authorship
    const p = new ArkivProvider(doc, { store: s, link, identity, salt, fullHistory, membershipAtBlock: true })
    const log = (a: Omit<Activity, "id" | "at">) => {
      activity.current = [{ id: nextId++, at: Date.now(), ...a }, ...activity.current].slice(0, 200)
      bump()
    }
    p.on("flush", (f: FlushInfo) => log({ kind: "flush", text: `Wrote ${f.bytes} encrypted bytes`, entity: f.entity, tx: f.txHash }))
    p.on("compact", (f: FlushInfo) => log({ kind: "compact", text: `Compacted into a snapshot (${f.bytes} bytes)`, entity: f.entity, tx: f.txHash }))
    p.on("remote-edit", (e: RemoteEdit) => {
      if (e.latencyMs !== undefined) latencies.current = [...latencies.current, e.latencyMs].slice(-30)
      log({ kind: "remote", text: `Edit applied`, entity: e.entity, author: e.author, latencyMs: e.latencyMs })
    })
    p.on("join-request", (j: JoinRequest) => log({ kind: "join", text: `${j.name || "Someone"} asked to join`, author: j.address }))
    p.on("rejected", (n: number) => log({ kind: "rejected", text: `Refused a write: from outside the member list, under someone else's client id, conflicting or malformed (${n} so far)` }))
    // the first ACL load is not news; only later changes are
    let aclLoads = 0
    p.on("acl", () => {
      if (aclLoads++ > 0) log({ kind: "acl", text: "Member list updated" })
      else bump()
    })
    p.on("lease", () => bump())
    // a snapshot clashed with a genuine edit, or two clashing edits arrived out of order: rebuild this
    // session from the chain, where the updates-first load and the ordering rules settle it as every
    // cold reader does
    // Never compact here: a snapshot of a diverged state would carry the clash forward. Send only what
    // this tab typed, then reload. At most twice a minute, so a persistent clash cannot loop.
    p.on("diverged", () => {
      const now = Date.now()
      // at most twice in ten minutes: each reload costs three queries, and a hostile snapshot could
      // otherwise keep spending a reader's free budget
      rebuilds.splice(0, rebuilds.length, ...rebuilds.filter((t) => now - t < 600_000))
      if (rebuilds.length >= 2) {
        log({ kind: "rejected", text: "Writes clashed again; not reloading. Reopen the page to rebuild." })
        return
      }
      rebuilds.push(now)
      log({ kind: "rejected", text: "Two writes clashed and this tab saw them out of order; reloading from Arkiv" })
      void p.flush().catch(() => undefined).finally(() => setAttempt((n) => n + 1))
    })
    p.on("history", () => bump())
    p.on("status", () => bump())
    p.on("live", (on: boolean) => {
      log({ kind: "error", text: on ? "Live edits are back" : "Live edits paused: Arkiv refused the socket for now. Checking by query, less often each time" })
      bump()
    })
    p.on("error", (e: Error) => {
      const d = describeError(e)
      log({ kind: "error", text: d.kind === "budget" ? "Free read budget used up; retrying later" : d.message })
    })
    setStore(s)
    setProvider(p)
    setError(null)
    let retry: ReturnType<typeof setTimeout> | undefined
    p.connect().then(
      () => bump(),
      (e: Error) => {
        const d = describeError(e)
        setError(d)
        if (d.kind === "budget") retry = setTimeout(() => setAttempt((n) => n + 1), Math.max(5_000, d.retryAt - Date.now()))
      },
    )
    // fold the last edits into a snapshot when the tab is hidden or closed, so nothing outlives its cover
    let hiddenAt = 0
    const onHide = () => {
      if (document.visibilityState === "hidden") {
        hiddenAt = Date.now()
        void p.close().catch(() => undefined)
      } else if (hiddenAt && Date.now() - hiddenAt > 60_000) catchUp()
    }
    // the socket may have dropped while the network or the tab was away: catch up at once (free reads by
    // key, plus one query), instead of waiting for the 15-minute resync
    const catchUp = () => void p.resync({ joins: true }).then(() => bump(), () => undefined)
    document.addEventListener("visibilitychange", onHide)
    window.addEventListener("pagehide", onHide)
    window.addEventListener("online", catchUp)
    return () => {
      if (retry) clearTimeout(retry)
      document.removeEventListener("visibilitychange", onHide)
      window.removeEventListener("pagehide", onHide)
      window.removeEventListener("online", catchUp)
      void p.close().catch(() => undefined).finally(() => p.destroy())
      setProvider(null)
    }
  }, [doc, link?.doc, identity?.address, attempt, fullHistory, relay])

  return { doc, provider, store, activity: activity.current, error, tick, latencies: latencies.current, fullHistory,
    loadFullHistory: () => setFullHistory(true),
    relay,
    node,
    useRelay: () => {
      if (node) {
        activity.current = [{ id: nextId++, at: Date.now(), kind: "error" as const, text: "Quire's relay stays off: it forwards to Arkiv's public endpoint, and you chose your own node (Explorer tab)" }, ...activity.current].slice(0, 200)
        bump()
        return
      }
      try {
        sessionStorage.setItem(RELAY_FLAG, "1")
      } catch {
        // storage blocked: the choice lasts until this page reloads
      }
      setRelay(true)
    },
  }
}
