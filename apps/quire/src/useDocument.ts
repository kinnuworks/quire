import { useEffect, useMemo, useReducer, useRef, useState } from "react"
import * as Y from "yjs"
import { ArkivProvider, type DocLink, type FlushInfo, type Identity, type JoinRequest, prepareDoc, type RemoteEdit, SdkStore } from "y-arkiv"

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
  const err = e as { shortMessage?: string; message?: string }
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

export function useDocument(link: DocLink | null, identity: Identity | undefined): DocumentSession {
  // bumping this reconnects with a fresh doc: after a budget wait, or to heal a divergence
  const [attempt, setAttempt] = useState(0)
  // opt in: a long-edited document can have many edits still on chain, and each page costs a query
  const [fullHistory, setFullHistory] = useState(false)
  // off unless the visitor opts in after their free budget runs out; remembered for this tab only
  const [relay, setRelay] = useState(relayChosen)
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
    const s = new SdkStore({ ...(identity ? { privateKey: identity.privateKey } : {}), ...(relay ? { relayUrl: "/api/rpc" } : {}) })
    const p = new ArkivProvider(doc, { store: s, link, identity, salt, fullHistory })
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
    p.on("rejected", (n: number) => log({ kind: "rejected", text: `Ignored a write from outside the member list (${n} so far)` }))
    // the first ACL load is not news; only later changes are
    let aclLoads = 0
    p.on("acl", () => {
      if (aclLoads++ > 0) log({ kind: "acl", text: "Member list updated" })
      else bump()
    })
    p.on("lease", () => bump())
    // a snapshot clashed with a genuine edit: rebuild this session from the chain, where the
    // updates-first load and the override check settle it in the genuine edit's favour
    p.on("diverged", () => {
      log({ kind: "rejected", text: "A snapshot conflicted with a checked edit; reloading from Arkiv" })
      void p.close().catch(() => undefined).finally(() => setAttempt((n) => n + 1))
    })
    p.on("history", () => bump())
    p.on("status", () => bump())
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
    const onHide = () => {
      if (document.visibilityState === "hidden") void p.close().catch(() => undefined)
    }
    document.addEventListener("visibilitychange", onHide)
    window.addEventListener("pagehide", onHide)
    return () => {
      if (retry) clearTimeout(retry)
      document.removeEventListener("visibilitychange", onHide)
      window.removeEventListener("pagehide", onHide)
      void p.close().catch(() => undefined).finally(() => p.destroy())
      setProvider(null)
    }
  }, [doc, link?.doc, identity?.address, attempt, fullHistory, relay])

  return { doc, provider, store, activity: activity.current, error, tick, latencies: latencies.current, fullHistory,
    loadFullHistory: () => setFullHistory(true),
    relay,
    useRelay: () => {
      try {
        sessionStorage.setItem(RELAY_FLAG, "1")
      } catch {
        // storage blocked: the choice lasts until this page reloads
      }
      setRelay(true)
    },
  }
}
