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

export type DocumentSession = {
  doc: Y.Doc
  provider: ArkivProvider | null
  store: SdkStore | null
  activity: Activity[]
  error: string | null
  /** Bumps on every provider event, so components re-read provider state. */
  tick: number
  latencies: number[]
}

let nextId = 1

export function useDocument(link: DocLink | null, identity: Identity | undefined): DocumentSession {
  // the client id is derived from our address before the editor binds to the doc
  const { doc, salt } = useMemo(() => {
    const d = new Y.Doc()
    return { doc: d, salt: identity ? prepareDoc(d, identity.address) : undefined }
  }, [link?.doc, identity?.address])
  const [provider, setProvider] = useState<ArkivProvider | null>(null)
  const [store, setStore] = useState<SdkStore | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [tick, bump] = useReducer((n: number) => n + 1, 0)
  const activity = useRef<Activity[]>([])
  const latencies = useRef<number[]>([])

  useEffect(() => {
    if (!link) return
    const s = new SdkStore(identity ? { privateKey: identity.privateKey } : {})
    const p = new ArkivProvider(doc, { store: s, link, identity, salt })
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
    p.on("acl", () => log({ kind: "acl", text: "Member list updated" }))
    p.on("lease", () => bump())
    p.on("history", () => bump())
    p.on("status", () => bump())
    p.on("error", (e: Error) => log({ kind: "error", text: e.message }))
    setStore(s)
    setProvider(p)
    setError(null)
    p.connect().then(
      () => bump(),
      (e: Error) => setError(e.message),
    )
    // fold the last edits into a snapshot when the tab is hidden or closed, so nothing outlives its cover
    const onHide = () => {
      if (document.visibilityState === "hidden") void p.close().catch(() => undefined)
    }
    document.addEventListener("visibilitychange", onHide)
    window.addEventListener("pagehide", onHide)
    return () => {
      document.removeEventListener("visibilitychange", onHide)
      window.removeEventListener("pagehide", onHide)
      void p.close().catch(() => undefined).finally(() => p.destroy())
      setProvider(null)
    }
  }, [doc, link?.doc, identity?.address])

  return { doc, provider, store, activity: activity.current, error, tick, latencies: latencies.current }
}
