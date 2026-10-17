import { render } from "@arkiv-network/sdk/query"
import { useEffect, useState } from "react"
import { type DocLink, formatVersionLink, type Frame, type Hex, type Identity, KIND, loadAt, type StoredEntity, toExpression } from "y-arkiv"
import { colorOf } from "./authorship"
import { addressUrl, blocksToDuration, entityUrl, hexPreview, plainText, short, txUrl } from "./format"
import { balanceOf, formatGlm } from "./gas"
import type { DocumentSession } from "./useDocument"

function Addr({ a, label }: { a: string; label?: string }) {
  return (
    <a className="addr" href={addressUrl(a)} target="_blank" rel="noreferrer" title={a}>
      <span className="dot" style={{ background: colorOf(a) }} />
      {label ?? short(a)}
    </a>
  )
}

// ------------------------------------------------------------------ people

export function PeoplePanel({ session, identity }: { session: DocumentSession; identity: Identity | undefined }) {
  const p = session.provider
  const [balance, setBalance] = useState<bigint | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  useEffect(() => {
    if (!identity) return
    let alive = true
    const load = () => balanceOf(identity.address).then((b) => alive && setBalance(b), () => undefined)
    load()
    const t = setInterval(load, 15_000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [identity?.address])

  if (!p?.acl) return <div className="panel muted">Loading the member list…</div>
  const owner = p.role === "owner"
  const act = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(label)
    setErr(null)
    try {
      await fn()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="panel">
      {identity && (
        <section>
          <h4>You in this document</h4>
          <p>
            <Addr a={identity.address} label={`${identity.name} · ${short(identity.address)}`} />
          </p>
          <p className="muted small">
            A key made for this document only. Balance {balance === null ? "…" : `${formatGlm(balance)} GLM`} of test gas.
          </p>
        </section>
      )}

      {owner && p.joinRequests.length > 0 && (
        <section>
          <h4>Asking to join</h4>
          {p.joinRequests.map((j) => (
            <div className="row" key={j.key}>
              <Addr a={j.address} label={`${j.name || "Unnamed"} · ${short(j.address)}`} />
              <button className="primary" disabled={!!busy} onClick={() => act("approve", () => p.approve(j.address))}>
                Add as writer
              </button>
            </div>
          ))}
          <p className="muted small">The request is signed by the key it asks you to trust, so nobody can request on someone else's behalf.</p>
        </section>
      )}

      <section>
        <h4>Members · epoch {p.acl.epoch}</h4>
        {p.acl.members.map((m) => (
          <div className="row" key={m.address}>
            <Addr a={m.address} label={`${m.name || "Unnamed"} · ${short(m.address)}`} />
            <span className="muted small">{m.role}</span>
            {owner && m.role !== "owner" && (
              <button disabled={!!busy} onClick={() => confirm(`Remove ${m.name}? Their key stops working for new edits.`) && act("revoke", () => p.revoke(m.address))}>
                Remove
              </button>
            )}
          </div>
        ))}
        <p className="muted small">
          Readers only accept edits whose on-chain creator is in this list. Removing someone starts a new epoch: a fresh key, wrapped for the members who stay.
        </p>
      </section>

      {p.acl.revoked.length > 0 && (
        <section>
          <h4>Removed</h4>
          {p.acl.revoked.map((r) => (
            <div className="row" key={r.address + r.atBlock}>
              <Addr a={r.address} />
              <span className="muted small">at block {r.atBlock}</span>
            </div>
          ))}
        </section>
      )}

      <section>
        <h4>Ignored writes</h4>
        <p>
          <strong>{p.stats.rejectedWrites}</strong> <span className="muted">entities for this document came from addresses outside the member list and were never applied.</span>
        </p>
      </section>
      {busy && <p className="muted">Working: {busy}…</p>}
      {err && <p className="error">{err}</p>}
    </div>
  )
}

// ------------------------------------------------------------------ activity

export function ActivityPanel({ session }: { session: DocumentSession }) {
  const p = session.provider
  const lat = [...session.latencies].sort((a, b) => a - b)
  const median = lat.length ? lat[Math.floor(lat.length / 2)]! : null
  return (
    <div className="panel">
      <section className="stats">
        <div>
          <span className="big">{median === null ? "–" : `${(median / 1000).toFixed(1)}s`}</span>
          <span className="muted small">median time from a collaborator's flush to your screen</span>
        </div>
        <div>
          <span className="big">{p?.stats.writes ?? 0}</span>
          <span className="muted small">transactions from this tab</span>
        </div>
        <div>
          <span className="big">{p ? p.stats.queries : 0}</span>
          <span className="muted small">queries since opening (live edits use none)</span>
        </div>
      </section>
      <ul className="feed">
        {session.activity.length === 0 && <li className="muted">Nothing yet. Type something, or open the invite link in a second window.</li>}
        {session.activity.map((a) => (
          <li key={a.id} className={`feed-${a.kind}`}>
            <span className="time">{new Date(a.at).toLocaleTimeString()}</span>
            <span>
              {a.author && <Addr a={a.author} />} {a.text}
              {a.latencyMs !== undefined && <span className="muted"> · {(a.latencyMs / 1000).toFixed(1)}s</span>}
              {a.entity && (
                <>
                  {" "}
                  <a href={entityUrl(a.entity)} target="_blank" rel="noreferrer">
                    entity
                  </a>
                </>
              )}
              {a.tx && (
                <>
                  {" "}
                  <a href={txUrl(a.tx)} target="_blank" rel="noreferrer">
                    tx
                  </a>
                </>
              )}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

// ------------------------------------------------------------------ explorer view

export function ChainPanel({ session }: { session: DocumentSession }) {
  const p = session.provider
  const latest = session.activity.find((a) => a.entity)?.entity as Hex | undefined
  const [key, setKey] = useState<Hex | undefined>(undefined)
  const [view, setView] = useState<{ entity: StoredEntity; frame: Frame | null } | null>(null)
  const target = key ?? latest ?? p?.snapshot?.key
  useEffect(() => {
    if (!p || !target) return
    let alive = true
    p.inspect(target).then((v) => alive && setView(v), () => alive && setView(null))
    return () => {
      alive = false
    }
  }, [p, target])
  if (!p) return null
  const sample = render(toExpression({ doc: p.link.doc, kind: KIND.update, creators: p.acl ? p.acl.members.map((m) => m.address) : [] }))

  return (
    <div className="panel">
      <p className="muted small">
        Left: what anyone sees on the explorer. Right: what this browser decrypts with the key from your link.
      </p>
      <div className="row wrap">
        {p.aclKey && <button onClick={() => setKey(p.aclKey!)}>Member list</button>}
        {p.snapshot && <button onClick={() => setKey(p.snapshot!.key)}>Snapshot</button>}
        {latest && <button onClick={() => setKey(latest)}>Latest edit</button>}
      </div>
      {view ? (
        <div className="split">
          <div className="public">
            <h4>Public</h4>
            <dl>
              <dt>key</dt>
              <dd>
                <a href={entityUrl(view.entity.key)} target="_blank" rel="noreferrer">
                  {short(view.entity.key, 6)}
                </a>
              </dd>
              <dt>$creator</dt>
              <dd>{short(view.entity.creator, 6)}</dd>
              <dt>$owner</dt>
              <dd>{short(view.entity.owner, 6)}</dd>
              <dt>qp</dt>
              <dd>quire1</dd>
              <dt>qd</dt>
              <dd>{short(view.entity.attributes.doc, 6)}</dd>
              <dt>qk</dt>
              <dd>{view.entity.attributes.kind}</dd>
              <dt>qs</dt>
              <dd>{view.entity.attributes.seq.toString()}</dd>
              <dt>expires</dt>
              <dd>block {view.entity.expiresAt.toString()}</dd>
              <dt>flags</dt>
              <dd>{[view.entity.readonly && "readonly", view.entity.permissionlessExtension && "anyone can extend"].filter(Boolean).join(", ") || "none"}</dd>
              <dt>payload</dt>
              <dd className="mono">
                {view.entity.payload.length} bytes
                <br />
                {hexPreview(view.entity.payload, 48)}
              </dd>
            </dl>
          </div>
          <div className="private">
            <h4>Decrypted here</h4>
            {view.frame ? <FrameView frame={view.frame} /> : <p className="muted">This browser has no key for that entity.</p>}
          </div>
        </div>
      ) : (
        <p className="muted">Write something, then look here.</p>
      )}
      <section>
        <h4>The query readers run</h4>
        <pre className="mono small">{sample}</pre>
        <p className="muted small">
          Network calls from this tab: {session.store?.calls.query ?? 0} queries, {session.store?.calls.getEntity ?? 0} free entity reads, {session.store?.calls.write ?? 0} writes.
        </p>
      </section>
    </div>
  )
}

function FrameView({ frame }: { frame: Frame }) {
  const kindName: Record<string, string> = { u: "edit", s: "snapshot", c: "snapshot chunk", a: "member list", j: "join request", v: "published version" }
  return (
    <dl>
      <dt>kind</dt>
      <dd>{kindName[frame.kind] ?? frame.kind}</dd>
      <dt>epoch</dt>
      <dd>{frame.epoch}</dd>
      {frame.kind === "a" && (
        <>
          <dt>members</dt>
          <dd>{(frame.header.members as { name: string }[]).map((m) => m.name || "Unnamed").join(", ")}</dd>
        </>
      )}
      {frame.kind === "j" && (
        <>
          <dt>name</dt>
          <dd>{String(frame.header.name)}</dd>
        </>
      )}
      {typeof frame.header.t === "number" && (
        <>
          <dt>written</dt>
          <dd>{new Date(frame.header.t).toLocaleTimeString()}</dd>
        </>
      )}
      {typeof frame.header.base === "string" && (
        <>
          <dt>covers up to</dt>
          <dd>block {frame.header.base}</dd>
        </>
      )}
      <dt>content</dt>
      <dd>{frame.data.length} bytes of Yjs data, padded to a fixed size before encryption</dd>
    </dl>
  )
}

// ------------------------------------------------------------------ history

export function HistoryPanel({ session, link }: { session: DocumentSession; link: DocLink }) {
  const p = session.provider
  const entries = p?.history ?? []
  const [i, setI] = useState<number | null>(null)
  const [check, setCheck] = useState<string | null>(null)
  if (!p) return null
  if (!entries.length) return <div className="panel muted">History starts at the newest snapshot. Edits made after it show up here.</div>
  const idx = i ?? entries.length - 1
  const at = entries[Math.min(idx, entries.length - 1)]!
  const text = plainText(p.stateAt(at.block))

  async function verify() {
    if (!session.store) return
    setCheck("Reading the document from Arkiv as of that block…")
    try {
      const past = await loadAt(session.store, link, at.block, p!.identity)
      setCheck(plainText(past) === text ? `Matches what Arkiv held at block ${at.block}.` : `Arkiv at block ${at.block} differs (an edit in the same block may be newer).`)
    } catch (e) {
      setCheck((e as Error).message)
    }
  }

  return (
    <div className="panel">
      <input type="range" min={0} max={entries.length - 1} value={idx} onChange={(e) => (setI(Number(e.target.value)), setCheck(null))} />
      <p className="small">
        Block {at.block.toString()} · <Addr a={at.author} />
      </p>
      <pre className="preview">{text || "(empty)"}</pre>
      <button onClick={verify}>Check against Arkiv at this block</button>
      {check && <p className="muted small">{check}</p>}
      <p className="muted small">The slider replays edits locally. The check rebuilds the document with atBlock reads and compares.</p>
    </div>
  )
}

// ------------------------------------------------------------------ lifetime

const LIFETIMES = [
  { label: "1 day", s: 86400 },
  { label: "1 week", s: 7 * 86400 },
  { label: "30 days", s: 30 * 86400 },
  { label: "1 year", s: 365 * 86400 },
]

export function LifetimePanel({ session }: { session: DocumentSession }) {
  const p = session.provider
  const [head, setHead] = useState<bigint | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [out, setOut] = useState<string | null>(null)
  useEffect(() => {
    if (!session.store) return
    session.store.head().then(setHead, () => undefined)
  }, [session.store, session.tick])
  if (!p) return null
  const writer = p.role === "owner" || p.role === "writer"
  const left = p.snapshot && head !== null ? p.snapshot.expiresAt - head : null
  const act = async (label: string, fn: () => Promise<string | void>) => {
    setBusy(label)
    setOut(null)
    try {
      const r = await fn()
      if (r) setOut(r)
    } catch (e) {
      setOut((e as Error).message)
    } finally {
      setBusy(null)
    }
  }
  return (
    <div className="panel">
      <section>
        <h4>This document lives for</h4>
        <p className="big">{left === null ? "…" : blocksToDuration(left)}</p>
        <p className="muted small">
          The newest snapshot is a lease. Each time a member opens the document past the halfway mark, it is renewed with Lifetime Extension. If nobody opens it, it expires and the
          chain forgets it. Single edits expire after a week, once snapshots cover them.
        </p>
      </section>
      {p.role === "owner" && (
        <section>
          <h4>Set the lifetime</h4>
          <div className="row wrap">
            {LIFETIMES.map((l) => (
              <button key={l.s} disabled={!!busy} onClick={() => act("lifetime", async () => (await p.setLifetime(l.s), `Lifetime set to ${l.label}.`))}>
                {l.label}
              </button>
            ))}
          </div>
        </section>
      )}
      {writer && (
        <section>
          <h4>Publish a frozen copy</h4>
          <p className="muted small">A readonly version with its own key. Nobody can change it, and anyone holding the link can keep it alive.</p>
          <button
            disabled={!!busy}
            onClick={() =>
              act("publish", async () => {
                const v = await p.publishVersion()
                const url = `${location.origin}${location.pathname}#${formatVersionLink(v)}`
                await navigator.clipboard?.writeText(url)
                return `Link copied: ${url}`
              })
            }
          >
            Publish version
          </button>
        </section>
      )}
      {p.identity && (
        <section>
          <h4>Shred my writing</h4>
          <p className="muted small">
            Deletes every entity your key created for this document, in one transaction: your edit history, your join request and any snapshot you still own. Text you wrote stays in
            the shared document until someone deletes it there.
          </p>
          <button
            className="danger"
            disabled={!!busy}
            onClick={() => confirm("Delete everything your key wrote for this document?") && act("shred", async () => `Deleted ${await p.shredMine()} entities.`)}
          >
            Shred my writing
          </button>
        </section>
      )}
      {busy && <p className="muted">Working…</p>}
      {out && <p className="small">{out}</p>}
    </div>
  )
}
