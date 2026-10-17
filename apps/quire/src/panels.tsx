import { render } from "@arkiv-network/sdk/query"
import { useEffect, useState } from "react"
import { type DocLink, formatDocLink, formatVersionLink, type Frame, type Hex, type Identity, KIND, loadAt, type StoredEntity, toExpression } from "y-arkiv"
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

function useAction() {
  const [busy, setBusy] = useState<string | null>(null)
  const [out, setOut] = useState<{ ok: boolean; text: string } | null>(null)
  const run = async (label: string, fn: () => Promise<string | void>) => {
    setBusy(label)
    setOut(null)
    try {
      const r = await fn()
      if (r) setOut({ ok: true, text: r })
    } catch (e) {
      setOut({ ok: false, text: (e as Error).message })
    } finally {
      setBusy(null)
    }
  }
  const view = (
    <>
      {busy && <p className="muted small">Working: {busy}…</p>}
      {out && <p className={`small ${out.ok ? "" : "error"}`}>{out.text}</p>}
    </>
  )
  return { busy, run, view }
}

/** Saves this browser's key and link for the document, so losing site data does not lose ownership. */
function exportKeys(identity: Identity, link: DocLink) {
  const blob = new Blob(
    [JSON.stringify({ warning: "This file controls your seat in one Quire document. Keep it private.", link: `#${formatDocLink(link)}`, address: identity.address, privateKey: identity.privateKey, name: identity.name }, null, 2)],
    { type: "application/json" },
  )
  const a = document.createElement("a")
  a.href = URL.createObjectURL(blob)
  a.download = `quire-${link.doc.slice(2, 10)}.json`
  a.click()
  URL.revokeObjectURL(a.href)
}

// ------------------------------------------------------------------ people

export function PeoplePanel({ session, identity, link }: { session: DocumentSession; identity: Identity | undefined; link: DocLink }) {
  const p = session.provider
  const [balance, setBalance] = useState<bigint | null>(null)
  const { busy, run, view } = useAction()
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

  if (!p?.acl) return <div className="panel-card muted">Loading the member list…</div>
  const owner = p.role === "owner"

  return (
    <div className="panel-card">
      {identity && (
        <section>
          <h4>You in this document</h4>
          <div className="row">
            <Addr a={identity.address} label={`${identity.name} · ${short(identity.address)}`} />
            <button className="btn btn-ghost" onClick={() => exportKeys(identity, link)}>
              Save key file
            </button>
          </div>
          <p className="muted small">A key made for this document only. {balance === null ? "" : `${formatGlm(balance)} GLM of test gas left.`}</p>
        </section>
      )}

      {owner && p.joinRequests.length > 0 && (
        <section>
          <h4>Asking to join</h4>
          {p.joinRequests.map((j) => (
            <div className="row" key={j.key}>
              <Addr a={j.address} label={`${j.name || "Unnamed"} · ${short(j.address)}`} />
              <button className="btn btn-candy" disabled={!!busy} onClick={() => run("adding", async () => (await p.approve(j.address), `${j.name || "They"} can write now.`))}>
                Add
              </button>
            </div>
          ))}
          <p className="muted small">Each request is sealed to your key and signed by the key it asks you to trust.</p>
        </section>
      )}

      <section>
        <h4>Members · epoch {p.acl.epoch}</h4>
        {p.acl.rosterHidden ? (
          <p className="muted small">The member list is sealed under a key this browser does not have.</p>
        ) : (
          p.acl.members.map((m) => (
            <div className="row" key={m.address}>
              <Addr a={m.address} label={`${m.name || "Unnamed"} · ${short(m.address)}`} />
              {owner && m.role !== "owner" ? (
                <button
                  className="btn btn-outline danger"
                  disabled={!!busy}
                  onClick={() => confirm(`Remove ${m.name}? The key rotates and they stop receiving new edits.`) && run("removing", async () => (await p.revoke(m.address), `Removed. New edits use epoch ${p.acl!.epoch}.`))}
                >
                  Remove
                </button>
              ) : (
                <span className="pill-tag">{m.role}</span>
              )}
            </div>
          ))
        )}
        <p className="muted small">Readers apply an edit only if its on-chain creator is in this list. Removing someone rotates the key for everyone who stays.</p>
      </section>

      <section>
        <h4>Ignored writes</h4>
        <p>
          <span className="big">{p.stats.rejectedWrites}</span> <span className="muted small">entities for this document came from outside the member list, or tried to write under someone else's name.</span>
        </p>
      </section>
      {view}
    </div>
  )
}

// ------------------------------------------------------------------ live

export function ActivityPanel({ session }: { session: DocumentSession }) {
  const p = session.provider
  const lat = [...session.latencies].sort((a, b) => a - b)
  const median = lat.length ? lat[Math.floor(lat.length / 2)]! : null
  return (
    <div className="panel-card">
      <section className="stats">
        <div>
          <span className="big">{median === null ? "–" : `${(median / 1000).toFixed(1)}s`}</span>
          <span className="muted small">typing to your screen, median</span>
        </div>
        <div>
          <span className="big">{p?.stats.writes ?? 0}</span>
          <span className="muted small">transactions from this tab</span>
        </div>
        <div>
          <span className="big">{session.store?.calls.query ?? 0}</span>
          <span className="muted small">queries; live edits use none</span>
        </div>
      </section>
      <ul className="feed">
        {session.activity.length === 0 && <li className="muted">Nothing yet. Type something, or open the invite link in a private window.</li>}
        {session.activity.map((a) => (
          <li key={a.id} className={`feed-${a.kind}`}>
            <span className="time">{new Date(a.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
            <span>
              {a.author && <Addr a={a.author} />} {a.text}
              {a.latencyMs !== undefined && <span className="muted"> · {(a.latencyMs / 1000).toFixed(1)}s</span>}
              {a.entity && (
                <>
                  {" · "}
                  <a className="link" href={entityUrl(a.entity)} target="_blank" rel="noreferrer">
                    entity
                  </a>
                </>
              )}
              {a.tx && (
                <>
                  {" · "}
                  <a className="link" href={txUrl(a.tx)} target="_blank" rel="noreferrer">
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
    <div className="panel-card">
      <p className="muted small">Left: what anyone sees on the explorer. Right: what this browser decrypts with the key from your link.</p>
      <div className="segmented" style={{ width: "100%" }}>
        {p.aclKey && (
          <button aria-pressed={target === p.aclKey} onClick={() => setKey(p.aclKey!)}>
            Member list
          </button>
        )}
        {p.snapshot && (
          <button aria-pressed={target === p.snapshot.key} onClick={() => setKey(p.snapshot!.key)}>
            Snapshot
          </button>
        )}
        {latest && (
          <button aria-pressed={target === latest} onClick={() => setKey(latest)}>
            Latest edit
          </button>
        )}
      </div>
      {view ? (
        <div className="split2">
          <div>
            <h4>Public</h4>
            <dl className="kv2">
              <dt>key</dt>
              <dd>
                <a className="t-accent" href={entityUrl(view.entity.key)} target="_blank" rel="noreferrer">
                  {short(view.entity.key, 5)}
                </a>
              </dd>
              <dt>$creator</dt>
              <dd className="mono">{short(view.entity.creator, 5)}</dd>
              <dt>qp</dt>
              <dd className="mono">quire1</dd>
              <dt>qd</dt>
              <dd className="mono">{short(view.entity.attributes.doc, 5)}</dd>
              <dt>qk</dt>
              <dd className="mono">{view.entity.attributes.kind}</dd>
              <dt>qs</dt>
              <dd className="mono">{view.entity.attributes.seq.toString()}</dd>
              <dt>expires</dt>
              <dd className="mono">#{view.entity.expiresAt.toString()}</dd>
              <dt>flags</dt>
              <dd>{[view.entity.readonly && "readonly", view.entity.permissionlessExtension && "anyone can extend"].filter(Boolean).join(", ") || "none"}</dd>
              <dt>payload</dt>
              <dd className="mono">{view.entity.payload.length} B</dd>
            </dl>
            <p className="mono small muted" style={{ marginTop: 8 }}>
              {hexPreview(view.entity.payload, 36)}
            </p>
          </div>
          <div className="private">
            <h4>Decrypted here</h4>
            {view.frame ? <FrameView frame={view.frame} /> : <p className="muted small">This browser has no key for that entity.</p>}
          </div>
        </div>
      ) : (
        <p className="muted">Write something, then look here.</p>
      )}
      <section>
        <h4>The query readers run</h4>
        <pre className="code">{sample}</pre>
        <p className="muted small" style={{ marginTop: 8 }}>
          From this tab: {session.store?.calls.query ?? 0} queries, {session.store?.calls.getEntity ?? 0} entity reads (not billed), {session.store?.calls.write ?? 0} writes.
        </p>
      </section>
    </div>
  )
}

function FrameView({ frame }: { frame: Frame }) {
  const kindName: Record<string, string> = { u: "edit", s: "snapshot", c: "snapshot chunk", a: "member list", j: "join request", v: "published version" }
  const h = frame.header
  return (
    <dl className="kv2">
      <dt>kind</dt>
      <dd>{kindName[frame.kind] ?? frame.kind}</dd>
      <dt>epoch</dt>
      <dd>{frame.kind === "a" ? String(h.epoch) : frame.epoch}</dd>
      {frame.kind === "a" && Array.isArray(h.members) && (
        <>
          <dt>members</dt>
          <dd>{(h.members as { name: string }[]).map((m) => m.name || "Unnamed").join(", ")}</dd>
        </>
      )}
      {frame.kind === "a" && typeof h.roster === "string" && (
        <>
          <dt>roster</dt>
          <dd>sealed under the epoch key</dd>
        </>
      )}
      {typeof h.t === "number" && (
        <>
          <dt>written</dt>
          <dd>{new Date(h.t).toLocaleTimeString()}</dd>
        </>
      )}
      {typeof h.base === "string" && (
        <>
          <dt>covers to</dt>
          <dd>#{h.base}</dd>
        </>
      )}
      <dt>content</dt>
      <dd>{frame.data.length} B of Yjs data, padded</dd>
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
  if (!entries.length) return <div className="panel-card muted">History starts at the newest snapshot. Edits made after it show up here.</div>
  const idx = Math.min(i ?? entries.length - 1, entries.length - 1)
  const at = entries[idx]!
  const text = plainText(p.stateAt(at.block))
  const pct = entries.length > 1 ? (idx / (entries.length - 1)) * 100 : 100

  async function verify() {
    if (!session.store) return
    setCheck("Reading the document from Arkiv as of that block…")
    try {
      const past = await loadAt(session.store, link, at.block, p!.identity)
      setCheck(plainText(past) === text ? `Matches what Arkiv held at block ${at.block}.` : `Arkiv at block ${at.block} differs. An edit in the same block may be newer.`)
    } catch (e) {
      setCheck((e as Error).message)
    }
  }

  return (
    <div className="panel-card">
      <input
        className="range"
        type="range"
        min={0}
        max={entries.length - 1}
        value={idx}
        style={{ "--val": `${pct}%` } as React.CSSProperties}
        onChange={(e) => (setI(Number(e.target.value)), setCheck(null))}
        aria-label="Edit history"
      />
      <div className="row">
        <span className="small mono">block {at.block.toString()}</span>
        <Addr a={at.author} />
      </div>
      <pre className="preview">{text || "(empty)"}</pre>
      <button className="btn btn-outline" onClick={verify}>
        Check against Arkiv at this block
      </button>
      {check && <p className="muted small">{check}</p>}
      <p className="muted small">The slider replays edits locally. The check rebuilds the document with atBlock reads and compares.</p>
    </div>
  )
}

// ------------------------------------------------------------------ lifetime

const KEEP = [
  { label: "90 days", s: 90 * 86400 },
  { label: "1 year", s: 365 * 86400 },
  { label: "3 years", s: 3 * 365 * 86400 },
]

export function LifetimePanel({ session }: { session: DocumentSession }) {
  const p = session.provider
  const [head, setHead] = useState<bigint | null>(null)
  const { busy, run, view } = useAction()
  useEffect(() => {
    if (!session.store) return
    session.store.head().then(setHead, () => undefined)
  }, [session.store, session.tick])
  if (!p) return null
  const writer = p.role === "owner" || p.role === "writer"
  const left = p.snapshot && head !== null ? p.snapshot.expiresAt - head : null
  const aclLeft = p.aclExpiresAt !== null && head !== null ? p.aclExpiresAt - head : null
  const total = 15 * 86400 * 2 // 30 days in blocks of 2 s
  const pct = left === null ? 0 : Math.max(2, Math.min(100, (Number(left) / total) * 100))
  return (
    <div className="panel-card">
      <section>
        <h4>This document lives for</h4>
        <div className="big" style={{ fontSize: 34 }}>
          {left === null ? "…" : blocksToDuration(left)}
        </div>
        <div className="meter" style={{ marginTop: 10 }}>
          <i style={{ width: `${pct}%` }} />
        </div>
        <p className="muted small" style={{ marginTop: 10 }}>
          The newest snapshot is a lease. When a member opens the document past its halfway mark, it is renewed. If nobody opens it, it expires and Arkiv forgets it. Only the document's own members can renew it.
        </p>
      </section>
      {p.role === "owner" && (
        <section>
          <h4>Keep it longer</h4>
          <div className="row wrap" style={{ gap: 8 }}>
            {KEEP.filter((k) => aclLeft === null || BigInt(Math.ceil(k.s / 2)) > aclLeft).map((k) => (
              <button key={k.s} className="btn btn-outline" disabled={!!busy} onClick={() => run("extending", async () => (await p.keepFor(k.s), `Kept for ${k.label}. Later snapshots honour it.`))}>
                {k.label}
              </button>
            ))}
          </div>
          <h4 style={{ marginTop: 16 }}>Or end it now</h4>
          <button
            className="btn btn-outline danger"
            disabled={!!busy}
            onClick={() =>
              confirm("Delete this document? The member list goes, so nobody can open it again. Members' remaining encrypted pieces expire on their own within 30 days.") &&
              run("deleting", async () => `Deleted ${await p.deleteDocument()} entities. The document no longer opens.`)
            }
          >
            Delete document
          </button>
        </section>
      )}
      {writer && (
        <section>
          <h4>Publish a frozen copy</h4>
          <p className="muted small">A readonly version with its own key. Nobody can change it, and anyone holding its link can keep it alive.</p>
          <button
            className="btn btn-outline"
            disabled={!!busy}
            onClick={() =>
              run("publishing", async () => {
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
          <h4>Shred my edit history</h4>
          <p className="muted small">
            Deletes every edit and join request your key wrote here, in one transaction. Your words stay in the shared text, and in snapshots other members wrote, until someone removes them or those expire.
          </p>
          <button className="btn btn-outline danger" disabled={!!busy} onClick={() => confirm("Delete your edit history for this document?") && run("shredding", async () => `Deleted ${await p.shredMine()} entities.`)}>
            Shred my edit history
          </button>
        </section>
      )}
      {view}
    </div>
  )
}
