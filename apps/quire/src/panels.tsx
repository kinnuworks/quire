import { render } from "@arkiv-network/sdk/query"
import { useEffect, useState } from "react"
import { privateKeyToAccount } from "viem/accounts"
import { type ArkivProvider, type DocLink, formatDocLink, formatVersionLink, type Frame, type Hex, type Identity, KIND, loadAt, type StoredEntity, toExpression, updateFilter } from "y-arkiv"
import { autoRotateSetting, ROTATE_EVERY_DAYS, rotatedNow, setAutoRotate } from "./autorotate"
import { colorOf } from "./authorship"
import { addressUrl, blocksToDuration, entityUrl, hexPreview, plainText, short, txUrl } from "./format"
import { balanceOf, formatGlm } from "./gas"
import { forgetDocument } from "./session"
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
      {identity && <ProveKey identity={identity} link={link} />}

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
      {owner && <FindRequest p={p} busy={!!busy} run={run} />}
      {owner && <RotateKey p={p} busy={!!busy} run={run} />}

      <section>
        <h4>Members · epoch {p.acl.epoch}</h4>
        {p.acl.rosterHidden ? (
          <p className="small">
            <span className="big">{p.acl.wraps.length}</span> <span className="muted">members. Their names and addresses are sealed under the current key, which this link does not carry.</span>
          </p>
        ) : (
          p.acl.members.map((m) => (
            <div className="row" key={m.address}>
              <Addr a={m.address} label={`${m.name || "Unnamed"} · ${short(m.address)}`} />
              {owner && m.role !== "owner" ? (
                <button
                  className="btn btn-outline danger"
                  disabled={!!busy}
                  onClick={() =>
                    confirm(`Remove ${m.name}? The key rotates and they stop receiving new edits. What they wrote while a member stays proven.`) &&
                    run("removing", async () => {
                      const shredOldEpoch = confirm(SHRED_OLD_QUESTION)
                      const r = await p.revoke(m.address, { shredOldEpoch })
                      return `Removed. New edits use epoch ${p.acl!.epoch}.${shredOldEpoch ? ` Deleted ${r.shredded} of your entities from earlier epochs.` : ""}`
                    })
                  }
                >
                  Remove
                </button>
              ) : (
                <span className="pill-tag">{m.role}</span>
              )}
            </div>
          ))
        )}
        {!p.acl.rosterHidden && <p className="muted small">Readers apply an edit only if its on-chain creator is in this list. Removing someone rotates the key for everyone who stays.</p>}
      </section>

      {!p.acl.rosterHidden && <OutsideWrites p={p} />}
      <section>
        <h4>This browser</h4>
        <p className="muted small">This browser keeps the document's link{identity ? " and your key" : ""} so you can reopen it. On a shared computer, remove it.</p>
        <button className="btn btn-ghost" onClick={() => confirm("Remove this document's link" + (identity ? " and your key" : "") + " from this browser?") && (forgetDocument(link.doc), (location.hash = "#/"))}>
          Forget this document
        </button>
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
          <span className="muted small">{session.provider?.livePaused ? "queries; live edits are paused, so the page checks by query, less often each time" : "queries; live edits use none"}</span>
        </div>
      </section>
      <ul className="feed">
        {session.activity.length === 0 && <li className="muted">{session.provider?.role === "owner" || session.provider?.role === "writer" ? "Nothing yet. Type something, or open the invite link in a private window." : "Nothing yet. New edits appear here a few seconds after a member types."}</li>}
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
  const target = key ?? latest ?? p?.snapshot?.key ?? p?.aclKey ?? undefined
  useEffect(() => {
    if (!p || !target) return
    let alive = true
    p.inspect(target).then((v) => alive && setView(v), () => alive && setView(null))
    return () => {
      alive = false
    }
  }, [p, target])
  if (!p) return null
  const base = p.snapshot?.base ?? 0n
  // the exact filter readers send: the window, the qs ceiling, members, and removed members bounded at their removal
  const from = base > 60n ? base - 60n : 0n
  const sample = render(toExpression({ doc: p.link.doc, kind: KIND.update, seqGte: from, seqLte: p.qsCeiling(), ...(p.acl ? updateFilter(p.acl, from) : {}) }))

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
        <p className="muted">{target ? "Reading that entity from Arkiv… (if this stays, the free query budget may be used up for now)" : "Write something, then look here."}</p>
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
          <dt>members</dt>
          <dd>{Array.isArray(h.wraps) ? h.wraps.length : 0} (one sealed key each)</dd>
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
      {frame.data.length > 0 && (
        <>
          <dt>content</dt>
          <dd>{frame.data.length} B of Yjs data, padded</dd>
        </>
      )}
    </dl>
  )
}

// ------------------------------------------------------------------ history

export function HistoryPanel({ session, link }: { session: DocumentSession; link: DocLink }) {
  const p = session.provider
  const entries = p?.history ?? []
  const [i, setI] = useState<number | null>(null)
  const [cache, setCache] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState<string | null>(null)
  if (!p) return null
  const older = !session.fullHistory && (
    <p className="muted small">
      Edits older than the newest snapshot are still on chain for up to 30 days, but opening skips them to save queries.{" "}
      <button className="link-button" onClick={session.loadFullHistory}>
        Load every edit still on chain
      </button>
      , which also proves who wrote the older text.
    </p>
  )
  if (!entries.length)
    return (
      <div className="panel-card">
        <p className="muted small">{session.fullHistory ? "No edits from members are left on chain: they expired or were shredded. The text comes from snapshots alone." : "No edits since the newest snapshot."}</p>
        {older}
      </div>
    )
  const idx = Math.min(i ?? entries.length - 1, entries.length - 1)
  const at = entries[idx]!
  const key = at.block.toString()
  const pct = entries.length > 1 ? (idx / (entries.length - 1)) * 100 : 100

  // every position is rebuilt from Arkiv itself with atBlock reads (three queries), then cached
  async function rebuild() {
    if (!session.store || cache[key] !== undefined) return
    setLoading(key)
    try {
      const past = await loadAt(session.store, link, at.block, p!.identity)
      setCache((c) => ({ ...c, [key]: plainText(past) }))
    } catch (e) {
      setCache((c) => ({ ...c, [key]: `Could not read block ${key}: ${(e as Error).message.split("\n")[0]}` }))
    } finally {
      setLoading(null)
    }
  }

  return (
    <div className="panel-card">
      <p className="muted small">
        Each step is one edit that is still on chain. Pick a step and Quire rebuilds the document exactly as Arkiv held it at that block, using atBlock reads. Nothing local is used.
      </p>
      <input
        className="range"
        type="range"
        min={0}
        max={entries.length - 1}
        value={idx}
        style={{ "--val": `${pct}%` } as React.CSSProperties}
        onChange={(e) => setI(Number(e.target.value))}
        aria-label="Edit history"
      />
      <div className="row">
        <span className="small mono">
          step {idx + 1} of {entries.length} · block {key}
        </span>
        <Addr a={at.author} />
      </div>
      {cache[key] !== undefined ? (
        <pre className="preview">{cache[key] || "(empty)"}</pre>
      ) : (
        <button className="btn btn-outline" disabled={loading !== null} onClick={rebuild}>
          {loading === key ? "Reading from Arkiv…" : "Rebuild from Arkiv at this block"}
        </button>
      )}
      <p className="muted small">Each rebuild costs three queries from your network's free budget.</p>
      {older}
    </div>
  )
}

// ------------------------------------------------------------------ lifetime

const KEEP = [
  { label: "90 days", s: 90 * 86400 },
  { label: "1 year", s: 365 * 86400 },
  { label: "3 years", s: 3 * 365 * 86400 },
]

const SHRED_OLD_QUESTION =
  "Also delete your own entities from before this rotation? The old link would then no longer open your earlier text from Arkiv's state, but that text would read as vouched for by your new snapshot rather than proven edit by edit. Block history keeps the old ciphertext either way. OK deletes them; Cancel keeps them."

/** Owner: a new key for everyone who stays, so a link that may have leaked opens nothing written from now on. */
function RotateKey({ p, busy, run }: { p: ArkivProvider; busy: boolean; run: (what: string, fn: () => Promise<string | void>) => Promise<void> }) {
  const [auto, setAuto] = useState(() => autoRotateSetting(p.link.doc).on)
  return (
    <section>
      <h4>Rotate the key</h4>
      <p className="muted small">
        The link carries only the first key. Rotating seals a new one to each member, so anyone holding just the link, including a link that leaked, reads nothing written from now on. They can still ask to join, and you decide. What was written before stays readable to the old link while it lives, and in block history for good.
      </p>
      <button
        className="btn btn-outline"
        disabled={busy}
        onClick={() =>
          confirm("Rotate the key? Members keep reading and writing; the link alone stops opening new text.") &&
          run("rotating", async () => {
            const shredOldEpoch = confirm(SHRED_OLD_QUESTION)
            const r = await p.rotateKey({ shredOldEpoch })
            rotatedNow(p.link.doc)
            return `Now on epoch ${p.acl!.epoch}.${shredOldEpoch ? ` Deleted ${r.shredded} of your entities from earlier epochs.` : ""}`
          })
        }
      >
        Rotate the key
      </button>
      <label className="toggle-row" style={{ marginTop: 12 }}>
        <input
          className="switch"
          type="checkbox"
          checked={auto}
          onChange={(e) => {
            setAutoRotate(p.link.doc, e.target.checked)
            setAuto(e.target.checked)
          }}
        />
        Rotate it for me every {ROTATE_EVERY_DAYS} days
      </label>
      <p className="muted small">
        When you open the document and {ROTATE_EVERY_DAYS} days have passed since the last rotation, this browser rotates the key first. A leaked link then opens at most a month of writing. Anyone who reads by link alone has to ask to join after each rotation. The setting lives in this browser only.
      </p>
    </section>
  )
}

/**
 * Writes kept out. The normal reads ask only for members' entities, so outside writes never even
 * arrive; one extra query, run once when this panel opens, lists them.
 */
function OutsideWrites({ p }: { p: ArkivProvider }) {
  const [outside, setOutside] = useState<Hex[] | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    let alive = true
    p.scanOutsiders().then((n) => alive && setOutside(n), () => alive && setFailed(true))
    return () => {
      alive = false
    }
  }, [p])
  const creators = outside ? [...new Set(outside)] : []
  return (
    <section>
      <h4>Writes kept out</h4>
      <p>
        <span className="big">{outside === null ? (failed ? "?" : "…") : outside.length}</span>{" "}
        <span className="muted small">
          {outside === null
            ? failed
              ? "could not check the chain just now."
              : "checking the chain for entities from outside the member list (one query)."
            : `${outside.length === 1 ? "entity" : "entities"} on chain for this document from outside the member list${creators.length ? ` (${creators.map((x) => short(x)).join(", ")})` : ""}. None were applied.${p.outsidersTruncated ? " This checked the first 200 entities only, so a busy document may hold more." : ""}`}
        </span>
      </p>
      {p.stats.rejectedWrites > 0 && <p className="muted small">This tab also refused {p.stats.rejectedWrites} {p.stats.rejectedWrites === 1 ? "write" : "writes"} that arrived: from outside the list, under someone else's client id, or malformed.</p>}
    </section>
  )
}

/**
 * Proves to a reviewer that this browser holds the key behind an address, without handing over the
 * key: the reviewer picks a phrase, this signs "quire1:prove:<doc>:<phrase>", and anyone checks it with
 * `y-arkiv check-signature`. The prefix keeps the signature from passing as anything else Quire signs.
 */
function ProveKey({ identity, link }: { identity: Identity; link: DocLink }) {
  const [phrase, setPhrase] = useState("")
  const [sig, setSig] = useState<string | null>(null)
  const message = `quire1:prove:${link.doc}:${phrase}`
  return (
    <section>
      <h4>Prove this key is yours</h4>
      <p className="muted small">Ask the person checking for a phrase, sign it here, and send them the signature. They learn that you hold this key; the key itself never leaves the browser.</p>
      <div className="row">
        <input className="input" placeholder="Their phrase" value={phrase} onChange={(e) => (setPhrase(e.target.value), setSig(null))} />
        <button className="btn btn-outline" disabled={!phrase} onClick={async () => setSig(await privateKeyToAccount(identity.privateKey).signMessage({ message }))}>
          Sign
        </button>
      </div>
      {sig && (
        <pre className="preview small">{`y-arkiv check-signature ${identity.address} '${message.replace(/'/g, "'\\''")}' ${sig}`}</pre>
      )}
    </section>
  )
}

/** The document id is public, so junk requests can crowd the list. A $creator query finds one person's request regardless. */
function FindRequest({ p, busy, run }: { p: ArkivProvider; busy: boolean; run: (what: string, fn: () => Promise<string | void>) => Promise<void> }) {
  const [address, setAddress] = useState("")
  return (
    <section>
      <h4>Expecting someone?</h4>
      <p className="muted small">Ask them for the address on their "Request sent" banner. One query finds their request, however many others there are.</p>
      <div className="row">
        <input className="input mono" placeholder="0x…" value={address} onChange={(e) => setAddress(e.target.value.trim())} spellCheck={false} />
        <button
          className="btn btn-outline"
          disabled={busy || !/^0x[0-9a-fA-F]{40}$/.test(address)}
          onClick={() =>
            run("looking", async () => {
              const found = await p.findJoinRequest(address as `0x${string}`)
              return found ? `Found ${found.name || "their"} request. It is in the list above.` : "No request from that address in the last hour."
            })
          }
        >
          Find
        </button>
      </div>
    </section>
  )
}

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
  const total = (30 * 86400) / 2 // 30 days in blocks of 2 s
  const pct = left === null ? 0 : Math.max(2, Math.min(100, (Number(left) / total) * 100))
  return (
    <div className="panel-card">
      <section>
        <h4>This document lives for</h4>
        <div className="big" style={{ fontSize: 34 }}>
          {p.acl?.rosterHidden ? "sealed" : left === null ? "…" : blocksToDuration(left)}
        </div>
        <div className="meter" style={{ marginTop: 10 }}>
          <i style={{ width: `${pct}%` }} />
        </div>
        <p className="muted small" style={{ marginTop: 10 }}>
          The newest snapshot is a lease. When a member opens the document past its halfway mark, it is renewed. If nobody opens it, it expires from Arkiv's state. Only the document's own members can renew it. The member list lives 90 days from the owner's last visit, or until the date the owner chose, and only the owner can extend it. Old encrypted payloads can remain in block history, readable only with the old link.
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
              confirm(
                `Delete this document? The member list goes, so nobody can open it again. Your own entities are deleted now; other members' encrypted pieces expire on their own ${
                  p.acl?.keepUntil && head !== null && BigInt(p.acl.keepUntil) > head
                    ? `by block ${p.acl.keepUntil}, about ${Math.ceil(Number(BigInt(p.acl.keepUntil) - head) / 43200)} days from now, because you chose to keep it`
                    : "within 30 days"
                } (Quire never extends them past that date, though another client could keep renewing its own pieces a month at a time). Until then anyone holding the link could still decrypt them, though without the member list no reader can check them. And block history keeps every payload for good: deleting removes entities from Arkiv's state, not from the chain's past.`,
              ) &&
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
      {writer && (
        <section>
          <h4>Keep proof of what I wrote</h4>
          <p className="muted small">
            Readers prove who wrote what from each person's edits, which are written for the document's lease. This extends every edit your key wrote here and a snapshot of yours (your edits sit on text others wrote), so <code>y-arkiv blame</code> keeps proving your text for as long as the document lives. The owner sets that lifetime (keeping the document longer also keeps the member list your edits are checked against); proof cannot outlive it.
          </p>
          <button
            className="btn btn-outline"
            disabled={!!busy}
            onClick={() =>
              run("extending your edits", async () => {
                const r = await p.keepMyProof(3 * 365 * 86400)
                return r.extended ? `Extended ${r.extended} entities until block ${r.until}, when the document ends.` : "Everything of yours already lives as long as the document."
              })
            }
          >
            Keep my proof as long as the document
          </button>
        </section>
      )}
      {p.identity && (
        <section>
          <h4>Shred my edit history</h4>
          <p className="muted small">
            Deletes every edit and join request your key wrote here, in one transaction, after folding the text into a snapshot. Your words stay in the shared text until someone removes them. They then read as claimed rather than proven, because the edits that proved them are gone.
          </p>
          <button className="btn btn-outline danger" disabled={!!busy} onClick={() => confirm("Delete your edit history for this document? Your edits leave Arkiv's state, and your text then reads as claimed rather than proven. Block history keeps the old ciphertext for good, so anyone with the link and an archive of old blocks could still decrypt it.") && run("shredding", async () => `Deleted ${await p.shredMine()} entities.`)}>
            Shred my edit history
          </button>
        </section>
      )}
      {view}
    </div>
  )
}
