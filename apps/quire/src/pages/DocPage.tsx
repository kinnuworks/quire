import Collaboration from "@tiptap/extension-collaboration"
import Placeholder from "@tiptap/extension-placeholder"
import { EditorContent, useEditor } from "@tiptap/react"
import StarterKit from "@tiptap/starter-kit"
import { useEffect, useRef, useState } from "react"
import { type DocLink, earlierWriters, type Identity, type StoredEntity } from "y-arkiv"
import { AuthorshipBars, blockAuthors, setMembers } from "../authorship"
import { rotatedNow, rotationDue } from "../autorotate"
import { ensureGas, fundFromWallet, hasWallet, WALLET_WARNING, waitForGas } from "../gas"
import { ActivityPanel, ChainPanel, HistoryPanel, LifetimePanel, PeoplePanel } from "../panels"
import { identityFor, newIdentity, preferredName, saveIdentity, setPreferredName, shareUrl } from "../session"
import { useDocument } from "../useDocument"

type Tab = "people" | "activity" | "chain" | "history" | "lifetime"
/** Shown when Arkiv's free read budget for this network is used up. Nothing is lost; the page retries by itself. */
function BudgetCard({ retryAt, relay, ownNode, useRelay }: { retryAt: number; relay: boolean; ownNode: boolean; useRelay: () => void }) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [])
  const left = Math.max(0, Math.ceil((retryAt - now) / 1000))
  return (
    <div className="ws-banner accent budget">
      <div>
        <b>Arkiv's free reads for your network are used up for now.</b>
        <p className="small">
          The public RPC gives every IP address a small query budget, and it refills on its own. Your document and its link are safe. This page reconnects in {Math.floor(left / 60)}:{String(left % 60).padStart(2, "0")}, or try from another network.
        </p>
        {ownNode ? (
          <p className="small">You chose your own Arkiv node (Explorer tab), so Quire's relay stays off: it forwards to the public endpoint.</p>
        ) : relay ? (
          <p className="small">Quire's relay is busy too. It will be tried again when the page reconnects.</p>
        ) : (
          <>
            <p className="small">
              Or use Quire's relay for this tab. It forwards only the document queries to Arkiv with our access key. It sees what Arkiv's RPC sees: your IP address, this document's id and its members' addresses. It never sees the text, names, keys or the link, and keeps nothing. Live edits and writes still go straight to Arkiv.
            </p>
            <button className="btn btn-sm btn-outline" onClick={useRelay}>
              Use Quire's relay
            </button>
          </>
        )}
      </div>
    </div>
  )
}

const TABS: { id: Tab; label: string }[] = [
  { id: "people", label: "People" },
  { id: "activity", label: "Live" },
  { id: "chain", label: "Explorer" },
  { id: "history", label: "History" },
  { id: "lifetime", label: "Lifetime" },
]

export function DocPage({ link }: { link: DocLink }) {
  const [identity, setIdentity] = useState<Identity | undefined>(() => identityFor(link.doc))
  const session = useDocument(link, identity)
  const { provider, doc } = session
  const [tab, setTab] = useState<Tab>("people")
  const [blame, setBlame] = useState(false)
  const [copied, setCopied] = useState(false)
  const blameRef = useRef(blame)
  blameRef.current = blame
  const providerRef = useRef(provider)
  providerRef.current = provider
  const [joinState, setJoinState] = useState<"idle" | "gas" | "owner-gas" | "asking" | "error">("idle")
  const [joinError, setJoinError] = useState<string | null>(null)
  const [wantJoin, setWantJoin] = useState(false)

  const role = provider?.role ?? "reader"
  const editable = role === "owner" || role === "writer"
  const synced = provider?.status === "synced"

  const editor = useEditor(
    {
      extensions: [
        StarterKit.configure({ undoRedo: false }),
        Collaboration.configure({ document: doc }),
        Placeholder.configure({ placeholder: "Start writing. Members see it a few seconds later." }),
        AuthorshipBars.configure({ doc, provider: () => providerRef.current, enabled: () => blameRef.current }),
      ],
      editable: false,
    },
    [doc],
  )

  useEffect(() => {
    editor?.setEditable(editable && synced)
  }, [editor, editable, synced])

  // members get palette colors in member-list order
  if (provider?.acl && !provider.acl.rosterHidden) setMembers(provider.acl.members.map((m) => m.address))

  useEffect(() => {
    // redraw the authorship bars when they are toggled or authorship changes
    if (editor && !editor.isDestroyed) editor.view.dispatch(editor.state.tr.setMeta("authorship", true))
  }, [editor, blame, session.tick])

  // "who wrote what" checks every edit still on chain, so it can also say who typed a passage first
  useEffect(() => {
    if (blame && !session.fullHistory) session.loadFullHistory()
  }, [blame, session.fullHistory])
  // an owner who erases someone from the member list hides their edits from the everyday read, so on
  // open the app walks the list's history; if anyone was erased, or the walk was cut short (the RPC's
  // read budget, a list renewed thousands of times), it checks every edit, toggle or not, and tries the
  // walk once more a minute later, when the budget has refilled
  const [erased, setErased] = useState<string[]>([])
  const [walkIncomplete, setWalkIncomplete] = useState(false)
  // entities older than the member list in use: the owner deleted the list and made a new one
  const [older, setOlder] = useState<{ entities: StoredEntity[]; truncated: boolean; listAt: bigint } | null>(null)
  const erasureChecked = useRef("")
  const retry = useRef<ReturnType<typeof setTimeout>>(undefined)
  useEffect(() => () => clearTimeout(retry.current), [])
  useEffect(() => {
    if (!provider || provider.status !== "synced" || erasureChecked.current === link.doc) return
    erasureChecked.current = link.doc
    const loadFull = session.loadFullHistory
    const check = (again: boolean) => {
      // the provider in use by then: loading every edit opens a new one
      const p = providerRef.current ?? provider
      p.erasedMembers().then(
        (found) => {
          setErased(found)
          setWalkIncomplete(p.listWalkIncomplete)
          if (found.length || p.listWalkIncomplete) loadFull()
          if (p.listWalkIncomplete && again) retry.current = setTimeout(() => check(false), 65_000)
        },
        () => setWalkIncomplete(true),
      )
    }
    check(true)
    provider.predatingEntities().then(
      (entities) => setOlder({ entities, truncated: provider.predatingTruncated, listAt: provider.aclCreatedAt }),
      () => undefined,
    )
  }, [provider, provider?.status, link.doc])
  // the copy note replays every edit, so it runs again only when the set of edits changes, not on every render
  const historyLength = provider?.history.length ?? 0
  const copyCheck = (blame || erased.length > 0) && session.fullHistory && provider?.status === "synced"
  // the note replays every edit, which takes a moment on a long document: work it out once editing has
  // paused for a second and a half, never inside a render, so typing never waits for it
  const [copies, setCopies] = useState<ReturnType<typeof earlierWriters>>([])
  useEffect(() => {
    if (!copyCheck || !provider) {
      setCopies([])
      return
    }
    const timer = setTimeout(() => setCopies(earlierWriters(doc, provider)), 1500)
    return () => clearTimeout(timer)
  }, [copyCheck, provider, doc, historyLength])

  // scheduled rotation: the owner turned it on and a full period has passed since the last one
  const rotating = useRef(false)
  useEffect(() => {
    if (!provider || provider.status !== "synced" || provider.role !== "owner" || rotating.current || !rotationDue(link.doc)) return
    rotating.current = true
    provider.rotateKey().then(
      () => rotatedNow(link.doc),
      () => undefined,
    ).finally(() => (rotating.current = false))
  }, [provider, session.tick, link.doc])

  // after a fresh identity connects, send its join request
  useEffect(() => {
    if (!wantJoin || !provider || provider.status !== "synced" || provider.role !== "reader") return
    setWantJoin(false)
    setJoinState("asking")
    provider.requestJoin().then(
      () => setJoinState("idle"),
      (e: Error) => {
        setJoinError(e.message)
        setJoinState("error")
      },
    )
  }, [wantJoin, provider, session.tick])

  function joinerKey(): Identity | null {
    const name = (identity?.name ?? prompt("Your name in this document (a pseudonym is fine)", preferredName()) ?? "").trim()
    if (!name) return null
    setPreferredName(name)
    const id = identity ?? newIdentity(name)
    saveIdentity(link.doc, id)
    return id
  }

  // gas from the owner instead of the drip: the joiner passes on their address, the owner sends gas from
  // the document's key, and the join request goes out once it lands
  function joinWithOwnerGas() {
    setJoinError(null)
    const id = joinerKey()
    if (!id) return
    setIdentity(id)
    setJoinState("owner-gas")
  }
  useEffect(() => {
    if (joinState !== "owner-gas" || !identity) return
    let stopped = false
    waitForGas(identity.address, () => stopped).then((ok) => ok && !stopped && setWantJoin(true))
    return () => {
      stopped = true
    }
  }, [joinState, identity?.address])

  async function join(viaWallet = false) {
    setJoinError(null)
    if (viaWallet && !confirm(WALLET_WARNING)) return
    const id = joinerKey()
    if (!id) return
    setJoinState("gas")
    const gas = viaWallet ? await fundFromWallet(id.address) : await ensureGas(id.address)
    if (!gas.ok) {
      // keep the key so funding it by hand and retrying works
      setIdentity(id)
      setJoinError(`${gas.reason} Your key for this document is ${id.address}.`)
      setJoinState("error")
      return
    }
    setIdentity(id)
    setWantJoin(true)
  }

  function copyInvite() {
    navigator.clipboard?.writeText(shareUrl(link))
    setCopied(true)
    setTimeout(() => setCopied(false), 1600)
  }

  const statusClass = provider?.status === "synced" ? "synced" : provider?.status === "error" ? "error" : ""
  const sealed = !!provider?.acl?.rosterHidden
  const statusText = synced && provider?.livePaused
    ? "Synced · live paused"
    : synced
    ? sealed
      ? "Sealed · no key"
      : role === "owner"
        ? "Synced · owner"
        : role === "writer"
          ? "Synced · writer"
          : "Synced · read only"
    : provider?.status === "error"
      ? "Connection problem"
      : "Connecting"

  return (
    <div className="ws">
      <header className="ws-bar">
        <a className="brand" href="#/">
          <span className="app-icon" />
          Quire
        </a>
        <span className={`status ${statusClass}`}>
          <span className="s-dot" />
          {statusText}
          {session.relay && <span title="Document queries go through Quire's relay for this tab (see the budget notice)"> · via relay</span>}
        </span>
        <div className="spacer" />
        <label className="toggle-row">
          <input className="switch" type="checkbox" checked={blame} onChange={(e) => setBlame(e.target.checked)} />
          Who wrote what
        </label>
        <button className="btn btn-sm btn-candy" onClick={copyInvite} title="The link carries the document key: anyone who sees it can read the document. Send it over an end-to-end encrypted channel such as Signal, not email or a work chat.">
          {copied ? "Copied" : "Copy invite link"}
        </button>
      </header>

      {session.error?.kind === "budget" && <BudgetCard retryAt={session.error.retryAt} relay={session.relay} ownNode={!!session.node} useRelay={session.useRelay} />}
      {session.error?.kind === "other" && <div className="ws-banner error">{session.error.message}</div>}
      {role === "reader" && synced && (
        <div className="ws-banner accent">
          <span>
            {provider?.canRead
              ? "You are reading this document."
              : `The owner has rotated this document's key since this link was made, so the link alone opens nothing new: you can see that the document exists and has ${provider?.acl?.wraps.length ?? 0} members. Ask to join, and once the owner adds you, you read everything.`}
          </span>
          {joinState === "idle" && (
            <>
              <button className="btn btn-sm btn-ink" onClick={() => join(false)}>
                Ask to join as a writer
              </button>
              <button className="btn btn-sm btn-ghost" onClick={joinWithOwnerGas} title="Quire's gas drip sees the IP address that asks for gas. Getting gas from the owner keeps it out of the picture.">
                Get gas from the owner
              </button>
            </>
          )}
          {joinState === "owner-gas" && identity && (
            <span className="small">
              Send this address to the owner over the same channel as the link: <code className="mono">{identity.address}</code>{" "}
              <button className="link-button" onClick={() => navigator.clipboard?.writeText(identity.address)}>
                Copy
              </button>
              . They send gas from the document's key (People, Send gas to someone joining), so Quire's drip never sees you. Waiting for it…
            </span>
          )}
          {joinState === "gas" && <span className="muted">Funding your key…</span>}
          {joinState === "asking" && <span className="muted">Sending your request…</span>}
          {joinState === "error" && (
            <>
              <span className="error small">{joinError}</span>
              <button className="btn btn-sm btn-outline" onClick={() => join(false)}>
                Try again
              </button>
              {hasWallet() && (
                <button className="btn btn-sm btn-ghost" onClick={() => join(true)}>
                  Fund from my wallet
                </button>
              )}
            </>
          )}
        </div>
      )}
      {role === "pending" && (
        <div className="ws-banner">
          Request sent. The owner sees it live and can add you. If they can't find it, send them your address: <code className="mono">{identity?.address}</code>
        </div>
      )}

      {blame && !session.fullHistory && session.provider && blockAuthors(doc, session.provider).flat().some((a) => !a.proven) && (
        <div className="ws-banner">
          Dashed bars are claimed: that text reached you inside a snapshot, so only the snapshot's writer vouches for it.{" "}
          <button className="link-button" onClick={session.loadFullHistory}>
            Check every edit still on chain
          </button>{" "}
          to prove it from the edits themselves.
        </div>
      )}

      {erased.length > 0 && (
        <div className="ws-banner accent">
          <span>
            <b>The owner erased {erased.length === 1 ? "a member" : `${erased.length} members`} from the member list:</b> {erased.map((a) => `${a.slice(0, 8)}…${a.slice(-4)}`).join(", ")}. Earlier versions of the list, read from the chain, still name them, so Quire checked every edit still on chain: what they wrote while members is applied and proven as theirs wherever it still stands. Text of theirs that was deleted is not in today's version, and if someone pasted or re-typed it, plain blame credits whoever did; a note below says who typed it first, and <code>y-arkiv blame --at &lt;block&gt;</code> shows it proven as theirs at that block.
          </span>
        </div>
      )}

      {older && older.entities.length > 0 && (
        <div className="ws-banner accent">
          <span>
            <b>The owner deleted the member list and made a new one.</b> {older.entities.length} {older.entities.length === 1 ? "entity on chain predates" : "entities on chain predate"} the list in use (made at block {String(older.listAt)}), written by {[...new Set(older.entities.map((e) => e.creator.toLowerCase()))].map((a) => `${a.slice(0, 8)}…${a.slice(-4)}`).join(", ")}. This page reads only what came after the new list, so whatever they wrote before it is not shown here. Run <code>y-arkiv blame --at {String(older.listAt - 1n)}</code> to read the earlier document and see who wrote it.
          </span>
        </div>
      )}
      {older && !older.entities.length && older.truncated && (
        <div className="ws-banner">
          <span>
            <b>Not checked to the end:</b> over 1,000 entities are stamped before this member list (made at block {String(older.listAt)}), so the app could not rule out an earlier list. Run <code>y-arkiv verify</code> to check.
          </span>
        </div>
      )}

      {(walkIncomplete || (session.fullHistory && provider?.status === "synced" && (provider.auditNarrowed || provider.auditUnchecked > 0))) && (
        <div className="ws-banner">
          <span>
            <b>This check is incomplete.</b>{" "}
            {(walkIncomplete || provider?.auditNarrowed) && (provider?.listWalkCut ? "The member list has more versions than the app will read, so someone the owner erased may not be named. Quire loaded every edit it can read instead. " : "The member list's history could not be read to its first version (the network's read limit, or a version this key cannot open), so someone the owner erased may not be named. Quire loaded every edit it can read instead and tries the list again in a minute. ")}
            {provider?.auditNarrowed && "The document also holds more entities than the app reads unfiltered. "}
            {provider && provider.auditUnchecked > 0 && `${provider.auditUnchecked} ${provider.auditUnchecked === 1 ? "edit was" : "edits were"} judged by today's member list because the list at ${provider.auditUnchecked === 1 ? "its" : "their"} block could not be read. `}
            Run <code>y-arkiv blame</code>, which waits out the network's read limit.
          </span>
        </div>
      )}

      {copies.map((c) => (
        <div className="ws-banner accent" key={`${c.block}-${c.first}-${c.text.slice(0, 24)}`}>
          <span>
            <b>Typed first by someone else.</b> “{c.text.length > 80 ? `${c.text.slice(0, 77)}…` : c.text}” is proven as {c.address.slice(0, 8)}…{c.address.slice(-4)}'s writing, finished at block {String(c.block)}, but {c.first.slice(0, 8)}…{c.first.slice(-4)} typed the same words, or all but a few, earlier, at blocks {String(c.from)} to {String(c.to)}. Run <code>y-arkiv blame --at {String(c.block - 1n)}</code>, the block before that edit, to see them proven as theirs.
          </span>
        </div>
      ))}

      <main className="ws-main">
        <article className={`sheet ${blame ? "blame" : ""}`}>
          <EditorContent editor={editor} />
        </article>
        <aside className="side">
          <div className="segmented" role="tablist">
            {TABS.map((t) => (
              <button key={t.id} role="tab" aria-selected={tab === t.id} onClick={() => setTab(t.id)}>
                {t.label}
                {t.id === "people" && provider?.role === "owner" && provider.joinRequests.length > 0 && <span className="badge-n">{provider.joinRequests.length}</span>}
              </button>
            ))}
          </div>
          {tab === "people" && <PeoplePanel session={session} identity={identity} link={link} />}
          {tab === "activity" && <ActivityPanel session={session} />}
          {tab === "chain" && <ChainPanel session={session} />}
          {tab === "history" && <HistoryPanel session={session} link={link} />}
          {tab === "lifetime" && <LifetimePanel session={session} />}
        </aside>
      </main>
    </div>
  )
}
