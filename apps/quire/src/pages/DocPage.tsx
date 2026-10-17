import Collaboration from "@tiptap/extension-collaboration"
import Placeholder from "@tiptap/extension-placeholder"
import { EditorContent, useEditor } from "@tiptap/react"
import StarterKit from "@tiptap/starter-kit"
import { useEffect, useRef, useState } from "react"
import type { DocLink, Identity } from "y-arkiv"
import { AuthorshipBars, blockAuthors, setMembers } from "../authorship"
import { ensureGas, fundFromWallet, hasWallet, WALLET_WARNING } from "../gas"
import { ActivityPanel, ChainPanel, HistoryPanel, LifetimePanel, PeoplePanel } from "../panels"
import { identityFor, newIdentity, preferredName, saveIdentity, setPreferredName, shareUrl } from "../session"
import { useDocument } from "../useDocument"

type Tab = "people" | "activity" | "chain" | "history" | "lifetime"
/** Shown when Arkiv's free read budget for this network is used up. Nothing is lost; the page retries by itself. */
function BudgetCard({ retryAt, relay, useRelay }: { retryAt: number; relay: boolean; useRelay: () => void }) {
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
        {relay ? (
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
  const [joinState, setJoinState] = useState<"idle" | "gas" | "asking" | "error">("idle")
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
        Placeholder.configure({ placeholder: "Start writing. Members see it a block or two later." }),
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

  async function join(viaWallet = false) {
    setJoinError(null)
    if (viaWallet && !confirm(WALLET_WARNING)) return
    const name = (identity?.name ?? prompt("Your name in this document (a pseudonym is fine)", preferredName()) ?? "").trim()
    if (!name) return
    setPreferredName(name)
    const id = identity ?? newIdentity(name)
    saveIdentity(link.doc, id)
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
  const statusText = synced
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
        <button className="btn btn-sm btn-candy" onClick={copyInvite} title="The link carries the document key. Share it only with people who should read it.">
          {copied ? "Copied" : "Copy invite link"}
        </button>
      </header>

      {session.error?.kind === "budget" && <BudgetCard retryAt={session.error.retryAt} relay={session.relay} useRelay={session.useRelay} />}
      {session.error?.kind === "other" && <div className="ws-banner error">{session.error.message}</div>}
      {role === "reader" && synced && (
        <div className="ws-banner accent">
          <span>
            {provider?.canRead
              ? "You are reading this document."
              : `This document's text and member list are sealed under a key this link does not carry. You can see that it exists and has ${provider?.acl?.wraps.length ?? 0} members, and nothing else.`}
          </span>
          {joinState === "idle" && (
            <button className="btn btn-sm btn-ink" onClick={() => join(false)}>
              Ask to join as a writer
            </button>
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
