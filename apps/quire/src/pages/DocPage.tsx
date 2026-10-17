import Collaboration from "@tiptap/extension-collaboration"
import Placeholder from "@tiptap/extension-placeholder"
import { EditorContent, useEditor } from "@tiptap/react"
import StarterKit from "@tiptap/starter-kit"
import { useEffect, useRef, useState } from "react"
import type { DocLink, Identity } from "y-arkiv"
import { AuthorshipBars } from "../authorship"
import { ensureGas, fundFromWallet, hasWallet } from "../gas"
import { ActivityPanel, ChainPanel, HistoryPanel, LifetimePanel, PeoplePanel } from "../panels"
import { identityFor, newIdentity, preferredName, saveIdentity, setPreferredName, shareUrl } from "../session"
import { useDocument } from "../useDocument"

type Tab = "people" | "activity" | "chain" | "history" | "lifetime"

export function DocPage({ link }: { link: DocLink }) {
  const [identity, setIdentity] = useState<Identity | undefined>(() => identityFor(link.doc))
  const session = useDocument(link, identity)
  const { provider, doc } = session
  const [tab, setTab] = useState<Tab>("people")
  const [blame, setBlame] = useState(false)
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
        Placeholder.configure({ placeholder: "Start writing. Everyone in the member list sees it within a block or two." }),
        AuthorshipBars.configure({ doc, provider: () => providerRef.current, enabled: () => blameRef.current }),
      ],
      editable: false,
    },
    [doc],
  )

  useEffect(() => {
    editor?.setEditable(editable && synced)
  }, [editor, editable, synced])

  useEffect(() => {
    // redraw the authorship bars when they are toggled or authorship changes
    editor?.view.dispatch(editor.state.tr.setMeta("authorship", true))
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
    const name = (prompt("Your name in this document (a pseudonym is fine)", preferredName()) ?? "").trim()
    if (!name) return
    setPreferredName(name)
    const id = identity ?? newIdentity(name)
    saveIdentity(link.doc, { ...id, name })
    setJoinState("gas")
    const gas = viaWallet ? await fundFromWallet(id.address) : await ensureGas(id.address)
    if (!gas.ok) {
      setJoinError(gas.reason)
      setJoinState("error")
      return
    }
    setIdentity({ ...id, name })
    setWantJoin(true)
  }

  const copy = (text: string) => navigator.clipboard?.writeText(text)

  return (
    <div className="doc-layout">
      <header className="topbar">
        <a className="mark small" href="#/">
          Quire
        </a>
        <span className={`pill ${provider?.status ?? "connecting"}`}>{statusLabel(provider?.status, role)}</span>
        <div className="spacer" />
        <label className="toggle">
          <input type="checkbox" checked={blame} onChange={(e) => setBlame(e.target.checked)} /> Show who wrote what
        </label>
        <button onClick={() => copy(shareUrl(link))} title="The link carries the document key. Share it only with people you want to read it.">
          Copy invite link
        </button>
      </header>

      {session.error && <div className="banner error">{session.error}</div>}
      {role === "reader" && synced && (
        <div className="banner">
          {provider?.canRead ? "You can read this document." : "The owner rotated the document key. Ask them to add you again."}{" "}
          {joinState === "idle" && (
            <button className="primary" onClick={() => join(false)}>
              Ask to join as a writer
            </button>
          )}
          {joinState === "gas" && <span>Getting your key some test gas…</span>}
          {joinState === "asking" && <span>Sending your request…</span>}
          {joinState === "error" && (
            <span className="error">
              {joinError} {hasWallet() && <button onClick={() => join(true)}>Fund from my wallet</button>}
            </span>
          )}
        </div>
      )}
      {role === "pending" && <div className="banner">Request sent. The owner sees it live and can add you.</div>}

      <main className="doc-main">
        <article className={`page ${blame ? "blame" : ""}`}>
          <EditorContent editor={editor} />
        </article>
        <aside className="side">
          <nav className="tabs">
            {(["people", "activity", "chain", "history", "lifetime"] as Tab[]).map((t) => (
              <button key={t} className={tab === t ? "active" : ""} onClick={() => setTab(t)}>
                {tabLabel[t]}
                {t === "people" && provider?.role === "owner" && provider.joinRequests.length > 0 && <span className="badge">{provider.joinRequests.length}</span>}
              </button>
            ))}
          </nav>
          {tab === "people" && <PeoplePanel session={session} identity={identity} />}
          {tab === "activity" && <ActivityPanel session={session} />}
          {tab === "chain" && <ChainPanel session={session} />}
          {tab === "history" && <HistoryPanel session={session} link={link} />}
          {tab === "lifetime" && <LifetimePanel session={session} />}
        </aside>
      </main>
    </div>
  )
}

const tabLabel: Record<Tab, string> = {
  people: "People",
  activity: "Live",
  chain: "Explorer view",
  history: "History",
  lifetime: "Lifetime",
}

function statusLabel(status: string | undefined, role: string): string {
  if (status === "synced") return role === "owner" ? "Synced · owner" : role === "writer" ? "Synced · writer" : "Synced · read only"
  if (status === "error") return "Connection problem"
  return "Connecting"
}
