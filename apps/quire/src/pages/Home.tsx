import { useEffect, useState } from "react"
import { ArkivProvider, formatDocLink, type Identity, newDocLink, SdkStore } from "y-arkiv"
import { short } from "../format"
import { ensureGas, fundFromWallet, hasWallet, WALLET_WARNING } from "../gas"
import { ArrowIcon, BookIcon, GithubIcon, HistoryIcon, HourglassIcon, KeyIcon, LockIcon, PlugIcon, ShieldIcon, SnowIcon, TerminalIcon } from "../icons"
import { NodeSetting } from "../panels"
import { knownDocuments, newIdentity, nodeOptions, preferredName, saveIdentity, saveLink, setPreferredName } from "../session"
import { CONTESTED, HeroStage, ProofStrip, Scrubber } from "../landing"
import { TryIt } from "../TryIt"

/** The open demo document from arkiv/demo.json: read-only for visitors. */
const DEMO = "#/d/cGY4Lxdu7yBatU75t4TxoyiHNJOtyVA3npCI1WcHL2c.OPYzqRUr9D1b_T_O3-7fsA0layOo0LcNOlMaphGxpSE.a7da7e4e17101ad0b4832c7cce0f87bf6e84b546"

const REPO = "https://github.com/kinnuworks/quire"

function useReveal() {
  useEffect(() => {
    const els = document.querySelectorAll(".reveal")
    if (!("IntersectionObserver" in window)) return els.forEach((el) => el.classList.add("in"))
    const io = new IntersectionObserver(
      (entries) =>
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add("in")
            io.unobserve(e.target)
          }
        }),
      { rootMargin: "0px 0px -8% 0px" },
    )
    els.forEach((el) => io.observe(el))
    return () => io.disconnect()
  }, [])
}

function CreateForm({ id }: { id: string }) {
  const [name, setName] = useState(preferredName())
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  // the key survives retries, so funding it by hand and pressing the button again works
  const [pending, setPending] = useState<Identity | null>(null)
  // a record of who wrote what should outlive the 30-day lease from the start
  const [record, setRecord] = useState(false)

  async function create(e?: React.FormEvent, viaWallet = false) {
    e?.preventDefault()
    setError(null)
    const pseudonym = name.trim() || "Owner"
    setPreferredName(pseudonym)
    const identity = pending ? { ...pending, name: pseudonym } : newIdentity(pseudonym)
    setPending(identity)
    const link = newDocLink(identity.address)
    try {
      setBusy("Funding a fresh key…")
      const gas = viaWallet ? await fundFromWallet(identity.address) : await ensureGas(identity.address)
      if (!gas.ok) throw new Error(gas.reason)
      setBusy("Writing to Arkiv…")
      await ArkivProvider.createDocument({ store: new SdkStore({ privateKey: identity.privateKey, ...nodeOptions() }), link, identity, keepForSeconds: record ? 365 * 86400 : undefined })
      saveIdentity(link.doc, identity)
      saveLink(link)
      location.hash = formatDocLink(link)
    } catch (err) {
      setError((err as Error).message)
      setBusy(null)
    }
  }

  return (
    <>
      <form className="join" onSubmit={create} id={id}>
        <input aria-label="Your name in this document" value={name} onChange={(e) => setName(e.target.value)} placeholder="Your name, a pseudonym is fine" maxLength={40} />
        <button className="btn btn-candy" disabled={!!busy}>
          {busy ?? (pending && error ? "Try again" : "New document")}
        </button>
      </form>
      <label className="toggle-row record-toggle">
        <input className="switch" type="checkbox" checked={record} onChange={(e) => setRecord(e.target.checked)} />
        Keep it as an authorship record for a year
      </label>
      {record && <p className="t-micro record-note">Every edit lives a year from today, so blame keeps proving who wrote what even if nobody opens it. Only you can end it sooner, by deleting it.</p>}
      {error && pending ? (
        <div className="card create-help">
          <p className="error">{error}</p>
          <p className="t-small">
            This document's key is <span className="t-mono">{pending.address}</span>. Send it a little test GLM (0.01 covers about 80 edits) from the{" "}
            <a href="https://hub.arkiv.network/faucet" target="_blank" rel="noreferrer">
              Arkiv faucet
            </a>{" "}
            or any Tiramisu wallet, then press Try again.
          </p>
          <div className="row wrap" style={{ gap: 8, marginTop: 10 }}>
            <button type="button" className="btn btn-sm btn-outline" onClick={() => navigator.clipboard?.writeText(pending.address)}>
              Copy address
            </button>
            {hasWallet() && (
              <button type="button" className="btn btn-sm btn-ghost" onClick={() => confirm(WALLET_WARNING) && create(undefined, true)}>
                Fund from my wallet
              </button>
            )}
          </div>
        </div>
      ) : (
        <p className="create-note">A fresh key for this document only, funded with test gas. About ten seconds.</p>
      )}
    </>
  )
}

export function Home() {
  useReveal()
  // a link such as /#proof arrives before the section exists: scroll to it once the page has rendered
  useEffect(() => {
    const id = location.hash.slice(1)
    if (/^[a-z]+$/.test(id)) document.getElementById(id)?.scrollIntoView()
  }, [])
  const docs = knownDocuments()
  return (
    <>
      <nav className="nav">
        <div className="nav__bar">
          <a className="nav__brand" href="#/">
            <span className="app-icon" />
            Quire
          </a>
          <div className="nav__links">
            <a href="#proof">Who wrote it</a>
            <a href="#how">Why it exists</a>
            <a href="#try">Try the encryption</a>
            <a href="#open">Build on it</a>
          </div>
          <a className="btn btn-sm btn-candy" href="#start">
            New document
          </a>
        </div>
      </nav>

      <header className="hero">
        <div className="container">
          <a className="badge" href="#proof">
            <span className="badge__tag">New</span>
            See the chain catch a stolen paragraph
          </a>
          <h1>
            Write together. <span className="hl">Prove who wrote it.</span>
          </h1>
          <p className="lead">
            Quire is a shared editor that no server can read. Every edit is encrypted in your browser and signed onto Arkiv, so anyone can check who wrote each line, even after someone tries to take the credit.
          </p>
          <div id="start">
            <CreateForm id="create" />
          </div>
          <p className="t-small demo-link">
            Or open a live document: <a href={DEMO}>the shared water log</a>, three writers and one forged write that never counts, or <a href={CONTESTED}>the contested study</a>.
          </p>
          <div className="trust">
            <span>Free on testnet</span>
            <span>No account</span>
            <span>Open source, MIT</span>
          </div>
          <div className="hero__visual bleed">
            <HeroStage />
          </div>
        </div>
      </header>

      <section className="section section--alt after-bleed">
        <div className="container">
          <ProofStrip />
        </div>
      </section>

      <section className="section" id="how">
        <div className="container">
          <div className="section-head">
            <span className="eyebrow">
              <span className="dot" />
              Why it exists
            </span>
            <h2>Your drafts live on someone else's server.</h2>
            <p className="lead">A hosted editor keeps the readable copy and the only edit history. It decides what happens to both.</p>
          </div>
          <div className="grid grid-2">
            <div className="card card--flat reveal">
              <p className="t-title">The usual way</p>
              <ul className="cases">
                <li>
                  <time>31 Oct 2017</time>
                  <span>Google Docs locked people out of their own drafts with a mistaken abuse flag, and confirmed it scans documents.</span>
                </li>
                <li>
                  <time>2 Apr 2013</time>
                  <span>In Dunbar v. Google, Google told a court that earlier versions of its continuously edited documents were not kept. Each save overwrote the last.</span>
                </li>
              </ul>
              <div className="flow">
                <span>Your browser</span>
                <i>→</i>
                <span>Their server, readable</span>
                <i>→</i>
                <span>Your team</span>
              </div>
            </div>
            <div className="card card--chosen reveal" style={{ "--i": 1 } as React.CSSProperties}>
              <p className="t-title">With Quire</p>
              <ul className="cases">
                <li>
                  <time>The words</time>
                  <span>Encrypted in your browser and padded before they leave. The key travels only in the link, so no host, RPC or Arkiv node can read them.</span>
                </li>
                <li>
                  <time>The history</time>
                  <span>Every edit is its own entity on Arkiv, signed by the key that wrote it. Nobody can rewrite it after the fact, us included.</span>
                </li>
              </ul>
              <div className="flow">
                <span>Your browser</span>
                <i>→</i>
                <span>Arkiv, encrypted</span>
                <i>→</i>
                <span>Your team</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="section section--alt" id="proof">
        <div className="container">
          <div className="section-head">
            <span className="eyebrow">
              <span className="dot" />
              Try it on this page
            </span>
            <h2>
              Someone took the credit. <span className="t-muted">The chain kept the receipts.</span>
            </h2>
            <p className="lead">
              A real document on Arkiv. Bea wrote the key finding. Then Asha, who owns the document, erased Bea from the member list and pasted the finding back as her own. Drag through the blocks: each step is one of its edits, recorded from the chain with <code>y-arkiv timeline</code>, which you can run yourself.
            </p>
          </div>
          <Scrubber />
          <div className="cta-row">
            <a className="btn btn-ink" href={CONTESTED}>
              Open the real document <ArrowIcon />
            </a>
            <a className="btn btn-outline" href={`${REPO}#who-is-harmed-today`} target="_blank" rel="noreferrer">
              <TerminalIcon /> Check it from a terminal
            </a>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container stack">
          <div className="split reveal">
            <div>
              <span className="eyebrow">
                <LockIcon /> What the public sees
              </span>
              <h3>On the explorer: four short fields and a block of ciphertext.</h3>
              <p className="lead">
                Each entity carries a protocol tag, a random document id, a kind and a block number. The text, the title and the member list are encrypted and padded to one of six sizes. You also get a fresh address in every document, so the chain alone does not tie your documents together.
              </p>
              <div className="chips">
                <span className="chip">AES-256-GCM</span>
                <span className="chip">Padded payloads</span>
                <span className="chip">Key per document</span>
              </div>
            </div>
            <div className="stage stage--soft" aria-hidden="true">
              <div className="mini">
                <div className="mini__head">
                  <span>One edit, two views</span>
                  <span className="pill-tag">same entity</span>
                </div>
                <div className="mini__body">
                  <div className="pair">
                    <div>
                      <h5>Public</h5>
                      <dl className="kv">
                        <dt>qk</dt>
                        <dd>"u"</dd>
                        <dt>qs</dt>
                        <dd>u64</dd>
                        <dt>size</dt>
                        <dd>1,058 B</dd>
                      </dl>
                    </div>
                    <div className="private">
                      <h5>Your browser</h5>
                      <dl className="kv">
                        <dt>kind</dt>
                        <dd>edit</dd>
                        <dt>by</dt>
                        <dd>Bea</dd>
                        <dt>text</dt>
                        <dd>"ask the ward office…"</dd>
                      </dl>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="split split--flip reveal">
            <div>
              <span className="eyebrow">
                <HourglassIcon /> Expiry you control
              </span>
              <h3>Documents live while people use them.</h3>
              <p className="lead">
                A document rests on a snapshot with a 30-day lease. Members renew it when they open the document past the halfway mark, so a document nobody touches lapses on its own. The owner can keep it longer or delete it now, and any member can shred their own edit history in one transaction.
              </p>
              <div className="chips">
                <span className="chip">Entity Expiration</span>
                <span className="chip">Lifetime Extension</span>
                <span className="chip">Shred my edit history</span>
              </div>
            </div>
            <div className="stage stage--soft" aria-hidden="true">
              <div className="mini">
                <div className="mini__head">
                  <span>Lifetime</span>
                  <span className="pill-tag">renewed by members</span>
                </div>
                <div className="mini__body">
                  <div className="countdown">28d 4h</div>
                  <div className="meter">
                    <i style={{ width: "92%" }} />
                  </div>
                  <div className="row wrap" style={{ gap: 8 }}>
                    <span className="chip chip--soft">Keep 90 days</span>
                    <span className="chip chip--soft">Keep 1 year</span>
                    <span className="chip chip--soft">Delete now</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="split reveal">
            <div>
              <span className="eyebrow">
                <KeyIcon /> Removing someone
              </span>
              <h3>Revoking a member rotates the key.</h3>
              <p className="lead">
                Removing a member starts a new epoch with a fresh key, wrapped only for the people who stay. The new member list and a snapshot under the new key land in the same transaction. The old link stops working for anything written afterwards.
              </p>
              <div className="chips">
                <span className="chip">Atomic batch</span>
                <span className="chip">ECDH key wrap</span>
              </div>
            </div>
            <div className="stage stage--soft" aria-hidden="true">
              <div className="mini">
                <div className="mini__head">
                  <span>Members</span>
                  <span className="pill-tag accent">epoch 1</span>
                </div>
                <div className="mini__body" style={{ gap: 0 }}>
                  {[
                    { n: "Asha", a: "0xa7da…b546", c: "var(--author-a)", r: "owner" },
                    { n: "Bea", a: "0xd947…00a4", c: "var(--author-b)", r: "writer" },
                    { n: "Ravi", a: "0x2a77…4b8b", c: "var(--author-c)", r: "removed", gone: true },
                  ].map((m) => (
                    <div className={`member ${m.gone ? "gone" : ""}`} key={m.n}>
                      <span className="dot" style={{ background: m.c }} />
                      <div className="who">
                        <b>{m.n}</b>
                        <span>{m.a}</span>
                      </div>
                      <span className="pill-tag">{m.r}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="section section--alt" id="try">
        <div className="container">
          <div className="section-head">
            <span className="eyebrow">
              <span className="dot" />
              Try it on this page
            </span>
            <h2>
              Encrypt a line <em className="t-serif">yourself.</em>
            </h2>
            <p className="lead">The same code an edit runs before it goes to Arkiv: a throwaway key, its signed salt, the padded frame and the encryption. Nothing is sent. Type below and compare the two views.</p>
          </div>
          <TryIt />
        </div>
      </section>

      <section className="section" id="open">
        <div className="container">
          <div className="section-head">
            <span className="eyebrow">
              <span className="dot" />
              Open protocol
            </span>
            <h2>Built so others can build on it.</h2>
            <p className="lead">The editor is one client. The protocol, the library, a CLI and a second reader in Python, written against the spec and its test vectors, are in the repository under MIT.</p>
          </div>
          <div className="grid grid-3">
            {[
              { i: <PlugIcon />, t: "y-arkiv", d: "A Yjs provider. Use it in place of y-websocket, with three more arguments, and a Yjs editor syncs its document over Arkiv: each writer needs a little test gas, and there are no shared cursors yet." },
              { i: <BookIcon />, t: "A written spec", d: "PROTOCOL.md, JSON Schema for every entity, and test vectors with a forged write." },
              { i: <TerminalIcon />, t: "Read without us", d: "Our CLI and the Python reader rebuild any document from chain data and check its membership and authorship, and a script shows the two agree." },
              { i: <HistoryIcon />, t: "Time travel", d: "Rebuild a document exactly as Arkiv held it at a past block, with atBlock reads." },
              { i: <SnowIcon />, t: "Frozen versions", d: "Publish a readonly copy with its own key. Anyone with the link can keep it alive." },
              { i: <ShieldIcon />, t: "Privacy audit", d: "A standard-library script checks what the explorer can see for any document id." },
            ].map((x, n) => (
              <div className="tile reveal" key={x.t} style={{ "--i": n % 3 } as React.CSSProperties}>
                <span className="icon-tile">{x.i}</span>
                <div>
                  <p className="t-title">{x.t}</p>
                  <p>{x.d}</p>
                </div>
              </div>
            ))}
          </div>
          <div className="cta-row">
            <a className="btn btn-outline" href={REPO} target="_blank" rel="noreferrer">
              <GithubIcon /> Read the code
            </a>
            <a className="btn btn-ghost" href={`${REPO}/blob/main/PROTOCOL.md`} target="_blank" rel="noreferrer">
              Read the protocol <ArrowIcon />
            </a>
          </div>
        </div>
      </section>

      <section className="section section--alt" id="faq">
        <div className="container">
          <div className="section-head">
            <h2>Questions.</h2>
          </div>
          <div className="faq">
            <details>
              <summary>Is there really no server?</summary>
              <p>
                There are two small functions, and neither touches document data. The drip sends a little test gas to a new document key; it sees that key's address and your IP address. You can skip it and fund the key yourself. The relay is off unless you turn it on: if your network runs out of Arkiv's free queries, the page offers it, and it then forwards your document queries to Arkiv with our access key. It sees what Arkiv's RPC sees (your IP address, the document id, the members' addresses) and keeps nothing. Everything else, live edits and writes included, goes from your browser straight to Arkiv's public RPC endpoint, which sees your IP address and the document id but only ciphertext.
              </p>
            </details>
            <details>
              <summary>What can someone watching the chain learn?</summary>
              <p>
                From the chain: that a document id exists, which addresses write to it and roughly when. Not the text, the title, the members' names or who the addresses belong to, and your address is new in every document. Two more parties see a little more. On testnet the drip funds every key from one wallet, so an observer can tell keys were funded by Quire. And whoever runs the RPC endpoint sees your IP address next to the document ids you read. Use a VPN or Tor if that matters, or choose the node below.
              </p>
            </details>
            <details>
              <summary>Can I use my own Arkiv node?</summary>
              <div className="faq-body">
                <NodeSetting />
              </div>
            </details>
            <details>
              <summary>Does it prove who I am?</summary>
              <p>
                It proves which key wrote each passage, and when. Each document gets its own key, so the link between key and person is yours to show: the People tab can sign a phrase someone chose, and <code>y-arkiv check-signature</code> verifies it. Between co-authors who each hold their own key, that settles the usual argument. For a lone writer accused of copying, the edit rhythm is evidence to weigh, not proof that a person typed it.
              </p>
            </details>
            <details>
              <summary>What happens if I lose the link?</summary>
              <p>The link is the key, and nobody else has a copy. Ask a member to send it again. This browser also remembers the documents you opened in it.</p>
            </details>
            <details>
              <summary>Can a removed member still read the document?</summary>
              <p>They keep whatever they already saw. They cannot read anything written after they were removed, because the key changed and their new copy was never wrapped for them.</p>
            </details>
            <details>
              <summary>Can I use this in my own app?</summary>
              <p>Yes. y-arkiv is a Yjs provider, so editors like Tiptap, BlockNote and CodeMirror work with it. PROTOCOL.md describes the format if you want to write your own client.</p>
            </details>
            <details>
              <summary>Why testnet only?</summary>
              <p>Arkiv's network is in testnet. Treat everything here as a working prototype and keep real secrets out of it.</p>
            </details>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container" style={{ textAlign: "center" }}>
          <span className="app-icon final-icon" style={{ display: "block" }} />
          <h2>
            Start a document. <span className="t-muted">Share the link.</span>
          </h2>
          <div style={{ marginTop: 8 }}>
            <CreateForm id="create-bottom" />
          </div>
          {docs.length > 0 && (
            <div className="chips" style={{ justifyContent: "center", marginTop: 28 }}>
              {docs.slice(0, 6).map((d) => (
                <a className="chip" key={d.doc} href={`#/doc/${d.doc}`}>
                  Reopen {short(d.doc, 4)}
                </a>
              ))}
            </div>
          )}
        </div>
      </section>

      <footer className="footer">
        <div className="container">
          <a className="nav__brand" href="#/">
            <span className="app-icon" />
            Quire
          </a>
          <div className="row wrap" style={{ gap: 20 }}>
            <a href={REPO} target="_blank" rel="noreferrer">GitHub</a>
            <a href={`${REPO}/blob/main/PROTOCOL.md`} target="_blank" rel="noreferrer">Protocol</a>
            <a href="https://arkiv.network" target="_blank" rel="noreferrer">Arkiv</a>
          </div>
          <span>Built on Arkiv for the Global Tour Stop. MIT licensed.</span>
        </div>
      </footer>
    </>
  )
}
