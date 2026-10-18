import { useEffect, useState } from "react"
import { ArkivProvider, formatDocLink, type Identity, newDocLink, SdkStore } from "y-arkiv"
import { short } from "../format"
import { ensureGas, fundFromWallet, hasWallet, WALLET_WARNING } from "../gas"
import { ArrowIcon, BookIcon, GithubIcon, HistoryIcon, HourglassIcon, KeyIcon, LockIcon, PenIcon, PlugIcon, ShieldIcon, SnowIcon, TerminalIcon } from "../icons"
import { knownDocuments, newIdentity, preferredName, saveIdentity, saveLink, setPreferredName } from "../session"
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
      await ArkivProvider.createDocument({ store: new SdkStore({ privateKey: identity.privateKey }), link, identity, keepForSeconds: record ? 365 * 86400 : undefined })
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
      <p className="t-micro t-muted record-note">
        {record
          ? "Every edit lives a year from today, so blame keeps proving who wrote what even if nobody opens it. Only you can end it sooner, by deleting it."
          : "Off: it lives while people use it, and expires a month after the last visit. You can keep it longer later."}
      </p>
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
        <p className="create-note">Creates a key for this document only, funds it with test gas, and writes the member list. About ten seconds.</p>
      )}
    </>
  )
}

function HeroVisual() {
  return (
    <div className="stage" aria-hidden="true">
      <div className="duo">
        <div className="window">
          <div className="window__bar">
            <div className="lights">
              <i />
              <i />
              <i />
            </div>
            <span className="window__title">Field notes · 3 members</span>
          </div>
          <div className="doc-mock">
            <h4>Site visit, Ward 14</h4>
            <p style={{ "--bar": "var(--author-a)" } as React.CSSProperties}>The pump house was locked again. Water came on at 6:40 and stopped before 8.</p>
            <p style={{ "--bar": "linear-gradient(var(--author-a) 50%, var(--author-b) 50%)" } as React.CSSProperties}>
              Residents counted four dry days this month. Two of them were not on the official roster.
            </p>
            <p style={{ "--bar": "var(--author-b)" } as React.CSSProperties}>
              Next: ask the ward office for the schedule in writing
              <span className="caret" />
              <span className="caret-tag">Bea</span>
            </p>
          </div>
        </div>
        <div className="window window--dark">
          <div className="window__bar">
            <div className="lights">
              <i />
              <i />
              <i />
            </div>
            <span className="window__title">Explorer</span>
          </div>
          <div className="pub">
            <dl>
              <dt>$creator</dt>
              <dd>0xd947…00a4</dd>
              <dt>qp</dt>
              <dd>"quire1"</dd>
              <dt>qd</dt>
              <dd>0x3f0a…c912</dd>
              <dt>qk</dt>
              <dd>"u"</dd>
              <dt>qs</dt>
              <dd>u64</dd>
              <dt>payload</dt>
              <dd>1,058 bytes</dd>
            </dl>
            <div className="hex">51 01 00 00 00 00 9c 4e 0b 71 e2 3a d8 05 f6 1c 77 a9 30 be 52 c4 8d 19 e7 6a 02 f3 bb 48 d1 7e 0c 95 a6 21 4f e8 ca 13 70 9d …</div>
          </div>
        </div>
      </div>
      <div className="float" style={{ left: "-8px", bottom: "26px" }}>
        <div className="float-row">
          <span className="live-dot" />
          <div>
            <b>Edit from Bea</b>
            <div className="t-micro">arrived a few seconds after she typed</div>
          </div>
        </div>
      </div>
      <div className="float" style={{ right: "18px", top: "-6px" }}>
        <div className="float-row">
          <ShieldIcon />
          <div>
            <b>1 outside write, never applied</b>
            <div className="t-micro">its creator is not a member</div>
          </div>
        </div>
      </div>
    </div>
  )
}

export function Home() {
  useReveal()
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
            <a href="#how">How it works</a>
            <a href="#try">Try the encryption</a>
            <a href="#open">Build on it</a>
            <a href="#faq">FAQ</a>
          </div>
          <a className="btn btn-sm btn-candy" href="#start">
            New document
          </a>
        </div>
      </nav>

      <header className="hero">
        <div className="container">
          <span className="badge badge--dot">Running on Arkiv's Tiramisu testnet</span>
          <h1>
            Write together. <span className="t-muted">Only people with the link can read it.</span>
          </h1>
          <p className="lead">
            Quire is a shared editor with no sync server. Every edit is encrypted in your browser, stored on Arkiv, and reaches your collaborators a few seconds later.
          </p>
          <div id="start">
            <CreateForm id="create" />
          </div>
          <p className="t-small demo-link">
            Or <a href={DEMO}>open the live demo document</a>: three members, read straight from Arkiv, plus one forged write from outside the member list that it never applies.
          </p>
          <div className="trust">
            <span>Free on testnet</span>
            <span>No account</span>
            <span>Open source, MIT</span>
          </div>
          <div className="hero__visual bleed">
            <HeroVisual />
          </div>
        </div>
      </header>

      <section className="section section--alt after-bleed" id="how">
        <div className="container">
          <div className="section-head">
            <span className="eyebrow">
              <span className="dot" />
              Why it exists
            </span>
            <h2>Whoever hosts your document decides whether it exists.</h2>
            <p className="lead">In the usual setup one company holds the only copy. Most can read it; even the encrypted ones can delete it, lock your account or shut down.</p>
          </div>
          <div className="grid grid-2">
            <div className="card card--flat reveal">
              <p className="t-title">The usual way</p>
              <ul className="cases">
                <li>
                  <time>31 Oct 2017</time>
                  <span>Google Docs locked journalists out of their own drafts with a mistaken terms-of-service flag.</span>
                </li>
                <li>
                  <time>Any day</time>
                  <span>The host can delete a document, close an account or shut down, and the only copy goes with it.</span>
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
              <p className="t-small" style={{ marginTop: 14 }}>
                Members and link holders hold the keys. Arkiv holds ciphertext that only they can open, and rotating the key shuts out an old link. Quire runs no server that can read your writing: the optional relay passes along encrypted query results only, so we hold no text to hand over. Arkiv's RPC still sees which document ids your IP address opens. What still stands in the way: this page is served by Vercel, today's network has one public endpoint, and new keys get gas from our sponsor. The readers in the repository work without the page, and any Arkiv node can serve the data.
              </p>
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
                <PenIcon /> Authorship you can check
              </span>
              <h3>See which wallet wrote each paragraph.</h3>
              <p className="lead">
                Turn on authorship and each paragraph gets a bar in the colors of the wallets that wrote it. Each live edit is checked against its on-chain creator and a salt that creator signed. Text that survives only inside a snapshot is shown as claimed, with the member who carried it. Writes from outside the member list are never applied.
              </p>
              <div className="chips">
                <span className="chip">$creator checks</span>
                <span className="chip">Forged writes ignored</span>
              </div>
            </div>
            <div className="stage stage--soft" aria-hidden="true">
              <div className="mini">
                <div className="mini__head">
                  <span>Who wrote what</span>
                  <span className="pill-tag accent">on</span>
                </div>
                <div className="doc-mock" style={{ minHeight: 0, padding: "18px 22px 20px 34px" }}>
                  <p style={{ "--bar": "var(--author-a)" } as React.CSSProperties}>Budget draft, second pass.</p>
                  <p style={{ "--bar": "var(--author-c)" } as React.CSSProperties}>Moved travel to its own line so it can be cut first.</p>
                  <p style={{ "--bar": "linear-gradient(var(--author-c) 50%, var(--author-b) 50%)" } as React.CSSProperties}>Printing costs are an estimate until Friday.</p>
                </div>
                <div className="mini__body" style={{ borderTop: "1px solid var(--line)" }}>
                  <div className="row wrap" style={{ gap: 14 }}>
                    <span className="addr"><span className="dot" style={{ background: "var(--author-a)" }} />Asha · 0xa7da…b546</span>
                    <span className="addr"><span className="dot" style={{ background: "var(--author-c)" }} />Ravi · 0x2a77…4b8b</span>
                    <span className="addr"><span className="dot" style={{ background: "var(--author-b)" }} />Bea · 0xd947…00a4</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="split reveal">
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

          <div className="split split--flip reveal">
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
              { i: <PlugIcon />, t: "y-arkiv", d: "A Yjs provider. Swap it for y-websocket and a Yjs editor syncs its document over Arkiv: each writer needs a little test gas, and there are no shared cursors yet." },
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
                From the chain: that a document id exists, which addresses write to it and roughly when. Not the text, the title, the members' names or who the addresses belong to, and your address is new in every document. Two more parties see a little more. On testnet the drip funds every key from one wallet, so an observer can tell keys were funded by Quire. And whoever runs the RPC endpoint sees your IP address next to the document ids you read. Use a VPN or Tor if that matters.
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
