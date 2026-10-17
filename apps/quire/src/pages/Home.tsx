import { useState } from "react"
import { ArkivProvider, formatDocLink, newDocLink, SdkStore } from "y-arkiv"
import { ensureGas, fundFromWallet, hasWallet } from "../gas"
import { knownDocuments, newIdentity, preferredName, saveIdentity, saveLink, setPreferredName } from "../session"
import { short } from "../format"

export function Home() {
  const [name, setName] = useState(preferredName())
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [needsWallet, setNeedsWallet] = useState<string | null>(null)
  const docs = knownDocuments()

  async function create(viaWallet = false) {
    setError(null)
    const pseudonym = name.trim() || "Owner"
    setPreferredName(pseudonym)
    const id = newIdentity(pseudonym)
    const link = newDocLink(id.address)
    try {
      setBusy("Getting this document's key some test gas")
      const gas = viaWallet ? await fundFromWallet(id.address) : await ensureGas(id.address)
      if (!gas.ok) {
        setNeedsWallet(gas.reason)
        setBusy(null)
        return
      }
      setBusy("Writing the member list and first snapshot in one transaction")
      await ArkivProvider.createDocument({ store: new SdkStore({ privateKey: id.privateKey }), link, identity: id })
      saveIdentity(link.doc, id)
      saveLink(link)
      location.hash = formatDocLink(link)
    } catch (e) {
      setError((e as Error).message)
      setBusy(null)
    }
  }

  return (
    <main className="home">
      <header className="hero">
        <div className="mark">Quire</div>
        <h1>Write together. No server reads it, and no server can take it away.</h1>
        <p className="lede">
          Every edit is encrypted in your browser and stored as an entity on Arkiv. Your collaborators get it within a block or two,
          straight from the chain. There is no Quire backend holding your documents. The link you share is the key.
        </p>
      </header>

      <section className="card create">
        <label>
          Your name in this document
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="A pseudonym is fine" maxLength={40} />
        </label>
        <button className="primary" disabled={!!busy} onClick={() => create(false)}>
          {busy ? busy : "New document"}
        </button>
        {needsWallet && (
          <div className="note">
            <p>{needsWallet}</p>
            {hasWallet() ? (
              <button onClick={() => create(true)}>Fund with my wallet and create</button>
            ) : (
              <p>Install a browser wallet, or get test GLM from the Arkiv faucet at hub.arkiv.network/faucet.</p>
            )}
          </div>
        )}
        {error && <p className="error">{error}</p>}
      </section>

      {docs.length > 0 && (
        <section className="card">
          <h2>Documents in this browser</h2>
          <ul className="doclist">
            {docs.map((d) => (
              <li key={d.doc}>
                <a href={`#/doc/${d.doc}`}>{short(d.doc, 6)}</a>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="facts">
        <div>
          <h3>Private by construction</h3>
          <p>The explorer sees four attributes and padded ciphertext. No titles, no text, no names, and a different address for you in every document.</p>
        </div>
        <div>
          <h3>Authorship you can check</h3>
          <p>Each paragraph shows which wallets wrote it, taken from the on-chain creator of every edit. Writes from outside the member list are ignored.</p>
        </div>
        <div>
          <h3>Expiry you control</h3>
          <p>A document lives as long as someone keeps opening it, or as long as the owner sets. Members can shred everything they wrote in one transaction.</p>
        </div>
      </section>
    </main>
  )
}
