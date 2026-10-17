import { useEffect, useState } from "react"
import { ArkivProvider, extendVersion, type Hex, SdkStore, type VersionLink } from "y-arkiv"
import { ensureGas } from "../gas"
import { newIdentity } from "../session"
import { addressUrl, entityUrl, plainText, short } from "../format"

export function VersionPage({ link }: { link: VersionLink }) {
  const [state, setState] = useState<{ text: string; creator: Hex; block: bigint } | { error: string } | null>(null)
  useEffect(() => {
    ArkivProvider.openVersion(new SdkStore(), link).then(
      (v) => setState({ text: plainText(v.doc), creator: v.creator, block: v.block }),
      (e: Error) => setState({ error: e.message }),
    )
  }, [link.key])
  return (
    <main className="version">
      <a className="nav__brand" href="#/">
        <span className="app-icon" />
        Quire
      </a>
      {!state && <p className="muted">Reading the published version from Arkiv…</p>}
      {state && "error" in state && <p className="error">{state.error}</p>}
      {state && "text" in state && (
        <>
          <p className="muted small">
            Frozen at block {state.block.toString()} by{" "}
            <a href={addressUrl(state.creator)} target="_blank" rel="noreferrer">
              {short(state.creator)}
            </a>
            . Readonly on chain: nobody can change it.{" "}
            <a href={entityUrl(link.key)} target="_blank" rel="noreferrer">
              View the entity
            </a>
          </p>
          <KeepAlive link={link} />
          <article className="sheet">
            {state.text.split("\n").map((line, i) => (
              <p key={i}>{line || " "}</p>
            ))}
          </article>
        </>
      )}
    </main>
  )
}

/**
 * Versions carry permissionless extension: any funded key may keep one alive.
 * This makes a throwaway key, funds it from the drip and extends the version.
 */
function KeepAlive({ link }: { link: VersionLink }) {
  const [state, setState] = useState<string | null>(null)
  async function keep() {
    setState("Funding a throwaway key…")
    try {
      const id = newIdentity("reader")
      const gas = await ensureGas(id.address)
      if (!gas.ok) throw new Error(gas.reason)
      setState("Extending on Arkiv…")
      const until = await extendVersion(new SdkStore({ privateKey: id.privateKey }), link, 3 * 365 * 86400)
      setState(`Kept alive until block ${until}, about three years. Anyone holding this link can do the same.`)
    } catch (e) {
      setState((e as Error).message.split("\n")[0]!)
    }
  }
  return (
    <div className="row wrap" style={{ gap: 10, marginTop: 12 }}>
      <button className="btn btn-sm btn-outline" onClick={keep} disabled={!!state && !state.startsWith("Kept") && !state.includes("not")}>
        Keep this version alive
      </button>
      {state && <span className="small muted">{state}</span>}
    </div>
  )
}
