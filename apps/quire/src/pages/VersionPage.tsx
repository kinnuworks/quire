import { useEffect, useState } from "react"
import { ArkivProvider, type Hex, SdkStore, type VersionLink } from "y-arkiv"
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
