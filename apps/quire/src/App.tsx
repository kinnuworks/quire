import { useEffect, useState } from "react"
import { type DocLink, type Hex, parseDocLink, parseVersionLink, type VersionLink } from "y-arkiv"
import { DocPage } from "./pages/DocPage"
import { Home } from "./pages/Home"
import { VersionPage } from "./pages/VersionPage"
import { linkFor, saveLink } from "./session"

type Route = { page: "home" } | { page: "doc"; link: DocLink } | { page: "version"; link: VersionLink } | { page: "missing" }

/**
 * Reads the route from the fragment. A full document link (with its secret)
 * is saved locally and then replaced in the address bar by a short form that
 * carries no secret, so it stays out of history, screenshots and screen shares.
 */
function resolve(): Route {
  const hash = location.hash
  const full = parseDocLink(hash)
  if (full) {
    saveLink(full)
    history.replaceState(null, "", `#/doc/${full.doc}`)
    return { page: "doc", link: full }
  }
  const m = /^#\/doc\/(0x[0-9a-f]{64})$/.exec(hash)
  if (m) {
    const saved = linkFor(m[1] as Hex)
    return saved ? { page: "doc", link: saved } : { page: "missing" }
  }
  const version = parseVersionLink(hash)
  if (version) return { page: "version", link: version }
  return { page: "home" }
}

export function App() {
  const [route, setRoute] = useState<Route>(resolve)
  useEffect(() => {
    const on = () => setRoute(resolve())
    window.addEventListener("hashchange", on)
    return () => window.removeEventListener("hashchange", on)
  }, [])

  if (route.page === "doc") return <DocPage key={route.link.doc} link={route.link} />
  if (route.page === "version") return <VersionPage link={route.link} />
  if (route.page === "missing")
    return (
      <main className="center">
        <h1>This browser has no key for that document</h1>
        <p>That address is the document's id without its key: the app removes the key from the address bar once it has read it. Ask whoever shared it for the full invite link (it starts with #/d/), or open it in the browser where you first did. Quire keeps document secrets in the browser that opened them and nowhere else.</p>
        <a href="#/">Back to start</a>
      </main>
    )
  return <Home />
}
