import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { App } from "./App"
// fonts are bundled with the app: no request to a font CDN, so no visitor IP goes to a third party
import "@fontsource-variable/inter"
import "@fontsource/jetbrains-mono/400.css"
import "@fontsource/jetbrains-mono/500.css"
import "@fontsource/instrument-serif/400.css"
import "@fontsource/instrument-serif/400-italic.css"
import "./design.css"
import "./app.css"

document.documentElement.classList.add("js")

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
