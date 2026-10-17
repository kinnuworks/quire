import { fileURLToPath } from "node:url"
import react from "@vitejs/plugin-react"
import { defineConfig, loadEnv, type Plugin } from "vite"

/** Serves api/drip.ts and api/rpc.ts during local development, with the dev key and access key from the repo-root .env. */
function devDrip(): Plugin {
  return {
    name: "quire-dev-drip",
    configureServer(server) {
      const env = loadEnv("development", fileURLToPath(new URL("../..", import.meta.url)), ["QUIRE_", "ARKIV_"])
      process.env.QUIRE_SPONSOR_KEY ??= env.QUIRE_SPONSOR_KEY ?? env.QUIRE_DEV_PRIVATE_KEY
      if (env.ARKIV_ACCESS_KEY) process.env.ARKIV_ACCESS_KEY ??= env.ARKIV_ACCESS_KEY
      for (const name of ["drip", "rpc"]) server.middlewares.use(`/api/${name}`, async (req, res) => {
        let raw = ""
        for await (const chunk of req) raw += chunk
        const { default: handler } = await server.ssrLoadModule(fileURLToPath(new URL(`../../api/${name}.ts`, import.meta.url)))
        const reply = {
          code: 200,
          status(n: number) {
            this.code = n
            return this
          },
          setHeader(k: string, v: string) {
            res.setHeader(k, v)
          },
          json(v: unknown) {
            res.statusCode = this.code
            res.setHeader("content-type", "application/json")
            res.end(JSON.stringify(v))
          },
        }
        await handler({ method: req.method, body: raw, headers: req.headers }, reply).catch((e: Error) => reply.status(500).json({ error: e.message }))
      })
    },
  }
}

export default defineConfig({
  plugins: [react(), devDrip()],
  resolve: {
    alias: {
      "y-arkiv": fileURLToPath(new URL("../../packages/y-arkiv/src/index.ts", import.meta.url)),
    },
    // one copy of Yjs for the editor and the provider, or updates silently fail to apply
    dedupe: ["yjs", "y-prosemirror", "lib0"],
  },
  build: { target: "es2022", sourcemap: true },
})
