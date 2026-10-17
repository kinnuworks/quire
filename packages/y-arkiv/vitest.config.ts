import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    // some tests mine weeks of blocks or run many sessions; on a slow machine they pass the 5 s default
    testTimeout: 30_000,
  },
})
