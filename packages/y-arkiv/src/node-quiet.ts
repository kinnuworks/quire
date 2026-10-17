/**
 * Imported first by the CLI. Newer Node versions print an ExperimentalWarning the moment anything
 * probes `globalThis.localStorage` without --localstorage-file, and a dependency probes it at import.
 * The CLI has no use for browser storage, so it is defined as absent before anything else loads.
 */
if (typeof process !== "undefined" && Object.getOwnPropertyDescriptor(globalThis, "localStorage")?.get) {
  Object.defineProperty(globalThis, "localStorage", { value: undefined, configurable: true, writable: true })
}
export {}
