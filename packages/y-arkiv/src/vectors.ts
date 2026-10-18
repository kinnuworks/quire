/**
 * A read-only ArkivStore over a conformance vectors file (spec/vectors/document.json):
 * the same section 5 filters a node applies, frozen at the file's head block. Lets any
 * reader built on this package run against the vectors exactly as it runs against Arkiv.
 */
import { fromRpcEntity, type RpcEntity } from "./sdk.js"
import type { ArkivStore, StoredEntity } from "./store.js"

export function vectorStore(vectors: { head: string; entities: RpcEntity[] }): ArkivStore {
  const head = BigInt(vectors.head)
  const entities = vectors.entities.map(fromRpcEntity).filter((e): e is StoredEntity => e !== null)
  return {
    address: undefined,
    head: async () => head,
    batch: async () => {
      throw new Error("the vectors are read-only")
    },
    predictKeys: async () => [],
    query: async (spec) => ({
      entities: entities.filter(
        (e) =>
          e.attributes.doc === spec.doc.toLowerCase() &&
          (!spec.kind || e.attributes.kind === spec.kind) &&
          (spec.seqGte === undefined || e.attributes.seq >= spec.seqGte) &&
          (spec.seqLte === undefined || e.attributes.seq <= spec.seqLte) &&
          (!spec.creators || spec.creators.some((c) => c.toLowerCase() === e.creator)),
      ),
      block: head,
    }),
    get: async (key) => entities.find((e) => e.key === key.toLowerCase()) ?? null,
    watch: () => () => undefined,
  }
}
