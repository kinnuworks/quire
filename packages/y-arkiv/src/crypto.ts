/**
 * Key handling.
 *
 * A document is opened with a 32-byte link secret carried in the URL fragment.
 * From it we derive two keys:
 *   - the meta key, which encrypts the ACL and join requests, and
 *   - the epoch 0 content key, which encrypts edits until the first revocation.
 *
 * Revoking a member starts a new epoch with a random content key. The owner
 * wraps that key for each remaining member with ECDH on secp256k1 (the same
 * curve as their Arkiv account), so the old link secret cannot read new edits.
 *
 * Payload encryption itself is arkiv-encryption's AES-256-GCM envelope.
 */
import { secp256k1 } from "@noble/curves/secp256k1.js"
import { hkdf } from "@noble/hashes/hkdf.js"
import { sha256 } from "@noble/hashes/sha2.js"
import { keccak_256 } from "@noble/hashes/sha3.js"
import { decryptPayload, encryptPayload, importKey } from "arkiv-encryption"
import { bytesToHex, hexToBytes } from "./hex.js"

const enc = new TextEncoder()

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n)
  // getRandomValues caps at 65,536 bytes per call
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)))
  return out
}

function derive(secret: Uint8Array, label: string): Uint8Array {
  return hkdf(sha256, secret, enc.encode("quire/v1"), enc.encode(label), 32)
}

export function deriveMetaKey(linkSecret: Uint8Array): Uint8Array {
  return derive(linkSecret, "meta")
}

export function deriveEpochZeroKey(linkSecret: Uint8Array): Uint8Array {
  return derive(linkSecret, "epoch/0")
}

/** Imported keys are cached per raw key so repeated encrypts stay cheap. */
const imported = new Map<string, Promise<CryptoKey>>()
function aes(raw: Uint8Array): Promise<CryptoKey> {
  const id = bytesToHex(raw)
  let k = imported.get(id)
  if (!k) {
    k = importKey(raw)
    imported.set(id, k)
  }
  return k
}

export async function seal(rawKey: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  return encryptPayload(await aes(rawKey), plaintext)
}

export async function open(rawKey: Uint8Array, envelope: Uint8Array): Promise<Uint8Array> {
  return decryptPayload(await aes(rawKey), envelope)
}

/** Ethereum address of an uncompressed secp256k1 public key (65 bytes, 0x04 prefix). */
export function addressOfPublicKey(publicKey: Uint8Array): `0x${string}` {
  if (publicKey.length !== 65 || publicKey[0] !== 4) throw new Error("expected an uncompressed public key")
  return `0x${bytesToHex(keccak_256(publicKey.subarray(1)).slice(-20))}`
}

export function publicKeyOf(privateKeyHex: `0x${string}`): Uint8Array {
  return secp256k1.getPublicKey(hexToBytes(privateKeyHex), false)
}

/**
 * Wraps an epoch key for one member. Output: ephemeral public key (65) || envelope.
 * The wrapping key is HKDF(ECDH(ephemeral, member), epoch label).
 */
export async function wrapForMember(epochKey: Uint8Array, memberPublicKey: Uint8Array, epoch: number): Promise<Uint8Array> {
  const ephemeral = secp256k1.utils.randomSecretKey()
  const shared = secp256k1.getSharedSecret(ephemeral, memberPublicKey)
  const kek = derive(shared, `wrap/${epoch}`)
  const envelope = await seal(kek, epochKey)
  const out = new Uint8Array(65 + envelope.length)
  out.set(secp256k1.getPublicKey(ephemeral, false), 0)
  out.set(envelope, 65)
  return out
}

export async function unwrapAsMember(wrapped: Uint8Array, memberPrivateKeyHex: `0x${string}`, epoch: number): Promise<Uint8Array> {
  const shared = secp256k1.getSharedSecret(hexToBytes(memberPrivateKeyHex), wrapped.subarray(0, 65))
  const kek = derive(shared, `wrap/${epoch}`)
  return open(kek, wrapped.subarray(65))
}
