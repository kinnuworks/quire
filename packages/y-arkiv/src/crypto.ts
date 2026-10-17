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

/** The x-coordinate of the ECDH point (32 bytes). noble returns the compressed point; drop its prefix byte. */
function sharedX(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return secp256k1.getSharedSecret(privateKey, publicKey).slice(1)
}

/**
 * Encrypts to one public key. Output: ephemeral public key (65) || envelope,
 * where the envelope key is HKDF(ECDH x-coordinate, label).
 */
export async function sealTo(publicKey: Uint8Array, plaintext: Uint8Array, label: string): Promise<Uint8Array> {
  const ephemeral = secp256k1.utils.randomSecretKey()
  const envelope = await seal(derive(sharedX(ephemeral, publicKey), label), plaintext)
  const out = new Uint8Array(65 + envelope.length)
  out.set(secp256k1.getPublicKey(ephemeral, false), 0)
  out.set(envelope, 65)
  return out
}

export async function openWith(privateKeyHex: `0x${string}`, sealed: Uint8Array, label: string): Promise<Uint8Array> {
  return open(derive(sharedX(hexToBytes(privateKeyHex), sealed.subarray(0, 65)), label), sealed.subarray(65))
}

/** Wraps an epoch key for one member: sealTo with label `wrap/<epoch>`. */
export function wrapForMember(epochKey: Uint8Array, memberPublicKey: Uint8Array, epoch: number): Promise<Uint8Array> {
  return sealTo(memberPublicKey, epochKey, `wrap/${epoch}`)
}

export function unwrapAsMember(wrapped: Uint8Array, memberPrivateKeyHex: `0x${string}`, epoch: number): Promise<Uint8Array> {
  return openWith(memberPrivateKeyHex, wrapped, `wrap/${epoch}`)
}

/** Largest integer a Yjs client id can safely be (Number.MAX_SAFE_INTEGER). */
const CLIENT_ID_MASK = (1n << 53n) - 1n

/**
 * A Yjs client id derived from the writer's address: the first 8 bytes of
 * keccak256(address || salt), masked to 53 bits. Readers check every edit's
 * client ids against its on-chain creator, so writing under someone else's
 * id needs a 2^53 preimage search.
 */
export function clientIdFor(address: string, salt: Uint8Array): number {
  const addr = hexToBytes(address)
  if (addr.length !== 20 || salt.length !== 16) throw new Error("clientIdFor needs a 20-byte address and a 16-byte salt")
  const input = new Uint8Array(20 + salt.length)
  input.set(addr, 0)
  input.set(salt, 20)
  const h = keccak_256(input)
  let n = 0n
  for (let i = 0; i < 8; i++) n = (n << 8n) | BigInt(h[i]!)
  const id = Number(n & CLIENT_ID_MASK)
  return id === 0 ? 1 : id
}
