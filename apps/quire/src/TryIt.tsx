import { useEffect, useState } from "react"
import * as Y from "yjs"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import { bucketFor, clientIdFor, deriveEpochZeroKey, encodeFrame, encodeOuter, KIND, open, PAD_BUCKETS, randomBytes, seal, decodeFrame, decodeOuter } from "y-arkiv"
import { hexPreview } from "./format"

/**
 * The real write path, run on this page: text becomes a Yjs update, is framed,
 * padded and encrypted exactly as an edit is before it goes to Arkiv.
 * Nothing is sent anywhere.
 */
const secret = randomBytes(32)
const doc = randomBytes(32)
const docHex = `0x${Array.from(doc, (b) => b.toString(16).padStart(2, "0")).join("")}`
// a throwaway writer, exactly as a real member: key, session salt, signed salt, derived client id
const writer = privateKeyToAccount(generatePrivateKey())
const salt = randomBytes(16)
const saltHex = Array.from(salt, (b) => b.toString(16).padStart(2, "0")).join("")
const sigPromise = writer.signMessage({ message: { raw: new Uint8Array([...new TextEncoder().encode("quire1:salt:"), ...doc, ...salt]) } })

type Out = { payload: Uint8Array; plainBytes: number; frameBytes: number; header: string; text: string }

async function encrypt(text: string): Promise<Out> {
  const y = new Y.Doc()
  y.clientID = clientIdFor(writer.address, salt)
  const p = new Y.XmlElement("paragraph")
  p.insert(0, [new Y.XmlText(text)])
  y.getXmlFragment("default").push([p])
  const update = Y.encodeStateAsUpdate(y)
  const key = deriveEpochZeroKey(secret)
  const frame = encodeFrame({ kind: KIND.update, doc, epoch: 0, header: { t: Date.now(), salt: saltHex, sig: await sigPromise }, data: update }, randomBytes)
  const payload = encodeOuter(0, await seal(key, frame))
  const opened = decodeFrame(await open(key, decodeOuter(payload).envelope))
  const back = new Y.Doc()
  Y.applyUpdate(back, opened.data)
  const shown = (back.getXmlFragment("default").toArray()[0] as Y.XmlElement | undefined)?.toArray().map((t) => t.toString()).join("") ?? ""
  const h = opened.header as { t: number; salt: string; sig: string }
  return { payload, plainBytes: update.length, frameBytes: frame.length, header: `t ${h.t}, salt ${h.salt.slice(0, 8)}…, sig ${h.sig.slice(0, 10)}…`, text: shown }
}

export function TryIt() {
  const [text, setText] = useState("Meeting moved to Thursday. Bring the draft budget.")
  const [reveal, setReveal] = useState(false)
  const [out, setOut] = useState<Out | null>(null)
  useEffect(() => {
    let alive = true
    encrypt(text).then((o) => alive && setOut(o))
    return () => {
      alive = false
    }
  }, [text])
  const bucket = out ? bucketFor(out.frameBytes) : 0

  return (
    <div className="try">
      <div className="card card--raised">
        <div>
          <label className="t-micro" htmlFor="try-text">
            Type something private
          </label>
          <textarea id="try-text" value={text} maxLength={4000} onChange={(e) => setText(e.target.value)} />
        </div>
        <div className="row-switch">
          <span>Show what a member's browser decrypts</span>
          <input className="switch" type="checkbox" checked={reveal} onChange={(e) => setReveal(e.target.checked)} aria-label="Show decrypted view" />
        </div>
        <p className="t-micro">
          This runs Quire's real encryption in your browser with a throwaway key. Nothing leaves this page.
        </p>
      </div>
      <div className="stage stage--soft try-out">
        <div className="window" aria-live="polite">
          <div className="window__bar">
            <div className="lights">
              <i />
              <i />
              <i />
            </div>
            <span className="window__title">{reveal ? "Decrypted in a member's browser" : "What anyone on the explorer sees"}</span>
          </div>
          <div className="window__body">
            {!reveal ? (
              <>
                <dl className="kv">
                  <dt>qp</dt>
                  <dd>str "quire1"</dd>
                  <dt>qd</dt>
                  <dd>bytes32 {docHex.slice(0, 18)}…</dd>
                  <dt>qk</dt>
                  <dd>str "u"</dd>
                  <dt>qs</dt>
                  <dd>u64, the block height</dd>
                  <dt>payload</dt>
                  <dd>{out ? `${out.payload.length} bytes` : "…"}</dd>
                </dl>
                <div className="bytes">{out ? hexPreview(out.payload, 220) : ""}</div>
                <div>
                  <p className="t-micro" style={{ marginBottom: 8 }}>
                    The plaintext is padded to one of six sizes before encryption, so the payload's length gives away little about what you typed. Payload = 6-byte header + padded frame + 28 bytes of encryption overhead.
                  </p>
                  <div className="buckets">
                    {PAD_BUCKETS.map((b) => (
                      <span key={b} className={b === bucket ? "on" : ""}>
                        {b >= 1024 ? `${b / 1024} KiB` : `${b} B`}
                      </span>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <>
                <dl className="kv">
                  <dt>kind</dt>
                  <dd>edit, epoch 0</dd>
                  <dt>header</dt>
                  <dd>{out?.header}</dd>
                  <dt>Yjs data</dt>
                  <dd>{out?.plainBytes} bytes, padded to {bucket}</dd>
                </dl>
                <p style={{ font: "400 22px/1.45 var(--doc-font)" }}>{out?.text || " "}</p>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
