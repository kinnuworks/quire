import { useEffect, useRef, useState } from "react"

/**
 * The contested-authorship demo on Tiramisu, as `y-arkiv timeline` prints it: every edit, its block,
 * its author and its words. Asha owns the document; Bea co-writes it; then Asha erases Bea from the
 * member list and pastes Bea's finding back as one edit of her own.
 */
export const CONTESTED = "#/d/DqGiOcF4WHKgOkfcBcEansmEdytSLBHDv5EkQf6YNFQ.EBkcdL5buH73K8vSpkP_8akeH1w-npysYnwdf3SzokY.b83063cf00de65f09187c9600b0b3fd951f60fb0"
type Who = "asha" | "bea"
type Edit = { block: number; who: Who; para: 0 | 1 | 2 | 3; text: string; paste?: boolean }
const EDITS: Edit[] = [
  { block: 734898, who: "asha", para: 0, text: "Water access study, section 3" },
  { block: 734902, who: "asha", para: 1, text: "We surveyed forty" },
  { block: 734908, who: "asha", para: 1, text: " households in Ward" },
  { block: 734913, who: "asha", para: 1, text: " 14 over thirty" },
  { block: 734918, who: "asha", para: 1, text: " days, twice a" },
  { block: 734922, who: "asha", para: 1, text: " day." },
  { block: 734926, who: "bea", para: 2, text: "Key finding: taps" },
  { block: 734931, who: "bea", para: 2, text: " ran dry on" },
  { block: 734938, who: "bea", para: 2, text: " eleven of thirty" },
  { block: 734944, who: "bea", para: 2, text: " days, three times" },
  { block: 734949, who: "bea", para: 2, text: " the figure in" },
  { block: 734955, who: "bea", para: 2, text: " the city's own" },
  { block: 734961, who: "bea", para: 2, text: " report." },
  { block: 734971, who: "asha", para: 3, text: "We recommend the" },
  { block: 734975, who: "asha", para: 3, text: " city publish its" },
  { block: 734979, who: "asha", para: 3, text: " supply log every" },
  { block: 734984, who: "asha", para: 3, text: " week." },
  { block: 735002, who: "asha", para: 2, text: "Key finding: taps ran dry on eleven of thirty days, three times the figure in the city's own report.", paste: true },
]
const FIRST = 734896
const LAST = 735006
const PASTE = 735002
const BEA_LAST = 734961
const NAMES: Record<Who, string> = { asha: "Asha", bea: "Bea" }
const ADDR: Record<Who, string> = { asha: "0xb830…0fb0", bea: "0xa1a1…4ec4" }

function stateAt(block: number) {
  const paras: { text: string; who: Who | null; copied?: boolean }[] = [0, 1, 2, 3].map(() => ({ text: "", who: null }))
  for (const e of EDITS) {
    if (e.block > block) break
    if (e.paste) paras[e.para] = { text: e.text, who: e.who, copied: true }
    else paras[e.para] = { text: paras[e.para]!.text + e.text, who: e.who }
  }
  return paras
}

/** Drag through the blocks and watch the document, the member list and the chain's verdict change. */
export function Scrubber() {
  const [block, setBlock] = useState(734966)
  const [playing, setPlaying] = useState(false)
  const timer = useRef<ReturnType<typeof setInterval> | null>(null)
  useEffect(() => {
    if (!playing) return
    if (block >= LAST) setBlock(FIRST)
    timer.current = setInterval(() => {
      setBlock((b) => {
        if (b >= LAST) {
          setPlaying(false)
          return b
        }
        return b + 1
      })
    }, 90)
    return () => {
      if (timer.current) clearInterval(timer.current)
    }
  }, [playing])
  const paras = stateAt(block)
  const beaEdits = EDITS.filter((e) => e.who === "bea" && e.block <= block)
  const erased = block >= PASTE
  const pct = ((block - FIRST) / (LAST - FIRST)) * 100

  let verdict: React.ReactNode
  if (beaEdits.length === 0) verdict = <>The finding is not written yet. Asha is drafting the opening.</>
  else if (!erased)
    verdict = (
      <>
        <b>Proven: Bea.</b> {beaEdits.length} {beaEdits.length === 1 ? "edit" : "edits"} so far, blocks 734926 to {beaEdits[beaEdits.length - 1]!.block}, each signed by her key while she was a member.
      </>
    )
  else
    verdict = (
      <>
        <b>Today the finding reads as Asha's:</b> one edit at block 735002 that removed 100 characters and put the same 100 back. <span className="verdict__twist">Bea typed those words first, at blocks 734926 to 734961, and <code>blame --at 734966</code> still proves them hers.</span>
      </>
    )

  return (
    <div className="scrub">
      <div className="scrub__doc window" aria-label="The contested document at the chosen block">
        <div className="window__bar">
          <div className="lights">
            <i />
            <i />
            <i />
          </div>
          <span className="window__title"><span className="hide-sm">Water access study · </span>block {block}</span>
        </div>
        <div className="doc-mock scrub__paper">
          <h4>{paras[0]!.text || " "}</h4>
          {paras.slice(1).map((p, i) => (
            <p key={i} className={p.copied ? "copied" : ""} style={{ "--bar": p.who ? `var(--author-${p.who === "asha" ? "a" : "b"})` : "transparent" } as React.CSSProperties}>
              {p.text || <span className="scrub__empty"> </span>}
              {p.copied && <span className="copied-tag">typed first by Bea</span>}
            </p>
          ))}
        </div>
      </div>

      <div className="scrub__side">
        <div className="card scrub__members">
          <p className="eyebrow">Member list at this block</p>
          {(["asha", "bea"] as Who[]).map((w) => (
            <div className={`member ${w === "bea" && erased ? "gone" : ""}`} key={w}>
              <span className="dot" style={{ background: `var(--author-${w === "asha" ? "a" : "b"})` }} />
              <div className="who">
                <b>{NAMES[w]}</b>
                <span>{ADDR[w]}</span>
              </div>
              <span className="pill-tag">{w === "asha" ? "owner" : erased ? "erased" : "writer"}</span>
            </div>
          ))}
        </div>
        <div className={`card verdict ${erased ? "verdict--twist" : ""}`} aria-live="polite">
          <p className="eyebrow">What the chain shows</p>
          <p className="verdict__text">{verdict}</p>
        </div>
      </div>

      <div className="scrub__controls card">
        <div className="scrub__row">
          <button type="button" className="btn btn-sm btn-ink" onClick={() => setPlaying((p) => !p)} aria-pressed={playing}>
            {playing ? "Pause" : block >= LAST ? "Replay" : "Play"}
          </button>
          <input
            className="range"
            type="range"
            min={FIRST}
            max={LAST}
            value={block}
            onChange={(e) => {
              setPlaying(false)
              setBlock(Number(e.target.value))
            }}
            style={{ "--val": `${pct}%` } as React.CSSProperties}
            aria-label="Block"
          />
          <span className="t-mono scrub__block">{block}</span>
        </div>
        <Rhythm block={block} onPick={(b) => (setPlaying(false), setBlock(b))} />
        <div className="scrub__marks">
          {[
            { b: 734926, t: "Bea starts the finding" },
            { b: BEA_LAST + 5, t: "Bea done" },
            { b: PASTE, t: "Asha's paste" },
          ].map((m) => (
            <button type="button" key={m.b} className="chip" aria-pressed={block === m.b} onClick={() => (setPlaying(false), setBlock(m.b))}>
              {m.t} <span className="t-mono">{m.b}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

/** Every edit as a bar: height is the characters it added, color is who wrote it. A paste is one tall bar. */
function Rhythm({ block, onPick }: { block: number; onPick: (b: number) => void }) {
  const writes = EDITS.filter((e) => e.para !== 0)
  return (
    <div className="rhythm" role="img" aria-label="Edit rhythm: Bea's seven small edits, then one paste of 100 characters by Asha">
      {writes.map((e) => {
        const left = ((e.block - FIRST) / (LAST - FIRST)) * 100
        const h = Math.max(6, Math.round((e.text.length / 100) * 100))
        return (
          <button
            type="button"
            key={e.block}
            tabIndex={-1}
            className={`rhythm__bar ${e.who} ${e.paste ? "paste" : ""} ${e.block <= block ? "on" : ""}`}
            style={{ left: `${left}%`, height: `${h}%` }}
            onClick={() => onPick(e.block)}
            title={`block ${e.block}: ${NAMES[e.who]} added ${e.text.length} characters${e.paste ? " and removed 100" : ""}`}
          />
        )
      })}
      <span className="rhythm__now" style={{ left: `${((block - FIRST) / (LAST - FIRST)) * 100}%` }} />
    </div>
  )
}

/** The hero: a dark Quire window and a terminal running blame on the same document, on a bold desk. */
export function HeroStage() {
  return (
    <div className="stage brand-stage" aria-hidden="true">
      <div className="duo2">
        <div className="window window--dark hero-doc">
          <div className="window__bar">
            <div className="lights">
              <i />
              <i />
              <i />
            </div>
            <span className="window__title"><span className="hide-sm">Water access study · </span>Who wrote what</span>
          </div>
          <div className="hero-doc__note">
            <b>Typed first by someone else.</b> This paragraph is one paste by Asha. Bea typed the same words, or all but a few, earlier, at blocks 734926 to 734955.
          </div>
          <div className="hero-doc__body">
            <h4>Water access study, section 3</h4>
            <p style={{ "--bar": "var(--author-a)" } as React.CSSProperties}>We surveyed forty households in Ward 14 over thirty days, twice a day.</p>
            <p className="copied" style={{ "--bar": "var(--author-a)" } as React.CSSProperties}>
              Key finding: taps ran dry on eleven of thirty days, three times the figure in the city's own report.
            </p>
            <p style={{ "--bar": "var(--author-a)" } as React.CSSProperties}>We recommend the city publish its supply log every week.</p>
          </div>
        </div>
        <div className="window window--dark term">
          <div className="window__bar">
            <div className="lights">
              <i />
              <i />
              <i />
            </div>
            <span className="window__title">y-arkiv blame --at 734966</span>
          </div>
          <pre className="term__body">
            <span className="term__dim">paragraph 3</span>
            {"\n"}
            <span className="term__b">0xa1a15f…4ec4</span> proven <span className="term__dim">734926</span> "Key finding: taps"{"\n"}
            <span className="term__b">0xa1a15f…4ec4</span> proven <span className="term__dim">734931</span> " ran dry on"{"\n"}
            <span className="term__b">0xa1a15f…4ec4</span> proven <span className="term__dim">734938</span> " eleven of thirty"{"\n"}
            <span className="term__b">0xa1a15f…4ec4</span> proven <span className="term__dim">734944</span> " days, three times"{"\n"}
            <span className="term__b">0xa1a15f…4ec4</span> proven <span className="term__dim">734949</span> " the figure in"{"\n"}
            <span className="term__b">0xa1a15f…4ec4</span> proven <span className="term__dim">734955</span> " the city's own"{"\n"}
            <span className="term__b">0xa1a15f…4ec4</span> proven <span className="term__dim">734961</span> " report."{"\n\n"}
            <span className="term__ok">members checked as the list stood at each block</span>
          </pre>
        </div>
      </div>
      <div className="float hero-float-a">
        <div className="float-row">
          <span className="live-dot" />
          <div>
            <b>Edit from Bea, block 734961</b>
            <div className="t-micro">signed by her key, encrypted in her browser</div>
          </div>
        </div>
      </div>
      <div className="float hero-float-b">
        <div className="float-row">
          <span className="erase-dot" />
          <div>
            <b>Erased from the member list</b>
            <div className="t-micro">still proven at the blocks she wrote</div>
          </div>
        </div>
      </div>
    </div>
  )
}

/** Real numbers from the repository and the chain. */
export function ProofStrip() {
  const items = [
    { n: "3", t: "live documents on Tiramisu, readable right now" },
    { n: "31/31", t: "runs where two independent readers agree" },
    { n: "196", t: "tests, and 86 of 86 broken security rules caught" },
    { n: "MIT", t: "spec, JSON Schema, vectors, two readers" },
  ]
  return (
    <div className="proof">
      {items.map((x, i) => (
        <div className="proof__item reveal" key={x.n} style={{ "--i": i } as React.CSSProperties}>
          <span className="proof__n t-mono">{x.n}</span>
          <span className="proof__t">{x.t}</span>
        </div>
      ))}
    </div>
  )
}
