// The Report view of a story (design A): the same rows the film tells, all at once, in the same
// order (Python's), each with its ink, its number and its recorded time. Selecting a row shows the
// recorded events behind it; a suspected link also shows its four plain lines. Below: what this
// investigation cannot see. Every sentence comes from the Python report; nothing is added here.
import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { api, type Citation, type Ink, type Investigation } from "../api";
import { InkLine, INKS, UI } from "./bits";
import { useLive } from "./hooks";
import { utcTime, type Row } from "./logic";

function Record({ c }: { c: Citation }) {
  const { words: w } = useLive();
  const [open, setOpen] = useState(false);
  const [rec, setRec] = useState<Record<string, unknown> | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const toggle = () => {
    setOpen(!open);
    if (!rec && !open) api.event(c.key).then(setRec).catch((e) => setErr(String(e)));
  };
  const hide = new Set(["dedup_key", "id"]);
  return (
    <li className="ua-record" data-open={open}>
      <button onClick={toggle}>
        {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
        <span>{w.events[String(c.event)] ?? c.text}</span>
        <small>{UI.record} {c.record} · {utcTime(c.time)}</small>
      </button>
      {open && (
        <div>
          {err ? <p>{UI.error} {err}</p> : !rec ? <p>{UI.loading}</p> : (
            <dl>{Object.entries(rec).filter(([k, v]) => !hide.has(k) && v !== "" && v !== null).map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{String(v)}</dd></div>)}</dl>
          )}
        </div>
      )}
    </li>
  );
}

export default function Report({ inv, rows }: { inv: Investigation; rows: Row[] }) {
  const { words: w } = useLive();
  const v = inv.report.verdict, c = inv.report.counts;
  const [sel, setSel] = useState<string | null>((rows.find((r) => r.n === 1) ?? rows[0])?.id ?? null);
  const cur = rows.find((r) => r.id === sel) ?? null;
  const totals: Record<Ink, number> = { fact: c?.facts ?? 0, hypothesis: c?.hypotheses ?? 0, gap: c?.gaps ?? 0 };
  return (
    <section className="ua-report">
      <div className="ua-panel ua-report-steps">
        <header>
          <h2>{w.steps_title}</h2>
          <div className="ua-report-nums">
            {INKS.map((ink) => <span key={ink} data-ink={ink}><b>{totals[ink]}</b><InkLine ink={ink} width={22} weight={2.5} />{w.inks[ink].word}</span>)}
          </div>
        </header>
        <ol>
          {rows.map((r) => (
            <li key={r.id} data-step-id={r.id} data-ink={r.ink} data-on={r.id === sel}>
              <button onClick={() => setSel(r.id)}>
                <em data-step={r.n ? "true" : "false"}>{r.n ?? ""}</em>
                <span className="ua-report-ink"><InkLine ink={r.ink} width={26} weight={3} />{w.inks[r.ink].word}{r.bandLabel ? ` · ${r.bandLabel}` : ""}</span>
                <span className="ua-report-text">{r.short}</span>
                <small>{r.offset ?? ""}</small>
              </button>
            </li>
          ))}
        </ol>
        {v?.offset_from && <footer>{w.offset_note.replace("{ref}", v.offset_from)}</footer>}
      </div>

      <div className="ua-report-side">
        <div className="ua-panel ua-report-proof" data-ink={cur?.ink} key={cur?.id ?? "none"}>
          {cur ? (
            <>
              <div className="ua-report-stamp"><InkLine ink={cur.ink} width={40} weight={4} /><strong>{w.inks[cur.ink].word}</strong><span>{cur.bandLabel ?? w.inks[cur.ink].explain}</span></div>
              <p className="ua-report-sentence">{cur.short}</p>
              {cur.ink === "gap" && cur.detail && <p className="ua-report-note">{cur.detail}</p>}
              {cur.chance && <p className="ua-report-note" data-ink="hypothesis">{cur.chance}</p>}
              {cur.plain && <dl className="ua-report-plain">{cur.plain.map((l, i) => <div key={i}><dt>{l.label}</dt><dd>{l.text}</dd></div>)}</dl>}
              {cur.citations.length > 0 && (
                <>
                  <h3>{w.evidence_title}</h3>
                  <ul className="ua-reclist">{cur.citations.map((x) => <Record key={x.key} c={x} />)}</ul>
                </>
              )}
            </>
          ) : <p className="ua-empty">{w.evidence_hint}</p>}
        </div>
        <div className="ua-panel ua-report-limits">
          <h2>{w.limits_title}</h2>
          <ul>{inv.report.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
        </div>
      </div>
    </section>
  );
}
