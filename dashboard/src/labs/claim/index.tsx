// Test a claim (night-pivot, 2026-11-24; VISION's idea #2). Back end: engine/labs/claim.py.
// Build one sentence from an alert's own story, [thing] [verb] [thing], and the lab answers from the evidence
// graph only: the fact's ink, the suspicion's ink, the gap's ink, or "No recorded evidence" (never "false").
// Every answer word comes from Python; every cited record is a pivot link.
import { useEffect, useState, type FormEvent } from "react";
import { Scale } from "lucide-react";
import type { Lab, LabProps } from "../registry";
import { NextStrip, useAlertParam } from "../kit";
import { PlusCase, Thing } from "../_things";
import { getJsonPatient, plainError } from "../_things/net";
import { utc, type Entity } from "../pivot/links";
import "./claim.css";

interface AlertRow { id: string; title: string; level: string; time: string }
interface Node { id: string; label: string; kind: string; kind_word?: string; plain?: string; pid?: number | null; gaps: string[]; entity: Entity | null }
interface Suggestion { subject: string; verb: string; object: string; claim: string; plain?: string; answer: string; word: string }
interface Parts { alert: AlertRow; nodes: Node[]; verbs: { id: string; word: string }[]; suggestions: Suggestion[]; answers: Record<string, string>;
  machinery_hidden?: number; machinery_word?: string }
interface Citation { key: string; time: string | null; summary: string; entities: Entity[] }
interface Because {
  sentence: string; time?: string; band?: string | null; band_word?: string; reason?: string | null; alternative?: string | null;
  gap?: string; missing?: string; citations: Citation[];
}
interface Answer {
  claim: string; answer: string; ink: string | null; word: string;
  because: Because[]; note?: string; also?: { sentence: string; ink: string }[];
  subject_entity: Entity | null; object_entity: Entity | null; subject_plain?: string; object_plain?: string;
}

const TEXT = {
  pick: "Alert whose story to question",
  intro: "Build one sentence from the things in this alert's story. The answer comes only from the records and the evidence graph.",
  tryThese: "Try these",
  tryHint: "Pick a sentence: the lab checks it against what was recorded.",
  ownClaim: "Or build your own claim",
  ownHint: "Choose a thing, what it did, and another thing from this alert's story.",
  test: "Test the claim",
  because: "Because",
  missing: "Missing witness:",
  why: "Why:",
  other: "Other explanation:",
  also: "What is recorded between these two instead",
  cites: "Records",
  pin: "Pin this answer to the case",
  none: "There is no alert from the lab machine to question yet.",
  loading: "Reading the story…",
  asking: "Checking the records…",
  things: "the things in the story",
};

async function getJson<T>(url: string): Promise<T> {
  return getJsonPatient<T>(url);                     // asks again while the server restarts (_things/net.ts)
}

function ThingSelect({ value, nodes, onChange, label }: { value: string; nodes: Node[]; onChange: (v: string) => void; label: string }) {
  return (
    <select className="cl-select" value={value} onChange={(e) => onChange(e.target.value)} aria-label={label}>
      {nodes.map((n) => <option key={n.id} value={n.id}>{n.plain ?? n.label}{n.kind_word ? `, ${n.kind_word}` : ""}</option>)}
    </select>
  );
}

function AnswerCard({ a }: { a: Answer }) {
  return (
    <section className="ua-panel cl-answer" data-answer={a.answer} data-ink={a.ink ?? "none"} aria-live="polite">
      <div className="cl-verdict">
        <span className="cl-word">{a.word}</span>
        <p className="cl-claim">“{a.claim}”</p>
        <span className="cl-grow" />
        <PlusCase hypothesis={`${a.claim}: ${a.word} (tested in the claim lab)`} label={`${a.claim}: ${a.word}`} text={TEXT.pin} />
      </div>
      {a.note && <p className="cl-note">{a.note}</p>}
      {a.because.length > 0 && <h3 className="cl-sub">{TEXT.because}</h3>}
      <ul className="cl-list">
        {a.because.map((b, i) => (
          <li key={i} className="cl-because">
            <p className="cl-sentence">{b.sentence}{b.band_word ? <span className="ua-hint"> ({b.band_word})</span> : null}
              {b.time ? <span className="ua-hint num"> · {utc(b.time)}</span> : null}</p>
            {b.missing && <p className="ua-hint"><b>{TEXT.missing}</b> {b.missing}</p>}
            {b.reason && <p className="ua-hint"><b>{TEXT.why}</b> {b.reason}</p>}
            {b.alternative && <p className="ua-hint"><b>{TEXT.other}</b> {b.alternative}</p>}
            {b.citations.length > 0 && (
              <div className="cl-cites"><span className="ua-hint">{TEXT.cites}</span>
                {b.citations.map((c) => (
                  <div key={c.key} className="cl-cite">
                    <span className="num ua-hint">{utc(c.time)}</span><span>{c.summary}</span>
                    <PlusCase event={c.key} label={c.summary} time={c.time} />
                    <div className="pv-chips">{c.entities.map((e) => <Thing key={`${e.kind}|${e.value}`} kind={e.kind} value={e.value} role={e.role} />)}</div>
                  </div>
                ))}
              </div>
            )}
          </li>
        ))}
      </ul>
      {a.also && a.also.length > 0 && (
        <>
          <h3 className="cl-sub">{TEXT.also}</h3>
          <ul className="cl-list">{a.also.map((x, i) => <li key={i} className="cl-also" data-ink={x.ink}>{x.sentence}</li>)}</ul>
        </>
      )}
      <div className="pv-chips">
        {a.subject_entity && <Thing kind={a.subject_entity.kind} value={a.subject_entity.value} label={a.subject_plain} plusCase />}
        {a.object_entity && <Thing kind={a.object_entity.kind} value={a.object_entity.value} label={a.object_plain} plusCase />}
      </div>
    </section>
  );
}

function ClaimLab(_: LabProps) {
  // the alert is kept in the address (#/labs/claim?alert=<id>), so the other labs' strip carries it here and on
  const [alertId, setAlertId] = useAlertParam();
  const [alerts, setAlerts] = useState<AlertRow[] | null>(null);
  const [parts, setParts] = useState<Parts | null>(null);
  const [s, setS] = useState(""), [v, setV] = useState(""), [o, setO] = useState("");
  const [answer, setAnswer] = useState<Answer | null>(null);
  const [busy, setBusy] = useState(false);
  const [machinery, setMachinery] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getJson<AlertRow[]>("/api/labs/claim/alerts").then((rows) => {
      setAlerts(rows);
      if (!alertId && rows[0]) setAlertId(rows[0].id, "replace");
    }).catch((e) => setErr(plainError(e)));
  }, []);  // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!alertId) return;
    setParts(null); setAnswer(null); setErr(null);
    getJson<Parts>(`/api/labs/claim/${encodeURIComponent(alertId)}/parts${machinery ? "?machinery=true" : ""}`).then((p) => {
      setParts(p);
      const first = p.suggestions[0];
      setS(first?.subject ?? p.nodes[0]?.id ?? ""); setV(first?.verb ?? p.verbs[0]?.id ?? ""); setO(first?.object ?? p.nodes[1]?.id ?? "");
    }).catch((e) => setErr(plainError(e)));
  }, [alertId, machinery]);

  const ask = (subject: string, verb: string, object: string) => {
    if (!alertId) return;
    setS(subject); setV(verb); setO(object); setBusy(true); setErr(null);
    const u = new URLSearchParams({ subject, verb, object });
    getJson<Answer>(`/api/labs/claim/${encodeURIComponent(alertId)}/test?${u}`)
      .then(setAnswer).catch((e) => { setAnswer(null); setErr(plainError(e)); })
      .finally(() => setBusy(false));
  };
  const submit = (e: FormEvent) => { e.preventDefault(); ask(s, v, o); };

  if (alerts && alerts.length === 0) return <p className="lab-state" data-kind="empty">{TEXT.none}</p>;
  return (
    <div className="cl-page">
      <NextStrip current="claim" alert={alertId} />
      <section className="ua-panel cl-panel">
        <label className="cl-row"><span className="ua-hint">{TEXT.pick}</span>
          <select className="cl-select cl-alert" value={alertId ?? ""} onChange={(e) => setAlertId(e.target.value)}>
            {(alerts ?? []).map((a) => <option key={a.id} value={a.id}>{a.title} · {a.level} · {utc(a.time)}</option>)}
          </select>
        </label>
        {!parts && !err && <p className="ua-hint">{TEXT.loading}</p>}
        {parts && parts.suggestions.length > 0 && (
          <div className="cl-try" aria-label={TEXT.tryThese}>
            <h2 className="cl-try-title">{TEXT.tryThese}</h2>
            <p className="ua-hint">{TEXT.tryHint}</p>
            <div className="cl-try-grid">
              {parts.suggestions.map((x) => (
                <button key={`${x.subject}|${x.verb}|${x.object}`} type="button" className="cl-suggest"
                  data-on={answer && answer.claim === x.claim ? "1" : undefined}
                  onClick={() => ask(x.subject, x.verb, x.object)}>“{x.plain ?? x.claim}”</button>
              ))}
            </div>
          </div>
        )}
        {parts && (
          <details className="cl-own" open={parts.suggestions.length === 0}>
            <summary>{TEXT.ownClaim}</summary>
            <p className="ua-hint">{TEXT.ownHint} {TEXT.intro}</p>
            <form className="cl-builder" onSubmit={submit}>
              <ThingSelect value={s} nodes={parts.nodes} onChange={setS} label={TEXT.things} />
              <select className="cl-select cl-verb" value={v} onChange={(e) => setV(e.target.value)} aria-label="verb">
                {parts.verbs.map((x) => <option key={x.id} value={x.id}>{x.word}</option>)}
              </select>
              <ThingSelect value={o} nodes={parts.nodes} onChange={setO} label={TEXT.things} />
              <button className="ua-btn" data-kind="primary" type="submit" disabled={busy}><Scale size={15} />{TEXT.test}</button>
            </form>
            {(parts.machinery_hidden ?? 0) > 0 || machinery ? (
              <label className="ua-hint cl-machinery">
                <input type="checkbox" checked={machinery} onChange={(e) => setMachinery(e.target.checked)} />{" "}
                {parts.machinery_word}{!machinery ? ` (${parts.machinery_hidden})` : ""}
              </label>
            ) : null}
          </details>
        )}
      </section>
      {err && <p className="lab-state" data-kind="error" role="alert">{err}</p>}
      {busy && <p className="ua-hint">{TEXT.asking}</p>}
      {answer && !busy && <AnswerCard a={answer} />}
    </div>
  );
}

export const lab: Lab = {
  id: "claim",
  title: "Test a claim",
  blurb: "Say what you think happened, from the alert's own story, and see what the records support: a fact, a suspicion, a missing witness, or nothing recorded.",
  icon: Scale,
  Component: ClaimLab,
};
