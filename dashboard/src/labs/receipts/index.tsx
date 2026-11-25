// Lab: Alarm track record ("receipts") (night-tools, 2026-11-24). Each alarm's record from the committed v4
// results: normal use, public tests, blind runs. Back end: engine/labs/receipts.py (all words and numbers there).
import { Receipt } from "lucide-react";
// No NextStrip here (Fable's visual pass, 2026-11-24): this page checks the tool itself, it is not a step of an
// alert's investigation. The alert in the address still focuses the list.
import { LabNumber, LabPanel, LabState, useAlertParam, useLab } from "../kit";
import { AlertScope } from "../fileinspect/alertscope";
import { labHref, type Lab, type LabProps } from "../registry";
import "../fileinspect/fileinspect.css";

interface Words {
  title: string; intro: string; normal: string; normal_line: string; normal_note: string; public: string; public_line: string;
  blind: string; blind_line: string; never: string; blind_none: string; blind_verdict?: Record<string, string>; blind_kind?: Record<string, string>; alerts: string; all: string; cite: string;
  hours_label?: string; hours_source?: string;
}
interface HoursSource { hours: number; period: string | null; code: string | null; file: string; commit: string | null; date: string | null }
export interface Rec {
  rule: string | null; title: string | null; measured: boolean;
  normal: { alerts: number; per_hour: number; days: number; programs: number; hours: number; period?: string } | null;
  public: { tests: number; techniques: string[]; executed: number } | null;
  blind: { alerts: number; runs: number; total: number } | null;
  blind_verdicts?: { round: number; scenarios: string[]; kind: string; runs: number; outcome: string }[] | null;
}
interface Source { kind: string; file: string; present: boolean; commit: string | null; date: string | null }
interface Body {
  words: Words; sources: Source[]; hours: number | null; period?: string | null; hours_source?: HoursSource | null; executed: number; blind_runs: number; blind_rules: number;
  alerts: { id: string; title: string; rule: string; level: string; time: string; record: Rec }[]; rules: Rec[];
}

export const fill = (s: string, v: Record<string, string | number>) => s.replace(/\{(\w+)\}/g, (_, k) => String(v[k] ?? `{${k}}`));

/** The active-hours number's label, naming the week it was counted on (other pages may count another week). */
export function hoursLabel(d: Pick<Body, "words" | "period">): string {
  return d.words.hours_label && d.period ? fill(d.words.hours_label, { period: d.period }) : "active hours of normal use counted";
}

/** "Active hours: 47.5 h, laptop week … (a test of normal use), counted with the v4 code. Source: <file> at commit <hash>. …" or null. */
export function hoursSource(d: Pick<Body, "words" | "hours_source">): string | null {
  const s = d.hours_source;
  if (!s || !d.words.hours_source) return null;
  return fill(d.words.hours_source, { hours: s.hours, period: s.period ?? "not stated in the file", code: s.code ?? "the frozen code",
                                      file: s.file, commit: s.commit ?? "unknown" });
}

/** The record's lines in Python's words: one per source that has a number, or "never measured". */
export function lines(r: Rec, w: Words): string[] {
  if (!r.measured) return [w.never];
  const out: string[] = [];
  if (r.normal) out.push(fill(w.normal_line, { ...r.normal, period: r.normal.period ?? "the week measured" }) + ". " + w.normal_note);
  if (r.public) out.push(fill(w.public_line, { tests: r.public.tests, executed: r.public.executed }) + ` (${r.public.techniques.join(", ")})`);
  if (r.blind) out.push(fill(w.blind_line, r.blind));
  for (const v of r.blind_verdicts ?? []) {
    const tpl = w.blind_verdict?.[v.outcome];
    if (tpl) out.push(fill(tpl, { round: v.round, scenarios: v.scenarios.join(" and "), kind: w.blind_kind?.[v.kind] ?? v.kind, runs: v.runs }));
  }
  return out;
}

function RecordLines({ r, w }: { r: Rec; w: Words }) {
  return <ul className="rc-lines">{lines(r, w).map((l) => <li key={l} data-never={!r.measured || undefined}>{l}</li>)}</ul>;
}

function ReceiptsLab(_: LabProps) {
  const { data: d, error, loading } = useLab<Body>("/api/labs/receipts");
  const [focus, setAlert] = useAlertParam();
  const picked = d?.alerts.find((a) => a.id === focus) ?? null;
  const shown = d ? (focus ? d.alerts.filter((a) => a.id === focus) : d.alerts) : [];
  return (
    <div className="ft-details">
    <LabState loading={loading} error={error}>
      {d && (
        <div className="ft-details">
          <LabPanel title={d.words.title} hint={d.words.intro}>
            <div className="lab-numbers">
              <LabNumber value={d.hours ?? "?"} label={hoursLabel(d)} title={hoursSource(d) ?? undefined} />
              <LabNumber value={d.executed} label="public tests run" />
              <LabNumber value={d.blind_runs} label="blind runs scored" />
            </div>
            {hoursSource(d) && <p className="ua-hint rc-hours-source">{hoursSource(d)}</p>}
            {d.blind_rules === 0 && <p className="ua-hint">{fill(d.words.blind_none, { total: d.blind_runs })}</p>}
            <p className="ua-hint">
              {d.words.cite}: {d.sources.map((s) => `${s.file}${s.commit ? ` @ ${s.commit} (${s.date})` : ""}`).join(" · ")}
            </p>
          </LabPanel>
          <LabPanel title={d.words.alerts}>
            <AlertScope alert={focus} title={picked?.title} onClear={() => setAlert(null)} what="The record" />
            {focus && !picked && <p className="lab-state" data-kind="empty">This alert isn't in this recording.</p>}
            {d.alerts.length === 0 && <p className="ua-hint">No alert at or above the screens' level in this store.</p>}
            {shown.map((a) => (
              <div key={a.id} className="ft-tool" data-focus={a.id === focus || undefined}>
                <header>
                  <b>{a.title}</b><span className="ft-tag">{a.level}</span>
                  <span>{a.time.slice(0, 19).replace("T", " ")} UTC</span>
                  {!focus && <button type="button" className="ft-a ft-linkbtn" onClick={() => setAlert(a.id)}>follow this alert</button>}
                  <a className="ft-a" href={labHref("why", { alert: a.id })}>why this alert</a>
                </header>
                <RecordLines r={a.record} w={d.words} />
              </div>
            ))}
          </LabPanel>
          <LabPanel title={d.words.all}>
            <details className="rc-all"><summary>Show the table of every rule with a record ({d.rules.length})</summary>
            <table className="ft-table">
              <thead><tr><th>Rule</th><th>{d.words.normal}</th><th>{d.words.public}</th></tr></thead>
              <tbody>
                {d.rules.map((r) => (
                  <tr key={`${r.rule ?? ""}|${r.title ?? ""}`}>
                    <td>{r.title ?? <code>{r.rule}</code>}</td>
                    <td>{r.normal ? `${r.normal.alerts} (${r.normal.per_hour} / active hour)` : "-"}</td>
                    <td>{r.public ? `${r.public.tests} of ${r.public.executed}` : "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            </details>
          </LabPanel>
        </div>
      )}
    </LabState>
    </div>
  );
}

export const lab: Lab = {
  id: "receipts",
  title: "Alarm track record",
  blurb: "How often each alarm has rung before on normal use and on the lab's tests, counted from the published results.",
  icon: Receipt,
  group: "tool",
  Component: ReceiptsLab,
};
