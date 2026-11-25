// Shared by the night-explain labs (why, techniques, respond, moment). Not a lab itself (no index.tsx, so the
// registry leaves this folder alone); each lab can be deleted without breaking the others.
import type { ReactNode } from "react";
import { LabPanel, LabState, useLab } from "../kit";
import { labHref } from "../registry";
import { fill, pieces } from "./logic";
import "./explain.css";

export interface AlertRow { id: string; title: string; level: string; time: string; host: string; source: string; rule_id: string; reason: string; declared: boolean }

export function Level({ level }: { level: string }) {
  return <span className="xp-level" data-level={level}>{level}</span>;
}

export function Marked({ value, spans }: { value: string; spans?: number[][] }) {
  return <>{pieces(value, spans).map((p, i) => (p.hit ? <mark key={i} className="xp-hit">{p.text}</mark> : <span key={i}>{p.text}</span>))}</>;
}

/** Internal ids (rule ids, file names, link types) behind a small "details" toggle (W3-6): there for whoever asks. */
export function Ids({ label, children }: { label: string; children: ReactNode }) {
  return <details className="xp-ids"><summary>{label}</summary><span>{children}</span></details>;
}

/** "Show the test machinery": a switch and how many lines it hides (the lines are never deleted). */
export function HarnessSwitch({ hidden, on, set, w }: { hidden: number; on: boolean; set: (v: boolean) => void; w: Record<string, string> }) {
  if (!hidden) return null;
  return (
    <p className="xp-row xp-small xp-dim xp-harness">
      {!on ? <span>{fill(w.harness_hidden, { n: hidden })}</span> : null}
      <button className="tq-check" aria-pressed={on} onClick={() => set(!on)}><i />{w.harness_switch}</button>
    </p>
  );
}

/** The alerts the screens show; a click opens `lab` on that alert. `url` = the lab's own list endpoint. */
export function AlertPicker({ lab, url }: { lab: string; url: string }) {
  const { data, error, loading } = useLab<{ words: Record<string, string>; alerts: AlertRow[] }>(url);
  return (
    <LabState loading={loading} error={error} empty={data && data.alerts.length === 0 ? data.words.no_alerts : null}>
      {data && (
        <LabPanel title={data.words.pick}>
          <ul className="xp-pick">{data.alerts.map((a) => (
            <li key={a.id}><a href={labHref(lab, { alert: a.id })}><Level level={a.level} /><span className="xp-grow">{a.title}</span>
              <span className="xp-small xp-dim xp-mono">{a.time}</span></a></li>))}</ul>
        </LabPanel>)}
    </LabState>
  );
}
