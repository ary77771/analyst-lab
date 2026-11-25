// Lab: Rule sandbox (night-tools, 2026-11-25, EXPERIMENTAL). Try a detection idea against what was recorded on the
// test machine: paste a Sigma rule (or start from one the lab runs), press "Try it", see what it would have matched.
// Back end: engine/labs/rulesandbox.py (the real detectors' own loading and matching; every word from there).
import { useState, type FormEvent } from "react";
import { FlaskConical } from "lucide-react";
import { LabNumber, LabPanel, LabState, useLab } from "../kit";
import type { Lab, LabProps } from "../registry";
import "./rulesandbox.css";

export interface Words {
  title: string; intro: string; sandbox: string; start_from: string; try: string; trying: string; matches: string;
  declared: string; windows: string; runs: string; outside: string; sample: string; fields_note: string; none: string;
  kinds: Record<string, string>; categories: string; unnamed: string;
}
interface Overview {
  words: Words; limits: { seconds: number; chars: number; sample: number }; categories: string[];
  starting: { key: string; title: string; source: string }[];
}
export interface Scenario { scenario: string | null; runs: number; records: number; kind: string | null; name: string }
export interface RuleAnswer {
  id: string; title: string; level: string; correlation: boolean; raised: boolean; level_line: string;
  alerts: number; records: number; declared: number; windows: number | null;
  runs: { run_id: string; scenario: string | null; records: number }[]; outside: number; scenarios: Scenario[];
  warnings: string[]; sample: { time: string; event_id: number; fields: { field: string; value: string; read: boolean }[] }[];
  fields: string[];
}
export interface Answer { rules: RuleAnswer[]; errors: string[] }

const utc = (t: string | null | undefined) => (t ? `${t.slice(0, 10)} ${t.slice(11, 19)} UTC` : "");

/** One tried rule's answer: numbers, warnings for innocent / control / baseline runs, scenarios, a sample. */
export function RuleResult({ r, w }: { r: RuleAnswer; w: Words }) {
  return (
    <LabPanel title={r.title}>
      <p className="rs-level" data-raised={r.raised || undefined}>{r.level_line}</p>
      <div className="lab-numbers">
        <LabNumber value={r.records} label={w.matches} />
        {r.declared > 0 && <LabNumber value={r.declared} label={w.declared} />}
        {r.correlation && <LabNumber value={r.windows ?? 0} label={w.windows} />}
        <LabNumber value={r.runs.length} label={w.runs.toLowerCase()} />
      </div>
      {r.records === 0 && <p className="lab-state" data-kind="empty">{w.none}</p>}
      {r.warnings.length > 0 && (
        <ul className="rs-warnings" role="note">{r.warnings.map((x) => <li key={x}>{x}</li>)}</ul>
      )}
      {r.scenarios.length > 0 && (
        <>
          <h3 className="rs-sub">{w.runs}</h3>
          <table className="rs-table">
            <tbody>
              {r.scenarios.map((s) => (
                <tr key={s.scenario ?? "none"} data-kind={s.kind ?? "unknown"}>
                  <td>{s.name}</td>
                  <td><span className="rs-kind" data-kind={s.kind ?? "unknown"}>{w.kinds[s.kind ?? "null"] ?? w.kinds["null"] ?? s.kind}</span></td>
                  <td className="num">{s.runs} run(s)</td><td className="num">{s.records} record(s)</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {r.outside > 0 && <p className="ua-hint">{r.outside} {w.outside}.</p>}
      {r.sample.length > 0 && (
        <details className="rs-sample" open>
          <summary>{w.sample} ({r.sample.length} of {r.records})</summary>
          <p className="ua-hint">{w.fields_note}</p>
          <ol>
            {r.sample.map((s, i) => (
              <li key={i}>
                <span className="rs-meta">{utc(s.time)} · event {s.event_id}</span>
                <dl>
                  {s.fields.map((f) => (
                    <div key={f.field} data-read={f.read || undefined}><dt>{f.field}</dt><dd><code>{f.value}</code></dd></div>
                  ))}
                </dl>
              </li>
            ))}
          </ol>
        </details>
      )}
    </LabPanel>
  );
}

async function send<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(String((await r.json().catch(() => null))?.detail ?? `${r.status} ${r.statusText}`));
  return (await r.json()) as T;
}

function RuleSandboxLab(_: LabProps) {
  const { data, error, loading } = useLab<Overview>("/api/labs/rulesandbox");
  const [text, setText] = useState("");
  const [picked, setPicked] = useState("");
  const [busy, setBusy] = useState(false);
  const [answer, setAnswer] = useState<Answer | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const w = data?.words;

  const pick = (key: string) => {
    setPicked(key);
    if (!key) return;
    fetch(`/api/labs/rulesandbox/rule/${encodeURIComponent(key)}`)
      .then(async (r) => { if (!r.ok) throw new Error((await r.json().catch(() => null))?.detail ?? r.statusText); return r.json(); })
      .then((x: { yaml: string }) => { setText(x.yaml); setAnswer(null); setProblem(null); })
      .catch((e) => setProblem(String(e instanceof Error ? e.message : e)));
  };
  const tryIt = (e: FormEvent) => {
    e.preventDefault();
    setBusy(true); setProblem(null); setAnswer(null);
    send<Answer>("/api/labs/rulesandbox/try", { yaml: text })
      .then(setAnswer).catch((x) => setProblem(String(x instanceof Error ? x.message : x))).finally(() => setBusy(false));
  };

  return (
    <div className="rs-page">
      <LabState loading={loading} error={error}>
        {data && w && (
          <>
            <LabPanel title={w.title} hint={w.intro}>
              <p className="rs-sandbox" role="note">{w.sandbox}</p>
              <form className="rs-form" onSubmit={tryIt}>
                {data.starting.length > 0 && (
                  <label className="rs-row"><span className="ua-hint">{w.start_from}</span>
                    <select className="rs-select" value={picked} onChange={(e) => pick(e.target.value)}>
                      <option value="">…</option>
                      {data.starting.map((s) => <option key={s.key} value={s.key}>{s.title} ({s.source})</option>)}
                    </select>
                  </label>
                )}
                <textarea className="rs-text" value={text} onChange={(e) => setText(e.target.value)} rows={14} spellCheck={false}
                  aria-label="Sigma rule (YAML)" placeholder={"title: ...\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '\\example.exe'\n  condition: selection\nlevel: medium"} />
                <div className="rs-row">
                  <button className="ua-btn" data-kind="primary" type="submit" disabled={busy || !text.trim()}>{busy ? w.trying : w.try}</button>
                  <span className="ua-hint">{w.categories}: {data.categories.join(", ")} · at most {data.limits.seconds} s per try</span>
                </div>
              </form>
              {problem && <p className="lab-state" data-kind="error" role="alert">{problem}</p>}
            </LabPanel>
            {answer && answer.rules.map((r) => <RuleResult key={r.id} r={r} w={w} />)}
            {answer && answer.errors.length > 0 && <p className="ua-hint">{answer.errors.join(" · ")}</p>}
          </>
        )}
      </LabState>
    </div>
  );
}

export const lab: Lab = {
  id: "rulesandbox",
  title: "Rule sandbox",
  blurb: "Try a detection idea: paste a Sigma rule and see what it would have matched on the test machine, run by run.",
  icon: FlaskConical,
  group: "tool",
  Component: RuleSandboxLab,
};
