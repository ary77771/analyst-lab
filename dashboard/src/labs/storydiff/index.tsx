// Lab: Story diff (night-tools, 2026-11-24). Any two recorded test runs side by side: what only A did, what both
// did, what only B did, and which alerts each raised. Back end: engine/labs/storydiff.py (all words from there).
import { useMemo, useState } from "react";
import { GitCompare } from "lucide-react";
// No NextStrip here (Fable's visual pass, 2026-11-24): comparing two runs checks the tool itself, it is not a step
// of an alert's investigation.
import { LabNumber, LabPanel, LabState, useAlertParam, useLab, useRunName } from "../kit";
import { AlertScope } from "../fileinspect/alertscope";
import { labHref, type Lab, type LabProps } from "../registry";
import "../fileinspect/fileinspect.css";
import "./storydiff.css";

type Side = "only_a" | "both" | "only_b";
interface Words {
  title: string; intro: string; kinds: Record<string, string>; only_a: string; both: string; only_b: string; own_steps: string;
  everything: string; raised: string; below: string; same: string; general: string; none: string;
}
export interface Run { id: string; scenario: string | null; start: string | null; replayed: string | null; exit_code: number | null }
interface Step { key: string; count: number; examples: string[] }
interface Kind { kind: string; word: string; only_a: Step[]; both: { key: string; a: Step; b: Step }[]; only_b: Step[] }
interface AlertRow { rule: string; title: string; level: string; count: number }
interface AlertSplit { a: number; b: number; only_a: AlertRow[]; both: AlertRow[]; only_b: AlertRow[] }
export interface Diff {
  a: Run; b: Run; summary: { kind: string; word: string; a: number; b: number; who: Side | "neither" }[]; kinds: Kind[];
  alerts: { raised: AlertSplit; below: AlertSplit }; differences: number; same: boolean; own_processes: { a: number; b: number }; everything: boolean;
}

/** "B18 · 2026-11-20 01:18", or with everyday names "B18 · Fake sync app ... · 2026-11-20 01:18" (useRunName). */
export const runLabel = (r: Run, name?: (id: string) => string) =>
  `${r.scenario ? (name ? name(r.scenario) : r.scenario) : "?"} · ${r.id.slice(0, 4)}-${r.id.slice(4, 6)}-${r.id.slice(6, 8)} ${r.id.slice(9, 11)}:${r.id.slice(11, 13)}`;

/** The default pair: the Evil twin's (B18 vs B19) when both are here, else the two newest runs. */
export function defaultPair(runs: Run[]): [string | null, string | null] {
  const b18 = runs.find((r) => r.scenario === "B18"), b19 = runs.find((r) => r.scenario === "B19");
  if (b18 && b19) return [b18.id, b19.id];
  return [runs[0]?.id ?? null, runs[1]?.id ?? runs[0]?.id ?? null];
}

function AlertCols({ s, words, title }: { s: AlertSplit; words: Words; title: string }) {
  const col = (rows: AlertRow[], side: Side) => (
    <div className="sd-col" data-side={side}>
      <h3>{words[side]}</h3>
      {rows.length === 0 ? <p className="ua-hint">none</p> : (
        <ul>{rows.map((a) => <li key={`${a.rule}|${a.title}`}><b>{a.title}</b> <span className="ft-muted">({a.level}{a.count > 1 ? `, ${a.count}×` : ""})</span></li>)}</ul>
      )}
    </div>
  );
  return (
    <LabPanel title={`${title}: A ${s.a} · B ${s.b}`}>
      <div className="sd-cols">{col(s.only_a, "only_a")}{col(s.both, "both")}{col(s.only_b, "only_b")}</div>
    </LabPanel>
  );
}

function KindCols({ k }: { k: Kind }) {
  const item = (s: Step) => <li key={s.key} title={s.examples.join("\n")}><code>{s.key}</code>{s.count > 1 && <span className="ft-muted"> ×{s.count}</span>}</li>;
  return (
    <div className="sd-kind">
      <h3>{k.word}</h3>
      <div className="sd-cols">
        <div className="sd-col" data-side="only_a"><ul>{k.only_a.map(item)}</ul></div>
        <div className="sd-col" data-side="both"><ul>{k.both.map((x) => <li key={x.key} title={[...x.a.examples, ...x.b.examples].join("\n")}><code>{x.key}</code> <span className="ft-muted">A ×{x.a.count} · B ×{x.b.count}</span></li>)}</ul></div>
        <div className="sd-col" data-side="only_b"><ul>{k.only_b.map(item)}</ul></div>
      </div>
    </div>
  );
}

export function DiffView({ d, words, name }: { d: Diff; words: Words; name?: (id: string) => string }) {
  const shown = d.kinds.filter((k) => k.only_a.length + k.both.length + k.only_b.length > 0);
  return (
    <div className="ft-details">
      <LabPanel>
        <div className="sd-head">
          <span><b>A</b> {runLabel(d.a, name)}</span><span><b>B</b> {runLabel(d.b, name)}</span>
        </div>
        {d.same ? <p className="ft-summary">{words.same}</p> : (
          <div className="lab-numbers">
            <LabNumber value={d.alerts.raised.a} label={`${words.raised}: A`} />
            <LabNumber value={d.alerts.raised.b} label={`${words.raised}: B`} />
            <LabNumber value={d.differences} label="differences (steps and alerts)" />
          </div>
        )}
        <p className="ua-hint">{d.everything ? words.everything : words.own_steps} {words.general}</p>
      </LabPanel>
      <AlertCols s={d.alerts.raised} words={words} title={words.raised} />
      <LabPanel title="Kinds of steps">
        <table className="ft-table sd-summary">
          <thead><tr><th>Kind</th><th>A</th><th>B</th><th /></tr></thead>
          <tbody>
            {d.summary.map((s) => (
              <tr key={s.kind} data-who={s.who}>
                <td>{s.word}</td><td>{s.a}</td><td>{s.b}</td>
                <td>{s.who === "neither" ? "" : <span className="ft-verdict" data-v={s.who === "both" ? "both" : s.who === "only_a" ? "only_ours" : "only_theirs"}>{words[s.who]}</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </LabPanel>
      <LabPanel title="Steps, side by side">
        <details className="sd-steps">
          <summary>Show every step, file by file ({shown.reduce((n, k) => n + k.only_a.length + k.both.length + k.only_b.length, 0)})</summary>
          <div className="sd-cols sd-colhead"><h3>{words.only_a}</h3><h3>{words.both}</h3><h3>{words.only_b}</h3></div>
          {shown.map((k) => <KindCols key={k.kind} k={k} />)}
        </details>
      </LabPanel>
      <AlertCols s={d.alerts.below} words={words} title={words.below} />
    </div>
  );
}

interface Listing {
  words: Words; floor: string; runs: Run[];
  alert: { id: string; title: string; time: string } | null; suggested: { a: string; b: string | null } | null;
}

function StoryDiffLab({ params }: LabProps) {
  const [alert, setAlert] = useAlertParam();
  const name = useRunName();
  const { data, error, loading } = useLab<Listing>(alert ? `/api/labs/storydiff?alert=${encodeURIComponent(alert)}` : "/api/labs/storydiff");
  const [pick, setPick] = useState<{ a: string | null; b: string | null }>({ a: params.get("a"), b: params.get("b") });
  const [everything, setEverything] = useState(params.get("everything") === "true");
  // with an alert: A = the run it happened in, B = another run of the same test (else the usual default)
  const [da, db] = useMemo(() => {
    const [x, y] = defaultPair(data?.runs ?? []);
    const s = data?.suggested;
    return s ? [s.a, s.b ?? (x === s.a ? y : x)] : [x, y];
  }, [data]);
  const a = pick.a ?? da, b = pick.b ?? db;
  const q = a && b ? `/api/labs/storydiff/diff?${new URLSearchParams({ a, b, everything: String(everything) })}` : null;
  const diff = useLab<Diff>(q);
  const set = (next: { a: string | null; b: string | null }) => {
    setPick(next);
    try { history.replaceState(null, "", labHref("storydiff", { a: next.a, b: next.b, alert })); } catch { /* address only */ }
  };
  const words = data?.words;
  return (
    <div className="ft-details">
    <LabState loading={loading} error={error}>
      {data && words && (
        <div className="ft-details">
          <LabPanel title={words.title} hint={words.intro}>
            <AlertScope alert={alert} title={data.alert?.title} onClear={() => setAlert(null)} what="Run A is the test run" />
            {alert && !data.suggested && <p className="ua-hint">No recorded test run holds this alert's time: pick two runs.</p>}
            {data.runs.length === 0 ? <p className="lab-state" data-kind="empty">{words.none}</p> : (
              <div className="sd-pick">
                {(["a", "b"] as const).map((side) => (
                  <label key={side}>
                    <b>{side.toUpperCase()}</b>
                    <select value={(side === "a" ? a : b) ?? ""} onChange={(e) => set({ a, b, [side]: e.target.value })}>
                      {data.runs.map((r) => <option key={r.id} value={r.id}>{runLabel(r, name)}</option>)}
                    </select>
                  </label>
                ))}
                <label className="ua-hint"><input type="checkbox" checked={everything} onChange={(e) => setEverything(e.target.checked)} /> show background Windows activity too</label>
              </div>
            )}
          </LabPanel>
          {q && <LabState loading={diff.loading} error={diff.error}>{diff.data && <DiffView d={diff.data} words={words} name={name} />}</LabState>}
        </div>
      )}
    </LabState>
    </div>
  );
}

export const lab: Lab = {
  id: "storydiff",
  title: "Story diff",
  blurb: "Two recorded test runs side by side: what only one did, what both did, and which alerts each raised.",
  icon: GitCompare,
  group: "tool",
  Component: StoryDiffLab,
};
