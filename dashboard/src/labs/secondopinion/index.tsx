// Lab: Second opinion (night-tools, 2026-11-23). One event log, our detectors and outside tools (Hayabusa,
// Chainsaw), lined up event by event. Back end: engine/labs/secondopinion.py.
import { useEffect, useMemo, useState } from "react";
import { Scale } from "lucide-react";
import { LabNumber, LabPanel, LabState, NextStrip, useAlertParam, useLab } from "../kit";
import type { Lab, LabProps } from "../registry";
import "../fileinspect/fileinspect.css";
import { Jargon } from "../fileinspect/jargon";

type Verdict = "both" | "near" | "only_ours" | "only_theirs";
interface Words {
  title: string; intro: string; jargon?: Record<string, string>; summary_title: string; summary_intro: string; rule_sets: string;
  pick_another: string; both: string; near: string; only_ours: string; only_theirs: string; other_channels: string; disagree_note: string; rule: string;
  no_tool: string; working: string; kinds: Record<string, string>; floor_note: string;
}
interface LogFile { id: string; name: string; kind: "vm" | "sample"; folder: string; size: number; sysmon: boolean }
interface Listing {
  words: Words; tools: Record<string, { present: boolean; license: string; site: string }>; files: LogFile[]; min_level: string;
  suggested: string | null; running: { id: string; name: string | null; step: string | null } | null;
}
interface Hit { title: string; level: string }
export interface Row {
  record_id: number; time: string | null; event_id: number | null; channel: string | null; image: string | null; process?: string | null;
  ours: Hit[]; theirs: Record<string, Hit[]>; verdicts: Record<string, Verdict>;
}
interface Result {
  rows: Row[]; counts: Record<string, Record<Verdict, number>>; other_channels: Record<string, number>; events: number; sysmon_events: number;
  ours_flagged: number; theirs_flagged: Record<string, number>; near_seconds: number;
  tools: Record<string, { state: "ran" | "missing" | "failed"; hits?: number; seconds?: number; reason?: string; version?: string | null; cached?: boolean }>;
  our_alerts: number; our_errors: number; our_rules: number; min_level: string;
}
interface Job { state: "not_run" | "working" | "ready" | "error"; step?: string; seconds?: number; error?: string; result?: Result; file: LogFile; busy?: string | null }

const VERDICTS: Verdict[] = ["both", "near", "only_ours", "only_theirs"];

export interface Summary {
  level: string; rows: { file: LogFile; sysmon_events: number; counts: Record<string, Record<Verdict, number>> }[];
  totals: Record<string, Record<Verdict, number>>; rule_sets: { ours: number | null; tools: Record<string, string | null> };
}

/** The first screen: every log compared so far, one row each (from kept results; nothing starts). */
export function SummaryView({ s, words, onPick }: { s: Summary; words: Words; onPick: (id: string) => void }) {
  const tools = Object.keys(s.rule_sets.tools);
  if (s.rows.length === 0) return <p className="lab-state" data-kind="empty">No log has been compared yet. Pick one below and run it.</p>;
  const rs = words.rule_sets.replace("{ours}", String(s.rule_sets.ours ?? "?")).replace("{hayabusa}", s.rule_sets.tools.hayabusa ?? "")
    .replace("{chainsaw}", s.rule_sets.tools.chainsaw ?? "");
  return (
    <>
      <p className="ua-hint">{words.rule} {rs}</p>
      <table className="ft-table">
        <thead>
          <tr><th>Log</th><th>Sysmon events</th>{tools.map((t) => <th key={t}>Us vs {t}: {words.both} / {words.near} / {words.only_ours} / {words.only_theirs}</th>)}</tr>
        </thead>
        <tbody>
          {s.rows.map((r) => (
            <tr key={r.file.id}>
              <td><button type="button" className="ft-a ft-linkbtn" onClick={() => onPick(r.file.id)}>{r.file.name}</button></td>
              <td>{r.sysmon_events}</td>
              {tools.map((t) => { const c = r.counts[t]; return <td key={t}>{c ? `${c.both} / ${c.near} / ${c.only_ours} / ${c.only_theirs}` : "-"}</td>; })}
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
/** The rows one tool's comparison shows: every row it has a verdict for, or only one kind. */
export const countBy = (rows: Row[], tool: string, v: Verdict | "all") =>
  rows.filter((r) => r.verdicts[tool] && (v === "all" || r.verdicts[tool] === v));

/** What is known about one log. Reading it never starts anything (the back end only reports); `run()` POSTs
 * the one request that starts a comparison, and the page then asks again every 2 s while it works. */
function useJob(id: string | null, allLevels: boolean) {
  const [tick, setTick] = useState(0);
  const [runError, setRunError] = useState<string | null>(null);
  const q = new URLSearchParams({ t: String(tick) });
  if (allLevels) q.set("all_levels", "true");
  const url = id ? `/api/labs/secondopinion/result/${encodeURIComponent(id)}?${q}` : null;
  const job = useLab<Job>(url);
  useEffect(() => {
    if (job.data?.state !== "working") return;
    const t = setTimeout(() => setTick((n) => n + 1), 2000);
    return () => clearTimeout(t);
  }, [job.data]);
  useEffect(() => setRunError(null), [id]);
  const run = async () => {
    if (!id) return;
    setRunError(null);
    const r = await fetch(`/api/labs/secondopinion/run/${encodeURIComponent(id)}${allLevels ? "?all_levels=true" : ""}`, { method: "POST" });
    if (!r.ok) setRunError(String((await r.json().catch(() => null))?.detail ?? `${r.status} ${r.statusText}`));
    setTick((n) => n + 1);
  };
  return { ...job, run, runError };
}

export function RunOffer({ job, onRun, runError }: { job: Job; onRun: () => void; runError: string | null }) {
  return (
    <div className="lab-state" data-kind="empty">
      <p>Not compared yet. Running it reads the log and runs our detectors, Hayabusa and Chainsaw: about two minutes of
        heavy work on this laptop, so it starts only when you ask. Results are kept, so it runs once per log.</p>
      {job.busy ? <p className="ua-hint">Another comparison is running ({job.busy}); one at a time.</p> : (
        <button type="button" className="ft-btn" onClick={onRun}>Run the comparison for {job.file.name}</button>
      )}
      {runError && <p className="ua-hint" role="alert">{runError}</p>}
    </div>
  );
}

function Hits({ hits }: { hits: Hit[] }) {
  return <ul>{hits.map((h, i) => <li key={i}>{h.title} <span className="ft-muted">({h.level})</span></li>)}</ul>;
}

function ResultView({ r, words, tools }: { r: Result; words: Words; tools: string[] }) {
  const ran = tools.filter((t) => r.tools[t]?.state === "ran");
  const [tool, setTool] = useState<string>(ran[0] ?? tools[0]);
  const [show, setShow] = useState<Verdict | "all">("all");
  const rows = useMemo(() => countBy(r.rows, tool, show), [r.rows, tool, show]);
  const c = r.counts[tool] ?? { both: 0, near: 0, only_ours: 0, only_theirs: 0 };
  return (
    <>
      <LabPanel>
        <div className="ft-btns" role="group" aria-label="Compare with">
          {tools.map((t) => (
            <button key={t} type="button" className="ft-btn" aria-pressed={tool === t} disabled={r.tools[t]?.state !== "ran"} onClick={() => setTool(t)}>
              Us vs {t}{r.tools[t]?.version ? ` ${r.tools[t].version}` : ""}
            </button>
          ))}
        </div>
        <div className="lab-numbers">
          <LabNumber value={c.both} label={words.both} />
          <LabNumber value={c.near} label={words.near} />
          <LabNumber value={c.only_ours} label={words.only_ours} />
          <LabNumber value={c.only_theirs} label={words.only_theirs} />
          <LabNumber value={r.sysmon_events} label="Sysmon events in the log" />
        </div>
        <p className="ua-hint">{words.rule}</p>
        <p className="ua-hint">
          Us: {r.our_rules.toLocaleString("en-US")} Sigma rules + our own rules; {r.ours_flagged} events flagged from {r.min_level} up.
          {" "}{tools.map((t) => {
            const s = r.tools[t];
            return `${t}: ${s.state === "ran" ? `${r.theirs_flagged[t] ?? 0} events flagged${s.seconds != null ? ` (${s.seconds} s${s.cached ? ", kept from before" : ""})` : ""}` : s.state === "missing" ? "not downloaded" : `failed (${s.reason})`}`;
          }).join(" · ")}.
        </p>
        {Object.keys(r.other_channels).length > 0 && (
          <p className="ua-hint">{words.other_channels}: {Object.entries(r.other_channels).map(([t, n]) => `${t} ${n}`).join(", ")}</p>
        )}
        <p className="ua-hint">{words.disagree_note}</p>
        <div className="ft-btns" role="group" aria-label="Show">
          {(["all", ...VERDICTS] as const).map((v) => (
            <button key={v} type="button" className="ft-btn" aria-pressed={show === v} onClick={() => setShow(v)}>
              {v === "all" ? `All (${c.both + c.near + c.only_ours + c.only_theirs})` : `${words[v]} (${c[v]})`}
            </button>
          ))}
        </div>
      </LabPanel>
      <LabPanel>
        <table className="ft-table">
          <thead><tr><th>Time (UTC)</th><th>Record</th><th>Program</th><th>Us</th><th>{tool}</th><th /></tr></thead>
          <tbody>
            {rows.slice(0, 400).map((x) => (
              <tr key={x.record_id}>
                <td className="ft-flags">{x.time ? x.time.slice(0, 19).replace("T", " ") : ""}</td>
                <td><code>{x.record_id}</code>{x.event_id != null && <span className="ft-muted"> · ev {x.event_id}</span>}</td>
                <td><code>{(x.image ?? "").split(/[\\/]/).pop()}</code></td>
                <td><Hits hits={x.ours} /></td>
                <td><Hits hits={x.theirs[tool] ?? []} /></td>
                <td><span className="ft-verdict" data-v={x.verdicts[tool]}>{words[x.verdicts[tool]]}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length > 400 && <p className="ua-hint">First 400 of {rows.length} shown.</p>}
      </LabPanel>
    </>
  );
}

function SecondOpinionLab({ params }: LabProps) {
  const [alert] = useAlertParam();
  const { data, error, loading } = useLab<Listing>("/api/labs/secondopinion");
  const summary = useLab<Summary>("/api/labs/secondopinion/summary");
  const [picked, setPicked] = useState<string | null>(params.get("evtx"));
  const [allLevels, setAllLevels] = useState(false);
  const [q, setQ] = useState("sysmon");
  const id = picked ?? data?.suggested ?? null;
  const job = useJob(data ? id : null, allLevels);
  const tools = data ? Object.keys(data.tools) : [];
  const files = (data?.files ?? []).filter((f) => !q.trim() || `${f.folder} ${f.name}`.toLowerCase().includes(q.trim().toLowerCase()));
  return (
    <div className="ft-details">
    <NextStrip current="secondopinion" alert={alert} />
    <LabState loading={loading} error={error}>
      {data && (
        <div className="ft-details">
          <LabPanel title={data.words.title} hint={data.words.intro}>
            {alert && <p className="ft-scope">This page compares whole saved event logs, not one alert; the strip above takes the alert on.</p>}
            <Jargon terms={data.words.jargon} />
            <div className="ft-btns">
              {tools.map((t) => (
                <span key={t} className="ft-tag" data-on={data.tools[t].present || undefined}>
                  {t}: {data.tools[t].present ? "ready" : data.words.no_tool.replace("{tool}", t)} · {data.tools[t].license}
                </span>
              ))}
            </div>
            <label className="ua-hint"><input type="checkbox" checked={allLevels} onChange={(e) => setAllLevels(e.target.checked)} /> count every level (not only from {data.min_level} up)</label>
          </LabPanel>
          <LabPanel title={data.words.summary_title} hint={data.words.summary_intro}>
            <LabState loading={summary.loading} error={summary.error}>
              {summary.data && <SummaryView s={summary.data} words={data.words} onPick={(fid) => setPicked(fid)} />}
            </LabState>
          </LabPanel>
          <details className="ft-more" open={!!picked}>
          <summary>{data.words.pick_another}</summary>
          <div className="ft-layout">
            <LabPanel title="Event logs">
              <input className="ft-search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter logs" aria-label="Filter logs" />
              <ul className="ft-files">
                {files.map((f) => (
                  <li key={f.id}>
                    <button type="button" className="ft-file" aria-selected={f.id === id} onClick={() => setPicked(f.id)}>
                      <b>{f.name}</b><span>{data.words.kinds[f.kind]}{f.folder ? ` · ${f.folder}` : ""} · {(f.size / 1024).toFixed(0)} KB</span>
                    </button>
                  </li>
                ))}
              </ul>
            </LabPanel>
            <div className="ft-details">
              {!id ? <p className="lab-state" data-kind="empty">No event log file is here yet.</p> : (
                <LabState loading={job.loading && !job.data} error={job.error}>
                  {job.data?.state === "not_run" && <RunOffer job={job.data} onRun={job.run} runError={job.runError} />}
                  {job.data?.state === "working" && <p className="lab-state" data-kind="loading">{data.words.working} ({job.data.step}, {job.data.seconds} s)</p>}
                  {job.data?.state === "error" && <p className="lab-state" data-kind="error">{job.data.error}</p>}
                  {job.data?.state === "ready" && job.data.result && <ResultView r={job.data.result} words={data.words} tools={tools} />}
                </LabState>
              )}
            </div>
          </div>
          </details>
        </div>
      )}
    </LabState>
    </div>
  );
}

export const lab: Lab = {
  id: "secondopinion",
  title: "Second opinion",
  blurb: "Two free log-search tools (Hayabusa, Chainsaw) and our detectors read the same event log: where do they agree, and where not?",
  icon: Scale,
  group: "tool",
  Component: SecondOpinionLab,
};
