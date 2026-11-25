// Labs page "Indicator sweep" (night-hunt): paste indicators (hashes, IPs, domains, files, registry keys, or a
// STIX 2.1 bundle such as the case board exports); each is looked for in the test machine's recording: seen,
// not seen, or "can't tell here" when the recorder does not collect that kind. Nothing is looked up online.
// Data and words: engine/labs/sweep.py (POST /api/labs/sweep/).
import { useEffect, useRef, useState } from "react";
import { ListChecks, Upload } from "lucide-react";
import type { Lab, LabProps } from "../registry";
import { NextStrip, useAlertParam } from "../kit";
import { Thing } from "../_things/Thing";
import { WINDOWS, count, fileName, shortTime, type WindowName } from "../hunts/logic";
import { Notes, Panel, Status, WindowPicker, WindowSpan, useJSON, useWindowParam, type Meta } from "../hunts/shared";
import "../hunts/hunt.css";

interface Row {
  raw: string; kind: string; value: string; verdict: "seen" | "not_seen" | "cant_tell"; verdict_word: string; count: number;
  first: string | null; last: string | null; hosts: string[]; programs: { program: string; count: number }[];
  why_uncertain: string | null; pivot: { kind: string; value: string } | null;
}
interface Result extends Meta {
  rows: Row[]; counts: Record<Row["verdict"], number>; skipped: { raw: string; why: string }[]; skipped_total: number;
  truncated: boolean; coverage: { hashes: string[]; dns: boolean; file_types: string[]; config_read: boolean };
  words: Record<string, string>; ms: number;
}

const FIELD: Record<string, string> = { hash: "sha256", ip: "DestinationIp", domain: "DestinationHostname", file: "TargetFilename", registry: "TargetObject" };
const TAG: Record<Row["verdict"], string> = { seen: "added", cant_tell: "gap", not_seen: "" };
interface WhereRow {
  raw: string; kind: string; value: string; role: string; verdict: Row["verdict"]; times: number; in_this_run: number; other_runs: number;
  elsewhere: number; elsewhere_first: string | null; elsewhere_last: string | null; hosts: string[]; why_uncertain: string | null;
  pivot: { kind: string; value: string } | null; common?: boolean; of?: string | null;
}
interface Where extends Partial<Meta> {
  alert: { id: string; missing?: boolean; title?: string; time?: string }; rows: WhereRow[]; spread?: number; notes: string[]; text: string; ms?: number;
}

/** One plain answer per indicator: where else it appears, counted by runs (a run = one machine start to the next). */
export function whereAnswer(r: WhereRow): string {
  if (r.verdict === "cant_tell") return `can't tell here: ${r.why_uncertain ?? ""}`;
  if (r.verdict === "not_seen") return "not seen in the recording";
  const here = `${r.in_this_run} time${r.in_this_run === 1 ? "" : "s"} in this alert's run`;
  if (!r.other_runs) return `only here: ${here}`;
  return `also in ${r.other_runs} other run${r.other_runs === 1 ? "" : "s"}: seen ${r.elsewhere} time${r.elsewhere === 1 ? "" : "s"} there, `
    + `first ${shortTime(r.elsewhere_first)}, last ${shortTime(r.elsewhere_last)} (and ${here})`;
}

const EXAMPLE = "# one per line; defanged forms like 10[.]0[.]2[.]2 or hxxp://... are fine\n";

export function SweepPage({ params }: LabProps) {
  const about = useJSON<{ words: Record<string, string>; max: number }>("/api/labs/sweep/");
  const [win, setWin] = useWindowParam(params, "all");
  const [text, setText] = useState(params.get("q") ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<Result | null>(null);
  const file = useRef<HTMLInputElement>(null);
  const [alert, setAlert] = useAlertParam();                       // "where else does this appear?" for one alert
  const where = useJSON<Where>(alert ? `/api/labs/sweep/alert/${encodeURIComponent(alert)}` : null);
  const wd = where.data && where.data.alert.id === alert ? where.data : null;
  useEffect(() => { if (wd?.text) setText((t) => t.trim() ? t : wd.text); }, [wd?.text]);   // prefill once, never over the analyst's own list

  async function go() {
    setBusy(true); setErr(null);
    try {
      const r = await fetch("/api/labs/sweep/", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text, window: win }) });
      if (!r.ok) throw new Error(String((await r.json().catch(() => null))?.detail ?? r.status));
      setRes((await r.json()) as Result);
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); } finally { setBusy(false); }
  }
  function load(f: File | undefined) {                         // read on this computer only: nothing is uploaded anywhere
    if (!f) return;
    const rd = new FileReader();
    rd.onload = () => setText(String(rd.result ?? ""));
    rd.readAsText(f);
  }
  const w = about.data?.words;

  return (
    <div className="hn" data-hunt-page="sweep">
      <NextStrip current="sweep" alert={alert} />
      {w && !alert && <p className="ua-hint">{w.intro}</p>}
      {alert && <Status loading={where.loading && !wd} error={where.error} />}
      {wd?.alert.missing && (
        <p className="hn-alertbar" data-kind="missing">This alert isn't in this recording (or is on a machine this dashboard doesn't show).{" "}
          <button className="hn-linkbtn" onClick={() => setAlert(null)}>forget the alert</button></p>
      )}
      {wd && !wd.alert.missing && (
        <Panel title="Where else does this appear?"
          intro={<>The alert <b>“{wd.alert.title}”</b>'s own things (its program, the files it wrote, the addresses it contacted, its parent),
            looked for in the whole recording and counted by runs.</>}
          right={<span className="hn-span">{count(wd.spread ?? 0)} of {count(wd.rows.length)} also appear elsewhere<span className="hn-nowrap"> · <button className="hn-linkbtn" onClick={() => setAlert(null)}>forget the alert</button></span></span>}>
          <Notes notes={wd.notes} />
          {wd.rows.length === 0 ? <p className="hn-empty">This alert names no file, fingerprint or address to look for.</p> : (
            <div className="hn-tablewrap"><table className="hn-table">
              <thead><tr><th>What</th><th>Thing</th><th>Where else</th></tr></thead>
              <tbody>{wd.rows.map((r) => (
                <tr key={r.kind + r.value} data-mark={r.other_runs && !r.common ? "new" : undefined}>
                  <td>{r.role}{r.of ? <> (<b>{r.of}</b>)</> : null}</td>
                  <td>{r.pivot && FIELD[r.pivot.kind] ? <Thing field={FIELD[r.pivot.kind]} value={r.pivot.value} host={r.hosts[0]} role={r.role} plusCase />
                    : <span className="hn-path">{r.raw}</span>}</td>
                  <td>{r.verdict === "cant_tell" ? <span className="hn-tag" data-kind="gap">{whereAnswer(r)}</span> : whereAnswer(r)}
                    {r.common && <> <span className="hn-tag" title="Seen in at least half of all runs: says little about this alert's reach">common on this machine</span></>}</td>
                </tr>))}</tbody>
            </table></div>
          )}
          <p className="hn-span">The same things are in the box below: edit the list and sweep again for any time window.</p>
        </Panel>
      )}
      <Status loading={about.loading && !about.data} error={about.error} />
      <div className="hn-sweep-in">
        <textarea className="hn-textarea" value={text} onChange={(e) => setText(e.target.value)} placeholder={EXAMPLE} spellCheck={false}
          aria-label="Indicators, one per line, or a STIX 2.1 bundle" rows={8} />
        <div className="hn-bar">
          <WindowPicker value={win} onChange={setWin} choices={WINDOWS as readonly WindowName[]} />
          <button className="ua-btn" onClick={() => file.current?.click()}><Upload size={14} aria-hidden />Load a file</button>
          <input ref={file} type="file" accept=".txt,.csv,.json,.stix" hidden onChange={(e) => load(e.target.files?.[0])} />
          <button className="ua-btn" data-kind="primary" onClick={go} disabled={busy || !text.trim()}>{busy ? "Looking…" : "Sweep"}</button>
          {res && <WindowSpan meta={res} />}
        </div>
      </div>
      {err && <p className="lab-state" data-kind="error" role="alert">The sweep could not run: {err}</p>}
      {res && (
        <Panel title={`${count(res.rows.length)} indicators looked for`} intro={res.words.not_seen_means}
          right={<span className="hn-span">{res.ms} ms</span>}>
          <div className="hn-counts">
            <div className="hn-big"><b>{count(res.counts.seen)}</b><span>{res.words.seen}</span></div>
            <div className="hn-big"><b>{count(res.counts.cant_tell)}</b><span>{res.words.cant_tell}</span></div>
            <div className="hn-big"><b>{count(res.counts.not_seen)}</b><span>{res.words.not_seen}</span></div>
          </div>
          <Notes notes={[`What the recorder collects (read from its settings): file fingerprints ${res.coverage.hashes.join(", ").toUpperCase()}; `
            + `name lookups ${res.coverage.dns ? "recorded" : "not recorded"}; new files recorded for ${res.coverage.file_types.join(" ")} and a few folders.`]} />
          <div className="hn-tablewrap">
            <table className="hn-table">
              <thead><tr><th>Indicator</th><th>Kind</th><th>Result</th><th>Times</th><th>First</th><th>Last</th><th>Programs</th><th>Why uncertain</th><th>Pivot</th></tr></thead>
              <tbody>
                {res.rows.map((r) => {
                  // the chip names the value as recorded (a full path, an HKU\<SID>\... key), not the pasted form
                  const field = r.pivot ? FIELD[r.pivot.kind] : null;
                  return (
                    <tr key={r.kind + r.value} data-mark={r.verdict === "seen" ? "new" : undefined}>
                      <td className="hn-path" title={r.value}>{r.raw}</td>
                      <td>{r.kind}</td>
                      <td>{TAG[r.verdict] ? <span className="hn-tag" data-kind={TAG[r.verdict]}>{r.verdict_word}</span> : <span className="hn-span">{r.verdict_word}</span>}</td>
                      <td className="hn-num">{r.count ? count(r.count) : <span className="hn-dash">-</span>}</td>
                      <td className="hn-time">{shortTime(r.first)}</td>
                      <td className="hn-time">{shortTime(r.last)}</td>
                      <td className="hn-path">{r.programs.map((p) => `${fileName(p.program)} (${p.count})`).join(", ") || <span className="hn-dash">-</span>}</td>
                      <td>{r.why_uncertain ?? <span className="hn-dash">-</span>}</td>
                      <td>{field && r.pivot && r.verdict === "seen" && (
                        <Thing field={field} value={r.pivot.value} host={r.hosts[0]} role="seen in the recording" plusCase />
                      )}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {res.truncated && <p className="hn-more">Only the first {count(about.data?.max ?? res.rows.length)} indicators were looked for.</p>}
          {res.skipped_total > 0 && (
            <details className="hn-skipped"><summary>{count(res.skipped_total)} line(s) were not indicators</summary>
              <ul>{res.skipped.map((s, i) => <li key={i}><code>{s.raw}</code>: {s.why}</li>)}</ul></details>
          )}
        </Panel>
      )}
    </div>
  );
}

export const lab: Lab = {
  id: "sweep",
  title: "Indicator sweep",
  blurb: "Paste hashes, addresses, domains, files or a STIX bundle: each is checked against the recording (seen, not seen, or can't tell here). No internet lookups.",
  icon: ListChecks,
  group: "happened",                  // "was this indicator here?" (the registry's table has no place for it)
  Component: SweepPage,
};
