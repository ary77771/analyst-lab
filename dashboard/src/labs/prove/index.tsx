// Lab "What would prove it?" (engine/labs/prove.py): every Suspected line and gap of an alert's story with its
// missing witness, and whether this recorder could collect it. Every word comes from Python.
import { SearchCheck } from "lucide-react";
import { LabPanel, LabState, NextStrip, useAlertParam, useLab } from "../kit";
import { PlusCase } from "../_things";            // one click to the case board (night-pivot)
import { type Lab, type LabProps } from "../registry";
import { Thing } from "../_things/Thing";
import { fill } from "../_explain/logic";
import { AlertPicker, HarnessSwitch, Ids, Level, type AlertRow } from "../_explain/shared";
import { useState } from "react";
import "./prove.css";

type Verdict = "collected" | "partly" | "not_configured" | "elsewhere";
type W = Record<string, string> & { verdict: Record<Verdict, string>; verdict_note: Record<Verdict, string>; state: Record<string, string>;
  inks: Record<string, string> };
interface Source { kind: "sysmon" | "recorder" | "none"; element?: string; type?: string; what: string; state: string; events: number[] }
export interface WitnessRow { kind: string; row: string; ink: string; witness: string; sources: Source[]; helps: Source[]; verdict: Verdict }
interface Line { ink: "hypothesis" | "gap"; kind: string; text: string; band: string | null; alternative: string | null; time: string | null; witness: WitnessRow | null;
  edge?: boolean; harness?: string | null; machinery?: string | null; corroborating?: { image: string; pid: number | null; command_line: string; command_short?: string | null; names: string }[];
  fingerprint?: { sha256: string; sha_short?: string; file: string; programs: { image: string; pid: number | null; command_line: string; command_short?: string | null }[] } | null }
interface Cfg { element: string; events: number[]; state: string; rules: number }
export interface Prove { words: W; alert: AlertRow; story: boolean; lines: Line[]; config: Cfg[] }
interface Whole { words: W; table: WitnessRow[]; config: Cfg[]; alerts: AlertRow[] }

function stateText(s: Source | Cfg, w: W) {
  const st = s.state;
  return st === "some" ? fill(w.state.some, { n: "rules" in s ? s.rules : "" }) : w.state[st] ?? st;
}

function SourceLine({ s, w }: { s: Source; w: W }) {
  return (
    <li className="pv-src" data-state={s.state}>
      <span>{s.what}</span>
      <b>{s.kind === "sysmon" ? `Sysmon ${s.element}${s.events.length ? ` (${s.events.join(", ")})` : ""}` : s.kind === "recorder" ? `${w.recorder} (${s.type})` : w.another_tool}</b>
      {s.kind !== "none" ? <em>{stateText(s, w)}</em> : null}
    </li>
  );
}

export function WitnessPanel({ r, w }: { r: WitnessRow; w: W }) {
  return (
    <div className="pv-witness" data-verdict={r.verdict}>
      <p className="pv-label">{w.witness}</p>
      <p className="pv-need">{r.witness}</p>
      <p className="pv-verdict" data-verdict={r.verdict}><b>{w.verdict[r.verdict]}</b>{w.verdict_note[r.verdict] ? <span> · {w.verdict_note[r.verdict]}</span> : null}</p>
      <p className="pv-label">{w.where}</p>
      <ul>{r.sources.map((s, i) => <SourceLine key={i} s={s} w={w} />)}</ul>
      {r.helps.length ? <><p className="pv-label">{w.helps}</p><ul>{r.helps.map((s, i) => <SourceLine key={i} s={s} w={w} />)}</ul></> : null}
    </div>
  );
}

function ConfigList({ cfg, w }: { cfg: Cfg[]; w: W }) {
  return (
    <details className="pv-config"><summary>{w.config_title} · <code>{w.config_file}</code></summary>
      <table className="xp-table"><tbody>{cfg.map((c) => (
        <tr key={c.element} data-state={c.state}><td className="xp-k">{c.element}</td><td className="xp-v">{c.events.join(", ")}</td><td>{stateText(c, w)}</td></tr>))}</tbody></table>
    </details>
  );
}

export function ProveView({ d }: { d: Prove }) {
  const w = d.words;
  const [showHarness, setShowHarness] = useState(false);
  const hiddenN = d.lines.filter((l) => l.harness && !l.edge).length;
  const shown = d.lines.filter((l) => !l.edge && (showHarness || !l.harness));
  return (
    <>
      <LabPanel>
        <div className="xp-row"><Level level={d.alert.level} /><h2 className="xp-title">{d.alert.title}</h2><span className="xp-grow" /><PlusCase alert={d.alert.id} label={d.alert.title} time={d.alert.time} text="Pin to case" />
          <span className="xp-small xp-dim xp-mono">{d.alert.time}</span></div>
        <p className="ua-hint">{w.intro}</p>
      </LabPanel>
      {!d.story ? <p className="lab-state" data-kind="empty">{w.no_story}</p>
        : d.lines.length === 0 ? <p className="lab-state" data-kind="empty">{w.no_lines}</p> : (
          <LabPanel title={`${w.lines} (${d.lines.length})`}>
            <HarnessSwitch hidden={hiddenN} on={showHarness} set={setShowHarness} w={w} />
            <ol className="pv-lines">{shown.map((l, i) => (
              <li key={i} className="pv-line" data-ink={l.ink}>
                <div className="pv-claim"><b className={`xp-ink-${l.ink}`}>{w.inks[l.ink]}{l.band ? ` · ${l.band}` : ""}</b><span>{l.text}</span>
                  {l.machinery ? <p className="xp-machinery">{l.machinery}</p> : null}
                  {l.alternative ? <p className="xp-small xp-dim">{w.alternative ? <span className="pv-alt">{w.alternative}: </span> : null}{l.alternative}</p> : null}
                  {l.corroborating?.length ? <div className="pv-corr"><b>{w.corroborating}</b><span className="xp-small xp-dim">{w.corroborating_note}</span>
                    {l.corroborating.map((c, j) => <p key={j} className="xp-small"><Thing field="Image" value={c.image} /> <code>{c.command_short ?? c.command_line}</code></p>)}</div> : null}
                  {l.fingerprint ? <div className="pv-corr pv-fp"><b>{w.fingerprint_title}</b><span className="xp-small xp-dim">{w.fingerprint_note}</span>
                    <p className="xp-small"><Thing field="TargetFilename" value={l.fingerprint.file} /> <span className="xp-dim">SHA-256</span> <code title={l.fingerprint.sha256}>{l.fingerprint.sha_short ?? l.fingerprint.sha256}</code></p>
                    {l.fingerprint.programs.map((c, j) => <p key={j} className="xp-small"><Thing field="Image" value={c.image} />{c.pid !== null ? <span className="xp-dim xp-mono"> PID {c.pid}</span> : null} <code>{c.command_short ?? c.command_line}</code></p>)}
                    <details className="pv-full"><summary className="xp-small xp-dim">{w.full_lines ?? "show more"}</summary>
                      <p className="xp-small"><span className="xp-dim">SHA-256 </span><code>{l.fingerprint.sha256}</code></p>
                      {l.fingerprint.programs.map((c, j) => <p key={j} className="xp-small"><code>{c.command_line}</code></p>)}</details></div> : null}</div>
                {l.witness ? <WitnessPanel r={l.witness} w={w} /> : null}
              </li>))}</ol>
            {d.lines.some((l) => l.edge) ? (
              <details className="xp-details pv-edge"><summary>{w.edge_title} ({d.lines.filter((l) => l.edge).length})</summary>
                <p className="xp-small xp-muted">{w.edge_note}</p>
                <ul className="xp-list">{d.lines.filter((l) => l.edge).map((l, i) => <li key={i}>{l.text}{l.machinery ? <span className="xp-machinery">{l.machinery}</span> : null}</li>)}</ul></details>) : null}
          </LabPanel>)}
      <ConfigList cfg={d.config} w={w} />
    </>
  );
}

function WholeTable() {
  const { data, error, loading } = useLab<Whole>("/api/labs/prove");
  return (
    <LabState loading={loading} error={error}>
      {data && (
        <LabPanel title={data.words.table_title} hint={data.words.table_note}>
          <ol className="pv-lines">{data.table.map((r) => (
            <li key={r.kind} className="pv-line" data-ink={r.ink}>
              <div className="pv-claim"><b className={`xp-ink-${r.ink}`}>{data.words.inks[r.ink]}</b><Ids label={data.words.details}>{r.row !== "gap" ? `${r.row} · ` : ""}{r.kind}</Ids></div>
              <WitnessPanel r={r} w={data.words} />
            </li>))}</ol>
          <ConfigList cfg={data.config} w={data.words} />
        </LabPanel>)}
    </LabState>
  );
}

function ProveLab(_: LabProps) {
  const [alert] = useAlertParam();
  const { data, error, loading } = useLab<Prove>(alert ? `/api/labs/prove/${encodeURIComponent(alert)}` : null);
  if (!alert) return <><AlertPicker lab="prove" url="/api/labs/prove" /><WholeTable /></>;
  return <><NextStrip current="prove" alert={alert} /><LabState loading={loading} error={error}>{data && <ProveView d={data} />}</LabState></>;
}

export const lab: Lab = {
  id: "prove",
  title: "What would prove it?",
  blurb: "For each Suspected line and gap: the one record that would settle it, and whether this recorder could collect it.",
  icon: SearchCheck,
  Component: ProveLab,
};
