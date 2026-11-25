// Labs page "Gap explorer" (night-hunt): an honest list of what the recorder could NOT see, each kind
// in plain words with its evidence. Same gap kinds as the evidence graph (engine/graph.py), drawn in the
// "can't be known" ink. Data and words: engine/labs/gaps.py (/api/labs/gaps/).
import { useState } from "react";
import { EyeOff } from "lucide-react";
import type { Lab, LabProps } from "../registry";
import { NextStrip, useAlertParam } from "../kit";
import { apiQuery, count, type WindowName } from "../hunts/logic";
import { AlertBanner, Panel, ResultTable, Status, WindowPicker, useJSON, useParam, useWindowParam, type AlertInView, type Column, type Meta, type ResultRow } from "../hunts/shared";

interface Section { id: string; title: string; plain: string; total: number; items: number; rows: ResultRow[]; truncated: boolean; columns: Column[]; note: string | null }
interface Gaps extends Meta { sections: Section[]; kinds_with_gaps: number; silence_minutes: number; ms: number; alert: AlertInView | null }

const WINDOWS: readonly WindowName[] = ["1h", "6h", "24h", "7d", "30d", "all"];
const SILENCE = [5, 10, 30, 60];
const UNITS: Record<string, string> = {
  parent_unknown: "starts", origin_unknown: "processes", actor_unknown: "events", content_unknown: "files", missing_records: "records",
  record_restarts: "times", silences: "silences", paused: "events", unreadable: "events", sysmon_errors: "errors",
};

export function GapsPage({ params }: LabProps) {
  const [win, setWin] = useWindowParam(params, "24h");
  const [silence, setSilence] = useState(Number(params.get("silence")) || 10);
  const [open, setOpen] = useState<string | null>(params.get("kind"));
  const [alert, setAlert] = useAlertParam();                       // wave 3 / N2: "?alert=<id>" limits to its run
  const [all, setAll] = useParam(params, "all", "");
  const { data: d, error, loading } = useJSON<Gaps>(`/api/labs/gaps/?${apiQuery({ window: win, silence_minutes: silence, alert, only_alert: alert ? (all ? "false" : "true") : null })}`);
  const shown = d?.sections.find((s) => s.id === open) ?? d?.sections.find((s) => s.total > 0) ?? null;

  return (
    <div className="hn" data-hunt-page="gaps">
      <NextStrip current="gaps" alert={alert} />
      <AlertBanner alert={d?.alert} words={d?.scope_words} onAll={(b) => { setAll(b ? "1" : null); if (b) setWin("all"); }} onClear={() => setAlert(null)} />
      <p className="ua-hint">Every recording has blind spots. Knowing where they are is part of the answer: a gap is never filled
        with a guess, and a missing parent is never drawn as a process.</p>
      <div className="hn-bar">
        <WindowPicker value={d?.alert?.limited ? ("" as WindowName) : win} onChange={(nw) => { if (d?.alert?.limited) setAll("1"); setWin(nw); }} choices={WINDOWS} meta={d} />
        <span className="hn-span">silence =</span>
        <div role="radiogroup" aria-label="A silence is longer than" className="hn-seg">
          {SILENCE.map((m) => <button key={m} role="radio" aria-checked={m === silence} onClick={() => setSilence(m)}>{m} min</button>)}
        </div>
      </div>
      <Status loading={loading && !d} error={error} />
      {d && (
        <div className="hn-split">
          <nav aria-label="Kinds of gap" className="hn-list">
            {d.sections.map((s) => (
              <button key={s.id} className="hn-item" onClick={() => setOpen(s.id)} aria-current={shown?.id === s.id} data-gap={s.id}>
                <span><b>{s.title}</b></span>
                <span className="hn-badge" data-kind={s.total ? "gap" : undefined}>{count(s.total)}</span>
              </button>
            ))}
            <p className="hn-span">{d.kinds_with_gaps} of {d.sections.length} kinds found in this window · {d.ms} ms</p>
          </nav>
          {shown ? (
            <Panel title={<span className="hn-gaptitle"><EyeOff size={16} aria-hidden />{shown.title}</span>} intro={shown.plain}
              right={<div className="hn-big"><b className="hn-gapnum">{count(shown.total)}</b><span>{UNITS[shown.id] ?? ""}</span></div>}>
              {shown.note && <p className="hn-note">{shown.note}</p>}
              <ResultTable columns={shown.columns} rows={shown.rows} host={d.host} empty="None in this window." />
              {shown.truncated && <p className="hn-more">Showing the first {shown.rows.length} of {count(shown.items)}.</p>}
            </Panel>
          ) : (
            <Panel title="No gaps found" intro="Nothing of these kinds in this time window. That is the recording's own claim; it cannot see what it was never shown.">
              <span />
            </Panel>
          )}
        </div>
      )}
    </div>
  );
}

export const lab: Lab = {
  id: "gaps",
  title: "Gap explorer",
  blurb: "What the recorder could NOT see: unknown parents, processes already running, unreadable files, lost record numbers, silent stretches.",
  icon: EyeOff,
  Component: GapsPage,
};
