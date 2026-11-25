// Labs page "Persistence before/after" (night-hunt): an Autoruns-style list of what starts by itself,
// replayed from the recorded writes, and what a chosen window (e.g. a test) added, changed or removed.
// Data and words: engine/labs/persistence.py (/api/labs/persistence/). Links: #/labs/persistence?start=&end=
import { useState } from "react";
import { History } from "lucide-react";
import type { Lab, LabProps } from "../registry";
import { NextStrip, useAlertParam } from "../kit";
import { apiQuery, count, shortTime, type WindowName } from "../hunts/logic";
import { AlertBanner, BigNumber, Notes, Panel, ResultTable, Status, WindowPicker, WindowSpan, useJSON, useParam, useWindowParam, type AlertInView, type Column, type Meta, type Pivot, type ResultRow } from "../hunts/shared";

interface Change { time: string; kind: string; place: string; name: string; what: string; value: string | null; by: string; pivots: Pivot[] }
interface Result extends Meta {
  rows: (ResultRow & { status: string })[]; counts: Record<"added" | "first_seen" | "changed" | "rewritten" | "removed" | "unchanged", number>; has_before: boolean; before_note: string | null;
  before_total: number; after_total: number; writes_in_window: number; log: Change[]; log_truncated: boolean;
  registry_recorded: boolean; not_seen: string[]; truncated: boolean; ms: number; alert: AlertInView | null;
}

const WINDOWS: readonly WindowName[] = ["1h", "6h", "24h", "7d", "30d"];
const COLUMNS: Column[] = [
  { key: "status", label: "In this window", kind: "tag" }, { key: "kind", label: "Kind" }, { key: "place", label: "Where", kind: "path" },
  { key: "name", label: "Entry", kind: "path" }, { key: "value", label: "Starts (now)", kind: "path" }, { key: "before", label: "Before", kind: "path" },
  { key: "by", label: "Written by" },
];
const LOG_COLUMNS: Column[] = [
  { key: "time", label: "When", kind: "time" }, { key: "what", label: "What happened" }, { key: "kind", label: "Kind" },
  { key: "name", label: "Entry", kind: "path" }, { key: "value", label: "Value", kind: "path" }, { key: "by", label: "By" },
];

/** "2026-11-01T09:10" (an <input type=datetime-local>, read as UTC) <-> "2026-11-01T09:10:00Z". */
const toInput = (iso: string | null | undefined) => (iso ? iso.slice(0, 19) : "");
const fromInput = (v: string) => (v ? `${v.length === 16 ? v + ":00" : v}Z` : null);

export function PersistencePage({ params }: LabProps) {
  const [win, setWin] = useWindowParam(params, "24h");
  const [start, setStart] = useParam(params, "start", "");
  const [end, setEnd] = useParam(params, "end", "");
  const [draft, setDraft] = useState({ start: toInput(start), end: toInput(end) });
  const [unchanged, setUnchanged] = useState(false);
  const [alert, setAlert] = useAlertParam();                       // wave 3: "#/labs/persistence?alert=<id>"
  const [all, setAll] = useParam(params, "all", "");
  const custom = !!(start || end);
  const alertQ = alert ? { alert, only_alert: all ? "false" : "true" } : {};
  const q = apiQuery(custom ? { start, end, show_unchanged: unchanged, ...alertQ } : { window: win, show_unchanged: unchanged, ...alertQ });
  const { data: d, error, loading } = useJSON<Result>(`/api/labs/persistence/?${q}`);
  const byAlert = !!(alert && d?.alert && !d.alert.missing);

  const pickWindow = (w: WindowName) => { if (alert) setAlert(null); setStart(null); setEnd(null); setWin(w); };
  const apply = () => { if (alert) setAlert(null); setStart(fromInput(draft.start)); setEnd(fromInput(draft.end)); };

  return (
    <div className="hn" data-hunt-page="persistence">
      <NextStrip current="persistence" alert={alert} />
      <AlertBanner alert={d?.alert} words={d?.scope_words} onAll={(b) => { setAll(b ? "1" : null); if (b) { setStart(null); setEnd(null); setWin("all"); } }} onClear={() => setAlert(null)} />
      <p className="ua-hint">
        Autoruns-style: everything that starts by itself, rebuilt from what the recorder saw being written. "Before" is
        the list at the start of the window, "after" at its end; the table shows the difference. Pick a test's start and
        end to see exactly what the test left behind.
      </p>
      <div className="hn-bar">
        <WindowPicker value={custom || byAlert ? ("" as WindowName) : win} onChange={pickWindow} choices={WINDOWS} />
        <span className="hn-when">
          or from <input type="datetime-local" step={1} value={draft.start} onChange={(e) => setDraft({ ...draft, start: e.target.value })} aria-label="Start (UTC)" />
          to <input type="datetime-local" step={1} value={draft.end} onChange={(e) => setDraft({ ...draft, end: e.target.value })} aria-label="End (UTC)" />
          UTC <button className="ua-btn" onClick={apply} disabled={!draft.start && !draft.end}>Compare</button>
        </span>
        {d && <WindowSpan meta={d} />}
      </div>
      <Status loading={loading && !d} error={error} />
      {d && (
        <>
          {/* critique 3: every number counts the same rows; without a real "before" only what can be said is shown */}
          <div className="hn-counts">
            {d.has_before ? (
              <>
                <BigNumber value={count(d.counts.added)} label="added" />
                <BigNumber value={count(d.counts.changed)} label="changed" />
                <BigNumber value={count(d.counts.rewritten)} label="written again (same value)" />
                <BigNumber value={count(d.counts.removed)} label="removed" />
                <BigNumber value={`${count(d.before_total)} → ${count(d.after_total)}`} label="entries at the start → at the end" />
              </>
            ) : (
              <BigNumber value={count(d.counts.first_seen)} label="set to start by itself, first seen in this recording" />
            )}
            <BigNumber value={count(d.writes_in_window)} label="writes recorded" />
          </div>
          <Panel title={d.has_before ? "What changed" : "What is set to start by itself"}
            intro={d.window.since ? <>Between {shortTime(d.window.since)} and {shortTime(d.window.until)} UTC.</> : <>Over all recorded time.</>}
            right={<label className="hn-check"><input type="checkbox" checked={unchanged} onChange={(e) => setUnchanged(e.target.checked)} />also show unchanged entries</label>}>
            {d.before_note && <Notes notes={[d.before_note]} />}
            <ResultTable columns={COLUMNS} rows={d.rows} host={d.host} empty="No autostart entry was added, changed, written again or removed in this window." />
            {d.truncated && <p className="hn-more">Showing the first {d.rows.length}.</p>}
          </Panel>
          <div className="hn-grid2">
            <Panel title="Every write in the window, in order" intro="The raw steps the table above was replayed from.">
              <ResultTable columns={LOG_COLUMNS} times={false}
                rows={d.log.map((c) => ({ cells: { ...c }, count: null, first: c.time, last: c.time, pivots: c.pivots }))}
                empty="No writes to autostart places in this window." />
              {d.log_truncated && <p className="hn-more">Only the last 500 writes are listed.</p>}
            </Panel>
            <Panel title="What this list cannot see" intro="Autoruns reads the live machine; this page only has the recording.">
              <ul className="hn-list-plain">{d.not_seen.map((n) => <li key={n}>{n}</li>)}</ul>
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}

export const lab: Lab = {
  id: "persistence",
  title: "Persistence before/after",
  blurb: "What starts automatically (Run keys, services, Startup folder, scheduled tasks), and what a chosen time window or test added, changed or removed.",
  icon: History,
  Component: PersistencePage,
};
