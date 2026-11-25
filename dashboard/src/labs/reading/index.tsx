// Labs page "Reading effort" (night-hunt, VISION idea 4): for one alert's run on the test machine, N raw records
// a person would face, M the story cites, K steps it found. Records, never minutes. Every number and word comes
// from engine/labs/reading.py at request time; each cited record opens through /api/events/{key}.
import { useState } from "react";
import { BookOpenCheck } from "lucide-react";
import type { Lab, LabProps } from "../registry";
import { count, shortTime } from "../hunts/logic";
import { NextStrip, useAlertParam } from "../kit";
import { Notes, Panel, Status, useJSON } from "../hunts/shared";
import "../hunts/hunt.css";

interface AlertRow { id: string; title: string; time: string; level: string; host: string }
interface Cited { key: string; event: number | null; record: number | null; time: string | null; text: string | null; in_store: boolean }
interface Effort {
  alert: AlertRow; n: number; m: number; k: number; one_in: number | null; cited: Cited[];
  window: { start: string | null; end: string | null; how: string }; notes: string[]; words: Record<string, string>; ms: number;
}

function Funnel({ e }: { e: Effort }) {
  const steps = [{ v: e.n, label: e.words.n }, { v: e.m, label: e.words.m }, { v: e.k, label: e.words.k }];
  const log = (v: number) => Math.log10(Math.max(1, v) + 1);
  const top = log(e.n);
  return (
    <div className="hn-funnel">
      {steps.map((s, i) => (
        <div key={s.label} className="hn-funnel-row" data-step={i}>
          <div className="hn-funnel-bar"><i style={{ width: `${Math.max(1.5, (log(s.v) / top) * 100)}%` }} /></div>
          <b>{count(s.v)}</b><span>{s.label}</span>
        </div>
      ))}
    </div>
  );
}

function Record({ c }: { c: Cited }) {
  const [open, setOpen] = useState(false);
  const rec = useJSON<Record<string, unknown>>(open && c.in_store ? `/api/events/${encodeURIComponent(c.key)}` : null);
  const shown = rec.data ? Object.entries(rec.data).filter(([k]) => !["dedup_key", "id", "raw_xml"].includes(k)) : [];
  return (
    <li className="hn-cited">
      <button onClick={() => setOpen(!open)} aria-expanded={open} disabled={!c.in_store}>
        <span className="hn-time">{shortTime(c.time)}</span><span>{c.text ?? c.key}</span>
        {!c.in_store && <span className="hn-tag" data-kind="gap">not in this store</span>}
      </button>
      {open && (rec.error ? <p className="hn-note" data-kind="gap">{rec.error}</p> : rec.data ? (
        <dl className="hn-record">{shown.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{String(v)}</dd></div>)}</dl>
      ) : <p className="hn-span">…</p>)}
      <a className="hn-pivot" href={`#/labs/moment?${new URLSearchParams({ event: c.key }).toString()}`}>around this moment</a>
    </li>
  );
}

export function ReadingPage(_: LabProps) {
  const list = useJSON<{ alerts: AlertRow[]; words: Record<string, string> }>("/api/labs/reading/");
  const [picked, setPicked] = useAlertParam();                   // wave 3: the alert travels between labs in the address
  const id = picked || list.data?.alerts[0]?.id || "";
  const e = useJSON<Effort>(id ? `/api/labs/reading/${encodeURIComponent(id)}` : null);
  const d = e.data && e.data.alert.id === id ? e.data : null;
  const w = list.data?.words;
  return (
    <div className="hn" data-hunt-page="reading">
      <NextStrip current="reading" alert={id || null} />
      <Status loading={list.loading && !list.data} error={list.error} />
      {list.data && !list.data.alerts.length && <p className="lab-state" data-kind="empty">No alert is shown on this dashboard yet: nothing to measure.</p>}
      {list.data && list.data.alerts.length > 0 && (
        <label className="hn-check">Alert
          <select className="hn-select" value={id} onChange={(ev) => setPicked(ev.target.value, "replace")}>
            {list.data.alerts.map((a) => <option key={a.id} value={a.id}>{shortTime(a.time)} · {a.title}</option>)}
          </select>
        </label>
      )}
      <Status loading={e.loading && !d} error={e.error} />
      {d && w && (
        <div className="hn-grid2">
          <Panel title={w.title} intro={w.intro}>
            <Funnel e={d} />
            {d.one_in != null && <p className="hn-noise-honest">The story cites about 1 record in {count(d.one_in)}.</p>}
            <p className="ua-hint">{w.honest}</p>
            <Notes notes={d.notes} />
            <p className="hn-span">Run: <b>{shortTime(d.window.start)}</b> to <b>{shortTime(d.window.end)}</b> UTC · {d.ms} ms ·{" "}
              <a className="hn-pivot" href={`#/labs/moment?${new URLSearchParams({ alert: d.alert.id, seconds: "300" }).toString()}`}>show the records around the alert</a></p>
          </Panel>
          <Panel title={`The ${count(d.m)} records the story cites`} intro="Click one to read it as recorded.">
            <ul className="hn-cited-list">{d.cited.map((c) => <Record key={c.key} c={c} />)}</ul>
          </Panel>
        </div>
      )}
    </div>
  );
}

export const lab: Lab = {
  id: "reading",
  title: "Reading effort",
  blurb: "For one alert's run: how many raw records a person would read, how many the story cites, and how many steps it found.",
  icon: BookOpenCheck,
  Component: ReadingPage,
};
