// Labs page "Saved hunts" (night-hunt): one-click questions over the event store. Each hunt has a
// plain title, why an analyst cares, a count and a table; every row links to the pivot page.
// Data and words: engine/labs/hunts.py (/api/labs/hunts/...). Nothing here raises an alert.
import { useState } from "react";
import { Crosshair } from "lucide-react";
import type { Lab, LabProps } from "../registry";
import { NextStrip, useAlertParam } from "../kit";
import { apiQuery, count, type WindowName } from "./logic";
import { AlertBanner, BigNumber, Notes, Panel, ResultTable, Status, WindowPicker, useJSON, useParam, useWindowParam, type AlertInView, type Column, type Meta, type ResultRow } from "./shared";

interface HuntInfo { id: string; title: string; why: string; technique: string; columns: Column[] }
interface Listing { hunts: HuntInfo[]; words: { intro: string; why: string; found: string; events: string; more: string } }
interface Summary extends Meta { hunts: { id: string; title: string; count: number; ms: number; not_recorded: string | null }[]; alert: AlertInView | null }
interface Result extends Meta, HuntInfo {
  count: number; events: number; rows: ResultRow[]; truncated: boolean; notes: string[]; not_recorded: string | null; ms: number;
}

const API = "/api/labs/hunts";

export function HuntsPage({ params }: LabProps) {
  const [win, setWin] = useWindowParam(params, "24h");
  const [own, setOwn] = useState(false);
  const [picked, setPicked] = useParam(params, "hunt", "");
  const [alert, setAlert] = useAlertParam();                       // wave 3: "#/labs/hunts?alert=<id>"
  const [all, setAll] = useParam(params, "all", "");
  const list = useJSON<Listing>(`${API}/`);
  const q = apiQuery({ window: win, include_own: own, alert, only_alert: alert ? (all ? "false" : "true") : null });
  const summary = useJSON<Summary>(`${API}/summary?${q}`);
  const hunts = list.data?.hunts ?? [];
  const current = hunts.find((h) => h.id === picked) ?? hunts[0];
  const result = useJSON<Result>(current ? `${API}/run/${current.id}?${q}&limit=300` : null);
  const counts = new Map(summary.data?.hunts.map((h) => [h.id, h]) ?? []);
  const limited = !!summary.data?.alert?.limited;
  const r = result.data && result.data.id === current?.id && (limited ? result.data.window.name === "alert" : result.data.window.name === win)
    ? result.data : null;
  const w = list.data?.words;
  const pickWindow = (nw: WindowName) => { if (limited) setAll("1"); setWin(nw); };

  return (
    <div className="hn" data-hunt-page="hunts">
      <NextStrip current="hunts" alert={alert} />
      {w && <p className="ua-hint">{w.intro}</p>}
      <AlertBanner alert={summary.data?.alert} words={summary.data?.scope_words} onAll={(b) => { setAll(b ? "1" : null); if (b) setWin("all"); }} onClear={() => setAlert(null)} />
      <WindowPicker value={limited ? ("" as WindowName) : win} onChange={pickWindow} includeOwn={own} onIncludeOwn={setOwn} meta={summary.data} />
      <Status loading={list.loading && !list.data} error={list.error ?? summary.error} />
      <div className="hn-split">
        <nav aria-label="Hunts" className="hn-list">
          {hunts.map((h) => {
            const c = counts.get(h.id);
            return (
              <button key={h.id} className="hn-item" onClick={() => setPicked(h.id)} aria-current={h.id === current?.id} data-hunt={h.id}>
                <span><b>{h.title}</b><small>ATT&CK {h.technique}</small></span>
                <span className="hn-badge" data-kind={c?.not_recorded ? "gap" : c && c.count > 0 ? "hit" : undefined}
                  title={c?.not_recorded ?? undefined}>{c ? (c.not_recorded ? "n/a" : count(c.count)) : "…"}</span>
              </button>
            );
          })}
        </nav>
        {current && (
          <Panel title={current.title} intro={<><b>{w?.why ?? "Why it matters"}: </b>{current.why}</>}
            right={<BigNumber value={r ? count(r.count) : "…"} label={r ? `${w?.found ?? "found"} · ${count(r.events)} ${w?.events ?? "events"} · ${r.ms} ms` : "…"} />}>
            <Status loading={result.loading && !r} error={result.error} />
            {r && <Notes notes={r.notes} notRecorded={r.not_recorded} />}
            {r && <ResultTable columns={current.columns} rows={r.rows} host={r.host} />}
            {r?.truncated && <p className="hn-more">{(w?.more ?? "Showing {n} of {total}.").replace("{n}", String(r.rows.length)).replace("{total}", count(r.count))}</p>}
          </Panel>
        )}
      </div>
    </div>
  );
}

export const lab: Lab = {
  id: "hunts",
  title: "Saved hunts",
  blurb: "One-click questions over the recording: programs deleted after they ran, run from Downloads, new autostarts, renamed tools, open ports.",
  icon: Crosshair,
  Component: HuntsPage,
};
