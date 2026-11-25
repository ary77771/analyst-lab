// Lab "Around this moment" (engine/labs/moment.py): everything on one machine within ±N s of an alert or an
// event, one lane per program, the picked item highlighted. Zoom with the wheel or the buttons, drag to move.
import { Clock } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type PointerEvent as RPointerEvent, type WheelEvent as RWheelEvent } from "react";
import { LabPanel, LabState, NextStrip, useAlertParam, useLab } from "../kit";
import { labHref, type Lab, type LabProps } from "../registry";
import { Thing } from "../_things/Thing";
import { fill } from "../_explain/logic";
import { AlertPicker, Level } from "../_explain/shared";
import { offsetText, pan, ticks, zoomAt, type Range } from "./view";
import "./moment.css";

type W = Record<string, string> & { kinds: Record<string, string> };
export interface MEvent { key: string; lane: string; t: string; offset: number; event_id: number | null; type: string | null; kind: string;
  name: string; what: string; anchor: boolean; alerts: string[]; own_tool: boolean; fields: [string, string | number][] }
export interface MLane { id: string; label: string | null; image: string | null; pid: number | null; parent: string | null; first: string;
  count: number; anchor: boolean; alerts: number; own_tool: boolean; started_here: boolean }
export interface Moment {
  words: W; anchor: { kind: "alert" | "event"; id: string; title: string; level: string | null; time: string | null; host: string } | null;
  window?: { start: string; end: string; seconds: number; t0: string }; lanes?: MLane[]; events?: MEvent[];
  total?: number; shown?: number; truncated?: boolean; max_rows?: number;
  counts?: { records: number; programs: number; machinery_records: number; machinery_programs: number };
}

const WINDOWS = [5, 10, 30, 60, 120, 300];
const LABEL_W = 230, ROW_H = 26, AXIS_H = 28, PAD_R = 16;

function laneName(l: MLane, w: W) {
  return l.label ? `${l.label}${l.pid !== null ? ` (${l.pid})` : ""}` : l.id === "machine" ? w.machine : l.id;
}

export function Timeline({ d, showOwn, selected, onSelect }: { d: Moment; showOwn: boolean; selected: string | null; onSelect: (k: string) => void }) {
  const s = d.window!.seconds;
  const limit: Range = [-s, s];
  const [view, setView] = useState<Range>(limit);
  useEffect(() => setView([-s, s]), [s, d.anchor?.id]);
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(1100);
  useEffect(() => {
    if (!box.current || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((e) => setWidth(Math.max(480, e[0].contentRect.width)));
    ro.observe(box.current);
    return () => ro.disconnect();
  }, []);
  const lanes = (d.lanes ?? []).filter((l) => showOwn || !l.own_tool);
  const row = new Map(lanes.map((l, i) => [l.id, i]));
  const events = (d.events ?? []).filter((e) => row.has(e.lane));
  const plotW = width - LABEL_W - PAD_R;
  const x = (t: number) => LABEL_W + ((t - view[0]) / (view[1] - view[0])) * plotW;
  const toT = (px: number) => view[0] + ((px - LABEL_W) / plotW) * (view[1] - view[0]);
  const height = AXIS_H + lanes.length * ROW_H + 8;
  const drag = useRef<{ px: number; view: Range } | null>(null);
  const onWheel = (e: RWheelEvent<SVGSVGElement>) => {
    const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
    setView((v) => zoomAt(v, e.deltaY < 0 ? 0.8 : 1.25, toT(e.clientX - r.left), limit));
  };
  const onDown = (e: RPointerEvent<SVGSVGElement>) => { drag.current = { px: e.clientX, view }; };
  const onMove = (e: RPointerEvent<SVGSVGElement>) => {
    if (!drag.current) return;
    const dt = ((drag.current.px - e.clientX) / plotW) * (drag.current.view[1] - drag.current.view[0]);
    setView(pan(drag.current.view, dt, limit));
  };
  const w = d.words;
  return (
    <div className="mo-chart" ref={box}>
      <div className="xp-row mo-tools">
        <button className="xp-link" onClick={() => setView((v) => zoomAt(v, 0.5, (v[0] + v[1]) / 2, limit))}>{w.zoom_in}</button>
        <button className="xp-link" onClick={() => setView((v) => zoomAt(v, 2, (v[0] + v[1]) / 2, limit))}>{w.zoom_out}</button>
        <button className="xp-link" onClick={() => setView(limit)}>{w.reset}</button>
        <span className="xp-small xp-dim xp-mono">{offsetText(view[0])} … {offsetText(view[1])}</span>
        <span className="xp-grow" /><span className="xp-small xp-dim">{w.zoom_hint}</span>
      </div>
      <svg width={width} height={height} className="mo-svg" onWheel={onWheel} onPointerDown={onDown} onPointerMove={onMove}
        onPointerUp={() => { drag.current = null; }} onPointerLeave={() => { drag.current = null; }} role="img">
        {ticks(view).map((t) => (
          <g key={t}><line className="mo-grid" x1={x(t)} x2={x(t)} y1={AXIS_H - 6} y2={height} />
            <text className="mo-tick" x={x(t)} y={AXIS_H - 10} textAnchor="middle">{offsetText(t)}</text></g>))}
        {lanes.map((l, i) => (
          <g key={l.id} className="mo-lane" data-anchor={l.anchor}>
            <rect x={0} y={AXIS_H + i * ROW_H} width={width} height={ROW_H} className={i % 2 ? "mo-band" : "mo-band mo-band-alt"} />
            <text className="mo-label" x={8} y={AXIS_H + i * ROW_H + ROW_H / 2 + 4}>{laneName(l, w).slice(0, 30)}</text>
          </g>))}
        {0 >= view[0] && 0 <= view[1] ? <line className="mo-now" x1={x(0)} x2={x(0)} y1={AXIS_H - 4} y2={height} /> : null}
        {events.filter((e) => e.offset >= view[0] && e.offset <= view[1]).map((e) => {
          const cy = AXIS_H + (row.get(e.lane) ?? 0) * ROW_H + ROW_H / 2;
          return (
            <circle key={e.key} cx={x(e.offset)} cy={cy} r={e.anchor ? 7 : e.key === selected ? 6 : 4.5}
              className={`mo-dot mo-k-${e.kind}`} data-anchor={e.anchor} data-alert={e.alerts.length > 0} data-selected={e.key === selected}
              onClick={(ev) => { ev.stopPropagation(); onSelect(e.key); }}>
              <title>{`${offsetText(e.offset)} · ${e.name} · ${e.what}`}</title>
            </circle>);
        })}
      </svg>
    </div>
  );
}

function EventDetail({ e, d, seconds }: { e: MEvent; d: Moment; seconds: number }) {
  const w = d.words;
  return (
    <div className="mo-detail">
      <div className="xp-row">
        <b className="xp-mono">{offsetText(e.offset)}</b><span className={`mo-kind mo-k-${e.kind}`}>{e.name}</span><span className="xp-grow" />
        <a className="xp-link" href={labHref("moment", { event: e.key, seconds })}>{w.center}</a>
        {e.alerts.map((a, i) => <a key={a} className="xp-link" href={labHref("why", { alert: a })}>{w.why}{e.alerts.length > 1 ? ` ${i + 1}` : ""}</a>)}
      </div>
      <table className="xp-table"><tbody>{e.fields.map(([k, v]) => (
        <tr key={k}><td className="xp-k">{k}</td><td className="xp-v">{String(v)}</td></tr>))}</tbody></table>
    </div>
  );
}

/** The records the page shows: Python's one rule (the checklist says the same number), plus the test machinery's
 * when it is shown. */
export function shownCount(d: Moment, showOwn: boolean): number {
  if (!d.counts) return d.shown ?? 0;
  return d.counts.records + (showOwn ? d.counts.machinery_records : 0);
}

export function MomentView({ d, seconds }: { d: Moment; seconds: number }) {
  const w = d.words;
  const [showOwn, setShowOwn] = useState(false);
  const firstAnchor = useMemo(() => d.events?.find((e) => e.anchor)?.key ?? null, [d]);
  const [selected, setSelected] = useState<string | null>(firstAnchor);
  useEffect(() => setSelected(firstAnchor), [firstAnchor]);
  if (!d.anchor || !d.window) return null;
  const lanes = (d.lanes ?? []).filter((l) => showOwn || !l.own_tool);
  const byLane = new Map<string, MEvent[]>();
  for (const e of d.events ?? []) { if (!byLane.has(e.lane)) byLane.set(e.lane, []); byLane.get(e.lane)!.push(e); }
  const sel = (d.events ?? []).find((e) => e.key === selected);
  const hidden = (d.lanes ?? []).filter((l) => l.own_tool).length;
  return (
    <>
      <LabPanel>
        <div className="xp-row">
          {d.anchor.level ? <Level level={d.anchor.level} /> : null}<h2 className="xp-title">{d.anchor.title}</h2>
          <span className="xp-small xp-dim xp-mono">{d.anchor.time}</span><span className="xp-grow" />
        </div>
        <p className="ua-hint">{w.intro}</p>
        <div className="xp-row">
          <span className="xp-small xp-dim">{w.seconds}</span>
          <div className="tq-toggle mo-windows">{WINDOWS.map((n) => (
            <a key={n} aria-pressed={n === seconds} href={labHref("moment", { [d.anchor!.kind]: d.anchor!.id, seconds: n })}>±{n} s</a>))}</div>
          <button className="tq-check" aria-pressed={showOwn} onClick={() => setShowOwn((v) => !v)}><i />{w.own_tools}{hidden ? ` (${hidden})` : ""}</button>
          <span className="xp-grow" />
          <span className="xp-small xp-muted"><b className="xp-mono">{shownCount(d, showOwn)}</b> {w.events} · <b className="xp-mono">{lanes.length}</b> {w.programs}</span>
        </div>
        <div className="xp-row mo-legend">{Object.entries(w.kinds).map(([k, v]) => <span key={k} className={`mo-kind mo-k-${k}`}>{v}</span>)}
          <span className="mo-kind mo-anchor">{d.anchor.kind === "alert" ? w.anchor_alert : w.anchor_event}</span>
          <span className="mo-kind mo-alert">{w.alert_evidence}</span></div>
        {d.truncated ? <p className="xp-note" data-kind="warn">{fill(w.truncated, { max: d.max_rows ?? 0 })}</p> : null}
      </LabPanel>
      {(d.events ?? []).length === 0 ? <p className="lab-state" data-kind="empty">{w.empty}</p> : (
        <>
          <section className="ua-panel lab-panel"><Timeline d={d} showOwn={showOwn} selected={selected} onSelect={setSelected} />
            {sel ? <EventDetail e={sel} d={d} seconds={seconds} /> : null}</section>
          <section className="ua-panel lab-panel mo-list">
            {lanes.map((l) => (
              <details key={l.id} open={l.anchor || l.alerts > 0} className="mo-group" data-anchor={l.anchor}>
                <summary>{l.image ? <Thing field="Image" value={l.image} label={laneName(l, w)} host={d.anchor?.host} /> : <b>{laneName(l, w)}</b>}{l.parent ? <span className="xp-dim"> · {w.started_by} {l.parent}</span> : null}
                  <span className="xp-dim"> · {l.count}</span></summary>
                <ol>{(byLane.get(l.id) ?? []).map((e) => (
                  <li key={e.key} data-anchor={e.anchor} data-alert={e.alerts.length > 0} aria-selected={e.key === selected} onClick={() => setSelected(e.key)}>
                    <span className="xp-mono mo-off">{offsetText(e.offset)}</span><span className={`mo-kind mo-k-${e.kind}`}>{e.name}</span>
                    <span className="mo-what">{e.what}</span>
                  </li>))}</ol>
              </details>))}
          </section>
        </>)}
    </>
  );
}

function MomentLab({ params }: LabProps) {
  const [alert] = useAlertParam();
  const event = params.get("event");
  const seconds = Number(params.get("seconds") || 30) || 30;
  const q = alert ? `alert=${encodeURIComponent(alert)}` : event ? `event=${encodeURIComponent(event)}` : null;
  const { data, error, loading } = useLab<Moment>(q ? `/api/labs/moment?${q}&seconds=${seconds}` : null);
  if (!q) return <AlertPicker lab="moment" url="/api/labs/moment" />;
  return <><NextStrip current="moment" alert={alert} /><LabState loading={loading} error={error}>{data && <MomentView d={data} seconds={seconds} />}</LabState></>;
}

export const lab: Lab = {
  id: "moment",
  title: "Around this moment",
  blurb: "Everything recorded on the machine seconds before and after an alert or an event, one lane per program; zoom in.",
  icon: Clock,
  Component: MomentLab,
};
