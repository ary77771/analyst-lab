// React pieces shared by the night-hunt Labs pages (hunts, rarity, persistence, network, gaps): data
// loading, the time-window picker, the result table with pivot links, notes. Styles: hunt.css (hn-*),
// in design A's tokens. What a page CANNOT see is always said (notes / not_recorded come from Python).
import { useCallback, useState, type ReactNode } from "react";
import { Info, EyeOff, X } from "lucide-react";
import { useLab } from "../kit";
import { Thing } from "../_things/Thing";
import { WINDOWS, WINDOW_WORDS, fileName, isWindow, pivotHref, shortTime, withParams, type WindowName } from "./logic";
import "./hunt.css";

export interface Pivot { field: string; value: string }
export interface ResultRow { cells: Record<string, unknown>; count: number | null; first: string | null; last: string | null; pivots: Pivot[] }
export interface Column { key: string; label: string; kind?: "num" | "path" | "time" | "text" | "tag" }
export interface Meta { window: { name: string; since: string | null; until: string | null }; store: { newest: string | null; hosts: string[] }; host: string | null; scope?: string; scope_words?: Partial<ScopeWords> }

export const useJSON = useLab;

/** A value kept in the page's address (#/labs/<id>?name=value), so a link or a reload keeps the choice.
 *  Starts from the registry's `params`; replaceState keeps it without a new history step or re-route. */
export function useParam(params: URLSearchParams, name: string, fallback: string): [string, (v: string | null) => void] {
  const [v, setV] = useState(params.get(name) ?? fallback);
  const set = useCallback((nv: string | null) => {
    history.replaceState(null, "", withParams(window.location.hash || "#", { [name]: nv }));
    setV(nv ?? fallback);
  }, [name, fallback]);
  return [v, set];
}

export function useWindowParam(params: URLSearchParams, fallback: WindowName = "24h"): [WindowName, (w: WindowName) => void] {
  const [w, setW] = useParam(params, "window", fallback);
  return [isWindow(w) ? w : fallback, setW];
}

export function WindowPicker({ value, onChange, includeOwn, onIncludeOwn, meta, choices = WINDOWS }: {
  value: WindowName; onChange: (w: WindowName) => void; includeOwn?: boolean; onIncludeOwn?: (b: boolean) => void;
  meta?: Meta | null; choices?: readonly WindowName[];
}) {
  return (
    <div className="hn-bar">
      <div role="radiogroup" aria-label="Time window" className="hn-seg">
        {choices.map((w) => (
          <button key={w} role="radio" aria-checked={value === w} onClick={() => onChange(w)} title={WINDOW_WORDS[w]}>{w}</button>
        ))}
      </div>
      {onIncludeOwn && (
        <label className="hn-check">
          <input type="checkbox" checked={!!includeOwn} onChange={(e) => onIncludeOwn(e.target.checked)} />
          show the test machinery
        </label>
      )}
      {meta && <WindowSpan meta={meta} />}
    </div>
  );
}

export function WindowSpan({ meta }: { meta: Meta }) {
  return (
    <span className="hn-span">
      {meta.window.since ? <>from <b>{shortTime(meta.window.since)}</b> to <b>{shortTime(meta.window.until)}</b> UTC</> : <>all recorded time</>}
      {isWindow(meta.window.name) && meta.store.newest && <> · counted back from the newest event, not from now</>}
      {meta.scope && <> · showing <b>{meta.scope}</b></>}
    </span>
  );
}

const PIVOT_WORDS: Record<string, string> = {
  ProcessGuid: "process", Image: "program", sha256: "file hash", DestinationIp: "address", DestinationHostname: "name",
  TargetFilename: "file", TargetObject: "registry",
};

/** The row's things as the dashboard's shared chips (wave 3: `Thing` from labs/_things): each opens Pivot;
 *  the first carries "+ case". `pin` is kept for callers but the chip's own "+ case" does the pinning. */
export function PivotLinks({ pivots, host }: { pivots: Pivot[]; host?: string | null; pin?: { label: string; time?: string | null } }) {
  const links = pivots.filter((p) => pivotHref(p.field, p.value, host));
  if (!links.length) return null;
  return (
    <span className="hn-pivots">
      {links.map((p, i) => (
        <Thing key={p.field + p.value} field={p.field} value={p.value} host={host} role={PIVOT_WORDS[p.field] ?? p.field}
          label={PIVOT_WORDS[p.field] ?? p.field} plusCase={i === 0} />
      ))}
    </span>
  );
}

const PATHLIKE = /program|place|value|parent|example|file|path|engine_path|where|target|destination/;

export function Cell({ v, kind }: { v: unknown; kind?: Column["kind"] }) {
  if (v === null || v === undefined || v === "") return <span className="hn-dash">-</span>;
  if (typeof v === "number") return <>{v.toLocaleString("en-GB")}</>;
  if (kind === "time") return <>{shortTime(String(v))}</>;
  if (kind === "tag") return <span className="hn-tag" data-kind={String(v)}>{String(v).replace(/_/g, " ")}</span>;
  const s = String(v);
  return <span title={s.length > 120 ? s : undefined}>{s.length > 120 ? s.slice(0, 118) + "…" : s}</span>;
}

function cellClass(c: Column, v: unknown) {
  if (c.kind) return c.kind === "num" ? "hn-num" : c.kind === "time" ? "hn-time" : c.kind === "path" ? "hn-path" : undefined;
  if (typeof v === "number") return "hn-num";
  return PATHLIKE.test(c.key) ? "hn-path" : undefined;
}

/** A few words for a pinned row: its first column's value (a path shortened to the file name). */
function pinLabel(r: ResultRow, columns: Column[]): string {
  const v = r.cells[columns[0]?.key];
  const s = String(v ?? "").trim();
  return (s.includes("\\") ? fileName(s) : s) || "finding";
}

export function ResultTable({ columns, rows, host, empty, times = true, mark, onPick, picked }: {
  columns: Column[]; rows: ResultRow[]; host?: string | null; empty?: ReactNode; times?: boolean;
  mark?: (r: ResultRow) => string | undefined; onPick?: (r: ResultRow, i: number) => void; picked?: number | null;
}) {
  if (!rows.length) return <p className="hn-empty">{empty ?? "Nothing found in this time window."}</p>;
  return (
    <div className="hn-tablewrap">
      <table className="hn-table">
        <thead>
          <tr>
            {columns.map((c) => <th key={c.key}>{c.label}</th>)}
            {times && <th>First</th>}
            {times && <th>Last</th>}
            <th>Pivot</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} data-mark={mark?.(r)} data-selected={picked === i || undefined}
              onClick={onPick ? () => onPick(r, i) : undefined} style={onPick ? { cursor: "pointer" } : undefined}>
              {columns.map((c) => {
                const col = c.kind || !c.key.endsWith("_at") ? c : { ...c, kind: "time" as const };   // "deleted_at" etc: a time
                return <td key={c.key} className={cellClass(col, r.cells[c.key])}><Cell v={r.cells[c.key]} kind={col.kind} /></td>;
              })}
              {times && <td className="hn-time">{shortTime(r.first)}</td>}
              {times && <td className="hn-time">{shortTime(r.last)}</td>}
              <td><PivotLinks pivots={r.pivots} host={host} pin={{ label: pinLabel(r, columns), time: r.first }} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Notes({ notes, notRecorded }: { notes?: string[]; notRecorded?: string | null }) {
  if (!notes?.length && !notRecorded) return null;
  return (
    <div className="hn-notes">
      {notRecorded && <p className="hn-note" data-kind="gap"><EyeOff size={14} aria-hidden />{notRecorded}</p>}
      {notes?.map((n) => <p key={n} className="hn-note"><Info size={14} aria-hidden />{n}</p>)}
    </div>
  );
}

export function Panel({ title, intro, right, children }: { title: ReactNode; intro?: ReactNode; right?: ReactNode; children: ReactNode }) {
  return (
    <section className="hn-panel">
      <header>
        <div>
          <h2>{title}</h2>
          {intro && <p>{intro}</p>}
        </div>
        {right}
      </header>
      <div className="hn-body">{children}</div>
    </section>
  );
}

export interface AlertInView { id: string; missing?: boolean; title?: string; time?: string; host?: string; how?: string; programs?: string[]; narrowed?: boolean; limited?: boolean }

/** Wave 3: the alert a page is narrowed to, and the one switch to see everything ("show all"). */
/** The scope sentences every lab shares (Python: engine/labs/_shared_defs.WORDS["scope"], sent as `scope_words`). */
export type ScopeWords = Record<"limited" | "programs" | "no_start" | "all" | "show_all" | "show_alert" | "missing" | "forget", string>;
const SCOPE_FALLBACK: ScopeWords = {
  limited: "Showing what relates to this alert's run", programs: "and its program{s} {programs}",
  no_start: "No machine start was recorded before this alert, so its run can't be told apart: showing the whole recording",
  all: "Showing the whole recording", show_all: "show the whole recording", show_alert: "show only this alert's run",
  missing: "This alert isn't in this recording, so the whole chosen time is shown", forget: "forget the alert",
};

/** Wave 3 / critique 3: ONE banner for every lab opened with ?alert=<id>, in the shared words. `onAll(true)` = show
 *  the whole recording, `onAll(false)` = show only this alert's run. */
export function AlertBanner({ alert, words, onAll, onClear }: {
  alert: AlertInView | null | undefined; words?: Partial<ScopeWords> | null; onAll: (all: boolean) => void; onClear: () => void;
}) {
  if (!alert) return null;
  const w: ScopeWords = { ...SCOPE_FALLBACK, ...(words ?? {}) };
  // each " · " stays on the line of the button it introduces (critique 4: a wrapped button left a dangling " · ")
  const forget = <span className="hn-nowrap"> · <button className="hn-linkbtn" onClick={onClear}><X size={12} aria-hidden />{w.forget}</button></span>;
  if (alert.missing) return <p className="hn-alertbar" data-kind="missing">{w.missing}.{forget}</p>;
  const which = <> (alert <b>“{alert.title}”</b>, {shortTime(alert.time)})</>;
  const limited = alert.limited ?? alert.narrowed ?? true;
  if (!limited) return <p className="hn-alertbar">{w.all}{which}<span className="hn-nowrap"> · <button className="hn-linkbtn" onClick={() => onAll(false)}>{w.show_alert}</button></span>{forget}</p>;
  if (alert.how !== "boot") return <p className="hn-alertbar">{w.no_start}{which}.{forget}</p>;
  const progs = (alert.programs ?? []).map(fileName);
  const programs = alert.narrowed && progs.length
    ? <> {w.programs.replace("{s}", progs.length === 1 ? "" : "s").replace("{programs}", "")}<b>{progs.join(", ")}</b></> : null;
  return <p className="hn-alertbar">{w.limited}{programs}{which}<span className="hn-nowrap"> · <button className="hn-linkbtn" onClick={() => onAll(true)}>{w.show_all}</button></span>{forget}</p>;
}

/** A technical word with its everyday meaning on hover (VISION W3-6): dotted underline, focusable. */
export function Term({ plain, children }: { plain: string; children: ReactNode }) {
  return <abbr className="hn-term" title={plain} tabIndex={0} aria-label={`${typeof children === "string" ? children : ""}: ${plain}`}>{children}</abbr>;
}

export function BigNumber({ value, label }: { value: ReactNode; label: ReactNode }) {
  return <div className="hn-big"><b>{value}</b><span>{label}</span></div>;
}

export function Status({ loading, error }: { loading: boolean; error: string | null }) {
  if (error) return <p className="lab-state" data-kind="error" role="alert">This lab could not load its data: {error}</p>;
  if (loading) return <p className="lab-state" data-kind="loading">Reading the event store…</p>;
  return null;
}
