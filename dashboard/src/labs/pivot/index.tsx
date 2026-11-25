// Pivot on anything (night-pivot, 2026-11-23). Back end: engine/labs/pivot.py.
// Give it a program, one run, a file, a fingerprint, an address, a domain, a registry key or a user: it lists
// every recorded event naming it, the runs that touched it with their parents and children, every other thing
// those events name (each a new pivot) and the alerts whose evidence includes them.
// "#/labs/pivot?kind=hash&value=..." opens a pivot directly.
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  AppWindow, ArrowRight, Cpu, Crosshair, FileText, Fingerprint, Globe, KeyRound, Network, Search, User,
} from "lucide-react";
import type { Lab, LabProps } from "../registry";
import { NextStrip, useLab } from "../kit";
import { groupByKind, KINDS, kindFrom, loadTrail, rawQuery, nextTrail, pivotHref, saveTrail, utc, type Entity, type Kind } from "./links";
import { PlusCase, Thing } from "../_things";
import "./pivot.css";

interface PivotEvent { key: string; time: string; host: string; event_id: number | null; type: string | null; summary: string; command_line: string | null; entities: Entity[] }
interface Proc { guid: string; label: string; image: string | null; pid: number | null; time?: string; first?: string; key?: string; events?: number }
interface AlertHit { id: string; title: string; level: string; time: string; host: string; rule: string; why: string; shared: number }
interface Gap { what: string; why: string; key: string }
interface PivotResult {
  kind: Kind; kind_word: string; value: string; total: number; shown: number; first: string | null; last: string | null;
  events: PivotEvent[]; processes: Proc[]; parents: Proc[]; children: Proc[]; linked: Entity[]; alerts: AlertHit[]; alerts_total: number; gaps: Gap[];
  machinery_hidden?: number; words?: { machinery_switch: string; machinery_hidden: string };
}
interface Start { id: string; title: string; level: string; time: string; entities: Entity[] }
interface KindRow { kind: Kind; word: string }

const ICON: Record<string, typeof Cpu> = {
  program: AppWindow, process: Cpu, file: FileText, hash: Fingerprint, ip: Network, domain: Globe, registry: KeyRound, user: User,
};
const TEXT = {
  searchHint: "Type part of a name (a program, file, domain, address, registry key or user) or paste a SHA-256 fingerprint.",
  searchPlaceholder: "e.g. tool.exe, 10.0.2.2, a fingerprint…",
  search: "Find",
  orExact: "or pivot on an exact value",
  go: "Pivot",
  startsTitle: "Start from an alert",
  startsHint: "The things named by the newest alerts' evidence. Click one to see everything linked to it.",
  noStarts: "There are no alerts to start from yet: use the search above.",
  noMatch: "Nothing in the store has that in its name.",
  trail: "Your trail",
  events: "events name it",
  runs: "runs touched it",
  linkedN: "other things linked",
  alertsN: "alerts involve it",
  timeline: "Every event that names it",
  timelineHint: "Oldest first. The chips are the other things each event names: click one to pivot on it.",
  more: (shown: number, total: number) => `Showing the first ${shown} of ${total} events.`,
  alerts: "Alerts that involve it",
  noAlerts: "No alert cites these events or mentions this value.",
  family: "Runs that touched it",
  familyHint: "Each run with the run that started it (above) and the runs it started (below).",
  parentOf: "started by",
  childOf: "started",
  linked: "Linked things",
  gaps: "What the records cannot say",
  nothing: (w: string) => `No recorded event names this ${w}.`,
  span: "Seen",
  to: "to",
  open: "Open the alert",
  cmd: "command line",
  loading: "Looking through every recorded event…",
  hideMachinery: "Hide the test machinery again",
  showAll: (n: number) => `Show all ${n}`,
  showFew: "Show fewer",
  alertsCut: (shown: number, total: number) => `The newest ${shown} of ${total} are listed.`,
};
const FEW = 6;

const useJson = useLab;                               // the kit's loader: patient through a restart

/** The pivot lab's chip: the shared <Thing/> (dashboard/src/labs/_things), kept under its old name. */
export function Chip({ e, current }: { e: Entity; current?: boolean }) {
  // a run is named by its program and PID when the row knows them (its id alone tells a person nothing)
  const label = e.kind === "process" && e.role && /\(PID /.test(e.role) ? e.role : undefined;
  return <Thing kind={e.kind} value={e.value} role={e.role} label={label} count={e.events ?? null} current={current} />;
}

function Panel({ title, hint, children, className }: { title: string; hint?: string; children: ReactNode; className?: string }) {
  return (
    <section className={`ua-panel pv-panel ${className ?? ""}`}>
      <h2>{title}</h2>
      {hint && <p className="ua-hint">{hint}</p>}
      {children}
    </section>
  );
}

function Finder({ kinds }: { kinds: KindRow[] }) {
  const [q, setQ] = useState("");
  const [asked, setAsked] = useState<string | null>(null);
  const [kind, setKind] = useState<Kind>("program");
  const [exact, setExact] = useState("");
  const found = useJson<(Entity & { kind_word: string })[]>(asked ? `/api/labs/pivot/search?q=${encodeURIComponent(asked)}` : null);
  const submit = (ev: FormEvent) => { ev.preventDefault(); setAsked(q.trim() || null); };
  const go = (ev: FormEvent) => { ev.preventDefault(); if (exact.trim()) window.location.hash = pivotHref(kind, exact.trim()); };
  return (
    <section className="ua-panel pv-panel pv-finder">
      <form onSubmit={submit} className="pv-row">
        <Search size={16} aria-hidden="true" />
        <input className="pv-input" value={q} onChange={(e) => setQ(e.target.value)} placeholder={TEXT.searchPlaceholder} aria-label={TEXT.searchHint} />
        <button className="ua-btn" data-kind="primary" type="submit">{TEXT.search}</button>
      </form>
      <form onSubmit={go} className="pv-row pv-exact">
        <span className="ua-hint">{TEXT.orExact}</span>
        <select className="pv-input pv-select" value={kind} onChange={(e) => setKind(e.target.value as Kind)} aria-label="kind">
          {(kinds.length ? kinds : KINDS.map((k) => ({ kind: k, word: k }))).map((k) => <option key={k.kind} value={k.kind}>{k.word}</option>)}
        </select>
        <input className="pv-input" value={exact} onChange={(e) => setExact(e.target.value)} aria-label="value" />
        <button className="ua-btn" type="submit">{TEXT.go}<ArrowRight size={14} /></button>
      </form>
      {asked && (
        found.error ? <p className="lab-state" data-kind="error">{found.error}</p>
          : found.loading ? <p className="ua-hint">…</p>
            : found.data && found.data.length === 0 ? <p className="ua-hint">{TEXT.noMatch}</p>
              : <div className="pv-chips">{found.data?.map((e) => <Chip key={`${e.kind}|${e.value}`} e={e} />)}</div>
      )}
    </section>
  );
}

function Starts() {
  const s = useJson<Start[]>("/api/labs/pivot/starts");
  return (
    <Panel title={TEXT.startsTitle} hint={TEXT.startsHint}>
      {s.error ? <p className="lab-state" data-kind="error">{s.error}</p>
        : s.loading ? <p className="ua-hint">…</p>
          : !s.data?.length ? <p className="ua-hint">{TEXT.noStarts}</p>
            : <ul className="pv-list">
              {s.data.map((a) => (
                <li key={a.id} className="pv-start">
                  <div className="pv-start-head">
                    <span className="ua-tag pv-level" data-level={a.level}>{a.level}</span>
                    <b>{a.title}</b>
                    <span className="ua-hint num">{utc(a.time)}</span>
                  </div>
                  <div className="pv-chips">{a.entities.map((e) => <Chip key={`${e.kind}|${e.value}`} e={e} />)}</div>
                </li>
              ))}
            </ul>}
    </Panel>
  );
}

function Family({ r }: { r: PivotResult }) {
  if (!r.processes.length && !r.parents.length) return null;
  const runs = r.processes.length ? r.processes : [];
  return (
    <Panel title={TEXT.family} hint={TEXT.familyHint}>
      <ul className="pv-list">
        {runs.map((p) => {
          const ups = r.parents.filter((x) => (x as Proc & { child?: string }).child === p.guid);
          const downs = r.children.filter((x) => (x as Proc & { parent?: string }).parent === p.guid);
          return (
            <li key={p.guid} className="pv-run">
              {ups.map((u) => (
                <div key={u.guid} className="pv-up"><span className="ua-hint">{TEXT.parentOf}</span>
                  <Chip e={{ kind: "process", value: u.guid, role: u.label }} /></div>
              ))}
              <div className="pv-self"><Chip e={{ kind: "process", value: p.guid, role: p.label }} current={r.kind === "process" && r.value === p.guid} />
                {p.image && <Chip e={{ kind: "program", value: p.image }} />}
                <span className="ua-hint num">{utc(p.first)}</span></div>
              {downs.length > 0 && (
                <div className="pv-down"><span className="ua-hint">{TEXT.childOf}</span>
                  {downs.map((d) => <Chip key={d.guid} e={{ kind: "process", value: d.guid, role: d.label }} />)}
                  </div>
              )}
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

/** The same pivot address with the test machinery shown or hidden. */
function machineryHref(show: boolean): string {
  const q = new URLSearchParams(rawQuery(window.location.hash));
  if (show) q.set("machinery", "1"); else q.delete("machinery");
  return `#/labs/pivot?${q.toString()}`;
}

function Result({ kind, value, host, machinery, words }: { kind: string; value: string; host: string | null; machinery: boolean; words: Record<string, string> }) {
  const [allAlerts, setAllAlerts] = useState(false);
  const r = useJson<PivotResult>(`/api/labs/pivot?kind=${encodeURIComponent(kind)}&value=${encodeURIComponent(value)}${host ? `&host=${encodeURIComponent(host)}` : ""}${machinery ? "&machinery=true" : ""}`);
  if (r.error) return <p className="lab-state" data-kind="error" role="alert">{r.error}</p>;
  if (r.loading || !r.data) return <p className="lab-state" data-kind="loading">{TEXT.loading}</p>;
  const d = r.data;
  const Icon = ICON[d.kind] ?? Crosshair;
  const groups = groupByKind(d.linked);
  return (
    <>
      <section className="ua-panel pv-panel pv-subject">
        <div className="pv-subject-head">
          <i><Icon size={20} /></i>
          <div>
            <span className="ua-hint">{d.kind_word}</span>
            <h2 className="pv-value">{d.value}</h2>
          </div>
          <span className="cs-grow" />
          <PlusCase kind={d.kind} value={d.value} label={d.value} time={d.first} text="Pin to case" />
        </div>
        <div className="lab-numbers">
          <div className="lab-number"><b>{d.total.toLocaleString("en-US")}</b><span>{TEXT.events}</span></div>
          <div className="lab-number"><b>{d.processes.length}</b><span>{TEXT.runs}</span></div>
          <div className="lab-number"><b>{d.linked.length}</b><span>{TEXT.linkedN}</span></div>
          <div className="lab-number"><b>{d.alerts_total.toLocaleString("en-US")}</b><span>{TEXT.alertsN}</span></div>
        </div>
        {d.first && <p className="ua-hint num">{TEXT.span} {utc(d.first)} {TEXT.to} {utc(d.last)}</p>}
        {d.words && (d.machinery_hidden ?? 0) > 0 && (
          <p className="ua-hint">{d.words.machinery_hidden.replace("{n}", String(d.machinery_hidden))}{" "}
            <a className="cs-link" href={machineryHref(true)}>{d.words.machinery_switch}</a></p>
        )}
        {machinery && d.words && <p className="ua-hint"><a className="cs-link" href={machineryHref(false)}>{TEXT.hideMachinery}</a></p>}
      </section>
      {d.total === 0 ? <p className="lab-state" data-kind="empty">{TEXT.nothing(d.kind_word)}</p> : (
        <div className="pv-grid">
          <Panel title={TEXT.timeline} hint={TEXT.timelineHint} className="pv-timeline">
            {d.shown < d.total && <p className="ua-hint">{TEXT.more(d.shown, d.total)}</p>}
            <ol className="pv-events">
              {d.events.map((e) => (
                <li key={e.key}>
                  <span className="pv-time num">{utc(e.time)}</span>
                  <div>
                    <p className="pv-sum">{e.summary}<PlusCase event={e.key} label={e.summary} time={e.time} host={e.host} /></p>
                    {e.command_line && <p className="pv-cmd" title={TEXT.cmd}>{e.command_line}</p>}
                    <div className="pv-chips">{e.entities.filter((x) => x.kind !== "process").map((x) => (
                      <Chip key={`${x.kind}|${x.value}`} e={x} current={x.kind === d.kind && x.value.toLowerCase() === d.value.toLowerCase()} />
                    ))}</div>
                  </div>
                </li>
              ))}
            </ol>
          </Panel>
          <div className="pv-side">
            <Panel title={`${TEXT.alerts} (${d.alerts_total})`}>
              {d.alerts.length === 0 ? <p className="ua-hint">{TEXT.noAlerts}</p> : (<>
                <ul className="pv-list">{(allAlerts ? d.alerts : d.alerts.slice(0, FEW)).map((a) => (
                  <li key={a.id} className="pv-alert">
                    <span className="ua-tag pv-level" data-level={a.level}>{a.level}</span>
                    <div><b>{a.title}</b><p className="ua-hint">{a.why} · <span className="num">{utc(a.time)}</span></p></div>
                    <span className="pv-alert-acts"><PlusCase alert={a.id} label={a.title} time={a.time} />
                      <a className="pv-open" href={`#a/story/${encodeURIComponent(a.id)}`} title={TEXT.open}><ArrowRight size={15} /></a></span>
                  </li>
                ))}</ul>
                {d.alerts.length > FEW && (
                  <button className="ua-btn cs-small" type="button" onClick={() => setAllAlerts((x) => !x)}>
                    {allAlerts ? TEXT.showFew : TEXT.showAll(d.alerts.length)}</button>
                )}
                {allAlerts && d.alerts_total > d.alerts.length && <p className="ua-hint">{TEXT.alertsCut(d.alerts.length, d.alerts_total)}</p>}
              </>)}
            </Panel>
            <Family r={d} />
            {groups.length > 0 && (
              <Panel title={TEXT.linked}>
                {groups.map(([k, items]) => (
                  <div key={k} className="pv-group">
                    <span className="ua-hint">{words[k] ?? k}</span>
                    <div className="pv-chips">{items.map((e) => <Chip key={`${e.kind}|${e.value}`} e={e} />)}</div>
                  </div>
                ))}
              </Panel>
            )}
            {d.gaps.length > 0 && (
              <Panel title={TEXT.gaps} className="pv-gaps">
                <ul className="pv-list">{d.gaps.map((g) => <li key={g.key}><b>{g.what}</b><p className="ua-hint">{g.why}</p></li>)}</ul>
              </Panel>
            )}
          </div>
        </div>
      )}
    </>
  );
}

function PivotLab(_: LabProps) {
  // read from the address itself, decoded once (a path may hold & + % =); the shell re-renders on every change
  const params = new URLSearchParams(rawQuery(window.location.hash));
  const kind = kindFrom(params);
  const value = params.get("value");
  const host = params.get("host");
  const machinery = params.get("machinery") === "1";
  const alert = params.get("alert");                   // opened from an alert's page: the strip leads back
  const kinds = useJson<KindRow[]>("/api/labs/pivot/kinds");
  const [trail, setTrail] = useState<Entity[]>(() => loadTrail());
  useEffect(() => {
    if (!kind || !value) return;
    setTrail((t) => { const n = nextTrail(t, { kind: kind as Kind, value }); saveTrail(n); return n; });
  }, [kind, value]);
  return (
    <div className="pv-page">
      {alert && <NextStrip current="pivot" alert={alert} />}
      <Finder kinds={kinds.data ?? []} />
      {trail.length > 1 && (
        <div className="pv-trail"><span className="ua-hint">{TEXT.trail}</span>
          {trail.map((e, i) => (
            <span key={`${e.kind}|${e.value}`} className="pv-trail-step">{i > 0 && <ArrowRight size={12} className="pv-dim" />}
              <Chip e={e} current={e.kind === kind && e.value.toLowerCase() === (value ?? "").toLowerCase()} /></span>
          ))}
        </div>
      )}
      {kind && value ? <Result key={`${kind}|${value}|${host ?? ""}|${machinery}`} kind={kind} value={value} host={host} machinery={machinery} words={Object.fromEntries((kinds.data ?? []).map((k) => [k.kind, k.word]))} /> : <Starts />}
    </div>
  );
}

export const lab: Lab = {
  id: "pivot",
  title: "Pivot on anything",
  blurb: "Pick a program, file, fingerprint, address, domain, registry key or user and see every recorded event, run and alert linked to it.",
  icon: Crosshair,
  Component: PivotLab,
};
