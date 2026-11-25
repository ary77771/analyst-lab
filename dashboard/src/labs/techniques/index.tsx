// Lab "ATT&CK map" (engine/labs/techniques.py): MITRE's matrix, tactics as columns, lit by the techniques our
// alerts' rules name in their tags, or by what our loaded rules can see at all. Words come from Python.
import { Grid3x3 } from "lucide-react";
import { LabNumber, LabPanel, LabState, useLab } from "../kit";
import { labHref, type Lab, type LabProps } from "../registry";
import { fill } from "../_explain/logic";
import { Level } from "../_explain/shared";
import "./techniques.css";

type W = Record<string, string>;
interface Sub { id: string; name: string; alerts: number; rules: number; rules_floor: number }
interface Cell extends Sub { subs: Sub[] }
interface Tactic { id: string; shortname: string; name: string; techniques: Cell[] }
interface Info { available: boolean; version: string | null; techniques: number; legal: string }
export interface MapData {
  words: W; attack: Info; min_level: string; levels?: string; tactics?: Tactic[];
  totals?: Record<string, number>; untagged?: { rule_id: string; title: string; source: string; alerts: number }[];
  unknown_tags?: { tag: string; note: string }[];
}
interface Detail {
  words: W; attack: Info;
  technique: { id: string; asked: string; note: string | null; name: string; full_name: string; url: string; description: string;
    tactics: { id: string; name: string }[]; platforms: string[]; parent: { id: string; name: string } | null; subs: { id: string; name: string }[] };
  alerts: { id: string; title: string; level: string; time: string; rule_id: string; techniques: string[] }[];
  rules: { id: string; title: string; level: string; source: string; raises: boolean }[]; rules_total: number;
}
export type Mode = "alerts" | "coverage";

/** How many a cell counts in this mode. */
export function countOf(c: Sub, mode: Mode, floorOnly: boolean): number {
  return mode === "alerts" ? c.alerts : floorOnly ? c.rules_floor : c.rules;
}

/** 0 (dark) .. 4 (brightest): a log scale, so one alert still shows and hundreds don't drown the rest. */
export function heat(n: number, max: number): number {
  if (n <= 0) return 0;
  if (max <= 1) return 4;
  return Math.max(1, Math.min(4, Math.ceil((Math.log(n + 1) / Math.log(max + 1)) * 4)));
}

/** The lit techniques once each (a technique sits under several goals), most alerts first: the calm first screen. */
export function litTechniques(d: MapData): { id: string; name: string; n: number; tactics: string[] }[] {
  const by = new Map<string, { id: string; name: string; n: number; tactics: string[] }>();
  for (const t of d.tactics ?? []) for (const c of t.techniques) {
    if (c.alerts <= 0) continue;
    const x = by.get(c.id) ?? { id: c.id, name: c.name, n: c.alerts, tactics: [] };
    x.tactics.push(t.name);
    by.set(c.id, x);
  }
  return [...by.values()].sort((a, b) => b.n - a.n || a.id.localeCompare(b.id));
}

export function CalmSummary({ d, p }: { d: MapData; p: URLSearchParams }) {
  const w = d.words;
  const lit = litTechniques(d);
  return (
    <LabPanel title={w.calm_title ?? "What the alerts here point to"} hint={w.calm_intro}>
      {lit.length === 0 ? <p className="xp-small xp-muted">{w.calm_none}</p> : (
        <ul className="tq-lit">{lit.map((t) => (
          <li key={t.id}><a href={params(p, { technique: t.id })}>
            <code className="xp-chip">{t.id}</code><b>{t.name}</b>
            <span className="xp-small xp-dim">{t.tactics.join(", ")}</span><span className="xp-grow" />
            <span className="xp-small xp-muted">{t.n === 1 ? (w.calm_one ?? "1 alert") : fill(w.calm_many ?? "{n} alerts", { n: t.n })}</span></a></li>))}</ul>)}
      {lit.length && d.totals?.alerts_reading ? <p className="xp-small xp-dim">{w.calm_reading}</p> : null}
    </LabPanel>
  );
}

function params(p: URLSearchParams, change: Record<string, string | null>) {
  const out: Record<string, string | null> = {};
  p.forEach((v, k) => { out[k] = v; });
  return labHref("techniques", { ...out, ...change });
}

export function Matrix({ d, mode, floorOnly, onlyLit, selected, p }: { d: MapData; mode: Mode; floorOnly: boolean; onlyLit: boolean; selected: string | null; p: URLSearchParams }) {
  // with "only lit", a goal (column) with nothing lit is left out too, so the lit boxes are in view
  const tactics = (d.tactics ?? []).filter((t) => !onlyLit || t.techniques.some((c) => countOf(c, mode, floorOnly) > 0));
  const max = Math.max(1, ...tactics.flatMap((t) => t.techniques.map((c) => countOf(c, mode, floorOnly))));
  return (
    <div className="tq-matrix" data-mode={mode}>
      {tactics.map((t) => {
        const cells = t.techniques.filter((c) => !onlyLit || countOf(c, mode, floorOnly) > 0);
        const lit = t.techniques.filter((c) => countOf(c, mode, floorOnly) > 0).length;
        return (
          <div key={t.id} className="tq-col">
            <header className="tq-head"><b>{t.name}</b><span className="xp-mono">{t.id} · {lit}/{t.techniques.length}</span></header>
            {cells.map((c) => {
              const n = countOf(c, mode, floorOnly);
              const sel = selected !== null && (selected === c.id || selected.startsWith(c.id + "."));
              return (
                <a key={c.id} className="tq-cell" data-heat={heat(n, max)} aria-current={sel ? "true" : undefined}
                  href={params(p, { technique: c.id })} title={`${c.id} ${c.name}`}>
                  <span className="tq-name">{c.name}</span>
                  <span className="tq-meta xp-mono">{c.id}{c.subs.length ? ` +${c.subs.filter((s) => countOf(s, mode, floorOnly) > 0).length}/${c.subs.length}` : ""}</span>
                  {n > 0 ? <b className="tq-n xp-mono">{n}</b> : null}
                </a>
              );
            })}
          </div>
        );
      })}
    </div>
  );
}

function DetailPanel({ id, p, all }: { id: string; p: URLSearchParams; all: boolean }) {
  const { data: d, error, loading } = useLab<Detail>(`/api/labs/techniques/${encodeURIComponent(id)}${all ? "?levels=all" : ""}`);
  return (
    <LabState loading={loading} error={error}>
      {d && (
        <section className="ua-panel lab-panel tq-detail">
          <div className="xp-row">
            <code className="xp-chip">{d.technique.id}</code><h2 className="xp-title">{d.technique.full_name}</h2><span className="xp-grow" />
            <a className="xp-link" href={d.technique.url} target="_blank" rel="noreferrer">{d.words.open_mitre}</a>
            <a className="xp-link" href={params(p, { technique: null })}>×</a>
          </div>
          {d.technique.note ? <p className="xp-small xp-ink-gap">{fill(d.words.revoked_note, { old: d.technique.asked, new: d.technique.id })}</p> : null}
          <p className="xp-row xp-small xp-dim">{d.technique.tactics.map((t) => <span key={t.id}>{t.name} ({t.id})</span>)}<span>{d.technique.platforms.join(", ")}</span></p>
          <p className="xp-text tq-desc">{d.technique.description}</p>
          {d.technique.parent ? <p className="xp-small"><a className="xp-chip" href={params(p, { technique: d.technique.parent.id })}>{d.technique.parent.id} {d.technique.parent.name}</a></p> : null}
          {d.technique.subs.length ? <p className="xp-row xp-small"><span className="xp-dim">{d.words.subs}</span>{d.technique.subs.map((s) => (
            <a key={s.id} className="xp-chip" href={params(p, { technique: s.id })}>{s.id} <span className="xp-muted">{s.name}</span></a>))}</p> : null}
          <div className="xp-sep">
            <h3 className="xp-sub">{d.words.detail_alerts} ({d.alerts.length})</h3>
            {d.alerts.length === 0 ? <p className="xp-small xp-muted">{d.words.detail_none}</p> : (
              <ul className="xp-pick">{d.alerts.slice(0, 40).map((a) => (
                <li key={a.id} className="tq-alert"><a href={labHref("why", { alert: a.id })}><Level level={a.level} /><span className="xp-grow">{a.title}</span>
                  <span className="xp-small xp-dim xp-mono">{a.techniques.join(" ")} · {a.time}</span></a>
                  <a className="xp-link" href={labHref("respond", { alert: a.id })}>{d.words.open_next}</a></li>))}</ul>)}
          </div>
          <div className="xp-sep">
            <h3 className="xp-sub">{d.words.detail_rules} ({d.rules_total})</h3>
            <ul className="tq-rules">{d.rules.map((r) => (
              <li key={r.id} data-raises={r.raises}><Level level={r.level} /><span>{r.title}</span><span className="xp-dim xp-small">{r.source}</span></li>))}</ul>
            {d.rules_total > d.rules.length ? <p className="xp-small xp-dim">{fill(d.words.detail_rules_more, { shown: d.rules.length, total: d.rules_total })}</p> : null}
          </div>
        </section>)}
    </LabState>
  );
}

function TechniquesLab({ params: p }: LabProps) {
  const mode: Mode = p.get("mode") === "coverage" ? "coverage" : "alerts";
  // Alerts mode shows only the lit boxes unless asked (a matrix of 200 dark boxes hides the one that matters)
  const onlyLit = p.get("lit") ? p.get("lit") === "1" : mode === "alerts";
  const floorOnly = p.get("floor") !== "0";
  const selected = p.get("technique");
  const all = p.get("all") === "1";
  const { data: d, error, loading } = useLab<MapData>(`/api/labs/techniques${all ? "?levels=all" : ""}`);
  return (
    <LabState loading={loading} error={error}>
      {d && !d.attack.available ? <p className="lab-state" data-kind="empty">{d.words.no_data}</p> : null}
      {d && d.attack.available && d.totals && (
        <>
          {mode === "alerts" ? <CalmSummary d={d} p={p} /> : null}
          {selected ? <DetailPanel id={selected} p={p} all={all} /> : null}
          <details className="tq-full" open={mode === "coverage" || ["lit", "all", "floor"].some((k) => p.has(k))}>
          <summary className="xp-small xp-dim">{d.words.show_matrix ?? "Show the full matrix and its settings"}</summary>
          <LabPanel title={fill(d.words.version, { version: d.attack.version ?? "?" })} hint={d.words.intro}>
            <div className="xp-row">
              <div className="tq-toggle" role="group">
                <a aria-pressed={mode === "alerts"} href={params(p, { mode: null })}>{d.words.mode_alerts}</a>
                <a aria-pressed={mode === "coverage"} href={params(p, { mode: "coverage" })}>{d.words.mode_coverage}</a>
              </div>
              <a className="tq-check" aria-pressed={onlyLit} href={params(p, { lit: onlyLit ? "0" : "1" })}><i />{d.words.only_lit}</a>
              {mode === "alerts" ? <a className="tq-check" aria-pressed={all} href={params(p, { all: all ? null : "1" })}><i />{fill(d.words.all_levels, { min_level: d.min_level })}</a> : null}
              {mode === "coverage" ? <a className="tq-check" aria-pressed={floorOnly} href={params(p, { floor: floorOnly ? "0" : null })}><i />{fill(d.words.floor_only, { min_level: d.min_level })}</a> : null}
            </div>
            <p className="ua-hint">{mode === "alerts" ? d.words.mode_alerts_hint : d.words.mode_coverage_hint}</p>
            {mode === "alerts" && all ? <p className="ua-hint">{d.words.all_levels_hint}</p> : null}
            {mode === "alerts" && !all && d.totals.alerts_tagged === 0 ? <p className="xp-note">{d.words.empty_hint}</p> : null}
            <div className="lab-numbers">
              {mode === "alerts" ? <>
                <LabNumber value={d.totals.alerts_tagged} label={d.words.alerts_tagged} />
                <LabNumber value={d.totals.alerts_untagged} label={d.words.alerts_untagged} />
                {d.totals.alerts_reading ? <LabNumber value={d.totals.alerts_reading} label={d.words.alerts_reading} title={d.words.reading_note} /> : null}
                <LabNumber value={`${d.totals.techniques_hit} / ${d.totals.techniques_total}`} label={d.words.techniques_hit} />
              </> : <>
                <LabNumber value={`${floorOnly ? d.totals.techniques_covered_floor : d.totals.techniques_covered} / ${d.totals.techniques_total}`} label={d.words.techniques_covered} />
                <LabNumber value={d.totals.rules_ours} label={d.words.rules_ours} />
              </>}
            </div>
          </LabPanel>
          <section className="ua-panel lab-panel"><Matrix d={d} mode={mode} floorOnly={floorOnly} onlyLit={onlyLit} selected={selected} p={p} /></section>
          {mode === "alerts" && d.untagged && d.untagged.length > 0 ? (
            <LabPanel title={d.words.untagged_title} hint={d.words.untagged_note}>
              <ul className="tq-rules">{d.untagged.map((u) => (
                <li key={u.rule_id}><b className="xp-mono">{u.alerts}</b><span>{u.title}</span><span className="xp-dim xp-small xp-mono">{u.rule_id}</span></li>))}</ul>
            </LabPanel>) : null}
          {d.unknown_tags && d.unknown_tags.length > 0 ? (
            <LabPanel title={d.words.unknown_tags_title}><p className="xp-row">{d.unknown_tags.map((u) => <code key={u.tag} className="xp-chip">{u.tag} · {u.note}</code>)}</p></LabPanel>) : null}
          </details>
          <p className="ua-hint">{d.words.legal}</p>
        </>)}
    </LabState>
  );
}

export const lab: Lab = {
  id: "techniques",
  title: "ATT&CK map",
  blurb: "MITRE's matrix of intruder techniques, lit by our alerts, and what our rules can see at all.",
  icon: Grid3x3,
  group: "tool",
  Component: TechniquesLab,
};
