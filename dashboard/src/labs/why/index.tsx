// Lab "Why is this suspicious?" (engine/labs/why.py): one alert's rule, the event fields that matched it,
// and its steps in the evidence graph. Every sentence comes from Python (`words`); this file only places it.
import { ShieldQuestion } from "lucide-react";
import { useEffect, useState } from "react";
import { LabPanel, LabState, NextStrip, useAlertParam, useLab } from "../kit";
import { PlusCase } from "../_things";            // one click to the case board (night-pivot)
import { labHref, type Lab, type LabProps } from "../registry";
import { Thing } from "../_things/Thing";
import { WordGrid, type WordData } from "../_explain/wordforword";
import { fill } from "../_explain/logic";
import { AlertPicker, HarnessSwitch, Ids, Level, Marked, type AlertRow } from "../_explain/shared";

type Tri = boolean | null;
export type Ink = "fact" | "hypothesis" | "gap";
type W = Record<string, string> & { inks: Record<Ink, string>; ink_explain: Record<Ink, string> };

interface Item { field: string | null; modifiers: string[]; words: string[]; values: string[]; match: "any" | "all"; negated: boolean;
  value?: string | null; present?: boolean; matched?: Tri; spans?: number[][]; matched_values?: string[] }
interface Selection { name: string; matched?: Tri; groups: (Item | null)[][]; group_linking: "any" | "all"; filter: boolean }
interface Technique { id: string; name: string | null; reading?: boolean }
interface RuleInfo {
  found: boolean; kind: "sigma" | "correlation" | "python" | "beacon" | "missing"; title: string; id?: string | null;
  description?: string; level?: string | null; status?: string | null; author?: string; date?: string | null; modified?: string | null;
  references?: string[]; falsepositives?: string[]; tags?: string[]; techniques?: Technique[]; file?: string | null;
  logsource?: { category: string; product: string; event_ids: number[] }; condition?: string[]; selections?: Selection[];
  correlation?: { type: string; group_by: string[]; timespan: string; condition: { op: string | null; count: number | null; field: string | null }; rules: RuleInfo[] };
  doc?: string; function?: string | null; settings?: Record<string, unknown>; details?: Record<string, unknown>;
}
interface EventX { key: string; kind: "recorded" | "declared"; missing: boolean; event_id: number | null; time: string | null; matched: Tri;
  base_rule: string | null; selections: Selection[]; matched_fields: string[]; highlights: Record<string, number[][]>; fields: [string, string | number][] }
interface StoryRow { ink: Ink | null; text: string; short?: string; time?: string | null; offset?: string | null; in_chain: boolean; placement?: string; harness?: string | null; machinery?: string | null }
export interface Why {
  words: W; alert: AlertRow; rule: RuleInfo; events: EventX[]; events_total: number;
  check: "reproduced" | "not_reproduced" | "not_checked" | "na"; partly_checked: boolean;
  wordforword?: WordData | null; noise?: { text: string; measured: boolean } | null;
  story: { available: boolean; problem?: string; counts?: Record<string, number>; summary?: string; rows?: StoryRow[]; limitations?: string[] };
}

const v3 = (m: Tri | undefined) => (m === true ? "yes" : m === false ? "no" : "unknown");

function Verdict({ m, w }: { m: Tri | undefined; w: W }) {
  return <span className="xp-verdict" data-v={v3(m)}>{m === true ? w.selection_held : m === false ? w.selection_failed : w.selection_unknown}</span>;
}

function ItemLine({ it, evaluated }: { it: Item; evaluated: boolean }) {
  return (
    <li className="xp-item" data-v={evaluated ? v3(it.matched) : undefined}>
      <div className="xp-item-head">
        <span className="xp-mark">{!evaluated ? "·" : it.matched === true ? "✓" : it.matched === false ? "✗" : "?"}</span>
        <span className="xp-field">{it.field ?? "*"}</span>
        {it.words.map((x) => <span key={x} className="xp-word">{x}</span>)}
        {it.values.map((v, i) => <code key={i} className="xp-val" data-hit={evaluated && !!it.matched_values?.includes(v)}>{v}</code>)}
      </div>
      {evaluated && it.value ? <div className="xp-item-value"><Marked value={it.value} spans={it.matched ? it.spans : []} /></div> : null}
    </li>
  );
}

function SelectionBox({ s, w, evaluated }: { s: Selection; w: W; evaluated: boolean }) {
  return (
    <div className="xp-sel" data-filter={s.filter} data-v={evaluated ? v3(s.matched) : undefined}>
      <div className="xp-row">
        <span className="xp-sel-name">{s.name}</span>
        {evaluated ? <Verdict m={s.matched} w={w} /> : null}
        {s.filter ? <span className="xp-small xp-dim">{w.filter_note}</span> : null}
        {s.groups.length > 1 ? <span className="xp-small xp-dim">{w.any_of}</span> : null}
      </div>
      {s.groups.map((g, gi) => (
        <ul key={gi} className={s.groups.length > 1 ? "xp-group" : ""}>
          {g.map((it, i) => (it ? <ItemLine key={i} it={it} evaluated={evaluated} /> : null))}
        </ul>
      ))}
    </div>
  );
}

function KeyValues({ obj }: { obj: Record<string, unknown> }) {
  const entries = Object.entries(obj).filter(([, v]) => v !== null && v !== undefined && v !== "");
  if (!entries.length) return null;
  return (
    <table className="xp-table"><tbody>{entries.map(([k, v]) => (
      <tr key={k}><td className="xp-k">{k}</td><td className="xp-v">{typeof v === "object" ? JSON.stringify(v) : String(v)}</td></tr>
    ))}</tbody></table>
  );
}

function Logic({ d, ev }: { d: Why; ev: EventX | undefined }) {
  const w = d.words, r = d.rule;
  if (r.kind === "correlation" && r.correlation) {
    const c = r.correlation;
    return (
      <div className="xp-sep">
        <h3 className="xp-sub">{w.logic_title}</h3>
        <p className="xp-row"><code className="xp-cond">{[c.type, c.group_by.join(", "), c.timespan,
          c.condition.op ? `${c.condition.op.toLowerCase()} ${c.condition.count ?? ""}${c.condition.field ? ` (${c.condition.field})` : ""}` : ""].filter(Boolean).join(" · ")}</code></p>
        {c.rules.map((b) => {
          const mine = !!ev && ev.base_rule === b.title;
          return (
            <div key={b.title} className="xp-sep">
              <p className="xp-small xp-muted">{b.title}{b.condition?.length ? <> · <code className="xp-mono">{b.condition.join(" / ")}</code></> : null}</p>
              <div className="xp-sels">{(mine ? ev!.selections : b.selections ?? []).map((s) => <SelectionBox key={s.name} s={s} w={w} evaluated={mine} />)}</div>
            </div>
          );
        })}
      </div>
    );
  }
  const evaluated = !!ev && ev.selections.length > 0;
  const sels = evaluated ? ev!.selections : r.selections ?? [];
  return (
    <div className="xp-sep">
      <h3 className="xp-sub">{w.logic_title}</h3>
      {r.logsource ? <p className="xp-small xp-muted">{r.logsource.category} · {w.sysmon_event} {r.logsource.event_ids.join(", ")}</p> : null}
      <p className="xp-row"><span className="xp-small xp-dim">{w.condition}</span>{(r.condition ?? []).map((c) => <code key={c} className="xp-cond">{c}</code>)}</p>
      <div className="xp-sels">{sels.map((s) => <SelectionBox key={s.name} s={s} w={w} evaluated={evaluated} />)}</div>
    </div>
  );
}

function RulePanel({ d, ev }: { d: Why; ev: EventX | undefined }) {
  const w = d.words, r = d.rule;
  if (!r.found || r.kind === "missing") {
    return <LabPanel title={w.rule_title}><p className="xp-text">{w.rule_missing}</p></LabPanel>;
  }
  if (r.kind === "python" || r.kind === "beacon") {
    return (
      <LabPanel title={w.rule_title}>
        <p className="xp-title">{r.title}</p>
        <p className="xp-small xp-muted">{r.kind === "beacon" ? w.beacon_rule : w.python_rule}{r.function ? <> <code className="xp-mono">{r.function}</code></> : null}</p>
        {r.techniques?.length ? <p className="xp-row xp-small"><span className="xp-dim">{w.reading}</span>
          {r.techniques.map((t) => <a key={t.id} className="xp-chip" href={labHref("techniques", { technique: t.id })}>{t.id}{t.name ? <span className="xp-muted">{t.name}</span> : null}</a>)}</p> : null}
        {r.doc ? <details className="xp-details"><summary>{w.how_rule}</summary><pre className="xp-pre">{r.doc}</pre></details> : null}
        <details className="xp-details"><summary>{w.rule_settings}</summary><KeyValues obj={{ ...(r.settings ?? {}), ...(r.details ?? {}) }} /></details>
      </LabPanel>
    );
  }
  // rule tags that are not ATT&CK techniques (e.g. tactic names) are internal codes: behind the details toggle
  const otherTags = (r.tags ?? []).filter((t) => !(r.techniques ?? []).some((x) => t.toLowerCase().endsWith(x.id.toLowerCase())));
  const ids = [r.id, r.file, ...otherTags].filter((x): x is string => !!x);
  return (
    <LabPanel title={w.rule_title}>
      <div className="xp-row"><p className="xp-title">{r.title}</p>{r.level ? <Level level={r.level} /> : null}
        {r.status ? <span className="xp-small xp-dim">{r.status}</span> : null}<span className="xp-grow" />
</div>
      {r.description ? <p className="xp-text">{r.description}</p> : null}
      <div className="xp-row xp-small">
        {r.author ? <span className="xp-dim">{r.author}{r.date ? ` · ${r.date}` : ""}{r.modified ? ` · ${r.modified}` : ""}</span> : null}
        <span className="xp-grow" />
        {(r.techniques ?? []).map((t) => (
          <a key={t.id} className="xp-chip" href={labHref("techniques", { technique: t.id })} title={t.name ?? t.id}>{t.id}{t.name ? <span className="xp-muted">{t.name}</span> : null}</a>))}
        {ids.length ? <Ids label={w.details}>{ids.join(" · ")}</Ids> : null}
      </div>
      {r.falsepositives?.length ? <div><p className="xp-small xp-dim">{w.falsepositives}</p><ul className="xp-list">{r.falsepositives.map((x) => <li key={x}>{x}</li>)}</ul></div> : null}
      {r.references?.length ? <div><p className="xp-small xp-dim">{w.references}</p><ul className="xp-list xp-mono">{r.references.map((x) => <li key={x}>{x}</li>)}</ul></div> : null}
      <Logic d={d} ev={ev} />
    </LabPanel>
  );
}

const PLAIN_SHOWN = 0;               // our own rules match no single field: the record folds away behind "all fields"
/** The fields of a record worth opening in Pivot, in reading order. */
const PIVOT_FIELDS = ["Image", "ParentImage", "TargetFilename", "DestinationIp", "DestinationHostname", "QueryName", "TargetObject", "User", "sha256"];

function EventsPanel({ d, pick, setPick }: { d: Why; pick: number; setPick: (i: number) => void }) {
  const w = d.words, ev = d.events[pick];
  if (!ev) return null;
  const isHit = (f: string) => f in ev.highlights || ev.matched_fields.includes(f);
  // a Python or beacon rule, or a rule file not on this laptop: nothing is "matched", so the usual fields are
  // shown open under a neutral title instead of an empty "matched" table
  const plain = !ev.fields.some(([f]) => isHit(f));
  const matched = plain ? ev.fields.slice(0, PLAIN_SHOWN) : ev.fields.filter(([f]) => isHit(f));
  const rest = plain ? ev.fields.slice(PLAIN_SHOWN) : ev.fields.filter(([f]) => !isHit(f));
  return (
    <LabPanel title={plain ? w.events_title_plain : w.events_title} hint={d.events_total > d.events.length ? fill(w.more_events, { shown: d.events.length, total: d.events_total }) : undefined}>
      {ev.kind === "declared" ? <p className="xp-note" data-kind="declared">{w.declared_note}</p> : null}
      {d.check === "not_reproduced" ? <p className="xp-note" data-kind="warn">{w.not_reproduced}</p> : null}
      {d.partly_checked ? <p className="xp-small xp-ink-gap">{w.partly_checked}</p> : null}
      {d.events.length > 1 ? (
        <div className="xp-tabs">{d.events.map((e, i) => (
          <button key={e.key} className="xp-tab" aria-pressed={i === pick} onClick={() => setPick(i)}>{i + 1}{e.matched ? " ✓" : ""}</button>))}</div>) : null}
      <div className="xp-row"><p className="xp-small xp-dim xp-mono">{w.sysmon_event} {ev.event_id ?? "?"} · {ev.time}{ev.base_rule ? ` · ${ev.base_rule}` : ""}</p>
        <span className="xp-grow" />{!ev.missing ? <a className="xp-link" href={labHref("moment", { event: ev.key })}>{w.open_moment}</a> : null}</div>
      {(() => {
        const things = PIVOT_FIELDS.map((f) => ev.fields.find(([k]) => k === f)).filter((x): x is [string, string | number] => !!x && !["", "-"].includes(String(x[1]).trim()));
        return things.length ? <div className="xp-row xp-things"><span className="xp-small xp-dim">{w.things}</span>
          {things.map(([f, v]) => <Thing key={f} field={f} value={v} role={f} host={d.alert.host} />)}</div> : null;
      })()}
      {matched.length ? <table className="xp-table"><tbody>{matched.map(([f, v]) => (
        <tr key={f} data-hit={!plain}><td className="xp-k">{f}</td><td className="xp-v"><Marked value={String(v)} spans={ev.highlights[f]} /></td></tr>))}
      </tbody></table> : null}
      {rest.length ? (
        <details className="xp-details"><summary>{plain ? w.all_fields : w.other_fields} ({rest.length})</summary>
          <table className="xp-table"><tbody>{rest.map(([f, v]) => (
            <tr key={f}><td className="xp-k">{f}</td><td className="xp-v xp-muted">{String(v)}</td></tr>))}</tbody></table>
        </details>) : null}
    </LabPanel>
  );
}

export function Steps({ rows, w }: { rows: StoryRow[]; w: { inks: Record<Ink, string> } }) {
  return (
    <ol className="xp-steps">{rows.map((r, i) => {
      const ink = (r.ink ?? "gap") as Ink;
      return (
        <li key={i} className="xp-step" data-ink={ink} data-chain={r.in_chain}>
          <b className={`xp-ink-${ink}`}>{w.inks[ink]}</b><span>{r.text}{r.machinery ? <span className="xp-machinery">{r.machinery}</span> : null}</span><span className="xp-small xp-dim xp-mono">{r.offset ?? ""}</span>
        </li>);
    })}</ol>
  );
}

function StoryPanel({ d, showHarness, setShowHarness }: { d: Why; showHarness: boolean; setShowHarness: (v: boolean) => void }) {
  const w = d.words, s = d.story;
  const all = s.rows ?? [];
  const rows = showHarness ? all : all.filter((r) => !r.harness);
  return (
    <LabPanel title={w.story_title} hint={w.story_note}>
      {!s.available ? <p className="xp-text">{w.no_story}</p> : (
        <>
          <div className="xp-inks">{(["fact", "hypothesis", "gap"] as Ink[]).map((k) => (
            <span key={k} className={`xp-ink-${k}`}><b>{w.inks[k]}</b> <span className="xp-dim">· {w.ink_explain[k]}</span></span>))}</div>
          <HarnessSwitch hidden={all.filter((r) => r.harness).length} on={showHarness} set={setShowHarness} w={w} />
          <Steps rows={rows} w={w} />
        </>)}
    </LabPanel>
  );
}

/** The whole explanation of one alert (no fetching: tests render it from a fixture). */
export function WhyView({ d }: { d: Why }) {
  const first = Math.max(0, d.events.findIndex((e) => e.matched));
  const [pick, setPick] = useState(first);
  useEffect(() => setPick(first), [d, first]);
  const ev = d.events[pick];
  const w = d.words;
  const [showHarness, setShowHarness] = useState(false);
  const ww = d.wordforword ? { ...d.wordforword, lines: showHarness ? d.wordforword.lines : d.wordforword.lines.filter((l) => !l.harness) } : null;
  const wwHidden = d.wordforword ? d.wordforword.lines.filter((l) => l.harness).length : 0;
  return (
    <>
      <section className="ua-panel lab-panel" data-alert={d.alert.id}>
        <div className="xp-row">
          <Level level={d.alert.level} /><h2 className="xp-title">{d.alert.title}</h2>
          <span className="xp-small xp-dim xp-mono">{d.alert.time}</span><span className="xp-grow" />
          <PlusCase alert={d.alert.id} label={d.alert.title} time={d.alert.time} text="Pin to case" />
        </div>
        <p className="xp-text"><span className="xp-dim">{w.reason}: </span>{d.alert.reason}</p>
        {d.noise ? <p className="xp-text"><span className="xp-dim">{w.noise_title} </span>{d.noise.text}</p> : null}
      </section>
      {ww ? <section className="xp-ww"><h2 className="xp-sub">{w.wordforword_title}</h2>
        <HarnessSwitch hidden={wwHidden} on={showHarness} set={setShowHarness} w={w} /><WordGrid d={ww} /></section> : null}
      <RulePanel d={d} ev={ev} />
      <EventsPanel d={d} pick={pick} setPick={setPick} />
      <StoryPanel d={d} showHarness={showHarness} setShowHarness={setShowHarness} />
      <p className="ua-hint">{w.source}</p>
    </>
  );
}

function WhyLab(_: LabProps) {
  const [alert] = useAlertParam();
  const { data, error, loading } = useLab<Why>(alert ? `/api/labs/why/${encodeURIComponent(alert)}` : null);
  if (!alert) return <AlertPicker lab="why" url="/api/labs/why" />;
  return <><NextStrip current="why" alert={alert} /><LabState loading={loading} error={error}>{data && <WhyView d={data} />}</LabState></>;
}

export const lab: Lab = {
  id: "why",
  title: "Why is this suspicious?",
  blurb: "One alert: the rule that fired, the exact fields that matched, and its steps in the evidence graph.",
  icon: ShieldQuestion,
  Component: WhyLab,
};
