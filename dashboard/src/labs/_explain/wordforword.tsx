// Word for word: an alert's records in Sysmon's own field names next to the story's sentences, each traced word
// pointing at its field (engine/labs/_wordforword.py). Shared by "Why is this suspicious?" (its first screen) and
// the older "This is what an alarm says" lab. Not a lab itself (no index.tsx).
import { useState } from "react";
import { fill } from "./logic";
import "./wordforword.css";

export type WW = Record<string, string> & { inks: Record<string, string> };
export interface Trace { start: number; end: number; field: string; key: string; value: string }
export interface Line { harness?: string | null; machinery?: string | null; ink: "fact" | "hypothesis"; text: string; keys: string[]; own: boolean; traces: Trace[] }
export interface Rec { key: string; missing: boolean; name?: string; event_id?: number | null; header: [string, string | number][]; fields: [string, string | number][];
  notes?: [string, string | number][]; by?: "windows" | "recorder" }
export interface WordData { words: WW; story: boolean; lines: Line[]; records: Rec[]; records_total: number }
export type View = "side" | "alarm" | "story";

/** The sentence cut into plain text and traced pieces (traces are sorted and never overlap). */
export function cut(text: string, traces: Trace[]): { text: string; t: Trace | null }[] {
  const out: { text: string; t: Trace | null }[] = [];
  let at = 0;
  for (const t of [...traces].sort((a, b) => a.start - b.start)) {
    if (t.start < at) continue;
    if (t.start > at) out.push({ text: text.slice(at, t.start), t: null });
    out.push({ text: text.slice(t.start, t.end), t });
    at = t.end;
  }
  if (at < text.length) out.push({ text: text.slice(at), t: null });
  return out;
}

function esc(v: string | number) { return String(v); }

export function RawRecord({ r, n, lit, w }: { r: Rec; n: number; lit: Set<string>; w?: WW }) {
  const hit = (f: string) => lit.has(`${r.key}|${f}`);
  return (
    <div className="al-rec" data-lit={[...lit].some((x) => x.startsWith(r.key + "|"))} id={`al-rec-${n}`}>
      <div className="al-rec-head"><b>#{n}</b><span>{r.name ?? "?"}</span></div>
      {r.by === "recorder" && w?.by_recorder ? <p className="xp-small xp-dim al-by">{w.by_recorder}</p> : null}
      {r.missing ? <p className="xp-small xp-dim">?</p> : (
        <pre className="al-xml">
          <span className="al-tag">{"<Event>"}</span>{"\n  "}<span className="al-tag">{"<System>"}</span>{"\n"}
          {r.header.map(([k, v]) => (
            <span key={k} className="al-line" data-hit={k === "event_id" && hit("EventID")}>{"    "}<span className="al-tag">{`<${k}>`}</span>{esc(v)}<span className="al-tag">{`</${k}>`}</span>{"\n"}</span>))}
          {"  "}<span className="al-tag">{"</System>"}</span>{"\n  "}<span className="al-tag">{"<EventData>"}</span>{"\n"}
          {r.fields.map(([k, v]) => (
            <span key={k} className="al-line" data-hit={hit(k)}>{"    "}<span className="al-tag">{`<Data Name="${k}">`}</span>{esc(v)}<span className="al-tag">{"</Data>"}</span>{"\n"}</span>))}
          {"  "}<span className="al-tag">{"</EventData>"}</span>{"\n"}<span className="al-tag">{"</Event>"}</span>
        </pre>)}
      {!r.missing && r.notes?.length ? (
        <details className="al-notes"><summary className="xp-small xp-dim">{w?.recorder_notes ?? "notes"} ({r.notes.length})</summary>
          <pre className="al-xml">{r.notes.map(([k, v]) => <span key={k} className="al-line">{`${k}: ${esc(v)}`}{"\n"}</span>)}</pre></details>) : null}
    </div>
  );
}

/** The two columns: the records as recorded, and the sentences with their traced words (hover lights the fields). */
export function WordGrid({ d, view = "side" }: { d: WordData; view?: View }) {
  const w = d.words;
  const [on, setOn] = useState<number | null>(0);
  const num = new Map(d.records.map((r, i) => [r.key, i + 1]));
  const line = on !== null ? d.lines[on] : undefined;
  const lit = new Set((line?.traces ?? []).map((t) => `${t.key}|${t.field}`));
  const shownRecs = line ? d.records.filter((r) => line.keys.includes(r.key)) : d.records;
  return (
      <div className="al-grid" data-view={view}>
        {view !== "story" ? (
          <section className="ua-panel lab-panel al-raw">
            <h2>{w.raw_title}</h2><p className="ua-hint">{w.raw_note}</p>
            {d.records_total > d.records.length ? <p className="ua-hint">{fill(w.more_records, { shown: d.records.length, total: d.records_total })}</p> : null}
            {(view === "side" ? shownRecs : d.records).map((r) => <RawRecord key={r.key} r={r} n={num.get(r.key) ?? 0} lit={view === "side" ? lit : new Set()} w={w} />)}
          </section>) : null}
        {view !== "alarm" ? (
          <section className="ua-panel lab-panel al-story">
            <h2>{w.story_title}</h2><p className="ua-hint">{w.story_note}</p>
            {!d.story ? <p className="lab-state" data-kind="empty">{w.no_story}</p> : d.lines.length === 0 ? <p className="lab-state" data-kind="empty">{w.no_lines}</p> : (
              <ol className="al-lines">{d.lines.map((l, i) => (
                <li key={i} className="al-sentence" data-ink={l.ink} aria-selected={i === on} onMouseEnter={() => setOn(i)} onClick={() => setOn(i)}>
                  <b className={`xp-ink-${l.ink}`}>{w.inks[l.ink]}</b>
                  <p>{cut(l.text, l.traces).map((p, j) => p.t
                    ? <mark key={j} className="al-word" data-field={p.t.field} title={`${p.t.field} = ${p.t.value} · #${num.get(p.t.key) ?? "?"}`}>{p.text}</mark>
                    : <span key={j}>{p.text}</span>)}</p>
                  {l.machinery ? <p className="xp-machinery">{l.machinery}</p> : null}
                  <p className="xp-small xp-dim">{w.cites} {l.keys.map((k) => `#${num.get(k) ?? "?"}`).join(", ")}</p>
                </li>))}</ol>)}
          </section>) : null}
      </div>
  );
}
