// Story: one alert's investigation, from report v3 (engine/report.py build()): the verdict, the
// story in Python's causal order (numbered chain steps, "before this" gaps first, the suspected link,
// other recorded facts nearby), the graph in per-program swimlanes left to right in time, and the
// recorded proof of whatever is selected. The page only places what Python says.
import { useEffect, useMemo, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Maximize2, Play } from "lucide-react";
import { api, type AlertRow, type Citation, type Ink, type Investigation, type ReportHypothesis, type TimelineItem } from "../api";
import Graph, { colors, type GraphHandle } from "../Graph";
import { iconUrl, STEP_ICON } from "../icons";
import { useWords } from "../words";
import { Button, Card, Eyebrow, InkTag, KeyValue, Legend, LevelTag, Stat, cx, INK_BORDER, INK_TEXT } from "../ui";
import { T } from "../ui-text";
import { fmtTime } from "./TwoMachines";

interface Row extends TimelineItem { n?: number; citations: Citation[]; hyp?: ReportHypothesis; band?: string | null; detail?: string }

function rowsOf(inv: Investigation): Row[] {
  const r = inv.report;
  const byId = new Map<string, { citations: Citation[]; hyp?: ReportHypothesis; band?: string | null; detail?: string }>();
  r.facts.forEach((f) => f.id && byId.set(f.id, { citations: f.citations }));
  r.hypotheses.forEach((h) => h.id && byId.set(h.id, { citations: h.citations, hyp: h, band: h.band }));
  r.gaps.forEach((g) => g.id && byId.set(g.id, { citations: g.citations, detail: g.reason }));
  const stepN = new Map((r.verdict?.steps ?? []).map((s) => [s.id, s.n]));
  return r.timeline.map((t) => ({ ...t, ...(byId.get(t.id) ?? { citations: [] }), n: stepN.get(t.id) }));
}

const COL = 175, LANE_H = 160;

function graphElements(inv: Investigation) {
  const L = inv.report.layout!;
  const els: unknown[] = L.lanes.map((l) => ({ data: { id: `lane:${l.lane}`, label: l.short }, classes: "lane",
    position: { x: -COL * 1.1, y: l.lane * LANE_H } }));
  // programs sit on their lane's centre line; the things they touch alternate just above and below
  // it, so a line from a program never runs straight through the next item in the same lane
  const seen = new Map<number, number>();
  for (const n of [...L.nodes].sort((a, b) => a.order - b.order)) {
    const k = seen.get(n.lane) ?? 0;
    if (n.kind !== "process") seen.set(n.lane, k + 1);
    const dy = n.kind === "process" ? 0 : (k % 2 === 0 ? -1 : 1) * 38;
    els.push({ data: { id: n.id, label: n.short, kind: n.kind, icon: n.icon, seed: inv.nodes.find((x) => x.id === n.id)?.seed ? 1 : 0,
                       gap: inv.nodes.find((x) => x.id === n.id)?.gaps.length ? 1 : 0 },
               position: { x: n.order * COL, y: n.lane * LANE_H + dy } });
  }
  for (const e of L.edges) {
    els.push({ data: { id: e.id, source: e.u, target: e.v, grade: e.grade, band: e.band ?? "", kind: e.kind, chain: e.in_chain ? 1 : 0 } });
  }
  return els;
}

function graphStyle(w: ReturnType<typeof useWords>) {
  const c = colors();
  const bandWord = (b: string) => (b ? (w.bands[b] ?? w.band_not_assessable) : "");
  const edgeLabel = { "font-size": 12, "font-weight": 600, "text-background-color": c.canvas, "text-background-opacity": 0.92,
    "text-background-padding": 3, "text-background-shape": "round-rectangle", "text-rotation": "autorotate" };
  return [
    { selector: "node", style: { label: "data(label)", "font-family": "Inter, sans-serif", "font-size": 14, "font-weight": 600, color: c.text,
      "text-valign": "bottom", "text-margin-y": 9, "text-wrap": "wrap", "text-max-width": 150,
      "text-background-color": c.canvas, "text-background-opacity": 0.85, "text-background-padding": 2,
      shape: "round-rectangle", width: 54, height: 54, "background-color": c.raised, "border-width": 1.5, "border-color": c.strong,
      "background-image": (el: { data: (k: string) => string }) => iconUrl(el.data("icon"), c.text, el.data("kind")),
      "background-width": "55%", "background-height": "55%" } },
    { selector: "node[seed = 1]", style: { "border-color": c.text, "border-width": 3 } },
    { selector: "node[gap = 1]", style: { "border-color": c.gap, "border-style": "dotted", "border-width": 3 } },
    { selector: "node.lane", style: { shape: "rectangle", width: 1, height: 1, "background-opacity": 0, "border-width": 0, "background-image": "none",
      "text-valign": "center", "text-halign": "left", "font-size": 13, "font-weight": 600, color: c.subtle, "text-background-opacity": 0, events: "no" } },
    { selector: "edge", style: { width: 2.5, "curve-style": "bezier", "target-arrow-shape": "triangle", "arrow-scale": 1.1,
      "line-color": c.fact, "target-arrow-color": c.fact, label: (el: { data: (k: string) => string }) => w.verbs[el.data("kind")] ?? "",
      color: c.muted, ...edgeLabel } },
    { selector: "edge[chain = 0][grade = 'fact']", style: { width: 1.5, opacity: 0.55 } },
    { selector: "edge[grade = 'hypothesis']", style: { "line-style": "dashed", "line-dash-pattern": [9, 6], "line-color": c.hypothesis,
      "target-arrow-color": c.hypothesis, color: c.hypothesis, width: 2.5, opacity: 1,
      label: (el: { data: (k: string) => string }) => `${w.inks.hypothesis.word} · ${bandWord(el.data("band"))}` } },
    { selector: "edge.sel", style: { width: 5, opacity: 1, "z-index": 99, "overlay-color": c.accent, "overlay-opacity": 0.25, "overlay-padding": 6 } },
  ];
}

function RecordToggle({ c }: { c: Citation }) {
  const w = useWords();
  const [open, setOpen] = useState(false);
  const [rec, setRec] = useState<Record<string, unknown> | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const toggle = () => {
    setOpen(!open);
    if (!rec && !open) api.event(c.key).then(setRec).catch((e) => setErr(String(e)));
  };
  const skip = new Set(["dedup_key", "id"]);
  return (
    <li className="rounded-[6px] border border-border bg-raised">
      <button onClick={toggle} className="flex w-full items-center gap-2 px-3 py-2.5 text-left text-[14px] hover:bg-border/40">
        {open ? <ChevronDown size={15} className="text-fg-muted" /> : <ChevronRight size={15} className="text-fg-muted" />}
        <span className="font-semibold">{w.events[String(c.event)] ?? c.text}</span>
        <span className="num ml-auto text-[13px] text-fg-muted">{fmtTime(c.time).slice(11)}</span>
      </button>
      {open && (
        <div className="max-h-64 overflow-auto border-t border-border px-3 py-2.5">
          {err ? <p className="text-[13px] text-alert">{err}</p> : !rec ? <p className="text-[13px] text-fg-muted">{T.loading}</p> :
            <KeyValue rows={Object.entries(rec).filter(([k, v]) => !skip.has(k) && v !== "" && v !== null).map(([k, v]) => [k, <span className="break-all">{String(v)}</span>])} />}
        </div>
      )}
    </li>
  );
}

function Verdict({ inv }: { inv: Investigation }) {
  const w = useWords();
  const v = inv.report.verdict!;
  const line = (ink: Ink, text: string) => (
    <div className={cx("border-l-[3px] pl-3", INK_BORDER[ink], ink === "hypothesis" ? "border-dashed" : ink === "gap" ? "border-dotted" : "border-solid")}>
      <InkTag ink={ink} size="sm" /><p className="mt-1 text-[15px] leading-relaxed text-fg">{text}</p>
    </div>
  );
  return (
    <div className="space-y-4">
      {line("fact", v.proven.text)}
      {v.not_proven && line("hypothesis", v.not_proven.text)}
      {v.cant_see && line("gap", v.cant_see.text)}
      <p className="border-t border-border pt-4 text-[14px] text-fg-muted">{w.evidence_hint}</p>
    </div>
  );
}

function Proof({ row }: { row: Row }) {
  const w = useWords();
  const [more, setMore] = useState(false);
  const h = row.hyp;
  return (
    <div className="rise space-y-4" key={row.id}>
      <InkTag ink={row.ink} band={row.band} />
      <p className="text-[17px] leading-relaxed text-fg">{row.short}</p>
      {row.detail && <p className="text-[15px] leading-relaxed text-fg-muted">{row.detail}</p>}
      {h?.chance_short && <p className={cx("text-[15px] font-semibold leading-relaxed", INK_TEXT.hypothesis)}>{h.chance_short}</p>}
      {h?.plain && (
        <dl className="space-y-3">
          {h.plain.map((l, i) => (
            <div key={i}><dt className="text-[13px] font-semibold text-fg-muted">{l.label}</dt><dd className="mt-0.5 text-[15px] leading-relaxed text-fg">{l.text}</dd></div>
          ))}
        </dl>
      )}
      {h?.details && (
        <div>
          <button onClick={() => setMore(!more)} className="flex items-center gap-1.5 text-[13px] font-semibold text-fg-muted hover:text-fg">
            {more ? <ChevronDown size={14} /> : <ChevronRight size={14} />}{T.details}</button>
          {more && <div className="mt-2"><KeyValue rows={h.details.map((l) => [l.label, l.text])} /></div>}
        </div>
      )}
      {row.citations.length > 0 && (
        <div>
          <Eyebrow className="mb-2">{w.evidence_title}</Eyebrow>
          <ul className="space-y-2">{row.citations.map((c) => <RecordToggle key={c.key} c={c} />)}</ul>
        </div>
      )}
    </div>
  );
}

function StepList({ rows, sel, onSelect, shown }: { rows: Row[]; sel: string | null; onSelect: (id: string) => void; shown: number }) {
  const refs = useRef<Map<string, HTMLLIElement>>(new Map());
  useEffect(() => { if (sel) refs.current.get(sel)?.scrollIntoView({ block: "nearest", behavior: "smooth" }); }, [sel]);
  return (
    <ol className="space-y-1">
      {rows.map((r, i) => {
        const Icon = STEP_ICON[r.icon] ?? STEP_ICON.other;
        const quiet = r.ink === "fact" && !r.in_chain;
        return (
          <li key={r.id} ref={(el) => { if (el) refs.current.set(r.id, el); }} className={cx("transition-opacity duration-300", i >= shown && "opacity-15")}>
            <button onClick={() => onSelect(r.id)}
              className={cx("flex w-full items-start gap-3 rounded-[6px] px-2.5 py-2.5 text-left transition-colors",
                sel === r.id ? "bg-raised ring-1 ring-accent" : "hover:bg-raised")}>
              <span className={cx("mt-0.5 flex h-8 w-8 flex-none items-center justify-center rounded-[6px] border",
                r.n ? "border-fact/60 bg-fact/10" : "border-border")}>
                {r.n ? <span className="num text-[14px] font-semibold text-fact">{r.n}</span> : <Icon size={16} className={INK_TEXT[r.ink]} />}
              </span>
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-3">
                  <InkTag ink={r.ink} band={r.band} size="sm" />
                  {r.offset_text && <span className="num ml-auto text-[13px] text-fg-muted">{r.offset_text}</span>}
                </span>
                <span className={cx("mt-1 block leading-snug", quiet ? "text-[15px] text-fg-muted" : "text-[16px] text-fg")}>{r.short}</span>
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

export default function Story({ alertId }: { alertId?: string | null }) {
  const w = useWords();
  const [alerts, setAlerts] = useState<AlertRow[] | null>(null);
  const [id, setId] = useState<string | null>(alertId ?? null);
  const [inv, setInv] = useState<Investigation | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [shown, setShown] = useState(Infinity);
  const graph = useRef<GraphHandle>(null);

  useEffect(() => {
    api.alerts().then((a) => { setAlerts(a); setId((cur) => (cur && a.some((x) => x.id === cur) ? cur : a[0]?.id ?? null)); })
      .catch((e) => setErr(String(e)));
  }, []);
  useEffect(() => { if (alertId) setId(alertId); }, [alertId]);
  useEffect(() => { if (id) { setInv(null); setSel(null); api.investigation(id).then(setInv).catch((e) => setErr(String(e))); } }, [id]);

  const rows = useMemo(() => (inv ? rowsOf(inv) : []), [inv]);
  const elements = useMemo(() => (inv?.report.layout ? graphElements(inv) : []), [inv]);
  const style = useMemo(() => graphStyle(w), [w]);

  // playback: rows in Python's order, one every 1.4 s; the graph shows only what has been told and
  // the proof panel narrates the current row
  const playing = shown !== Infinity;
  const hidden = useMemo(() => {
    if (!playing || !inv?.report.layout) return null;
    const told = new Set(rows.slice(0, shown).map((r) => r.id));
    return new Set(inv.report.layout.edges.filter((e) => !told.has(e.id)).map((e) => e.id));
  }, [playing, shown, inv, rows]);
  useEffect(() => {
    if (!playing) return;
    if (shown > rows.length) { setShown(Infinity); return; }
    if (shown > 0) setSel(rows[shown - 1]?.id ?? null);
    const t = setTimeout(() => setShown(shown + 1), shown === 0 ? 500 : 1500);
    return () => clearTimeout(t);
  }, [shown, playing, rows]);

  if (err) return <p className="text-alert">{T.errorPrefix} {err}</p>;
  if (!alerts) return <p className="text-fg-muted">{T.loading}</p>;
  if (!inv) return <p className="text-fg-muted">{alerts.length ? T.loading : w.no_alerts}</p>;

  const a = inv.alert, r = inv.report, v = r.verdict, c = r.counts;
  const selRow = rows.find((x) => x.id === sel) ?? null;
  const edgeIds = new Set((r.layout?.edges ?? []).map((e) => e.id));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <LevelTag level={a.level} label={w.alert_level} />
            <span className="num text-[14px] text-fg-muted">{a.host} · {fmtTime(a.time)}</span>
          </div>
          <h1 className="text-[32px] font-semibold">{v?.title ?? a.title}</h1>
          <p className="mt-2 max-w-[72ch] text-[16px] leading-relaxed text-fg-muted">{a.reason}</p>
        </div>
        {alerts.length > 1 && (
          <select value={id ?? ""} onChange={(e) => setId(e.target.value)}
            className="rounded-[6px] border border-border bg-raised px-3 py-2 text-[14px] text-fg">
            {alerts.map((x) => <option key={x.id} value={x.id}>{x.title} · {fmtTime(x.time)}</option>)}
          </select>
        )}
      </div>

      {r.declared_banner && (
        <div className="rounded-[10px] border border-border-strong bg-raised px-5 py-3 text-[15px] font-semibold text-fg">{r.declared_banner.text}</div>
      )}

      {c && (
        <div className="grid gap-px overflow-hidden rounded-[10px] border border-border bg-border sm:grid-cols-3">
          <div className="bg-surface px-6 py-5"><Stat value={c.facts} ink="fact"
            label={<span className="inline-flex flex-wrap items-center gap-2"><InkTag ink="fact" /><span>{w.chain_note.replace("{n}", String(c.steps))}</span></span>} /></div>
          <div className="bg-surface px-6 py-5"><Stat value={c.hypotheses} ink="hypothesis"
            label={<span className="inline-flex flex-wrap items-center gap-2"><InkTag ink="hypothesis" band={v?.not_proven?.band} /></span>} /></div>
          <div className="bg-surface px-6 py-5"><Stat value={c.gaps} ink="gap" label={<InkTag ink="gap" />} /></div>
        </div>
      )}

      {/* the graph runs left to right in time, one lane per program, so it gets the full width */}
      <Card pad={false} className="min-w-0" title={<Legend />}
        actions={<>
          <Button icon={<Maximize2 size={14} />} onClick={() => graph.current?.fit()}>{T.fit}</Button>
          <Button variant="primary" icon={<Play size={14} />} onClick={() => { setSel(null); setShown(0); }}>{T.play}</Button>
        </>}>
        <Graph ref={graph} elements={elements} style={style} selected={sel && edgeIds.has(sel) ? sel : null} hidden={hidden}
          onSelect={(eid) => { setShown(Infinity); setSel(eid); }} className="h-[440px] w-full" />
      </Card>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Card title={w.steps_title} className="min-w-0"
          actions={v?.offset_from ? <span className="text-[13px] text-fg-muted">{w.offset_note.replace("{ref}", v.offset_from)}</span> : null}>
          <div className="xl:max-h-[620px] xl:overflow-auto xl:pr-1">
            <StepList rows={rows} sel={sel} onSelect={(x) => { setShown(Infinity); setSel(x); }} shown={shown} />
          </div>
        </Card>
        <Card title={selRow ? w.evidence_title : w.summary_title} className="min-w-0">
          {selRow ? <Proof row={selRow} /> : v ? <Verdict inv={inv} /> : null}
        </Card>
      </div>

      <Card title={w.limits_title}>
        <ul className="max-w-[90ch] space-y-2 text-[15px] leading-relaxed text-fg-muted">{r.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
      </Card>
    </div>
  );
}
