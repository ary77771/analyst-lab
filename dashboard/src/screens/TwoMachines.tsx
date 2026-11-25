// "Two machines (public data)": one public OTRF recording where activity moves from one Windows
// machine to another, shown as the linker saw it. A display of docs/results/linker/*.json,
// served by engine/dashboard/public.py; nothing is graded here.
import { useEffect, useMemo, useRef, useState } from "react";
import { Maximize2, Monitor, Play } from "lucide-react";
import { api, type PublicEdge, type TwoMachines as TM } from "../api";
import Graph, { colors, type GraphHandle } from "../Graph";
import { iconUrl } from "../icons";
import { useWords } from "../words";
import { Button, Card, Eyebrow, InkTag, KeyValue, Legend, Stat } from "../ui";
import { T } from "../ui-text";

const COL = 380, ROW = 84;

function layout(d: TM, all: boolean) {
  const order: string[] = [];
  const nodeHost = new Map(d.nodes.map((n) => [n.id, n.machine]));
  const edgesShown = d.edges.filter((e) => all || e.focus);
  const touched = new Set(edgesShown.flatMap((e) => [e.source, e.target]));
  [...d.edges].filter((e) => e.focus).sort((a, b) => a.time.localeCompare(b.time)).forEach((e) => {
    for (const id of [e.source, e.target]) { const m = nodeHost.get(id)!; if (!order.includes(m)) order.push(m); }
  });
  if (all) d.machines.filter((m) => m.in_picture).forEach((m) => { if (!order.includes(m.machine)) order.push(m.machine); });
  const rows = new Map<string, number>();
  const nodes = d.nodes.filter((n) => touched.has(n.id) && order.includes(n.machine))
    .sort((a, b) => Number(b.focus) - Number(a.focus) || (a.start ?? "").localeCompare(b.start ?? "") || a.label.localeCompare(b.label));
  const els: unknown[] = order.map((m) => {
    const info = d.machines.find((x) => x.machine === m)!;
    return { data: { id: `m:${m}`, label: `${m}  ·  ${info.sysmon_events} ${d.words.machine_events}`, machine: 1 } };
  });
  for (const n of nodes) {
    const r = rows.get(n.machine) ?? 0;
    rows.set(n.machine, r + 1);
    els.push({ data: { id: n.id, label: n.label, kind: n.kind, parent: `m:${n.machine}`, faded: n.focus ? 0 : 1 },
               position: { x: order.indexOf(n.machine) * COL, y: r * ROW } });
  }
  for (const e of edgesShown) {
    els.push({ data: { id: e.id, source: e.source, target: e.target, grade: e.grade, kind: e.kind, faded: e.focus ? 0 : 1,
                       band: e.grade === "hypothesis" ? (e.band ?? "") : "" } });
  }
  return els;
}

function graphStyle(w: ReturnType<typeof useWords>) {
  const c = colors();
  const bandWord = (b: string) => (b ? (w.bands[b] ?? w.band_not_assessable) : "");
  const edgeLabel = { "font-size": 12, "font-weight": 600, "text-background-color": c.canvas, "text-background-opacity": 0.9,
    "text-background-padding": 3, "text-background-shape": "round-rectangle", "text-rotation": "autorotate" };
  return [
    { selector: "node", style: { label: "data(label)", "font-family": "Inter, sans-serif", "font-size": 14, "font-weight": 600, color: c.text,
      "text-valign": "center", "text-halign": "center", "text-margin-x": 12, shape: "round-rectangle", width: 200, height: 44,
      "background-color": c.raised, "border-width": 1.5, "border-color": c.strong,
      "background-image": (el: { data: (k: string) => string }) => iconUrl(undefined, c.muted, el.data("kind") || "process"),
      "background-width": 18, "background-height": 18, "background-position-x": 14, "background-position-y": "50%" } },
    { selector: "node[faded = 1]", style: { opacity: 0.45 } },
    { selector: "node[machine = 1]", style: { "font-size": 16, "font-weight": 600, "text-valign": "top", "text-halign": "center",
      "text-margin-y": -10, "text-margin-x": 0, color: c.text, "background-color": c.surface, "background-opacity": 1,
      "background-image": "none", "border-color": c.strong, "border-width": 1.5, padding: 28, shape: "round-rectangle" } },
    { selector: "edge", style: { width: 2.5, "curve-style": "bezier", "target-arrow-shape": "triangle", "arrow-scale": 1.1,
      "line-color": c.fact, "target-arrow-color": c.fact } },
    { selector: "edge[faded = 1]", style: { width: 1, opacity: 0.25 } },
    { selector: "edge[grade = 'hypothesis']", style: { "line-style": "dashed", "line-dash-pattern": [9, 6], "line-color": c.hypothesis,
      "target-arrow-color": c.hypothesis, color: c.hypothesis, ...edgeLabel,
      label: (el: { data: (k: string) => string }) => `${w.inks.hypothesis.word} · ${bandWord(el.data("band"))}` } },
    { selector: "edge.sel", style: { width: 5, opacity: 1, "z-index": 99, "overlay-color": c.accent, "overlay-opacity": 0.25, "overlay-padding": 6 } },
  ];
}

export const fmtTime = (t: string) => t.replace("T", " ").replace(/\.(\d{3})\d*/, ".$1").replace(/(\+00:00|Z)$/, " UTC");

function Proof({ edge, d }: { edge: PublicEdge | null; d: TM }) {
  const w = useWords();
  if (!edge) {
    return (
      <ol className="space-y-4">
        {d.story.map((s, i) => (
          <li key={i} className="rise flex gap-3" style={{ animationDelay: `${i * 80}ms` }}>
            <span className="num mt-0.5 flex h-7 w-7 flex-none items-center justify-center rounded-full border border-border-strong text-[13px] font-semibold text-fg-muted">{i + 1}</span>
            <span className="text-[16px] leading-relaxed text-fg">{s}</span>
          </li>
        ))}
        <li className="border-t border-border pt-4 text-[14px] text-fg-muted">{w.evidence_hint}</li>
      </ol>
    );
  }
  return (
    <div className="rise space-y-4" key={edge.id}>
      <InkTag ink={edge.grade} band={edge.band} />
      <p className="text-[17px] leading-relaxed text-fg">{edge.sentence}</p>
      <div>
        <Eyebrow className="mb-2">{w.evidence_title}</Eyebrow>
        <ul className="space-y-2">
          {edge.evidence.map((ev) => (
            <li key={ev.key} className="rounded-[6px] border border-border bg-raised px-3.5 py-3">
              <div className="mb-2 flex items-center gap-2 text-[15px] font-semibold"><Monitor size={16} className="text-fg-muted" />{ev.machine}</div>
              <KeyValue rows={[
                [w.evidence_role, ev.role],
                [T.event, w.events[String(ev.event)] ?? ev.event],
                [T.time, <span className="num">{fmtTime(ev.time)}</span>],
                [T.record, <span className="num">{ev.record_id}</span>],
              ]} />
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default function TwoMachines() {
  const w = useWords();
  const [d, setD] = useState<TM | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [shown, setShown] = useState(Infinity);
  const [all, setAll] = useState(false);
  const graph = useRef<GraphHandle>(null);

  useEffect(() => { api.twoMachines().then(setD).catch((e) => setErr(String(e))); }, []);
  const elements = useMemo(() => (d ? layout(d, all) : []), [d, all]);
  const style = useMemo(() => graphStyle(w), [w]);
  const story = useMemo(() => (d ? [...d.edges].filter((e) => e.focus).sort((a, b) => a.time.localeCompare(b.time)).map((e) => e.id) : []), [d]);
  const playing = shown !== Infinity;
  const hidden = useMemo(() => (playing && d ? new Set(d.edges.map((e) => e.id).filter((id) => !story.slice(0, shown).includes(id))) : null),
    [playing, shown, d, story]);
  useEffect(() => {
    if (!playing) return;
    if (shown > story.length) { setShown(Infinity); return; }
    if (shown > 0) setSel(story[shown - 1]);
    const t = setTimeout(() => setShown(shown + 1), shown === 0 ? 500 : 1400);
    return () => clearTimeout(t);
  }, [shown, playing, story]);

  if (err) return <p className="text-alert">{T.errorPrefix} {err}</p>;
  if (!d) return <p className="text-fg-muted">{T.loading}</p>;
  const edge = d.edges.find((e) => e.id === sel) ?? null;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-[32px] font-semibold">{d.words.title}</h1>
        <p className="mt-2 max-w-[72ch] text-[16px] leading-relaxed text-fg-muted">{d.words.badge}</p>
      </div>

      <div className="grid gap-4 xl:grid-cols-[440px_minmax(0,1fr)]">
        <Card title={edge ? w.evidence_title : d.words.story_title} className="min-w-0"><Proof edge={edge} d={d} /></Card>
        <Card pad={false} className="flex min-w-0 flex-col" title={<Legend />}
          actions={<>
            <Button icon={<Maximize2 size={14} />} onClick={() => graph.current?.fit()}>{T.fit}</Button>
            <Button variant="primary" icon={<Play size={14} />} onClick={() => { setAll(false); setSel(null); setShown(0); }}>{T.play}</Button>
          </>}>
          <Graph ref={graph} elements={elements} style={style} selected={sel} hidden={hidden}
            onSelect={(id) => { setShown(Infinity); setSel(id); }} className="min-h-[560px] w-full flex-1" />
          <div className="space-y-2 border-t border-border px-5 py-3">
            <label className="flex cursor-pointer select-none items-center gap-2 text-[14px] text-fg-muted">
              <input type="checkbox" checked={all} onChange={(e) => { setShown(Infinity); setSel(null); setAll(e.target.checked); }} className="h-4 w-4 accent-[var(--color-accent)]" />
              {d.words.show_all}
            </label>
            {all && <p className="max-w-[90ch] text-[14px] text-fg-muted">{d.story_others.join(" ")} {d.words.focus_hint}</p>}
          </div>
        </Card>
      </div>

      <Card title={d.words.numbers_title}>
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-5">
          {d.headline.map((h, i) => <Stat key={i} value={h.value} label={h.label} ink={h.ink} />)}
        </div>
        <ul className="mt-6 max-w-[90ch] space-y-1.5 border-t border-border pt-5 text-[15px] leading-relaxed text-fg-muted">
          {d.sentences.map((s, i) => <li key={i}>{s}</li>)}
        </ul>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={d.words.limit_title} className="border-l-2 !border-l-border-strong">
          <p className="max-w-[72ch] text-[16px] leading-relaxed">{d.limit}</p>
        </Card>
        <Card title={d.words.dataset_title}>
          <KeyValue rows={[
            [T.dataset, `${d.dataset.name} (${T.commit} ${d.dataset.commit.slice(0, 7)})`],
            [T.file, d.file],
            [T.licence, d.dataset.licence_text],
          ]} />
        </Card>
      </div>
    </div>
  );
}
