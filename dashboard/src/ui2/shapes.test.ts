// The Story screen's logic on the SHAPES of real stories (tests/fixtures/stories/, from the sweep of
// 2026-11-21): the biggest story found (1,120 rows on 42 rails) and the oddest ones. Every name in
// those files is made up; the rows, inks, order, rails, links and counts are the real ones.
// tests/test_dashboard_film_shapes.py checks the same files against the Python rule that cuts the film.
import { describe, expect, it } from "vitest";
import type { Investigation } from "../api";
import { buildMap, camera, filmCut, filmRows, filmView, rowsOf, tally } from "./logic";

const FILES = import.meta.glob<Investigation>("../../../tests/fixtures/stories/*.json", { eager: true, import: "default" });
const byName = new Map(Object.entries(FILES).map(([file, story]) => [file.split("/").pop()!.replace(/\.json$/, ""), story]));
const NAMES: string[] = [...byName.keys()].sort();
const load = (name: string) => structuredClone(byName.get(name)!);

// the film panel on the demo laptop (Edge maximised, 1463 x 780): measured in the real browser
const W = 1421, H = 355, R = 22;
const scene = (inv: Investigation) => {
  const view = filmView(inv), rows = filmRows(inv, rowsOf(inv)), L = view.report.layout!;
  const columns = Math.max(1, L.nodes.length - 1), lanes = Math.max(1, L.lanes.length);
  const left = 96, right = 80, top = 50 + R + 24, bottom = 50 + R + 40;
  const col = Math.min(210, Math.max(112, (W - left - right) / columns));
  const room = lanes > 1 ? (H - top - bottom) / (lanes - 1) : 0;
  const laneH = lanes > 1 ? Math.min(170, Math.max(104, room)) : 0;                    // as Film.tsx sizes it
  return { rows, m: buildMap(view, rows, { r: R, off: 50, col, laneH, left, right, top, bottom, stub: 26, compact: room < 104 ? 2 * R + 28 : undefined }) };
};
const inView = (c: { x: number; y: number; k: number }, x: number, y: number) =>
  x * c.k + c.x >= R && x * c.k + c.x <= W - R && y * c.k + c.y >= R && y * c.k + c.y <= H - R;

describe("real story shapes are there", () => {
  it("has the biggest story and the odd ones", () => {
    expect(NAMES.length).toBeGreaterThanOrEqual(10);
    expect(rowsOf(load("biggest-1120-rows"))).toHaveLength(1120);
  });
});

describe.each(NAMES)("the shape of a real story: %s", (name) => {
  const inv = load(name), all = rowsOf(inv), cut = filmCut(inv);

  it("the report keeps every row, in Python's order, with its ink", () => {
    expect(all.map((r) => r.id)).toEqual(inv.report.timeline.map((t) => t.id));
    expect(all.map((r) => r.ink)).toEqual(inv.report.timeline.map((t) => t.ink));
    const c = inv.report.counts!;
    expect(tally(all, all.length)).toEqual({ fact: c.facts, hypothesis: c.hypotheses, gap: c.gaps });
  });

  it("the film tells exactly Python's rows, in the story's order, and its two sets of counts add up", () => {
    const rows = filmRows(inv, all);
    if (!cut) { expect(rows).toBe(all); return; }
    expect(rows.map((r) => r.id)).toEqual(cut.ids);                                    // Python's cut is already in the story's order
    expect(rows.length).toBeLessThan(all.length);
    expect(tally(rows, rows.length)).toEqual(cut.counts);
    expect(tally(all, all.length)).toEqual(cut.story_counts);
    expect(cut.note).toContain(String(all.length));
  });

  it("every filmed link is drawn once, in its own ink, and nothing else is", () => {
    const { rows, m } = scene(inv);
    const links = new Set(filmView(inv).report.layout!.edges.map((e) => e.id));
    const expected = rows.filter((r) => links.has(r.id));
    expect(m.edges.map((e) => e.id).sort()).toEqual(expected.map((r) => r.id).sort());
    for (const e of m.edges) expect(e.ink).toBe(rows.find((r) => r.id === e.id)!.ink);
    for (const e of m.edges) expect(rows[e.at - 1].id).toBe(e.id);                     // drawn when its own row is told
  });

  it("the camera keeps what is being told on screen, from the first row to the last frame", () => {
    const { rows, m } = scene(inv);
    for (let shown = 1; shown <= rows.length; shown++) {
      const c = camera(m, W, H, shown, rows.length);
      expect(Number.isFinite(c.x) && Number.isFinite(c.y) && c.k > 0).toBe(true);
      const e = m.edges.find((x) => x.at === shown);
      if (e && shown < rows.length) expect(inView(c, e.tx, e.ty)).toBe(true);          // where the link arrives
    }
    const end = camera(m, W, H, rows.length, rows.length);
    const chain = m.edges.filter((e) => e.chain);
    const whole = m.nodes.filter((n) => n.at <= rows.length).every((n) => inView(end, n.x, n.y));
    // the last frame: everything; or (a long film) every thing of the alert's own steps; or, when even the
    // steps alone are too wide to read on one screen (99 steps in a row), the last link, as while playing
    const box = m.chain();
    const stepsFit = !!box && (box.x1 - box.x0 + 240) * 0.3 <= W && (box.y1 - box.y0 + 150) * 0.3 <= H;
    if (!whole && chain.length && stepsFit) for (const e of chain) { expect(inView(end, e.sx, e.sy)).toBe(true); expect(inView(end, e.tx, e.ty)).toBe(true); }
    if (!whole && !stepsFit) { const last = m.edges.find((x) => x.at === rows.length); if (last) expect(inView(end, last.tx, last.ty)).toBe(true); }
    expect(end.k).toBeGreaterThanOrEqual(0.3);
  });

  it("a suspected link's word never stands on a shape, on a name or on another word", () => {
    const { m } = scene(inv);
    const words = m.edges.filter((e) => e.label);
    const box = (e: { lx: number; ly: number; ang: number }) => {
      const c = Math.abs(Math.cos((e.ang * Math.PI) / 180)), s = Math.abs(Math.sin((e.ang * Math.PI) / 180));
      return { x0: e.lx - 44 * c - 11 * s, x1: e.lx + 44 * c + 11 * s, y0: e.ly - 44 * s - 11 * c, y1: e.ly + 44 * s + 11 * c };
    };
    const hit = (a: ReturnType<typeof box>, b: ReturnType<typeof box>) => a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1;
    let onShape = 0, onWord = 0;
    words.forEach((w, i) => {
      for (const n of m.nodes.filter((x) => Number.isFinite(x.at))) if (hit(box(w), { x0: n.x - R, x1: n.x + R, y0: n.y - R, y1: n.y + R })) onShape++;
      for (const v of words.slice(i + 1)) if (hit(box(w), box(v))) onWord++;
    });
    // a crowded map can leave a word no free place within reach: then it stays beside its link. Never more than a few.
    expect(onShape).toBeLessThanOrEqual(Math.floor(words.length / 10));
    expect(onWord).toBeLessThanOrEqual(Math.floor(words.length / 10));
  });

  it("no two things of the film stand on the same spot", () => {
    const { m } = scene(inv);
    const seen = new Set<string>();
    for (const n of m.nodes.filter((x) => Number.isFinite(x.at))) {
      const key = `${Math.round(n.x)}:${Math.round(n.y)}`;
      expect(seen.has(key)).toBe(false);
      seen.add(key);
    }
  });
});
