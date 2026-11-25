// Pure logic shared by both designs (no React, no DOM): unit-tested with vitest (logic.test.ts).
// Nothing here writes a claim: it only orders, counts and compares what the Python API sent.
import type { Citation, Ink, Investigation, Line } from "../api";

export type Skin = "a" | "b";
export type Screen = "watch" | "story" | "proof" | "labs";
export interface Route { skin: Skin; screen: Screen; param: string | null }

/** The design the demo opens: Yousif picked A ("Console") on 2026-11-20. B stays reachable at #b/... */
export const DEFAULT_SKIN: Skin = "a";

/**
 * "#a/story/3b3e" -> {skin: "a", screen: "story", param: "3b3e"}. The addresses demo/start.ps1 opens
 * ("#live", "#story") and the bare page open the picked design, so the launcher needs no change.
 * The old extra tabs ("#twin", "#coverage", "#scoreboard", "#twoMachines") -> null: the old app.
 */
const decode = (s: string) => { try { return decodeURIComponent(s); } catch { return s; } };       // a broken %-escape is kept as typed

export function parseRoute(hash: string): Route | null {
  // Labs (2026-11-23): "#/labs", "#/labs/<id>?<query>" (the form labs link to each other with), "#labs/..."
  // The part after "labs/" is kept exactly as typed: its query is decoded ONCE, by the lab's own reader
  // (splitLabParam / URLSearchParams). Decoding it here too mangled values holding & + % or = (night-pivot).
  const lab = /^#(?:a|b)?\/?labs(?:\/(.*))?$/.exec(hash);
  if (lab) return { skin: DEFAULT_SKIN, screen: "labs", param: lab[1] || null };
  const [first, ...more] = hash.replace(/^#/, "").split("/");
  if (first === "" || first === "live" || first === "watch") return { skin: DEFAULT_SKIN, screen: "watch", param: null };
  if (first === "proof") return { skin: DEFAULT_SKIN, screen: "proof", param: null };
  if (first === "story") return { skin: DEFAULT_SKIN, screen: "story", param: more.length ? decode(more.join("/")) || null : null };
  const [skin, screen, ...rest] = [first, ...more];
  if (skin !== "a" && skin !== "b") return null;
  const s: Screen = screen === "story" || screen === "proof" || screen === "labs" ? screen : "watch";
  const param = rest.length ? decode(rest.join("/")) : null;
  return { skin, screen: s, param: param || null };
}
export const href = (skin: Skin, screen: Screen, param?: string | null) =>
  `#${skin}/${screen}${param ? `/${encodeURIComponent(param)}` : ""}`;

/** One told step of the story: a row of Python's timeline with the words Python chose for it. */
export interface Row {
  id: string; ink: Ink; short: string; offset: string | null; icon: string; n?: number;
  bandLabel?: string; chance?: string; plain?: Line[]; nodeId?: string; detail?: string; citations: Citation[];
}

/** Python's timeline, in Python's order. This function must never sort, filter or merge rows. */
export function rowsOf(inv: Investigation): Row[] {
  const r = inv.report;
  const fact = new Map(r.facts.map((f) => [f.id, f]));
  const hyp = new Map(r.hypotheses.map((h) => [h.id, h]));
  const gap = new Map(r.gaps.map((g) => [g.id, g as typeof g & { node_id?: string }]));
  const stepN = new Map((r.verdict?.steps ?? []).map((s) => [s.id, s.n]));
  return r.timeline.map((t) => {
    const h = hyp.get(t.id), g = gap.get(t.id);
    return {
      id: t.id, ink: t.ink, short: t.short, offset: t.offset_text, icon: t.icon, n: stepN.get(t.id),
      bandLabel: h?.band_label, chance: h?.chance_short, plain: h?.plain, nodeId: g?.node_id, detail: g?.reason,
      citations: (fact.get(t.id) ?? h ?? g)?.citations ?? [],
    };
  });
}

/** Python's cut for the film, or null when the film tells the whole story (also: an answer without a cut). */
export const filmCut = (inv: Investigation) => (inv.film && !inv.film.whole ? inv.film : null);

/**
 * The film's rows: the rows Python chose (film.ids), taken from the story's rows without changing their
 * order. With no cut, every row. The choice is never made here: a row Python did not name is not filmed,
 * and nothing Python named is left out.
 */
export function filmRows(inv: Investigation, rows: Row[]): Row[] {
  const cut = filmCut(inv);
  if (!cut) return rows;
  const keep = new Set(cut.ids);
  return rows.filter((r) => keep.has(r.id));
}

/** The investigation as the film's map draws it: with Python's own cut-down layout when there is a cut. */
export function filmView(inv: Investigation): Investigation {
  const cut = filmCut(inv);
  return cut?.layout ? { ...inv, report: { ...inv.report, layout: cut.layout } } : inv;
}

export function tally(rows: Row[], shown: number): Record<Ink, number> {
  const c: Record<Ink, number> = { fact: 0, hypothesis: 0, gap: 0 };
  rows.slice(0, shown).forEach((r) => { c[r.ink] += 1; });
  return c;
}

/**
 * Which alerts are NEW since the page opened. Alerts already there at the first look never fire
 * (opening the page on an old alert is not news); each later id fires exactly once.
 */
export class AlertWatch {
  private known: Set<string> | null = null;
  update(viewIds: string[]): string[] {
    if (this.known === null) { this.known = new Set(viewIds); return []; }
    const fresh = viewIds.filter((id) => !this.known!.has(id));
    fresh.forEach((id) => this.known!.add(id));
    return fresh;
  }
}

/**
 * The story on screen never changes by itself: a new alert only marks the Watch screen. Returns the
 * alert the Story screen should show: the one asked for, else the one already showing, else the newest.
 */
export function storyAlert(asked: string | null, showing: string | null, ids: string[]): string | null {
  if (asked && ids.includes(asked)) return asked;
  if (showing && ids.includes(showing)) return showing;
  return ids.length ? ids[ids.length - 1] : null;
}

/** A long name shortened in the middle for a map label (the caption and the tooltip keep the full name). */
export const shortName = (s: string, max = 20) => (s.length <= max ? s : `${s.slice(0, Math.ceil(max / 2) - 1)}…${s.slice(-(Math.floor(max / 2) - 1))}`);

export const utcTime = (iso: string) => `${iso.slice(11, 19)} UTC`;
export const utcDate = (iso: string) => iso.slice(0, 10);
export const clock = (seconds: number) => `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(Math.floor(seconds % 60)).padStart(2, "0")}`;

// ---- the map (design A): positions from Python's lane and order only ----

/** `at`: the row that first shows the thing; `gapAt`: the row that says something about it can't be known (null: none) */
/** `side`: where the thing stands to its program's rail (-1 above, 0 on it, 1 below); its name is written on the far side */
export interface MapNode { id: string; short: string; kind: string; icon: string; lane: number; x: number; y: number; side: -1 | 0 | 1; gapAt: number | null; at: number }
export interface MapEdge { id: string; ink: Ink; d: string; at: number; chain: boolean; label: string | null; lx: number; ly: number; ang: number; sx: number; sy: number; tx: number; ty: number }
export interface MapScene {
  nodes: MapNode[]; edges: MapEdge[]; rails: { y: number; x: number; at: number }[];
  /** one per "can't be known" gap: a dotted stub entering its node from a question mark (a program from above,
   *  anything else from its free right side) */
  stubs: { id: string; d: string; qx: number; qy: number; at: number }[]; width: number; height: number;
  /** the distance between two columns (a name must fit between its neighbours on the same side of a rail) */
  col: number;
  /** where the camera looks when `shown` rows have been told */
  focus: (shown: number) => { x: number; y: number } | null;
  /** the box around everything drawn once `shown` rows have been told (null: nothing yet) */
  drawn: (shown: number) => Box | null;
  /** the box around the link told at row `shown`, from its source to its target (null: that row draws no link) */
  link: (shown: number) => Box | null;
  /** the box around the alert's own chain: the things joined by the links Python marked `in_chain` (null: none) */
  chain: () => Box | null;
}
export interface Box { x0: number; y0: number; x1: number; y1: number }
export interface Cam { x: number; y: number; k: number }
export interface MapOpts {
  r: number; off: number; col: number; laneH: number; left: number; right: number; top: number; bottom: number; stub: number;
  /** the smaller distance between two rails with nothing drawn between them (left out: every rail keeps `laneH`) */
  compact?: number;
}

/** The map's columns: Python's order; on a tie the program first, then Python's own list order. */
export function mapOrder<T extends { order: number; kind: string }>(nodes: T[]): T[] {
  return nodes.map((n, i) => ({ n, i })).sort((a, b) => a.n.order - b.n.order || Number(a.n.kind !== "process") - Number(b.n.kind !== "process") || a.i - b.i).map((x) => x.n);
}

export function buildMap(inv: Investigation, rows: Row[], o: MapOpts): MapScene {
  const L = inv.report.layout!;
  const lanes = Math.max(1, L.lanes.length);
  const rowAt = new Map(rows.map((r, i) => [r.id, i + 1]));
  const gapAt = new Map<string, number>();                    // a thing's FIRST "can't be known" row places its stub
  for (const r of rows) if (r.nodeId && !gapAt.has(r.nodeId)) gapAt.set(r.nodeId, rowAt.get(r.id)!);
  const band = new Map(rows.map((r) => [r.id, r.bandLabel ?? null]));

  // one column per thing, left to right in Python's order. Two things first seen in the same step share
  // an order: the program goes first (it acts, the other is acted on), then Python's own list order.
  // A thing that is not a program stands above or below its program's rail, in turn.
  const ordered = mapOrder(L.nodes);
  const seen = new Map<number, number>();
  const placed = ordered.map((n, column) => {
    const k = seen.get(n.lane) ?? 0;
    if (n.kind !== "process") seen.set(n.lane, k + 1);
    const side: -1 | 0 | 1 = n.kind === "process" ? 0 : k % 2 === 0 ? -1 : 1;
    return { n, x: o.left + column * o.col, side };
  });

  // How far apart two neighbouring rails must be: far enough that nothing of the upper one (a name under
  // its program, a thing below it and that thing's name) shares its place with anything of the lower one
  // (a thing above it and its name, the "?" over a program). Only things that stand over each other
  // count, so rails with nothing between them sit close. Never closer than `compact` (a story with too
  // many rails for the panel) or `laneH` (a story that fits is spread out). Every rail and thing is drawn.
  const base = Math.min(o.laneH, Math.max(o.compact ?? o.laneH, 2 * o.r + 28));
  const NAME = 16, CHAR = 9.9;                                    // a name's height and width per letter at its largest (x1.3)
  type Area = { x0: number; x1: number; top: number; bottom: number };
  const boxes = (lane: number): Area[] => placed.filter((p) => p.n.lane === lane).flatMap((p) => {
    const half = (Math.min(p.n.short.length, 26) * CHAR) / 2, c = p.side * o.off;
    const shape: Area = { x0: p.x - o.r, x1: p.x + o.r, top: c - o.r, bottom: c + o.r };
    const name: Area = p.side < 0 ? { x0: p.x - half, x1: p.x + half, top: c - o.r - 8 - NAME, bottom: c - o.r - 4 }
      : { x0: p.x - half, x1: p.x + half, top: c + o.r + 5, bottom: c + o.r + 9 + NAME };
    const unknown: Area[] = p.side === 0 && gapAt.has(p.n.id) ? [{ x0: p.x - 14, x1: p.x + 14, top: -(o.r + 7 + o.stub + 28), bottom: -o.r }] : [];
    return [shape, name, ...unknown];
  });
  const laneY: number[] = [o.top];
  for (let i = 1; i < lanes; i++) {
    let need = base;
    const upper = boxes(i - 1), lower = boxes(i);
    for (const u of upper) for (const l of lower) if (u.x0 < l.x1 + 6 && l.x0 < u.x1 + 6) need = Math.max(need, u.bottom - l.top + 6);
    laneY[i] = laneY[i - 1] + need;
  }

  const nodes = new Map<string, MapNode>();
  for (const p of placed) {
    const n = p.n;
    nodes.set(n.id, { id: n.id, short: n.short, kind: n.kind, icon: n.icon, lane: n.lane, x: p.x,
      y: (laneY[n.lane] ?? o.top + n.lane * o.laneH) + p.side * o.off, side: p.side, gapAt: gapAt.get(n.id) ?? null, at: gapAt.get(n.id) ?? Infinity });
  }
  const incoming = new Map<string, number>();
  const edges: MapEdge[] = [];
  const R = o.r;
  // Where a suspected link's word ("weak lead") may stand: not on a shape, not on a name, not on another
  // word (the sweep of 2026-11-21: of 47 words drawn, 27 stood on a shape and 14 on each other). It is
  // tried on the link first, then level at the link's middle, then beside it, a step further each time.
  const taken: Box[] = [];
  for (const n of nodes.values()) {
    const half = (Math.min(n.short.length, 26) * 7.6) / 2;
    taken.push({ x0: n.x - R - 4, x1: n.x + R + 4, y0: n.y - R - 4, y1: n.y + R + 4 });
    taken.push(n.side < 0 ? { x0: n.x - half, x1: n.x + half, y0: n.y - R - 24, y1: n.y - R - 4 } : { x0: n.x - half, x1: n.x + half, y0: n.y + R + 4, y1: n.y + R + 24 });
  }
  const wordBox = (x: number, y: number, ang: number): Box => {
    const c = Math.abs(Math.cos((ang * Math.PI) / 180)), sn = Math.abs(Math.sin((ang * Math.PI) / 180));
    const hw = 46 * c + 13 * sn, hh = 46 * sn + 13 * c;
    return { x0: x - hw, x1: x + hw, y0: y - hh, y1: y + hh };
  };
  const clear = (b: Box) => !taken.some((t) => b.x0 < t.x1 && t.x0 < b.x1 && b.y0 < t.y1 && t.y0 < b.y1);
  const placeWord = (on: [number, number, number], mid: [number, number], nx: number, ny: number): [number, number, number] => {
    const step = 16 + 44 * Math.abs(nx) + 11 * Math.abs(ny);
    const tries: [number, number, number][] = [on, [mid[0], mid[1], 0]];
    for (const d of [1, -1, 2, -2, 3, -3]) tries.push([mid[0] + nx * d * step, mid[1] + ny * d * step, 0]);
    const got = tries.find(([x, y, g]) => clear(wordBox(x, y, g))) ?? tries[2];
    taken.push(wordBox(got[0], got[1], got[2]));
    return got;
  };
  for (const e of [...L.edges].sort((a, b) => a.order - b.order)) {
    const a = nodes.get(e.u), b = nodes.get(e.v);
    if (!a || !b) continue;
    const at = rowAt.get(e.id);
    if (at === undefined) continue;                 // not in Python's timeline: never drawn
    a.at = Math.min(a.at, at); b.at = Math.min(b.at, at);
    const s = b.x >= a.x ? 1 : -1;
    const k = incoming.get(b.id) ?? 0;
    incoming.set(b.id, k + 1);
    // several links into the same thing fan out a little, so repeated actions stay countable
    const nudge = k === 0 ? 0 : Math.max(-R * 0.72, Math.min(R * 0.72, (k % 2 ? -1 : 1) * Math.ceil(k / 2) * R * 0.3));
    const word = e.grade === "hypothesis" ? band.get(e.id) ?? null : null;
    let d: string, lx: number, ly: number, ang = 0;
    if (a.kind !== "process" && b.kind !== "process") {
      // thing to thing (a suspected link): a straight line, trimmed at both shapes
      const len = Math.hypot(b.x - a.x, b.y - a.y) || 1, ux = (b.x - a.x) / len, uy = (b.y - a.y) / len;
      d = `M ${a.x + ux * (R + 6)} ${a.y + uy * (R + 6)} L ${b.x - ux * (R + 10)} ${b.y - uy * (R + 10)}`;
      lx = (a.x + b.x) / 2; ly = (a.y + b.y) / 2; ang = (Math.atan2(uy, ux) * 180) / Math.PI;
      if (ang > 90 || ang < -90) ang += 180;
      if (word) [lx, ly, ang] = placeWord([lx, ly, ang], [lx, ly], -uy, ux);
    } else {
      // along the source's own level, then one smooth turn into the target
      const sx = a.x + s * (R + 3), ex = b.x - s * (R + 9), ey = b.y + nudge;
      const turn = Math.min(o.col * 0.62, 84);
      const lead = s > 0 ? Math.max(sx, ex - turn) : Math.min(sx, ex + turn);
      d = `M ${sx} ${a.y} L ${lead} ${a.y} C ${lead + s * turn * 0.55} ${a.y}, ${ex - s * turn * 0.55} ${ey}, ${ex} ${ey}`;
      lx = (sx + lead) / 2; ly = a.y;
      if (word) {
        // the middle of the turn (the curve's own halfway point), and the direction across the link
        const p1x = lead + s * turn * 0.55, p2x = ex - s * turn * 0.55;
        const mx = 0.125 * lead + 0.375 * p1x + 0.375 * p2x + 0.125 * ex, my = 0.5 * a.y + 0.5 * ey;
        const len = Math.hypot(ex - lead, ey - a.y) || 1;
        [lx, ly, ang] = placeWord([lx, ly, 0], [mx, my], -(ey - a.y) / len, (ex - lead) / len);
      }
    }
    edges.push({ id: e.id, ink: e.grade, d, at, chain: e.in_chain, label: word, lx, ly, ang, sx: a.x, sy: a.y, tx: b.x, ty: b.y });
  }
  const list = [...nodes.values()];
  const rails = L.lanes.map((l) => {
    const p = list.find((n) => n.id === l.node_id) ?? list.find((n) => n.lane === l.lane && n.kind === "process");
    return p ? { y: p.y, x: p.x, at: p.at } : null;
  }).filter((x): x is { y: number; x: number; at: number } => !!x);
  const stubs = list.filter((n) => gapAt.has(n.id)).map((g) => (g.kind === "process"
    ? { id: g.id, d: `M ${g.x} ${g.y - R - 7 - o.stub} L ${g.x} ${g.y - R - 7}`, qx: g.x, qy: g.y - R - 7 - o.stub - 14, at: gapAt.get(g.id)! }
    : { id: g.id, d: `M ${g.x + R + 7 + o.stub} ${g.y} L ${g.x + R + 7} ${g.y}`, qx: g.x + R + 7 + o.stub + 14, qy: g.y, at: gapAt.get(g.id)! }));
  const width = o.left + Math.max(1, ordered.length - 1) * o.col + o.right, height = laneY[lanes - 1] + o.bottom;
  const focus = (shown: number) => {
    if (shown <= 0) return null;
    const e = edges.find((x) => x.at === shown);
    if (e) return { x: e.tx, y: e.ty };
    const n = list.find((x) => x.at === shown);
    return n ? { x: n.x, y: n.y } : null;
  };
  const around = (pts: [number, number][]): Box | null => (pts.length
    ? { x0: Math.min(...pts.map((p) => p[0])), y0: Math.min(...pts.map((p) => p[1])), x1: Math.max(...pts.map((p) => p[0])), y1: Math.max(...pts.map((p) => p[1])) }
    : null);
  const drawn = (shown: number) => {
    const pts: [number, number][] = [];
    for (const n of list) if (n.at <= shown) pts.push([n.x, n.y]);
    for (const s of stubs) if (s.at <= shown) pts.push([s.qx, s.qy]);
    return around(pts);
  };
  const link = (shown: number) => {
    const e = edges.find((x) => x.at === shown);
    return e ? around([[e.sx, e.sy], [e.tx, e.ty]]) : null;
  };
  const chain = () => around(edges.filter((e) => e.chain).flatMap((e): [number, number][] => [[e.sx, e.sy], [e.tx, e.ty]]));
  return { nodes: list, edges, rails, stubs, width, height, col: o.col, focus, drawn, link, chain };
}

/**
 * Where the camera stands when `shown` of `total` rows have been told, for a panel of w x h.
 * - While everything drawn so far fits readably, all of it is framed (and the frame widens as the story grows).
 * - A longer story is followed: the link being told is framed from its source to its target.
 * - At the end of a long story the camera returns to the alert's own chain (the links Python marked
 *   `in_chain`), so the last picture is what the alert is about, not wherever the last row happened to be.
 * It only moves and scales the picture: nothing is added, dropped or reordered here.
 */
export function camera(sc: MapScene, w: number, h: number, shown: number, total: number): Cam {
  if (!w || !h) return { x: 0, y: 0, k: 1 };
  const padX = 120, padTop = 64, padBottom = 86;                    // room for labels, the "?" above a program, and the arrow ahead
  const fit = (b: Box, least: number, most: number): Cam | null => {
    const bw = b.x1 - b.x0 + padX * 2, bh = b.y1 - b.y0 + padTop + padBottom;
    const k = Math.min(most, w / bw, h / bh);
    return k < least ? null : { x: w / 2 - ((b.x0 + b.x1) / 2) * k, y: (h - bh * k) / 2 - (b.y0 - padTop) * k, k };
  };
  const all = sc.drawn(shown) ?? sc.drawn(1) ?? { x0: 0, y0: 0, x1: sc.width, y1: sc.height };
  const whole = fit(all, 0.5, 1.45);
  if (whole) return whole;
  if (shown >= total) {
    const c = sc.chain();
    const end = c && (fit(c, 0.5, 1.1) ?? fit(c, 0.3, 1.1));
    if (end) return end;
  }
  const l = sc.link(shown);
  const one = l && fit(l, 0.5, 0.9);
  if (one) return one;
  const f = sc.focus(Math.max(1, shown)) ?? { x: all.x1, y: (all.y0 + all.y1) / 2 }, k = 0.8;
  return { x: w * 0.6 - f.x * k, y: h / 2 - f.y * k, k };
}

/**
 * WHEN Watch asks again for the story behind the newest alert's card (its steps and three counts).
 * It asks when the alert lands and whenever this word changes; never per poll.
 *
 * Found by the end-to-end run of 2026-11-24 (in the rehearsed build too): the word used to change only
 * when a VM run ended. A replay has no run, and its last records arrive after the alert, so a Watch page
 * left open kept the counts of the moment the alert landed ("7 Proven") while Story said 8.
 * Now the store going quiet is such a moment as well: no new record for PREVIEW_QUIET_S seconds, with the
 * number of records in the word, so each quiet stretch asks once, and a later one with more records asks
 * again. While records are still arriving the word stays what it was (the card never steps back to an
 * older answer).
 */
export const PREVIEW_QUIET_S = 6;
export function previewPhase(prev: string, running: boolean, records: number | null | undefined, seconds: number | null | undefined): string {
  if (running) return "running";
  if (typeof records === "number" && typeof seconds === "number" && seconds >= PREVIEW_QUIET_S) return `settled:${records}`;
  return prev === "running" ? "settled" : prev;      // a run that just ended: ask now, as always
}

/**
 * What a screen says when it has no alert to show. A recording that is whole and has none: Python's
 * `no_alerts` ("No alerts have been raised in this recording."). A replay that is still playing: Python's
 * own sentence for that moment (GET /api/health `replay_playing`), because "in this recording" would be a
 * statement about records that have not arrived yet (seen 2026-11-24, 14 of 85 records in).
 */
export function noAlertsText(health: { replay_playing?: { text?: string | null } | null } | null | undefined, noAlerts: string): string {
  return health?.replay_playing?.text || noAlerts;
}
