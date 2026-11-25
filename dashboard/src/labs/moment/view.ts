// Pure helpers of the "Around this moment" timeline: the visible range, zooming and the tick marks.

export type Range = [number, number];

/** Zoom the range by `factor` (<1 = in) around the point `at` (seconds), never wider than `limit`. */
export function zoomAt(r: Range, factor: number, at: number, limit: Range): Range {
  const span = Math.max(0.05, (r[1] - r[0]) * factor);
  const maxSpan = limit[1] - limit[0];
  if (span >= maxSpan) return [...limit] as Range;
  const k = (at - r[0]) / (r[1] - r[0] || 1);
  let a = at - k * span, b = a + span;
  if (a < limit[0]) { a = limit[0]; b = a + span; }
  if (b > limit[1]) { b = limit[1]; a = b - span; }
  return [a, b];
}

/** Move the range by `delta` seconds, kept inside `limit`. */
export function pan(r: Range, delta: number, limit: Range): Range {
  const span = r[1] - r[0];
  let a = r[0] + delta;
  a = Math.max(limit[0], Math.min(limit[1] - span, a));
  return [a, a + span];
}

const STEPS = [0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 1200];

/** Tick positions (seconds) for about `want` ticks over the range, on round steps. */
export function ticks(r: Range, want = 8): number[] {
  const span = r[1] - r[0];
  const step = STEPS.find((s) => span / s <= want) ?? STEPS[STEPS.length - 1];
  const out: number[] = [];
  for (let t = Math.ceil(r[0] / step) * step; t <= r[1] + 1e-9; t += step) out.push(Math.round(t * 1000) / 1000);
  return out;
}

/** "+1.25 s", "−30 s", "0" for a tick or an offset. */
export function offsetText(s: number): string {
  if (Math.abs(s) < 1e-9) return "0";
  const a = Math.abs(s);
  const v = a >= 10 ? a.toFixed(a % 1 ? 1 : 0) : a >= 1 ? a.toFixed(a % 1 ? 2 : 0) : a.toFixed(3);
  return `${s < 0 ? "−" : "+"}${v.includes(".") ? v.replace(/\.?0+$/, "") : v} s`;
}
