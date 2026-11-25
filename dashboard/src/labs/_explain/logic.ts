// Pure helpers shared by the night-explain labs (why, techniques, next, moment). No words live here:
// every sentence the pages show comes from Python (engine/labs/*.py). Links between labs: registry.labHref.

export interface Piece { text: string; hit: boolean }

/** Cut `value` into plain and highlighted pieces at the [start, end) spans Python sent (merged, in order).
 *  Spans outside the text are clipped; overlapping spans are merged. */
export function pieces(value: string, spans: number[][] = []): Piece[] {
  const clean = spans
    .map(([s, e]) => [Math.max(0, Math.min(s, value.length)), Math.max(0, Math.min(e, value.length))])
    .filter(([s, e]) => e > s)
    .sort((a, b) => a[0] - b[0]);
  const merged: number[][] = [];
  for (const [s, e] of clean) {
    const last = merged[merged.length - 1];
    if (last && s <= last[1]) last[1] = Math.max(last[1], e);
    else merged.push([s, e]);
  }
  const out: Piece[] = [];
  let at = 0;
  for (const [s, e] of merged) {
    if (s > at) out.push({ text: value.slice(at, s), hit: false });
    out.push({ text: value.slice(s, e), hit: true });
    at = e;
  }
  if (at < value.length || out.length === 0) out.push({ text: value.slice(at), hit: false });
  return out;
}

/** Fill "{name}" slots in a Python sentence. */
export function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (m, k) => (k in values ? String(values[k]) : m));
}
