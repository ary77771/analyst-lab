// The replay lab's clock: which rows of a story are on screen at a recorded second.
// The map draws rows as a prefix of Python's order (it never reorders them), so the times used here are
// made never-decreasing along that order: a row with no recorded time, or one recorded earlier than the
// row before it, appears together with the row before it.

/** The second (counted from the alert's first step) at which each row appears, in the rows' own order. */
export function rowTimes(rows: { id: string }[], offsets: Map<string, number | null | undefined>): number[] {
  const out: number[] = [];
  let last: number | null = null;
  for (const r of rows) {
    const t = offsets.get(r.id);
    const at: number = typeof t === "number" && Number.isFinite(t) ? (last === null ? t : Math.max(last, t)) : (last ?? 0);
    out.push(at);
    last = at;
  }
  return out;
}

/** How many rows are on screen at second `t` (every row whose time has been reached). */
export function shownAt(times: number[], t: number): number {
  let n = 0;
  while (n < times.length && times[n] <= t + 1e-9) n++;
  return n;
}

/** The stretch the slider covers: from a moment before the first row to a moment after the last. */
export function span(times: number[], lead = 1, tail = 0.5): { from: number; to: number } {
  if (times.length === 0) return { from: 0, to: 0 };
  return { from: times[0] - lead, to: times[times.length - 1] + tail };
}

/**
 * One tick of the clock: `t` moved on by `dt` seconds of real time at `speed`. With `skip`, a wait of more
 * than `quiet` recorded seconds before the next row is jumped to one second before that row (the jump is
 * returned, so the screen can say how much recorded time was skipped). Never past `to`.
 */
export function advance(times: number[], t: number, dt: number, speed: number, to: number, skip: boolean, quiet = 3): { t: number; skipped: number } {
  let next = t + dt * speed, skipped = 0;
  if (skip) {
    const upcoming = times.find((x) => x > t + 1e-9);
    if (upcoming !== undefined && upcoming - t > quiet) { skipped = upcoming - 1 - t; next = upcoming - 1; }
  }
  return { t: Math.min(to, next), skipped };
}

/** "12.4 s", "-0.2 s", "2 min 05 s": a recorded offset in plain form. */
export function seconds(t: number): string {
  const sign = t < -0.05 ? "-" : "", a = Math.abs(t);
  if (a < 60) return `${sign}${a.toFixed(1)} s`;
  const m = Math.floor(a / 60), s = Math.floor(a - m * 60);
  return `${sign}${m} min ${String(s).padStart(2, "0")} s`;
}
