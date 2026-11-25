import { describe, expect, it } from "vitest";
import { advance, rowTimes, seconds, shownAt, span } from "./time";

const rows = ["a", "b", "c", "d", "e"].map((id) => ({ id }));

describe("the replay lab's clock", () => {
  it("gives every row its recorded second, never going backwards along Python's order", () => {
    const t = rowTimes(rows, new Map<string, number | null>([["a", -0.2], ["b", 0], ["c", null], ["d", 10.1], ["e", 9.5]]));
    expect(t).toEqual([-0.2, 0, 0, 10.1, 10.1]);                      // no time: with the row before; an earlier time: with the row before
    expect(rowTimes(rows, new Map())).toEqual([0, 0, 0, 0, 0]);       // nothing recorded: all at once, never invented times
    expect(rowTimes([], new Map())).toEqual([]);
  });

  it("shows exactly the rows whose time has been reached, and never drops one", () => {
    const t = [-0.2, 0, 0, 10.1, 10.1];
    expect(shownAt(t, -1)).toBe(0);
    expect(shownAt(t, -0.2)).toBe(1);
    expect(shownAt(t, 0)).toBe(3);
    expect(shownAt(t, 10)).toBe(3);
    expect(shownAt(t, 10.1)).toBe(5);
    expect(shownAt(t, 999)).toBe(5);
    let last = 0;
    for (let x = -2; x <= 12; x += 0.05) { const n = shownAt(t, x); expect(n).toBeGreaterThanOrEqual(last); last = n; }
  });

  it("covers the whole story with the slider", () => {
    expect(span([-0.2, 0, 10.1])).toEqual({ from: -1.2, to: 10.6 });
    expect(span([])).toEqual({ from: 0, to: 0 });
  });

  it("plays at the chosen speed, stops at the end, and says how much waiting it skipped", () => {
    const t = [0, 0.1, 10.1];
    expect(advance(t, 0, 0.5, 1, 10.6, false)).toEqual({ t: 0.5, skipped: 0 });
    expect(advance(t, 0, 0.5, 4, 10.6, false)).toEqual({ t: 2, skipped: 0 });
    expect(advance(t, 10.5, 1, 1, 10.6, false)).toEqual({ t: 10.6, skipped: 0 });
    const j = advance(t, 0.2, 0.016, 1, 10.6, true);                 // 9.9 s of nothing ahead: jump to one second before the next row
    expect(j.t).toBeCloseTo(9.1);
    expect(j.skipped).toBeCloseTo(8.9);
    expect(advance(t, 9.1, 0.5, 1, 10.6, true)).toEqual({ t: 9.6, skipped: 0 });      // within the quiet limit: plain time
    const plain = advance(t, 10.2, 0.2, 1, 10.6, true);                               // nothing ahead: plain time
    expect(plain.t).toBeCloseTo(10.4);
    expect(plain.skipped).toBe(0);
  });

  it("writes a recorded offset in plain form", () => {
    expect(seconds(0)).toBe("0.0 s");
    expect(seconds(12.44)).toBe("12.4 s");
    expect(seconds(-0.2)).toBe("-0.2 s");
    expect(seconds(125)).toBe("2 min 05 s");
  });
});
