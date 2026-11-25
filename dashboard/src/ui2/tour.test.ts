import { describe, expect, it } from "vitest";
import { placeBubble } from "./Tour";

const win = { w: 1463, h: 780 }, bubble = { w: 420, h: 200 };
const inside = (p: { x: number; y: number }) => p.x >= 12 && p.y >= 12 && p.x + bubble.w <= win.w - 12 && p.y + bubble.h <= win.h - 12;
const overlaps = (p: { x: number; y: number }, t: { x: number; y: number; w: number; h: number }) =>
  p.x < t.x + t.w && p.x + bubble.w > t.x && p.y < t.y + t.h && p.y + bubble.h > t.y;

describe("where the tour's bubble goes", () => {
  it("sits under the part when there is room, and never on it", () => {
    const top = { x: 0, y: 0, w: 1463, h: 52 };                           // the top bar
    const p = placeBubble(top, bubble, win);
    expect(p.y).toBe(52 + 14);
    expect(inside(p)).toBe(true);
    expect(overlaps(p, top)).toBe(false);
  });

  it("goes above a part at the foot of the window", () => {
    const foot = { x: 20, y: 700, w: 1400, h: 60 };                       // the story's play bar
    const p = placeBubble(foot, bubble, win);
    expect(p.y + bubble.h).toBe(700 - 14);
    expect(inside(p)).toBe(true);
    expect(overlaps(p, foot)).toBe(false);
  });

  it("goes beside a tall part, on the side that has room", () => {
    const left = { x: 20, y: 60, w: 360, h: 700 };                        // the test machine panel
    const p = placeBubble(left, bubble, win);
    expect(p.x).toBe(20 + 360 + 14);
    expect(inside(p)).toBe(true);
    expect(overlaps(p, left)).toBe(false);
    const right = { x: 1080, y: 60, w: 360, h: 700 };
    const q = placeBubble(right, bubble, win);
    expect(q.x + bubble.w).toBe(1080 - 14);
    expect(overlaps(q, right)).toBe(false);
  });

  it("stays inside the window for a part as big as the window, and in the middle when there is no part", () => {
    expect(inside(placeBubble({ x: 0, y: 0, w: 1463, h: 780 }, bubble, win))).toBe(true);
    const c = placeBubble(null, bubble, win);
    expect(c).toEqual({ x: (1463 - 420) / 2, y: (780 - 200) / 2 });
    // a part near the right edge: the bubble is pushed back inside
    const edge = placeBubble({ x: 1400, y: 10, w: 50, h: 30 }, bubble, win);
    expect(inside(edge)).toBe(true);
    // a window smaller than the bubble never throws it off the left or top edge
    const tiny = placeBubble(null, bubble, { w: 300, h: 150 });
    expect(tiny.x).toBe(12);
    expect(tiny.y).toBe(12);
  });
});
