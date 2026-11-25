import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { MomentView, type Moment } from "./index";
import { offsetText, pan, ticks, zoomAt } from "./view";

describe("timeline range", () => {
  it("zooms around the pointer and never past the window", () => {
    expect(zoomAt([-30, 30], 0.5, 0, [-30, 30])).toEqual([-15, 15]);
    expect(zoomAt([-30, 30], 0.5, 30, [-30, 30])).toEqual([0, 30]);
    expect(zoomAt([-10, 10], 4, 0, [-30, 30])).toEqual([-30, 30]);
  });
  it("pans inside the window", () => {
    expect(pan([-10, 10], 50, [-30, 30])).toEqual([10, 30]);
    expect(pan([-10, 10], -5, [-30, 30])).toEqual([-15, 5]);
  });
  it("ticks on round steps; offsets in plain seconds", () => {
    expect(ticks([-30, 30])).toEqual([-30, -20, -10, 0, 10, 20, 30]);
    expect(ticks([-1, 1]).length).toBeGreaterThan(3);
    expect([offsetText(0), offsetText(2), offsetText(-1.5), offsetText(0.25), offsetText(12.5)]).toEqual(["0", "+2 s", "−1.5 s", "+0.25 s", "+12.5 s"]);
    expect([offsetText(-30), offsetText(10), offsetText(120), offsetText(0.1)]).toEqual(["−30 s", "+10 s", "+120 s", "+0.1 s"]);   // "−3 s" for −30 was a real bug
  });
});

const words = { intro: "", seconds: "W", zoom_in: "+", zoom_out: "-", reset: "R", zoom_hint: "", anchor_alert: "AA", anchor_event: "AE",
  alert_evidence: "EV", own_tools: "OWN", events: "e", programs: "p", truncated: "CUT {max}", empty: "EMPTY", machine: "MACHINE", started_by: "by",
  center: "C", why: "WHY", fields: "F", kinds: { process: "P", file: "FI" } } as unknown as Moment["words"];
const lane = (id: string, label: string, own = false, anchor = false) => ({ id, label, image: label, pid: 1, parent: "cmd.exe", first: "t", count: 1, anchor, alerts: 0, own_tool: own, started_here: true });
const ev = (key: string, lane: string, offset: number, anchor = false, alerts: string[] = []) =>
  ({ key, lane, t: "t", offset, event_id: 1, type: null, kind: "process", name: "process start", what: `what-${key}`, anchor, alerts, own_tool: false, fields: [["Image", "x"]] as [string, string][] });
const d: Moment = { words, anchor: { kind: "alert", id: "a1", title: "T", level: "high", time: "t", host: "h" },
  window: { start: "s", end: "e", seconds: 30, t0: "t" }, total: 3, shown: 3, truncated: false, max_rows: 3000,
  lanes: [lane("{A}", "a.exe", false, true), lane("{T}", "tool.exe", true)],
  events: [ev("k1", "{A}", 0, true), ev("k2", "{A}", 5, false, ["alert-2"]), ev("k3", "{T}", 1)] };

describe("the moment page", () => {
  it("one lane per program; the anchor and alert evidence are marked; our own tools hidden by default", () => {
    const h = renderToStaticMarkup(<MomentView d={d} seconds={30} />);
    expect(h).toContain("a.exe (1)");
    expect(h).not.toContain("tool.exe (1)");
    expect(h).toContain("OWN (1)");
    expect((h.match(/<circle[^>]*data-anchor="true"/g) ?? []).length).toBe(1);
    expect((h.match(/<circle[^>]*data-alert="true"/g) ?? []).length).toBe(1);
    expect(h).toContain('href="#/labs/moment?event=k1&amp;seconds=30"');   // the anchor's own detail is open, with "center here"
    expect(h).toContain("−30 s … +30 s");
  });
  it("says when the window was cut", () => {
    expect(renderToStaticMarkup(<MomentView d={{ ...d, truncated: true }} seconds={30} />)).toContain("CUT 3000");
  });
});
