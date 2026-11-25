import { describe, expect, it } from "vitest";
import { LEFTOVER_MS, activeCase, caseTitle, isLeftover, pinFromParams, pinHref, setActiveCase, visibleCases } from "./pin";

describe("pinning from any lab", () => {
  it("round-trips a pin through the address", () => {
    const h = pinHref({ type: "entity", ref: "C:\\a&b+c.exe", label: "a&b+c.exe", kind: "file", time: "2026-10-22T10:00:00Z" });
    expect(h.startsWith("#/labs/cases?")).toBe(true);
    const p = pinFromParams(new URLSearchParams(h.slice(h.indexOf("?") + 1)));
    expect(p).toEqual({ type: "entity", ref: "C:\\a&b+c.exe", label: "a&b+c.exe", kind: "file", time: "2026-10-22T10:00:00Z", host: null });
  });

  it("ignores addresses without a usable pin", () => {
    expect(pinFromParams(new URLSearchParams("case=c-1"))).toBeNull();
    expect(pinFromParams(new URLSearchParams("pin=rumour&ref=x"))).toBeNull();
    expect(pinFromParams(new URLSearchParams("pin=alert"))).toBeNull();
    expect(pinFromParams(new URLSearchParams("pin=alert&ref=abc"))?.label).toBe("abc");
  });

  it("remembers the open case", () => {
    const box: Record<string, string> = {};
    const store = { getItem: (k: string) => box[k] ?? null, setItem: (k: string, v: string) => { box[k] = v; }, removeItem: (k: string) => { delete box[k]; } };
    expect(activeCase(store)).toBeNull();
    setActiveCase("c-20261123-000000-abcdef", store);
    expect(activeCase(store)).toBe("c-20261123-000000-abcdef");
    setActiveCase(null, store);
    expect(activeCase(store)).toBeNull();
  });
});

describe("a new case is named after what started it", () => {
  const when = new Date("2026-11-24T03:04:00Z");
  it("names an alert's case after the run and the alert", () => {
    expect(caseTitle({ type: "alert", ref: "a1", label: "Program connected out" }, "S1 \u00b7 Download and run", when))
      .toBe("S1 \u00b7 Download and run: Program connected out");
    expect(caseTitle({ type: "alert", ref: "a1", label: "Program connected out" }, null, when)).toBe("Program connected out");
  });
  it("falls back to the date only when nothing better is known", () => {
    expect(caseTitle({ type: "entity", ref: "x", label: "x.exe", kind: "file" }, null, when)).toBe("Case 2026-11-24 03:04");
    expect(caseTitle({ type: "entity", ref: "x", label: "x.exe", kind: "file" }, "S1 \u00b7 Download and run", when))
      .toBe("S1 \u00b7 Download and run: x.exe");
  });
});

describe("drafts stay out of the way", () => {
  const row = (id: string, draft: boolean) => ({ id, title: id, created: "", updated: "", pins: 1, notes: 0, draft });
  const rows = [row("named", false), row("d1", true), row("d2", true)];
  it("hides drafts unless asked, open or active", () => {
    expect(visibleCases(rows, false, null, null).map((r) => r.id)).toEqual(["named"]);
    expect(visibleCases(rows, false, "d1", null).map((r) => r.id)).toEqual(["named", "d1"]);
    expect(visibleCases(rows, false, null, "d2").map((r) => r.id)).toEqual(["named", "d2"]);
    expect(visibleCases(rows, true, null, null).length).toBe(3);
  });
});

describe("a leftover draft never receives a pin", () => {
  const now = Date.parse("2026-11-24T20:00:00Z");
  const row = (draft: boolean, updated: string) => ({ id: "c", title: "Untitled case", created: updated, updated, pins: 1, notes: 0, draft });
  it("an old untouched draft is a leftover; a fresh one or a real case is not", () => {
    expect(isLeftover(row(true, "2026-11-24T16:57:00Z"), now)).toBe(true);
    expect(isLeftover(row(true, new Date(now - LEFTOVER_MS + 60_000).toISOString()), now)).toBe(false);
    expect(isLeftover(row(false, "2026-11-24T16:57:00Z"), now)).toBe(false);
    expect(isLeftover(undefined, now)).toBe(false);
  });
});
