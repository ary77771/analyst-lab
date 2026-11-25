// Story diff page: the twin pair by default, Python's words, three columns, "no differences" when the same.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { defaultPair, DiffView, lab, runLabel, type Diff, type Run } from "./index";
import { AlertScope } from "../fileinspect/alertscope";

const run = (id: string, scenario: string): Run => ({ id, scenario, start: null, replayed: null, exit_code: 0 });
const words = {
  title: "T", intro: "I", kinds: {}, only_a: "ONLY-A", both: "BOTH", only_b: "ONLY-B", own_steps: "OWN", everything: "ALL",
  raised: "RAISED", below: "BELOW", same: "SAME-WORDS", general: "GEN", none: "NONE",
};
const split = (a: string[], both: string[], b: string[]) => ({
  a: a.length + both.length, b: b.length + both.length,
  only_a: a.map((t) => ({ rule: t, title: t, level: "high", count: 1 })), both: both.map((t) => ({ rule: t, title: t, level: "low", count: 1 })),
  only_b: b.map((t) => ({ rule: t, title: t, level: "medium", count: 1 })),
});
const diff = (over: Partial<Diff>): Diff => ({
  a: run("20261120-011832-4287", "B18"), b: run("20261120-013940-301b", "B19"),
  summary: [{ kind: "created", word: "Created a file", a: 10, b: 24, who: "both" }, { kind: "connected", word: "Connected out", a: 1, b: 0, who: "only_a" }],
  kinds: [{ kind: "connected", word: "Connected out", only_a: [{ key: "10.0.2.2:18765", count: 1, examples: [] }], both: [], only_b: [] }],
  alerts: { raised: split(["Cmdkey", "Wipe after connect"], [], []), below: split(["Accounts"], [], ["Wipe"]) },
  differences: 5, same: false, own_processes: { a: 2, b: 1 }, everything: false, ...over,
});

describe("story diff", () => {
  it("is a lab the registry accepts", () => {
    expect(lab.id).toBe("storydiff");
    expect(typeof lab.Component).toBe("function");
  });

  it("opens on the Evil twin pair when both runs are here", () => {
    const runs = [run("3", "S1"), run("2", "B19"), run("1", "B18")];
    expect(defaultPair(runs)).toEqual(["1", "2"]);
    expect(defaultPair([run("3", "S1"), run("2", "S2")])).toEqual(["3", "2"]);
    expect(runLabel(run("20261120-011832-4287", "B18"))).toBe("B18 · 2026-11-20 01:18");
  });

  it("shows the alerts in three columns and the steps side by side", () => {
    const h = renderToStaticMarkup(<DiffView d={diff({})} words={words} />);
    expect(h).toContain("RAISED: A 2 · B 0");
    expect(h).toContain("Cmdkey");
    expect(h).toContain("10.0.2.2:18765");
    expect(h).toContain("OWN GEN");
    expect(h.match(/data-side="only_a"/g)?.length).toBeGreaterThan(2);
  });

  it("says plainly when there is no difference", () => {
    const h = renderToStaticMarkup(<DiffView d={diff({ same: true, differences: 0 })} words={words} />);
    expect(h).toContain("SAME-WORDS");
  });

  it("names runs in everyday words when the names are there (wave 3)", () => {
    expect(runLabel(run("20261120-011832-4287", "B18"), (id) => `${id} · Fake sync app`)).toBe("B18 · Fake sync app · 2026-11-20 01:18");
  });

  it("says which alert a page is about, with a way back to everything", () => {
    const h = renderToStaticMarkup(<AlertScope alert="a1" title="TITLE" onClear={() => {}} what="Run A is the test run" />);
    expect(h).toContain("Run A is the test run for the alert ");
    expect(h).toContain("<b>TITLE</b>");
    expect(h).toContain("show everything instead");
    expect(renderToStaticMarkup(<AlertScope alert={null} onClear={() => {}} what="x" />)).toBe("");
  });
});

