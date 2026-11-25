import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { countOf, heat, Matrix, type MapData } from "./index";

const cell = (id: string, alerts: number, rules: number, floor: number) => ({ id, name: `name ${id}`, alerts, rules, rules_floor: floor, subs: [] });
const d: MapData = {
  words: {}, min_level: "medium", attack: { available: true, version: "99", techniques: 3, legal: "" },
  tactics: [{ id: "TA0002", shortname: "execution", name: "Execution", techniques: [cell("T1059", 3, 2, 2), cell("T1106", 0, 1, 0)] },
            { id: "TA0005", shortname: "stealth", name: "Stealth", techniques: [cell("T1497", 0, 0, 0)] }],
};
const html = (mode: "alerts" | "coverage", onlyLit = false, floorOnly = true) =>
  renderToStaticMarkup(<Matrix d={d} mode={mode} floorOnly={floorOnly} onlyLit={onlyLit} selected="T1059.001" p={new URLSearchParams("mode=coverage")} />);

describe("the ATT&CK matrix", () => {
  it("counts per mode", () => {
    expect(countOf(d.tactics![0].techniques[0], "alerts", true)).toBe(3);
    expect(countOf(d.tactics![0].techniques[1], "coverage", true)).toBe(0);
    expect(countOf(d.tactics![0].techniques[1], "coverage", false)).toBe(1);
  });
  it("heat: zero stays dark, one still shows, the most is brightest", () => {
    expect([heat(0, 100), heat(1, 100) >= 1, heat(100, 100)]).toEqual([0, true, 4]);
    expect(heat(1, 1)).toBe(4);
  });
  it("one column per tactic, a box per technique; only-lit hides the dark ones", () => {
    const all = html("alerts");
    expect((all.match(/class="tq-col"/g) ?? []).length).toBe(2);
    expect((all.match(/class="tq-cell"/g) ?? []).length).toBe(3);
    expect((html("alerts", true).match(/class="tq-cell"/g) ?? []).length).toBe(1);
    expect((html("alerts", true).match(/class="tq-col"/g) ?? []).length).toBe(1);          // the empty column goes too
    expect((html("coverage", true, false).match(/class="tq-cell"/g) ?? []).length).toBe(2);
  });
  it("a parent box is marked when its sub-technique is selected, and links keep the other params", () => {
    const h = html("alerts");
    expect(h).toContain('aria-current="true"');
    expect(h).toContain('href="#/labs/techniques?mode=coverage&amp;technique=T1106"');
  });
});
