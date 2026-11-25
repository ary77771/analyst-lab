// The ATT&CK map's calm first screen (2026-11-24): one sentence, the lit techniques once each, the matrix behind a
// toggle. A coverage check, not an alarm.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { CalmSummary, litTechniques, type MapData } from "./index";

const cell = (id: string, alerts: number) => ({ id, name: `name ${id}`, alerts, rules: 0, rules_floor: 0, subs: [] });
const words = { calm_title: "CALM", calm_intro: "INTRO", calm_none: "NONE", calm_one: "ONE", calm_many: "{n} MANY", calm_reading: "OURS" };
const d: MapData = { words, min_level: "medium", attack: { available: true, version: "20.1", techniques: 3, legal: "" },
  totals: { alerts_reading: 1 },
  tactics: [{ id: "TA0011", shortname: "c2", name: "Command and Control", techniques: [cell("T1105", 1), cell("T1071", 0)] },
            { id: "TA0002", shortname: "ex", name: "Execution", techniques: [cell("T1059", 3)] },
            { id: "TA0008", shortname: "lm", name: "Lateral Movement", techniques: [cell("T1105", 1)] }] };

describe("ATT&CK map, calm first screen", () => {
  it("lists each lit technique once, with all its goals, most alerts first", () => {
    expect(litTechniques(d)).toEqual([
      { id: "T1059", name: "name T1059", n: 3, tactics: ["Execution"] },
      { id: "T1105", name: "name T1105", n: 1, tactics: ["Command and Control", "Lateral Movement"] }]);
  });
  it("says what the map is, names the lit techniques, and that our own rule's label is ours", () => {
    const h = renderToStaticMarkup(<CalmSummary d={d} p={new URLSearchParams()} />);
    for (const s of ["CALM", "INTRO", "T1105", "Command and Control, Lateral Movement", "ONE", "3 MANY", "OURS"]) expect(h).toContain(s);
    expect(h).not.toContain("T1071");
  });
  it("says so plainly when nothing is lit", () => {
    const none = { ...d, tactics: [{ ...d.tactics![0], techniques: [cell("T1071", 0)] }] };
    const h = renderToStaticMarkup(<CalmSummary d={none} p={new URLSearchParams()} />);
    expect(h).toContain("NONE");
    expect(h).not.toContain("OURS");
  });
});

describe("ATT&CK map against a server older than the page", () => {
  it("never shows a bare row: the heading and counts have plain fallbacks", () => {
    const h = renderToStaticMarkup(<CalmSummary d={{ ...d, words: {} }} p={new URLSearchParams()} />);
    expect(h).toContain("What the alerts here point to");
    expect(h).toContain("1 alert");
    expect(h).toContain("3 alerts");
  });
});

