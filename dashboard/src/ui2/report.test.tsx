// The Report view lists exactly the rows the film tells, in the same order (Python's), each in its own
// ink, and shows only sentences the API sent. Rendered to plain HTML (no browser needed).
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { Words } from "../api";
import { LiveProvider, type Live } from "./hooks";
import { rowsOf } from "./logic";
import Report from "./Report";
import { sample } from "./testdata";

const words = {
  inks: { fact: { word: "WORD-FACT", explain: "x" }, hypothesis: { word: "WORD-HYPO", explain: "x" }, gap: { word: "WORD-GAP", explain: "x" } },
  steps_title: "STEPS", limits_title: "LIMITS", evidence_title: "EVIDENCE", evidence_hint: "HINT", offset_note: "from {ref}", events: {},
} as unknown as Words;
const live = { words, mode: null, modeKnown: true, devOk: false, health: null, steps: null, alerts: [], error: null, landed: new Map(), arrivals: [], elapsed: null,
  run: async () => {}, runPending: false, runError: null } as Live;

function html(inv = sample()) {
  return renderToStaticMarkup(<LiveProvider value={live}><Report inv={inv} rows={rowsOf(inv)} /></LiveProvider>);
}
const stepIds = (h: string) => [...h.matchAll(/data-step-id="([^"]+)"/g)].map((m) => m[1]);

describe("the Report view and the film tell the same rows", () => {
  it("lists every film row once, in the film's order", () => {
    const inv = sample(), film = rowsOf(inv).map((r) => r.id);
    expect(stepIds(html(inv))).toEqual(film);
    expect(film).toEqual(inv.report.timeline.map((t) => t.id));       // and that order is Python's
  });
  it("follows Python's order even when ids and times would sort differently", () => {
    const inv = sample();
    inv.report.timeline.reverse();
    expect(stepIds(html(inv))).toEqual(["h1", "e7", "e2", "e9", "g1"]);
  });
  it("keeps each row's ink: a suspected row is never listed as a fact", () => {
    const h = html();
    const ink = (id: string) => new RegExp(`data-step-id="${id}" data-ink="([a-z]+)"`).exec(h)?.[1];
    expect([ink("g1"), ink("e9"), ink("e2"), ink("e7"), ink("h1")]).toEqual(["gap", "fact", "fact", "fact", "hypothesis"]);
    expect(h).toContain("WORD-HYPO · weak lead");                    // the band word travels with the suspected row
  });
  it("shows the API's sentences and limits, and adds none of its own", () => {
    const inv = sample();
    inv.report.limitations = ["LIMIT-ONE", "LIMIT-TWO"];
    const h = html(inv);
    for (const t of inv.report.timeline) expect(h).toContain(t.short);
    expect(h).toContain("LIMIT-ONE");
    expect(h).toContain("LIMIT-TWO");
    expect(h).toContain("process start (Sysmon 1), record 1");       // the selected step's recorded proof (step 1 opens first)
  });
});
