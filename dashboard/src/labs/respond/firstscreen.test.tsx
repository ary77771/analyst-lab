// The e2e review of the professor's path (2026-11-24): the first screen shows MITRE's short words and keeps the
// long ones folded, and prove labels the other explanation and shows short command lines first.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { NextView, splitFirst, type Next } from "./index";
import { ProveView, type Prove } from "../prove/index";

describe("What to do next: short words first", () => {
  it("cuts MITRE's description after its first sentence", () => {
    expect(splitFirst("Adversaries may transfer tools. Tools may be copied (e.g. ftp). More.")).toEqual(["Adversaries may transfer tools.", "Tools may be copied (e.g. ftp). More."]);
    expect(splitFirst("One sentence only.")).toEqual(["One sentence only.", ""]);
    expect(splitFirst("")).toEqual(["", ""]);
  });
  it("the mitigation's own short description is shown; MITRE's how-it-applies note and D3FEND's link lines are folded", () => {
    const words = { tactics: {}, how_title: "HOW-T", links_title: "LINKS-T", technique_more: "MORE-T", link_words: "{defence} LINK", more_links: "+{n}",
      source_attack: "", source_d3fend: "" } as unknown as Next["words"];
    const d = { words, rule_tags: [], alert: { id: "a1", title: "A", level: "high", time: "t", host: "h", source: "sigma", rule_id: "r", reason: "", declared: false },
      attack: { available: true, version: "1" }, d3fend: { available: true, version: "1" },
      techniques: [{ id: "T1105", name: "Ingress", url: "u", description: "First one. Second one.",
        mitigations: [{ id: "M1", name: "N", url: "mu", how: "LONG-HOW", description: "SHORT-DESC" }],
        d3fend: { via: "T1105", count: 1, url: "du", tactics: [{ tactic: "Isolate", techniques: [{ id: "D3-X", name: "X", definition: "DEF",
          links: [{ defence: "X", defence_rel: "", artifact: "", attack_rel: "", attack_artifact: "" }], more_links: 0 }] }] } }] } as unknown as Next;
    const h = renderToStaticMarkup(<NextView d={d} />);
    expect(h.indexOf("SHORT-DESC")).toBeLessThan(h.indexOf("HOW-T"));
    expect(h.indexOf("LONG-HOW")).toBeGreaterThan(h.indexOf("HOW-T"));
    expect(h.indexOf("X LINK")).toBeGreaterThan(h.indexOf("LINKS-T"));
    expect(h.indexOf("Second one.")).toBeGreaterThan(h.indexOf("MORE-T"));
  });
});

describe("What would prove it: first screen", () => {
  it("labels the other explanation and shows the short command line and fingerprint first", () => {
    const words = { inks: { hypothesis: "INK-H", gap: "INK-G" }, verdict: {}, verdict_note: {}, state: {}, alternative: "OTHER", full_lines: "SHOW-ALL",
      fingerprint_title: "FP", corroborating: "CORR" } as unknown as Prove["words"];
    const d = { words, story: true, config: [], alert: { id: "a1", title: "A", level: "high", time: "t", host: "h", source: "sigma", rule_id: "r", reason: "", declared: false },
      lines: [{ ink: "hypothesis", kind: "content_from", text: "L", band: "low", alternative: "ALT", time: null, witness: null,
        corroborating: [{ image: "f.exe", pid: 1, command_line: "LONG-CMD", command_short: "SHORT-CMD", names: "x" }],
        fingerprint: { sha256: "FULLSHA", sha_short: "SHORTSHA", file: "p.exe", programs: [{ image: "f.exe", pid: 1, command_line: "LONG-CMD", command_short: "SHORT-CMD" }] } }] } as unknown as Prove;
    const h = renderToStaticMarkup(<ProveView d={d} />);
    expect(h).toContain("OTHER: </span>ALT");
    expect(h.indexOf("SHORT-CMD")).toBeLessThan(h.indexOf("SHOW-ALL"));
    expect(h.indexOf("SHORTSHA")).toBeLessThan(h.indexOf("SHOW-ALL"));
    expect(h.indexOf("LONG-CMD")).toBeGreaterThan(h.indexOf("SHOW-ALL"));
  });
});
