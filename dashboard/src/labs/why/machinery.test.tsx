// The lab's own test launcher named as a parent (PROOF 2026-11-24): the story's fact stays, and the plain words that
// Python sends ("started by the lab's own test launcher ..., not by a user") are shown with it, in why, checklist, prove.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Steps } from "./index";
import { ChecklistView, type Checklist, type Program } from "../checklist/index";
import { ProveView, type Prove } from "../prove/index";

const inks = { fact: "INK-F", hypothesis: "INK-H", gap: "INK-G" };

describe("the test launcher said in plain words", () => {
  it("why: the story row keeps its sentence and adds the note", () => {
    const h = renderToStaticMarkup(<Steps w={{ inks }} rows={[
      { ink: "fact", text: "powershell.exe started s1_fetch.exe", in_chain: true, machinery: "NOTE-LAUNCHER" },
      { ink: "fact", text: "s1_fetch.exe connected", in_chain: true }]} />);
    expect(h).toContain("powershell.exe started s1_fetch.exe");
    expect(h).toContain("NOTE-LAUNCHER");
    expect((h.match(/xp-machinery/g) ?? []).length).toBe(1);
  });
  it("checklist: the program list says it under the parent", () => {
    const p: Program = { guid: "{B}", recorded: true, image: "s1_fetch.exe", pid: 2780, command_line: "s1_fetch.exe", parent: "powershell.exe",
      parent_command_line: "powershell.exe -File run_scenario.ps1", parent_machinery: "NOTE-PARENT", user: null, time: null, children: [] };
    const d = { words: { intro: "", status: {}, open: {}, verdict: {}, questions: {}, sections: {} }, story: true, guid: "{B}", host: "vm", scope: [], own: [],
      alert: { id: "a1", title: "T", level: "high", time: "t", host: "vm", source: "sigma", rule_id: "r", reason: "", declared: false },
      questions: [{ key: "what", question: "Q", status: "fact", lines: [], more: 0, note: null, witness: null, links: [], programs: [p] }] } as unknown as Checklist;
    expect(renderToStaticMarkup(<ChecklistView d={d} />)).toContain("NOTE-PARENT");
  });
  it("prove: the recording-edge line about the launcher carries the note", () => {
    const words = { inks: { hypothesis: "INK-H", gap: "INK-G" }, verdict: {}, verdict_note: {}, state: {}, edge_title: "EDGE" } as unknown as Prove["words"];
    const d = { words, story: true, config: [], alert: { id: "a1", title: "A", level: "high", time: "t", host: "h", source: "sigma", rule_id: "r", reason: "", declared: false },
      lines: [{ ink: "gap", kind: "origin_unknown", text: "how powershell.exe was started", band: null, alternative: null, time: null, witness: null,
                edge: true, machinery: "NOTE-EDGE" }] } as unknown as Prove;
    const h = renderToStaticMarkup(<ProveView d={d} />);
    expect(h).toContain("how powershell.exe was started");
    expect(h).toContain("NOTE-EDGE");
  });
});
