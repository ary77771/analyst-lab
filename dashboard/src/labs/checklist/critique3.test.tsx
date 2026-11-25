// VISION's critique-3: the landing page's "What ran?" is light (short command line, the full ones folded, the lab's
// own launcher named as such, no empty label), and word for word keeps the recorder's notes apart from Windows' words.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ChecklistView, type Checklist, type Program } from "./index";
import { RawRecord, type Rec, type WW } from "../_explain/wordforword";

const words = { intro: "", status: {}, open: {}, verdict: {}, questions: {}, sections: {}, program_parent: "BY", program_children: "KIDS",
  program_cmd: "CMD", program_launcher: "THE-LAUNCHER", program_show_cmd: "SHOW-FULL" };
const view = (programs: Program[]) => renderToStaticMarkup(<ChecklistView d={{ words, story: true, guid: "{B}", host: "vm", scope: [], own: [],
  alert: { id: "a1", title: "T", level: "high", time: "t", host: "vm", source: "sigma", rule_id: "r", reason: "", declared: false },
  questions: [{ key: "what", question: "Q", status: "fact", lines: [], more: 0, note: null, witness: null, links: [], programs }] } as unknown as Checklist} />);
const prog = (over: Partial<Program>): Program => ({ guid: "{B}", recorded: true, image: "C:\\s1\\s1_fetch.exe", pid: 2780, command_line: "FULL-LINE",
  command_short: "SHORT-LINE", parent: "C:\\Windows\\powershell.exe", parent_command_line: "PARENT-FULL", parent_machinery: null, user: null, time: null,
  children: [], ...over });

describe("checklist first screen (critique-3)", () => {
  it("short command line first, full lines folded behind one toggle", () => {
    const h = view([prog({})]);
    expect(h).toContain("SHORT-LINE");
    expect(h).toContain("SHOW-FULL");
    expect(h.indexOf("FULL-LINE")).toBeGreaterThan(h.indexOf("<details"));
    expect(h.indexOf("PARENT-FULL")).toBeGreaterThan(h.indexOf("<details"));
  });
  it("the lab's own launcher is named as such, not as a program of the test", () => {
    const h = view([prog({ parent_machinery: "M" })]);
    expect(h).toContain("THE-LAUNCHER");
    expect(h).toContain("(powershell.exe)");
  });
  it("no empty labels: no parent, no children, no command line means no line at all", () => {
    const h = view([prog({ parent: null, parent_command_line: null, command_line: null, command_short: null, children: [{ image: "", pid: 1 }] })]);
    for (const s of ["BY", "KIDS", "SHOW-FULL"]) expect(h).not.toContain(s);
  });
});

describe("word for word: Windows' words and the recorder's notes (critique-3)", () => {
  const w = { recorder_notes: "OUR-NOTES", by_recorder: "BY-RECORDER", inks: {} } as unknown as WW;
  const r: Rec = { key: "k", missing: false, name: "process start", header: [["record_id", 12]], fields: [["Image", "a.exe"]],
    notes: [["origin", "normal"], ["session", "s"]], by: "windows" };
  it("the notes are folded under the record, marked as ours, outside the Windows record", () => {
    const h = renderToStaticMarkup(<RawRecord r={r} n={1} lit={new Set()} w={w} />);
    expect(h).toContain("OUR-NOTES (2)");
    expect(h.indexOf("origin: normal")).toBeGreaterThan(h.indexOf("&lt;/Event&gt;"));
    expect(h).not.toContain("BY-RECORDER");
    expect(renderToStaticMarkup(<RawRecord r={{ ...r, by: "recorder" }} n={1} lit={new Set()} w={w} />)).toContain("BY-RECORDER");
  });
});
