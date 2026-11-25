import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ProveView, type Prove } from "./index";

const words = { intro: "", witness: "NEED", where: "WHERE", helps: "HELPS", recorder: "REC", no_lines: "NOLINES", no_story: "NOSTORY", lines: "LINES",
  config_title: "CFG", config_file: "f", open_why: "W",
  verdict: { collected: "V-COLLECTED", partly: "V-PART", not_configured: "V-OFF", elsewhere: "V-ELSEWHERE" },
  verdict_note: { collected: "", partly: "", not_configured: "", elsewhere: "" },
  state: { all: "S-ALL", some: "S-SOME {n}", none: "S-NONE", unset: "S-UNSET", recorder: "S-REC" },
  inks: { hypothesis: "INK-H", gap: "INK-G" } } as unknown as Prove["words"];
const row = (verdict: "collected" | "elsewhere") => ({ kind: "content_from", row: "T1", ink: "hypothesis", witness: `WITNESS-${verdict}`, verdict,
  sources: [{ kind: "none" as const, what: "a packet capture", state: "elsewhere", events: [] }],
  helps: [{ kind: "sysmon" as const, element: "FileCreateStreamHash", what: "download mark", state: "all", events: [15] }] });
const d: Prove = { words, story: true, config: [{ element: "ProcessCreate", events: [1], state: "all", rules: 0 }],
  alert: { id: "a1", title: "A", level: "high", time: "t", host: "h", source: "sigma", rule_id: "r", reason: "", declared: false },
  lines: [{ ink: "hypothesis", kind: "content_from", text: "LINE-1", band: "low", alternative: "ALT", time: null, witness: row("elsewhere") },
          { ink: "gap", kind: "parent_unknown", text: "LINE-2", band: null, alternative: null, time: null, witness: row("collected") }] };

describe("What would prove it", () => {
  it("every Suspected line and gap shows its witness and the verdict Python sent", () => {
    const h = renderToStaticMarkup(<ProveView d={d} />);
    for (const s of ["LINE-1", "LINE-2", "WITNESS-elsewhere", "V-ELSEWHERE", "V-COLLECTED", "Sysmon FileCreateStreamHash (15)", "S-ALL", "INK-H · low", "INK-G", "ALT"]) expect(h).toContain(s);
    expect(h.indexOf('data-ink="gap"')).toBeGreaterThan(h.indexOf('data-ink="hypothesis"'));
  });
  it("shows a matching fingerprint as corroboration under the Suspected line, not as a new grade", () => {
    const fp = { sha256: "5277F0EF", file: "C:\\t\\pay.exe", programs: [{ image: "C:\\t\\fetch.exe", pid: 7, command_line: "fetch.exe -sha256 5277f0ef" }] };
    const lines = [{ ...d.lines[0], fingerprint: fp }, d.lines[1]];
    const h = renderToStaticMarkup(<ProveView d={{ ...d, words: { ...words, fingerprint_title: "FP-TITLE", fingerprint_note: "FP-NOTE" } as unknown as Prove["words"], lines }} />);
    for (const s of ["FP-TITLE", "FP-NOTE", "5277F0EF", "fetch.exe -sha256 5277f0ef", "PID 7", "INK-H · low"]) expect(h).toContain(s);
    expect(renderToStaticMarkup(<ProveView d={d} />)).not.toContain("pv-fp");
  });
  it("says so when there is nothing suspected", () => {
    expect(renderToStaticMarkup(<ProveView d={{ ...d, lines: [] }} />)).toContain("NOLINES");
    expect(renderToStaticMarkup(<ProveView d={{ ...d, story: false }} />)).toContain("NOSTORY");
  });
});
