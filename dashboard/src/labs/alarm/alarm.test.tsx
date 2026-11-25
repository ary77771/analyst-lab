import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AlarmView, cut, type Alarm } from "./index";

const words = { alarm_title: "ALARM", rule: "RULE", reason: "REASON", details: "DET", raw_title: "RAW", raw_note: "", story_title: "STORY", story_note: "",
  cites: "CITES", no_story: "NOSTORY", no_lines: "NOLINES", more_records: "{shown}/{total}", inks: { fact: "INK-F", hypothesis: "INK-H" } } as unknown as Alarm["words"];
const text = "powershell.exe (PID 2180) started conhost.exe";
const d: Alarm = { words, story: true, records_total: 1,
  alert: { id: "a1", title: "T", level: "high", time: "t", host: "h", source: "sigma", rule_id: "r", reason: "", declared: false },
  alarm: { title: "Rule Title", level: "high", rule_id: "rid-1", source: "sigma", reason: "ENGINE-REASON", time: "t", details: {}, declared: null },
  records: [{ key: "k1", missing: false, name: "process start", event_id: 1, header: [["event_id", 1], ["record_id", 12]],
    fields: [["Image", "C:\\x\\conhost.exe"], ["ParentProcessId", 2180], ["User", "u"]] }],
  lines: [{ ink: "fact", text, keys: ["k1"], own: true, traces: [
    { start: 20, end: 24, field: "ParentProcessId", key: "k1", value: "2180" },
    { start: 26, end: 33, field: "EventID", key: "k1", value: "1 (process start)" },
    { start: 34, end: 45, field: "Image", key: "k1", value: "C:\\x\\conhost.exe" }] }] };

describe("raw vs plain", () => {
  it("cuts a sentence at its traces and keeps every character", () => {
    const parts = cut(text, d.lines[0].traces);
    expect(parts.map((p) => p.text).join("")).toBe(text);
    expect(parts.filter((p) => p.t).map((p) => p.text)).toEqual(["2180", "started", "conhost.exe"]);
  });
  it("side by side: the engine's own words, the record in Sysmon's names, the traced fields lit", () => {
    const h = renderToStaticMarkup(<AlarmView d={d} view="side" />);
    for (const s of ["ENGINE-REASON", "rid-1", "&lt;Data Name=&quot;Image&quot;&gt;", "#1", "CITES #1", 'data-field="Image"']) expect(h).toContain(s);
    expect((h.match(/class="al-line" data-hit="true"/g) ?? []).length).toBe(3);    // Image, ParentProcessId, the event id
    expect(h).toContain('data-hit="false"');                                         // User is not in the sentence: not lit
  });
  it("alarm only shows no story; story only shows no raw record", () => {
    expect(renderToStaticMarkup(<AlarmView d={d} view="alarm" />)).not.toContain("STORY");
    expect(renderToStaticMarkup(<AlarmView d={d} view="story" />)).not.toContain("RAW");
  });
});
