// The Why page shows what Python sent: the matched characters marked, the selections' verdicts, the graph
// rows in their own inks, and the warning when the page could not reproduce the engine's match.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { WhyView, type Why } from "./index";

const words = {
  rule_title: "RULE", events_title_plain: "PLAIN", logic_title: "LOGIC", events_title: "EVENTS", story_title: "STORY", story_note: "NOTE", condition: "WHEN",
  selection_held: "HELD", selection_failed: "FAILED", selection_unknown: "UNKNOWN", filter_note: "FILTER", any_of: "ANY",
  sysmon_event: "EV", declared_note: "DECLARED", not_reproduced: "NOT-REPRODUCED", partly_checked: "PARTLY", rule_missing: "MISSING",
  python_rule: "PY", beacon_rule: "BEACON", more_events: "{shown}/{total}", other_fields: "OTHER", no_story: "NOSTORY",
  references: "REFS", falsepositives: "FPS", reason: "REASON", source: "SOURCE", open_moment: "MOMENT", open_next: "NEXT", pick: "PICK",
  inks: { fact: "INK-FACT", hypothesis: "INK-HYPO", gap: "INK-GAP" }, ink_explain: { fact: "f", hypothesis: "h", gap: "g" },
} as unknown as Why["words"];

function sample(over: Partial<Why> = {}): Why {
  return {
    words, events_total: 1, check: "reproduced", partly_checked: false,
    alert: { id: "a1", title: "Fixture alert", level: "high", time: "2026-10-22T10:00:00.000Z", host: "h1", source: "sigma", rule_id: "r", reason: "why", declared: false },
    rule: { found: true, kind: "sigma", title: "Fixture rule", level: "high", tags: ["mitre.t1497.003"], techniques: [{ id: "T1497.003", name: null }],
      logsource: { category: "process_creation", product: "windows", event_ids: [1] }, condition: ["sel"], selections: [] },
    events: [{ key: "k1", kind: "recorded", missing: false, event_id: 1, time: "t", matched: true, base_rule: null, matched_fields: ["CommandLine"],
      highlights: { CommandLine: [[5, 8]] }, fields: [["CommandLine", "ping -n 5"], ["User", "u"]],
      selections: [{ name: "sel", matched: true, filter: false, group_linking: "all", groups: [[{ field: "CommandLine", modifiers: ["contains"], words: ["contains"],
        values: ["-n "], match: "any", negated: false, value: "ping -n 5", matched: true, spans: [[5, 8]], matched_values: ["-n "] }]] },
        { name: "filter", matched: false, filter: true, group_linking: "all", groups: [[]] }] }],
    story: { available: true, rows: [{ ink: "fact", text: "a started b", in_chain: true, offset: "start" }, { ink: "gap", text: "who started a", in_chain: false }] },
    ...over,
  };
}

const html = (d: Why) => renderToStaticMarkup(<WhyView d={d} />);

describe("the Why page", () => {
  it("marks exactly the matched characters and the verdict of each selection", () => {
    const h = html(sample());
    expect(h).toContain('<mark class="xp-hit">-n </mark>');
    expect(h).toContain("HELD");
    expect(h).toContain("FAILED");
    expect(h).toContain("FILTER");
    expect(h).not.toContain("NOT-REPRODUCED");
  });
  it("the word-for-word view comes first, and the rule's noise line is in the header", () => {
    const ww = { words: { raw_title: "RAW", raw_note: "", story_title: "SAYS", story_note: "", cites: "C", no_story: "", no_lines: "", more_records: "", inks: { fact: "F", hypothesis: "H" } },
      story: true, records_total: 1, records: [{ key: "k1", missing: false, name: "process start", event_id: 1, header: [["record_id", 1]], fields: [["Image", "x"]] }],
      lines: [{ ink: "fact", text: "a started x", keys: ["k1"], own: true, traces: [] }] } as unknown as NonNullable<Why["wordforword"]>;
    const h = html(sample({ wordforword: ww, noise: { text: "NOISE-LINE", measured: true } }));
    expect(h).toContain("NOISE-LINE");
    expect(h.indexOf("al-grid")).toBeGreaterThan(-1);
    expect(h.indexOf("al-grid")).toBeLessThan(h.indexOf("RULE"));
  });
  it("links each technique to the technique map", () => {
    expect(html(sample())).toContain('href="#/labs/techniques?technique=T1497.003"');
  });
  it("shows the graph rows in their own inks, in order", () => {
    const h = html(sample());
    expect(h.indexOf("INK-FACT</b><span>a started b")).toBeGreaterThan(-1);
    expect(h.indexOf('data-ink="gap"')).toBeGreaterThan(h.indexOf('data-ink="fact"'));
  });
  it("a Python rule: no 'matched' title, the record's things as Pivot chips, the raw fields behind a toggle", () => {
    const base = sample();
    const ev = { ...base.events[0], matched: null, matched_fields: [], highlights: {}, selections: [] };
    const h = html(sample({ rule: { found: true, kind: "python", title: "Py rule", doc: "DOC" }, check: "na", events: [ev] }));
    expect(h).toContain("PLAIN");
    expect(h).not.toContain(">EVENTS<");
    expect(h).toContain('class="th-chip"');                       // User is something to open in Pivot
    expect(h.indexOf("ping -n 5")).toBeGreaterThan(h.indexOf("<details"));   // the raw record only behind the toggle
  });
  it("says so when the match was not reproduced, and when the rule file is missing", () => {
    expect(html(sample({ check: "not_reproduced" }))).toContain("NOT-REPRODUCED");
    expect(html(sample({ rule: { found: false, kind: "missing", title: "x" } }))).toContain("MISSING");
  });
});
