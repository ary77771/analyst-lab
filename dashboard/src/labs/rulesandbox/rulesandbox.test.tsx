// Rule sandbox page: Python's answer drawn plainly; warnings for innocent runs; the fields the rule reads marked.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { lab, RuleResult, type RuleAnswer, type Words } from "./index";

const w = {
  title: "T", intro: "I", sandbox: "SANDBOX", start_from: "S", try: "Try it", trying: "…", matches: "records it matches",
  declared: "DECLARED", windows: "WINDOWS", runs: "Test runs it would have fired in", outside: "OUTSIDE", sample: "SAMPLE",
  fields_note: "NOTE", none: "NONE", kinds: { innocent: "innocent test", planted: "planted misuse", null: "kind not on record" },
  categories: "C", unnamed: "unnamed run",
} as Words;
const answer = (over: Partial<RuleAnswer>): RuleAnswer => ({
  id: "r", title: "Rule", level: "high", correlation: false, raised: true, level_line: "At level high it would be raised.",
  alerts: 2, records: 2, declared: 0, windows: null, runs: [{ run_id: "r1", scenario: "B19", records: 2 }], outside: 0,
  scenarios: [{ scenario: "B19", runs: 1, records: 2, kind: "innocent", name: "B19 · Backup tool" }],
  warnings: ["This rule would have fired on an innocent test: B19 · Backup tool (1 run(s), 2 record(s))."],
  sample: [{ time: "2026-11-01T10:00:05Z", event_id: 1, fields: [{ field: "Image", value: "C:\\x.exe", read: true },
                                                                   { field: "User", value: "VM\\a", read: false }] }],
  fields: ["Image"], ...over,
});

describe("rule sandbox", () => {
  it("is a lab the registry accepts, under Testing the tool itself", () => {
    expect(lab.id).toBe("rulesandbox");
    expect(lab.group).toBe("tool");
  });

  it("warns plainly about an innocent run and names its kind", () => {
    const h = renderToStaticMarkup(<RuleResult r={answer({})} w={w} />);
    expect(h).toContain("would have fired on an innocent test: B19");
    expect(h).toContain('data-kind="innocent"');
    expect(h).toContain("innocent test");
    expect(h).toContain("B19 · Backup tool");
  });

  it("marks the fields the rule reads, and says when nothing matched", () => {
    const h = renderToStaticMarkup(<RuleResult r={answer({})} w={w} />);
    expect(h).toContain('<div data-read="true"><dt>Image</dt>');
    expect(h).toContain("<div><dt>User</dt>");
    const none = renderToStaticMarkup(<RuleResult r={answer({ records: 0, alerts: 0, runs: [], scenarios: [], warnings: [], sample: [] })} w={w} />);
    expect(none).toContain("NONE");
    expect(none).not.toContain("rs-warnings");
  });
});
