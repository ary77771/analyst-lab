// File check's YARA section, LOLBAS and Second opinion pages: registry shape, and the small pure pieces they show.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { MatchCard } from "./yarasection";
import { lab as lolbasLab, fill } from "../lolbas/index";
import { lab as soLab, countBy, RunOffer, SummaryView, type Row } from "../secondopinion/index";
import { Jargon } from "./jargon";

describe("night-tools labs", () => {
  it("each is a lab the registry accepts, with its folder's id", () => {
    for (const [l, id] of [[lolbasLab, "lolbas"], [soLab, "secondopinion"]] as const) {
      expect(l.id).toBe(id);
      expect(l.title && l.blurb).toBeTruthy();
      expect(typeof l.Component).toBe("function");
    }
  });

  it("a YARA match shows the rule author's own description, quoted, with author and licence", () => {
    const h = renderToStaticMarkup(<MatchCard m={{ rule: "R1", namespace: "set-a/a.yar", set: "set-a", tags: [], description: "DESC", author: "AUTH",
      license: "DRL 1.1", reference: "https://example.invalid/r", score: 70, patterns: [{ id: "$a", hits: 2, offsets: [10, 20], preview: "http://10.0.2.2" }] }} />);
    expect(h).toContain("“DESC”");
    expect(h).toContain("by AUTH");
    expect(h).toContain("licence: DRL 1.1");
    expect(h).toContain("$a ×2: http://10.0.2.2");
    expect(h).toContain('rel="noreferrer noopener"');
  });

  it("LOLBAS words are filled from Python's template", () => {
    expect(fill("{n} of the {of} switches", { n: 4, of: 5 })).toBe("4 of the 5 switches");
    expect(fill("original name is {orig}", {})).toBe("original name is {orig}");
  });

  it("second opinion filters rows by verdict", () => {
    const r = (id: number, verdicts: Row["verdicts"]): Row => ({ record_id: id, time: null, event_id: 1, channel: null, image: null, ours: [], theirs: {}, verdicts });
    const rows = [r(1, { hayabusa: "both" }), r(2, { hayabusa: "only_ours", chainsaw: "near" }), r(3, { chainsaw: "only_theirs" }), r(4, { hayabusa: "both" })];
    expect(countBy(rows, "hayabusa", "all").map((x) => x.record_id)).toEqual([1, 2, 4]);
    expect(countBy(rows, "hayabusa", "both").map((x) => x.record_id)).toEqual([1, 4]);
    expect(countBy(rows, "chainsaw", "near").map((x) => x.record_id)).toEqual([2]);
  });

  it("card blurbs start with plain words before the technical name (W3-6)", () => {
    expect(lolbasLab.blurb.startsWith("Windows' own tools that can be misused (LOLBAS)")).toBe(true);
    expect(soLab.blurb.startsWith("Two free log-search tools (Hayabusa, Chainsaw)")).toBe(true);
  });

  it("each technical name is shown with its plain line, on hover and written out", () => {
    const h = renderToStaticMarkup(<Jargon terms={{ YARA: "pattern rules for files", LOLBAS: "own tools misused" }} />);
    expect(h).toContain('<abbr title="pattern rules for files">YARA</abbr> = pattern rules for files');
    expect(h).toContain("own tools misused.");
    expect(renderToStaticMarkup(<Jargon terms={null} />)).toBe("");
  });

  it("second opinion offers a button instead of starting by itself, and says when another runs", () => {
    const file = { id: "x", name: "a.evtx", kind: "sample" as const, folder: "", size: 1, sysmon: true };
    const free = renderToStaticMarkup(<RunOffer job={{ state: "not_run", file, busy: null }} onRun={() => {}} runError={null} />);
    expect(free).toContain("Run the comparison for a.evtx");
    expect(free).toContain("starts only when you ask");
    const busy = renderToStaticMarkup(<RunOffer job={{ state: "not_run", file, busy: "b.evtx" }} onRun={() => {}} runError="409" />);
    expect(busy).toContain("Another comparison is running (b.evtx)");
    expect(busy).not.toContain("<button");
  });

  it("second opinion leads with one summary table of the logs compared so far, rule sets named", () => {
    const w = { rule: "RULE.", rule_sets: "ours {ours}; Hayabusa {hayabusa}; Chainsaw {chainsaw}", both: "B", near: "N", only_ours: "O", only_theirs: "T" } as never;
    const file = { id: "x", name: "a.evtx", kind: "sample" as const, folder: "", size: 1, sysmon: true };
    const s = { level: "medium", rows: [{ file, sysmon_events: 565, counts: { hayabusa: { both: 86, near: 1, only_ours: 1, only_theirs: 22 } } }],
      totals: {}, rule_sets: { ours: 1869, tools: { hayabusa: "4.4.0" } } };
    const h = renderToStaticMarkup(<SummaryView s={s} words={w} onPick={() => {}} />);
    expect(h).toContain("86 / 1 / 1 / 22");
    expect(h).toContain("ours 1869; Hayabusa 4.4.0");
    expect(h).toContain("RULE.");
    expect(renderToStaticMarkup(<SummaryView s={{ ...s, rows: [] }} words={w} onPick={() => {}} />)).toContain("No log has been compared yet");
  });
});

