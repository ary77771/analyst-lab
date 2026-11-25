// Alarm track record page: Python's words filled with the record's numbers; "never measured" when there is none.
import { describe, expect, it } from "vitest";
import { hoursLabel, hoursSource, lab, lines, type Rec } from "./index";

const w = {
  title: "T", intro: "I", normal: "N", normal_line: "Rang {alerts} times in {hours} hours, {period}", normal_note: "NOTE", public: "P",
  public_line: "Flagged {tests} of {executed}", blind: "B", blind_line: "Blind {alerts} in {runs} of {total}", never: "NEVER",
  blind_none: "BN", alerts: "A", all: "ALL", cite: "C",
};
const rec = (over: Partial<Rec>): Rec => ({ rule: "r", title: "t", measured: true, normal: null, public: null, blind: null, ...over });

describe("alarm track record", () => {
  it("is a lab the registry accepts", () => {
    expect(lab.id).toBe("receipts");
    expect(typeof lab.Component).toBe("function");
    expect(lab.group).toBe("tool");                         // "Testing the tool itself" (critique 3)
  });

  it("says never measured when there is no record", () => {
    expect(lines(rec({ measured: false }), w)).toEqual(["NEVER"]);
  });

  it("fills one line per source with a number", () => {
    const l = lines(rec({ normal: { alerts: 116, per_hour: 2.4, days: 7, programs: 12, hours: 47.5, period: "2026-10-23 to 2026-10-29" },
      public: { tests: 2, techniques: ["T1012", "T1016"], executed: 362 } }), w);
    expect(l).toEqual(["Rang 116 times in 47.5 hours, 2026-10-23 to 2026-10-29. NOTE", "Flagged 2 of 362 (T1012, T1016)"]);
  });

  it("says what the blind rounds found for this rule", () => {
    const w2 = { ...w, blind_verdict: { flagged: "Round {round}: flagged {scenarios} ({kind}, {runs} runs)" }, blind_kind: { planted: "PLANTED" } };
    const l = lines(rec({ blind_verdicts: [{ round: 4, scenarios: ["B18", "B20"], kind: "planted", runs: 6, outcome: "flagged" }] }), w2);
    expect(l).toEqual(["Round 4: flagged B18 and B20 (PLANTED, 6 runs)"]);
  });

  it("names the active hours' week, code and source file at its commit", () => {
    const w3 = { ...w, hours_label: "active hours ({period})", hours_source: "{hours} h, week {period}, {code}. Source: {file} at commit {commit}." };
    const hs = { hours: 47.5, period: "2026-10-23 to 2026-10-29", code: "the v4 code", file: "docs/results/v4/x.md", commit: "abc1234", date: "2026-11-19" };
    expect(hoursLabel({ words: w3, period: hs.period })).toBe("active hours (2026-10-23 to 2026-10-29)");
    expect(hoursSource({ words: w3, hours_source: hs })).toBe("47.5 h, week 2026-10-23 to 2026-10-29, the v4 code. Source: docs/results/v4/x.md at commit abc1234.");
    expect(hoursSource({ words: w3, hours_source: null })).toBeNull();
    expect(hoursLabel({ words: w, period: null })).toBe("active hours of normal use counted");
  });
});

