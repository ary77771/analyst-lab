import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ChecklistView, hrefFor, type Checklist } from "./index";

const words = { intro: "", no_story: "NOSTORY", witness: "WIT", more: "+{n}",
  status: { fact: "S-FACT", hypothesis: "S-HYP", gap: "S-GAP", none: "S-NONE" },
  open: { why: "O-WHY", moment: "O-MOMENT", prove: "O-PROVE", pivot: "O-PIVOT", persistence: "O-PERSIST" },
  verdict: { elsewhere: "V-ELSEWHERE" }, questions: {} } as unknown as Checklist["words"];
const d: Checklist = { words, story: true, guid: "{AAAA}", host: "analystlab-vm", scope: [], own: [],
  alert: { id: "a1", title: "T", level: "high", time: "t", host: "analystlab-vm", source: "sigma", rule_id: "r", reason: "", declared: false },
  questions: [
    { key: "who", question: "Q-WHO", status: "fact", lines: [{ ink: "fact", text: "x.exe started a.exe", time: null }], more: 0, note: null, witness: null, links: ["moment"] },
    { key: "deleted", question: "Q-DEL", status: "none", lines: [], more: 0, note: "NOTE-ONLY-SOME", witness: null, links: ["moment"] },
    { key: "files", question: "Q-FILES", status: "gap", lines: [{ ink: "gap", text: "content unknown", time: null }], more: 3, note: null,
      witness: { kind: "content_unknown", witness: "A FINGERPRINT", verdict: "elsewhere" }, links: ["pivot", "prove"] },
  ] };

describe("the investigation checklist", () => {
  it("each question shows its status, the story's lines, the note or the witness", () => {
    const h = renderToStaticMarkup(<ChecklistView d={d} />);
    for (const s of ["Q-WHO", "S-FACT", "x.exe started a.exe", "Q-DEL", "S-NONE", "NOTE-ONLY-SOME", "A FINGERPRINT", "V-ELSEWHERE", "+3"]) expect(h).toContain(s);
    expect(h).toContain('data-status="gap"');
  });
  it("a line's ink word is shown only when it differs from its question's (no double badge), and the recording line is on top", () => {
    const h = renderToStaticMarkup(<ChecklistView d={{ ...d, recording: "REC-LINE" }} />);
    expect((h.match(/S-FACT/g) ?? []).length).toBe(1);          // the question's badge, not again on its own line
    expect(h).toContain("REC-LINE");
  });
  it("links go to the lab that shows the answer", () => {
    expect(hrefFor("pivot", d)).toBe("#/labs/pivot?kind=process&value=%7BAAAA%7D&host=analystlab-vm");
    expect(hrefFor("prove", d)).toBe("#/labs/prove?alert=a1");
    expect(hrefFor("persistence", d)).toBe("#/labs/persistence");
    expect(hrefFor("pivot", { ...d, guid: null })).toBeNull();
  });
});
