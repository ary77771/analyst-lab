import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Picker, StartView, type Start } from "./index";

const words = { intro: "", pick: "PICK", pick_note: "", times: "{n} times, first at {first}", once: "once, at {first}", no_alerts: "NONE",
  path: "PATH", open: "Open", questions: {}, labs: {}, status: {} } as unknown as Start["words"];
const step = (key: string, lab: string, status: Start["steps"][0]["status"]) =>
  ({ key, question: `Q-${key}`, status, status_word: `S-${status}`, line: `LINE-${key}`, lab, lab_name: `LAB-${lab}` });
const d: Start = { words, repeats: 3, alert: { id: "a1", title: "T", level: "high", time: "t", host: "h" },
  steps: [step("fired", "why", "fact"), step("around", "moment", "none"), step("sure", "alarm", "gap"), step("spread", "checklist", "fact"),
          step("unseen", "prove", "gap"), { ...step("todo", "respond", "unchecked"), reason: "WHY-NOT" }] };

describe("I have an alert", () => {
  it("six numbered steps, each with its status word, its line and an Open link carrying the alert", () => {
    const h = renderToStaticMarkup(<StartView d={d} />);
    expect((h.match(/class="st-step"/g) ?? []).length).toBe(6);
    for (const lab of ["why", "moment", "alarm", "checklist", "prove", "respond"]) expect(h).toContain(`href="#/labs/${lab}?alert=a1"`);
    for (const s of ["S-fact", "S-none", "S-unchecked", "LINE-unseen", "WHY-NOT", "LAB-respond"]) expect(h).toContain(s);
  });
  it("the picker shows a repeated alert once, with how many times", () => {
    const h = renderToStaticMarkup(<Picker w={words} groups={[{ id: "b2", ids: ["b2", "b1"], title: "A shell", rule_id: "r", level: "medium",
      first: "2026-10-31T10:00:00Z", last: "2026-10-31T11:00:00Z", count: 2 }]} />);
    expect(h).toContain("2 times, first at 2026-10-31 10:00:00");
    expect(h).toContain('href="#/labs/start?alert=b2"');
  });
});
