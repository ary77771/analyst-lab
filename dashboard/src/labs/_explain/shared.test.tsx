import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Ids } from "./shared";
import { ProveView, type Prove } from "../prove";

describe("internal ids behind a details toggle (W3-6)", () => {
  it("the id is inside a closed <details>, behind the plain word", () => {
    const h = renderToStaticMarkup(<Ids label="details">T1 · content_from</Ids>);
    expect(h).toBe('<details class="xp-ids"><summary>details</summary><span>T1 · content_from</span></details>');
    expect(h).not.toContain("open");
  });
  it("a lab page never shows a bare internal id outside the toggle", () => {
    const words = { intro: "", witness: "", where: "", helps: "", recorder: "", no_lines: "", no_story: "", lines: "", config_title: "", config_file: "",
      details: "details", verdict: { elsewhere: "" }, verdict_note: { elsewhere: "" }, state: {}, inks: { hypothesis: "H" } } as unknown as Prove["words"];
    const d: Prove = { words, story: true, config: [],
      alert: { id: "a", title: "A", level: "high", time: "t", host: "h", source: "sigma", rule_id: "rule-uuid", reason: "", declared: false },
      lines: [{ ink: "hypothesis", kind: "content_from", text: "LINE", band: null, alternative: null, time: null, witness: null }] };
    const h = renderToStaticMarkup(<ProveView d={d} />);
    expect(h).not.toContain("rule-uuid");
  });
});
