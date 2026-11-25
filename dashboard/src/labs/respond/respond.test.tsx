import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { NextView, type Next } from "./index";

const words = { intro: "INTRO", technique: "TECH", mitigations: "MITS", mitigations_note: "", no_mitigations: "NOMITS", d3fend: "D3", d3fend_note: "",
  d3fend_via: "VIA {asked}->{via}", no_d3fend: "NOD3", link_words: "{defence} {defence_rel} {artifact}; {attack_rel} {attack_artifact}", more_links: "+{n}",
  no_tags: "NOTAGS", no_attack: "NOATT", no_d3fend_data: "NOD3DATA", source_attack: "ATT {version}", source_d3fend: "D3 {version}", open_mitre: "M",
  open_d3fend: "D", open_why: "W", legal: "L", tactics: { Isolate: "ISO-WORDS" } } as unknown as Next["words"];

function sample(over: Partial<Next> = {}): Next {
  return {
    words, rule_tags: [], alert: { id: "a1", title: "A", level: "high", time: "t", host: "h", source: "sigma", rule_id: "r", reason: "", declared: false },
    attack: { available: true, version: "99" }, d3fend: { available: true, version: "9" },
    techniques: [{ id: "T1059.001", name: "CSI: PowerShell", url: "u", description: "desc",
      mitigations: [{ id: "M1038", name: "Execution Prevention", url: "mu", how: "HOW-TEXT", description: "md" }],
      d3fend: { via: "T1059", count: 1, url: "du", tactics: [{ tactic: "Isolate", techniques: [{ id: "D3-EAL", name: "Executable Allowlisting", definition: "DEF",
        links: [{ defence: "Executable Allowlisting", defence_rel: "blocks", artifact: "Executable File", attack_rel: "executes", attack_artifact: "Executable Script" }], more_links: 2 }] }] } }],
    ...over,
  };
}

describe("What to do next", () => {
  it("shows MITRE's mitigation with its how-sentence and D3FEND's defence with its link", () => {
    const h = renderToStaticMarkup(<NextView d={sample()} />);
    for (const s of ["M1038", "HOW-TEXT", "D3-EAL", "DEF", "Executable Allowlisting blocks Executable File; executes Executable Script", "+2", "ISO-WORDS", "VIA T1059.001-&gt;T1059"]) expect(h).toContain(s);
  });
  it("says why there are no steps instead of inventing any", () => {
    expect(renderToStaticMarkup(<NextView d={sample({ techniques: [] })} />)).toContain("NOTAGS");
    expect(renderToStaticMarkup(<NextView d={sample({ attack: { available: false, version: null } })} />)).toContain("NOATT");
  });
});
