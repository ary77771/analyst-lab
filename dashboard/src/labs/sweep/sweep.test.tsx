// "Indicator sweep": the lab entry follows the contract; the page renders its form without a server and never
// sends anything anywhere but its own back end.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { lab, whereAnswer } from "./index";
import src from "./index.tsx?raw";

describe("sweep lab", () => {
  it("follows the Labs contract", () => {
    expect(lab.id).toBe("sweep");
    expect(lab.title).toBeTruthy();
    expect(lab.blurb).toBeTruthy();
    expect(typeof lab.Component).toBe("function");
  });
  it("renders the form, starting from a list in the address", () => {
    const html = renderToStaticMarkup(<lab.Component params={new URLSearchParams("q=10.0.2.2")} />);
    expect(html).toContain("<textarea");
    expect(html).toContain("10.0.2.2");
    expect(html).toMatch(/aria-checked="true"[^>]*>all</);
  });
  it("answers 'where else' in runs, plainly", () => {
    const base = { raw: "x", kind: "ip", value: "x", role: "an address it contacted", times: 3, hosts: [], why_uncertain: null, pivot: null,
      elsewhere_first: "2026-10-31T17:00:00.0000000Z", elsewhere_last: "2026-10-31T18:00:00.0000000Z" };
    expect(whereAnswer({ ...base, verdict: "seen", in_this_run: 1, other_runs: 2, elsewhere: 2 }))
      .toBe("also in 2 other runs: seen 2 times there, first 31 Oct 17:00:00, last 31 Oct 18:00:00 (and 1 time in this alert's run)");
    expect(whereAnswer({ ...base, verdict: "seen", in_this_run: 3, other_runs: 0, elsewhere: 0 })).toBe("only here: 3 times in this alert's run");
    expect(whereAnswer({ ...base, verdict: "cant_tell", in_this_run: 0, other_runs: 0, elsewhere: 0, why_uncertain: "SHA256 only" }))
      .toBe("can't tell here: SHA256 only");
  });
  it("talks to its own back end only", () => {
    const urls = [...src.matchAll(/fetch\(\s*"([^"]+)"/g)].map((m) => m[1]);
    expect(urls).toEqual(["/api/labs/sweep/"]);
    expect(src).not.toMatch(/https?:\/\//);
  });
});
