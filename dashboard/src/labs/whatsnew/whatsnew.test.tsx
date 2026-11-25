// What's new tonight: one card per lab with the builder's words, its screenshot through the lab's own route, the
// open link, and "no status entry" said plainly.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Box } from "lucide-react";
import { Card, lab, order, shotUrl, type Facts } from "./index";
import type { Lab } from "../registry";

const mk = (id: string, title: string): Lab => ({ id, title, blurb: `BLURB-${id}`, icon: Box, Component: () => null });
const words = { title: "T", intro: "I", questions: "Q", not_done: "ND", no_entry: "NO-ENTRY", source: "From", loaded: "L", left_out: "LEFT-OUT" };
const facts = (over: Partial<Facts>): Facts => ({
  source: "status-night-x.md", heading: "Thing (#/labs/a)", what: "WHAT-LINE", open: [], off: ["delete engine/labs/a.py"],
  not_done: ["NOT-DONE-LINE"], checks: ["8 tests"], notes: ["NOTE"], shots: ["night-x-01-a.png"], ...over,
});

describe("what's new tonight", () => {
  it("is a lab the registry accepts", () => {
    expect(lab.id).toBe("whatsnew");
    expect(typeof lab.Component).toBe("function");
  });

  it("orders cards: with a screenshot, then with an entry, then the rest; itself and the example lab left out", () => {
    const labs = [mk("whatsnew", "W"), mk("glance", "G"), mk("c", "C"), mk("b", "B"), mk("a", "A")];
    const f = { a: facts({ shots: [] }), b: facts({}), c: null };
    expect(order(labs, f).map((l) => l.id)).toEqual(["b", "a", "c"]);
  });

  it("shows the builder's words, the shot through the lab's route and the open link", () => {
    const h = renderToStaticMarkup(<Card lab={mk("a", "Alpha")} f={facts({})} words={words} loaded />);
    for (const s of ["BLURB-a", "WHAT-LINE", "delete engine/labs/a.py", "NOT-DONE-LINE", "8 tests", "status-night-x.md", 'href="#/labs/a"'])
      expect(h).toContain(s);
    expect(h).toContain(`src="${shotUrl("night-x-01-a.png")}"`);
    expect(h).not.toContain("LEFT-OUT");
  });

  it("says plainly when a lab has no status entry, and when it is left out", () => {
    const h = renderToStaticMarkup(<Card lab={mk("z", "Zed")} f={null} words={words} loaded={false} />);
    expect(h).toContain("NO-ENTRY");
    expect(h).toContain("LEFT-OUT");
  });
});
