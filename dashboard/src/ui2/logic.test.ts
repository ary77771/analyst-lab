// The honesty rules that live in the front end's logic: the story is told in Python's order and
// only from Python's rows; a new alert fires once and never changes the story on screen.
// Run: npm test (tests/test_dashboard_frontend_logic.py runs it from pytest).
import { describe, expect, it } from "vitest";
import { AlertWatch, PREVIEW_QUIET_S, buildMap, camera, filmCut, filmRows, filmView, noAlertsText, parseRoute, previewPhase, rowsOf, storyAlert, tally } from "./logic";
import { longStory, sample } from "./testdata";

describe("the story is told in Python's order, from Python's rows only", () => {
  it("keeps the API timeline's order exactly, even when ids and times would sort differently", () => {
    const inv = sample();
    expect(rowsOf(inv).map((r) => r.id)).toEqual(inv.report.timeline.map((t) => t.id));
    inv.report.timeline.reverse();                                  // whatever order Python sends is the order told
    expect(rowsOf(inv).map((r) => r.id)).toEqual(["h1", "e7", "e2", "e9", "g1"]);
  });
  it("adds no row and drops no row, and takes each row's words from the API", () => {
    const inv = sample(), rows = rowsOf(inv);
    expect(rows).toHaveLength(inv.report.timeline.length);
    expect(rows.find((r) => r.id === "h1")).toMatchObject({ ink: "hypothesis", bandLabel: "weak lead", chance: "by chance about 903 in 1,000 times", short: "the content of f1 may have come from n1" });
    expect(rows.find((r) => r.id === "e2")).toMatchObject({ n: 1, offset: "start" });
    expect(rows.find((r) => r.id === "g1")).toMatchObject({ ink: "gap", nodeId: "p0" });
  });
  it("counts only what has been told so far", () => {
    const rows = rowsOf(sample());
    expect(tally(rows, 0)).toEqual({ fact: 0, hypothesis: 0, gap: 0 });
    expect(tally(rows, 3)).toEqual({ fact: 2, hypothesis: 0, gap: 1 });
    expect(tally(rows, 99)).toEqual({ fact: 3, hypothesis: 1, gap: 1 });
  });
});

describe("the map draws a link only when its row is told", () => {
  const opts = { r: 22, off: 50, col: 120, laneH: 140, left: 200, right: 80, top: 90, bottom: 110, stub: 30 };
  it("reveals each link at its own row, and no thing before the first link (or gap) that mentions it", () => {
    const inv = sample(), rows = rowsOf(inv), m = buildMap(inv, rows, opts);
    const at = (id: string) => rows.findIndex((r) => r.id === id) + 1;
    for (const e of m.edges) expect(e.at).toBe(at(e.id));
    const node = (id: string) => m.nodes.find((n) => n.id === id)!;
    expect(node("p0").at).toBe(at("g1"));                           // the unknown start is told first
    expect(node("p1").at).toBe(at("e9"));
    expect(node("n1").at).toBe(at("e2"));
    expect(node("f1").at).toBe(at("e7"));
    expect(m.stubs.map((s) => [s.id, s.at])).toEqual([["p0", at("g1")]]);
    expect(node("p0").gapAt).toBe(at("g1"));                        // its dotted outline appears with that row, not before
    expect(node("p1").gapAt).toBe(null);
  });
  it("never draws a link that is not a row of Python's timeline", () => {
    const inv = sample();
    inv.report.layout!.edges.push({ id: "ghost", u: "p1", v: "f1", kind: "deleted", grade: "fact", band: null, lane: 1, order: 9, icon: "x", short: "", in_chain: false });
    const m = buildMap(inv, rowsOf(inv), opts);
    expect(m.edges.map((e) => e.id)).not.toContain("ghost");
    expect(m.edges).toHaveLength(4);
  });
  it("keeps every ink it was given: a suspected link is never drawn as a fact", () => {
    const inv = sample(), m = buildMap(inv, rowsOf(inv), opts);
    expect(m.edges.find((e) => e.id === "h1")).toMatchObject({ ink: "hypothesis", label: "weak lead" });
    expect(m.edges.filter((e) => e.ink === "fact").map((e) => e.id).sort()).toEqual(["e2", "e7", "e9"]);
  });
  it("gives two things first seen in the same step their own places, the program first", () => {
    const inv = sample();
    for (const n of inv.report.layout!.nodes) if (n.id === "f1" || n.id === "n1") n.order = 1;      // same order as p1
    const m = buildMap(inv, rowsOf(inv), opts);
    const x = (id: string) => m.nodes.find((n) => n.id === id)!.x;
    expect(new Set(m.nodes.map((n) => n.x)).size).toBe(m.nodes.length);
    expect(x("p0")).toBeLessThan(x("p1"));
    expect(x("p1")).toBeLessThan(Math.min(x("f1"), x("n1")));
  });
  it("frames only what has been drawn so far", () => {
    const inv = sample(), rows = rowsOf(inv), m = buildMap(inv, rows, opts);
    expect(m.drawn(0)).toBe(null);
    const one = m.drawn(1)!, all = m.drawn(rows.length)!;
    expect(one.x1).toBeLessThan(all.x1);                             // the frame grows as the story is told
    expect(all.x1).toBe(Math.max(...m.nodes.map((n) => n.x)));
  });
  it("places things left to right by Python's order", () => {
    const inv = sample(), m = buildMap(inv, rowsOf(inv), opts);
    const xs = ["p0", "p1", "n1", "f1"].map((id) => m.nodes.find((n) => n.id === id)!.x);
    expect(xs).toEqual([...xs].sort((a, b) => a - b));
  });
});

describe("a new alert fires once and never changes the story on screen", () => {
  it("does not fire for alerts already there when the page opens", () => {
    const w = new AlertWatch();
    expect(w.update(["a1", "a2"])).toEqual([]);
    expect(w.update(["a1", "a2"])).toEqual([]);
  });
  it("fires exactly once for an alert that arrives later", () => {
    const w = new AlertWatch();
    expect(w.update([])).toEqual([]);
    expect(w.update(["a1"])).toEqual(["a1"]);
    expect(w.update(["a1"])).toEqual([]);
    expect(w.update(["a1", "a2", "a3"])).toEqual(["a2", "a3"]);
    expect(w.update(["a1", "a2", "a3"])).toEqual([]);
  });
  it("keeps showing the story being watched when a later alert arrives", () => {
    expect(storyAlert(null, "a1", ["a1", "a2"])).toBe("a1");        // a2 landed mid-film: the film stays on a1
    expect(storyAlert("a2", "a1", ["a1", "a2"])).toBe("a2");        // only an explicit pick changes it
    expect(storyAlert(null, null, ["a1", "a2"])).toBe("a2");        // nothing showing yet: the newest
    expect(storyAlert("gone", null, [])).toBe(null);
  });
});

describe("addresses", () => {
  it("opens the picked design for the addresses the demo launcher opens, so the launcher needs no change", () => {
    expect(parseRoute("")).toEqual({ skin: "a", screen: "watch", param: null });
    expect(parseRoute("#live")).toEqual({ skin: "a", screen: "watch", param: null });
    expect(parseRoute("#story")).toEqual({ skin: "a", screen: "story", param: null });
    expect(parseRoute("#story/abc")).toEqual({ skin: "a", screen: "story", param: "abc" });
    expect(parseRoute("#proof")).toEqual({ skin: "a", screen: "proof", param: null });
  });
  it("keeps a broken address as typed instead of failing", () => {
    expect(parseRoute("#story/%E0%A4%A")).toEqual({ skin: "a", screen: "story", param: "%E0%A4%A" });
    expect(parseRoute("#a/story/%zz")).toEqual({ skin: "a", screen: "story", param: "%zz" });
  });
  it("still opens the old app for the old extra tabs", () => {
    for (const h of ["#scoreboard", "#twin", "#coverage", "#twoMachines"]) expect(parseRoute(h)).toBe(null);
  });
  it("reads the new addresses", () => {
    expect(parseRoute("#a")).toEqual({ skin: "a", screen: "watch", param: null });
    expect(parseRoute("#b/story/3b3e")).toEqual({ skin: "b", screen: "story", param: "3b3e" });
    expect(parseRoute("#a/proof")).toEqual({ skin: "a", screen: "proof", param: null });
  });
});

describe("the camera only moves the picture, and a long story ends on the alert's own chain", () => {
  const W = 1420, H = 420;                                            // the film panel on the demo laptop
  const scene = (inv: ReturnType<typeof longStory>) => {
    const rows = rowsOf(inv);
    return { rows, m: buildMap(inv, rows, { r: 22, off: 50, col: 112, laneH: 104, left: 96, right: 80, top: 96, bottom: 112, stub: 26, compact: 72 }) };
  };
  const inView = (c: { x: number; y: number; k: number }, x: number, y: number, edge = 22) =>
    x * c.k + c.x >= edge && x * c.k + c.x <= W - edge && y * c.k + c.y >= edge && y * c.k + c.y <= H - edge;

  it("frames a short story whole, at every step", () => {
    const inv = sample(), rows = rowsOf(inv), m = buildMap(inv, rows, { r: 22, off: 50, col: 210, laneH: 170, left: 96, right: 80, top: 96, bottom: 112, stub: 26 });
    for (let shown = 1; shown <= rows.length; shown++) {
      const c = camera(m, W, H, shown, rows.length);
      for (const n of m.nodes.filter((x) => x.at <= shown)) expect(inView(c, n.x, n.y)).toBe(true);
    }
  });
  for (const helpers of [8, 3, 14]) {
    it(`ends a long story (${helpers + 3} rails) with every thing of the alert's chain on screen`, () => {
      const { rows, m } = scene(longStory(helpers));
      const c = camera(m, W, H, rows.length, rows.length);
      const chain = m.edges.filter((e) => e.chain);
      expect(chain.map((e) => e.id)).toEqual(["c1", "c2", "c3", "c4"]);
      for (const e of chain) { expect(inView(c, e.sx, e.sy)).toBe(true); expect(inView(c, e.tx, e.ty)).toBe(true); }
      expect(c.k).toBeGreaterThanOrEqual(0.5);                        // and large enough to read the names
    });
  }
  it("follows a long story link by link: the link being told is on screen, source and target", () => {
    const { rows, m } = scene(longStory(8));
    let followed = 0;
    for (let shown = 1; shown < rows.length; shown++) {
      const c = camera(m, W, H, shown, rows.length), e = m.edges.find((x) => x.at === shown)!;
      expect(inView(c, e.tx, e.ty)).toBe(true);                       // where the link arrives is always visible
      if (c.k < 0.9 && c.k >= 0.5 && !m.nodes.filter((n) => n.at <= shown).every((n) => inView(c, n.x, n.y))) {
        followed++;
        if (c.k !== 0.8) expect(inView(c, e.sx, e.sy)).toBe(true);
      }
    }
    expect(followed).toBeGreaterThan(0);                              // this story really is too long to frame whole
  });
  it("puts rails with nothing between them closer together, and never on top of each other", () => {
    const { m } = scene(longStory(8));
    const ys = m.rails.map((r) => r.y);
    const gaps = ys.slice(1).map((y, i) => y - ys[i]);
    expect(Math.min(...gaps)).toBeGreaterThanOrEqual(2 * 22 + 28);    // a shape and its name always fit
    expect(Math.min(...gaps)).toBeLessThan(104);                      // helpers with nothing of their own are packed
    expect(m.rails).toHaveLength(11);                                 // and every rail is still there
    expect(m.edges).toHaveLength(rowsOf(longStory(8)).length);        // every row still draws its link
    // a story that fits the panel is not packed: every rail keeps its full room
    const inv = longStory(8), roomy = buildMap(inv, rowsOf(inv), { r: 22, off: 50, col: 112, laneH: 104, left: 96, right: 80, top: 96, bottom: 112, stub: 26 });
    expect(Math.min(...roomy.rails.slice(1).map((r, i) => r.y - roomy.rails[i].y))).toBe(104);
  });
  it("moves two rails apart exactly where something of one would stand on something of the other", () => {
    // the real case (the sweep of 2026-11-21): a program's name under it, and right below, the name over a
    // thing of the next rail. Seen as "svchost.exe" written across a web address.
    const make = (columnsApart: number) => {
      const inv = sample(), L = inv.report.layout!;
      L.lanes = [{ lane: 0, node_id: "up", short: "up" }, { lane: 1, node_id: "low", short: "low" }];
      L.nodes = [{ id: "up", short: "a-program-with-a-long-name.exe", label: "", kind: "process", icon: "x", lane: 0, order: 0, t_offset_s: 0 },
                 ...Array.from({ length: columnsApart }, (_, i) => ({ id: `pad${i}`, short: "p", label: "", kind: "process", icon: "x", lane: 1, order: 1 + i, t_offset_s: 0 })),
                 { id: "low", short: "low.exe", label: "", kind: "process", icon: "x", lane: 1, order: 50, t_offset_s: 0 },
                 { id: "thing", short: "a-thing-with-a-long-name.example", label: "", kind: "endpoint", icon: "x", lane: 1, order: columnsApart ? 49 : 0.5, t_offset_s: 0 }];
      L.edges = [];
      inv.report.timeline = [];
      const m = buildMap(inv, [], { r: 22, off: 50, col: 112, laneH: 104, left: 96, right: 80, top: 96, bottom: 112, stub: 26, compact: 72 });
      return m.rails[1].y - m.rails[0].y;
    };
    const near = make(0), far = make(8);
    expect(near).toBeGreaterThanOrEqual(22 + 9 + 16 + 50 + 22 + 8 + 16);   // the program's name, then the thing's name over the thing, over its rail
    expect(far).toBeLessThan(80);                                     // the same rails and names, eight columns apart: packed (a shape under a name is all there is)
  });
});

describe("the film tells the rows Python chose, and only those; the report keeps every row", () => {
  const cut = (ids: string[]) => ({ whole: false, ids, rows: ids.length, total: 5, note: "n", counts: { fact: 1, hypothesis: 1, gap: 0 },
    story_counts: { fact: 3, hypothesis: 1, gap: 1 }, labels: { film: "in the film", story: "in the whole story" } });
  it("films every row when Python sends no cut, or says the film is the whole story", () => {
    const inv = sample(), rows = rowsOf(inv);
    expect(filmRows(inv, rows)).toBe(rows);
    inv.film = null;
    expect(filmRows(inv, rows)).toBe(rows);
    inv.film = { ...cut(["e2"]), whole: true };
    expect(filmRows(inv, rows)).toBe(rows);
    expect(filmCut(inv)).toBe(null);
    expect(filmView(inv)).toBe(inv);
  });
  it("films exactly Python's rows, in the story's own order, whatever order the cut lists them in", () => {
    const inv = sample(), rows = rowsOf(inv);
    inv.film = cut(["h1", "e2"]);
    expect(filmRows(inv, rows).map((r) => r.id)).toEqual(["e2", "h1"]);
    expect(rowsOf(inv)).toHaveLength(5);                              // the report's rows are untouched
    inv.film = cut(["e2", "not-a-row"]);                              // an id that is not a row of the story adds nothing
    expect(filmRows(inv, rows).map((r) => r.id)).toEqual(["e2"]);
    expect(filmRows(inv, rows)[0]).toBe(rows.find((r) => r.id === "e2"));   // the same row, words and ink as they were
  });
  it("draws the film's map from Python's cut-down layout, leaving the story's own layout alone", () => {
    const inv = sample(), full = inv.report.layout!;
    const small = { lanes: [full.lanes[1]], nodes: full.nodes.filter((n) => n.id !== "p0"), edges: full.edges.filter((e) => e.id !== "e9") };
    inv.film = { ...cut(["e2", "e7", "h1"]), layout: small };
    const view = filmView(inv);
    expect(view.report.layout).toBe(small);
    expect(inv.report.layout).toBe(full);
    const m = buildMap(view, filmRows(inv, rowsOf(inv)), { r: 22, off: 50, col: 120, laneH: 140, left: 200, right: 80, top: 90, bottom: 110, stub: 30 });
    expect(m.nodes.map((n) => n.id).sort()).toEqual(["f1", "n1", "p1"]);
    expect(m.edges.map((e) => e.id).sort()).toEqual(["e2", "e7", "h1"]);
    expect(m.edges.find((e) => e.id === "h1")!.ink).toBe("hypothesis");     // a suspected link stays suspected in the film
  });
});

describe("Watch asks again for the newest alert's counts when the store has gone quiet", () => {
  // every poll of the dashboard's feed, in order: [a VM run is going, records so far, seconds since the newest one]
  const walk = (polls: [boolean, number | null, number | null][], start = "settled") => {
    const words: string[] = [];
    let prev = start;
    for (const [running, records, seconds] of polls) { prev = previewPhase(prev, running, records, seconds); words.push(prev); }
    return words;
  };
  const asks = (words: string[], first = "settled") => words.filter((w, i) => w !== (i === 0 ? first : words[i - 1])).length;

  it("a replay: the last records come after the alert, and the card asks once more when they are in", () => {
    // found 2026-11-24: the alert lands at 51 records (the card says 7), the 8th line arrives 16 s later, nothing asked again
    const polls: [boolean, number, number][] = [[false, 51, 0], [false, 56, 0], [false, 77, 1], [false, 85, 0], [false, 85, 2], [false, 85, 4], [false, 85, 6], [false, 85, 8], [false, 85, 200]];
    const words = walk(polls);
    expect(words).toEqual(["settled", "settled", "settled", "settled", "settled", "settled", "settled:85", "settled:85", "settled:85"]);
    expect(asks(words)).toBe(1);                                             // once more, when the store is whole; never per poll
    expect(PREVIEW_QUIET_S).toBeGreaterThan(4);                              // longer than any pause inside a refill (about 3.7 s)
  });

  it("a pause inside the refill asks once, and the true end asks again: the card never keeps an early answer", () => {
    const words = walk([[false, 51, 0], [false, 60, 6], [false, 60, 7], [false, 70, 0], [false, 85, 1], [false, 85, 6]]);
    expect(words).toEqual(["settled", "settled:60", "settled:60", "settled:60", "settled:60", "settled:85"]);     // while records arrive the word stays (no step back)
    expect(asks(words)).toBe(2);
  });

  it("a VM run is as it was: asked while it runs, again when it has ended, and once more when its last records are in", () => {
    const words = walk([[true, 10, 0], [true, 40, 0], [false, 40, 1], [false, 44, 0], [false, 44, 6], [false, 44, 60]], "settled");
    expect(words).toEqual(["running", "running", "settled", "settled", "settled:44", "settled:44"]);
    expect(asks(words)).toBe(3);
  });

  it("what is not known changes nothing", () => {
    expect(walk([[false, null, null], [false, 85, null], [false, null, 30]])).toEqual(["settled", "settled", "settled"]);
    expect(previewPhase("settled:85", false, 85, 0)).toBe("settled:85");
    expect(previewPhase("settled:85", true, 85, 0)).toBe("running");
  });
});

describe("what a screen says when it has no alert to show", () => {
  const old = "No alerts have been raised in this recording.";
  it("a replay that is still playing gets Python's sentence for that moment; a whole recording keeps the old one", () => {
    const playing = { replay_playing: { total: 85, records: 14, text: "No alert yet: the replay is still playing (14 of 85 records)." } };
    expect(noAlertsText(playing, old)).toBe("No alert yet: the replay is still playing (14 of 85 records).");
    for (const whole of [{}, { replay_playing: null }, { replay_playing: undefined }, null, undefined, { replay_playing: { text: "" } }, { replay_playing: { text: null } }]) expect(noAlertsText(whole, old)).toBe(old);
  });
});
