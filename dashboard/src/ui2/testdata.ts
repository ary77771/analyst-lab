// Made-up data for the front-end tests only (logic.test.ts, report.test.tsx). Never shown on a screen.
import type { Investigation } from "../api";

/** A small investigation whose timeline is deliberately NOT in id, time or lane order. */
export function sample(): Investigation {
  const cite = [{ key: "k", event: 1, record: 1, time: "t", text: "process start (Sysmon 1), record 1" }];
  const tl = (id: string, ink: "fact" | "hypothesis" | "gap", order: number, short: string, off: string | null) =>
    ({ id, short, text: short, ink, grade: ink, order, offset_text: off, t_offset_s: null, icon: "x", in_chain: ink === "fact" });
  return {
    alert: { id: "A", title: "t", rule: "r", source: "s", level: "medium", time: "2026-10-30T20:01:41.825Z", host: "vm", reason: "", events: 1 },
    nodes: [{ id: "p0", label: "p0", kind: "process", gaps: ["origin_unknown"], seed: false, hub: false, hop: false },
            { id: "p1", label: "p1", kind: "process", gaps: [], seed: true, hub: false, hop: false },
            { id: "f1", label: "f1", kind: "file", gaps: [], seed: false, hub: false, hop: false },
            { id: "n1", label: "n1", kind: "endpoint", gaps: [], seed: false, hub: false, hop: false }],
    edges: [], warnings: [],
    report: {
      timeline: [tl("g1", "gap", 0, "Before this: unknown start", null), tl("e9", "fact", 1, "p0 started p1", "0.2 s before"),
                 tl("e2", "fact", 2, "p1 connected to n1", "start"), tl("e7", "fact", 3, "p1 created f1", "within 0.1 s"),
                 tl("h1", "hypothesis", 4, "the content of f1 may have come from n1", "within 0.1 s")],
      facts: [{ id: "e2", sentence: "", kind: "connected_to", time: "", citations: cite }, { id: "e7", sentence: "", kind: "created", time: "", citations: cite },
              { id: "e9", sentence: "", kind: "started", time: "", citations: cite }],
      hypotheses: [{ id: "h1", sentence: "", kind: "content_from", time: "", citations: cite, band: "low", band_label: "weak lead", chance_short: "by chance about 903 in 1,000 times" }],
      gaps: [Object.assign({ id: "g1", what: "origin unknown", where: "p0", reason: "start never recorded", time: "", citations: [] }, { node_id: "p0" })],
      verdict: { title: "t", level: "medium", level_text: "Alert level: medium", host: "vm", time: "2026-10-30T20:01:41.825Z",
        steps: [{ n: 1, id: "e2", text: "", offset_text: "start", t_offset_s: 0, icon: "x", citations: [] }, { n: 2, id: "e7", text: "", offset_text: "", t_offset_s: 0, icon: "x", citations: [] }],
        steps_more: 0, proven: { text: "p", ids: [] }, not_proven: null, cant_see: null },
      counts: { facts: 3, hypotheses: 1, gaps: 1, before: 1, in_chain: 2, steps: 2 },
      layout: {
        lanes: [{ lane: 0, node_id: "p0", short: "p0" }, { lane: 1, node_id: "p1", short: "p1" }],
        nodes: [{ id: "f1", short: "f1", label: "f1", kind: "file", icon: "file", lane: 1, order: 3, t_offset_s: 0 },
                { id: "p1", short: "p1", label: "p1", kind: "process", icon: "program", lane: 1, order: 1, t_offset_s: 0 },
                { id: "n1", short: "n1", label: "n1", kind: "endpoint", icon: "address", lane: 1, order: 2, t_offset_s: 0 },
                { id: "p0", short: "p0", label: "p0", kind: "process", icon: "program", lane: 0, order: 0, t_offset_s: 0 }],
        edges: [{ id: "h1", u: "n1", v: "f1", kind: "content_from", grade: "hypothesis", band: "low", lane: 1, order: 4, icon: "x", short: "", in_chain: false },
                { id: "e7", u: "p1", v: "f1", kind: "created", grade: "fact", band: null, lane: 1, order: 3, icon: "x", short: "", in_chain: true },
                { id: "e9", u: "p0", v: "p1", kind: "started", grade: "fact", band: null, lane: 0, order: 1, icon: "x", short: "", in_chain: false },
                { id: "e2", u: "p1", v: "n1", kind: "connected_to", grade: "fact", band: null, lane: 1, order: 2, icon: "x", short: "", in_chain: true }],
      },
      summary: "", summary_lines: [], declared_banner: null, limitations: [], next_steps: [],
    },
  };
}

/**
 * A long made-up story shaped like a real live run: one starter program that starts `helpers` programs
 * (each on its own rail, with nothing of its own), then the alert's own chain on the last two rails
 * (a program connects out, creates a file, starts it). `helpers` = 8 gives 11 rails and 24 rows.
 */
export function longStory(helpers = 8): Investigation {
  const inv = sample();
  const L = inv.report.layout!;
  L.lanes = []; L.nodes = []; L.edges = []; inv.report.timeline = [];
  let order = 0;
  const lane = (id: string) => { L.lanes.push({ lane: L.lanes.length, node_id: id, short: id }); return L.lanes.length - 1; };
  const node = (id: string, kind: string, ln: number) => L.nodes.push({ id, short: id, label: id, kind, icon: "x", lane: ln, order: order++, t_offset_s: 0 });
  const link = (id: string, u: string, v: string, ln: number, chain: boolean, grade: "fact" | "hypothesis" = "fact") => {
    L.edges.push({ id, u, v, kind: "k", grade, band: grade === "hypothesis" ? "low" : null, lane: ln, order: order++, icon: "x", short: "", in_chain: chain });
    inv.report.timeline.push({ id, short: id, text: id, ink: grade, grade, order: order, offset_text: null, t_offset_s: null, icon: "x", in_chain: chain });
  };
  const top = lane("starter");
  node("starter", "process", top);
  for (let i = 0; i < helpers; i++) {
    const ln = lane(`helper${i}`);
    node(`helper${i}`, "process", ln);
    link(`start${i}`, "starter", `helper${i}`, top, false);
    if (i % 3 === 0) { node(`note${i}`, "file", top); link(`write${i}`, "starter", `note${i}`, top, false); }
  }
  const a = lane("fetch"), b = lane("payload");
  node("fetch", "process", a);
  link("startfetch", "starter", "fetch", top, false);
  node("server", "endpoint", a); link("c1", "fetch", "server", a, true);
  node("dropped", "file", a); link("c2", "fetch", "dropped", a, true);
  link("guess", "server", "dropped", a, false, "hypothesis");
  node("payload", "process", b); link("c3", "fetch", "payload", a, true);
  link("c4", "payload", "dropped", b, true);
  // and the story goes on elsewhere after the chain: the last row is far from it
  link("late", "starter", "helper0", top, false);
  return inv;
}
