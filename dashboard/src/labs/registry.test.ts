import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Gauge } from "lucide-react";
import { parseRoute } from "../ui2/logic";
import { Guard } from "./LabsScreen";
import { ALERT_PATH, EXPERIMENTAL, GROUPS, GROUP_OF, alertOf, allLabs, collect, countExperimental, findLab, groupLabs, groupOf, isExperimental, labHref, loadLabs,
  isStaleBuild, pathFor, readShowExperimental, runName, splitLabParam, storeState, withAlert, writeShowExperimental, type Lab, type Loaders } from "./registry";
import { guideSteps } from "./guide";

// the fixture labs (dashboard/src/labs/__fixtures__/): never part of the build, loaded here the way the build loads a lab
const fixtures: Loaders = {
  "./fine/index.tsx": () => import("./__fixtures__/fine/index"),
  "./broken/index.tsx": () => import("./__fixtures__/broken/index") as Promise<{ lab?: Partial<Lab> }>,
  "./crashes/index.tsx": () => import("./__fixtures__/crashes/index"),
};

describe("the Labs registry", () => {
  it("finds the labs of this build by themselves, from their folders, and nothing of the fixtures", async () => {
    const { labs, leftOut } = await allLabs();
    expect(labs.map((l) => l.id)).toEqual(expect.arrayContaining(["glance", "replay"]));
    expect(labs.map((l) => l.id)).not.toEqual(expect.arrayContaining(["fine"]));
    expect(leftOut).toEqual([]);
    const g = findLab(labs, "glance")!;
    expect(g.title).toBeTruthy();
    expect(g.blurb).toBeTruthy();
    expect(typeof g.Component).toBe("function");
    expect(findLab(labs, "no-such-lab")).toBe(null);
    expect(findLab(labs, null)).toBe(null);
  });

  it("a lab that throws while it loads is left out and named, and every other lab loads", async () => {
    const { labs, leftOut } = await loadLabs(fixtures);
    expect(labs.map((l) => l.id).sort()).toEqual(["crashes", "fine"]);                 // both working files are in
    expect(leftOut).toEqual([{ path: "./broken/index.tsx", id: "broken", problem: "failed to load: this lab is broken on purpose" }]);
  });

  it("the same for a lab whose piece of the build can't be fetched, or whose loader throws at once", async () => {
    const { labs, leftOut } = await loadLabs({
      ...fixtures,
      "./offline/index.tsx": () => Promise.reject(new TypeError("Failed to fetch dynamically imported module")),
      "./sync/index.tsx": () => { throw new Error("thrown before any promise"); },
    });
    expect(labs.map((l) => l.id).sort()).toEqual(["crashes", "fine"]);
    expect(Object.fromEntries(leftOut.map((x) => [x.id, x.problem]))).toEqual({
      broken: "failed to load: this lab is broken on purpose",
      offline: "failed to load: Failed to fetch dynamically imported module",
      sync: "failed to load: thrown before any promise",
    });
    expect(await loadLabs({})).toEqual({ labs: [], leftOut: [] });
  });

  it("a lab whose page throws while it is drawn is kept to its own place", async () => {
    const { labs } = await loadLabs(fixtures);
    const crashes = findLab(labs, "crashes")!;
    expect(() => renderToStaticMarkup(createElement(crashes.Component, { params: new URLSearchParams() }))).toThrow("crashes on purpose");
    // the screen wraps every lab's page in this guard: what it shows once a page has thrown
    const state = Guard.getDerivedStateFromError(new Error("this lab's page crashes on purpose"));
    expect(state).toEqual({ error: "this lab's page crashes on purpose" });
    const guard = new Guard({ name: "crashes?", children: null });
    guard.state = state;
    const shown = renderToStaticMarkup(createElement("div", null, guard.render()));
    expect(shown).toContain("This lab ran into an error and stopped. The rest of the dashboard is not affected.");
    expect(shown).toContain("crashes on purpose");
    expect(renderToStaticMarkup(createElement("div", null, new Guard({ name: "fine?", children: "the page" }).render()))).toBe("<div>the page</div>");
  });

  it("leaves out a folder that is not a proper lab, and says why", () => {
    const ok = (id: string, title = id): Lab => ({ id, title, blurb: "b", icon: Gauge, Component: () => null });
    const got = collect({
      "./zeta/index.tsx": { lab: ok("zeta", "Zeta") },
      "./alpha/index.tsx": { lab: ok("alpha", "Alpha") },
      "./wrong/index.tsx": { lab: ok("another-name") },
      "./empty/index.tsx": {},
      "./Bad_Name/index.tsx": { lab: ok("Bad_Name") },
      "./half/index.tsx": { lab: { id: "half", title: "Half" } },
    });
    expect(got.labs.map((l) => l.id)).toEqual(["alpha", "zeta"]);          // by title
    expect(Object.fromEntries(got.leftOut.map((x) => [x.path, x.problem]))).toEqual({
      "./wrong/index.tsx": `its id must be its folder's name ("wrong")`,
      "./empty/index.tsx": "exports no `lab`",
      "./Bad_Name/index.tsx": "its id may hold lower-case letters, digits and - only",
      "./half/index.tsx": "needs a title, a blurb, an icon and a Component",
    });
    expect(got.leftOut.find((x) => x.path === "./wrong/index.tsx")!.id).toBe("wrong");
  });

  it("gives every lab an address that the dashboard's own route reader opens", () => {
    expect(labHref()).toBe("#/labs");
    expect(labHref("glance")).toBe("#/labs/glance");
    expect(labHref("pivot", { hash: "ab12", t: 5, none: null, empty: "" })).toBe("#/labs/pivot?hash=ab12&t=5");
    expect(parseRoute("#/labs")).toEqual({ skin: "a", screen: "labs", param: null });
    expect(parseRoute("#labs")).toEqual({ skin: "a", screen: "labs", param: null });
    expect(parseRoute("#/labs/glance")).toEqual({ skin: "a", screen: "labs", param: "glance" });
    expect(parseRoute("#a/labs/glance")).toEqual({ skin: "a", screen: "labs", param: "glance" });
    expect(splitLabParam(null)).toEqual({ id: null, params: new URLSearchParams() });
    expect(splitLabParam("glance/").id).toBe("glance");
  });

  it("a value in a lab's address survives the trip whole: & + % = and spaces (decoded once, by the lab's reader)", () => {
    // found by night-pivot: the route reader used to decode the address too, so "&" split the value and "+" became a space
    for (const value of ["a b/c?d", "C:\\dir\\a&b.exe", "1+1=2", "100%", "50%25 off", "k=v&k2=v2", "ünï cödé", "#hash"]) {
      const r = parseRoute(labHref("pivot", { kind: "file", value }))!;
      expect(r.screen).toBe("labs");
      const { id, params } = splitLabParam(r.param);
      expect(id).toBe("pivot");
      expect(params.get("kind")).toBe("file");
      expect(params.get("value")).toBe(value);
      expect([...params.keys()]).toEqual(["kind", "value"]);
    }
    // an address built with URLSearchParams by hand (as night-pivot does) reads the same
    const q = new URLSearchParams({ kind: "file", value: "C:\\a&b+c" });
    expect(splitLabParam(parseRoute(`#/labs/pivot?${q}`)!.param).params.get("value")).toBe("C:\\a&b+c");
  });

  it("leaves the rehearsed addresses exactly as they were", () => {
    expect(parseRoute("")).toEqual({ skin: "a", screen: "watch", param: null });
    expect(parseRoute("#live")).toEqual({ skin: "a", screen: "watch", param: null });
    expect(parseRoute("#story/abc")).toEqual({ skin: "a", screen: "story", param: "abc" });
    expect(parseRoute("#proof")).toEqual({ skin: "a", screen: "proof", param: null });
    expect(parseRoute("#a/story/labs")).toEqual({ skin: "a", screen: "story", param: "labs" });
    expect(parseRoute("#b/story/3b3e")).toEqual({ skin: "b", screen: "story", param: "3b3e" });
    for (const h of ["#scoreboard", "#twin", "#coverage", "#twoMachines"]) expect(parseRoute(h)).toBe(null);
  });
});

describe("the labs as one investigation (wave 3)", () => {
  const lab = (id: string, group?: Lab["group"]) => ({ id, group });

  it("puts every lab under exactly one question, and a lab nobody placed under Other", async () => {
    const { labs } = await allLabs();
    const groups = groupLabs(labs, false, []);                                             // (with nothing hidden: the questions alone)
    expect(groups.flatMap((g) => g.labs.map((l) => l.id)).sort()).toEqual(labs.map((l) => l.id).sort());      // each once, none lost
    expect(groups.map((g) => g.id)).toEqual(GROUPS.map((g) => g.id).filter((id) => groups.some((g) => g.id === id)));   // in the questions' own order
    expect(groupLabs(labs, true).flatMap((g) => g.labs.map((l) => l.id)).sort()).toEqual(labs.map((l) => l.id).sort());   // and with the list as it stands, switched on
    expect(groups.every((g) => g.labs.length > 0)).toBe(true);
    expect(groupOf(lab("replay"))).toBe("start");
    expect(["guide", "checklist", "whatsnew"].map((id) => groupOf(lab(id)))).toEqual(["start", "start", "start"]);
    expect(["tree", "sweep"].map((id) => groupOf(lab(id)))).toEqual(["happened", "happened"]);
    expect(["receipts", "noise", "storydiff", "techniques"].map((id) => groupOf(lab(id)))).toEqual(["tool", "tool", "tool", "tool"]);
    // a placement decided for the whole product wins over the lab's own word (the track record's file says "sure")
    expect(groupOf({ id: "receipts", group: "sure" })).toBe("tool");
    expect(groupOf({ id: "prove", group: "sure" })).toBe("sure");
    expect(groupOf(lab("glance"))).toBe("sure");
    const made = groupLabs([lab("zz-new-lab"), lab("why"), lab("noise"), lab("prove"), lab("zz-own", "now"), lab("why2", "nonsense" as Lab["group"])], false, []);
    expect(Object.fromEntries(made.map((g) => [g.id, g.labs.map((l) => l.id)]))).toEqual({
      happened: ["why"], sure: ["prove"], now: ["zz-own"], tool: ["noise"], other: ["zz-new-lab", "why2"],
    });
    expect(made[made.length - 1].title).toBe("Other");
    // the table places only into questions that exist, and never the same lab twice
    expect(Object.values(GROUP_OF).every((g) => GROUPS.some((x) => x.id === g))).toBe(true);
    expect(GROUPS.map((g) => g.title)).toEqual(["Start here", "What happened?", "How sure are we?", "How far did it go?", "What now?", "Testing the tool itself", "Other"]);
    // the first move and the secondary group each say in one line what they are; the questions speak for themselves
    expect(GROUPS.filter((g) => g.note).map((g) => g.id)).toEqual(["start", "tool"]);
    expect(GROUPS.find((g) => g.id === "start")!.note).toContain("Pick an alert");
    expect(GROUPS.find((g) => g.id === "tool")!.note).toContain("not steps of an investigation");
    expect(groupLabs([lab("checklist"), lab("noise")], false, []).map((g) => [g.id, g.note !== ""])).toEqual([["start", true], ["tool", true]]);
    // inside a question: the strip's labs first, in the strip's order; then the rest as they came (by title)
    const byTitle = ["moment", "sweep", "pivot", "tree", "why", "fileinspect", "rarity", "network", "persistence", "hunts"].map((id) => lab(id));
    const inOrder = Object.fromEntries(groupLabs(byTitle, false, []).map((g) => [g.id, g.labs.map((l) => l.id)]));
    expect(inOrder).toEqual({ happened: ["why", "moment", "tree", "sweep", "pivot"], far: ["network", "persistence", "fileinspect", "rarity", "hunts"] });
  });

  it("reads the alert from a lab address and writes it back, leaving everything else alone", () => {
    expect(alertOf("#/labs/why?alert=17")).toBe("17");
    expect(alertOf("#a/labs/prove?x=1&alert=3b3e-1")).toBe("3b3e-1");
    for (const none of ["#/labs/why", "#/labs/why?alert=", "#/labs", "#/labs?alert=5", "#story/abc?alert=5", "", "#proof"]) expect(alertOf(none)).toBe(null);
    expect(withAlert("#/labs/why", "17")).toBe("#/labs/why?alert=17");
    expect(withAlert("#/labs/why?alert=17", "18")).toBe("#/labs/why?alert=18");
    expect(withAlert("#/labs/moment?seconds=30&alert=17&event=9", null)).toBe("#/labs/moment?seconds=30&event=9");
    expect(withAlert("#/labs/moment?seconds=30&event=9", "a b&c")).toBe("#/labs/moment?seconds=30&event=9&alert=a+b%26c");
    expect(alertOf(withAlert("#/labs/moment?seconds=30", "a b&c"))).toBe("a b&c");                 // the id survives the trip whole
    for (const other of ["#story/abc", "#/labs", "", "#watch"]) expect(withAlert(other, "17")).toBe(other);   // never another screen's address
    // what a lab's own list of alerts links to is what the reader reads
    expect(alertOf(labHref("prove", { alert: "17" }))).toBe("17");
    expect(parseRoute(withAlert("#/labs/why", "17"))).toEqual({ skin: "a", screen: "labs", param: "why?alert=17" });
  });

  it("the strip carries the same alert to every lab of the path that is in the build, in the path's order", () => {
    const all = ALERT_PATH.map((p) => ({ id: p.lab }));
    const chips = pathFor(all, "prove", "17", []);
    // PROOF's order after the critiques of night 2
    expect(chips.map((c) => c.lab)).toEqual(["checklist", "why", "moment", "tree", "prove", "network", "sweep", "persistence", "respond", "cases"]);
    // the process tree has no chip until it is part of the build; "alarm" is no step any more
    expect(pathFor(all.filter((l) => l.id !== "tree").concat({ id: "alarm" }), "why", "17").map((c) => c.lab)).toEqual(["checklist", "why", "moment", "prove", "network", "sweep", "persistence", "respond", "cases"]);
    expect(chips.every((c) => alertOf(c.href) === "17" && c.label && c.hint)).toBe(true);
    expect(chips.filter((c) => c.current).map((c) => c.lab)).toEqual(["prove"]);
    // only labs that are part of this build; with no alert picked the chips open each lab's own list
    const some = pathFor([{ id: "why" }, { id: "glance" }, { id: "respond" }], "why", null, []);
    expect(some.map((c) => [c.lab, c.href])).toEqual([["why", "#/labs/why"], ["respond", "#/labs/respond"]]);
    expect(pathFor([{ id: "glance" }, { id: "replay" }], "glance", "17", [])).toEqual([]);
    expect(new Set(ALERT_PATH.map((p) => p.lab)).size).toBe(ALERT_PATH.length);
    // a check of the tool is not a step of an investigation: no strip on such a page, even when it asks for one
    const built = [...all, { id: "receipts", group: "sure" as const }, { id: "storydiff" }, { id: "noise" }, { id: "techniques", group: "tool" as const }];
    for (const tool of ["receipts", "storydiff", "noise", "techniques"]) expect(pathFor(built, tool, "17", [])).toEqual([]);
    expect(pathFor(built, "claim", "17", []).length).toBe(ALERT_PATH.length);              // a lab off the path that IS about the alert keeps it
  });

  it("says a test run with its everyday name, and never makes one up", () => {
    const names = { s1: "Download and run", b18: "Sync agent sweeps saved secrets and sends them in slow slices" };
    expect(runName("s1", names)).toBe("S1 \u00b7 Download and run");
    expect(runName(" S1 ", names)).toBe("S1 \u00b7 Download and run");
    expect(runName("b33", names)).toBe("B33 \u00b7 unnamed run");
    expect(runName("s2j", {})).toBe("S2J \u00b7 unnamed run");
    expect(runName("s1", null)).toBe("S1");                                 // the names have not loaded yet: the code alone, no guess
  });
});

describe("experimental labs: kept, but not shown unless switched on (night 2)", () => {
  const lab = (id: string) => ({ id });
  const build = ["why", "moment", "prove", "network", "respond", "cases", "rarity", "yara", "zz-new"].map(lab);
  const hidden = ["rarity", "network", "zz-new"];

  it("leaves them off the Labs page, and with the switch on shows each once, under Experimental and nowhere else", () => {
    const off = groupLabs(build, false, hidden);
    expect(off.flatMap((g) => g.labs.map((l) => l.id)).sort()).toEqual(["cases", "moment", "prove", "respond", "why", "yara"]);
    expect(off.some((g) => g.id === "experimental" || g.id === "other")).toBe(false);          // an unplaced hidden lab does not show as "Other" either
    const on = groupLabs(build, true, hidden);
    expect(on[on.length - 1]).toEqual({ id: "experimental", title: "Experimental", note: "", labs: [lab("network"), lab("rarity"), lab("zz-new")].sort((a, b) => build.findIndex((x) => x.id === a.id) - build.findIndex((x) => x.id === b.id)) });
    expect(on.flatMap((g) => g.labs.map((l) => l.id)).sort()).toEqual(build.map((l) => l.id).sort());     // every lab once
    expect(on.slice(0, -1)).toEqual(off);                                                    // the questions' own groups do not change
    expect(groupLabs(build, true, [])).toEqual(groupLabs(build, false, []));                 // nothing hidden: no such group, switch or not
    expect(countExperimental(build, hidden)).toBe(3);
    expect(countExperimental(build, ["not-in-this-build"])).toBe(0);
    expect(isExperimental("rarity", hidden) && !isExperimental("why", hidden)).toBe(true);
  });

  it("the strip and the walk-through never lead to one", () => {
    expect(pathFor(build, "why", "17", hidden).map((c) => c.lab)).toEqual(["why", "moment", "prove", "respond", "cases"]);
    expect(pathFor(build, "network", "17", hidden).some((c) => c.current)).toBe(false);       // opened directly, it is not a step of the path
    const script = { alert: { id: "17", title: "t", level: "medium", time: "", host: "vm" }, steps: ["why", "network", "prove", "rarity"].map((l) => ({ lab: l, question: l, text: l })) };
    const walk = guideSteps(script, build, hidden);
    expect(walk.steps.map((s) => [s.n, s.total, s.lab])).toEqual([[1, 2, "why"], [2, 2, "prove"]]);
    expect(walk.steps[0].next).toBe(walk.steps[1].href);
  });

  it("the switch is off until someone turns it on, is remembered in the browser, and works without any storage", () => {
    const kept = new Map<string, string>();
    const box = { getItem: (k: string) => kept.get(k) ?? null, setItem: (k: string, v: string) => void kept.set(k, v), removeItem: (k: string) => void kept.delete(k) };
    expect(readShowExperimental(box)).toBe(false);
    writeShowExperimental(box, true);
    expect(readShowExperimental(box)).toBe(true);
    expect([...kept.keys()]).toEqual(["analystlab.labs.showExperimental"]);
    writeShowExperimental(box, false);
    expect(readShowExperimental(box)).toBe(false);
    expect(kept.size).toBe(0);
    const broken = { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); }, removeItem: () => { throw new Error("blocked"); } };
    expect(readShowExperimental(broken)).toBe(false);
    expect(() => writeShowExperimental(broken, true)).not.toThrow();
    expect(readShowExperimental(null)).toBe(false);
    expect(() => writeShowExperimental(undefined, true)).not.toThrow();
  });

  it("the list itself names each lab once, by a lab's kind of name; with it as it stands every shown lab is on the page once", async () => {
    expect(new Set(EXPERIMENTAL).size).toBe(EXPERIMENTAL.length);
    expect(EXPERIMENTAL.every((id) => /^[a-z0-9-]+$/.test(id))).toBe(true);
    // PROOF's list of night 2; the checklist and the labs of the strip are never among them
    expect([...EXPERIMENTAL].sort()).toEqual(["alarm", "fileinspect", "glance", "guide", "lolbas", "reading", "replay", "rulesandbox", "secondopinion", "start", "whatsnew"]);
    expect(ALERT_PATH.map((p) => p.lab).filter((l) => isExperimental(l))).toEqual([]);
    for (const shown of ["checklist", "why", "moment", "pivot", "prove", "gaps", "claim", "network", "persistence", "hunts", "rarity", "respond", "cases", "receipts", "noise", "storydiff", "tree", "sweep"]) expect(isExperimental(shown)).toBe(false);
    const { labs } = await allLabs();
    const shown = groupLabs(labs).flatMap((g) => g.labs.map((l) => l.id)).sort();
    expect(shown).toEqual(labs.map((l) => l.id).filter((id) => !isExperimental(id)).sort());
    // a hidden lab's address still opens it: the registry still finds it
    for (const id of EXPERIMENTAL) if (labs.some((l) => l.id === id)) expect(findLab(labs, id)?.id).toBe(id);
  });
});

describe("may a lab speak right now? (critique 3: a refilling replay must never read as a finding)", () => {
  it("a replay is ready when the replay itself says it has finished, and not a moment before", () => {
    const filling = (records: number | null, total: number | null) => ({ kind: "filling", records, total });
    expect(storeState("replay", "Failed to fetch", null, { total: 85, done: true })).toEqual({ kind: "down" });
    expect(storeState("replay", null, null, undefined)).toEqual(filling(null, null));                  // nothing asked yet: no number is known
    expect(storeState("replay", null, { records: 0, seconds: null }, { total: 85, done: false })).toEqual(filling(0, 85));
    expect(storeState("replay", null, { records: 51, seconds: 0 }, { total: 85, done: false })).toEqual(filling(51, 85));
    // a quiet stretch INSIDE the recording is not the end: the store has been still for a minute, the replay is not done
    expect(storeState("replay", null, { records: 60, seconds: 60 }, { total: 85, done: false })).toEqual(filling(60, 85));
    // every record is in, but the last scoring pass (the alert) is still to come
    expect(storeState("replay", null, { records: 85, seconds: 1 }, { total: 85, done: false })).toEqual(filling(85, 85));
    expect(storeState("replay", null, { records: 85, seconds: 0 }, { total: 85, done: true })).toEqual({ kind: "ready" });
    expect(storeState("replay", null, null, { total: 85, done: true })).toEqual({ kind: "ready" });
  });

  it("where the server can't say (an older one), a replay must have records and have been still for longer than any pause inside a refill", () => {
    const filling = (records: number | null) => ({ kind: "filling", records, total: null });
    expect(storeState("replay", null, null, null)).toEqual(filling(null));
    expect(storeState("replay", null, { records: 0, seconds: 30 }, null)).toEqual(filling(0));                  // an empty store is never "whole"
    expect(storeState("replay", null, { records: 85, seconds: 4 }, null)).toEqual(filling(85));                 // 4 s can be a pause inside a refill
    expect(storeState("replay", null, { records: 85, seconds: 7 }, null)).toEqual(filling(85));
    expect(storeState("replay", null, { records: 85, seconds: 8 }, null)).toEqual({ kind: "ready" });
    expect(storeState("replay", null, { records: 85 }, null)).toEqual(filling(85));                             // not knowing is never "ready"
  });

  it("a live store grows all the time and is ready; a silent server is said, whatever the mode", () => {
    expect(storeState("live", null, { records: 931, seconds: 0 })).toEqual({ kind: "ready" });
    expect(storeState("live", null, null)).toEqual({ kind: "ready" });
    expect(storeState(null, null, { records: 0, seconds: null })).toEqual({ kind: "ready" });
    expect(storeState("rehearsal", null, { records: 5, seconds: 0 })).toEqual({ kind: "ready" });
    for (const mode of ["live", "replay", null, undefined]) expect(storeState(mode, "/api/health: 500", { records: 85, seconds: 99 }, { total: 85, done: true })).toEqual({ kind: "down" });
  });

  it("a page whose code can't be fetched after a rebuild is a stale tab, not a broken lab", () => {
    for (const p of ["failed to load: Failed to fetch dynamically imported module: http://x/assets/index-abc.js", "failed to load: Importing a module script failed.",
      "failed to load: error loading dynamically imported module", "failed to load: Failed to fetch", "failed to load: 'text/html' is not a valid JavaScript MIME type."]) expect(isStaleBuild(p)).toBe(true);
    for (const p of ["failed to load: this lab is broken on purpose", "exports no `lab`", `its id must be its folder's name ("wrong")`, "", null, undefined]) expect(isStaleBuild(p)).toBe(false);
  });
});
