import { describe, expect, it } from "vitest";
import { parseRoute } from "../ui2/logic";
import { guideApi, guideHome, guideStepAt, guideSteps, type GuideData } from "./guide";
import { alertOf, allLabs, splitLabParam } from "./registry";

const script: Pick<GuideData, "steps" | "alert"> = {
  alert: { id: "al 1&2", title: "t", level: "medium", time: "2026-11-23T20:19:46", host: "vm" },
  steps: ["why", "replay", "moment", "prove", "network", "respond", "cases"].map((lab) => ({ lab, question: lab + "?", text: "Look at " + lab + "." })),
};
const build = (...ids: string[]) => ids.map((id) => ({ id }));

describe("the walk-through: one alert, start to finish", () => {
  it("numbers the steps this build can walk, each on the same alert, and leaves the others out", () => {
    const all = guideSteps(script, build("why", "replay", "moment", "prove", "network", "respond", "cases", "glance"), []);
    expect(all.steps.map((s) => [s.n, s.lab])).toEqual([[1, "why"], [2, "replay"], [3, "moment"], [4, "prove"], [5, "network"], [6, "respond"], [7, "cases"]]);
    expect(all.leftOut).toEqual([]);
    expect(all.steps.every((s) => s.total === 7 && alertOf(s.href) === "al 1&2")).toBe(true);       // the id survives the address whole
    const some = guideSteps(script, build("replay", "glance", "prove"), []);
    expect(some.steps.map((s) => [s.n, s.total, s.lab])).toEqual([[1, 2, "replay"], [2, 2, "prove"]]);
    expect(some.leftOut).toEqual(["why", "moment", "network", "respond", "cases"]);
    expect(guideSteps(script, build("glance"), [])).toEqual({ steps: [], leftOut: script.steps.map((s) => s.lab), hidden: [] });
    expect(guideSteps({ ...script, alert: null }, build("why", "prove"), []).steps).toEqual([]);         // no alert: nothing to follow
  });

  it("links every step to the one before and the one after, and the last one home", () => {
    const { steps } = guideSteps(script, build("why", "prove", "respond"), []);
    expect(steps[0].back).toBe(null);
    expect(steps[0].next).toBe(steps[1].href);
    expect(steps[1].back).toBe(steps[0].href);
    expect(steps[2].next).toBe(guideHome(true));
    expect(guideHome(true)).toBe("#/labs/guide?done=1");
    expect(guideHome()).toBe("#/labs/guide");
    // each address is one the dashboard's route reader opens, on that lab, with the step in it
    for (const s of steps) {
      const r = parseRoute(s.href)!;
      const { id, params } = splitLabParam(r.param);
      expect([r.screen, id, params.get("guide"), params.get("alert")]).toEqual(["labs", s.lab, String(s.n), "al 1&2"]);
    }
  });

  it("shows a step's bar only on the lab the step belongs to", () => {
    const { steps } = guideSteps(script, build("why", "prove", "respond"), []);
    expect(guideStepAt(steps, "prove", "2")?.question).toBe("prove?");
    for (const [lab, guide] of [["prove", "1"], ["prove", "9"], ["prove", "0"], ["prove", null], ["prove", "two"], ["prove", "2.0"], ["glance", "2"]] as const) {
      expect(guideStepAt(steps, lab, guide)).toBe(null);
    }
  });

  it("a step whose lab is experimental is not walked and is NOT called missing from the build", () => {
    const got = guideSteps(script, build("why", "replay", "prove", "respond"), ["replay", "respond", "yara"]);
    expect(got.steps.map((s) => [s.n, s.total, s.lab])).toEqual([[1, 2, "why"], [2, 2, "prove"]]);
    expect(got.hidden).toEqual(["replay", "respond"]);                       // in the build, listed as experimental
    expect(got.leftOut).toEqual(["moment", "network", "cases"]);            // really not in the build
    expect(got.hidden.some((l) => got.leftOut.includes(l))).toBe(false);
  });

  it("asks for the script of the alert the address names, or of the store's own pick", () => {
    expect(guideApi(null)).toBe("/api/labs/guide");
    expect(guideApi("")).toBe("/api/labs/guide");
    expect(guideApi("3b3e")).toBe("/api/labs/guide?alert=3b3e");
    expect(guideApi("a b&c=d")).toBe("/api/labs/guide?alert=a%20b%26c%3Dd");
  });

  it("is itself a lab of this build, under Start here", async () => {
    const { labs } = await allLabs();
    const g = labs.find((l) => l.id === "guide")!;
    expect(g.group).toBe("start");
    expect(g.title).toBe("One alert, start to finish");
  });
});
