// "Noise meter": the lab entry follows the contract, and the page has no number of its own (all from Python).
import { describe, expect, it } from "vitest";
import { lab } from "./index";
import src from "./index.tsx?raw";

describe("noise lab", () => {
  it("follows the Labs contract", () => {
    expect(lab.id).toBe("noise");
    expect(lab.title).toBeTruthy();
    expect(lab.blurb).toBeTruthy();
    expect(typeof lab.Component).toBe("function");
  });
  it("types none of the measured rates", () => {
    expect(src).toContain("NoisePage");
    for (const n of ["95.2", "6.28", "6.3", "4.22", "4.2", "82.6", "75.6"]) expect(src).not.toContain(n);
  });
});
