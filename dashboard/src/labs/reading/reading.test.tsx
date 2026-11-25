// "Reading effort": the lab entry follows the contract and the page claims no time saved and types no count.
import { describe, expect, it } from "vitest";
import { lab } from "./index";
import src from "./index.tsx?raw";

describe("reading lab", () => {
  it("follows the Labs contract", () => {
    expect(lab.id).toBe("reading");
    expect(lab.title).toBeTruthy();
    expect(lab.blurb).toBeTruthy();
    expect(typeof lab.Component).toBe("function");
  });
  it("never speaks of minutes or time saved", () => {
    expect(src.toLowerCase()).not.toMatch(/minutes? saved|time saved|hours? saved|faster/);
  });
});
