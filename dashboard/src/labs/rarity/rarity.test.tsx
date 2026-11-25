// "First seen / rare here": the lab entry follows the contract and the page renders a stack from Python.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { lab } from "./index";

describe("rarity lab", () => {
  it("follows the Labs contract", () => {
    expect(lab.id).toBe("rarity");
    expect(lab.title).toBeTruthy();
    expect(lab.blurb).toBeTruthy();
    expect(lab.icon).toBeTruthy();
    expect(typeof lab.Component).toBe("function");
  });
  it("renders its controls before any data arrives (no crash without a server)", () => {
    const html = renderToStaticMarkup(<lab.Component params={new URLSearchParams("kind=pairs&window=30d")} />);
    expect(html).toContain("Parent → child");
    expect(html).toContain('aria-pressed="true"');
    expect(html).toMatch(/aria-checked="true"[^>]*>30d</);
  });
  it("explains 'stack counting' in everyday words on hover (W3-6)", () => {
    const html = renderToStaticMarkup(<lab.Component params={new URLSearchParams()} />);
    expect(html).toMatch(/<abbr[^>]*title="the rarer, the more interesting"[^>]*>Stack counting<\/abbr>/);
  });
});
