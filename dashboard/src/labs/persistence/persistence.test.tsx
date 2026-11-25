// "Persistence before/after": the lab entry follows the contract; a custom window from the address fills the inputs.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { lab } from "./index";

describe("persistence lab", () => {
  it("follows the Labs contract", () => {
    expect(lab.id).toBe("persistence");
    expect(lab.title).toBeTruthy();
    expect(lab.blurb).toBeTruthy();
    expect(typeof lab.Component).toBe("function");
  });
  it("takes a test's start and end from the address", () => {
    const html = renderToStaticMarkup(<lab.Component params={new URLSearchParams("start=2026-11-01T09:00:00Z&end=2026-11-01T10:30:00Z")} />);
    expect(html).toContain('value="2026-11-01T09:00:00"');
    expect(html).toContain('value="2026-11-01T10:30:00"');
    expect(html).not.toMatch(/aria-checked="true"/);          // no preset window is chosen when a custom one is
  });
});
