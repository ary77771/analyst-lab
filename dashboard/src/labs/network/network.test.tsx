// "Network view": the lab entry follows the contract and the page renders without a server.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { lab } from "./index";

describe("network lab", () => {
  it("follows the Labs contract", () => {
    expect(lab.id).toBe("network");
    expect(lab.title).toBeTruthy();
    expect(lab.blurb).toBeTruthy();
    expect(typeof lab.Component).toBe("function");
  });
  it("renders its window choice from the address", () => {
    const html = renderToStaticMarkup(<lab.Component params={new URLSearchParams("window=7d")} />);
    expect(html).toMatch(/aria-checked="true"[^>]*>7d</);
    expect(html).not.toContain(">all<");                     // the rhythm needs a bounded window
  });
});
