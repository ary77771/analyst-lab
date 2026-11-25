// "Gap explorer": the lab entry follows the contract and the page renders its controls without a server.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { lab } from "./index";

describe("gaps lab", () => {
  it("follows the Labs contract", () => {
    expect(lab.id).toBe("gaps");
    expect(lab.title).toBeTruthy();
    expect(lab.blurb).toBeTruthy();
    expect(typeof lab.Component).toBe("function");
  });
  it("takes the silence length from the address", () => {
    const html = renderToStaticMarkup(<lab.Component params={new URLSearchParams("silence=30")} />);
    expect(html).toMatch(/aria-checked="true"[^>]*>30 min</);
  });
});
