import { describe, expect, it } from "vitest";
import { fill, pieces } from "./logic";

describe("highlight pieces", () => {
  it("marks exactly the spans Python sent", () => {
    const p = pieces("ping -n 5 127.0.0.1", [[5, 8], [10, 19]]);
    expect(p.filter((x) => x.hit).map((x) => x.text)).toEqual(["-n ", "127.0.0.1"]);
    expect(p.map((x) => x.text).join("")).toBe("ping -n 5 127.0.0.1");
  });
  it("merges overlaps and clips spans outside the text", () => {
    const p = pieces("abcdef", [[4, 99], [1, 3], [2, 4]]);
    expect(p).toEqual([{ text: "a", hit: false }, { text: "bcdef", hit: true }]);
  });
  it("no spans: the whole value, unmarked", () => {
    expect(pieces("xyz")).toEqual([{ text: "xyz", hit: false }]);
    expect(pieces("")).toEqual([{ text: "", hit: false }]);
  });
});

describe("fill", () => {
  it("fills named slots and leaves unknown ones", () => {
    expect(fill("{shown} of {total} events shown.", { shown: 2, total: 9 })).toBe("2 of 9 events shown.");
    expect(fill("{x}", {})).toBe("{x}");
  });
});
