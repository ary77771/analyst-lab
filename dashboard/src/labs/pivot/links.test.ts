import { describe, expect, it } from "vitest";
import { groupByKind, kindFrom, loadTrail, nextTrail, pivotHref, rawQuery, saveTrail, shortName, utc } from "./links";

describe("pivot links", () => {
  it("builds a deep link that survives backslashes and colons", () => {
    const h = pivotHref("file", "C:\\Users\\u\\tool.exe");
    expect(h.startsWith("#/labs/pivot?")).toBe(true);
    const q = new URLSearchParams(h.slice(h.indexOf("?") + 1));
    expect(q.get("kind")).toBe("file");
    expect(q.get("value")).toBe("C:\\Users\\u\\tool.exe");
  });

  it("keeps & + % = in a value through the address (decoded once)", () => {
    const v = "C:\\a++b&c=d 100%.exe";
    const h = pivotHref("program", v);
    const q = new URLSearchParams(rawQuery(h));
    expect(q.get("value")).toBe(v);
    expect(q.get("kind")).toBe("program");
    expect(rawQuery("#/labs/pivot")).toBe("");
  });

  it("takes the kind from kind= or from another lab's field=", () => {
    expect(kindFrom(new URLSearchParams("kind=hash&value=x"))).toBe("hash");
    expect(kindFrom(new URLSearchParams("field=Image&value=x"))).toBe("program");
    expect(kindFrom(new URLSearchParams("field=DestinationHostname&value=x"))).toBe("domain");
    expect(kindFrom(new URLSearchParams("field=Nope&value=x"))).toBeNull();
  });

  it("shortens names for chips", () => {
    expect(shortName("program", "C:\\Users\\u\\fetch.exe")).toBe("fetch.exe");
    expect(shortName("hash", "ab".repeat(32))).toBe("abababababab…");
    expect(shortName("registry", "HKU\\S\\Software\\Run\\tool")).toBe("…\\Run\\tool");
    expect(shortName("ip", "10.0.2.2")).toBe("10.0.2.2");
    expect(shortName("process", "{F00DCAFE-1}")).toBe("F00DCAFE");
  });

  it("formats UTC times and unknowns", () => {
    expect(utc("2026-10-22T10:00:05.123Z")).toBe("2026-10-22 10:00:05 UTC");
    expect(utc(null)).toBe("?");
  });

  it("keeps a short trail without repeats, newest last", () => {
    let t = nextTrail([], { kind: "ip", value: "10.0.2.2" });
    t = nextTrail(t, { kind: "file", value: "A" });
    t = nextTrail(t, { kind: "ip", value: "10.0.2.2" });
    expect(t.map((e) => e.value)).toEqual(["A", "10.0.2.2"]);
    for (let i = 0; i < 20; i++) t = nextTrail(t, { kind: "user", value: `u${i}` }, 5);
    expect(t.length).toBe(5);
    expect(t[4].value).toBe("u19");
  });

  it("stores and reads the trail, ignoring junk", () => {
    const box: Record<string, string> = {};
    const store = { getItem: (k: string) => box[k] ?? null, setItem: (k: string, v: string) => { box[k] = v; } };
    saveTrail([{ kind: "ip", value: "10.0.2.2" }], store);
    expect(loadTrail(store)).toEqual([{ kind: "ip", value: "10.0.2.2" }]);
    box["analystlab.pivot.trail"] = "not json";
    expect(loadTrail(store)).toEqual([]);
  });

  it("groups by kind in the lab's order", () => {
    const g = groupByKind([{ kind: "ip" }, { kind: "program" }, { kind: "ip" }, { kind: "new-kind" }]);
    expect(g.map(([k, v]) => `${k}:${v.length}`)).toEqual(["program:1", "ip:2", "new-kind:1"]);
  });
});
