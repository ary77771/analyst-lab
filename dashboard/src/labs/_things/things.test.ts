import { describe, expect, it } from "vitest";
import { plusCasePin, thingHref, thingKind, thingShort, thingValue } from "./things";

const HASH = "AB".repeat(32);

describe("shared things", () => {
  it("takes the kind from kind= or from a Sysmon field", () => {
    expect(thingKind("hash")).toBe("hash");
    expect(thingKind(null, "Image")).toBe("program");
    expect(thingKind(null, "DestinationHostname")).toBe("domain");
    expect(thingKind("colour")).toBeNull();
    expect(thingKind(null, "Nope")).toBeNull();
  });

  it("refuses values that are not things", () => {
    expect(thingValue("program", "")).toBeNull();
    expect(thingValue("domain", "-")).toBeNull();
    expect(thingValue("process", "{00000000-0000-0000-0000-000000000000}")).toBeNull();
    expect(thingValue("hash", "not a hash")).toBeNull();
    expect(thingValue("hash", `MD5=${"0".repeat(32)},SHA256=${HASH}`)).toBe(HASH.toLowerCase());
  });

  it("links to the pivot page, keeping & + % in values", () => {
    const h = thingHref("file", "C:\\a++b&c.exe", "analystlab-vm")!;
    const q = new URLSearchParams(h.slice(h.indexOf("?") + 1));
    expect(h.startsWith("#/labs/pivot?")).toBe(true);
    expect([q.get("kind"), q.get("value"), q.get("host")]).toEqual(["file", "C:\\a++b&c.exe", "analystlab-vm"]);
    expect(thingHref(null, "x")).toBeNull();
  });

  it("shortens for chips", () => {
    expect(thingShort("program", "C:\\Users\\u\\fetch.exe")).toBe("fetch.exe");
    expect(thingShort("hash", HASH.toLowerCase())).toBe("abababababab…");
    expect(thingShort("process", "{0D5356CF-1234-5678-9ABC-DEF0123456AB}")).toBe("run 12345678");
    // the test machine's runs share both the machine part and the last part: the middle tells them apart
    expect(thingShort("process", "{0d5356cf-f79b-6ae4-cd00-000000001000}"))
      .not.toBe(thingShort("process", "{0d5356cf-f7a5-6ae4-d700-000000001000}"));
  });

  it("builds the case board's pin for each kind of thing", () => {
    expect(plusCasePin({ alert: "a1", label: "An alert" })).toEqual({ type: "alert", ref: "a1", label: "An alert", time: null, host: null });
    expect(plusCasePin({ event: "k1" })?.type).toBe("event");
    expect(plusCasePin({ hypothesis: "it ran twice" })?.label).toBe("it ran twice");
    expect(plusCasePin({ field: "sha256", value: HASH })).toMatchObject({ type: "entity", kind: "hash", ref: HASH.toLowerCase() });
    expect(plusCasePin({ field: "Image", value: "-" })).toBeNull();
    expect(plusCasePin({})).toBeNull();
  });
});
