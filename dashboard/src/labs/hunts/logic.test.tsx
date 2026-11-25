// night-hunt shared helpers + the result table (rendered to plain HTML, no browser needed).
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { apiQuery, fileName, hashParams, pinHref, pivotHref, plural, shortTime, withParams } from "./logic";
import { AlertBanner, ResultTable } from "./shared";
import { lab } from "./index";

describe("pivot links", () => {
  it("builds the pivot page's own #/labs/pivot?kind=&value= with the value encoded", () => {
    expect(pivotHref("Image", "C:\\Users\\a b\\evil.exe")).toBe("#/labs/pivot?kind=program&value=C%3A%5CUsers%5Ca+b%5Cevil.exe");
    expect(pivotHref("ProcessGuid", "{x}", "lab-vm")).toBe("#/labs/pivot?kind=process&value=%7Bx%7D&host=lab-vm");
    expect(pivotHref("DestinationIp", "10.0.2.2")).toBe("#/labs/pivot?kind=ip&value=10.0.2.2");
    expect(pivotHref("TargetObject", "HKU\\x")).toBe("#/labs/pivot?kind=registry&value=HKU%5Cx");
  });
  it("pins to the case board with night-pivot's documented address", () => {
    const href = pinHref("Image", "C:\\x\\evil.exe", "evil.exe", "2026-11-01T09:10:00Z", "analystlab-vm")!;
    const q = new URLSearchParams(href.split("?")[1]);
    expect(href.startsWith("#/labs/cases?")).toBe(true);
    expect(Object.fromEntries(q)).toEqual({ pin: "entity", kind: "program", ref: "C:\\x\\evil.exe", label: "evil.exe",
      time: "2026-11-01T09:10:00Z", host: "analystlab-vm" });
    expect(pinHref("CommandLine", "x", "y")).toBeNull();
  });
  it("round-trips a path with & + % = through the address", () => {
    const v = "C:\\a&b+c%d=e.exe";
    const href = pivotHref("TargetFilename", v)!;
    expect(new URLSearchParams(href.split("?")[1]).get("value")).toBe(v);
  });
  it("links nothing for empty values or fields the pivot page does not take", () => {
    expect(pivotHref("Image", "")).toBeNull();
    expect(pivotHref("Image", null)).toBeNull();
    expect(pivotHref("CommandLine", "x")).toBeNull();
  });
});

describe("hash query", () => {
  it("reads and replaces values, keeping the path", () => {
    expect(hashParams("#/labs/hunts?hunt=autostart&window=7d").get("window")).toBe("7d");
    expect(hashParams("#/labs/hunts").get("window")).toBeNull();
    expect(withParams("#/labs/hunts?hunt=a", { window: "1h" })).toBe("#/labs/hunts?hunt=a&window=1h");
    expect(withParams("#/labs/hunts?hunt=a", { hunt: null })).toBe("#/labs/hunts");
  });
  it("drops empty and false values from API queries", () => {
    expect(apiQuery({ window: "24h", include_own: false, host: null })).toBe("window=24h");
    expect(apiQuery({ window: "7d", include_own: true })).toBe("window=7d&include_own=true");
  });
});

describe("plural", () => {
  it("says 1 program, 2 programs, 1 address, 2 addresses", () => {
    expect(plural(1, "program")).toBe("program");
    expect(plural(2, "program")).toBe("programs");
    expect(plural(0, "program")).toBe("programs");
    expect(plural(1, "address", "addresses")).toBe("address");
    expect(plural(3, "address", "addresses")).toBe("addresses");
  });
});

describe("words", () => {
  it("formats times and file names", () => {
    expect(shortTime("2026-11-01T09:10:05.1234567Z")).toBe("1 Nov 09:10:05");
    expect(shortTime(null)).toBe("-");
    expect(fileName("C:\\Windows\\System32\\cmd.exe")).toBe("cmd.exe");
  });
});

describe("result table", () => {
  const columns = [{ key: "program", label: "Program file" }, { key: "runs", label: "Runs" }];
  it("shows every row with its pivot links and times", () => {
    const html = renderToStaticMarkup(<ResultTable columns={columns} rows={[
      { cells: { program: "C:\\x\\evil.exe", runs: 1234 }, count: 1, first: "2026-11-01T09:10:05.0Z", last: "2026-11-01T09:11:05.0Z",
        pivots: [{ field: "Image", value: "C:\\x\\evil.exe" }, { field: "CommandLine", value: "x" }] },
    ]} />);
    expect(html).toContain("evil.exe");
    expect(html).toContain("1,234");
    expect(html).toContain("1 Nov 09:10:05");
    expect(html.match(/href="#\/labs\/pivot\?kind=program/g)?.length).toBe(1);   // the shared Thing chip; CommandLine is no thing
    expect(html.match(/class="th-plus"/g)?.length).toBe(1);                       // and one "+ case" for the row
  });
  it("says so when nothing was found", () => {
    expect(renderToStaticMarkup(<ResultTable columns={columns} rows={[]} />)).toContain("Nothing found");
  });
});

describe("the one scope banner (critique 3)", () => {
  const base = { id: "a1", title: "Dropper", time: "2026-11-01T09:10:00.0000000Z", host: "analystlab-vm", programs: ["c:\\x\\evil.exe"] };
  const html = (alert: Parameters<typeof AlertBanner>[0]["alert"]) =>
    renderToStaticMarkup(<AlertBanner alert={alert} onAll={() => {}} onClear={() => {}} />).replace(/&#x27;/g, "'");
  it("says the alert's run, and the switch to the whole recording", () => {
    const h = html({ ...base, how: "boot", narrowed: true, limited: true });
    expect(h).toContain("Showing what relates to this alert's run");
    expect(h).toContain("evil.exe");
    expect(h).toContain("show the whole recording");
  });
  it("says plainly when no machine start splits the recording", () => {
    const h = html({ ...base, how: "records", limited: true });
    expect(h).toContain("No machine start was recorded before this alert");
    expect(h).not.toContain("show the whole recording");
  });
  it("keeps every ' · ' with the button after it, so none is left dangling at a line end (critique 4)", () => {
    for (const a of [{ ...base, how: "boot", narrowed: true, limited: true }, { ...base, how: "boot", limited: false },
                     { ...base, how: "records", limited: true }, { id: "x", missing: true }]) {
      const h = html(a);
      expect(h.split(" · ").length - 1).toBe((h.match(/<span class="hn-nowrap"> · <button/g) ?? []).length);
      expect(h).not.toMatch(/ · <\/p>/);
    }
  });
  it("offers to go back to the alert's run, and says when the alert isn't here", () => {
    expect(html({ ...base, how: "boot", limited: false })).toContain("show only this alert's run");
    expect(html({ id: "x", missing: true })).toContain("This alert isn't in this recording");
  });
});

describe("the lab entry", () => {
  it("follows the Labs contract", () => {
    expect(lab.id).toBe("hunts");
    expect(lab.title).toBeTruthy();
    expect(lab.blurb).toBeTruthy();
    expect(typeof lab.Component).toBe("function");
    expect(lab.icon).toBeTruthy();
  });
});
