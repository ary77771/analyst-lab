// File inspector page: shows Python's words and numbers, lists openable files first, marks random sections.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { bytes, InfoView, lab, sortFiles, type FileItem, type Info } from "./index";

const file = (over: Partial<FileItem>): FileItem => ({
  id: "x", name: "x.exe", recorded_path: null, host: null, sha256: null, kinds: ["started"], first: null, last: null, times: 1,
  match: "none", match_words: "MATCH-WORDS", inspectable: false, ...over,
});

const words = {
  title: "T", intro: "I", pick: "P", pick_alert: "PA", no_alert_files: "NAF", where_from: "W", imports_note: "IN", go_note: "GO-NOTE", entropy_note: "EN", strings_note: "SN", noise_note: "NOISE",
  no_pe: "NO-PE", not_installed: "NI", sig_off: "SIG-OFF", sig_button: "SIG-BUTTON",
  sections: { hashes: "H", signature: "S", pe: "PE", imports: "IMP", entropy: "ENT", strings: "STR" },
};

const info: Info = {
  name: "s9.exe", size: 2048, sha256: "a".repeat(64), md5: "b".repeat(32), truncated: false, summary: "SUMMARY-FROM-PYTHON",
  pe: { pe: true, machine: "64-bit (x64)", kind: "console program", built: null, built_note: "not set", go: true, dlls: [{ dll: "kernel32.dll", count: 47 }],
    import_count: 47, groups: [{ key: "network", title: "Network", means: "can talk over the network", functions: ["connect"] }], go_runtime_left_out: 40,
    sections: [{ name: ".text", size: 1024, virtual_size: 1024, entropy: 6.1, executable: true, writable: false, high: false },
      { name: "UPX1", size: 4096, virtual_size: 4096, entropy: 7.9, executable: true, writable: true, high: true }] },
  strings: { urls: { items: ["http://10.0.2.2:18765/x"], count: 1, noise: 3 }, ips: { items: [], count: 0, noise: 0 },
    paths: { items: [], count: 0, noise: 0 }, registry: { items: [], count: 0, noise: 0 } },
  signature: { checked: true, status: "NotSigned", type: "None", valid: false },
};

describe("file inspector", () => {
  it("is a lab the registry accepts", () => {
    expect(lab.id).toBe("fileinspect");
    expect(lab.title && lab.blurb).toBeTruthy();
    expect(lab.icon).toBeTruthy();
    expect(typeof lab.Component).toBe("function");
  });

  it("lists the files it can open first, and filters by name or hash", () => {
    const fs = [file({ id: "1", name: "b.exe" }), file({ id: "2", name: "a.exe", inspectable: true, sha256: "cafe", match: "lab" }),
      file({ id: "3", name: "c.exe", inspectable: true, match: "sha256" })];
    expect(sortFiles(fs, "").map((f) => f.id)).toEqual(["3", "2", "1"]);
    expect(sortFiles(fs, "caf").map((f) => f.id)).toEqual(["2"]);
    expect(sortFiles(fs, "B.EXE").map((f) => f.id)).toEqual(["1"]);
  });

  it("says sizes plainly", () => {
    expect(bytes(512)).toBe("512 bytes");
    expect(bytes(2048)).toBe("2.0 KB");
    expect(bytes(5 * 1024 * 1024)).toBe("5.0 MB");
  });

  it("shows Python's summary and words, the Go note, and marks the random section", () => {
    const h = renderToStaticMarkup(<InfoView file={file({ inspectable: true, match: "sha256" })} info={info} words={words} />);
    expect(h).toContain("SUMMARY-FROM-PYTHON");
    expect(h).toContain("MATCH-WORDS");
    expect(h).toContain("GO-NOTE");
    expect(h).toContain("40 functions every Go program imports were left out");
    expect(h).toContain("(+3 NOISE)");
    expect(h.match(/data-high="true"/g)?.length).toBe(1);
    expect(h).toContain("YARA: published pattern rules");                 // the YARA section is on this page now
    expect(h).not.toContain("#/labs/yara");
    expect(h).toContain(`href="#/labs/pivot?kind=hash&amp;value=${"a".repeat(64)}"`);
  });

  it("offers Windows' signature check as a button, never runs it by itself", () => {
    const h = renderToStaticMarkup(<InfoView file={file({ inspectable: true })} info={{ ...info, signature: { checked: false, reason: "MAY-GO-ONLINE", can_check: true } }}
      words={words} onCheckSignature={() => {}} />);
    expect(h).toContain("MAY-GO-ONLINE");
    expect(h).toContain("SIG-BUTTON");
  });
});

