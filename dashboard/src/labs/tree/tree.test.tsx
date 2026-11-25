// Process tree page: marked command-line parts, the alert's own programs marked, test machinery and gaps said.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { CmdLine, lab, NodeRow, RETRY_MS, retryLater, shownNodes, Waiting, type TreeNode } from "./index";

const words = {
  title: "T", intro: "I", pick: "P", first: "F", first_why: "W", marks_note: "M", not_recorded: "NOT-RECORDED-WORDS",
  harness: "HARNESS", own: "OWN", show_harness: "S", none: "N", kinds: { url: "a web address", hash: "a fingerprint" },
};
const node = (over: Partial<TreeNode>): TreeNode => ({
  guid: "g", name: "s1_fetch.exe", image: "D:\\s1\\s1_fetch.exe", cmd: "s1_fetch.exe -server http://x", user: "VM\\analyst",
  time: "2026-11-01T10:00:00Z", pid: 1, parent: null, children: [], depth: 1, own: true, ancestor: false, harness: false, recorded: true,
  marks: [], ...over,
});

describe("process tree", () => {
  it("is a lab the registry accepts, under What happened?", () => {
    expect(lab.id).toBe("tree");
    expect(lab.group).toBe("happened");
    expect(typeof lab.Component).toBe("function");
  });

  it("highlights the marked parts of a command line, with their kind on hover", () => {
    const h = renderToStaticMarkup(<CmdLine cmd="x.exe -u http://10.0.2.2 abc" marks={[[9, 24, "url"]]} kinds={words.kinds} />);
    expect(h).toContain('<mark data-kind="url" title="a web address">http://10.0.2.2</mark>');
    expect(h).toContain("x.exe -u ");
    expect(renderToStaticMarkup(<CmdLine cmd={null} marks={[]} kinds={{}} />)).toContain("no command line recorded");
  });

  it("marks the alert's own programs, dims the test machinery and says when a start was not recorded", () => {
    const own = renderToStaticMarkup(<NodeRow n={node({})} words={words} host="vm" first />);
    expect(own).toContain('data-own="true"');
    expect(own).toContain('data-first="true"');
    expect(own).toContain("OWN");
    expect(own).toContain("margin-left:1.75rem");
    const gap = renderToStaticMarkup(<NodeRow n={node({ own: false, harness: true, recorded: false })} words={words} host="vm" first={false} />);
    expect(gap).toContain("HARNESS");
    expect(gap).toContain("NOT-RECORDED-WORDS");
    expect(gap).toContain('data-harness="true"');
  });

  it("opens on the alert's own branch, re-indented, and shows every program when asked", () => {
    const tree = [
      node({ guid: "svc", name: "services.exe", own: false, depth: 0, branch: false, branch_depth: null }),
      node({ guid: "sh", name: "powershell.exe", own: false, depth: 3, branch: true, branch_depth: 0 }),
      node({ guid: "f", name: "s1_fetch.exe", own: true, depth: 4, branch: true, branch_depth: 1 }),
    ];
    expect(shownNodes(tree, false).map(({ n, depth }) => `${n.name}@${depth}`)).toEqual(["powershell.exe@0", "s1_fetch.exe@1"]);
    expect(shownNodes(tree, true).map(({ n, depth }) => `${n.name}@${depth}`)).toEqual(["services.exe@0", "powershell.exe@3", "s1_fetch.exe@4"]);
    expect(renderToStaticMarkup(<NodeRow n={tree[2]} depth={1} words={words} host="vm" first={false} />)).toContain("margin-left:1.75rem");
  });

  it("says the replay hasn't reached the alert yet, then asks again by itself", () => {
    const h = renderToStaticMarkup(<Waiting text="The replay hasn't reached this alert yet" retry={() => {}} />);
    expect(h).toContain("reached this alert yet");
    expect(h).toContain('role="status"');
    vi.useFakeTimers();
    try {
      const retry = vi.fn();
      retryLater(retry);
      vi.advanceTimersByTime(RETRY_MS - 1);
      expect(retry).not.toHaveBeenCalled();
      vi.advanceTimersByTime(1);
      expect(retry).toHaveBeenCalledTimes(1);
      const again = vi.fn();
      retryLater(again)();                                   // cancelled (the page left, or the answer came)
      vi.advanceTimersByTime(RETRY_MS * 2);
      expect(again).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
});
