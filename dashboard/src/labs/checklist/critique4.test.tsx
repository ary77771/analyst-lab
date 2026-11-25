// critique-4: the lab's own test machinery among the alert's programs is hidden behind the switch, never deleted.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ChecklistView, type Checklist, type Program } from "./index";

const prog = (guid: string, image: string, harness: boolean): Program => ({ guid, recorded: true, image, pid: 1, command_line: null, command_short: null,
  parent: null, parent_command_line: null, user: null, time: null, children: [], harness });
const words = { intro: "", status: {}, open: {}, verdict: {}, questions: {}, sections: {}, programs_hidden: "HIDDEN {n}", harness_switch: "SWITCH" };
const view = (programs: Program[]) => renderToStaticMarkup(<ChecklistView d={{ words, story: true, guid: "{A}", host: "vm", scope: [], own: [],
  alert: { id: "a1", title: "T", level: "high", time: "t", host: "vm", source: "sigma", rule_id: "r", reason: "", declared: false },
  questions: [{ key: "what", question: "Q", status: "fact", lines: [], more: 0, note: null, witness: null, links: [], programs }] } as unknown as Checklist} />);

describe("checklist: the test machinery among the alert's programs", () => {
  it("is hidden by default, with how many and the switch", () => {
    const h = view([prog("{A}", "a.exe", false), prog("{H}", "VBoxControl.exe", true)]);
    expect(h).toContain("a.exe");
    expect(h).not.toContain("VBoxControl.exe");
    expect(h).toContain("HIDDEN 1");
    expect(h).toContain("SWITCH");
  });
  it("no switch when there is no machinery", () => {
    expect(view([prog("{A}", "a.exe", false)])).not.toContain("SWITCH");
  });
});
