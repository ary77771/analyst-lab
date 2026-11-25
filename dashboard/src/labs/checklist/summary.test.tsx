// The incident in one paragraph: every part shows the question it summarises on hover; nothing when there is none.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Summary, type Checklist } from "./index";

const base = { words: { summary: { title: "IN SHORT", hover: "From: {source}" } }, story: true, guid: "{A}", host: "vm", scope: [], own: [], questions: [],
  alert: { id: "a1", title: "T", level: "high", time: "t", host: "vm", source: "sigma", rule_id: "r", reason: "", declared: false } } as unknown as Checklist;

describe("checklist: in short", () => {
  it("renders each part with its source on hover, in order", () => {
    const d = { ...base, summary: [[{ text: "fetch.exe", status: "fact", source: "what", label: "What ran?" },
      { text: " connected to 10.0.2.2:18765.", status: "fact", source: "network", label: "Did it connect out?" }],
      [{ text: "(second part, from Python): X.", status: "hypothesis", source: "sure", label: "How sure are we?" }]] } as Checklist;
    const h = renderToStaticMarkup(<Summary d={d} />);
    for (const s of ["IN SHORT", "From: What ran?", "From: Did it connect out?", "From: How sure are we?", 'data-status="hypothesis"']) expect(h).toContain(s);
    expect(h.indexOf("fetch.exe")).toBeLessThan(h.indexOf("connected to"));
    expect(h.indexOf("connected to")).toBeLessThan(h.indexOf("(second part, from Python)"));
  });
  it("shows nothing without a paragraph", () => {
    expect(renderToStaticMarkup(<Summary d={{ ...base, summary: [] }} />)).toBe("");
  });
});
