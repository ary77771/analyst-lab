// Small pieces both designs share. They are styled only through each design's CSS variables.
import { AppWindow, AtSign, Box, FileCode, Globe, Plug, Repeat, type LucideIcon } from "lucide-react";
import type { Ink } from "../api";
import { useCountUp } from "./hooks";

/** Neutral interface words (they claim nothing). Every claim word comes from the Python API. */
export const UI = {
  app: "Analyst Lab",
  nav: { watch: "Watch", story: "Story", proof: "Proof", labs: "Labs" },
  machine: "Test machine", elapsed: "Elapsed", open: "Open the story", switchLive: "Switch to the live view",
  play: "Play", pause: "Pause", again: "Play again", back: "Back one step", next: "Next step", start: "To the start",
  details: "Details", close: "Close", of: "of", loading: "Loading…", error: "Could not load:", dismiss: "Dismiss",
  keys: "Space plays · arrows step",
  // What each number on the screens counts, in plain words (shown on hover). They describe; they claim nothing.
  tips: {
    elapsed: "Time since this run was clicked, by this laptop's clock.",
    startElapsed: "Time since the start of the test machine was clicked, by this laptop's clock.",
    records: "Records received from the test machine and stored so far. Each record is one thing Windows reported: a program started, a file created, a connection made.",
    arrivals: "New records at each look at the store, newest on the right.",
    alertsInView: "Alerts shown in this list.",
    stepNo: "This step's place in the alert's own chain, in recorded order.",
    offset: "When this was recorded, counted from the alert's first step.",
    told: "Steps of this kind told so far, of all of them in what the film tells.",
    total: "How many statements of this kind the whole story holds.",
    checksReady: "Checks ready to run.", checksPassed: "Checks passed so far in this run.",
    groupCount: "Passed, of the checks in this group.",
    pick: "Alerts in this store, oldest first.",
    barOf: (value: number, of: number) => `${value} of ${of}`,
    bootLoading: "Loading…", bootFailing: "The dashboard's own server is not answering. Trying again…",
  },
  film: "Film", report: "Report", fullReport: "Open the full report", readReport: "Read the report", record: "record",
} as const;

export const INK_VAR: Record<Ink, string> = { fact: "var(--ink-fact)", hypothesis: "var(--ink-hypo)", gap: "var(--ink-gap)" };
export const DASH: Record<Ink, string | undefined> = { fact: undefined, hypothesis: "9 7", gap: "1.5 6.5" };
export const INKS: Ink[] = ["fact", "hypothesis", "gap"];
export const NODE_ICON: Record<string, LucideIcon> = { program: AppWindow, file: FileCode, item: Box, address: Globe, name: AtSign, port: Plug, autostart: Repeat };

/** The ink's line: solid, dashed or dotted. The product's one signature, used everywhere a grade shows. */
export function InkLine({ ink, width = 28, weight = 3 }: { ink: Ink; width?: number; weight?: number }) {
  const h = weight + 2;
  return (
    <svg className="inkl" width={width} height={h} aria-hidden="true">
      <line x1={weight / 2} y1={h / 2} x2={width - weight / 2} y2={h / 2} stroke={INK_VAR[ink]} strokeWidth={weight} strokeLinecap="round"
        strokeDasharray={ink === "gap" ? `0.1 ${weight * 2.3}` : ink === "hypothesis" ? `${weight * 2.6} ${weight * 2.1}` : undefined} />
    </svg>
  );
}

export function Mark({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 22 22" aria-hidden="true">
      <path d="M3 17 L9 5" stroke="var(--ink-fact)" strokeWidth="2.6" strokeLinecap="round" />
      <path d="M10 17 L16 5" stroke="var(--ink-hypo)" strokeWidth="2.6" strokeLinecap="round" strokeDasharray="3.2 3" />
      <path d="M17 17 L19.5 12" stroke="var(--ink-gap)" strokeWidth="2.6" strokeLinecap="round" strokeDasharray="0.1 3.6" />
    </svg>
  );
}

/** A number that rolls to its new value (the value itself is always the API's). */
export function Roll({ value, ms }: { value: number; ms?: number }) {
  return <>{useCountUp(value, ms).toLocaleString("en-US")}</>;
}

export const cx = (...xs: (string | false | null | undefined)[]) => xs.filter(Boolean).join(" ");
