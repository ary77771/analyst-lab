// The walk-through "One alert, start to finish" (wave 3, W3-7): plain functions for its steps. The script (the
// labs, the questions, every sentence) and the alert it follows come from Python (GET /api/labs/guide,
// engine/labs/guide.py). A step is nothing but a lab's own address with "?alert=<id>&guide=<n>": the shell
// shows the step's sentence in a bar above that lab (GuideBar.tsx). Nothing is run, nothing is changed.
import { EXPERIMENTAL, isExperimental, labHref, type Lab } from "./registry";

export interface GuideWords { title: string; intro: string; which: string; alert: string; chosen: string; unknown: string; others: string; no_alert: string; start: string; again: string; step: string;
  next: string; back: string; finish: string; end: string; bar: string; left_out: string; none_here: string; finished: string }
export interface GuideAlert { id: string; title: string; level: string; time: string; host: string }
export interface GuideData { words: GuideWords; steps: { lab: string; question: string; text: string }[]; alert: GuideAlert | null;
  /** the address named this alert (not the store's own pick) / named one that is not among the shown alerts */
  chosen?: boolean; unknown?: boolean; others?: GuideAlert[] }

/** Where the script is asked for: about the alert the address names, or (without one) the store's own pick. */
export const guideApi = (alert: string | null | undefined) => `/api/labs/guide${alert ? `?alert=${encodeURIComponent(alert)}` : ""}`;
export interface GuideStep { n: number; total: number; lab: string; question: string; text: string; href: string; back: string | null; next: string }

/** The address of the walk-through's own page; `done` after the last step. */
export const guideHome = (done = false) => labHref("guide", done ? { done: 1 } : undefined);

/**
 * The steps that can be walked in THIS build, numbered 1..n in the script's order. A step whose lab is not
 * part of the build is left out and listed by `leftOut` (the page shows it as such); a step whose lab is
 * experimental is left out and listed by `hidden` (the page does not show it at all: it IS part of the
 * build). Each step carries its own address, the one before it and the one after it (after the last: the
 * walk-through's page, marked done).
 */
export function guideSteps(data: Pick<GuideData, "steps" | "alert">, labs: Pick<Lab, "id">[], experimental: readonly string[] = EXPERIMENTAL):
    { steps: GuideStep[]; leftOut: string[]; hidden: string[] } {
  const built = new Set(labs.map((l) => l.id));
  const have = new Set([...built].filter((id) => !isExperimental(id, experimental)));                 // never into an experimental lab
  const alert = data.alert?.id ?? null;
  const can = alert ? data.steps.filter((s) => have.has(s.lab)) : [];
  const at = (i: number) => labHref(can[i].lab, { alert, guide: i + 1 });
  return {
    steps: can.map((s, i) => ({ ...s, n: i + 1, total: can.length, href: at(i), back: i > 0 ? at(i - 1) : null, next: i + 1 < can.length ? at(i + 1) : guideHome(true) })),
    // two different reasons, never mixed up on the page: the lab is not part of this build / it is, but experimental
    leftOut: data.steps.filter((s) => !built.has(s.lab)).map((s) => s.lab),
    hidden: data.steps.filter((s) => built.has(s.lab) && !have.has(s.lab)).map((s) => s.lab),
  };
}

/** The step a lab page is showing: `guide` is the address's own "guide=<n>", `lab` the lab that is open. Null when
 *  the address names no step, a step that does not exist, or a step that belongs to another lab. */
export function guideStepAt(steps: GuideStep[], lab: string, guide: string | null): GuideStep | null {
  if (!guide || !/^\d+$/.test(guide)) return null;
  const s = steps[Number(guide) - 1];
  return s && s.lab === lab ? s : null;
}
