// The Labs registry (2026-11-23). A lab's page is ONE new folder, dashboard/src/labs/<id>/index.tsx, with
//
//     export const lab: Lab = { id: "<id>", title: "...", blurb: "...", icon: SomeLucideIcon, Component };
//
// Nothing else is touched: this file finds every such folder, the Labs screen shows it as a card, and
// "#/labs/<id>?key=value" opens it (labs link to each other that way: see labHref). The page's back end
// is engine/labs/<id>.py under /api/labs/<id> (engine/labs/__init__.py).
//
// ISOLATION (night plan rule 13): every lab is loaded BY ITSELF, as its own piece of the build, after the
// dashboard is up. A lab whose file throws while it loads, exports no proper `lab`, or throws while it
// draws is listed as "failed to load" (or shows its error in its own place): the dashboard and the other
// labs go on. The whole of Labs is off when the dashboard was started with --no-labs.
//
// A lab's Component gets the address's query as `params` (new URLSearchParams("key=value")).
// The rules of the dashboard's own screens hold in a lab too: Proven / Suspected / Can't be known keep
// their colours and line styles, and words that make a claim come from Python, not from the page.
import { useEffect, useState, type ComponentType } from "react";
import type { LucideIcon } from "lucide-react";

export interface LabProps { params: URLSearchParams }
export interface Lab {
  /** the folder's own name: lower-case letters, digits and "-" */
  id: string;
  /** the card's title (a few words) */
  title: string;
  /** one plain sentence: what an investigator does here */
  blurb: string;
  icon: LucideIcon;
  Component: ComponentType<LabProps>;
  /** which question this lab answers (the Labs page shows the labs under these headings). Optional: a lab
   *  that names none is placed by GROUP_OF below, and one nobody placed goes under "Other". */
  group?: LabGroup;
}
export interface LeftOut { path: string; id: string | null; problem: string }
export interface Found { labs: Lab[]; leftOut: LeftOut[] }
type Module = { lab?: Partial<Lab> } | undefined;
export type Loaders = Record<string, () => Promise<Module>>;

const folderOf = (path: string) => /^\.\/([^/]+)\/index\.tsx$/.exec(path)?.[1] ?? null;

/** The labs among loaded modules (path -> module), by title, and why any folder was left out. */
export function collect(mods: Record<string, Module>): Found {
  const labs: Lab[] = [], leftOut: LeftOut[] = [];
  for (const path of Object.keys(mods).sort()) {
    const folder = folderOf(path);
    const lab = mods[path]?.lab;
    const bad = (problem: string) => leftOut.push({ path, id: folder, problem });
    if (!folder) bad("not a lab folder (expected ./<id>/index.tsx)");
    else if (!lab) bad("exports no `lab`");
    else if (lab.id !== folder) bad(`its id must be its folder's name ("${folder}")`);
    else if (!/^[a-z0-9-]+$/.test(folder)) bad("its id may hold lower-case letters, digits and - only");
    else if (!lab.title || !lab.blurb || !lab.icon || !lab.Component) bad("needs a title, a blurb, an icon and a Component");
    else labs.push(lab as Lab);
  }
  return { labs: labs.sort((a, b) => a.title.localeCompare(b.title)), leftOut };
}

/** Load every lab by itself. One that fails (its file throws, or can't be fetched) is left out with the reason; the others load. */
export async function loadLabs(loaders: Loaders): Promise<Found> {
  const mods: Record<string, Module> = {}, failed: LeftOut[] = [];
  await Promise.all(Object.keys(loaders).map(async (path) => {
    try {
      mods[path] = await loaders[path]();
    } catch (e) {
      failed.push({ path, id: folderOf(path), problem: `failed to load: ${String(e instanceof Error ? e.message : e)}` });
    }
  }));
  const found = collect(mods);
  return { labs: found.labs, leftOut: [...found.leftOut, ...failed].sort((a, b) => a.path.localeCompare(b.path)) };
}

// each lab is its own piece of the build, fetched when the dashboard is already running (NOT `eager`)
const loaders = import.meta.glob<Module>("./*/index.tsx") as Loaders;
let all: Promise<Found> | null = null;
/** Every lab of this build (loaded once). Never rejects. */
export const allLabs = (): Promise<Found> => (all ??= loadLabs(loaders).catch((e) => ({ labs: [], leftOut: [{ path: "*", id: null, problem: String(e) }] })));

/** The labs for a component: null while they load. */
export function useLabs(): Found | null {
  const [found, setFound] = useState<Found | null>(null);
  useEffect(() => { let on = true; void allLabs().then((f) => { if (on) setFound(f); }); return () => { on = false; }; }, []);
  return found;
}

/** What the dashboard's back end says about Labs (GET /api/labs): on or off, and labs it had to leave out. */
export interface LabsBackend { enabled: boolean; labs: { name: string; prefix: string }[]; left_out: { name: string; problem: string }[]; hosts?: string[] | null;
  /** everyday names of the lab's test runs, by run id in lower case (engine/labs/_names.py) */
  run_names?: Record<string, string> }
let backend: Promise<LabsBackend | null> | null = null;
export const labsBackend = (): Promise<LabsBackend | null> =>
  (backend ??= fetch("/api/labs").then((r) => (r.ok ? (r.json() as Promise<LabsBackend>) : null)).catch(() => null));
/** undefined while it is being asked; null when the back end has no Labs at all (an older one, or it can't be asked). */
export function useLabsBackend(): LabsBackend | null | undefined {
  const [b, setB] = useState<LabsBackend | null | undefined>(undefined);
  useEffect(() => { let on = true; void labsBackend().then((x) => { if (on) setB(x); }); return () => { on = false; }; }, []);
  return b;
}

export const findLab = (labs: Lab[], id: string | null | undefined) => labs.find((l) => l.id === id) ?? null;

/** "#/labs/<id>?key=value": the address of a lab, for links between labs (a pivot on a hash, a time, ...). */
export function labHref(id?: string, params?: Record<string, string | number | null | undefined>): string {
  if (!id) return "#/labs";
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params ?? {})) if (v !== null && v !== undefined && v !== "") q.set(k, String(v));
  const s = q.toString();
  return `#/labs/${id}${s ? `?${s}` : ""}`;
}

/**
 * The route's parameter ("<id>?key=value" exactly as it stands in the address, or null for the list of
 * labs) taken apart. The query is decoded here, once (URLSearchParams), so a value may hold & + % = and
 * spaces: build such addresses with labHref or URLSearchParams.
 */
export function splitLabParam(param: string | null): { id: string | null; params: URLSearchParams } {
  if (!param) return { id: null, params: new URLSearchParams() };
  const at = param.indexOf("?");
  let id = (at < 0 ? param : param.slice(0, at)).replace(/\/+$/, "");
  try { id = decodeURIComponent(id); } catch { /* kept as typed */ }
  return { id: id || null, params: new URLSearchParams(at < 0 ? "" : param.slice(at + 1)) };
}

// ---------------------------------------------------------------------------------------------------------
// Wave 3 (2026-11-24): the labs as ONE investigation. The Labs page groups them by the question they answer;
// an alert picked in one lab travels to the next in the address ("?alert=<id>"); a test run is shown with
// its everyday name. Everything here is plain functions (tested in registry.test.ts); the hooks and the
// strip built on them are in kit.tsx.

/**
 * EXPERIMENTAL LABS (night 2, 2026-11-24; Yousif: weak labs are hidden, off by default, code kept).
 * A lab whose id is listed here is still built and its address still opens it, but:
 *   - the Labs page does not show its card unless "Show experimental labs" is switched on (remembered in
 *     this browser, off by default); switched on, it stands under "Experimental", not under its question;
 *   - the strip of an alert's other views (NextStrip) and the walk-through never lead to it.
 * One list, here. Add a lab's id (its folder's name) to hide it; take it out to show it again.
 */
export const EXPERIMENTAL: readonly string[] = [
  // PROOF's decisions after both critiques of night 2 (docs/night/2026-11-24.md, "DECISIONS"):
  "start", "glance",                 // absorbed by the checklist, which is THE landing page
  "alarm",                           // its side-by-side view moves into "why"
  "lolbas",                          // becomes one of the saved hunts
  "replay",                          // the Story screen already plays the story
  "guide",                           // a third way in; the checklist and the strip are the one path
  "whatsnew",                        // the builders' notes of the night, not for a visitor
  "secondopinion", "reading",
  "fileinspect",                     // critique-3: on the S1 replay it can only show a rebuild, not the file that ran
  "rulesandbox",                     // night 2, new: try a Sigma rule on the recordings; for Yousif to look at first
  // PROOF ~22:00: "techniques" stays visible (lights T1105 on S1 via the labs' own-rule reading, testing group);
  // "fileinspect" is visible as "File check" (exact-hash evidence only, rebuilds labelled; YARA is a section
  // of it now, the yara page is gone).
];
export const isExperimental = (id: string, list: readonly string[] = EXPERIMENTAL) => list.includes(id);

/** The questions of an investigation, in the order the Labs page shows them. */
export const GROUPS = [
  // `note`: one line under the heading. "Start here" is the visitor's first move (its cards are drawn large);
  // "Testing the tool itself" is set apart and drawn small: it is about the tool, not about an alert.
  { id: "start", title: "Start here", note: "Pick an alert, read what the recording answers, then follow the strip at the top of each page to the next question." },
  { id: "happened", title: "What happened?", note: "" },
  { id: "sure", title: "How sure are we?", note: "" },
  { id: "far", title: "How far did it go?", note: "" },
  { id: "now", title: "What now?", note: "" },
  { id: "tool", title: "Testing the tool itself", note: "Checks of the tool, not steps of an investigation: how noisy it is, how two test runs differ, what its rules cover." },
  { id: "other", title: "Other", note: "" },
] as const;
export type LabGroup = (typeof GROUPS)[number]["id"];
/** The heading experimental labs stand under when they are shown (not a question a lab can choose). */
export const EXPERIMENTAL_GROUP = { id: "experimental", title: "Experimental" } as const;

/** Where a lab goes when its own file names no `group` (so no lab's file had to change). */
export const GROUP_OF: Record<string, LabGroup> = {
  guide: "start", checklist: "start", start: "start", whatsnew: "start", replay: "start",
  why: "happened", alarm: "happened", moment: "happened", pivot: "happened", tree: "happened", sweep: "happened",
  prove: "sure", claim: "sure", gaps: "sure", secondopinion: "sure", glance: "sure",
  network: "far", persistence: "far", rarity: "far", hunts: "far", lolbas: "far", fileinspect: "far", yara: "far",
  respond: "now", cases: "now",
  // PROOF's decisions of night 2: the alarm track record and the ATT&CK map are checks of the tool
  receipts: "tool", noise: "tool", storydiff: "tool", techniques: "tool", reading: "tool",
};

/** Placements decided for the whole product (PROOF, night 2): these win over the lab's own `group`. */
export const GROUP_FIXED: Record<string, LabGroup> = {
  receipts: "tool",                  // the alarm track record is a check of the tool, not a step of an investigation
};

const isGroup = (g: unknown): g is LabGroup => GROUPS.some((x) => x.id === g);
/** The group of one lab: its own `group`, else the table above, else "other" (never left out). */
export const groupOf = (lab: Pick<Lab, "id" | "group">): LabGroup => GROUP_FIXED[lab.id] ?? (isGroup(lab.group) ? lab.group : GROUP_OF[lab.id] ?? "other");

/**
 * The labs under their questions, in GROUPS' order: every shown lab exactly once, no empty group.
 * Experimental labs are left out; with `showExperimental` they come last, under "Experimental".
 */
export function groupLabs<T extends Pick<Lab, "id" | "group">>(labs: T[], showExperimental = false, experimental: readonly string[] = EXPERIMENTAL):
    { id: LabGroup | "experimental"; title: string; note: string; labs: T[] }[] {
  // inside a question, the labs of the strip come first and in the strip's order (the order a visitor meets
  // them in); the others keep the order they came in (by title)
  const step = (l: T) => { const i = ALERT_PATH.findIndex((p) => p.lab === l.id); return i < 0 ? ALERT_PATH.length : i; };
  const ordered = labs.map((l, i) => ({ l, i })).sort((a, b) => step(a.l) - step(b.l) || a.i - b.i).map((x) => x.l);
  const usual = ordered.filter((l) => !isExperimental(l.id, experimental)), hidden = labs.filter((l) => isExperimental(l.id, experimental));
  const out: { id: LabGroup | "experimental"; title: string; note: string; labs: T[] }[] =
    GROUPS.map((g) => ({ id: g.id, title: g.title, note: g.note, labs: usual.filter((l) => groupOf(l) === g.id) })).filter((g) => g.labs.length > 0);
  if (showExperimental && hidden.length > 0) out.push({ ...EXPERIMENTAL_GROUP, note: "", labs: hidden });
  return out;
}

/** How many labs of this build are experimental (the Labs page offers its switch only when there is one). */
export const countExperimental = (labs: Pick<Lab, "id">[], experimental: readonly string[] = EXPERIMENTAL) => labs.filter((l) => isExperimental(l.id, experimental)).length;

// "Show experimental labs": remembered in this browser only, off until someone switches it on. A browser that
// gives no storage (private window, blocked site data) simply does not remember: the page works the same.
const SHOW_KEY = "analystlab.labs.showExperimental";
type Keeps = Pick<Storage, "getItem" | "setItem" | "removeItem">;
export function readShowExperimental(storage: Keeps | null | undefined): boolean {
  try { return storage?.getItem(SHOW_KEY) === "1"; } catch { return false; }
}
export function writeShowExperimental(storage: Keeps | null | undefined, on: boolean): void {
  try { if (on) storage?.setItem(SHOW_KEY, "1"); else storage?.removeItem(SHOW_KEY); } catch { /* not remembered */ }
}

const LAB_ADDRESS = /^#(?:a|b)?\/?labs\/([^?]*)(?:\?(.*))?$/;

/** The alert a lab address is about ("#/labs/why?alert=17" -> "17"); null without one, or outside a lab. */
export function alertOf(hash: string): string | null {
  const m = LAB_ADDRESS.exec(hash);
  if (!m || !m[1]) return null;
  return new URLSearchParams(m[2] ?? "").get("alert") || null;
}

/** The same lab address about another alert (null: about none). Every other parameter stays as it is. An
 *  address that is not a lab's own page is returned unchanged. */
export function withAlert(hash: string, id: string | null): string {
  const m = LAB_ADDRESS.exec(hash);
  if (!m || !m[1]) return hash;
  const q = new URLSearchParams(m[2] ?? "");
  if (id) q.set("alert", id); else q.delete("alert");
  const s = q.toString();
  return `#/labs/${m[1]}${s ? `?${s}` : ""}`;
}

/** One alert through the labs, in the order an investigation asks its questions. A chip is shown only for a
 *  lab that is part of this build. Every lab named here reads "?alert=<id>" from its address. */
export const ALERT_PATH: { lab: string; label: string; hint: string }[] = [
  // PROOF's order after the critiques of night 2: checklist > why > moment > tree > prove > network >
  // persistence > respond > cases ("tree" is the process-tree lab; until it is in the build it has no chip)
  { lab: "checklist", label: "The questions", hint: "What an analyst asks about this alert, answered from the recording" },
  { lab: "why", label: "What fired", hint: "The rule behind this alert and the recorded values it matched" },
  { lab: "moment", label: "Around the moment", hint: "Everything recorded seconds before and after" },
  { lab: "tree", label: "Process tree", hint: "Which program started which, around this alert" },
  { lab: "prove", label: "How sure", hint: "What is on record for each line, and what would settle the rest" },
  { lab: "network", label: "How far: connections", hint: "Who talked to whom around this alert" },
  { lab: "sweep", label: "Where else?", hint: "This alert's files, fingerprints and addresses: in which other runs they appear" },
  { lab: "persistence", label: "How far: autostarts", hint: "What was set to start by itself" },
  { lab: "respond", label: "What now", hint: "Published response steps for this kind of alert" },
  { lab: "cases", label: "Add to case", hint: "Keep this alert in a case, with notes" },
];

/** The chips of the strip for this build: the path's labs that exist and are not experimental, each with its
 *  address for `alert`. */
export function pathFor(labs: Pick<Lab, "id" | "group">[], current: string, alert: string | null | undefined, experimental: readonly string[] = EXPERIMENTAL) {
  // a check of the tool itself (the alarm track record, the story diff, ...) is not a step of an alert's
  // investigation: on such a page there is no strip at all, even where the page asks for one (PROOF, night 2)
  if (groupOf({ id: current, group: labs.find((l) => l.id === current)?.group }) === "tool") return [];
  const have = new Set(labs.map((l) => l.id).filter((id) => !isExperimental(id, experimental)));
  return ALERT_PATH.filter((p) => have.has(p.lab)).map((p) => ({ ...p, href: labHref(p.lab, { alert: alert || null }), current: p.lab === current }));
}

/** A test run as people say it: "S1 · Download and run". The names come from Python (GET /api/labs,
 *  `run_names`); a run without one is "unnamed run", never a guess. `names` null: not loaded yet (the code alone). */
export function runName(id: string, names: Record<string, string> | null | undefined): string {
  const code = id.trim().toUpperCase();
  if (!names) return code;
  const name = names[id.trim().toLowerCase()];
  return `${code} \u00b7 ${name || "unnamed run"}`;
}

// ---------------------------------------------------------------------------------------------------------
// May a lab speak right now? (critique 3 of night 2: after a restart the replay store refills from nothing
// in 15 to 20 seconds, and in that time labs said "This alert isn't in this recording" and "Failed to
// fetch": they read as findings.) The shell asks this BEFORE it draws a lab, from what the dashboard's own
// feed already knows (GET /api/health every 2 s, GET /api/mode), so no lab has to.

export type StoreState =
  | { kind: "ready" }
  | { kind: "down" }                              // the server did not answer its last question (it may be restarting)
  // a replay whose recording is still arriving: how many records so far and of how many, where known
  | { kind: "filling"; records: number | null; total: number | null };

/** What the replay itself says (GET /api/labs/state, engine/labs/_replay.py): how many records its recording
 *  holds, and whether every record and alert is in the store. null: this server can't say (no replay runs
 *  in it, or it is an older server). undefined: not asked yet. */
export type ReplaySays = { total: number | null; done: boolean } | null | undefined;

/** Only for a replay whose server can't say when it is whole: how long its store must have been still.
 *  The replay feeds at 3x with quiet gaps capped at 5 recorded seconds and scores every 2 s, so a pause of
 *  up to about 4 s (7 s at 1x) happens INSIDE a refill; 8 s is past both. */
export const SETTLE_S = 8;

/**
 * `mode`: the dashboard's own word for what it is ("replay", "live", ...). `error`: the feed's last failure,
 * null when its last poll was answered. `health`: `records` so far and `seconds` since the newest one arrived.
 * `replay`: the replay's own word, which decides whenever there is one.
 * A live store grows all the time and is always "ready". A replay is "filling" until the replay says it is
 * done; where the server can't say, until it has records and none arrived for SETTLE_S seconds. Not knowing
 * counts as filling, never as ready.
 */
export function storeState(mode: string | null | undefined, error: string | null | undefined,
    health: { records?: number | null; seconds?: number | null } | null | undefined, replay?: ReplaySays, settle = SETTLE_S): StoreState {
  if (error) return { kind: "down" };
  if (mode !== "replay") return { kind: "ready" };
  const records = health ? health.records ?? 0 : null;
  if (replay === undefined) return { kind: "filling", records, total: null };                 // not asked yet: nothing is known
  if (replay) return replay.done ? { kind: "ready" } : { kind: "filling", records, total: replay.total };
  const still = health?.seconds;
  if (!health || !records || still === null || still === undefined || still < settle) return { kind: "filling", records, total: null };
  return { kind: "ready" };
}

/** Ask the replay (every 2 s while `on`): see ReplaySays. A server without the question answers null. */
export function useReplaySays(on: boolean): ReplaySays {
  const [says, setSays] = useState<ReplaySays>(undefined);
  useEffect(() => {
    if (!on) { setSays(undefined); return; }
    let live = true;
    const ask = () => fetch("/api/labs/state")
      .then((r) => (r.ok ? (r.json() as Promise<{ replay?: ReplaySays }>) : { replay: null }))
      .then((j) => { if (live) setSays(j.replay ?? null); })
      .catch(() => { /* the feed's own error says the server is silent */ });
    void ask();
    const t = window.setInterval(ask, 2000);
    return () => { live = false; window.clearInterval(t); };
  }, [on]);
  return says;
}

/** A lab page whose code could not be fetched: after a rebuild, a tab that was open before asks for files
 *  that are gone. That is a stale tab, not a broken lab: the fix is to reload. */
export const isStaleBuild = (problem: string | null | undefined) =>
  !!problem && /dynamically imported module|importing a module script failed|error loading dynamically|failed to fetch|is not a valid javascript mime type|unexpected token '<'/i.test(problem);
