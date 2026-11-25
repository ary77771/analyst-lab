// Types and fetchers for the Python API (engine/dashboard/app.py, words.py, public.py).
// The page only places and styles what these return; every claim word comes from Python.

export type Ink = "fact" | "hypothesis" | "gap";

export interface Words {
  tagline: string;
  verbs: Record<string, string>;
  lanes: Record<string, string>;
  start_tag: string;
  summary_title: string;
  chain_note: string;
  offset_note: string;
  inks: Record<Ink, { word: string; explain: string }>;
  bands: Record<string, string>;
  band_not_assessable: string;
  events: Record<string, string>;
  legend_title: string;
  legend: { ink: Ink; line: "solid" | "dashed" | "dotted"; text: string }[];
  evidence_title: string;
  evidence_hint: string;
  evidence_role: string;
  public_badge: string;
  alert_level: string;
  steps_title: string;
  limits_title: string;
  no_alerts: string;
  raised_title: string;
  run_hint: string;
  run_one: string;
  run_three: string;
  run_three_hint: string;
  live_notice: string;
  live_label: string;
  replay_offer: string;
  story_pick: string;
  proof: { scores_title: string; twin_title: string; strict_label: string };
}

export interface Evidence {
  role: string;
  host: string;
  machine: string;
  key: string;
  record_id: number;
  event: number;
  time: string;
}

export interface PublicNode {
  id: string;
  kind: string;
  host: string;
  machine: string;
  label: string;
  image?: string;
  start: string | null;
  gaps: string[];
  focus: boolean;
}

export interface PublicEdge {
  id: string;
  source: string;
  target: string;
  kind: string;
  grade: Ink;
  band: string | null;
  crosshost: boolean;
  time: string;
  focus: boolean;
  sentence: string;
  evidence: Evidence[];
  port?: number;
}

export interface TwoMachines {
  words: Record<string, string>;
  dataset: { name: string; commit: string; url: string; licence: string; licence_text: string };
  file: string;
  choice_rule: string;
  machines: { machine: string; host: string; sysmon_events: number; in_picture: boolean }[];
  story: string[];
  story_others: string[];
  nodes: PublicNode[];
  edges: PublicEdge[];
  headline: { value: number; label: string; ink?: Ink }[];
  sentences: string[];
  limit: string;
}

export interface AlertRow {
  id: string; title: string; rule: string; source: string; level: string; time: string; host: string; reason: string; events: number;
}

export interface Citation { key: string; event: number | string; record: number; time: string; text: string }
export interface Line { label: string; text: string }

export interface ReportFact { id?: string; sentence: string; short?: string; kind: string; time: string; citations: Citation[]; in_chain?: boolean }
export interface ReportHypothesis extends ReportFact {
  band: string; band_label?: string; chance_text?: string; chance_short?: string; plain?: Line[]; details?: Line[]; alternative?: string;
  assessable?: boolean; lead_only?: boolean;
}
export interface ReportGap { id?: string; what: string; where: string; reason: string; plain?: string; placement?: string; time: string; citations: Citation[] }

export interface Step { n: number; id: string; text: string; offset_text: string; t_offset_s: number; icon: string; citations: Citation[] }
export interface Verdict {
  title: string; level: string; level_text: string; host: string; time: string;
  steps: Step[]; steps_more: number; offset_from?: string;
  proven: { text: string; ids: string[] };
  not_proven: { text: string; id: string; band: string } | null;
  cant_see: { text: string; id: string } | null;
}
export interface TimelineItem {
  id: string; short: string; text: string; ink: Ink; grade: string; placement?: string; order: number;
  offset_text: string | null; t_offset_s: number | null; icon: string; in_chain: boolean;
}
export interface LayoutNode { id: string; short: string; label: string; kind: string; icon: string; lane: number; order: number; t_offset_s: number | null }
export interface LayoutEdge { id: string; u: string; v: string; kind: string; grade: Ink; band: string | null; lane: number; order: number; icon: string; short: string; in_chain: boolean }
export interface Layout { lanes: { lane: number; node_id: string; short: string }[]; nodes: LayoutNode[]; edges: LayoutEdge[] }

export interface Report {
  verdict?: Verdict;
  counts?: { facts: number; hypotheses: number; gaps: number; before: number; in_chain: number; steps: number };
  layout?: Layout;
  timeline: TimelineItem[];
  summary: string;
  summary_lines: { label: string; text: string }[];
  /** an alert raised on something a command line DECLARED (not a recorded action): Python's short note and sentence */
  declared_banner: { note: string; kind: string; text: string } | null;
  facts: ReportFact[];
  hypotheses: ReportHypothesis[];
  gaps: ReportGap[];
  limitations: string[];
  next_steps: string[];
}

export interface GraphNode { id: string; label: string; kind: string; gaps: string[]; seed: boolean; hub: boolean; hop: boolean }
export interface GraphEdge {
  id: string; source: string; target: string; kind: string; grade: string; band: string | null; sentence: string; time: string | null; evidence: string[];
}
/**
 * Which of the report's rows the Story screen's film tells (engine/dashboard/film.py). `whole`: all of them.
 * Otherwise `ids` is Python's cut, in the timeline's order; `counts` are the film's rows by ink and
 * `story_counts` the whole story's (two sets, each named by `labels`); `note` is the line kept visible
 * under the film; `layout` is the report's layout cut down to the film's things.
 */
export interface FilmCut {
  whole: boolean; ids: string[]; rows: number; total: number; note: string | null;
  counts: Record<Ink, number>; story_counts: Record<Ink, number>; labels: { film: string; story: string }; layout?: Layout;
}
export interface Investigation { alert: AlertRow; nodes: GraphNode[]; edges: GraphEdge[]; report: Report; warnings: string[]; film?: FilmCut | null }

export interface Scoreboard {
  title: string;
  intro: string;
  groups: ScoreGroup[];
  lost: string;
  laptop: string[];
  source: string;
  /** the panel's second view (2026-11-24): a week of real use and the newest unseen stories. Absent on an older server. */
  latest?: { title: string; tabs: { first: string; latest: string }; intro: string; groups: ScoreGroup[]; summary: string; worse: string; sources: string[] };
}
/** `text`: the number as Python wrote it out (a rate with one decimal); without it the number is a count. */
export interface ScoreGroup { title: string; bars: { label: string; name?: string; value: number; text?: string; of: number }[]; unit: string; notes: string[]; visible?: number; short?: string; caveat?: string; of_text?: string }

export interface Health {
  state: "waiting" | "starting" | "watching" | "quiet" | "alert";
  text: string;
  seconds: number | null;
  alerts: number;
  alert?: { id: string; title: string; level: string; time: string };
  view_ids: string[];
  watch_note: string | null;
  /** only while a demo replay is still feeding its store: how far it is, and Python's sentence for "no alert yet" */
  replay_playing?: { total: number; records: number; text: string } | null;
  before_test: { count: number; id: string; text: string } | null;
  /** alerts raised after the test finished: not the test's, shown as their own quiet line */
  after_test?: { count: number; id: string; text: string } | null;
  /** alerts about other programs on the test machine while a test's own programs are known: not the test's */
  other_alerts?: { count: number; id: string; text: string } | null;
  records: number;
  records_text: string;
}
export interface RunSteps {
  steps: { text: string; state: "done" | "current" | "todo" | "failed" }[];
  finished: boolean; running: boolean; scenario: string | null; exit_code: number | null; outcome: string | null;
  started: number | null; now: number; ended: number | null;
}

export interface Coverage {
  words: { title: string; intro: string; results: Record<string, string>; results_short?: Record<string, string>; toggle: string; toggle_note: string; caught_label: string; source: string; declared_note: string; meaning: string };
  total: number; caught: number; caught_strict: number; declared: number; half: string;
  groups: { technique: string; name: string; tests: { technique: string; guid: string; phase: number; result: string; without_citing_rules: boolean; technique_name: string; test_name: string }[] }[];
}

export interface Twin {
  words: { title: string; intro: string; picked: string; writer_title: string; kind: Record<string, string>; raised: string; none_raised: string; below: string; steps: string; verdicts: string; difference: string };
  source: string; floor: string; headline?: string | null;
  sides: { scenario: string; run_id: string; kind: string; title: string;
    raised: { title: string; level: string; rule: string; plain?: string | null; steps?: string[] }[];
    below_floor: { title: string; level: string; rule: string; plain?: string | null }[];
    verdicts: { v3: string; v4: string; runs: number } | null }[];
}

export interface ChecksState {
  words: Record<string, string>;
  running: boolean; busy: boolean; total: number | null; passed: number; failed: number; skipped: number;
  seconds: number | null; exit_code: number | null; text?: string; ready_text?: string;
  ok: boolean | null; items: { name: string; outcome: "passed" | "failed" | "skipped" }[];
  groups?: { name: string; total: number | null; passed: number; failed: number; skipped: number }[];
}

export interface Warm {
  enabled: boolean;
  words: { title: string; practice: string; practice_tag: string; start: string; start_hint: string; stop: string; used: string; one_boot: string; other_run: string };
  state?: "off" | "starting" | "ready" | "running" | "stopping" | "failed" | "ended" | "recovering";
  /** after a restart of the dashboard: why tests are not offered yet; or that the machine is on but is not this dashboard's */
  hint?: string; foreign_text?: string;
  text?: string; error?: string | null; ready_text?: string; warning?: string; ended_text?: string;
  /** the start as steps, and the seconds since the click on "start" (both from Python) */
  boot_list?: { text: string; state: "done" | "current" | "todo" }[]; starting_seconds?: number | null;
  seconds_left?: number | null; other_run?: boolean; can_start?: boolean; can_stop?: boolean;
  tests?: { id: string; label: string; used: boolean; can_run: boolean }[];
}

/** A warm session's alert, for the Story header: whose programs it was raised on (Python decides, by the records). */
export interface AlertLabel { label: string; kind: "test" | "other"; title: string }

/** The guided tour: Python's steps and words (engine/dashboard/tour.py). */
export interface TourStep { screen: "watch" | "story" | "proof" | "labs"; target: string; title: string; text: string }
export interface Tour { words: Record<string, string>; steps: TourStep[] }

export interface Mode { mode: "live" | "replay" | "rehearsal" | null; badge: string | null; detail: string | null; can_run: boolean }

async function get<T>(path: string): Promise<T> {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return (await r.json()) as T;
}

export const api = {
  words: () => get<Words>("/api/words"),
  twoMachines: () => get<TwoMachines>("/api/public/two-machines"),
  alerts: () => get<AlertRow[]>("/api/alerts"),
  tour: () => get<Tour>("/api/tour"),
  alertLabels: () => get<Record<string, AlertLabel>>("/api/alert-labels"),
  scoreboard: () => get<Scoreboard>("/api/scoreboard"),
  health: () => get<Health>("/api/health"),
  mode: () => get<Mode>("/api/mode"),
  peer: () => get<{ live_url: string | null; replay_url: string | null }>("/api/peer"),
  checks: () => get<ChecksState>("/api/checks"),
  coverage: () => get<Coverage>("/api/coverage"),
  twin: () => get<Twin>("/api/twin"),
  runChecks: async () => {
    const r = await fetch("/api/checks/run", { method: "POST" });
    if (!r.ok) throw new Error((await r.json().catch(() => ({ detail: r.status }))).detail);
  },
  runSteps: () => get<RunSteps>("/api/run/steps"),
  warm: () => get<Warm>("/api/warm"),
  warmDo: async (what: string) => {
    const r = await fetch(`/api/warm/${what}`, { method: "POST" });
    if (!r.ok) throw new Error(String((await r.json().catch(() => ({ detail: r.status }))).detail));
    return (await r.json()) as Warm;
  },
  runThree: async () => {
    const r = await fetch("/api/run/three", { method: "POST" });
    if (!r.ok) throw new Error(String((await r.json().catch(() => ({ detail: r.status }))).detail));
  },
  runScenario: async (id: string) => {
    const r = await fetch(`/api/scenarios/${encodeURIComponent(id)}/run`, { method: "POST" });
    if (!r.ok) throw new Error(String((await r.json().catch(() => ({ detail: r.status }))).detail));
  },
  investigation: (id: string) => get<Investigation>(`/api/alerts/${encodeURIComponent(id)}`),
  film: (id: string) => get<FilmCut>(`/api/alerts/${encodeURIComponent(id)}/film`),
  event: (key: string) => get<Record<string, unknown>>(`/api/events/${encodeURIComponent(key)}`),
};
