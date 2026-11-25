// Shared React plumbing for both designs: the live feed (polled once, at the top, so it survives
// screen changes), the story film's clock, the checks runner, and small helpers.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { api, type AlertLabel, type AlertRow, type ChecksState, type Coverage, type Health, type Investigation, type Mode, type RunSteps,
  type Scoreboard, type Twin, type Warm, type Words } from "../api";
import { AlertWatch, parseRoute, rowsOf, type Route, type Row } from "./logic";

export function useRoute(): Route | null {
  const [r, setR] = useState<Route | null>(() => parseRoute(window.location.hash));
  useEffect(() => {
    const on = () => setR(parseRoute(window.location.hash));
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return r;
}

export interface Live {
  words: Words; mode: Mode | null; health: Health | null; steps: RunSteps | null; alerts: AlertRow[]; error: string | null;
  /** true once this dashboard has said what it is (live, replay, rehearsal or plain); until then nothing is assumed */
  modeKnown: boolean;
  /** the development flags ?landed and ?fixture: only on a plain or rehearsal dashboard whose mode is known */
  devOk: boolean;
  /** alert id -> when it landed on this page (ms); only alerts that arrived after the page opened */
  landed: Map<string, number>;
  /** records received per poll, oldest first (the last few minutes) */
  arrivals: number[];
  /** seconds since the run started, ticking between polls; null when no run */
  elapsed: number | null;
  run: (what: "one" | "three") => Promise<void>;
  /** a run was just asked for (the buttons wait); and why the last ask was refused, until the next ask */
  runPending: boolean; runError: string | null;
}
const LiveContext = createContext<Live | null>(null);
export const LiveProvider = LiveContext.Provider;
export function useLive(): Live {
  const v = useContext(LiveContext);
  if (!v) throw new Error("live feed not ready");
  return v;
}

const POLL_MS = 2000, KEEP = 90;

/** A demo dashboard (LIVE or REPLAY badge) never honours the development flags; nor does one whose mode is not known yet. */
export const devFlagsAllowed = (mode: Mode | null, known: boolean) => known && (!mode?.mode || mode.mode === "rehearsal");

/** Returns null until the words have loaded and the dashboard has said what it is (both are asked again until answered). */
export function useLiveFeed(): { live: Live | null; failing: boolean } {
  const [words, setWords] = useState<Words | null>(null);
  const [mode, setMode] = useState<Mode | null>(null);
  const [modeKnown, setModeKnown] = useState(false);
  const [health, setHealth] = useState<Health | null>(null);
  const [steps, setSteps] = useState<RunSteps | null>(null);
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [landed, setLanded] = useState<Map<string, number>>(new Map());
  const [arrivals, setArrivals] = useState<number[]>([]);
  const [now, setNow] = useState(Date.now());
  const [runPending, setRunPending] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const polledAt = useRef(Date.now());
  const watch = useRef(new AlertWatch());
  const lastRecords = useRef<number | null>(null);
  const first = useRef(true);
  const asking = useRef(false);
  const [failing, setFailing] = useState(false);            // the first questions were not answered (the server is down or starting)

  useEffect(() => {
    let on = true;
    const timers: number[] = [];
    const again = (f: () => void, ms: number) => { if (on) { setFailing(true); timers.push(window.setTimeout(f, ms)); } };
    const askWords = () => { api.words().then((x) => { if (on) setWords(x); }).catch(() => again(askWords, 2000)); };
    const askMode = () => { api.mode().then((m) => { if (on) { setMode(m); setModeKnown(true); } }).catch(() => again(askMode, 2000)); };
    askWords(); askMode();
    return () => { on = false; timers.forEach((t) => window.clearTimeout(t)); };
  }, []);
  const devOk = devFlagsAllowed(mode, modeKnown);
  useEffect(() => {
    if (!modeKnown) return;
    let on = true;
    const tick = async () => {
      try {
        const [h, s, a] = await Promise.all([api.health(), api.runSteps(), api.alerts()]);
        if (!on) return;
        // ?landed (screenshots, never on a demo dashboard): treat the alerts already there as just landed
        if (first.current && devOk && window.location.search.includes("landed")) watch.current.update([]);
        first.current = false;
        const fresh = watch.current.update(h.view_ids ?? []);
        if (fresh.length) setLanded((m) => { const n = new Map(m); fresh.forEach((id) => n.set(id, Date.now())); return n; });
        const rec = h.records ?? 0;
        const delta = lastRecords.current === null ? 0 : Math.max(0, rec - lastRecords.current);
        lastRecords.current = rec;
        setArrivals((x) => [...x, delta].slice(-KEEP));
        setHealth(h); setSteps(s); setAlerts(a); setError(null); polledAt.current = Date.now();
      } catch (e) { if (on) setError(String(e instanceof Error ? e.message : e)); }
    };
    tick();
    const t = window.setInterval(tick, POLL_MS);
    const c = window.setInterval(() => setNow(Date.now()), 1000);
    return () => { on = false; window.clearInterval(t); window.clearInterval(c); };
  }, [modeKnown, devOk]);

  // one ask at a time: the buttons wait until the run shows up (or a few seconds), and a refusal stays
  // on screen next to them until the next ask (it used to vanish with the next poll)
  const run = useCallback(async (what: "one" | "three") => {
    if (asking.current) return;
    asking.current = true; setRunPending(true); setRunError(null);
    try { await (what === "three" ? api.runThree() : api.runScenario("s1")); } catch (e) { setRunError(String(e instanceof Error ? e.message : e)); }
    window.setTimeout(() => { asking.current = false; setRunPending(false); }, 4000);
  }, []);
  // ticking between polls while the run goes; fixed at the run's own length once Python says it ended
  const elapsed = !steps?.started ? null : steps.ended ? Math.max(0, steps.ended - steps.started)
    : Math.max(0, steps.now - steps.started + (now - polledAt.current) / 1000);
  const live = useMemo(() => (words && modeKnown ? { words, mode, modeKnown, devOk, health, steps, alerts, error, landed, arrivals, elapsed, run, runPending, runError } : null),
    [words, mode, modeKnown, devOk, health, steps, alerts, error, landed, arrivals, elapsed, run, runPending, runError]);
  return { live, failing: failing && !live };
}

/**
 * One alert's investigation. It is fetched when the story is opened and when `reload()` is called
 * ("play again"), never by itself: while records still arrive the story on screen must not change
 * under the viewer, and a live test machine must not be asked to rebuild the graph every two seconds.
 * A failed ask keeps the story already on screen and only reports the error.
 */
export function useStory(id: string | null, devOk: boolean): { inv: Investigation | null; rows: Row[]; error: string | null; reload: () => Promise<void> } {
  const [inv, setInv] = useState<Investigation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const want = useRef<string | null>(null);
  const load = useCallback(async (which: string) => {
    // ?fixture=name (development, never on a demo dashboard): a saved investigation from /static/dev/
    const fx = devOk ? new URLSearchParams(window.location.search).get("fixture") : null;
    try {
      // the story and Python's cut for its film (its own route). Without a cut the film tells every row.
      const x = await (fx ? fetch(`/static/dev/${encodeURIComponent(fx)}.json`).then((r) => r.json() as Promise<Investigation>)
        : Promise.all([api.investigation(which), api.film(which).catch(() => null)]).then(([story, film]) => ({ ...story, film })));
      if (want.current === which) { setInv(x); setError(null); }
    } catch (e) { if (want.current === which) setError(String(e instanceof Error ? e.message : e)); }
  }, [devOk]);
  useEffect(() => {
    want.current = id;
    setInv(null); setError(null);
    if (id) void load(id);
  }, [id, load]);
  const reload = useCallback(() => (want.current ? load(want.current) : Promise.resolve()), [load]);
  const rows = useMemo(() => (inv ? rowsOf(inv) : []), [inv]);
  return { inv, rows, error, reload };
}

/**
 * The newest alert's story, for the preview inside its card on Watch. This is the one place a story is
 * asked for without a click (DESIGN-SYSTEM.md says so): when the alert lands, and again whenever `phase`
 * changes (the run has ended; the store has gone quiet: logic.ts previewPhase), so the card's counts end
 * up equal to the Story's. Never per poll.
 */
const previews = new Map<string, Promise<Investigation>>();
/** Python's labels for the alerts of a warm session ("S1", "other"); {} when there are none or they can't be asked. */
export function useAlertLabels(key: string): Record<string, AlertLabel> {
  const [labels, setLabels] = useState<Record<string, AlertLabel>>({});
  useEffect(() => {
    let on = true;
    api.alertLabels().then((l) => { if (on) setLabels(l); }).catch(() => { if (on) setLabels({}); });
    return () => { on = false; };
  }, [key]);
  return labels;
}

export function usePreview(id: string | null, phase: string): Investigation | null {
  const [got, setGot] = useState<Investigation | null>(null);
  useEffect(() => {
    if (!id) return;
    let on = true;
    const key = `${id}|${phase}`;
    let p = previews.get(key);
    if (!p) { p = api.investigation(id); previews.set(key, p); p.catch(() => previews.delete(key)); }
    p.then((x) => { if (on) setGot(x); }).catch(() => {});
    return () => { on = false; };
  }, [id, phase]);
  return got && got.alert.id === id ? got : null;
}

/** The film's clock: `shown` rows have been told (0 = nothing yet, total = everything). */
export function useFilm(total: number, stepMs: number, key: string | null) {
  const [shown, setShown] = useState(0);
  const [playing, setPlaying] = useState(false);
  useEffect(() => { setShown(0); setPlaying(false); }, [key]);
  useEffect(() => {
    if (!playing) return;
    if (shown >= total) { setPlaying(false); return; }
    const t = window.setTimeout(() => setShown((s) => s + 1), shown === 0 ? 500 : stepMs);
    return () => window.clearTimeout(t);
  }, [playing, shown, total, stepMs]);
  const go = useCallback((n: number) => { setPlaying(false); setShown(Math.max(0, Math.min(total, n))); }, [total]);
  const restart = useCallback(() => { setShown(0); setPlaying(true); }, []);
  const toggle = useCallback(() => { if (shown >= total) { setShown(0); setPlaying(true); } else setPlaying((p) => !p); }, [shown, total]);
  return { shown, playing, go, restart, toggle, done: total > 0 && shown >= total };
}

/** Space = play/pause, arrows = one step, Home = start. Ignored while typing in a field. */
export function useKeys(handlers: Record<string, () => void>) {
  const h = useRef(handlers);
  h.current = handlers;
  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if (e.altKey || e.ctrlKey || e.metaKey) return;             // Alt+Left stays the browser's "back"
      const el = e.target as HTMLElement | null;
      if (el && (el.tagName === "INPUT" || el.tagName === "SELECT" || el.tagName === "TEXTAREA")) return;
      const f = h.current[e.key === " " ? "Space" : e.key];
      if (f) { e.preventDefault(); f(); }
    };
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, []);
}

export function useChecks(): { s: ChecksState | null; start: () => void; error: string | null } {
  const [s, setS] = useState<ChecksState | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let on = true;
    const tick = () => api.checks().then((x) => { if (on) setS(x); }).catch(() => {});
    tick();
    const t = window.setInterval(tick, 350);
    return () => { on = false; window.clearInterval(t); };
  }, []);
  const start = useCallback(() => { setError(null); api.runChecks().catch((e) => setError(String(e instanceof Error ? e.message : e))); }, []);
  return { s, start, error };
}

/** The warm test machine's state (asked every 2 s; the server answers from memory) and its three actions. */
export function useWarm(): { w: Warm | null; act: (what: string) => void; error: string | null; pending: boolean } {
  const [w, setW] = useState<Warm | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  useEffect(() => {
    let on = true;
    const tick = () => api.warm().then((x) => { if (on) setW(x); }).catch(() => {});
    tick();
    const t = window.setInterval(tick, 1000);                       // every second: the start's clock is Python's, shown as it arrives
    return () => { on = false; window.clearInterval(t); };
  }, []);
  const act = useCallback((what: string) => {
    setPending(true); setError(null);
    api.warmDo(what).then(setW).catch((e) => setError(String(e instanceof Error ? e.message : e)))
      .finally(() => window.setTimeout(() => setPending(false), 1500));
  }, []);
  return { w, act, error, pending };
}

/** The Proof screen's three sources, asked separately: one that fails leaves the other panels standing. */
export interface ProofData { sb: Scoreboard | null; cov: Coverage | null; twin: Twin | null; failed: string[]; ready: boolean }
export function useProof(): ProofData {
  const [d, setD] = useState<ProofData>({ sb: null, cov: null, twin: null, failed: [], ready: false });
  useEffect(() => {
    let on = true;
    Promise.allSettled([api.scoreboard(), api.coverage(), api.twin()]).then(([sb, cov, twin]) => {
      if (!on) return;
      const failed = [sb, cov, twin].filter((x) => x.status === "rejected").map((x) => String((x as PromiseRejectedResult).reason?.message ?? (x as PromiseRejectedResult).reason));
      setD({ sb: sb.status === "fulfilled" ? sb.value : null, cov: cov.status === "fulfilled" ? cov.value : null,
             twin: twin.status === "fulfilled" ? twin.value : null, failed, ready: true });
    });
    return () => { on = false; };
  }, []);
  return d;
}

const reduced = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/** A number that runs from its last value to the new one. The end value is always the API's. */
export function useCountUp(value: number, ms = 900): number {
  const [shown, setShown] = useState(value);
  const from = useRef(value);
  useEffect(() => {
    if (reduced() || from.current === value) { setShown(value); from.current = value; return; }
    const start = performance.now(), a = from.current;
    let raf = 0;
    const step = (t: number) => {
      const k = Math.min(1, (t - start) / ms), e = 1 - Math.pow(1 - k, 3);
      setShown(Math.round(a + (value - a) * e));
      if (k < 1) raf = requestAnimationFrame(step); else from.current = value;
    };
    raf = requestAnimationFrame(step);
    return () => { cancelAnimationFrame(raf); from.current = value; };
  }, [value, ms]);
  return shown;
}

/** A number that counts up from 0 the first time it is seen (proof screen). */
export function useCountIn(value: number, ms = 1100, delay = 0): number {
  const [shown, setShown] = useState(reduced() ? value : 0);
  useEffect(() => {
    if (reduced()) { setShown(value); return; }
    let raf = 0;
    const t0 = performance.now() + delay;
    const step = (t: number) => {
      const k = Math.max(0, Math.min(1, (t - t0) / ms)), e = 1 - Math.pow(1 - k, 3);
      setShown(Math.round(value * e));
      if (k < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [value, ms, delay]);
  return shown;
}

/** The size of an element, for drawings that must fill their panel. */
export function useSize<T extends HTMLElement>(): [React.RefObject<T | null>, { w: number; h: number }] {
  const ref = useRef<T | null>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  useEffect(() => {
    if (!ref.current) return;
    const el = ref.current;
    // the same size object is kept when nothing changed, so a repeated measure costs no re-render
    const measure = () => setSize((s) => (s.w === el.clientWidth && s.h === el.clientHeight ? s : { w: el.clientWidth, h: el.clientHeight }));
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    window.addEventListener("resize", measure);                    // a window resize is measured even where the observer is slow to report
    return () => { ro.disconnect(); window.removeEventListener("resize", measure); };
  }, []);
  return [ref, size];
}

/**
 * The demo's other dashboard. On the replay page: the live one's state (read every 3 s; silent if it
 * is not there). On the live page: a link to the replay. Addresses come from /api/peer.
 */
export interface Peer {
  /** replay page only: the live dashboard's current state */
  live: { text: string; state: Health["state"]; alertTitle: string | null; watchUrl: (skin: string) => string; storyUrl: (skin: string) => string } | null;
  /** live page only: where the recorded run plays */
  replayUrl: ((skin: string) => string) | null;
}
export function usePeer(mode: Mode | null): Peer {
  const [urls, setUrls] = useState<{ live_url: string | null; replay_url: string | null } | null>(null);
  const [h, setH] = useState<Health | null>(null);
  const known = !!mode?.mode;
  useEffect(() => { if (known) api.peer().then(setUrls).catch(() => setUrls(null)); }, [known]);
  const live = urls?.live_url ?? null;
  useEffect(() => {
    if (!live) return;
    let on = true;
    const tick = () => fetch(`${live}/api/health`).then((r) => (r.ok ? r.json() : null)).then((x) => { if (on) setH(x); }).catch(() => { if (on) setH(null); });
    tick();
    const t = window.setInterval(tick, 3000);
    return () => { on = false; window.clearInterval(t); };
  }, [live]);
  const replay = urls?.replay_url ?? null;
  return {
    live: live && h ? { text: h.text, state: h.state, alertTitle: h.state === "alert" && h.alert ? h.alert.title : null,
      watchUrl: (skin) => `${live}/#${skin}/watch`,
      storyUrl: (skin) => `${live}/#${skin}/story${h.alert ? `/${encodeURIComponent(h.alert.id)}` : ""}` } : null,
    replayUrl: replay ? (skin) => `${replay}/#${skin}/story` : null,
  };
}
