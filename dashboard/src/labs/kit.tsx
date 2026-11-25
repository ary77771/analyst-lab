// Small shared pieces for lab pages, so they load, fail and look alike (2026-11-23).
// Optional: a lab may use them or not. Nothing here knows about any one lab.
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { ArrowRight } from "lucide-react";
import { alertOf, labsBackend, pathFor, runName, useLabs, withAlert } from "./registry";

/** What a lab says when the server did not answer at all: never the browser's own "Failed to fetch". */
export const NO_ANSWER = "the dashboard's server did not answer (it may be restarting); this page asks again by itself";
/** ... and once it has stopped asking (after about 40 seconds): it must not go on saying that it asks. */
export const NO_ANSWER_STOPPED = "the dashboard's server did not answer for a while; reload the page when it is back";
const TRIES = 20;

/** GET a lab's JSON. `data` is null while loading; `error` is the plain reason when it failed. */
export function useLab<T>(url: string | null): { data: T | null; error: string | null; loading: boolean; reload: () => void } {
  const [state, setState] = useState<{ data: T | null; error: string | null; loading: boolean }>({ data: null, error: null, loading: !!url });
  const [turn, setTurn] = useState(0);
  const tries = useRef(0);
  useEffect(() => {
    if (!url) { setState({ data: null, error: null, loading: false }); return; }
    let on = true;
    setState((s) => ({ ...s, loading: true, error: null }));
    let again = 0;
    fetch(url)
      .then(async (r) => {
        if (!r.ok) throw new Error(String((await r.json().catch(() => null))?.detail ?? `${r.status} ${r.statusText}`));
        return (await r.json()) as T;
      })
      .then((data) => { if (on) { tries.current = 0; setState({ data, error: null, loading: false }); } })
      .catch((e) => {
        if (!on) return;
        // the server did not answer at all (a browser says "Failed to fetch"): say that, and ask again by
        // itself a few times; a restart takes seconds. An answer that is an error is the lab's to show.
        const silent = e instanceof TypeError;
        const more = silent && tries.current < TRIES;
        setState({ data: null, error: silent ? (more ? NO_ANSWER : NO_ANSWER_STOPPED) : String(e instanceof Error ? e.message : e), loading: false });
        if (more) { tries.current += 1; again = window.setTimeout(() => { if (on) setTurn((n) => n + 1); }, 2000); }
      });
    return () => { on = false; window.clearTimeout(again); };
  }, [url, turn]);
  return { ...state, reload: () => setTurn((n) => n + 1) };
}

/** The same three states on every lab page: loading, failed (with the reason), nothing to show. */
export function LabState({ loading, error, empty, children }: { loading?: boolean; error?: string | null; empty?: string | false | null; children?: ReactNode }) {
  if (error) return <p className="lab-state" data-kind="error" role="alert">This lab could not load its data: {error}</p>;
  if (loading) return <p className="lab-state" data-kind="loading">Loading…</p>;
  if (empty) return <p className="lab-state" data-kind="empty">{empty}</p>;
  return <>{children}</>;
}

/** A titled panel in the dashboard's own look. */
export function LabPanel({ title, hint, children }: { title?: string; hint?: string; children: ReactNode }) {
  return (
    <section className="ua-panel lab-panel">
      {title && <h2>{title}</h2>}
      {hint && <p className="ua-hint">{hint}</p>}
      {children}
    </section>
  );
}

/** One counted number with its plain label (and, on hover, what exactly was counted). */
export function LabNumber({ value, label, title }: { value: number | string; label: string; title?: string }) {
  return <div className="lab-number" title={title}><b>{typeof value === "number" ? value.toLocaleString("en-US") : value}</b><span>{label}</span></div>;
}

// ---------------------------------------------------------------------------------------------------------
// Wave 3 (2026-11-24): one alert through the labs. A lab that is about one alert uses these three, so the
// alert picked in one lab is still picked in the next and no lab is a dead end.

/**
 * The alert this lab page is about, kept in the address ("#/labs/<lab>?alert=<id>").
 *     const [alert, setAlert] = useAlertParam();
 * `alert` is null when the address names none (show the lab's own list of alerts then). `setAlert(id)` writes
 * it into the address (Back returns to the alert before; pass "replace" to keep Back out of it) and
 * `setAlert(null)` takes it away. An id that is not in this recording is the lab's to say: show
 * "This alert isn't in this recording" rather than an empty page.
 */
export function useAlertParam(): [string | null, (id: string | null, how?: "push" | "replace") => void] {
  const read = () => (typeof window === "undefined" ? null : alertOf(window.location.hash));
  const [alert, setAlert] = useState<string | null>(read);
  useEffect(() => {
    const on = () => setAlert(read());
    window.addEventListener("hashchange", on);
    on();
    return () => window.removeEventListener("hashchange", on);
  }, []);
  const set = useCallback((id: string | null, how: "push" | "replace" = "push") => {
    const to = withAlert(window.location.hash, id);
    if (to === window.location.hash) return;
    if (how === "replace") window.location.replace(to); else window.location.hash = to;      // both tell the dashboard's route reader
  }, []);
  return [alert, set];
}

/**
 * The thin strip at the top of a lab that is about one alert: the same alert's other views, in the order
 * an investigation asks its questions, the present one marked.
 *     <NextStrip current="why" alert={alert} />
 * Only labs that are part of this build get a chip; with fewer than two there is no strip. A lab that is
 * not about an alert simply does not draw it.
 */
export function NextStrip({ current, alert }: { current: string; alert: string | null | undefined }) {
  const found = useLabs();
  const chips = found ? pathFor(found.labs, current, alert) : [];
  if (chips.length < 2) return null;
  return (
    <nav className="lab-path" aria-label="This alert in the other labs">
      <span className="lab-path-lead">{alert ? "This alert:" : "One alert, step by step:"}</span>
      <ol>
        {chips.map((c, i) => (
          <li key={c.lab}>
            {i > 0 && <ArrowRight size={13} aria-hidden="true" />}
            <a href={c.href} title={c.hint} data-lab={c.lab} aria-current={c.current ? "step" : undefined}>{c.label}</a>
          </li>
        ))}
      </ol>
    </nav>
  );
}

/**
 * Everyday names for test runs: `const name = useRunName();` then `name("s1")` gives "S1 · Download and run".
 * The names are Python's (engine/labs/_names.py, read from each scenario's own file); a run without one is
 * "unnamed run". Until they have loaded, the code alone is shown.
 */
export function useRunName(): (id: string) => string {
  const [names, setNames] = useState<Record<string, string> | null>(null);
  useEffect(() => { let on = true; void labsBackend().then((b) => { if (on) setNames(b?.run_names ?? {}); }); return () => { on = false; }; }, []);
  return useCallback((id: string) => runName(id, names), [names]);
}
export { runName };
