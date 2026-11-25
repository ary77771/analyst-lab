// The Labs screen: every lab as a card, under the question it answers (wave 3: "Start here", "What
// happened?", ...; registry.ts GROUPS); "#/labs/<id>?..." opens one. Each lab is loaded by itself; one that
// fails to load is shown as such, and one that crashes while drawing shows its own error in its own place:
// the dashboard around it keeps working.
import { Component, useEffect, useRef, useState, type ReactNode } from "react";
import { ArrowLeft, ArrowRight, Eye, EyeOff, FlaskConical, RotateCw, TriangleAlert } from "lucide-react";
import { useLive } from "../ui2/hooks";
import GuideBar from "./GuideBar";
import { countExperimental, findLab, groupLabs, isExperimental, isStaleBuild, labHref, pathFor, readShowExperimental, splitLabParam, storeState, useLabs, useLabsBackend, useReplaySays,
  writeShowExperimental } from "./registry";
import "./labs.css";

const TEXT = {
  title: "Labs",
  // VISION's front-door wording (docs/night/labs-qa.md, part 1); it names the first card by its own title
  intro: "Tools for looking closer at one alert. They only read the recording; they never change it. New here? Start with \u201cI have an alert\u201d.",
  startHere: "Start here",
  thenPath: "Then, the same alert, question by question:",
  loading: "Loading the labs…",
  none: "No lab is part of this build yet.",
  off: "Labs are switched off on this dashboard (it was started with --no-labs).",
  back: "All labs",
  unknown: (id: string) => `There is no lab called "${id}" in this build.`,
  crashed: "This lab ran into an error and stopped. The rest of the dashboard is not affected.",
  failed: "This lab failed to load",
  failedPage: "The page of this lab failed to load",
  failedBack: "The dashboard's server left this lab's data out",
  failedHint: "The other labs and the rest of the dashboard are not affected.",
  // experimental labs (registry.ts EXPERIMENTAL): kept, but not on the page unless this is switched on
  showExperimental: (n: number) => `Show experimental labs (${n})`,
  hideExperimental: "Hide experimental labs",
  experimentalHint: "Kept, but not shown by default: on our own recordings these say little yet, or say what another lab says better.",
  onlyExperimental: "Every lab of this build is experimental. Switch them on below to see them.",
  experimentalTag: "Experimental",
  experimentalTagHint: "This lab is experimental: it is not on the Labs page unless experimental labs are switched on there.",
};

const storage = () => { try { return window.localStorage; } catch { return null; } };

// What the shell says instead of (or above) a lab while the lab could not speak truly (registry.ts storeState).
const STATE = {
  // only numbers that are known are said: before the first answer there is none
  filling: (n: number | null, total: number | null) =>
    `The replay is still loading${n === null ? "" : total ? ` (${n.toLocaleString("en-US")} of ${total.toLocaleString("en-US")} records so far)` : ` (${n.toLocaleString("en-US")} record${n === 1 ? "" : "s"} so far)`}. `
    + "This page opens by itself when the recording is complete, so that nothing is said about half of it.",
  down: "The dashboard's server did not answer its last question; it may be restarting. What this page shows may be out of date, and a line like \"Failed to fetch\" below means only that.",
  back: "The dashboard is answering again.",
  reload: "Load this page's data again",
  stale: "A newer version of the dashboard is ready. Reload the page to get it.",
  reloadPage: "Reload the page",
};

/** Around every lab's page: a page that throws while it is drawn is replaced by this line, and only that page. */
export class Guard extends Component<{ name: string; children: ReactNode }, { error: string | null }> {
  state = { error: null as string | null };
  static getDerivedStateFromError(e: unknown) { return { error: String(e instanceof Error ? e.message : e) }; }
  componentDidUpdate(prev: { name: string }) { if (prev.name !== this.props.name && this.state.error) this.setState({ error: null }); }
  render() {
    if (this.state.error) return <p className="lab-state" data-kind="error" role="alert">{TEXT.crashed} ({this.state.error})</p>;
    return this.props.children;
  }
}

export default function LabsScreen({ param }: { param: string | null }) {
  const { id, params } = splitLabParam(param);
  const found = useLabs();
  const backend = useLabsBackend();
  const [showExperimental, setShowExperimental] = useState(() => readShowExperimental(storage()));      // remembered in this browser; off by default
  // may a lab speak right now? (the feed the whole dashboard already has: nothing new is asked of the server)
  const live = useLive();
  const replaySays = useReplaySays(live.mode?.mode === "replay" && !!id);      // the replay's own word on whether its store is whole
  const store = storeState(live.mode?.mode, live.error, live.health, replaySays);
  const wasDown = useRef(false);
  const [back, setBack] = useState(false);                 // the server answers again after a silence: offer to load the page's data anew
  const [turn, setTurn] = useState(0);                     // (a new turn draws the lab afresh)
  useEffect(() => {
    if (store.kind === "down") { wasDown.current = true; setBack(false); }
    else if (store.kind === "filling") { wasDown.current = false; setBack(false); }      // the lab is taken away and comes back fresh by itself
    else if (wasDown.current) { wasDown.current = false; setBack(true); }
  }, [store.kind]);
  const head = (children: ReactNode) => <header className="lab-head">{children}</header>;

  if (backend && backend.enabled === false) {
    return <div className="lab-page">{head(<><FlaskConical size={18} /><h1>{TEXT.title}</h1></>)}<p className="lab-state" data-kind="empty">{TEXT.off}</p></div>;
  }
  if (!found) {
    return <div className="lab-page">{head(<><FlaskConical size={18} /><h1>{TEXT.title}</h1></>)}<p className="lab-state" data-kind="loading">{TEXT.loading}</p></div>;
  }
  // what failed: a page of this build that did not load, and a back-end file the server had to leave out
  const failedPages = found.leftOut;
  const failedBack = (backend?.left_out ?? []).filter((b) => !failedPages.some((p) => p.id === b.name));

  if (id) {
    const lab = findLab(found.labs, id);
    const broken = failedPages.find((x) => x.id === id);
    const noData = backend?.left_out.find((b) => b.name === id);
    return (
      <div className="lab-page" data-lab={id}>
        {head(<>
          <a className="lab-back" href={labHref()}><ArrowLeft size={15} />{TEXT.back}</a>
          {lab && <><lab.icon size={18} /><h1>{lab.title}</h1>
            {isExperimental(id) && <span className="lab-tag" title={TEXT.experimentalTagHint}>{TEXT.experimentalTag}</span>}
            <p>{lab.blurb}</p></>}
        </>)}
        {noData && <p className="lab-state" data-kind="error" role="alert">{TEXT.failedBack}: {noData.problem}. {TEXT.failedHint}</p>}
        {store.kind === "down" && <p className="lab-state lab-notice" data-kind="error" role="status">{STATE.down}</p>}
        {store.kind === "ready" && back && (
          <p className="lab-state lab-notice" data-kind="empty" role="status">{STATE.back}
            <button type="button" className="ua-btn" onClick={() => { setBack(false); setTurn((n) => n + 1); }}><RotateCw size={14} />{STATE.reload}</button></p>
        )}
        {lab && store.kind !== "filling" && params.get("guide") && <Guard name={`guide-bar ${id}?${params}`}><GuideBar lab={id} params={params} /></Guard>}
        {store.kind === "filling" ? <p className="lab-state" data-kind="loading" role="status">{STATE.filling(store.records, store.total)}</p>
          : lab ? <Guard key={turn} name={`${id}?${params}`}><lab.Component params={params} /></Guard>
          : broken && isStaleBuild(broken.problem) ? (
            <p className="lab-state lab-notice" data-kind="empty" role="alert">{STATE.stale}
              <button type="button" className="ua-btn" data-kind="primary" onClick={() => window.location.reload()}><RotateCw size={14} />{STATE.reloadPage}</button></p>)
          : broken ? <p className="lab-state" data-kind="error" role="alert">{TEXT.failedPage}: {broken.problem}. {TEXT.failedHint}</p>
            : <p className="lab-state" data-kind="empty">{TEXT.unknown(id)}</p>}
      </div>
    );
  }
  return (
    <div className="lab-page">
      {head(<><FlaskConical size={18} /><h1>{TEXT.title}</h1><p>{TEXT.intro}</p></>)}
      {found.labs.length === 0 && failedPages.length === 0 && <p className="lab-state" data-kind="empty">{TEXT.none}</p>}
      {found.labs.length > 0 && !showExperimental && groupLabs(found.labs).length === 0 && <p className="lab-state" data-kind="empty">{TEXT.onlyExperimental}</p>}
      {groupLabs(found.labs, showExperimental).map((g) => (
        <section key={g.id} className="lab-group" data-group={g.id} aria-labelledby={`lab-group-${g.id}`}>
          <h2 id={`lab-group-${g.id}`}>{g.title}</h2>
          {g.note && <p className="lab-group-note">{g.note}</p>}
          {g.id === "experimental" && <p className="lab-group-hint">{TEXT.experimentalHint}</p>}
          <div className="lab-cards">
            {g.labs.map((l) => (
              <a key={l.id} className="ua-panel lab-card" href={labHref(l.id)} data-lab={l.id} data-hero={g.id === "start" || undefined}>
                <i><l.icon size={g.id === "start" ? 26 : 20} /></i>
                <b>{l.title}</b>
                <span>{l.blurb}</span>
                <em>{g.id === "start" && TEXT.startHere}<ArrowRight size={15} /></em>
              </a>
            ))}
          </div>
          {/* the visitor's first move, and where it leads: the strip's own questions, in its own order */}
          {g.id === "start" && pathFor(found.labs, "", null).length > 1 && (
            <p className="lab-path-preview"><span>{TEXT.thenPath}</span>
              {pathFor(found.labs, "", null).map((c, i) => <b key={c.lab}>{i > 0 && <ArrowRight size={12} aria-hidden="true" />}{c.label}</b>)}</p>
          )}
        </section>
      ))}
      {countExperimental(found.labs) > 0 && (
        <button type="button" className="lab-toggle" aria-pressed={showExperimental}
          onClick={() => { const on = !showExperimental; writeShowExperimental(storage(), on); setShowExperimental(on); }}>
          {showExperimental ? <EyeOff size={14} /> : <Eye size={14} />}
          {showExperimental ? TEXT.hideExperimental : TEXT.showExperimental(countExperimental(found.labs))}
        </button>
      )}
      <div className="lab-cards">
        {failedPages.map((x) => (
          <div key={x.path} className="ua-panel lab-card" data-failed="true" data-lab={x.id ?? undefined}>
            <i><TriangleAlert size={20} /></i>
            <b>{TEXT.failed}{x.id ? `: ${x.id}` : ""}</b>
            <span>{isStaleBuild(x.problem) ? STATE.stale : `${x.problem}. ${TEXT.failedHint}`}</span>
          </div>
        ))}
        {failedBack.map((b) => (
          <div key={b.name} className="ua-panel lab-card" data-failed="true" data-lab={b.name}>
            <i><TriangleAlert size={20} /></i>
            <b>{TEXT.failed}: {b.name}</b>
            <span>{TEXT.failedBack}: {b.problem}. {TEXT.failedHint}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
