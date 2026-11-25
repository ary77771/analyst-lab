// Design A, "Console": a top bar that never leaves, panels with thin borders, and the story as a map
// that draws itself, with its full report below it. Nothing ever covers the screen: an alert lands
// as a card in its place.
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ArrowDown, ArrowRight, Check, ChevronLeft, ChevronRight, ExternalLink, Pause, Play, Power, RotateCcw, SkipBack, SkipForward } from "lucide-react";
import "@fontsource/jetbrains-mono/latin-500.css";
import type { Ink } from "../api";
import { InkLine, INKS, Mark, Roll, UI } from "./bits";
import ChecksStrip from "./ChecksStrip";
import Film from "./Film";
import { useAlertLabels, useFilm, useKeys, useLive, usePeer, usePreview, useStory, useWarm } from "./hooks";
import { clock, filmCut, filmRows, filmView, href, noAlertsText, previewPhase, storyAlert, tally, utcDate, utcTime, type Route } from "./logic";
import Proof from "./Proof";
import Report from "./Report";
import Tour from "./Tour";
import LabsScreen from "../labs/LabsScreen";
import { useLabsBackend } from "../labs/registry";
import "./a.css";

function Shell({ route, children }: { route: Route; children: ReactNode }) {
  const live = useLive();
  const w = live.words, h = live.health;
  const peer = usePeer(live.mode);
  // the Labs entry is there only when this dashboard's server says Labs are on (off: --no-labs, or an older server)
  const labsOn = useLabsBackend()?.enabled === true;
  // the red dot on the Watch tab: alerts that landed while the viewer was on another screen, until Watch is opened
  const [seen, setSeen] = useState<Set<string>>(new Set());
  const landedIds = [...live.landed.keys()];
  const unseen = landedIds.filter((id) => !seen.has(id)).length;
  useEffect(() => {
    if (route.screen === "watch" && unseen > 0) setSeen(new Set(landedIds));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [route.screen, unseen]);
  return (
    <div className="ua">
      <header className="ua-top">
        <a className="ua-brand" href={href("a", "watch")}><Mark size={22} /><span>{UI.app}</span></a>
        <nav className="ua-nav">
          {(["watch", "story", "proof", "labs"] as const).filter((s) => s !== "labs" || labsOn).map((s) => (
            <a key={s} href={href("a", s)} data-on={route.screen === s}>
              {UI.nav[s]}{s === "watch" && unseen > 0 && route.screen !== "watch" ? <i className="ua-dot" /> : null}
            </a>
          ))}
        </nav>
        <div className="ua-right">
          <Tour route={route} />
          {h && (
            <span className="ua-status" data-state={h.state} key={h.state}>
              <i /><span>{h.state === "alert" && h.alert ? `${h.text} · ${w.alert_level.toLowerCase()} ${h.alert.level}` : h.text}</span>
            </span>
          )}
          {live.mode?.badge && <span className="ua-mode" data-mode={live.mode.mode}><b>{live.mode.badge}</b>{live.mode.detail ? <em>{live.mode.detail}</em> : null}</span>}
        </div>
      </header>
      {/* on the replay dashboard only: what the LIVE test machine is doing, one click away; red when it raised an alert */}
      {peer.live && (
        <a className="ua-livebar" data-state={peer.live.state} href={peer.live.alertTitle ? peer.live.storyUrl("a") : peer.live.watchUrl("a")}>
          <i /><b>{peer.live.alertTitle ? w.live_notice : w.live_label}</b><span>{peer.live.alertTitle ?? peer.live.text}</span>
          <em>{UI.switchLive}<ArrowRight size={15} /></em>
        </a>
      )}
      <main className="ua-main" data-screen={route.screen}>{children}</main>
    </div>
  );
}

// ---------------------------------------------------------------- Watch

function RunPanel() {
  const { words: w, mode, steps, elapsed, run, runPending, runError } = useLive();
  const peer = usePeer(mode);
  const warm = useWarm();
  const wm = warm.w?.enabled ? warm.w : null;                       // the warm test machine, where this dashboard has one
  const ww = warm.w?.words;
  // a dashboard with no demo mode (a plain development server) never offers the run buttons
  const running = !!steps?.running, canRun = !!mode?.mode && mode.can_run;
  const ended = !!steps?.outcome && steps.steps.every((s) => s.state === "done");
  const warmBusy = !!wm && wm.state !== "off" && wm.state !== "failed" && wm.state !== "ended";
  return (
    <section className="ua-panel ua-run">
      <h2 className="ua-run-head">{UI.machine}{wm && ww && <span className="ua-tag" title={ww.practice}>{ww.practice_tag}</span>}</h2>

      {/* the warm test machine: started once, then one click per test (practice runs) */}
      {wm && ww && (
        <div className="ua-warm" data-state={wm.state}>
          <p className="ua-warm-state"><i />{wm.text}</p>
          {wm.state === "starting" && wm.boot_list && (
            <>
              <div className="ua-clock" title={UI.tips.startElapsed}><b>{clock(wm.starting_seconds ?? 0)}</b><span>{UI.elapsed}</span></div>
              <ol className="ua-steps">
                {wm.boot_list.map((s, i) => (
                  <li key={i} data-state={s.state}><i>{s.state === "done" ? <Check size={13} strokeWidth={3} /> : null}</i><span>{s.text}</span></li>
                ))}
              </ol>
            </>
          )}
          {wm.foreign_text && <p className="ua-warm-warning">{wm.foreign_text}</p>}
          {wm.hint && <p className="ua-warm-sub">{wm.hint}</p>}
          {wm.ready_text && <p className="ua-warm-until">{wm.ready_text}</p>}
          {wm.warning && <p className="ua-warm-warning">{wm.warning}</p>}
          {wm.state === "off" && wm.ended_text && <p className="ua-warm-sub">{wm.ended_text}</p>}
          {wm.error && <p className="ua-run-error">{wm.error}</p>}
          {warm.error && <p className="ua-run-error">{warm.error}</p>}
          {wm.can_start && (
            <>
              <button className="ua-btn" data-kind="primary" disabled={warm.pending || running} onClick={() => warm.act("start")}><Power size={15} />{ww.start}</button>
              <p className="ua-hint">{ww.start_hint} {ww.practice}</p>
            </>
          )}
          {(wm.state === "ready" || wm.state === "running") && (
            <div className="ua-warm-tests">
              {(wm.tests ?? []).map((t) => (
                <button key={t.id} className="ua-btn" data-kind={t.can_run ? "primary" : undefined} disabled={!t.can_run || warm.pending}
                  title={t.used ? ww.used : undefined} onClick={() => warm.act(`run/${t.id}`)}>
                  {t.used ? <Check size={14} strokeWidth={3} /> : <Play size={14} />}{t.label}
                </button>
              ))}
            </div>
          )}
          {wm.can_stop && <button className="ua-btn" disabled={warm.pending} onClick={() => warm.act("stop")}><Power size={14} />{ww.stop}</button>}
        </div>
      )}

      {steps && (steps.scenario || !wm) ? (
        <>
          <div className="ua-clock" data-idle={!steps.scenario} title={UI.tips.elapsed}><b>{elapsed !== null ? clock(elapsed) : "00:00"}</b><span>{UI.elapsed}</span></div>
          <ol className="ua-steps">
            {steps.steps.map((s, i) => (
              <li key={i} data-state={s.state}><i>{s.state === "done" ? <Check size={13} strokeWidth={3} /> : null}</i><span>{s.text}</span></li>
            ))}
            {steps.outcome && <li className="ua-outcome" data-state={ended ? "done" : "failed"}><i>{ended ? <Check size={13} strokeWidth={3} /> : null}</i><span>{steps.outcome}</span></li>}
          </ol>
          {!steps.scenario && canRun && <p className="ua-hint">{w.run_three_hint}</p>}
        </>
      ) : null}

      <div className="ua-run-foot">
        {peer.replayUrl && <a className="ua-offer" href={peer.replayUrl("a")}><span>{w.replay_offer}</span><ArrowRight size={15} /></a>}
        {runError && <p className="ua-run-error">{runError}</p>}
        {canRun && !running && !warmBusy && (
          <div className="ua-run-buttons">
            {wm && ww && <p className="ua-hint">{ww.one_boot}</p>}
            <button className="ua-btn" data-kind={wm ? undefined : "primary"} disabled={runPending} onClick={() => run("three")}><Play size={15} />{w.run_three}</button>
            <button className="ua-btn" disabled={runPending} onClick={() => run("one")}><Play size={15} />{w.run_one}</button>
          </div>
        )}
      </div>
    </section>
  );
}

function Arrivals() {
  const { arrivals } = useLive();
  const max = Math.max(4, ...arrivals);
  const N = 90, bars = [...Array(Math.max(0, N - arrivals.length)).fill(0), ...arrivals];
  return (
    <svg className="ua-arrivals" viewBox={`0 0 ${N * 8} 64`} preserveAspectRatio="none" role="img" aria-label={UI.tips.arrivals}>
      <title>{UI.tips.arrivals}</title>
      <line x1="0" y1="63" x2={N * 8} y2="63" className="ua-arrivals-base" />
      {bars.map((v, i) => <rect key={i} x={i * 8 + 1.5} width={5} rx={1.5} y={62 - (v ? 6 + (v / max) * 54 : 0)} height={v ? 6 + (v / max) * 54 : 0} data-new={i === N - 1 && v > 0} />)}
    </svg>
  );
}

function Signal() {
  const { health: h, arrivals } = useLive();
  if (!h) return <section className="ua-panel ua-signal" />;
  return (
    <section className="ua-panel ua-signal" data-state={h.state}>
      <div className="ua-signal-text">
        <span className="ua-beacon" data-state={h.state}><i /><i /></span>
        <div><h1 key={h.state}>{h.text}</h1>{h.watch_note && <p>{h.watch_note}</p>}</div>
      </div>
      <div className="ua-count" title={UI.tips.records}><b><Roll value={h.records} ms={700} /></b><span>{h.records_text.replace(/^[\d,.\s]+/, "")}</span></div>
      {arrivals.some((x) => x > 0) && <Arrivals />}
    </section>
  );
}

function Preview({ id }: { id: string }) {
  const { words: w, steps, health } = useLive();
  // asked when the alert lands, when the run has ended, and when the store has gone quiet (a replay has no
  // run, and its last records come after the alert), so the counts end up equal to the Story's: logic.ts previewPhase
  const phase = useRef("settled");
  phase.current = previewPhase(phase.current, !!steps?.running, health?.records, health?.seconds);
  const inv = usePreview(id, phase.current);
  const v = inv?.report.verdict, c = inv?.report.counts;
  if (!v || !c) return null;
  const totals: Record<Ink, number> = { fact: c.facts, hypothesis: c.hypotheses, gap: c.gaps };
  const shown = v.steps.slice(0, 4);
  return (
    <div className="ua-preview">
      <div>
        {/* an alert raised on something a command line DECLARED (not a recorded action) says so, in Python's sentence */}
        {inv?.report.declared_banner && <p className="ua-declared">{inv.report.declared_banner.text}</p>}
        <ol>{shown.map((s) => <li key={s.id}><em title={UI.tips.stepNo}>{s.n}</em><span>{s.text}</span><small title={UI.tips.offset}>{s.offset_text}</small></li>)}</ol>
        {/* when the alert has more numbered steps than fit here, Python's own sentence says how many there are */}
        {(v.steps.length > shown.length || v.steps_more > 0) && <p>{v.proven.text}</p>}
      </div>
      <div className="ua-preview-tally">
        {INKS.map((ink) => <span key={ink} data-ink={ink} title={`${UI.tips.total} ${w.inks[ink].word}: ${w.inks[ink].explain}`}><b>{totals[ink]}</b><InkLine ink={ink} width={22} weight={2.5} />{w.inks[ink].word}</span>)}
      </div>
    </div>
  );
}

function AlertList() {
  const { words: w, health: h, alerts, landed } = useLive();
  const shown = h?.view_ids ? alerts.filter((a) => h.view_ids.includes(a.id)) : alerts;
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const t = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(t); }, []);
  // "No alerts have been raised" is said only when that is known and true: the feed has answered, and the
  // store holds none at all (alerts from an earlier run or from start-up are not "none")
  const none = !!h && alerts.length === 0 && !h.before_test && !h.after_test && !h.other_alerts;
  return (
    <section className="ua-panel ua-alerts">
      <h2>{w.raised_title}{shown.length > 0 && <em title={UI.tips.alertsInView}>{shown.length}</em>}</h2>
      {shown.length === 0 ? (none ? <p className="ua-empty">{noAlertsText(h, w.no_alerts)}</p> : <div className="ua-alerts-none" />) : (
        <ul>
          {shown.map((a, i) => {
            const at = landed.get(a.id);
            return (
              <li key={a.id} className="ua-alert" data-new={at !== undefined} data-pulse={at !== undefined && now - at < 9000}>
                <span className="ua-level" data-level={a.level}>{w.alert_level}: {a.level}</span>
                <div><h3>{a.title}</h3><p>{a.host} · {utcDate(a.time)} · {utcTime(a.time)}</p></div>
                <a className="ua-btn" data-kind="primary" href={href("a", "story", a.id)}>{UI.open}<ArrowRight size={15} /></a>
                {i === 0 && <Preview id={a.id} />}
              </li>
            );
          })}
        </ul>
      )}
      {h?.before_test && <a className="ua-before" href={href("a", "story", h.before_test.id)}>{h.before_test.text}</a>}
      {h?.after_test && <a className="ua-before" href={href("a", "story", h.after_test.id)}>{h.after_test.text}</a>}
      {h?.other_alerts && <a className="ua-before" href={href("a", "story", h.other_alerts.id)}>{h.other_alerts.text}</a>}
    </section>
  );
}

function Watch() {
  const { error } = useLive();
  return (
    <>
      <RunPanel />
      <div className="ua-watch-right">
        <Signal />
        <AlertList />
        <ChecksStrip />
        {error && <p className="ua-error">{UI.error} {error}</p>}
      </div>
    </>
  );
}

// ---------------------------------------------------------------- Story

/** Which alert's story is showing, and the way to the others (oldest = 1). A few alerts: one numbered
 *  button each. Many (a store can hold dozens: 93 in one lab run): "12 of 93" with a step either way,
 *  so the header never grows wider than the screen. */
function AlertPick({ id }: { id: string }) {
  const { alerts, words: w, steps } = useLive();
  // whose alert each one is ("S1", "other"): Python's labels for a warm session; without them, plain numbers
  const labels = useAlertLabels(`${alerts.map((a) => a.id).join("|")}|${steps?.running ? 1 : 0}`);
  if (alerts.length < 2) return null;
  const list = [...alerts].reverse(), at = list.findIndex((a) => a.id === id);
  const tip = (a: { id: string; title: string }) => (labels[a.id] ? `${a.title} · ${labels[a.id].title}` : a.title);
  if (list.length <= PICK_BUTTONS) {
    return (
      <div className="ua-pick" title={w.story_pick}>
        {list.map((a, i) => (
          <a key={a.id} href={href("a", "story", a.id)} data-on={a.id === id} data-kind={labels[a.id]?.kind} title={tip(a)}>
            {i + 1}{labels[a.id] && <small>{labels[a.id].label}</small>}
          </a>
        ))}
      </div>
    );
  }
  const step = (to: number, icon: ReactNode) => (to >= 0 && to < list.length
    ? <a href={href("a", "story", list[to].id)} title={list[to].title}>{icon}</a> : <a aria-disabled="true">{icon}</a>);
  return (
    <div className="ua-pick" data-many="true" title={w.story_pick}>
      {step(at - 1, <ChevronLeft size={15} />)}
      <span title={at >= 0 ? tip(list[at]) : undefined}><b>{at + 1}</b> {UI.of} {list.length}{at >= 0 && labels[list[at].id] && <small>{labels[list[at].id].label}</small>}</span>
      {step(at + 1, <ChevronRight size={15} />)}
    </div>
  );
}
const PICK_BUTTONS = 8;

function Story({ param }: { param: string | null }) {
  const live = useLive();
  const w = live.words;
  const ids = live.alerts.map((a) => a.id).reverse();              // oldest first
  const showing = useRef<string | null>(null);
  const id = storyAlert(param, showing.current, ids);
  showing.current = id;
  const { inv, rows: all, error, reload } = useStory(id, live.devOk);
  // The film tells the rows Python chose (the alert's own chain when the story is long); the report
  // below keeps every row. Which rows: engine/dashboard/film.py, never decided here.
  const rows = useMemo(() => (inv ? filmRows(inv, all) : all), [inv, all]);
  const mapInv = useMemo(() => (inv ? filmView(inv) : null), [inv]);
  // long stories are told faster (a 99-step story in about a minute); the caption still shows each step's recorded time
  const stepMs = rows.length > 20 ? Math.max(650, Math.round(44000 / rows.length)) : 2200;
  const film = useFilm(rows.length, stepMs, id);
  const query = new URLSearchParams(window.location.search);
  const at = query.get("at");                                        // ?at=5 or ?at=end: open on that step, paused
  const started = useRef<string | null>(null);
  const report = useRef<HTMLDivElement>(null);
  const { go, restart } = film;
  // play again = ask Python again (records that arrived since may have added steps), then tell it from the start
  const play = () => { if (film.done) void reload().then(restart); else film.toggle(); };
  const toReport = (smooth = true) => report.current?.scrollIntoView({ behavior: smooth ? "smooth" : "auto", block: "start" });
  useEffect(() => {
    if (!inv || !rows.length || started.current === inv.alert.id) return;
    started.current = inv.alert.id;
    const n = at === "end" ? rows.length : at === null ? NaN : Number(at);
    if (Number.isFinite(n)) go(n); else restart();
    if (query.get("view") === "report") window.setTimeout(() => toReport(false), 50);     // screenshots
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inv, rows.length, at, go, restart]);
  useKeys({ Space: play, ArrowRight: () => go(film.shown + 1), ArrowLeft: () => go(film.shown - 1), Home: () => go(0), End: () => go(rows.length) });

  if (error && !inv) return <p className="ua-error ua-story-empty">{UI.error} {error}</p>;
  if (live.error && !live.health) return <p className="ua-error ua-story-empty">{UI.error} {live.error}</p>;
  if (!live.health) return <p className="ua-empty ua-story-empty">{UI.loading}</p>;
  if (!id) return <p className="ua-empty ua-story-empty">{noAlertsText(live.health, w.no_alerts)}</p>;
  if (!inv || !inv.report.verdict || !inv.report.counts) return <p className="ua-empty ua-story-empty">{UI.loading}</p>;
  const v = inv.report.verdict, c = inv.report.counts;
  const cur = film.shown > 0 ? rows[film.shown - 1] : null;
  const told = tally(rows, film.shown);
  const cut = filmCut(inv);
  // two sets of numbers, never mixed: the whole story's (the ending) and, when the film is a cut, the film's (the running tally)
  const totals: Record<Ink, number> = { fact: c.facts, hypothesis: c.hypotheses, gap: c.gaps };
  const filmTotals: Record<Ink, number> = cut ? cut.counts : totals;
  const second = cur ? (cur.chance ?? (cur.citations.length ? `${w.evidence_title}: ${cur.citations.map((x) => x.text).join(" · ")}` : null)) : null;

  return (
    <>
      {/* the first screen: the film. The report is below it, reached by scrolling. */}
      <div className="ua-filmpage" style={{ ["--draw" as string]: `${Math.min(850, Math.round(stepMs * 0.8))}ms` }}>
        <section className="ua-panel ua-story-head">
          <span className="ua-level" data-level={v.level}>{v.level_text}</span>
          <h1>{v.title}</h1>
          <span className="ua-meta">{v.host} · {utcDate(v.time)} · {utcTime(v.time)}</span>
          <AlertPick id={id} />
          <button className="ua-btn" onClick={() => toReport()}>{UI.report}<ArrowDown size={14} /></button>
        </section>

        {inv.report.declared_banner && <p className="ua-declared">{inv.report.declared_banner.text}</p>}

        <section className="ua-panel ua-film"><Film inv={mapInv ?? inv} rows={rows} shown={film.shown} onPick={go} /></section>
        {/* Python's line about the film: what a cut film shows, or that there is no story to tell. Never hidden. */}
        {inv.film?.note && (
          <p className="ua-film-note" data-empty={rows.length === 0}><span>{inv.film.note}</span><button onClick={() => toReport()}>{UI.report}<ArrowDown size={13} /></button></p>
        )}

        <section className="ua-caption">
          {film.done ? (
            <div className="ua-verdict" key="verdict" data-cut={!!cut}>
              {cut && <span className="ua-verdict-set">{cut.labels.story}</span>}
              {([["fact", v.proven.text], ["hypothesis", v.not_proven?.text], ["gap", v.cant_see?.text]] as [Ink, string | undefined][]).map(([ink, text], i) => (
                <div key={ink} data-ink={ink} data-none={!text} style={{ animationDelay: `${i * 120}ms` }} title={`${UI.tips.total} ${w.inks[ink].word}: ${w.inks[ink].explain}`}>
                  <b>{totals[ink]}</b>
                  <div><span className="ua-inkword"><InkLine ink={ink} width={30} />{w.inks[ink].word}</span><p>{text ?? "—"}</p></div>
                </div>
              ))}
              <button className="ua-btn ua-toreport" onClick={() => toReport()}>{UI.readReport}<ArrowDown size={15} /></button>
            </div>
          ) : cur ? (
            <div className="ua-cap" key={cur.id} data-ink={cur.ink}>
              <div className="ua-cap-ink">
                <InkLine ink={cur.ink} width={54} weight={4} />
                <strong>{w.inks[cur.ink].word}</strong>
                <span>{cur.bandLabel ?? w.inks[cur.ink].explain}</span>
              </div>
              <div className="ua-cap-text">
                <p>{cur.n ? <em>{cur.n}</em> : null}<span>{cur.short}</span></p>
                {second && <small>{second}</small>}
              </div>
              <div className="ua-cap-time" title={UI.tips.offset}>{cur.offset ? <><b>{cur.offset}</b><span>{v.offset_from ? w.offset_note.replace("{ref}", v.offset_from) : ""}</span></> : null}</div>
            </div>
          ) : <p className="ua-cap-idle">{w.steps_title}</p>}
        </section>

        <footer className="ua-bar">
          <div className="ua-transport">
            <button onClick={() => go(0)} aria-label={UI.start} title={UI.start}><SkipBack size={16} /></button>
            <button className="ua-playbtn" onClick={play} aria-label={film.playing ? UI.pause : UI.play} title={UI.keys}>
              {film.done ? <RotateCcw size={18} /> : film.playing ? <Pause size={18} /> : <Play size={18} />}</button>
            <button onClick={() => go(film.shown + 1)} aria-label={UI.next} title={UI.next}><SkipForward size={16} /></button>
          </div>
          <ol className="ua-scrub" data-dense={rows.length > 8}>
            {rows.map((r, i) => (
              <li key={r.id} data-ink={r.ink} data-told={i < film.shown} data-now={i === film.shown - 1 && !film.done}>
                <button onClick={() => go(i + 1)} title={r.short}><i /><span>{r.offset ?? "?"}</span></button>
              </li>
            ))}
          </ol>
          <div className="ua-tally" data-cut={!!cut}>
            {cut && <em className="ua-tally-set">{cut.labels.film}</em>}
            {INKS.map((ink) => (
              <div key={ink} data-ink={ink} title={`${UI.tips.told} ${w.inks[ink].word}: ${w.inks[ink].explain}`}>
                <b>{told[ink]}<small> {UI.of} {filmTotals[ink]}</small></b>
                <span><InkLine ink={ink} width={22} weight={2.5} />{w.inks[ink].word}</span>
              </div>
            ))}
          </div>
        </footer>
      </div>

      <div className="ua-reportpage" ref={report}>
        <header>
          <h2>{UI.report}</h2>
          {error && <p className="ua-error">{UI.error} {error}</p>}
          <a className="ua-btn" href={`/api/alerts/${encodeURIComponent(id)}/report`} target="_blank" rel="noreferrer">{UI.fullReport}<ExternalLink size={14} /></a>
        </header>
        <Report inv={inv} rows={all} key={inv.alert.id} />
      </div>
    </>
  );
}

export default function A({ route }: { route: Route }) {
  return (
    <Shell route={route}>
      {route.screen === "labs" ? <LabsScreen param={route.param} />
        : route.screen === "story" ? <Story param={route.param} /> : route.screen === "proof" ? <Proof /> : <Watch />}
    </Shell>
  );
}
