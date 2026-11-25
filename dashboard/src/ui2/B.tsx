// Design B, "Casebook": a quiet sidebar and a reading column. The story is told one statement at a
// time, each stamped with its ink, while the chain of evidence grows beside it in the three line
// styles. Nothing ever covers the screen: an alert lands as a new entry under a red rule.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { ArrowLeft, ArrowRight, Pause, Play, RotateCcw, X } from "lucide-react";
import "@fontsource/newsreader/latin-500.css";
import "@fontsource/jetbrains-mono/latin-500.css";
import type { Ink } from "../api";
import { InkLine, INKS, Mark, Roll, UI } from "./bits";
import { useFilm, useKeys, useLive, usePeer, useStory } from "./hooks";
import { clock, href, noAlertsText, storyAlert, tally, utcDate, utcTime, type Route } from "./logic";
import Proof from "./Proof";
import "./b.css";

const pad = (n: number) => String(n).padStart(2, "0");

function Shell({ route, children }: { route: Route; children: ReactNode }) {
  const live = useLive();
  const h = live.health;
  const peer = usePeer(live.mode);
  const notice = peer.live?.alertTitle ? peer.live : null;
  const [hidden, setHidden] = useState(false);
  const fresh = live.landed.size;
  return (
    <div className="ub">
      <aside className="ub-side">
        <a className="ub-brand" href={href("b", "watch")}><Mark size={22} /><span>{UI.app}</span></a>
        <nav>
          {(["watch", "story", "proof"] as const).map((s, i) => (
            <a key={s} href={href("b", s)} data-on={route.screen === s}>
              <em>{pad(i + 1)}</em>{UI.nav[s]}{s === "watch" && fresh > 0 && route.screen !== "watch" ? <i className="ub-dot" /> : null}
            </a>
          ))}
        </nav>
        <div className="ub-side-foot">
          {h && <p className="ub-state" data-state={h.state} key={h.state}><i />{h.text}</p>}
          {peer.live && <a className="ub-livelink" data-state={peer.live.state} href={peer.live.watchUrl("b")}><b><i />{live.words.live_label}<ArrowRight size={13} /></b><span>{peer.live.text}</span></a>}
          {live.mode?.badge && <p className="ub-mode" data-mode={live.mode.mode}>{live.mode.badge}{live.mode.detail ? <span>{live.mode.detail}</span> : null}</p>}
        </div>
      </aside>
      <div className="ub-body">
        {notice && !hidden && (
          <div className="ub-notice">
            <i /><b>{live.words.live_notice}</b><span>{notice.alertTitle}</span>
            <a href={notice.storyUrl("b")}>{UI.switchLive}<ArrowRight size={15} /></a>
            <button onClick={() => setHidden(true)} aria-label={UI.dismiss}><X size={15} /></button>
          </div>
        )}
        <main className="ub-main" data-screen={route.screen}>{children}</main>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- Watch

function Watch() {
  const { words: w, mode, health: h, steps, alerts, landed, elapsed, run, error } = useLive();
  const peer = usePeer(mode);
  const running = !!steps?.running, canRun = !!mode?.mode && mode.can_run;
  const shown = h?.view_ids ? alerts.filter((a) => h.view_ids.includes(a.id)) : alerts;
  const reached = steps ? steps.steps.reduce((k, s, i) => (s.state === "done" || s.state === "current" || s.state === "failed" ? i : k), -1) : -1;
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const t = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(t); }, []);
  return (
    <div className="ub-watch">
      <header className="ub-lede" data-state={h?.state}>
        <small>{UI.machine}</small>
        <h1 key={h?.state}>{h?.text ?? UI.loading}</h1>
        <p>{h?.watch_note ? <span>{h.watch_note}</span> : null}{h ? <span className="ub-records"><b><Roll value={h.records} ms={700} /></b> {h.records_text.replace(/^[\d,.\s]+/, "")}</span> : null}</p>
      </header>

      {steps && (
        <section className="ub-run">
          <ol style={{ ["--reach" as string]: steps.steps.length > 1 ? Math.max(0, reached) / (steps.steps.length - 1) : 0 }}>
            {steps.steps.map((s, i) => <li key={i} data-state={s.state}><i /><span>{s.text}</span></li>)}
          </ol>
          <div className="ub-run-foot">
            <span className="ub-clock" data-idle={!steps.scenario}><b>{elapsed !== null ? clock(elapsed) : "00:00"}</b>{UI.elapsed.toLowerCase()}</span>
            {steps.outcome && <span className="ub-outcome">{steps.outcome}</span>}
            {peer.replayUrl && <a className="ub-offer" href={peer.replayUrl("b")}>{w.replay_offer}<ArrowRight size={15} /></a>}
            {canRun && !running && (
              <span className="ub-run-buttons">
                <button className="ub-btn" data-kind="primary" onClick={() => run("three")}><Play size={14} />{w.run_three}</button>
                <button className="ub-btn" onClick={() => run("one")}><Play size={14} />{w.run_one}</button>
              </span>
            )}
          </div>
        </section>
      )}

      <section className="ub-entries">
        <h2>{w.raised_title}</h2>
        {shown.length === 0 ? <p className="ub-empty">{noAlertsText(h, w.no_alerts)}</p> : (
          <ul>
            {shown.map((a) => {
              const at = landed.get(a.id);
              return (
                <li key={a.id} data-new={at !== undefined} data-pulse={at !== undefined && now - at < 9000}>
                  <a href={href("b", "story", a.id)}>
                    <i className="ub-rule" />
                    <small>{w.alert_level}: {a.level} · {a.host} · {utcDate(a.time)} · {utcTime(a.time)}</small>
                    <h3>{a.title}</h3>
                    <span className="ub-link">{UI.open}<ArrowRight size={15} /></span>
                  </a>
                </li>
              );
            })}
          </ul>
        )}
        {h?.before_test && <a className="ub-before" href={href("b", "story", h.before_test.id)}>{h.before_test.text}</a>}
        {error && <p className="ub-error">{UI.error} {error}</p>}
      </section>
    </div>
  );
}

// ---------------------------------------------------------------- Story

function Story({ param }: { param: string | null }) {
  const live = useLive();
  const w = live.words;
  const ids = live.alerts.map((a) => a.id).reverse();
  const showing = useRef<string | null>(null);
  const id = storyAlert(param, showing.current, ids);
  showing.current = id;
  const { inv, rows, error, reload } = useStory(id, live.devOk);
  // one extra beat: the closing ledger. Long stories are told faster; each statement still shows its recorded time
  const film = useFilm(rows.length + 1, rows.length > 20 ? Math.max(900, Math.round(70000 / rows.length)) : 3600, id);
  const at = new URLSearchParams(window.location.search).get("at");
  const started = useRef<string | null>(null);
  const chain = useRef<HTMLOListElement>(null);
  const { go, restart } = film;
  // play again = ask Python again (records that arrived since may have added steps), then tell it from the start
  const play = () => { if (film.done) void reload().then(restart); else film.toggle(); };
  useEffect(() => {
    if (!inv || !rows.length || started.current === inv.alert.id) return;
    started.current = inv.alert.id;
    if (at) go(at === "end" ? rows.length + 1 : Number(at)); else restart();
  }, [inv, rows.length, at, go, restart]);
  useEffect(() => { chain.current?.querySelector('[data-now="true"]')?.scrollIntoView({ block: "nearest", behavior: "smooth" }); }, [film.shown]);
  useKeys({ Space: play, ArrowRight: () => go(film.shown + 1), ArrowLeft: () => go(film.shown - 1), Home: () => go(1), End: () => go(rows.length + 1) });

  if (error) return <p className="ub-error">{UI.error} {error}</p>;
  if (!id) return <p className="ub-empty">{noAlertsText(live.health, w.no_alerts)}</p>;
  if (!inv || !inv.report.verdict || !inv.report.counts) return <p className="ub-empty">{UI.loading}</p>;
  const v = inv.report.verdict, c = inv.report.counts;
  const total = rows.length, ledger = film.shown > total;
  const cur = !ledger && film.shown > 0 ? rows[film.shown - 1] : null;
  const told = tally(rows, Math.min(film.shown, total));
  const totals: Record<Ink, number> = { fact: c.facts, hypothesis: c.hypotheses, gap: c.gaps };
  const second = cur ? (cur.chance ?? (cur.citations.length ? `${w.evidence_title}: ${cur.citations.map((x) => x.text).join(" · ")}` : null)) : null;

  return (
    <div className="ub-story">
      <header className="ub-case">
        <i className="ub-rule" />
        <div><small>{v.level_text} · {v.host} · {utcDate(v.time)} · {utcTime(v.time)}</small><h1>{v.title}</h1></div>
        {live.alerts.length > 1 && (
          <div className="ub-pick" title={w.story_pick}>
            {[...live.alerts].reverse().map((a, i) => <a key={a.id} href={href("b", "story", a.id)} data-on={a.id === id} title={a.title}>{i + 1}</a>)}
          </div>
        )}
      </header>

      <section className="ub-read">
        {ledger ? (
          <div className="ub-ledger" key="ledger">
            <h2>{w.summary_title}</h2>
            <div>
              {([["fact", v.proven.text], ["hypothesis", v.not_proven?.text], ["gap", v.cant_see?.text]] as [Ink, string | undefined][]).map(([ink, text], i) => (
                <article key={ink} data-ink={ink} data-none={!text} style={{ animationDelay: `${i * 220}ms` }}>
                  <b>{totals[ink]}</b>
                  <InkLine ink={ink} width={150} weight={4} />
                  <strong>{w.inks[ink].word}</strong>
                  <p>{text ?? "—"}</p>
                </article>
              ))}
            </div>
          </div>
        ) : cur ? (
          <div className="ub-say" key={cur.id} data-ink={cur.ink}>
            <span className="ub-count">{pad(film.shown)} <em>/ {pad(total)}</em></span>
            <div className="ub-stamp"><InkLine ink={cur.ink} width={40} weight={4} /><strong>{w.inks[cur.ink].word}</strong><span>{cur.bandLabel ?? w.inks[cur.ink].explain}</span></div>
            <p className="ub-sentence" data-long={cur.short.length > 70}>{cur.short}</p>
            {second && <p className="ub-second">{second}</p>}
            {cur.offset && <p className="ub-time"><b>{cur.offset}</b>{v.offset_from ? <span>{w.offset_note.replace("{ref}", v.offset_from)}</span> : null}</p>}
          </div>
        ) : <p className="ub-idle">{w.steps_title}</p>}
      </section>

      <aside className="ub-chain">
        <h2>{w.steps_title}</h2>
        <ol ref={chain}>
          {rows.slice(0, Math.min(film.shown, total)).map((r, i) => (
            <li key={r.id} data-ink={r.ink} data-now={i === film.shown - 1}>
              <button onClick={() => go(i + 1)}><i /><b />{r.n ? <em>{r.n}</em> : null}<span>{r.short}</span></button>
            </li>
          ))}
        </ol>
      </aside>

      <footer className="ub-foot">
        <div className="ub-transport">
          <button onClick={() => go(Math.max(1, film.shown - 1))} aria-label={UI.back} title={UI.back}><ArrowLeft size={17} /></button>
          <button className="ub-playbtn" onClick={play} aria-label={film.playing ? UI.pause : UI.play} title={UI.keys}>
            {film.done ? <RotateCcw size={17} /> : film.playing ? <Pause size={17} /> : <Play size={17} />}</button>
          <button onClick={() => go(film.shown + 1)} aria-label={UI.next} title={UI.next}><ArrowRight size={17} /></button>
        </div>
        <div className="ub-progress" data-dense={rows.length > 30}>{[...rows, null].map((r, i) => <button key={i} data-ink={r?.ink ?? "end"} data-told={i < film.shown} onClick={() => go(i + 1)} aria-label={r?.short ?? w.summary_title} />)}</div>
        <div className="ub-tally">
          {INKS.map((ink) => <span key={ink} data-ink={ink}><InkLine ink={ink} width={24} weight={3} /><b>{ledger ? totals[ink] : told[ink]}</b>{w.inks[ink].word}</span>)}
        </div>
      </footer>
    </div>
  );
}

export default function B({ route }: { route: Route }) {
  return (
    <Shell route={route}>
      {route.screen === "story" ? <Story param={route.param} /> : route.screen === "proof" ? <Proof /> : <Watch />}
    </Shell>
  );
}
