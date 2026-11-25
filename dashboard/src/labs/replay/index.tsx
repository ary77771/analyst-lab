// Lab: an alert's story played in RECORDED time. The Story screen tells the steps at an even pace; here the
// clock is the recording's own: a slider over the seconds from the first step to the last, a speed, and the
// same map drawing each link at the moment it was recorded. It shows only what the Story shows: the same
// rows, in Python's order, in the same inks. Nothing is added, dropped or reordered (see time.ts).
// No back end of its own: it reads the alert's story the way the Story screen does.
import { useEffect, useMemo, useRef, useState } from "react";
import { Clapperboard, Pause, Play, RotateCcw } from "lucide-react";
import Film from "../../ui2/Film";
import { InkLine } from "../../ui2/bits";
import { useLive, useStory } from "../../ui2/hooks";
import { filmRows, filmView, utcDate, utcTime } from "../../ui2/logic";
import { LabState } from "../kit";
import { labHref, type Lab, type LabProps } from "../registry";
import { advance, rowTimes, seconds, shownAt, span } from "./time";
import "./replay.css";

const TEXT = {
  pick: "Alert",
  none: "There is no alert in this store to replay.",
  play: "Play", pause: "Pause", again: "From the start",
  speed: "Speed", skip: "Skip waits over 3 s",
  skipTitle: "When nothing was recorded for more than 3 seconds, jump to one second before the next record.",
  time: "recorded time, counted from the alert's first step",
  skipped: (s: string) => `skipped ${s} in which nothing was recorded`,
  before: "Nothing yet: the first record of this story is about to arrive.",
  slider: "Recorded time",
  cut: "This is the part of the story the Story screen's film tells; the full report is on the Story screen.",
  open: "Open on the Story screen",
};
const SPEEDS = [1, 4, 16];

function ReplayLab({ params }: LabProps) {
  const live = useLive();
  const w = live.words;
  const asked = params.get("alert");
  const id = (asked && live.alerts.some((a) => a.id === asked) ? asked : live.alerts[0]?.id) ?? null;     // the newest by default
  const { inv, rows: all, error } = useStory(id, live.devOk);
  const rows = useMemo(() => (inv ? filmRows(inv, all) : all), [inv, all]);
  const mapInv = useMemo(() => (inv ? filmView(inv) : null), [inv]);
  const times = useMemo(() => rowTimes(rows, new Map((inv?.report.timeline ?? []).map((x) => [x.id, x.t_offset_s]))), [rows, inv]);
  const { from, to } = useMemo(() => span(times), [times]);
  const [t, setT] = useState(from);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [skip, setSkip] = useState(false);
  const [skipped, setSkipped] = useState(0);
  const tRef = useRef(t);
  tRef.current = t;

  // a new story: back to its start, and play. A short story plays at its true pace; one longer than a minute
  // starts with its long waits skipped (the box can be unticked, and the foot says how much was skipped).
  useEffect(() => { setT(from); setSkipped(0); setSkip(to - from > 60); setPlaying(rows.length > 0); }, [inv?.alert.id, from, to, rows.length]);

  useEffect(() => {
    if (!playing) return;
    let raf = 0, last = performance.now();
    const tick = (now: number) => {
      const dt = Math.min(0.25, (now - last) / 1000);
      last = now;
      const a = advance(times, tRef.current, dt, speed, to, skip);
      if (a.skipped > 0) setSkipped((s) => s + a.skipped);
      setT(a.t);
      if (a.t >= to) setPlaying(false); else raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [playing, speed, skip, times, to]);

  const shown = shownAt(times, t);
  const cur = shown > 0 ? rows[shown - 1] : null;
  const done = t >= to && rows.length > 0;
  const jump = (x: number) => { setPlaying(false); setSkipped(0); setT(Math.max(from, Math.min(to, x))); };
  const restart = () => { setT(from); setSkipped(0); setPlaying(true); };
  const pct = (x: number) => (to > from ? ((x - from) / (to - from)) * 100 : 0);

  if (live.alerts.length === 0) return <LabState empty={live.health ? TEXT.none : null} loading={!live.health} />;
  return (
    <div className="rp">
      <div className="rp-pick">
        <label htmlFor="rp-alert">{TEXT.pick}</label>
        <select id="rp-alert" value={id ?? ""} onChange={(e) => { window.location.hash = labHref("replay", { alert: e.target.value }); }}>
          {live.alerts.map((a) => <option key={a.id} value={a.id}>{`${a.level} · ${a.title} · ${utcDate(a.time)} ${utcTime(a.time)}`}</option>)}
        </select>
        {id && <a className="ua-btn" href={`#a/story/${encodeURIComponent(id)}`}>{TEXT.open}</a>}
      </div>
      <LabState error={error && !inv ? error : null} loading={!inv && !error}>
        {inv && (
          <>
            <section className="ua-panel ua-film rp-film"><Film inv={mapInv ?? inv} rows={rows} shown={shown} onPick={(n) => jump(times[n - 1] ?? from)} /></section>
            {inv.film?.note && <p className="ua-hint">{inv.film.note} {TEXT.cut}</p>}
            <div className="rp-now" data-ink={cur?.ink}>
              {cur ? (
                <>
                  <span className="rp-ink"><InkLine ink={cur.ink} width={40} weight={3.5} /><b>{w.inks[cur.ink].word}</b></span>
                  <p>{cur.n ? <em>{cur.n}</em> : null}{cur.short}</p>
                </>
              ) : <p className="rp-idle">{TEXT.before}</p>}
              <div className="rp-clock" title={TEXT.time}><b>{seconds(t)}</b><span>{TEXT.time}</span></div>
            </div>
            <div className="rp-bar">
              <button className="rp-play" onClick={() => (done ? restart() : setPlaying((p) => !p))} aria-label={done ? TEXT.again : playing ? TEXT.pause : TEXT.play} title={done ? TEXT.again : playing ? TEXT.pause : TEXT.play}>
                {done ? <RotateCcw size={18} /> : playing ? <Pause size={18} /> : <Play size={18} />}
              </button>
              <div className="rp-track">
                <div className="rp-fill" style={{ width: `${pct(t)}%` }} />
                {rows.map((r, i) => (
                  <button key={r.id} className="rp-tick" data-ink={r.ink} data-told={i < shown} style={{ left: `${pct(times[i])}%` }}
                    onClick={() => jump(times[i])} title={`${seconds(times[i])} · ${r.short}`} aria-label={`${seconds(times[i])}: ${r.short}`} />
                ))}
                <input type="range" min={from} max={to} step={0.05} value={t} onChange={(e) => jump(Number(e.target.value))} aria-label={TEXT.slider} />
              </div>
              <div className="rp-speed" role="group" aria-label={TEXT.speed}>
                <span>{TEXT.speed}</span>
                {SPEEDS.map((s) => <button key={s} data-on={speed === s} onClick={() => setSpeed(s)}>{s}×</button>)}
              </div>
              <label className="rp-skip" title={TEXT.skipTitle}><input type="checkbox" checked={skip} onChange={(e) => setSkip(e.target.checked)} />{TEXT.skip}</label>
            </div>
            <p className="ua-hint rp-foot">
              <span>{seconds(from)} to {seconds(to)}</span>
              {skipped > 0.05 && <span>{TEXT.skipped(seconds(skipped))}</span>}
            </p>
          </>
        )}
      </LabState>
    </div>
  );
}

export const lab: Lab = {
  id: "replay",
  title: "Replay in recorded time",
  blurb: "Play an alert's story at the pace it was recorded: a time slider, a speed, and the map drawing each link at its own moment.",
  icon: Clapperboard,
  Component: ReplayLab,
};
