// Live: the heartbeat (arrival-based, never "all clear"), the VM run with plain progress steps, and
// alerts sliding in as they are raised. Words come from engine/dashboard/live_status.py and words.py.
import { useEffect, useRef, useState } from "react";
import { Check, CircleDot, Circle, Play, Radio, PauseCircle, Siren, XCircle } from "lucide-react";
import { api, type AlertRow, type Health, type RunSteps } from "../api";
import { useWords } from "../words";
import { Button, Card, LevelTag, cx } from "../ui";
import { T } from "../ui-text";
import { fmtTime } from "./TwoMachines";

function Heartbeat({ h }: { h: Health | null }) {
  const w = useWords();
  if (!h) return null;
  const tone = h.state === "alert" ? "border-alert bg-alert/12" : h.state === "quiet" ? "border-border-strong bg-raised" : "border-border bg-surface";
  const Icon = h.state === "alert" ? Siren : h.state === "quiet" ? PauseCircle : Radio;
  return (
    <div className={cx("rise flex items-center gap-5 rounded-[10px] border px-6 py-5 transition-colors duration-300", tone)} key={h.state}>
      <span className="relative flex h-11 w-11 flex-none items-center justify-center">
        {h.state === "watching" && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent/25" />}
        <Icon size={30} className={h.state === "alert" ? "text-alert" : h.state === "quiet" ? "text-fg-muted" : "text-accent"} />
      </span>
      <div className="min-w-0 flex-1">
        <div className={cx("text-[22px] font-semibold", h.state === "alert" ? "text-alert" : "text-fg")}>{h.text}</div>
        {h.watch_note && <div className="mt-0.5 text-[14px] text-fg-muted">{h.watch_note}</div>}
        {h.alert && (
          <div className="mt-1 flex flex-wrap items-center gap-3 text-[16px]">
            <LevelTag level={h.alert.level} label={w.alert_level} />
            <a href={`#story/${encodeURIComponent(h.alert.id)}`} className="font-semibold text-fg underline decoration-border-strong underline-offset-4 hover:decoration-accent">{h.alert.title}</a>
          </div>
        )}
      </div>
    </div>
  );
}

function Stepper({ s }: { s: RunSteps | null }) {
  if (!s || !s.scenario) return null;
  return (
    <ol className="space-y-2.5">
      {s.steps.map((st, i) => (
        <li key={i} className={cx("flex items-center gap-3 text-[15px]", st.state === "todo" ? "text-fg-subtle" : "text-fg")}>
          {st.state === "done" ? <Check size={18} className="text-fg-muted" /> :
            st.state === "failed" ? <XCircle size={18} className="text-fg" /> :
            st.state === "current" ? <CircleDot size={18} className="animate-pulse text-accent" /> : <Circle size={18} />}
          <span className={st.state === "current" || st.state === "failed" ? "font-semibold" : undefined}>{st.text}</span>
        </li>
      ))}
      {s.outcome && <li className="border-t border-border pt-3 text-[15px] font-semibold text-fg">{s.outcome}</li>}
    </ol>
  );
}

export default function Live() {
  const w = useWords();
  const [h, setH] = useState<Health | null>(null);
  const [steps, setSteps] = useState<RunSteps | null>(null);
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());
  const polledAt = useRef(Date.now());
  const known = useRef<Set<string>>(new Set());
  const [canRun, setCanRun] = useState(true);
  useEffect(() => { api.mode().then((m) => setCanRun(m.can_run)).catch(() => setCanRun(true)); }, []);

  useEffect(() => {
    let live = true;
    const tick = async () => {
      try {
        const [hh, ss, aa] = await Promise.all([api.health(), api.runSteps(), api.alerts()]);
        if (!live) return;
        setH(hh); setSteps(ss); setAlerts(aa); setErr(null); polledAt.current = Date.now();
      } catch (e) { if (live) setErr(String(e)); }
    };
    tick();
    const t = window.setInterval(tick, 2000);
    const c = window.setInterval(() => setNow(Date.now()), 1000);
    return () => { live = false; window.clearInterval(t); window.clearInterval(c); };
  }, []);

  const run = async (what: "s1" | "three") => {
    try { await (what === "three" ? api.runThree() : api.runScenario("s1")); } catch (e) { setErr(String(e)); }
  };
  const running = !!steps?.running;
  // the list shows what the live view watches (debate 12 option (c)); start-up alerts get the quiet line
  const shown = h?.view_ids ? alerts.filter((a) => h.view_ids.includes(a.id)) : alerts;
  // elapsed from the server's own start time (survives a reload), ticking locally between polls
  const elapsed = steps?.started ? Math.max(0, steps.now - steps.started + (now - polledAt.current) / 1000) : null;
  const fresh = (id: string) => { const isNew = !known.current.has(id); known.current.add(id); return isNew; };

  return (
    <div className="space-y-4">
      <Heartbeat h={h} />
      {err && <p className="text-[13px] text-alert">{T.errorPrefix} {err}</p>}
      <div className="grid gap-4 xl:grid-cols-[440px_1fr]">
        <Card title={T.runTitle}>
          {canRun && (
            <div className="mb-4 flex flex-wrap gap-2">
              <Button variant="primary" icon={<Play size={14} />} onClick={() => run("three")} disabled={running}>{w.run_three}</Button>
              <Button icon={<Play size={14} />} onClick={() => run("s1")} disabled={running}>{w.run_one}</Button>
            </div>
          )}
          {steps?.scenario ? <Stepper s={steps} /> : <p className="text-[14px] leading-relaxed text-fg-muted">{w.run_three_hint}</p>}
          {running && elapsed !== null && <p className="num mt-4 text-[15px] text-fg-muted">{T.elapsed} {Math.floor(elapsed / 60)}:{String(Math.floor(elapsed % 60)).padStart(2, "0")}</p>}
        </Card>
        <Card title={w.raised_title} pad={false}>
          {shown.length === 0 ? <p className="p-5 text-[14px] text-fg-muted">{w.no_alerts}</p> : (
            <ul className="divide-y divide-border">
              {shown.map((a) => (
                <li key={a.id} className={cx(fresh(a.id) && "rise")}>
                  <a href={`#story/${encodeURIComponent(a.id)}`} className="flex items-start gap-4 px-5 py-4 transition-colors hover:bg-raised">
                    <LevelTag level={a.level} />
                    <div className="min-w-0 flex-1">
                      <div className="text-[16px] font-semibold">{a.title}</div>
                      <div className="mt-1 text-[14px] leading-relaxed text-fg-muted">{a.reason}</div>
                    </div>
                    <span className="num flex-none text-[12px] text-fg-subtle">{a.host}<br />{fmtTime(a.time)}</span>
                  </a>
                </li>
              ))}
            </ul>
          )}
          {h?.before_test && (
            <a href={`#story/${encodeURIComponent(h.before_test.id)}`}
              className="block border-t border-border px-5 py-3 text-[14px] text-fg-muted underline decoration-border-strong underline-offset-4 hover:text-fg">
              {h.before_test.text}</a>
          )}
        </Card>
      </div>
    </div>
  );
}
