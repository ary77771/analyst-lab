// "How we know it works": the frozen-code test results, read by engine/dashboard/scoreboard.py from
// docs/results/v4/README.md. One big before -> after number per card (readable from the back of the
// room), the bars, the one sentence that keeps the number honest, and the rest behind "details".
import { useEffect, useState } from "react";
import { ArrowRight, ChevronDown, ChevronRight, Play } from "lucide-react";
import { api, type ChecksState, type Scoreboard as SB } from "../api";
import { Button, Card, Eyebrow, cx } from "../ui";
import { T } from "../ui-text";

type Group = SB["groups"][number];

function Bars({ bars }: { bars: Group["bars"] }) {
  return (
    <div className="space-y-2.5">
      {bars.map((b, i) => {
        const pct = b.of ? (100 * b.value) / b.of : 0;
        const current = i === bars.length - 1;
        return (
          <div key={b.label} className="grid grid-cols-[36px_1fr] items-center gap-3">
            <span className={cx("text-[14px] font-semibold", current ? "text-fg" : "text-fg-muted")}>{b.label}</span>
            <div className="h-3 rounded-full bg-raised">
              <div className={cx("rise h-full rounded-full", current ? "bg-accent" : "bg-border-strong")}
                style={{ width: `${Math.max(pct, b.value ? 1.5 : 0)}%`, animationDelay: `${i * 120}ms` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function GroupCard({ g }: { g: Group }) {
  const [open, setOpen] = useState(false);
  const [before, after] = g.bars;
  const shown = g.notes.slice(0, g.visible ?? 1);
  const rest = g.notes.slice(g.visible ?? 1);
  return (
    <Card title={g.title} className="flex flex-col">
      <div className="flex items-baseline gap-4">
        <span className="num text-[40px] font-semibold leading-none text-fg-muted">{before.value}</span>
        <ArrowRight size={26} className="self-center text-fg-subtle" />
        <span className="num text-[64px] font-semibold leading-none tracking-[-0.02em] text-fg">{after.value}</span>
        <span className="num text-[18px] text-fg-muted">/ {after.of}</span>
      </div>
      <p className="mt-2 text-[15px] text-fg-muted">{g.unit} <span className="text-fg-subtle">({before.label} {T.to} {after.label})</span></p>
      <div className="mt-5"><Bars bars={g.bars} /></div>
      {shown.length > 0 && (
        <div className="mt-5 space-y-2 border-t border-border pt-4">
          {shown.map((n, i) => <p key={i} className="text-[15px] leading-relaxed text-fg">{n}</p>)}
        </div>
      )}
      {rest.length > 0 && (
        <div className="mt-3">
          <button onClick={() => setOpen(!open)} className="flex items-center gap-1.5 text-[13px] font-semibold text-fg-muted hover:text-fg">
            {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}{T.moreDetails}</button>
          {open && <ul className="mt-2 space-y-2 text-[14px] leading-relaxed text-fg-muted">{rest.map((n, i) => <li key={i}>{n}</li>)}</ul>}
        </div>
      )}
    </Card>
  );
}

function ChecksCard() {
  const [s, setS] = useState<ChecksState | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    const tick = () => api.checks().then((x) => { if (live) setS(x); }).catch(() => {});
    tick();
    const t = window.setInterval(tick, 400);
    return () => { live = false; window.clearInterval(t); };
  }, []);
  if (!s) return null;
  const w = s.words;
  const done = s.passed + s.failed + s.skipped;
  const pct = s.total ? Math.min(100, (100 * done) / s.total) : 0;
  const start = async () => { setErr(null); try { await api.runChecks(); } catch (e) { setErr(String(e)); } };
  return (
    <Card title={w.title} actions={<Button variant="primary" icon={<Play size={14} />} disabled={s.running || s.busy} onClick={start}>{w.button}</Button>}>
      <p className="max-w-[90ch] text-[15px] leading-relaxed text-fg-muted">{w.intro}</p>
      {s.busy && <p className="mt-3 text-[14px] text-fg">{w.busy}</p>}
      {err && <p className="mt-3 text-[14px] text-fg">{err}</p>}
      {(s.running || s.exit_code !== null) && (
        <div className="mt-5 grid items-center gap-6 md:grid-cols-[auto_1fr]">
          <div className="num flex items-baseline gap-2">
            <span className="text-[56px] font-semibold leading-none text-fg">{s.passed}</span>
            {s.total !== null && <span className="text-[20px] text-fg-muted">/ {s.total}</span>}
          </div>
          <div>
            <div className="h-3 rounded-full bg-raised"><div className="h-full rounded-full bg-accent transition-[width] duration-300" style={{ width: `${pct}%` }} /></div>
            <p className="mt-2 text-[15px] font-semibold text-fg">{s.running ? `${w.running} ${s.seconds ?? 0} s` : s.text}</p>
          </div>
        </div>
      )}
    </Card>
  );
}

export default function Scoreboard() {
  const [d, setD] = useState<SB | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { api.scoreboard().then(setD).catch((e) => setErr(String(e))); }, []);
  if (err) return <p className="text-alert">{T.errorPrefix} {err}</p>;
  if (!d) return <p className="text-fg-muted">{T.loading}</p>;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-[32px] font-semibold">{d.title}</h1>
        <p className="mt-2 max-w-[72ch] text-[16px] leading-relaxed text-fg-muted">{d.intro}</p>
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        {d.groups.map((g) => <GroupCard key={g.title} g={g} />)}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="border-l-2 !border-l-border-strong">
          <p className="text-[15px] leading-relaxed">{d.lost}</p>
        </Card>
        <Card>
          <ul className="space-y-2 text-[15px] leading-relaxed">{d.laptop.map((l, i) => <li key={i}>{l}</li>)}</ul>
        </Card>
      </div>
      <ChecksCard />
      <Eyebrow>{T.source}: {d.source}</Eyebrow>
    </div>
  );
}
