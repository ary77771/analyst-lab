// "Attack coverage": v4 on the 170 Atomic Red Team tests it had never seen, one square per test,
// grouped by technique. A toggle shows the stricter score (without community rules written with
// these tests in mind). Data and words: engine/dashboard/coverage.py.
import { useEffect, useMemo, useState } from "react";
import { api, type Coverage as CV } from "../api";
import { Card, cx } from "../ui";
import { T } from "../ui-text";

type Kind = "recorded" | "declared" | "missed";
// neutral greys (accent is for clickable things only): recorded = solid, declared = outline with a
// diagonal hatch (clearly weaker than solid at projector distance), missed = empty outline
const TILE: Record<Kind, string> = {
  recorded: "bg-fg-muted border-fg-muted",
  declared: "hatch border-fg-muted",
  missed: "bg-transparent border-border-strong",
};

export default function Coverage() {
  const [d, setD] = useState<CV | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [strict, setStrict] = useState(false);
  const [hover, setHover] = useState<string | null>(null);
  useEffect(() => { api.coverage().then(setD).catch((e) => setErr(String(e))); }, []);
  const kindOf = useMemo(() => (t: CV["groups"][number]["tests"][number]): Kind =>
    strict ? (t.without_citing_rules ? (t.result === "declared" ? "declared" : "recorded") : "missed") : (t.result as Kind), [strict]);
  if (err) return <p className="text-alert">{T.errorPrefix} {err}</p>;
  if (!d) return <p className="text-fg-muted">{T.loading}</p>;
  const w = d.words;
  const caught = strict ? d.caught_strict : d.caught;
  const all = d.groups.flatMap((g) => g.tests);
  const hovered = all.find((t) => t.guid === hover);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div>
          <h1 className="text-[32px] font-semibold">{w.title}</h1>
          <p className="mt-2 max-w-[80ch] text-[16px] leading-relaxed text-fg-muted">{w.intro}</p>
        </div>
        <div className="text-right">
          <div className="num text-[64px] font-semibold leading-none tracking-[-0.02em]">{caught}</div>
          <div className="mt-1 text-[15px] text-fg-muted">{w.caught_label.replace("{n}", String(d.total))}</div>
          {!strict && <div className="mt-1 text-[14px] text-fg">{w.declared_note.replace("{d}", String(d.declared))}</div>}
        </div>
      </div>

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap gap-x-6 gap-y-2 text-[14px] text-fg-muted">
            {(Object.keys(TILE) as Kind[]).map((k) => (
              <span key={k} className="inline-flex items-center gap-2">
                <span className={cx("inline-block h-4 w-4 rounded-[4px] border-2", TILE[k])} />{w.results[k]}
              </span>
            ))}
          </div>
          <label className="flex cursor-pointer select-none items-center gap-2 text-[14px] font-semibold text-fg">
            <input type="checkbox" checked={strict} onChange={(e) => setStrict(e.target.checked)} className="h-4 w-4 accent-[var(--color-accent)]" />
            {w.toggle}
          </label>
        </div>
        <p className="mt-3 max-w-[100ch] text-[14px] text-fg-muted">{w.toggle_note} {w.meaning}</p>
      </Card>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
        {d.groups.map((g) => (
          <div key={g.technique} className="rounded-[10px] border border-border bg-surface px-4 py-3">
            <div className="flex items-baseline justify-between gap-3">
              <span className="truncate text-[14px] font-semibold text-fg" title={g.name}>{g.name || g.technique}</span>
              <span className="num flex-none text-[12px] text-fg-subtle">{g.technique}</span>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {g.tests.map((t) => (
                <span key={t.guid} onMouseEnter={() => setHover(t.guid)} onMouseLeave={() => setHover(null)}
                  className={cx("h-5 w-5 rounded-[4px] border-2 transition-colors duration-300", TILE[kindOf(t)])} />
              ))}
            </div>
          </div>
        ))}
      </div>

      <div className="min-h-[48px] text-[14px] text-fg-muted">
        {hovered && <span><span className="font-semibold text-fg">{hovered.technique}</span> · {hovered.test_name} · {w.results[kindOf(hovered)]}</span>}
      </div>
      <p className="text-[12px] text-fg-subtle">{w.source} {d.half}</p>
    </div>
  );
}
