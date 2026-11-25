// Proof: one screen, three panels, one idea each (the live checks moved to Watch). Both designs use this
// structure and style it through their own CSS variables. Every number and sentence comes from
// /api/scoreboard, /api/coverage and /api/twin; long caveats open in a side drawer (never a full-screen layer).
import { useEffect, useState, type ReactNode } from "react";
import { ArrowRight, X } from "lucide-react";
import type { Coverage, Scoreboard, Twin } from "../api";
import { cx, UI } from "./bits";
import { useCountIn, useLive, useProof } from "./hooks";

type Drawer = { title: string; body: ReactNode } | null;

function CountIn({ value, delay }: { value: number; delay?: number }) {
  return <>{useCountIn(value, 1100, delay)}</>;
}

function Scores({ sb, title, open }: { sb: Scoreboard; title: string; open: (d: Drawer) => void }) {
  // The panel's second view (2026-11-24): the newest results. The rehearsed view is the one shown first; the
  // two words of the switch, like every number and sentence of both views, come from /api/scoreboard.
  const [newest, setNewest] = useState(false);
  const L = newest ? sb.latest : undefined;
  const groups = L ? L.groups : sb.groups;
  const heading = L ? L.title : title;
  return (
    <section className="pf-panel pf-scores" data-view={L ? "latest" : "first"}>
      <header><h2>{heading}</h2>
        <button className="pf-more" onClick={() => open({ title: heading, body: L ? (
          <>
            <p>{L.intro}</p>
            {L.groups.map((g) => <div key={g.title}><h4>{g.title}</h4><ul>{g.notes.map((n, i) => <li key={i}>{n}</li>)}</ul></div>)}
            <p>{L.summary}</p>
            <small>{L.sources.join(" · ")}</small>
          </>) : (
          <>
            <p>{sb.intro}</p>
            {sb.groups.map((g) => <div key={g.title}><h4>{g.title}</h4><ul>{g.notes.map((n, i) => <li key={i}>{n}</li>)}</ul></div>)}
            <p>{sb.lost}</p>
            <ul>{sb.laptop.map((l, i) => <li key={i}>{l}</li>)}</ul>
            <small>{sb.source}</small>
          </>) })}>{UI.details}</button>
      </header>
      {sb.latest && (
        <div className="pf-tabs" role="tablist">
          <button role="tab" aria-selected={!newest} data-on={!newest} onClick={() => setNewest(false)}>{sb.latest.tabs.first}</button>
          <button role="tab" aria-selected={newest} data-on={newest} onClick={() => setNewest(true)}>{sb.latest.tabs.latest}</button>
        </div>
      )}
      {/* Yousif, 2026-11-20: "showing small numbers isnt right and it isnt clear what they represent". Old and new
          stand side by side at the same size, each named in words; the new one is brighter, not bigger. The
          total is said in words, and one short caveat follows. The full notes are in Details. */}
      <ol key={L ? "latest" : "first"}>
        {groups.map((g, i) => (
          <li key={g.title}>
            <p className="pf-short">{g.short ?? g.unit}</p>
            <div className="pf-two" data-n={g.bars.length}>
              {g.bars.map((b, k) => (
                <div key={b.label} data-now={k === g.bars.length - 1} title={`${b.label}: ${b.text ?? UI.tips.barOf(b.value, b.of)} (${g.unit})`}>
                  <small>{b.name ?? b.label}</small>
                  <b>{b.text ?? (k === g.bars.length - 1 ? <CountIn value={b.value} delay={200 + i * 220} /> : b.value)}</b>
                </div>
              ))}
              <span className="pf-oftext">{g.of_text ?? `/ ${g.bars[g.bars.length - 1].of}`}</span>
            </div>
            {g.caveat ? <p className="pf-caveat">{g.caveat}</p> : g.notes.slice(0, g.visible ?? 1).map((n, k) => <p className="pf-caveat" key={k}>{n}</p>)}
          </li>
        ))}
      </ol>
      {L && <p className="pf-sum">{L.summary}</p>}
    </section>
  );
}

function Wall({ cov, strictLabel, open }: { cov: Coverage; strictLabel: string; open: (d: Drawer) => void }) {
  const [strict, setStrict] = useState(false);
  const tests = cov.groups.flatMap((g) => g.tests);
  return (
    <section className="pf-panel pf-wall">
      <header><h2>{cov.words.title}</h2>
        <button className="pf-more" onClick={() => open({ title: cov.words.title, body: (
          <><p>{cov.words.intro}</p><ul>{(["recorded", "declared", "missed"] as const).map((k) => <li key={k}>{cov.words.results[k]}</li>)}</ul><p>{cov.words.meaning}</p><p>{cov.words.declared_note.replace("{d}", String(cov.declared))}</p><p>{cov.words.toggle_note}</p><small>{cov.words.source} {cov.half}</small></>) })}>{UI.details}</button>
      </header>
      <div className="pf-wall-nums">
        <button data-on={!strict} onClick={() => setStrict(false)} title={cov.words.meaning}><b><CountIn value={cov.caught} /></b><span>{cov.words.caught_label.replace("{n}", String(cov.total))}</span></button>
        <button data-on={strict} onClick={() => setStrict(true)} title={cov.words.toggle_note}><b><CountIn value={cov.caught_strict} delay={250} /></b><span>{strictLabel.replace("{n}", String(cov.total))}</span></button>
      </div>
      <div className="pf-tiles" data-strict={strict}>
        {tests.map((t, i) => (
          <i key={t.guid + i} data-result={t.result} data-kept={t.result !== "missed" && t.without_citing_rules} title={`${t.technique} · ${t.technique_name}: ${t.test_name}`}
            style={{ animationDelay: `${250 + (i % 34) * 14 + Math.floor(i / 34) * 40}ms` }} />
        ))}
      </div>
      <ul className="pf-legend">
        {(["recorded", "declared", "missed"] as const).map((k) => <li key={k} title={cov.words.results[k]}><i data-result={k} /><span>{cov.words.results_short?.[k] ?? cov.words.results[k]}</span></li>)}
      </ul>
    </section>
  );
}

function Pair({ twin, title, levelWord, open }: { twin: Twin; title: string; levelWord: string; open: (d: Drawer) => void }) {
  const tw = twin.words;
  const item = (r: Twin["sides"][number]["raised"][number] | Twin["sides"][number]["below_floor"][number], below: boolean) => (
    <li key={r.rule + r.level} data-below={below}><em data-level={r.level} title={`${levelWord}: ${r.level}`}>{r.level}</em><span>{r.plain ?? r.title}</span></li>
  );
  return (
    <section className="pf-panel pf-pair">
      <header><h2>{title}</h2>
        <button className="pf-more" onClick={() => open({ title, body: (
          <>
            <p>{tw.intro}</p><p>{tw.difference}</p>
            {twin.sides.map((s) => (
              <div key={s.scenario}><h4>{s.title}</h4>
                <ul>{s.raised.map((r) => <li key={r.rule}>{levelWord}: {r.level}. {r.plain ?? r.title}</li>)}
                  {s.below_floor.map((r) => <li key={r.rule}>{tw.below.replace("{floor}", twin.floor)}: {r.plain ?? r.title}</li>)}</ul></div>
            ))}
            <p>{tw.picked}</p><small>{twin.source}</small>
          </>) })}>{UI.details}</button>
      </header>
      {twin.headline && <p className="pf-headline">{twin.headline}</p>}
      <div className="pf-sides">
        {twin.sides.map((s) => (
          <article key={s.scenario} data-raised={s.raised.length > 0}>
            <div className="pf-side-top"><small>{tw.kind[s.kind] ?? s.kind}</small><p className="pf-verdict"><i />{s.raised.length ? `${tw.raised}: ${s.raised.length}` : tw.none_raised}</p></div>
            <h3>{s.title}</h3>
            {/* every raised alert; what stayed below the alarm line is listed when nothing was raised (all of it is in Details) */}
            <ul>{s.raised.length ? s.raised.map((r) => item(r, false)) : s.below_floor.map((r) => item(r, true))}</ul>
            {s.verdicts && <p className="pf-versions"><span>v3: {s.verdicts.v3}</span><ArrowRight size={13} /><b>v4: {s.verdicts.v4}</b></p>}
          </article>
        ))}
      </div>
    </section>
  );
}

export default function Proof() {
  const { words: w } = useLive();
  const d = useProof();
  const [drawer, setDrawer] = useState<Drawer>(null);
  useEffect(() => {
    const on = (e: KeyboardEvent) => { if (e.key === "Escape") setDrawer(null); };
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, []);
  if (!d.ready) return <p className="pf-msg">{UI.loading}</p>;
  // a source that could not be read leaves its panel saying so; the others stand
  const missing = (cls: string) => <section className={`pf-panel ${cls}`}><p className="pf-msg">{UI.error} {d.failed.join(" · ")}</p></section>;
  return (
    <div className={cx("pf", drawer && "pf-open")}>
      {d.sb ? <Scores sb={d.sb} title={w.proof.scores_title} open={setDrawer} /> : missing("pf-scores")}
      {d.cov ? <Wall cov={d.cov} strictLabel={w.proof.strict_label} open={setDrawer} /> : missing("pf-wall")}
      {d.twin ? <Pair twin={d.twin} title={w.proof.twin_title} levelWord={w.alert_level} open={setDrawer} /> : missing("pf-pair")}
      <aside className="pf-drawer" data-open={!!drawer} aria-hidden={!drawer}>
        <header><h3>{drawer?.title}</h3><button onClick={() => setDrawer(null)} aria-label={UI.close}><X size={18} /></button></header>
        <div>{drawer?.body}</div>
      </aside>
    </div>
  );
}
