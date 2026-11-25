// "Run the honesty checks", on the Watch screen (Yousif, 2026-11-20: "i want the honesty test in the
// first page"). A strip of fixed height: the ring and the count never move while the tests tick.
// Beside them, one plain line per group of checks (Python's words) with its own count, each ticking
// off when its group is through: nothing scrolls and nothing is cut. Words and counts come from
// /api/checks. While the test machine runs the button is off and the strip says why.
import { Check, Play, X } from "lucide-react";
import { UI } from "./bits";
import { useChecks } from "./hooks";

export default function ChecksStrip() {
  const { s, start, error } = useChecks();
  // before the first answer: say so (and say why when there is none), instead of an empty panel
  if (!s) return <section className="ua-panel ck"><p className="ua-hint ck-wait">{error ? `${UI.error} ${error}` : UI.loading}</p></section>;
  const w = s.words, done = s.passed + s.failed + s.skipped;
  const pct = s.total ? Math.min(1, done / s.total) : 0;
  const idle = !s.running && s.exit_code === null;                 // nothing run yet: show how many checks are ready
  const state = s.running ? "running" : s.ok === true ? "ok" : s.ok === false ? "bad" : "idle";
  const C = 2 * Math.PI * 52;
  return (
    <section className="ua-panel ck" data-state={state}>
      <div className="ck-ring">
        <svg viewBox="0 0 120 120" aria-hidden="true">
          <circle cx="60" cy="60" r="52" className="ck-track" />
          <circle cx="60" cy="60" r="52" className="ck-fill" strokeDasharray={C} strokeDashoffset={C * (1 - pct)} transform="rotate(-90 60 60)" />
        </svg>
        <b title={idle ? UI.tips.checksReady : UI.tips.checksPassed}>{idle ? s.total ?? "" : s.passed}</b>
      </div>
      <div className="ck-head">
        <h2>{w.title}</h2>
        <p>{s.busy ? w.busy : s.running ? `${w.running} ${Math.round(s.seconds ?? 0)} s` : s.text ?? s.ready_text ?? ""}</p>
        {error && !s.busy && <p>{error}</p>}
        <button className="ua-btn" data-kind="primary" disabled={s.running || s.busy} onClick={start}><Play size={15} />{w.button}</button>
      </div>
      <div className="ck-box">
        <ul title={w.intro}>
          {(s.groups ?? []).map((g) => {
            const through = g.passed + g.failed + g.skipped;
            const st = g.failed > 0 ? "failed" : g.total !== null && through >= g.total && through > 0 ? "passed" : through > 0 ? "going" : "waiting";
            return (
              <li key={g.name} data-state={st}>
                <i>{st === "passed" ? <Check size={12} strokeWidth={3.5} /> : st === "failed" ? <X size={12} strokeWidth={3.5} /> : null}</i>
                <span>{g.name}</span>
                <small title={through > 0 ? UI.tips.groupCount : UI.tips.checksReady}>{g.total === null ? "" : through > 0 ? `${g.passed} / ${g.total}` : g.total}</small>
              </li>
            );
          })}
        </ul>
      </div>
    </section>
  );
}
