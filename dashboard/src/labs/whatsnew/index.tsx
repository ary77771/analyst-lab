// Lab: What's new tonight (night-tools, 2026-11-24). The morning page: one card per lab built on the night of
// 23 to 24 November, in the builders' own words from their status files (engine/labs/whatsnew.py), with its
// screenshot, how to open it and switch it off, and what is not done. Titles and icons come from the registry.
import { Fragment, useMemo } from "react";
import { Sparkles } from "lucide-react";
import { LabNumber, LabPanel, LabState, useLab } from "../kit";
import { labHref, useLabs, type Lab, type LabProps } from "../registry";
import "../fileinspect/fileinspect.css";
import "./whatsnew.css";

interface Words { title: string; intro: string; questions: string; not_done: string; no_entry: string; source: string; loaded: string; left_out: string }
export interface Facts {
  source: string; heading: string; what: string; open: string[]; off: string[]; not_done: string[]; checks: string[];
  notes: string[]; shots: string[];
}
export interface Body {
  words: Words; labs: Record<string, Facts | null>; loaded: string[]; left_out: { name: string; problem: string }[] | false;
  questions: { source: string; heading: string; lines: string[] }[]; not_done: { lab: string; source: string; line: string }[];
  status_files: string[];
}

export const shotUrl = (name: string) => `/api/labs/whatsnew/shot/${encodeURIComponent(name)}`;
const who = (source: string) => source.replace(/^status-/, "").replace(/\.md$/, "");

/** Cards in order: labs with a status entry and a screenshot first, then by title. */
export function order(labs: Lab[], facts: Record<string, Facts | null>): Lab[] {
  const rank = (l: Lab) => (facts[l.id] ? (facts[l.id]!.shots.length ? 0 : 1) : 2);
  return labs.filter((l) => l.id !== "whatsnew" && l.id !== "glance").sort((a, b) => rank(a) - rank(b) || a.title.localeCompare(b.title));
}

export function Card({ lab, f, words, loaded }: { lab: Lab; f: Facts | null; words: Words; loaded: boolean }) {
  const Icon = lab.icon;
  return (
    <article className="wn-card">
      {f?.shots[0] ? (
        <a className="wn-shot" href={shotUrl(f.shots[0])} target="_blank" rel="noreferrer" title="Open the screenshot full size">
          <img src={shotUrl(f.shots[0])} alt={`Screenshot of ${lab.title}`} loading="lazy" />
        </a>
      ) : <div className="wn-shot wn-noshot"><Icon size={28} aria-hidden /></div>}
      <div className="wn-body">
        <header>
          <Icon size={18} aria-hidden /><b>{lab.title}</b>
          {!loaded && <span className="ft-tag" data-on>{words.left_out}</span>}
        </header>
        <p className="wn-blurb">{lab.blurb}</p>
        {f ? (
          <>
            {f.what && <p className="wn-what">{f.what}</p>}
            <dl className="wn-dl">
              {f.off[0] && <><dt>Switch off</dt><dd>{f.off[0]}</dd></>}
              {f.checks[0] && <><dt>Checked</dt><dd>{f.checks[0]}</dd></>}
              {f.not_done.map((n) => <Fragment key={n}><dt>Not done</dt><dd className="wn-nd">{n}</dd></Fragment>)}
            </dl>
            {f.notes.length > 0 && (
              <details className="wn-notes"><summary>More from the builder's notes</summary><ul>{f.notes.map((n) => <li key={n}>{n}</li>)}</ul></details>
            )}
            <p className="ua-hint">{words.source} {f.source} · {f.heading}{f.shots.length > 1 ? ` · ${f.shots.length} screenshots` : ""}</p>
          </>
        ) : <p className="ua-hint">{words.no_entry}</p>}
        <a className="ft-btn wn-open" href={labHref(lab.id)}>Open {lab.title}</a>
      </div>
    </article>
  );
}

function WhatsNewLab(_: LabProps) {
  const { data, error, loading } = useLab<Body>("/api/labs/whatsnew");
  const found = useLabs();
  const cards = useMemo(() => (data && found ? order(found.labs, data.labs) : []), [data, found]);
  return (
    <LabState loading={loading || !found} error={error}>
      {data && found && (
        <div className="ft-details">
          <LabPanel title={data.words.title} hint={data.words.intro}>
            <div className="lab-numbers">
              <LabNumber value={cards.length} label="labs to try" />
              <LabNumber value={cards.filter((l) => data.labs[l.id]?.shots.length).length} label="with a screenshot" />
              <LabNumber value={data.not_done.length} label="things the builders say are not done" />
              <LabNumber value={data.status_files.length} label="builders' status files read" />
            </div>
          </LabPanel>
          {data.questions.length > 0 && (
            <LabPanel title={data.words.questions}>
              {data.questions.map((q) => (
                <div key={q.heading} className="wn-question">
                  <b>{q.heading}</b>
                  <ul>{q.lines.map((l) => <li key={l}>{l}</li>)}</ul>
                  <p className="ua-hint">{data.words.source} {q.source} ({who(q.source)})</p>
                </div>
              ))}
            </LabPanel>
          )}
          <div className="wn-grid">
            {cards.map((l) => <Card key={l.id} lab={l} f={data.labs[l.id] ?? null} words={data.words} loaded={data.loaded.includes(l.id)} />)}
          </div>
          {data.not_done.length > 0 && (
            <LabPanel title={data.words.not_done}>
              <ul className="wn-ndlist">
                {data.not_done.map((n, i) => <li key={i}><a className="ft-a" href={labHref(n.lab)}>{n.lab}</a>: {n.line} <span className="ft-muted">({who(n.source)})</span></li>)}
              </ul>
            </LabPanel>
          )}
          {data.left_out && data.left_out.length > 0 && (
            <LabPanel title={data.words.left_out}>
              <ul>{data.left_out.map((b) => <li key={b.name}><code>{b.name}</code>: {b.problem}</li>)}</ul>
            </LabPanel>
          )}
        </div>
      )}
    </LabState>
  );
}

export const lab: Lab = {
  id: "whatsnew",
  title: "What's new tonight",
  blurb: "Start here: every lab built on the night of 23 to 24 November, what it is for, a screenshot, and what is not done yet.",
  icon: Sparkles,
  group: "start",
  Component: WhatsNewLab,
};
