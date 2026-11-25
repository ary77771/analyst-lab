// Lab "Investigation checklist" (engine/labs/checklist.py): the analyst's questions about one alert, each answered
// with the story's own sentences, or "can't be known" with the missing witness. Every word comes from Python.
import { DoorOpen } from "lucide-react";
import { LabPanel, LabState, NextStrip, useAlertParam, useLab } from "../kit";
import { labHref, type Lab, type LabProps } from "../registry";
import { Thing } from "../_things/Thing";
import { fill } from "../_explain/logic";
import { HarnessSwitch, Level, type AlertRow } from "../_explain/shared";
import { useState } from "react";
import "./checklist.css";

type Status = "fact" | "hypothesis" | "gap" | "none" | "mixed" | "unproven" | "raised" | "listed" | "unchecked";
type W = Record<string, string> & { questions: Record<string, string>; status: Record<Status, string>; open: Record<string, string>; verdict: Record<string, string>; sections: Record<string, string> };
interface QLine { ink: Status | null; text: string; time: string | null }
interface Group { id: string; title: string; level: string; first: string; count: number }
export interface Program { guid: string; recorded: boolean; image: string | null; pid: number | null; command_line: string | null; command_short?: string | null;
  parent: string | null; parent_command_line: string | null; parent_machinery?: string | null; harness?: boolean; user: string | null; time: string | null; children: { image: string; pid: number | null }[] }
interface Question { key: string; question: string; status: Status; lines: QLine[]; more: number; note: string | null; programs?: Program[];
  witness: { kind: string; witness: string; verdict: string } | null; links: string[]; section?: string; harness_hidden?: number }
export interface SummaryPart { text: string; status: Status | null; source: string; label: string }
export interface Checklist { words: W; alert: AlertRow; story: boolean; guid: string | null; host: string; recording?: string | null; questions: Question[]; scope: string[]; own: string[];
  summary?: SummaryPart[][] }

/** The incident in one paragraph (engine/labs/_summary.py): each part says which question it summarises; a click
 * scrolls to that question. Python wrote every word. */
export function Summary({ d }: { d: Checklist }) {
  const s = d.words.summary as unknown as Record<string, string> | undefined;
  if (!d.summary?.length) return null;
  const go = (key: string) => document.getElementById(`cl-q-${key}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
  return (
    <div className="cl-summary">
      <b className="cl-summary-title">{s?.title ?? "In short"}</b>
      <p>{d.summary.map((sentence, i) => (
        <span key={i}>{i ? " " : ""}{sentence.map((p, j) => (
          <span key={j} className="cl-sum-part" data-status={p.status ?? "none"} title={fill(s?.hover ?? "{source}", { source: p.label })}
            onClick={() => go(p.source)}>{p.text}</span>))}</span>))}</p>
    </div>
  );
}

/** Where each "open ..." link of a question goes. */
export function hrefFor(link: string, d: Checklist): string | null {
  const alert = d.alert.id;
  if (link === "pivot") return d.guid ? labHref("pivot", { kind: "process", value: d.guid, host: d.host }) : null;
  if (link === "persistence") return labHref("persistence");
  if (["why", "moment", "prove", "respond", "claim", "alarm"].includes(link)) return labHref(link, { alert });
  return null;
}

const SECTIONS = ["happened", "far", "sure", "now"];
const baseName = (path: string) => path.replace(/\//g, "\\").split("\\").pop() ?? path;
const short = (t: string) => (t ? `${t.slice(0, 10)} ${t.slice(11, 19)}` : "?");

/** The alerts once each ("3 times, first at ..."), newest first: the landing page's first screen. */
export function GroupPicker({ groups, w }: { groups: Group[]; w: W }) {
  if (!groups.length) return <p className="lab-state" data-kind="empty">{w.no_alerts}</p>;
  return (
    <LabPanel title={w.pick} hint={w.pick_note}>
      <ul className="xp-pick">{groups.map((g) => (
        <li key={g.id}><a href={labHref("checklist", { alert: g.id })}><Level level={g.level} /><span className="xp-grow">{g.title}</span>
          <span className="xp-small xp-dim">{g.count > 1 ? fill(w.times, { n: g.count, first: short(g.first) }) : fill(w.once, { first: short(g.first) })}</span></a></li>))}</ul>
    </LabPanel>
  );
}

export function ChecklistView({ d }: { d: Checklist }) {
  const w = d.words;
  const [showHarness, setShowHarness] = useState(false);
  return (
    <>
      <LabPanel>
        <div className="xp-row"><Level level={d.alert.level} /><h2 className="xp-title">{d.alert.title}</h2>
          <span className="xp-small xp-dim xp-mono">{d.alert.time}</span></div>
        <p className="ua-hint">{w.intro}</p>
        {d.recording ? <p className="cl-recording">{d.recording}</p> : null}
        <Summary d={d} />
        {!d.story ? <p className="xp-note">{w.no_story}</p> : null}
      </LabPanel>
      {SECTIONS.filter((s) => d.questions.some((q) => (q.section ?? "happened") === s)).map((s) => (
      <section key={s} className="cl-section"><h2 className="cl-section-title">{w.sections?.[s] ?? s}</h2>
      <ol className="cl-list">{d.questions.filter((q) => (q.section ?? "happened") === s).map((q) => (
        <li key={q.key} id={`cl-q-${q.key}`} className="ua-panel cl-q" data-status={q.status}>
          <div className="cl-head">
            <span className="cl-n xp-mono">{d.questions.indexOf(q) + 1}</span><h3>{q.question}</h3>
            <span className="cl-status" data-status={q.status}>{w.status[q.status]}</span>
          </div>
          {q.lines.length ? (
            <ul className="cl-lines">{q.lines.map((l, j) => (
              <li key={j} data-ink={l.ink ?? "none"}>{l.ink && l.ink !== q.status ? <b className={`xp-ink-${l.ink}`}>{w.status[l.ink]}</b> : null}<span>{l.text}</span></li>))}
              {q.more ? <li data-ink="none"><span className="xp-dim">{fill(w.more, { n: q.more })}</span></li> : null}</ul>) : null}
          {q.programs?.some((p) => p.harness) ? <HarnessSwitch hidden={q.programs.filter((p) => p.harness).length} on={showHarness} set={setShowHarness}
            w={{ harness_hidden: w.programs_hidden ?? "{n}", harness_switch: w.harness_switch ?? "show" }} /> : null}
          {q.programs?.length ? <ul className="cl-programs">{q.programs.filter((p) => showHarness || !p.harness).map((p) => (
            <li key={p.guid}>
              <div className="xp-row"><Thing field="Image" value={p.image ?? p.guid} host={d.host} />{p.pid !== null ? <span className="xp-small xp-dim xp-mono">PID {p.pid}</span> : null}
                {!p.recorded ? <span className="xp-small xp-ink-gap">{w.program_unrecorded}</span> : null}</div>
              {p.command_short ? <p className="cl-cmd"><code>{p.command_short}</code></p> : null}
              {p.parent ? (p.parent_machinery
                ? <p className="cl-cmd cl-harness" title={p.parent_machinery}><span className="xp-dim">{w.program_parent}: </span>{w.program_launcher} <span className="xp-dim xp-mono">({baseName(p.parent)})</span></p>
                : <p className="cl-cmd xp-row"><span className="xp-dim">{w.program_parent}:</span><Thing field="ParentImage" value={p.parent} host={d.host} /></p>) : null}
              {p.children.filter((c) => c.image).length ? <p className="cl-cmd xp-row"><span className="xp-dim">{w.program_children}:</span>
                {p.children.filter((c) => c.image).map((c, i) => <Thing key={i} field="Image" value={c.image} host={d.host} />)}</p> : null}
              {p.command_line || p.parent_command_line ? <details className="cl-full"><summary className="xp-small xp-dim">{w.program_show_cmd}</summary>
                {p.command_line ? <p className="cl-cmd"><span className="xp-dim">{w.program_cmd}: </span><code>{p.command_line}</code></p> : null}
                {p.parent_command_line ? <p className="cl-cmd"><span className="xp-dim">{w.program_parent}: </span><code>{p.parent_command_line}</code></p> : null}
              </details> : null}
            </li>))}</ul> : null}
          {q.note ? <p className="cl-note">{q.note}</p> : null}
          {q.harness_hidden ? <p className="xp-small xp-dim">{fill(w.harness_hidden, { n: q.harness_hidden })}</p> : null}
          {q.witness ? <p className="cl-witness"><span className="xp-dim">{w.witness}: </span>{q.witness.witness}
            {w.verdict[q.witness.verdict] ? <em> · {w.verdict[q.witness.verdict]}</em> : null}</p> : null}
          {q.links.length ? <div className="xp-row cl-links">{q.links.map((k) => {
            const href = hrefFor(k, d);
            return href ? <a key={k} className="xp-link" href={href}>{w.open[k] ?? k}</a> : null;
          })}</div> : null}
        </li>))}</ol></section>))}
    </>
  );
}

function ChecklistLab(_: LabProps) {
  const [alert] = useAlertParam();
  const { data, error, loading } = useLab<Checklist>(alert ? `/api/labs/checklist/${encodeURIComponent(alert)}` : null);
  const list = useLab<{ words: W; groups: Group[] }>(alert ? null : "/api/labs/checklist");
  if (!alert) return <LabState loading={list.loading} error={list.error}>{list.data && <GroupPicker groups={list.data.groups} w={list.data.words} />}</LabState>;
  return <><NextStrip current="checklist" alert={alert} /><LabState loading={loading} error={error}>{data && <ChecklistView d={data} />}</LabState></>;
}

export const lab: Lab = {
  id: "checklist",
  title: "I have an alert",
  // (VISION's front-door wording, docs/night/labs-qa.md; its last words "proven, suspected, or can't be known"
  // are claim words, which only Python may put on a page: tests/test_dashboard_frontend.py. So: "how sure".)
  blurb: "Start here: pick an alert and get the questions an investigator would ask, each answered from the recording and marked with how sure the answer is.",
  icon: DoorOpen,
  group: "start",
  Component: ChecklistLab,
};
