// Lab "I have an alert" (engine/labs/start.py): the investigation's front door. Pick an alert (repeats shown once),
// then six questions as a numbered path, each answered by the lab that owns it, one click away. Words from Python.
import { DoorOpen } from "lucide-react";
import { LabPanel, LabState, NextStrip, useAlertParam, useLab } from "../kit";
import { labHref, type Lab, type LabProps } from "../registry";
import { fill } from "../_explain/logic";
import { Level } from "../_explain/shared";
import "./start.css";

type Status = "fact" | "hypothesis" | "gap" | "none" | "unchecked" | "mixed" | "unproven" | "raised" | "listed";
type W = Record<string, string> & { questions: Record<string, string>; labs: Record<string, string>; status: Record<Status, string> };
interface Group { id: string; ids: string[]; title: string; rule_id: string; level: string; first: string; last: string; count: number }
export interface Step { key: string; question: string; status: Status; status_word: string; line: string; lab: string; lab_name: string; reason?: string | null }
export interface Start { words: W; alert: { id: string; title: string; level: string; time: string; host: string }; repeats: number; steps: Step[] }

const short = (t: string) => (t ? `${t.slice(0, 10)} ${t.slice(11, 19)}` : "?");

export function Picker({ groups, w }: { groups: Group[]; w: W }) {
  if (!groups.length) return <p className="lab-state" data-kind="empty">{w.no_alerts}</p>;
  return (
    <LabPanel title={w.pick} hint={w.pick_note}>
      <ul className="st-groups">{groups.map((g) => (
        <li key={g.id}><a href={labHref("start", { alert: g.id })}>
          <Level level={g.level} /><span className="st-title">{g.title}</span>
          <span className="xp-small xp-dim">{g.count > 1 ? fill(w.times, { n: g.count, first: short(g.first) }) : fill(w.once, { first: short(g.first) })}</span>
        </a></li>))}</ul>
    </LabPanel>
  );
}

export function StartView({ d }: { d: Start }) {
  const w = d.words;
  return (
    <>
      <LabPanel>
        <div className="xp-row"><Level level={d.alert.level} /><h2 className="xp-title">{d.alert.title}</h2>
          <span className="xp-small xp-dim xp-mono">{d.alert.time}</span><span className="xp-grow" />
          <a className="xp-link" href={labHref("start")}>{w.pick}</a></div>
        <p className="ua-hint">{w.intro}</p>
      </LabPanel>
      <section className="ua-panel lab-panel">
        <h2>{w.path}</h2>
        <ol className="st-path">{d.steps.map((s, i) => (
          <li key={s.key} className="st-step" data-status={s.status}>
            <span className="st-n">{i + 1}</span>
            <div className="st-body">
              <h3>{s.question}</h3>
              <p><b className="st-status" data-status={s.status}>{s.status_word}</b> {s.line}</p>
              {s.reason ? <p className="xp-small xp-dim">{s.reason}</p> : null}
            </div>
            <a className="xp-link st-open" href={labHref(s.lab, { alert: d.alert.id })}>{w.open}: {s.lab_name} →</a>
          </li>))}</ol>
      </section>
    </>
  );
}

function StartLab(_: LabProps) {
  const [alert] = useAlertParam();
  const list = useLab<{ words: W; groups: Group[] }>(alert ? null : "/api/labs/start");
  const one = useLab<Start>(alert ? `/api/labs/start/${encodeURIComponent(alert)}` : null);
  if (!alert) return <LabState loading={list.loading} error={list.error}>{list.data && <Picker groups={list.data.groups} w={list.data.words} />}</LabState>;
  return <><NextStrip current="start" alert={alert} /><LabState loading={one.loading} error={one.error}>{one.data && <StartView d={one.data} />}</LabState></>;
}

export const lab: Lab = {
  id: "start",
  title: "I have an alert",
  blurb: "Start here: pick an alert and follow six questions, each answered by the page that shows it in full.",
  icon: DoorOpen,
  group: "start",
  Component: StartLab,
};
