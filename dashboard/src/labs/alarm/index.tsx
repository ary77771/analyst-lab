// Lab "This is what an alarm says" (engine/labs/alarm.py): what the computer recorded, next to what the
// dashboard says, each traced word pointing at its field. Every sentence and label comes from Python.
import { Languages } from "lucide-react";
import { LabPanel, LabState, NextStrip, useAlertParam, useLab } from "../kit";
import { labHref, type Lab, type LabProps } from "../registry";
import { cut, WordGrid, type View, type WordData, type WW } from "../_explain/wordforword";
import { AlertPicker, Ids, Level, type AlertRow } from "../_explain/shared";

type W = WW;
export interface Alarm extends WordData {
  words: W; alert: AlertRow;
  alarm: { title: string; level: string; rule_id: string; source: string; reason: string; time: string; details: Record<string, unknown>; declared: Record<string, unknown> | null };
}
export { cut };

export function AlarmView({ d, view }: { d: Alarm; view: View }) {
  const w = d.words;
  return (
    <>
      <LabPanel title={w.alarm_title}>
        <div className="xp-row"><Level level={d.alarm.level} /><h2 className="xp-title al-mono-title">{d.alarm.title}</h2>
          <span className="xp-small xp-dim xp-mono">{d.alarm.time}</span></div>
        <Ids label={w.details}>{w.rule}: {d.alarm.rule_id} · {d.alarm.source}</Ids>
        <p className="al-reason"><span className="xp-dim">{w.reason}: </span>{d.alarm.reason}</p>
        {Object.keys(d.alarm.details).length ? (
          <details className="xp-details"><summary>{w.details}</summary>
            <pre className="xp-pre">{JSON.stringify(d.alarm.details, null, 2)}</pre></details>) : null}
      </LabPanel>
      <WordGrid d={d} view={view} />
    </>
  );
}

function AlarmLab({ params }: LabProps) {
  const [alert] = useAlertParam();
  const view = (["side", "alarm", "story"].includes(params.get("view") ?? "") ? params.get("view") : "side") as View;
  const { data, error, loading } = useLab<Alarm>(alert ? `/api/labs/alarm/${encodeURIComponent(alert)}` : null);
  if (!alert) return <AlertPicker lab="alarm" url="/api/labs/alarm" />;
  return (
    <>
    <NextStrip current="alarm" alert={alert} />
    <LabState loading={loading} error={error}>
      {data && (
        <>
          <LabPanel>
            <div className="xp-row"><p className="ua-hint xp-grow">{data.words.intro}</p>
              <div className="tq-toggle">{(["side", "alarm", "story"] as View[]).map((v) => (
                <a key={v} aria-pressed={v === view} href={labHref("alarm", { alert, view: v === "side" ? null : v })}>{data.words[`view_${v}`]}</a>))}</div></div>
          </LabPanel>
          <AlarmView d={data} view={view} />
        </>)}
    </LabState>
    </>
  );
}

export const lab: Lab = {
  id: "alarm",
  title: "This is what an alarm says",
  blurb: "What the computer recorded, word for word, next to what the dashboard says: every plain word traced to its field.",
  icon: Languages,
  Component: AlarmLab,
};
