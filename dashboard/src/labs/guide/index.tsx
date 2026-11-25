// Lab: "One alert, start to finish": the walk-through's own page (wave 3, W3-7). It names the alert the
// dashboard's store gives it and lists the steps; each step is a lab's own address on that alert. The script,
// the alert and every sentence come from Python (engine/labs/guide.py). Nothing is run, nothing is changed.
import { ArrowRight, Footprints } from "lucide-react";
import { guideApi, guideSteps, type GuideAlert, type GuideData } from "../guide";
import { LabPanel, LabState, useLab } from "../kit";
import { labHref, useLabs, type Lab, type LabProps } from "../registry";
import "./guide.css";

const when = (a: GuideAlert) => `${a.level} · ${a.time.replace("T", " ").slice(0, 19)} UTC`;

/** The other alerts of the recording: a click follows that one instead. */
function Others({ data }: { data: GuideData }) {
  if (!data.others || data.others.length === 0) return null;
  return (
    <LabPanel title={data.words.others}>
      <ul className="gd-others">
        {data.others.map((a) => <li key={a.id}><a href={labHref("guide", { alert: a.id })}><b>{a.title}</b><span>{when(a)}</span></a></li>)}
      </ul>
    </LabPanel>
  );
}

function GuideLab({ params }: LabProps) {
  const { data, error, loading } = useLab<GuideData>(guideApi(params.get("alert")));
  const found = useLabs();
  return (
    <LabState loading={loading || !found} error={error}>
      {data && found && (() => {
        const w = data.words;
        const { steps, hidden } = guideSteps(data, found.labs);
        const done = params.get("done") === "1";
        if (!data.alert) return <><p className="lab-state" data-kind="empty">{data.unknown ? w.unknown : w.no_alert}</p><Others data={data} /></>;
        return (
          <>
            <LabPanel hint={w.intro}>
              <div className="gd-alert">
                <small>{w.alert}</small>
                <b>{data.alert.title}</b>
                <span>{when(data.alert)} · {data.alert.host}</span>
              </div>
              <p className="ua-hint">{data.chosen ? w.chosen : w.which}</p>
              {done && <p className="gd-done" role="status">{w.finished}</p>}
              {steps.length > 0
                ? <a className="ua-btn gd-start" data-kind="primary" href={steps[0].href}>{done ? w.again : w.start}<ArrowRight size={15} /></a>
                : <p className="lab-state" data-kind="empty">{w.none_here}</p>}
            </LabPanel>
            <ol className="gd-steps">
              {data.steps.filter((s) => !hidden.includes(s.lab)).map((s) => {
                const step = steps.find((x) => x.lab === s.lab);
                return (
                  <li key={s.lab} data-out={!step}>
                    <i>{step ? step.n : "–"}</i>
                    {step ? <a href={step.href}><b>{s.question}</b><span>{s.text}</span></a>
                      : <div><b>{s.question}</b><span>{s.text}</span><em>{w.left_out}</em></div>}
                  </li>
                );
              })}
            </ol>
            <Others data={data} />
          </>
        );
      })()}
    </LabState>
  );
}

export const lab: Lab = {
  id: "guide",
  title: "One alert, start to finish",
  blurb: "Follow one recorded alert through the labs, one question per step: a whole investigation as a walk-through.",
  icon: Footprints,
  group: "start",
  Component: GuideLab,
};
