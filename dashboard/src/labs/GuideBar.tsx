// The bar above a lab while the walk-through "One alert, start to finish" is going: which step this is, its
// question and its one sentence, Back / Next / End. Drawn by the Labs shell when the address carries
// "guide=<n>"; every word comes from Python (GET /api/labs/guide). It shows nothing when the walk-through's
// back end is not there, the address names no real step, or the step belongs to another lab.
import { ArrowLeft, ArrowRight, Footprints, X } from "lucide-react";
import { guideApi, guideStepAt, guideSteps, type GuideData } from "./guide";
import { useLab } from "./kit";
import { labHref, useLabs } from "./registry";

export default function GuideBar({ lab, params }: { lab: string; params: URLSearchParams }) {
  const { data } = useLab<GuideData>(guideApi(params.get("alert")));      // the steps of the alert this address is about
  const found = useLabs();
  if (!data || !found) return null;
  const step = guideStepAt(guideSteps(data, found.labs).steps, lab, params.get("guide"));
  if (!step) return null;
  const w = data.words;
  const rest = new URLSearchParams(params);
  rest.delete("guide");
  return (
    <aside className="lab-guide" aria-label={w.bar} data-step={step.n}>
      <span className="lab-guide-n"><Footprints size={15} aria-hidden="true" />{w.step.replace("{n}", String(step.n)).replace("{total}", String(step.total))}</span>
      <p><b>{step.question}</b> {step.text}</p>
      <span className="lab-guide-go">
        {step.back && <a className="ua-btn" href={step.back}><ArrowLeft size={14} />{w.back}</a>}
        <a className="ua-btn" data-kind="primary" href={step.next}>{step.n === step.total ? w.finish : w.next}{step.n < step.total && <ArrowRight size={14} />}</a>
        <a className="lab-guide-end" href={labHref(lab, Object.fromEntries(rest))} title={w.end} aria-label={w.end}><X size={15} /></a>
      </span>
    </aside>
  );
}
