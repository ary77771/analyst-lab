// <PlusCase/>: a small "+ case" button that pins something to the open case on the case board (starting a case
// when none is open, named after what is pinned) without leaving the page, then confirms with a small toast that
// links to the case (night-pivot, W3-4; one click from the professor's path, 2026-11-24). Exactly one of:
//
//   <PlusCase alert={alertId} label={title} time={time} />     (no label: the alert's title is looked up first)
//   <PlusCase event={dedupKey} label={summary} time={time} />
//   <PlusCase kind="hash" value={sha} />    or    <PlusCase field="Image" value={path} />
//   <PlusCase hypothesis="the tool was copied in by the downloader" />
//
// `text` shows words next to the icon ("Pin to case"); without it the button is the compact "+ case".
import { useEffect, useState } from "react";
import { Check, Plus } from "lucide-react";
import { pinTo } from "../cases/pin";
import { plainError } from "./net";
import { plusCasePin, type PlusCaseInput } from "./things";
import "./things.css";

const TOAST_MS = 5000;

/** The alert's own title, for a pin given only the alert's id (so the case and the pin read in words). */
async function alertTitle(id: string): Promise<string | null> {
  try {
    const r = await fetch(`/api/labs/cases/alert/${encodeURIComponent(id)}`);
    return r.ok ? ((await r.json()) as { title?: string }).title ?? null : null;
  } catch {
    return null;
  }
}

export function PlusCase(props: PlusCaseInput & { text?: string; onPinned?: (c: { id: string; title: string }) => void }) {
  const pin = plusCasePin(props);
  const [state, setState] = useState<{ done?: { id: string; title: string }; error?: string; busy?: boolean }>({});
  const [toast, setToast] = useState(false);
  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => setToast(false), TOAST_MS);
    return () => window.clearTimeout(t);
  }, [toast]);
  if (!pin) return null;
  const click = async () => {
    setState({ busy: true });
    try {
      const p = pin.type === "alert" && !props.label ? { ...pin, label: (await alertTitle(pin.ref)) ?? pin.label } : pin;
      const c = await pinTo(p);
      setState({ done: c });
      setToast(true);
      props.onPinned?.(c);
    } catch (e) {
      setState({ error: plainError(e) });
    }
  };
  const what = pin.type === "entity" ? "thing" : pin.type;
  const title = state.done ? `Pinned to the case “${state.done.title}”` : state.error ? `Could not pin: ${state.error}`
    : `Pin this ${what} to the open case (or start one)`;
  return (
    <>
      <button type="button" className="th-plus" data-wide={props.text ? "1" : undefined} data-done={state.done ? "1" : undefined}
        data-error={state.error ? "1" : undefined} onClick={() => { void click(); }} disabled={state.busy} title={title} aria-label={title}>
        {state.done ? <Check size={13} aria-hidden="true" /> : <Plus size={13} aria-hidden="true" />}
        <span>{state.done ? "in case" : props.text ?? "case"}</span>
      </button>
      {toast && state.done && (
        <div className="th-toast" role="status">
          <Check size={15} aria-hidden="true" />
          <span>Pinned to <b>{state.done.title}</b></span>
          <a href={`#/labs/cases?case=${encodeURIComponent(state.done.id)}`}>Open the case</a>
        </div>
      )}
    </>
  );
}
