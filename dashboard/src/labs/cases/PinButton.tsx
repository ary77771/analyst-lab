// A "Pin to case" button any lab can drop in: pins to the open case (starting one when none is open).
import { useState } from "react";
import { Check, Pin } from "lucide-react";
import { pinTo, type PinInput } from "./pin";
import "./cases.css";

export function PinButton({ pin, label = "Pin to case", compact = false }: { pin: PinInput; label?: string; compact?: boolean }) {
  const [state, setState] = useState<{ done?: string; error?: string; busy?: boolean }>({});
  const click = () => {
    setState({ busy: true });
    pinTo(pin).then((c) => setState({ done: c.title })).catch((e) => setState({ error: String(e instanceof Error ? e.message : e) }));
  };
  const title = state.done ? `Pinned to “${state.done}”` : state.error ? `Could not pin: ${state.error}` : label;
  return (
    <button type="button" className={compact ? "cs-icon pv-pin" : "ua-btn cs-small pv-pin"} onClick={click} disabled={state.busy}
      title={title} aria-label={title} data-done={state.done ? "1" : undefined}>
      {state.done ? <Check size={14} /> : <Pin size={14} />}
      {!compact && <span>{state.done ? "Pinned" : label}</span>}
    </button>
  );
}
