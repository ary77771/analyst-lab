// <Thing/>: any program, run, file, fingerprint, address, domain, registry key or user, as a chip that opens
// Pivot on it (night-pivot, W3-4). Values that cannot be pivoted on (empty, "-", the zero parent id) show as
// plain text, never as a link.
//
//   <Thing kind="hash" value={sha} />                      the pivot kind
//   <Thing field="Image" value={row.Image} />              or the Sysmon field the lab has
//   <Thing field="TargetFilename" value={p} count={12} host={h} plusCase />   with a count, a host, and "+ case"
import { AppWindow, Cpu, Crosshair, FileText, Fingerprint, Globe, KeyRound, Network, User } from "lucide-react";
import { PlusCase } from "./PlusCase";
import { thingHref, thingKind, thingShort, thingValue } from "./things";
import "./things.css";

const ICON: Record<string, typeof Cpu> = {
  program: AppWindow, process: Cpu, file: FileText, hash: Fingerprint, ip: Network, domain: Globe, registry: KeyRound, user: User,
};

export interface ThingProps {
  kind?: string | null; field?: string | null; value: unknown;
  /** what it is to the row, shown on hover ("parent program", "remote address", ...) */
  role?: string; count?: number | null; host?: string | null;
  /** the text to show instead of the short name */
  label?: string; current?: boolean;
  /** add a "+ case" button that pins this thing */
  plusCase?: boolean;
}

export function Thing({ kind, field, value, role, count, host, label, current, plusCase }: ThingProps) {
  const k = thingKind(kind, field);
  const v = thingValue(k, value);
  if (v === null || !k) {
    const raw = value === null || value === undefined ? "" : String(value);
    return raw ? <span className="th-chip" data-plain="1" title={raw}><span>{label ?? raw}</span></span> : null;
  }
  const Icon = ICON[k] ?? Crosshair;
  const chip = (
    <a className="th-chip" data-kind={k} data-current={current ? "1" : undefined} href={thingHref(k, v, host)!}
      title={`${role ? `${role}: ` : ""}${v} (open in Pivot)`}>
      <Icon size={13} aria-hidden="true" />
      <span>{label ?? thingShort(k, v)}</span>
      {typeof count === "number" && <em className="num">{count}</em>}
    </a>
  );
  if (!plusCase) return chip;
  return <span className="th-with-case">{chip}<PlusCase kind={k} value={v} label={v} host={host} /></span>;
}
