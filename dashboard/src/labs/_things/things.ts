// Shared, pure helpers behind <Thing/> and <PlusCase/> (night-pivot, W3-4). No React: vitest checks them.
// Any lab may import from "../_things" (this folder has no index.tsx, so the Labs registry never lists it).

/** The pivot page's kinds (engine/labs/pivot.py KINDS). */
export const THING_KINDS = ["program", "process", "file", "hash", "ip", "domain", "registry", "user"] as const;
export type ThingKind = (typeof THING_KINDS)[number];

/** Sysmon / agent field names -> the pivot kind (so a lab can pass the column it has). */
export const FIELD_TO_KIND: Record<string, ThingKind> = {
  image: "program", parentimage: "program", originalfilename: "program", processguid: "process", parentprocessguid: "process",
  targetfilename: "file", final_path: "file", sha256: "hash", hashes: "hash", hash: "hash",
  destinationip: "ip", sourceip: "ip", localip: "ip", destinationhostname: "domain", queryname: "domain",
  targetobject: "registry", user: "user", parentuser: "user",
};

const ZERO_GUID = "{00000000-0000-0000-0000-000000000000}";

/** The pivot kind for a `kind` or a `field`; null when neither names one. */
export function thingKind(kind?: string | null, field?: string | null): ThingKind | null {
  if (kind && (THING_KINDS as readonly string[]).includes(kind)) return kind as ThingKind;
  if (field) return FIELD_TO_KIND[field.toLowerCase()] ?? null;
  return null;
}

/** A value worth pivoting on: not empty, not Sysmon's "-", not the all-zero "parent unknown" id. A
 *  "SHA256=...,MD5=..." Hashes string gives its SHA-256. */
export function thingValue(kind: ThingKind | null, value: unknown): string | null {
  if (value === null || value === undefined) return null;
  let v = String(value).trim();
  if (!v || v === "-" || v.toUpperCase() === ZERO_GUID) return null;
  if (kind === "hash") {
    const m = /SHA256=([0-9A-Fa-f]{64})/.exec(v);
    if (m) v = m[1];
    if (!/^[0-9A-Fa-f]{64}$/.test(v)) return null;
    v = v.toLowerCase();
  }
  return v;
}

/** "#/labs/pivot?kind=...&value=...[&host=...]", or null when it cannot be pivoted on. */
export function thingHref(kind: ThingKind | null, value: unknown, host?: string | null): string | null {
  const v = thingValue(kind, value);
  if (!kind || v === null) return null;
  const q = new URLSearchParams({ kind, value: v });
  if (host) q.set("host", host);
  return `#/labs/pivot?${q.toString()}`;
}

/** What to show in a small chip: a path's last part, the first 12 hex of a fingerprint, ... */
export function thingShort(kind: ThingKind | null, value: string): string {
  if (kind === "program" || kind === "file") return value.split(/[\\/]/).filter(Boolean).pop() ?? value;
  if (kind === "hash") return value.length > 16 ? `${value.slice(0, 12)}…` : value;
  if (kind === "registry") {
    const parts = value.split("\\").filter(Boolean);
    return parts.length > 2 ? `…\\${parts.slice(-2).join("\\")}` : value;
  }
  // a run's id ({machine-time-time-xxxx-counter}): the machine part is the same for every run and on a test machine
  // the last part can be too, so the middle (when the run began) tells runs apart
  if (kind === "process") {
    const parts = value.replace(/[{}]/g, "").toLowerCase().split("-");
    return parts.length === 5 ? `run ${parts[1]}${parts[2]}` : `run …${parts.join("").slice(-8)}`;
  }
  return value;
}

export type PinType = "alert" | "event" | "entity" | "hypothesis";
export interface PlusCaseInput {
  alert?: string | null; event?: string | null; hypothesis?: string | null;
  kind?: string | null; field?: string | null; value?: unknown;
  label?: string | null; time?: string | null; host?: string | null;
}

/** The case board's pin ({type, ref, label, kind, time, host}) for one of: alert=, event=, hypothesis=, or a
 *  thing (kind|field + value). Null when nothing pinnable was given. */
export function plusCasePin(p: PlusCaseInput): { type: PinType; ref: string; label: string; kind?: string | null; time?: string | null; host?: string | null } | null {
  const base = { time: p.time ?? null, host: p.host ?? null };
  if (p.alert) return { type: "alert", ref: p.alert, label: p.label || p.alert, ...base };
  if (p.event) return { type: "event", ref: p.event, label: p.label || p.event, ...base };
  if (p.hypothesis) return { type: "hypothesis", ref: p.hypothesis, label: p.label || p.hypothesis, ...base };
  const kind = thingKind(p.kind, p.field);
  const v = thingValue(kind, p.value);
  if (kind && v !== null) return { type: "entity", ref: v, kind, label: p.label || v, ...base };
  return null;
}
