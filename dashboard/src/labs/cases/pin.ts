// Pinning evidence to a case from any lab (night-pivot, 2026-11-23).
//
// Another lab can pin without importing anything, by opening
//   #/labs/cases?pin=alert&ref=<alert id>&label=<a few words>[&time=<ISO>][&kind=<entity kind>]
// (pin = alert | event | entity | hypothesis; for an entity, ref = its value and kind = program/file/hash/...).
// A lab in this build may also import `pinTo` / `pinHref` from here.
import { labsBackend, runName } from "../registry";
import { getJsonPatient } from "../_things/net";

export type PinType = "alert" | "event" | "entity" | "hypothesis";
export interface PinInput {
  type: PinType;
  ref: string;
  label: string;
  time?: string | null;
  kind?: string | null;       // an entity's kind (program, file, hash, ip, domain, registry, user, process)
  host?: string | null;
}
export interface CaseRow { id: string; title: string; created: string; updated: string; pins: number; notes: number; draft?: boolean }

/** How long an untouched draft stays "just started" (a pin may go into it); after that it is a leftover. */
export const LEFTOVER_MS = 10 * 60 * 1000;

/** A leftover draft (VISION critique-4): a draft nobody touched for LEFTOVER_MS. A pin never lands in one: it
 *  starts a new case named after what is pinned instead. Nothing is deleted. */
export function isLeftover(row: CaseRow | undefined | null, now = Date.now()): boolean {
  if (!row || !row.draft) return false;
  const t = Date.parse(row.updated);
  return Number.isFinite(t) && now - t > LEFTOVER_MS;
}

/** The cases the list shows: drafts (an automatic title, at most one pin, nothing written) only when asked
 *  for, or when one is the open or the active case. Nothing is ever removed from the store. */
export function visibleCases(rows: CaseRow[], showDrafts: boolean, open: string | null, active: string | null): CaseRow[] {
  return rows.filter((r) => showDrafts || !r.draft || r.id === open || r.id === active);
}

const ACTIVE_KEY = "analystlab.cases.active";

export function activeCase(store: Pick<Storage, "getItem"> | null = typeof localStorage === "undefined" ? null : localStorage): string | null {
  try { return store?.getItem(ACTIVE_KEY) || null; } catch { return null; }
}

export function setActiveCase(id: string | null, store: Pick<Storage, "setItem" | "removeItem"> | null = typeof localStorage === "undefined" ? null : localStorage) {
  try { if (id) store?.setItem(ACTIVE_KEY, id); else store?.removeItem(ACTIVE_KEY); } catch { /* the choice is a convenience only */ }
}

/** The address that pins `p` to the open case (and opens the case board). */
export function pinHref(p: PinInput): string {
  const q = new URLSearchParams({ pin: p.type, ref: p.ref, label: p.label });
  if (p.time) q.set("time", p.time);
  if (p.kind) q.set("kind", p.kind);
  if (p.host) q.set("host", p.host);
  return `#/labs/cases?${q.toString()}`;
}

/** A pin read back from a #/labs/cases?pin=... address, or null when the address holds none. */
export function pinFromParams(params: URLSearchParams): PinInput | null {
  const type = params.get("pin") as PinType | null;
  const ref = params.get("ref");
  if (!type || !ref || !["alert", "event", "entity", "hypothesis"].includes(type)) return null;
  return { type, ref, label: params.get("label") || ref, time: params.get("time"), kind: params.get("kind"), host: params.get("host") };
}

async function json<T>(r: Response): Promise<T> {
  if (!r.ok) throw new Error(String((await r.json().catch(() => null))?.detail ?? `${r.status} ${r.statusText}`));
  return (await r.json()) as T;
}

export const casesApi = {
  list: () => getJsonPatient<CaseRow[]>("/api/labs/cases"),       // asks again while the server restarts
  create: (title: string) =>
    fetch("/api/labs/cases", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title }) })
      .then((r) => json<{ id: string; title: string }>(r)),
  pin: (caseId: string, p: PinInput) =>
    fetch(`/api/labs/cases/${encodeURIComponent(caseId)}/pins`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(p),
    }).then((r) => json<{ id: string; case: { id: string; title: string } }>(r)),
};

/** The test run this dashboard shows, by its everyday name ("S1 · Download and run"), or null (a live
 *  dashboard, or no name). From the dashboard's own mode line and the Labs back end's run names. */
export async function runTitle(): Promise<string | null> {
  try {
    const [mode, labs] = await Promise.all([
      fetch("/api/mode").then((r) => (r.ok ? r.json() : null)).catch(() => null) as Promise<{ detail?: string | null } | null>,
      labsBackend(),
    ]);
    const id = /^\s*([A-Za-z]+\d+[a-z]?)\b/.exec(mode?.detail ?? "")?.[1];
    return id ? runName(id, labs?.run_names ?? null) : null;
  } catch {
    return null;
  }
}

/** The title of a case started by pinning `p`: the run and the alert for an alert ("S1 · Download and run:
 *  <alert title>"), the run and the thing otherwise; the date only when nothing better is known. */
export function caseTitle(p: PinInput, run: string | null, now = new Date()): string {
  const what = p.label;
  const cut = (s: string) => (s.length > 110 ? `${s.slice(0, 109)}…` : s);
  if (run) return cut(`${run}: ${what}`);
  if (p.type === "alert") return cut(what);
  return `Case ${now.toISOString().slice(0, 16).replace("T", " ")}`;
}

/** Pin to the open case; with none open (or the open one gone), start a new one first, named after what is
 *  pinned (caseTitle). Returns the case's id and title. */
export async function pinTo(p: PinInput, newTitle?: string): Promise<{ id: string; title: string }> {
  let id = activeCase();
  if (id) {
    // the open case is a leftover draft (an untouched "Untitled case" from earlier): start a new one instead
    const row = (await casesApi.list().catch(() => [] as CaseRow[])).find((c) => c.id === id);
    if (isLeftover(row)) id = null;
  }
  if (id) {
    try {
      return (await casesApi.pin(id, p)).case;
    } catch (e) {
      const open = id;
      if ((await casesApi.list()).some((c) => c.id === open)) throw e;   // the case is there: the pin itself failed
    }
  }
  const c = await casesApi.create(newTitle ?? caseTitle(p, await runTitle()));
  setActiveCase(c.id);
  return (await casesApi.pin(c.id, p)).case;
}
