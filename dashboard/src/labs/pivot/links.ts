// Pure helpers of the pivot lab (no React): addresses, short names, the trail of earlier pivots.
// Tested in links.test.ts.

export type Kind = "program" | "process" | "file" | "hash" | "ip" | "domain" | "registry" | "user";
export const KINDS: Kind[] = ["program", "file", "hash", "ip", "domain", "registry", "user", "process"];

export interface Entity { kind: Kind; value: string; role?: string; events?: number | null }

/** "#/labs/pivot?kind=hash&value=..." (the same shape as the registry's labHref). */
export function pivotHref(kind: string, value: string): string {
  const q = new URLSearchParams({ kind, value });
  return `#/labs/pivot?${q.toString()}`;
}

/** What to call a thing in a small chip: a path's last part, the first 12 hex of a fingerprint, ... */
export function shortName(kind: string, value: string): string {
  if (kind === "program" || kind === "file") return value.split(/[\\/]/).filter(Boolean).pop() ?? value;
  if (kind === "hash") return value.length > 16 ? `${value.slice(0, 12)}…` : value;
  if (kind === "registry") {
    const parts = value.split("\\").filter(Boolean);
    return parts.length > 2 ? `…\\${parts.slice(-2).join("\\")}` : value;
  }
  if (kind === "process") return value.replace(/[{}]/g, "").slice(0, 8);
  return value;
}

/** "2026-10-22 10:00:05 UTC" from an ISO time (the store's own clock is UTC). */
export function utc(t: string | null | undefined): string {
  if (!t) return "?";
  return `${t.slice(0, 10)} ${t.slice(11, 19)} UTC`;
}

const TRAIL_KEY = "analystlab.pivot.trail";
const same = (a: Entity, b: Entity) => a.kind === b.kind && a.value.toLowerCase() === b.value.toLowerCase();

/** The trail after visiting `e`: newest last, no repeats (a revisit moves it to the end), at most `max`. */
export function nextTrail(trail: Entity[], e: Entity, max = 8): Entity[] {
  const kept = trail.filter((t) => !same(t, e)).map(({ kind, value }) => ({ kind, value }));
  return [...kept, { kind: e.kind, value: e.value }].slice(-max);
}

export function loadTrail(store: Pick<Storage, "getItem"> | null = typeof sessionStorage === "undefined" ? null : sessionStorage): Entity[] {
  try {
    const raw = store?.getItem(TRAIL_KEY);
    const v = raw ? JSON.parse(raw) : [];
    return Array.isArray(v) ? v.filter((x) => x && typeof x.kind === "string" && typeof x.value === "string") : [];
  } catch {
    return [];
  }
}

export function saveTrail(trail: Entity[], store: Pick<Storage, "setItem"> | null = typeof sessionStorage === "undefined" ? null : sessionStorage) {
  try { store?.setItem(TRAIL_KEY, JSON.stringify(trail)); } catch { /* private mode: the trail is a convenience only */ }
}

/** Group linked things by kind, in the lab's kind order, each group as given (most events first). */
export function groupByKind<T extends { kind: string }>(items: T[]): [string, T[]][] {
  const groups = new Map<string, T[]>();
  for (const k of KINDS) groups.set(k, []);
  for (const it of items) (groups.get(it.kind) ?? groups.set(it.kind, []).get(it.kind)!).push(it);
  return [...groups.entries()].filter(([, v]) => v.length > 0);
}

/** The query of a "#/labs/<id>?..." address, exactly as written (not yet decoded): URLSearchParams then decodes
 *  it once. (The shell hands labs a param it has already decoded, which breaks values holding & + % or =.) */
export function rawQuery(hash: string): string {
  const at = hash.indexOf("?");
  return at < 0 ? "" : hash.slice(at + 1);
}

/** Other labs may link with the Sysmon field name instead of the kind (night-hunt: field=Image&value=...). */
export const FIELD_KIND: Record<string, Kind> = {
  processguid: "process", image: "program", parentimage: "program", sha256: "hash", hashes: "hash",
  destinationip: "ip", sourceip: "ip", destinationhostname: "domain", queryname: "domain",
  targetfilename: "file", targetobject: "registry", user: "user",
};

/** The kind asked for: `kind=`, else the kind of `field=`, else null. */
export function kindFrom(q: URLSearchParams): string | null {
  return q.get("kind") ?? FIELD_KIND[(q.get("field") ?? "").toLowerCase()] ?? null;
}
