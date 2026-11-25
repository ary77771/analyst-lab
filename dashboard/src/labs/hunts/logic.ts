// Pure helpers shared by the night-hunt Labs pages (hunts, rarity, persistence, network, gaps).
// No React here, so vitest can check them without a browser.

export const WINDOWS = ["1h", "6h", "24h", "7d", "30d", "all"] as const;
export type WindowName = (typeof WINDOWS)[number];

export const WINDOW_WORDS: Record<WindowName, string> = {
  "1h": "last hour", "6h": "last 6 hours", "24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days", all: "everything",
};

/** The Sysmon field a hunt row names -> the pivot page's own `kind` (night-pivot: engine/labs/pivot.py KINDS).
 *  Fields with no kind there are not linked. */
export const PIVOT_KINDS: Record<string, string> = {
  Image: "program", ProcessGuid: "process", TargetFilename: "file", sha256: "hash", DestinationIp: "ip",
  DestinationHostname: "domain", TargetObject: "registry",
};
export const PIVOT_FIELDS = Object.keys(PIVOT_KINDS);

/** Link to the pivot page: #/labs/pivot?kind=program&value=C%3A%5C...[&host=...] (night-pivot's documented form). */
export function pivotHref(field: string, value: unknown, host?: string | null): string | null {
  const kind = PIVOT_KINDS[field];
  if (value === null || value === undefined || value === "" || !kind) return null;
  const q = new URLSearchParams({ kind, value: String(value) });
  if (host) q.set("host", host);
  return `#/labs/pivot?${q.toString()}`;
}

/** Pin a thing to the open case on night-pivot's case board (their documented address, no import):
 *  #/labs/cases?pin=entity&kind=<kind>&ref=<value>&label=<few words>[&time=][&host=]. */
export function pinHref(field: string, value: unknown, label: string, time?: string | null, host?: string | null): string | null {
  const kind = PIVOT_KINDS[field];
  if (value === null || value === undefined || value === "" || !kind) return null;
  const q = new URLSearchParams({ pin: "entity", kind, ref: String(value), label: label.slice(0, 80) });
  if (time) q.set("time", time);
  if (host) q.set("host", host);
  return `#/labs/cases?${q.toString()}`;
}

/** The query part of a hash like "#/labs/hunts?hunt=autostart&window=7d". */
export function hashParams(hash: string): URLSearchParams {
  const i = hash.indexOf("?");
  return new URLSearchParams(i < 0 ? "" : hash.slice(i + 1));
}

/** The same hash with some query values replaced (null removes one); the path part is kept. */
export function withParams(hash: string, values: Record<string, string | null | undefined>): string {
  const i = hash.indexOf("?");
  const path = i < 0 ? hash : hash.slice(0, i);
  const q = hashParams(hash);
  for (const [k, v] of Object.entries(values)) {
    if (v === null || v === undefined || v === "") q.delete(k);
    else q.set(k, v);
  }
  const s = q.toString();
  return s ? `${path}?${s}` : path;
}

export function isWindow(x: string | null): x is WindowName {
  return !!x && (WINDOWS as readonly string[]).includes(x);
}

/** "2026-11-01T09:10:05.1234567Z" -> "1 Nov 09:10:05" (UTC, as recorded). */
export function shortTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  const m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2}:\d{2})/.exec(iso);
  if (!m) return iso;
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${Number(m[3])} ${months[Number(m[2]) - 1]} ${m[4]}`;
}

/** The last part of a Windows path. */
export function fileName(path: unknown): string {
  return String(path ?? "").replace(/\//g, "\\").split("\\").pop() ?? "";
}

/** "1 program" / "2 programs" (the word only; the number is shown apart). */
export function plural(n: number | null | undefined, one: string, many = `${one}s`): string {
  return n === 1 ? one : many;
}

/** "1 234" style thousands for big counts. */
export function count(n: number | null | undefined): string {
  if (n === null || n === undefined) return "-";
  return n.toLocaleString("en-GB");
}

/** Query string for the Python API from the page's state. */
export function apiQuery(p: { window?: string; start?: string | null; end?: string | null; host?: string | null; include_own?: boolean; [k: string]: unknown }): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(p)) {
    if (v === null || v === undefined || v === "" || v === false) continue;
    q.set(k, String(v));
  }
  return q.toString();
}
