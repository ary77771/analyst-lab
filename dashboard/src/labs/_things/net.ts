// Asking the dashboard's server, patiently (night-pivot, 2026-11-24; VISION critique-3: "Failed to fetch" for
// ~15 s after a restart). A server that does not answer at all (the browser's TypeError) is asked again every
// 2 s for a while; only then is it said, in the kit's own words (NO_ANSWER). An answer that is an error (404,
// 400, ...) is passed on at once: that is the lab's to show.
import { NO_ANSWER } from "../kit";

/** The plain reason to show for a failed request: never the browser's own "Failed to fetch". */
export function plainError(e: unknown): string {
  if (e instanceof TypeError) return NO_ANSWER;
  return String(e instanceof Error ? e.message : e);
}

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** GET JSON, asking again while the server does not answer (default: 12 tries, 2 s apart: ~24 s). */
export async function getJsonPatient<T>(url: string, tries = 12, wait = 2000, f: typeof fetch = fetch): Promise<T> {
  for (let i = 1; ; i++) {
    let r: Response;
    try {
      r = await f(url);
    } catch (e) {
      if (e instanceof TypeError && i < tries) { await pause(wait); continue; }
      throw e instanceof TypeError ? new Error(NO_ANSWER) : e;
    }
    if (!r.ok) throw new Error(String((await r.json().catch(() => null))?.detail ?? `${r.status} ${r.statusText}`));
    return (await r.json()) as T;
  }
}
