// End-to-end check that `night` does not break the screens Yousif rehearsed (night-tools, 2026-11-24; PROOF's request).
//
//   npm run e2e:rehearsed                      # rehearsed build on 8787, night on 8786
//   npm run e2e:rehearsed -- --rehearsed http://127.0.0.1:8787 --night http://127.0.0.1:8786 [--out <folder>]
//
// Two copies of the same S1 replay side by side: the REHEARSED front end (wt\dash's static build, never rebuilt)
// and NIGHT. It opens the rehearsed screens on both, the same way and at the same moment of the film:
//   Watch (the replay has reached the alert), Story (the S1 alert, its film moved to its last step),
//   Proof (its first view, once its numbers stop counting up), and the Tour's opening bubble
// and compares what a visitor SEES: every visible line of the page in order (headings, numbers, button labels,
// counts, the story's lines), plus the story's lines on their own. Each line that is on one side only is
// either a KNOWN change of night (listed in KNOWN below, with why) or a REGRESSION. Tooltips are not visible
// text, so they never count. Paired screenshots and report.md / report.json go to docs/night/shots/e2e-rehearsed/;
// exit code 1 = at least one regression; 2 = inconclusive (a dashboard restarted during the check, or it broke).
// The Watch screen's honesty-checks panel depends on the machine (is the test VM running, could the dashboard
// count its checks at start-up): when the two differ in exactly that, the panel is compared apart, in a note.
//
// Read-only: the browser refuses every request other than GET, on both dashboards.
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..", "..");

const opt = { rehearsed: "http://127.0.0.1:8787", night: "http://127.0.0.1:8786",
              out: path.join(REPO, "docs", "night", "shots", "e2e-rehearsed"),
              title: "Program connected out, wrote an executable, and it was started", wait: 300 };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a === "--rehearsed") opt.rehearsed = process.argv[++i].replace(/\/+$/, "");
  else if (a === "--night") opt.night = process.argv[++i].replace(/\/+$/, "");
  else if (a === "--out") opt.out = path.resolve(process.argv[++i]);
  else if (a === "--alert-title") opt.title = process.argv[++i];
  else if (a === "--wait") opt.wait = Number(process.argv[++i]);
}

// What night is EXPECTED to show differently (PROOF's list, 2026-11-24). A line on one side only that matches
// one of these is "known"; anything else is a regression. `side`: where the line is expected ("night" = only
// on night, "rehearsed" = only on the rehearsed build, "either").
export const KNOWN = [
  { name: "the Labs entry", side: "night", test: (l) => /^Labs$/.test(l) },
  { name: "the Tour button", side: "night", test: (l) => /^Tour$/.test(l) },
  { name: "Story's S1 / other labels", side: "night",
    test: (l) => /^Raised on .+'s own programs$|^Raised on another program|^other$|^S\d+(?: · .+)?$/.test(l) },
  { name: "the Proof switch row", side: "night", test: (l) => /^(Earlier|Newest|All|Latest) tests$|^Show:?$/.test(l) },
  { name: "the first-load text", side: "either", test: (l) => /^Loading|^…$|^Asking the engine|^One moment/.test(l) },
  // the Watch screen's own clock: seconds since the replay began, so it depends on when each page was opened
  { name: "the run clock (depends on when the page was opened)", side: "either", test: (l) => /^\d{1,2}:\d{2}(?::\d{2})?$/.test(l) },
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function health(base) {
  const r = await fetch(`${base}/api/health`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

/** Both replays at the alert and quiet (no new record for the dashboard's own quiet time), so both Watch
 *  screens show the same moment. */
async function waitQuiet() {
  const until = Date.now() + opt.wait * 1000;
  let why = "";
  while (Date.now() < until) {
    try {
      const [a, b] = await Promise.all([health(opt.rehearsed), health(opt.night)]);
      const at = (h) => h.alert?.title === opt.title || (h.view_ids || []).length > 0;
      const quiet = (h) => h.seconds == null || h.seconds >= (h.quiet_after_s ?? 90);
      if (at(a) && at(b) && quiet(a) && quiet(b)) return { rehearsed: a, night: b };
      why = `rehearsed ${a.records} records, ${a.seconds} s quiet; night ${b.records} records, ${b.seconds} s quiet`;
    } catch (e) { why = String(e.cause?.code ?? e.message ?? e); }
    process.stdout.write(`waiting for both replays to reach the alert and go quiet (${why})\n`);
    await sleep(5000);
  }
  throw new Error(`the replays did not settle within ${opt.wait} s (${why})`);
}

async function launch() {
  try { return { browser: await chromium.launch({ channel: "msedge", headless: true }), name: "Edge" }; }
  catch { return { browser: await chromium.launch({ headless: true }), name: "Chromium" }; }
}

/** The visible lines of the page, trimmed, empty ones dropped. */
const linesOf = (text) => text.split("\n").map((l) => l.replace(/\s+/g, " ").trim()).filter(Boolean);

/** Longest-common-subsequence diff of two line lists: [{op: "=", "-", "+", line}] ("-" rehearsed only, "+" night only). */
export function diffLines(a, b) {
  const n = a.length, m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push({ op: "=", line: a[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) out.push({ op: "-", line: a[i++] });
    else out.push({ op: "+", line: b[j++] });
  }
  while (i < n) out.push({ op: "-", line: a[i++] });
  while (j < m) out.push({ op: "+", line: b[j++] });
  return out;
}

/** Each one-sided line, named known (with which known change) or a regression. */
export function classify(diff) {
  const known = [], regressions = [];
  for (const d of diff) {
    if (d.op === "=") continue;
    const side = d.op === "+" ? "night" : "rehearsed";
    const k = KNOWN.find((x) => (x.side === side || x.side === "either") && x.test(d.line));
    (k ? known : regressions).push({ side, line: d.line, ...(k ? { known: k.name } : {}) });
  }
  return { known, regressions };
}

async function main() {
  mkdirSync(opt.out, { recursive: true });
  const settled = await waitQuiet();
  const alertId = settled.rehearsed.alert?.id ?? settled.rehearsed.view_ids[0];
  if ((settled.night.alert?.id ?? settled.night.view_ids[0]) !== alertId) throw new Error("the two replays show different alerts");
  const { browser, name } = await launch();
  const began = Date.now();

  async function side(base) {
    const ctx = await browser.newContext({ viewport: { width: 1463, height: 914 }, deviceScaleFactor: 1.75, colorScheme: "dark" });
    const refused = [];
    await ctx.route("**/*", (route) => {
      const m = route.request().method();
      if (m === "GET" || m === "HEAD" || m === "OPTIONS") return route.continue();
      refused.push(`${m} ${new URL(route.request().url()).pathname}`);
      return route.abort("blockedbyclient");
    });
    const page = await ctx.newPage();
    const errors = [];
    page.on("console", (msg) => {
      if (msg.type() !== "error") return;
      const where = msg.location()?.url || "";
      // the replay page asks the LIVE dashboard (8780) for its health: not running here, not this screen's fault
      if (where && !where.startsWith(base) && /\/api\/(health|mode|peer)\b/.test(where)) return;
      errors.push(`${msg.text().slice(0, 200)}${where ? ` (${where.replace(base, "")})` : ""}`);
    });
    page.on("pageerror", (e) => errors.push(`page error: ${String(e).slice(0, 200)}`));
    return { base, ctx, page, errors, refused };
  }
  const R = await side(opt.rehearsed), N = await side(opt.night);

  /** Wait until the page's visible text stops changing (counters counting up, a film moving). */
  async function steady(p, ms = 30000) {
    await p.waitForLoadState("networkidle", { timeout: ms }).catch(() => {});
    const until = Date.now() + ms;
    let last = null, same = 0;
    while (Date.now() < until && same < 3) {
      const t = await p.evaluate(() => document.body.innerText);
      same = t === last ? same + 1 : 0;
      last = t;
      await p.waitForTimeout(700);
    }
    return same >= 3;
  }

  const screens = [];
  const BUSY = /^Not while the test machine is running/;
  let n = 0;
  /** `extract` (run in the page) gives the screen's own lines (the story's lines); with `only`, those lines are
   *  all that is compared (the Tour: its bubble, not the page under it). */
  async function compare(key, title, open, extract = null, only = false) {
    n += 1;
    let shots, texts, parts, panels, notes;
    const looks = [];
    // The honesty-checks panel follows the REAL test machine: each dashboard asks VirtualBox whether the VM runs
    // and keeps the answer 10 s (engine/dashboard/checks.py vm_running). While the VM starts or stops, the two
    // pages can disagree for a few seconds: then both are looked at again (up to 3 times).
    for (let attempt = 1; attempt <= 3; attempt++) {
      ({ shots, texts, parts, panels, notes } = await capture(key, open, extract, only));
      const busy = ["rehearsed", "night"].map((l) => texts[l].some((x) => BUSY.test(x)));
      if (busy[0] === busy[1]) break;
      looks.push(`the test machine's state differed between the two pages (look ${attempt} of 3)`);
      if (attempt < 3) await sleep(12000);
    }
    finish(key, title, shots, texts, parts, panels, [...looks, ...notes], await panelSkew(panels));
  }

  async function capture(key, open, extract, only) {
    const shots = {}, texts = {}, parts = {}, panels = {}, notes = [];
    for (const [label, s] of [["rehearsed", R], ["night", N]]) {
      const before = s.errors.length;
      const ok = await open(s, label);
      const stable = ok === false ? false : await steady(s.page);
      if (!stable) notes.push(`${label}: the page kept changing for 30 s`);
      const file = `${String(n).padStart(2, "0")}-${key}-${label}.png`;
      await s.page.screenshot({ path: path.join(opt.out, file) });
      shots[label] = file;
      parts[label] = extract && ok !== null ? await s.page.evaluate(extract) : null;
      texts[label] = ok === null ? [] : only ? linesOf((parts[label] || []).join("\n"))
        : linesOf(await s.page.evaluate(() => document.body.innerText));
      // the honesty-checks panel's own lines (Watch), kept apart in case its state is the machine's, not night's
      panels[label] = ok === null || only ? [] : linesOf(await s.page.evaluate(() => document.querySelector(".ck-ring")?.closest(".ua-panel")?.innerText ?? ""));
      if (only) parts[label] = null;
      if (s.errors.length > before) notes.push(...s.errors.slice(before).map((e) => `${label} console: ${e}`));
    }
    return { shots, texts, parts, panels, notes };
  }

  /** The honesty-checks panel depends on the machine, not only on the code: whether VirtualBox says the test VM
   *  runs (each dashboard asks on its own 10 s clock), and whether the dashboard could count its checks (only
   *  once, after it starts, and never while the VM runs). When the two dashboards differ in exactly that, the
   *  panel is compared apart and said in a note; every other line is judged as usual. */
  async function panelSkew(panels) {
    const same = panels.rehearsed.join("\n") === panels.night.join("\n");
    if (same || !panels.rehearsed.length || !panels.night.length) return null;
    const busy = ["rehearsed", "night"].map((l) => panels[l].some((x) => BUSY.test(x)));
    let counted = [null, null];
    try {
      counted = await Promise.all([opt.rehearsed, opt.night].map(async (b) => (await (await fetch(`${b}/api/checks`)).json()).total != null));
    } catch { /* unknown: judged as usual */ }
    if (busy[0] === busy[1] && counted[0] === counted[1]) return null;
    return `the honesty-checks panel differs because of the machine, not the code (test VM running according to: rehearsed ${busy[0] ? "yes" : "no"}, ` +
      `night ${busy[1] ? "yes" : "no"}; checks counted at start-up: rehearsed ${counted[0] ? "yes" : "no"}, night ${counted[1] ? "yes" : "no"}); ` +
      `compared apart: rehearsed "${panels.rehearsed.slice(0, 3).join(" / ")}…", night "${panels.night.slice(0, 3).join(" / ")}…"`;
  }

  /** `lines` without the contiguous run `sub` (the panel), or unchanged when it isn't there. */
  const without = (lines, sub) => {
    if (!sub.length) return lines;
    for (let i = 0; i + sub.length <= lines.length; i++) if (sub.every((x, k) => lines[i + k] === x)) return [...lines.slice(0, i), ...lines.slice(i + sub.length)];
    return lines;
  };

  function finish(key, title, shots, texts, parts, panels, notes, skew) {
    if (skew) {
      texts = { rehearsed: without(texts.rehearsed, panels.rehearsed), night: without(texts.night, panels.night) };
      notes.push(skew);
    }
    const diff = diffLines(texts.rehearsed, texts.night);
    const { known, regressions } = classify(diff);
    const partsDiff = parts.rehearsed && parts.night ? classify(diffLines(parts.rehearsed, parts.night)) : null;
    if (partsDiff) for (const r of partsDiff.regressions) regressions.push({ ...r, line: `[story line] ${r.line}` });
    for (const x of notes.filter((x) => / console: /.test(x))) regressions.push({ side: x.split(" ")[0], line: x });
    screens.push({ key, title, shots, lines: { rehearsed: texts.rehearsed.length, night: texts.night.length, same: diff.filter((d) => d.op === "=").length },
                   storyLines: parts.night ? { rehearsed: parts.rehearsed, night: parts.night } : undefined, known, regressions, notes });
  }

  /** One screen's line in the console (after the Tour's own rule below has run). */
  const say = (s) => {
    process.stdout.write(`${s.regressions.length ? "REGRESSION" : "same      "} ${s.title}: ${s.lines.same} lines alike, ` +
      `${s.known.length} known change(s), ${s.regressions.length} regression(s)\n`);
    for (const r of s.regressions) process.stdout.write(`    ${r.side === "night" ? "+ night only:    " : "- rehearsed only:"} ${r.line}\n`);
  };

  try {
    // 1. Watch: the replay has reached the alert
    await compare("watch", "Watch", async (s) => {
      await s.page.goto(`${s.base}/#a/watch`);
      await s.page.waitForFunction((t) => document.body.innerText.includes(t), opt.title, { timeout: 60000 }).catch(() => {});
    });
    // 2. Story of the S1 alert: the film moved to its last step (End), so both show the same frame
    await compare("story", "Story (S1 alert, film at its last step)", async (s) => {
      await s.page.goto(`${s.base}/#a/story/${encodeURIComponent(alertId)}`);
      await s.page.waitForSelector(".film", { timeout: 60000 }).catch(() => {});
      await s.page.waitForTimeout(1500);
      await s.page.keyboard.press("End");
      await s.page.waitForTimeout(1500);
    }, () => [...document.querySelectorAll(".ua-report .ua-report-text")].map((e) => e.innerText.replace(/\s+/g, " ").trim()));
    // 3. Proof, first view, once its numbers have counted up
    await compare("proof", "Proof (first view)", async (s) => {
      await s.page.goto(`${s.base}/#a/proof`);
      await s.page.waitForTimeout(2000);
    });
    // 4. The Tour's opening: its button, then the first bubble
    await compare("tour", "Tour (opening bubble)", async (s, label) => {
      await s.page.goto(`${s.base}/#a/watch`);
      await steady(s.page);
      const btn = s.page.locator("button.ua-tourbtn");
      if (!(await btn.count())) return null;                 // no Tour in this build: nothing to compare
      await btn.first().click();
      await s.page.waitForSelector(".tour-bubble", { timeout: 15000 }).catch(() => {});
    }, () => [...document.querySelectorAll(".tour-bubble")].map((e) => e.innerText), true);
    // the Tour is night's own (PROOF: "the Tour button" is a known change): a side without it is known, not lost
    const tour = screens.find((s) => s.key === "tour");
    if (tour && tour.lines.rehearsed === 0) {
      tour.known.push(...tour.regressions.filter((r) => r.side === "night").map((r) => ({ ...r, known: "the Tour (new on night)" })));
      tour.regressions = tour.regressions.filter((r) => r.side !== "night");
      tour.notes.push("the rehearsed build has no Tour: night's Tour is new, shown for reference");
    }
  } finally {
    await browser.close();
  }
  screens.forEach(say);

  // A dashboard restarted during the check plays its replay again: its pages showed a replay mid-way (the Watch
  // tally, for one, keeps the count of the moment the alert landed). Such a run proves nothing either way.
  const restarted = [];
  const took = (Date.now() - began) / 1000;
  for (const [label, base] of [["rehearsed", opt.rehearsed], ["night", opt.night]]) {
    try {
      const h = await health(base);
      if (h.records !== settled[label].records || (h.seconds ?? 0) < (settled[label].seconds ?? 0) + took - 30) restarted.push(label);
    } catch { restarted.push(label); }
  }
  const regressions = screens.reduce((k, s) => k + s.regressions.length, 0);
  const refused = [...R.refused, ...N.refused];
  const report = { when: new Date().toISOString(), browser: name, rehearsed: opt.rehearsed, night: opt.night, alert: { id: alertId, title: opt.title },
                   records: { rehearsed: settled.rehearsed.records, night: settled.night.records }, refused, screens, regressions,
                   restarted_during_check: restarted, conclusive: restarted.length === 0,
                   known_rules: KNOWN.map((k) => k.name) };
  writeFileSync(path.join(opt.out, "report.json"), JSON.stringify(report, null, 1) + "\n");
  const md = [`# Rehearsed screens: night vs the rehearsed build (${report.when.slice(0, 19)} UTC)`, "",
    `Rehearsed: ${opt.rehearsed} (wt\\dash's static build) · night: ${opt.night} · ${name} 1463 x 914 at 175 % · the S1 replay ` +
    `(${settled.rehearsed.records} / ${settled.night.records} records), alert "${opt.title}" (${alertId}).`, "",
    restarted.length ? `**INCONCLUSIVE: the ${restarted.join(" and ")} dashboard restarted during the check** (its replay played again); run it once more.` : null,
    `**${regressions ? `${regressions} REGRESSION(S)` : "No regression"}.** A line on one side only is either a known change of night or a regression.`, "",
    "| screen | lines alike | known changes | regressions | rehearsed | night |", "|---|---:|---:|---:|---|---|",
    ...screens.map((s) => `| ${s.title} | ${s.lines.same} of ${s.lines.rehearsed} / ${s.lines.night} | ${s.known.length} | ${s.regressions.length ? `**${s.regressions.length}**` : 0} | ${s.shots.rehearsed} | ${s.shots.night} |`), ""];
  for (const s of screens) {
    md.push(`## ${s.title}`, "");
    if (s.regressions.length) md.push("Regressions:", "", ...s.regressions.map((r) => `- **${r.side} only:** ${r.line}`), "");
    if (s.known.length) md.push("Known changes:", "", ...s.known.map((k) => `- ${k.side} only: \`${k.line}\` (${k.known})`), "");
    if (!s.regressions.length && !s.known.length) md.push("Identical visible text.", "");
    if (s.notes.length) md.push(...s.notes.map((x) => `- note: ${x}`), "");
  }
  md.push(refused.length ? `Refused requests (this check only reads): ${refused.join(", ")}` : "Read-only: no request other than GET was made.", "",
    "Known changes (PROOF's list): " + KNOWN.map((k) => k.name).join("; ") + ".", "");
  writeFileSync(path.join(opt.out, "report.md"), md.filter((x) => x !== null).join("\n"));
  if (restarted.length) process.stdout.write(`\nINCONCLUSIVE: the ${restarted.join(" and ")} dashboard restarted during the check; run it once more.\n`);
  process.stdout.write(`\n${regressions ? `${regressions} REGRESSION(S)` : "No regression"} · ${path.join(opt.out, "report.md")}\n`);
  process.exitCode = restarted.length ? 2 : regressions ? 1 : 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { console.error(e); process.exit(2); });
}
