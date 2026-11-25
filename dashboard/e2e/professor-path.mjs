// End-to-end check of the professor's path through the Labs (night-tools, 2026-11-24; PROOF's request).
//
//   npm run e2e:path                         # against http://127.0.0.1:8786 (the night replay copy)
//   npm run e2e:path -- http://127.0.0.1:8781 [--out <folder>] [--alert-title "<title>"] [--wait 180]
//
// It drives Edge (or Chromium when Edge is missing) at 1463 x 914, 175 % like the demo laptop, and walks:
//   Labs page > checklist (the S1 alert) > why > moment > tree > prove > claim (every "Try these") > network >
//   respond > cases (pin the alert into a throwaway case, then the printable report)
// following docs/night/rehearsal-labs-path.md, by the same clicks: the Labs page's checklist card, the
// checklist's alert, then the strip of chips that carries the alert (NextStrip) from page to page.
//
// Every step is checked for: none of the failure words on the page, no console error, no page scrolling
// sideways, the strip present with every chip carrying ?alert=<the alert>, and nothing still loading. One
// screenshot per step goes to docs/night/shots/e2e/ with report.json and report.md. Exit code 1 = a check failed.
//
// It writes NOTHING except the case pin: every request other than GET is refused by the browser here, except
// (1) creating ONE case named "e2e check", (2) pinning the alert into that case, (3) deleting that case at the
// end through the case board's own route (DELETE /api/labs/cases/<id>, which moves it to cases/deleted).
// Before it starts it waits for the replay to reach the alert (GET /api/alerts).
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..", "..");

function args(argv) {
  const o = { base: "http://127.0.0.1:8786", out: path.join(REPO, "docs", "night", "shots", "e2e"),
              title: "Program connected out, wrote an executable, and it was started", wait: 180 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--out") o.out = path.resolve(argv[++i]);
    else if (a === "--alert-title") o.title = argv[++i];
    else if (a === "--wait") o.wait = Number(argv[++i]);
    else if (!a.startsWith("--")) o.base = a.replace(/\/+$/, "");
  }
  return o;
}

const opt = args(process.argv.slice(2));
const CASE_TITLE = "e2e check";
// the words a broken page shows (LabState "could not load its data", a missing alert, the app's error boundary,
// a dropped connection)
const BAD = /failed to load|could not load|isn't in this recording|something went wrong|failed to fetch|Internal Server Error/i;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Poll GET /api/alerts until the alert is there (a replay reaches it after a while). */
async function waitForAlert() {
  const until = Date.now() + opt.wait * 1000;
  let last = "";
  while (Date.now() < until) {
    try {
      const r = await fetch(`${opt.base}/api/alerts`);
      if (r.ok) {
        const a = (await r.json()).find((x) => x.title === opt.title);
        if (a) return a;
        last = "the replay hasn't reached it yet";
      } else last = `HTTP ${r.status}`;
    } catch (e) { last = String(e.cause?.code ?? e.message ?? e); }
    process.stdout.write(`waiting for the alert "${opt.title}" (${last})\n`);
    await sleep(3000);
  }
  throw new Error(`the alert "${opt.title}" did not appear within ${opt.wait} s (${last})`);
}

async function launch() {
  try { return { browser: await chromium.launch({ channel: "msedge", headless: true }), name: "Edge" }; }
  catch { return { browser: await chromium.launch({ headless: true }), name: "Chromium" }; }
}

async function main() {
  mkdirSync(opt.out, { recursive: true });
  const alert = await waitForAlert();
  const id = alert.id;
  const { browser, name } = await launch();
  const ctx = await browser.newContext({ viewport: { width: 1463, height: 914 }, deviceScaleFactor: 1.75, colorScheme: "dark" });

  // the write guard: only the throwaway case's own requests may change anything
  let caseId = null;
  const refused = [];
  await ctx.route("**/*", async (route) => {
    const req = route.request();
    const m = req.method();
    if (m === "GET" || m === "HEAD" || m === "OPTIONS") return route.continue();
    const u = new URL(req.url());
    const p = u.pathname;
    let ok = false;
    if (m === "POST" && p === "/api/labs/cases" && !caseId) {
      try { ok = JSON.parse(req.postData() || "{}").title === CASE_TITLE; } catch { ok = false; }
    } else if (caseId && m === "POST" && p === `/api/labs/cases/${caseId}/pins`) ok = true;
    if (!ok) { refused.push(`${m} ${p}`); return route.abort("blockedbyclient"); }
    return route.continue();
  });

  const page = await ctx.newPage();
  let errors = [];
  // The replay page asks the LIVE dashboard (8780, demo_mode.LIVE_DASHBOARD) for its health, for the small "live
  // raised an alert" notice. With no live dashboard running that request fails in the console on every page:
  // the other dashboard's state, not this path's; counted once as a warning, never as a failed step.
  const peerDown = new Set();
  page.on("console", (msg) => {
    if (msg.type() !== "error") return;
    const where = msg.location()?.url || "";                // "Failed to load resource" names no address itself
    if (where && !where.startsWith(opt.base) && /\/api\/(health|mode|peer)\b/.test(where)) { peerDown.add(where); return; }
    errors.push(`${msg.text().slice(0, 300)}${where ? ` (${where.replace(opt.base, "")})` : ""}`);
  });
  page.on("pageerror", (e) => errors.push(`page error: ${String(e).slice(0, 300)}`));
  page.on("response", async (r) => {
    if (r.url().startsWith(opt.base) && r.status() >= 500) errors.push(`HTTP ${r.status()} ${new URL(r.url()).pathname}`);
  });

  const results = [];
  let n = 0;

  /** Wait until the page has settled: no request in flight, nothing saying it is loading. */
  async function settle(ms = 45000) {
    await page.waitForLoadState("networkidle", { timeout: ms }).catch(() => {});
    await page.waitForFunction(() => !document.querySelector('.lab-state[data-kind="loading"], .cs-busy'), null, { timeout: ms }).catch(() => {});
    await page.waitForTimeout(500);
  }

  /** The checks of one step, its screenshot, its row in the report. */
  async function check(step, { strip = true, extra = [] } = {}) {
    await settle();
    n += 1;
    const file = `${String(n).padStart(2, "0")}-${step}.png`;
    const seen = await page.evaluate((idValue) => {
      const text = document.body.innerText || "";
      const sx = document.scrollingElement;
      const main = document.querySelector(".ua-main");
      const wide = [sx, main].filter(Boolean).some((el) => el.scrollWidth > el.clientWidth + 1);
      const nav = document.querySelector("nav.lab-path");
      const chips = nav ? [...nav.querySelectorAll("a[href]")].map((a) => a.getAttribute("href")) : [];
      const want = `alert=${encodeURIComponent(idValue)}`;
      return { text, wide, width: sx.scrollWidth, strip: !!nav, chips, chipsMissingAlert: chips.filter((h) => !h.includes(want)),
               loading: !!document.querySelector('.lab-state[data-kind="loading"]'), hash: location.hash };
    }, id);
    await page.screenshot({ path: path.join(opt.out, file) });
    const problems = [...extra];
    const bad = seen.text.match(BAD);
    if (bad) problems.push(`the page says "${bad[0]}": ${seen.text.slice(Math.max(0, bad.index - 80), bad.index + 120).replace(/\s+/g, " ")}`);
    if (errors.length) problems.push(...errors.map((e) => `console: ${e}`));
    if (seen.wide) problems.push(`scrolls sideways (content ${seen.width}px wide)`);
    if (seen.loading) problems.push("still loading after 45 s");
    if (strip && !seen.strip) problems.push("no strip of chips (NextStrip)");
    if (strip && seen.strip && seen.chipsMissingAlert.length) problems.push(`chips without ?alert=: ${seen.chipsMissingAlert.join(", ")}`);
    results.push({ step, ok: problems.length === 0, problems, screenshot: file, address: seen.hash, chips: seen.chips.length });
    process.stdout.write(`${problems.length ? "FAIL" : "ok  "} ${step}${problems.length ? `\n       ${problems.join("\n       ")}` : ""}\n`);
    errors = [];
  }

  /** Go to the next lab the way the presenter does: its chip in the strip; the address if there is no chip. */
  async function chip(lab) {
    const a = page.locator(`nav.lab-path a[data-lab="${lab}"]`);
    const extra = [];
    if (await a.count()) await a.first().click();
    else {
      extra.push(`no "${lab}" chip in the strip: opened by its address`);
      await page.goto(`${opt.base}/#/labs/${lab}?alert=${encodeURIComponent(id)}`);
    }
    await page.waitForFunction((l) => location.hash.startsWith(`#/labs/${l}`), lab, { timeout: 10000 }).catch(() => {});
    const hash = await page.evaluate(() => location.hash);
    if (!hash.includes(`alert=${encodeURIComponent(id)}`)) extra.push(`the address lost the alert: ${hash}`);
    return extra;
  }

  try {
    // 1. the Labs page, then its checklist card
    await page.goto(`${opt.base}/#/labs`);
    await check("labs", { strip: false });
    const card = page.locator('a[href^="#/labs/checklist"]').first();
    const extra = [];
    if (await card.count()) await card.click();
    else { extra.push("no checklist card on the Labs page: opened by its address"); await page.goto(`${opt.base}/#/labs/checklist`); }
    await settle();
    // 2. the checklist's own list of alerts: the S1 alert
    const pick = page.locator(`a[href="#/labs/checklist?alert=${encodeURIComponent(id)}"]`).first();
    if (await pick.count()) await pick.click();
    else { extra.push("the S1 alert is not in the checklist's list: opened by its address"); await page.goto(`${opt.base}/#/labs/checklist?alert=${encodeURIComponent(id)}`); }
    await check("checklist", { extra });

    for (const lab of ["why", "moment", "tree", "prove"]) {
      const x = await chip(lab);
      await check(lab, { extra: x });
    }

    // 3. claim: every "Try these" sentence, each must get an answer
    await page.goto(`${opt.base}/#/labs/claim?alert=${encodeURIComponent(id)}`);
    await settle();
    const claims = [];
    const tries = page.locator("button.cl-suggest");
    const count = await tries.count();
    const cx = count ? [] : ['no "Try these" sentences'];
    for (let i = 0; i < count; i++) {
      const b = tries.nth(i);
      const said = (await b.innerText()).trim();
      await b.click();
      await page.waitForFunction((s) => {
        const c = document.querySelector(".cl-answer .cl-claim");
        return c && s.includes(c.textContent.replace(/[“”]/g, "").trim());
      }, said, { timeout: 30000 }).catch(() => {});
      await settle();
      const word = await page.locator(".cl-answer .cl-word").first().innerText().catch(() => null);
      claims.push({ claim: said, answer: word });
      if (!word) cx.push(`no answer for ${said}`);
      const shown = await page.evaluate(() => document.body.innerText || "");   // each answer, not only the last
      const bad = shown.match(BAD);
      if (bad) cx.push(`after ${said} the page says "${bad[0]}"`);
      await page.screenshot({ path: path.join(opt.out, `claim-${i + 1}.png`) });
    }
    await check("claim", { extra: cx });
    results[results.length - 1].claims = claims;

    for (const lab of ["network", "respond"]) {
      const x = await chip(lab);
      await check(lab, { extra: x });
    }

    // 4. cases: a throwaway case, the alert pinned into it, the printable report
    const cxs = await chip("cases");
    await settle();
    await page.locator(".cs-cases input.cs-input").fill(CASE_TITLE);
    const made = page.waitForResponse((r) => r.request().method() === "POST" && new URL(r.url()).pathname === "/api/labs/cases");
    await page.locator(".cs-cases button[type=submit]").click();
    const mr = await made;
    caseId = (await mr.json()).id;
    await settle();
    const offer = page.locator('.cs-offer button.th-plus');
    if (await offer.count()) {
      const pinned = page.waitForResponse((r) => r.request().method() === "POST" && r.url().includes(`/api/labs/cases/${caseId}/pins`), { timeout: 30000 });
      await offer.first().click();
      const pr = await pinned.catch(() => null);
      if (!pr || !pr.ok()) cxs.push(`the pin failed (${pr ? pr.status() : "no answer"})`);
    } else cxs.push('no "Pin this alert to the open case" offer');
    await settle();
    const caseText = await page.locator(".cs-main").innerText().catch(() => "");
    if (!caseText.includes(opt.title)) cxs.push("the pinned alert is not shown in the case");
    await check("cases", { extra: cxs });

    const link = page.locator(".cs-exports a", { hasText: "Printable report" }).first();
    const rx = [];
    if (await link.count()) {
      const [rep] = await Promise.all([ctx.waitForEvent("page"), link.click()]);
      await rep.waitForLoadState("networkidle").catch(() => {});
      const t = await rep.evaluate(() => document.body.innerText || "");
      const wide = await rep.evaluate(() => document.scrollingElement.scrollWidth > document.scrollingElement.clientWidth + 1);
      await rep.screenshot({ path: path.join(opt.out, `${String(++n).padStart(2, "0")}-report.png`) });
      const bad = t.match(BAD);
      if (bad) rx.push(`the report says "${bad[0]}"`);
      if (!t.includes(opt.title)) rx.push("the report does not name the pinned alert");
      if (wide) rx.push("the report scrolls sideways");
      if (errors.length) rx.push(...errors.map((e) => `console: ${e}`));
      results.push({ step: "printable report", ok: rx.length === 0, problems: rx, screenshot: `${String(n).padStart(2, "0")}-report.png` });
      process.stdout.write(`${rx.length ? "FAIL" : "ok  "} printable report${rx.length ? `\n       ${rx.join("\n       ")}` : ""}\n`);
      await rep.close();
    } else results.push({ step: "printable report", ok: false, problems: ['no "Printable report" link'] });
  } catch (e) {
    results.push({ step: "the walk itself", ok: false, problems: [String(e).slice(0, 500)] });
    process.stdout.write(`FAIL the walk stopped: ${String(e).slice(0, 500)}\n`);
  } finally {
    // the throwaway case goes to cases/deleted through the case board's own route
    let cleaned = caseId ? "not deleted" : "no case was made";
    if (caseId) {
      try {
        const r = await fetch(`${opt.base}/api/labs/cases/${encodeURIComponent(caseId)}`, { method: "DELETE" });
        cleaned = r.ok ? "moved to cases/deleted" : `delete answered HTTP ${r.status}`;
      } catch (e) { cleaned = `delete failed: ${e}`; }
    }
    await browser.close();
    const failed = results.filter((r) => !r.ok);
    if (refused.length) failed.push({ step: "write guard", problems: refused.map((x) => `refused: ${x}`) });
    const report = { when: new Date().toISOString(), base: opt.base, browser: name, alert: { id, title: alert.title, time: alert.time },
                     case: { title: CASE_TITLE, id: caseId, cleanup: cleaned }, refused, results, passed: failed.length === 0,
                     warnings: [...peerDown].map((u) => `the other dashboard did not answer: ${u} (start it, or ignore this on a replay-only check)`) };
    writeFileSync(path.join(opt.out, "report.json"), JSON.stringify(report, null, 1) + "\n");
    const md = [`# Professor's path, end to end (${report.when.slice(0, 19)} UTC)`, "",
      `${opt.base} · ${name} 1463 x 914 at 175 % · alert "${alert.title}" (${id}) · throwaway case: ${cleaned}`, "",
      "| step | result | problems | screenshot |", "|---|---|---|---|",
      ...results.map((r) => `| ${r.step} | ${r.ok ? "ok" : "**FAIL**"} | ${(r.problems || []).join("<br>").replace(/\|/g, "\\|") || "-"} | ${r.screenshot ?? "-"} |`),
      "", refused.length ? `Refused writes: ${refused.join(", ")}` : "No write other than the throwaway case's.", "",
      ...report.warnings.map((w) => `Warning: ${w}`), report.warnings.length ? "" : null].filter((x) => x !== null);
    const claimRow = results.find((r) => r.claims);
    if (claimRow) md.push("Claims tried:", "", ...claimRow.claims.map((c) => `- ${c.claim} → ${c.answer ?? "no answer"}`), "");
    writeFileSync(path.join(opt.out, "report.md"), md.join("\n"));
    for (const w of report.warnings) process.stdout.write(`warn ${w}\n`);
    process.stdout.write(`\n${report.passed ? "PASSED" : `FAILED: ${failed.length} step(s)`} · throwaway case ${cleaned} · ${path.join(opt.out, "report.md")}\n`);
    process.exitCode = report.passed ? 0 : 1;
  }
}

main().catch((e) => { console.error(e); process.exit(2); });
