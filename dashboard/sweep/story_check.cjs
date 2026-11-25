// The Story screen measured in the REAL browser (the Edge that is installed, driven by playwright-core;
// nothing is downloaded), at the demo laptop's size 1463 x 780. Written after the sweep of 2026-11-21:
// every screen bug it found (a crash on "declared" alerts, a film collapsed to nothing, a header 2,968 px
// wide, names and words written across each other) was found by looking at the page, not by a unit test.
//
//   node dashboard/sweep/story_check.cjs <base url> <stories folder> [name ...]
//
// <base url>: a dashboard in plain (development) mode that serves the stories as /static/dev/<name>.json
// (tests/test_dashboard_browser.py starts one and copies tests/fixtures/stories/ there).
// Prints one JSON line per story: {name, problems: [...], ...numbers}. Exit code 1 if any story has a problem.
const fs = require("fs"), path = require("path");
const { chromium } = require("playwright-core");
const [base, dir, ...only] = process.argv.slice(2);

const measure = () => {
  const film = document.querySelector(".film");
  if (!film || !film.querySelector("svg")) return { noFilm: true };
  const P = film.getBoundingClientRect();
  const inside = (b, pad = 0) => b.left >= P.left - pad && b.right <= P.right + pad && b.top >= P.top - pad && b.bottom <= P.bottom + pad;
  const touches = (b) => b.right > P.left && b.left < P.right && b.bottom > P.top && b.top < P.bottom;
  const hit = (a, b, m = 1) => a.left < b.right - m && b.left < a.right - m && a.top < b.bottom - m && b.top < a.bottom - m;
  const nodes = [...document.querySelectorAll('.film-node[data-id][data-on="true"]')].map((g) => ({ id: g.dataset.id, box: g.querySelector(".film-box").getBoundingClientRect(),
    label: g.querySelector(".film-label").getBoundingClientRect(), shown: getComputedStyle(g.querySelector(".film-label")).opacity !== "0" }));
  const vis = nodes.filter((n) => touches(n.box)), names = vis.filter((n) => n.shown && touches(n.label));
  let nameOnName = 0, nameOnShape = 0;
  for (let i = 0; i < names.length; i++) {
    for (let j = i + 1; j < names.length; j++) if (hit(names[i].label, names[j].label)) nameOnName++;
    for (const n of vis) if (n.id !== names[i].id && hit(names[i].label, n.box, 2)) nameOnShape++;
  }
  const words = [...document.querySelectorAll('.film-node[data-on="true"] .film-chip')].map((c) => c.getBoundingClientRect()).filter(touches);
  let wordOnShape = 0, wordOnName = 0, wordOnWord = 0;
  for (let i = 0; i < words.length; i++) {
    for (const n of vis) { if (hit(words[i], n.box, 2)) wordOnShape++; if (n.shown && hit(words[i], n.label, 1)) wordOnName++; }
    for (let j = i + 1; j < words.length; j++) if (hit(words[i], words[j], 1)) wordOnWord++;
  }
  const head = document.querySelector(".ua-story-head"), h1 = head.querySelector("h1"), cap = document.querySelector(".ua-cap-text p");
  const marks = [...document.querySelectorAll(".ua-scrub li span")].filter((x) => getComputedStyle(x).visibility !== "hidden" && x.textContent)
    .map((x) => { const r = document.createRange(); r.selectNodeContents(x); return r.getBoundingClientRect(); });
  return {
    panel: [Math.round(P.width), Math.round(P.height)], shown: nodes.length, cutShapes: vis.filter((n) => !inside(n.box)).length,
    nameOnName, nameOnShape, wordOnShape, wordOnName, wordOnWord, words: words.length,
    smallestName: names.length ? Math.round(Math.min(...names.map((n) => n.label.height)) * 10) / 10 : null,
    headHeight: Math.round(head.getBoundingClientRect().height), titleClipped: h1.scrollWidth > h1.clientWidth + 1,
    // everything in the header (title, time, the alert picker, the Report button) inside the header's own box
    headSpills: [...head.children].filter((c) => { const b = c.getBoundingClientRect(), H = head.getBoundingClientRect(); return b.right > H.right + 1 || b.left < H.left - 1; }).length,
    titleWidth: Math.round(h1.getBoundingClientRect().width),
    captionClipped: cap ? cap.scrollHeight > cap.clientHeight + 2 || cap.scrollWidth > cap.clientWidth + 2 : false,
    marksOverlap: marks.filter((b, i) => i > 0 && b.left < marks[i - 1].right - 1).length,
    pageWide: document.scrollingElement.scrollWidth > window.innerWidth + 1, controlsBottom: Math.round(document.querySelector(".ua-bar").getBoundingClientRect().bottom),
    note: document.querySelector(".ua-film-note span")?.textContent ?? null, declared: document.querySelector(".ua-filmpage > .ua-declared")?.textContent ?? null,
    filmLabel: document.querySelector(".ua-tally-set")?.textContent ?? null, storyLabel: document.querySelector(".ua-verdict-set")?.textContent ?? null,
    pick: document.querySelector(".ua-pick")?.textContent ?? null,
  };
};
const stepsInView = (ids) => {
  const P = document.querySelector(".film").getBoundingClientRect();
  return ids.filter((id) => { const g = [...document.querySelectorAll(".film-node[data-id]")].find((x) => x.dataset.id === id); if (!g) return false;
    const b = g.querySelector(".film-box").getBoundingClientRect(); return b.left >= P.left && b.right <= P.right && b.top >= P.top && b.bottom <= P.bottom; }).length;
};
const reportRows = () => [...document.querySelectorAll(".ua-report-steps ol li[data-step-id]")].map((l) => [l.dataset.stepId, l.dataset.ink]);

(async () => {
  const names = fs.readdirSync(dir).filter((f) => f.endsWith(".json")).map((f) => f.slice(0, -5)).filter((n) => !only.length || only.includes(n)).sort();
  const browser = await chromium.launch({ channel: "msedge", headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1463, height: 780 }, deviceScaleFactor: 1 });
  let bad = 0;
  for (const name of names) {
    const story = JSON.parse(fs.readFileSync(path.join(dir, name + ".json"), "utf8"));
    const film = story.film, total = story.report.timeline.length, cut = !!(film && !film.whole);
    const n = cut ? film.rows : total, lay = cut && film.layout ? film.layout : story.report.layout;
    const steps = [...new Set((lay.edges || []).filter((e) => e.in_chain).flatMap((e) => [e.u, e.v]))];
    const r = { name, rows: total, film: n, problems: [] };
    const say = (ok, what) => { if (!ok) r.problems.push(what); };
    const page = await ctx.newPage();
    page.on("pageerror", (e) => r.problems.push("script error: " + String(e.message).slice(0, 120)));
    try {
      for (const [frame, at] of [["first", 1], ["middle", Math.max(1, Math.round(n / 2))], ["last", "end"]]) {
        await page.goto(`${base}/?fixture=${name}&at=${at}&v=${Date.now()}#story`);
        await page.waitForSelector(".ua-story-head, .ua-story-empty", { timeout: 15000 });
        const has = await page.waitForSelector(".film svg", { timeout: 8000 }).then(() => true).catch(() => false);
        await page.waitForTimeout(1300);                                   // the camera's move and the link's draw
        const m = await page.evaluate(measure);
        if (!has || m.noFilm) { say(total === 0, `${frame}: no film drawn`); continue; }
        say(m.panel[1] >= 250, `${frame}: the film panel is only ${m.panel[1]} px high`);
        say(m.headHeight <= 120, `${frame}: the header is ${m.headHeight} px high`);
        say(m.headSpills === 0 && m.titleWidth >= 180, `${frame}: the header does not hold its parts (${m.headSpills} run off its edge; the title has ${m.titleWidth} px)`);
        say(!m.titleClipped && !m.captionClipped, `${frame}: the title or the caption is cut`);
        say(m.nameOnName === 0, `${frame}: ${m.nameOnName} name(s) written across another name`);
        say(m.nameOnShape === 0, `${frame}: ${m.nameOnShape} name(s) written across a shape`);
        say(m.wordOnShape + m.wordOnName + m.wordOnWord === 0, `${frame}: a suspected link's word stands on a shape (${m.wordOnShape}), a name (${m.wordOnName}) or another word (${m.wordOnWord})`);
        say(m.smallestName === null || m.smallestName >= 8, `${frame}: names are only ${m.smallestName} px high`);
        say(m.marksOverlap === 0, `${frame}: ${m.marksOverlap} time mark(s) overlap`);
        say(!m.pageWide && m.controlsBottom <= 780, `${frame}: the page is wider than the screen or the controls are off it`);
        say((m.note ?? null) === ((film && film.note) || null), `${frame}: the line under the film is not Python's ("${m.note}")`);
        say((m.declared ?? null) === (story.report.declared_banner ? story.report.declared_banner.text : null), `${frame}: the "declared" sentence is wrong or missing`);
        say(cut ? m.filmLabel === film.labels.film : m.filmLabel === null, `${frame}: the "in the film" label`);
        if (frame === "first") say(m.cutShapes === 0 && m.shown >= 1, "first: a shape is cut by the panel edge");
        if (frame === "last") {
          say(cut ? m.storyLabel === film.labels.story : m.storyLabel === null, 'last: the "in the whole story" label');
          if (steps.length && steps.length <= 12) say((await page.evaluate(stepsInView, steps)) === steps.length, "last: a thing of the alert's own steps is off the film");
          Object.assign(r, { scale_names_px: m.smallestName, words: m.words });
        }
      }
      await page.goto(`${base}/?fixture=${name}&at=end&view=report&v=${Date.now()}#story`);
      await page.waitForSelector(total ? ".ua-report-steps ol li" : ".ua-report-steps", { timeout: 8000 }).catch(() => {});
      await page.waitForTimeout(500);
      const rows = await page.evaluate(reportRows);
      say(rows.length === total, `report: ${rows.length} rows shown, the story has ${total}`);
      say(JSON.stringify(rows.map((x) => x[0])) === JSON.stringify(story.report.timeline.map((t) => t.id)), "report: the rows are not in Python's order");
      say(rows.map((x) => x[1]).join() === story.report.timeline.map((t) => t.ink).join(), "report: a row has another ink than Python gave it");
      say(await page.evaluate(() => !!document.querySelector('.ua-reportpage header a[href*="/report"]')), 'report: no "Open the full report" link');
    } catch (e) { r.problems.push("check failed: " + String(e.message).split("\n")[0]); }
    await page.close();
    if (r.problems.length) bad++;
    console.log(JSON.stringify(r));
  }
  await browser.close();
  process.exit(bad ? 1 : 0);
})().catch((e) => { console.error("could not run: " + e.message.split("\n")[0]); process.exit(2); });
