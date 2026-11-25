// The guided tour: a "Tour" button in the top bar that walks through the screens with plain-English
// bubbles. Every word and the list of steps come from Python (GET /api/tour, engine/dashboard/tour.py);
// this file only goes to the step's screen, finds the part it points at, and places a ring and a bubble.
// It changes nothing: no run is started, no data is asked for that the screens do not ask for themselves.
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { ArrowLeft, ArrowRight, Compass, X } from "lucide-react";
import { api, type Tour as TourData } from "../api";
import { href, type Route } from "./logic";
import "./tour.css";

interface Box { x: number; y: number; w: number; h: number }
const PAD = 6, GAP = 14, EDGE = 12;

/** Where the bubble goes: under the part when there is room, else above, else beside; always inside the window. */
export function placeBubble(target: Box | null, bubble: { w: number; h: number }, win: { w: number; h: number }): { x: number; y: number } {
  const clampX = (x: number) => Math.max(EDGE, Math.min(x, win.w - bubble.w - EDGE));
  const clampY = (y: number) => Math.max(EDGE, Math.min(y, win.h - bubble.h - EDGE));
  if (!target) return { x: clampX((win.w - bubble.w) / 2), y: clampY((win.h - bubble.h) / 2) };
  const mid = target.x + target.w / 2 - bubble.w / 2;
  const below = target.y + target.h + GAP, above = target.y - GAP - bubble.h;
  if (below + bubble.h + EDGE <= win.h) return { x: clampX(mid), y: below };
  if (above >= EDGE) return { x: clampX(mid), y: above };
  const right = target.x + target.w + GAP, left = target.x - GAP - bubble.w;
  const y = clampY(target.y + target.h / 2 - bubble.h / 2);
  if (right + bubble.w + EDGE <= win.w) return { x: right, y };
  if (left >= EDGE) return { x: left, y };
  return { x: clampX(mid), y: clampY(win.h - bubble.h - EDGE) };       // a part as big as the window: the bubble sits inside it, at the bottom
}

export default function Tour({ route }: { route: Route }) {
  const [tour, setTour] = useState<TourData | null>(null);
  const [at, setAt] = useState<number | null>(null);                    // null: the tour is not running
  const [box, setBox] = useState<Box | null>(null);
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);
  const bubble = useRef<HTMLDivElement>(null);

  useEffect(() => { api.tour().then(setTour).catch(() => setTour(null)); }, []);
  const steps = tour?.steps ?? [];
  const step = at !== null ? steps[at] : null;

  const end = useCallback(() => { setAt(null); setBox(null); setPos(null); }, []);
  const go = useCallback((n: number) => { if (n < 0) return; if (n >= steps.length) end(); else { setBox(null); setPos(null); setAt(n); } }, [steps.length, end]);

  // go to the step's screen (its own address; the story keeps whichever alert it shows)
  useEffect(() => {
    if (!step || route.screen === step.screen) return;
    window.location.hash = step.screen === "labs" ? "#/labs" : href("a", step.screen);
  }, [step, route.screen]);

  // find the part and follow it (it may still be drawing, the window may be resized, the page may scroll)
  useEffect(() => {
    if (!step) return;
    let on = true, scrolled = false;
    const look = () => {
      if (!on) return;
      const el = route.screen === step.screen ? document.querySelector<HTMLElement>(step.target) : null;
      if (el) {
        if (!scrolled) { scrolled = true; el.scrollIntoView({ block: "nearest", inline: "nearest" }); }
        const r = el.getBoundingClientRect();
        const b = { x: Math.max(0, r.left - PAD), y: Math.max(0, r.top - PAD), w: Math.min(window.innerWidth, r.width + 2 * PAD), h: Math.min(window.innerHeight, r.height + 2 * PAD) };
        setBox((old) => (old && old.x === b.x && old.y === b.y && old.w === b.w && old.h === b.h ? old : b));
      } else setBox(null);
    };
    look();
    const t = window.setInterval(look, 200);
    window.addEventListener("resize", look);
    return () => { on = false; window.clearInterval(t); window.removeEventListener("resize", look); };
  }, [step, route.screen]);

  useLayoutEffect(() => {
    if (!step || !bubble.current) return;
    const r = bubble.current.getBoundingClientRect();
    setPos(placeBubble(box, { w: r.width, h: r.height }, { w: window.innerWidth, h: window.innerHeight }));
  }, [step, box]);

  useEffect(() => {
    if (at === null) return;
    const on = (e: KeyboardEvent) => {
      if (e.key === "Escape") end();
      else if (e.key === "ArrowRight" || e.key === "Enter") go(at + 1);
      else if (e.key === "ArrowLeft") go(at - 1);
      else return;
      e.preventDefault(); e.stopPropagation();
    };
    window.addEventListener("keydown", on, true);                       // before the story's own keys: the tour has them while it runs
    return () => window.removeEventListener("keydown", on, true);
  }, [at, go, end]);

  if (!tour || steps.length === 0) return null;
  const w = tour.words, last = at === steps.length - 1;
  return (
    <>
      <button className="ua-tourbtn" onClick={() => go(0)} title={w.button_title} aria-pressed={at !== null}><Compass size={14} />{w.button}</button>
      {step && at !== null && createPortal(
        <div className="tour" role="dialog" aria-modal="false" aria-label={step.title}>
          {box ? <div className="tour-ring" style={{ left: box.x, top: box.y, width: box.w, height: box.h }} /> : <div className="tour-dim" />}
          <div className="tour-bubble" ref={bubble} style={pos ? { left: pos.x, top: pos.y } : { left: 0, top: 0, visibility: "hidden" }} key={at}>
            <header>
              <span>{w.step.replace("{n}", String(at + 1)).replace("{total}", String(steps.length))}</span>
              <button onClick={end} aria-label={w.end} title={w.end}><X size={15} /></button>
            </header>
            <h3>{step.title}</h3>
            <p>{step.text}</p>
            {!box && route.screen === step.screen && <p className="tour-missing">{w.missing}</p>}
            <footer>
              <small>{w.keys}</small>
              <button className="ua-btn" disabled={at === 0} onClick={() => go(at - 1)}><ArrowLeft size={14} />{w.back}</button>
              <button className="ua-btn" data-kind="primary" onClick={() => go(at + 1)}>{last ? w.done : w.next}{!last && <ArrowRight size={14} />}</button>
            </footer>
          </div>
        </div>, document.body)}
    </>
  );
}
