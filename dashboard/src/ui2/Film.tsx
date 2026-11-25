// The story as a map that draws itself (design A). One rail per program, left to right in the order
// Python recorded. Each link appears only when its row of Python's timeline is told, drawn in its
// ink: solid, dashed or dotted. The camera follows the newest link when the map is wider than the panel.
import { useCallback, useMemo } from "react";
import { Box } from "lucide-react";
import type { Ink, Investigation } from "../api";
import { DASH, INK_VAR, INKS, NODE_ICON } from "./bits";
import { useSize } from "./hooks";
import { buildMap, camera, shortName, type Row } from "./logic";

const R = 22, OFF = 50;

export default function Film({ inv, rows, shown, onPick }: { inv: Investigation; rows: Row[]; shown: number; onPick: (n: number) => void }) {
  const [box, { w, h }] = useSize<HTMLDivElement>();
  // a stable function: React calls it once when the spark appears (an inline one would restart the spark on every re-render)
  const begin = useCallback((el: SVGAnimationElement | null) => { el?.beginElement(); }, []);
  const sc = useMemo(() => {
    if (!inv.report.layout || !w || !h) return null;
    const L = inv.report.layout;
    const columns = Math.max(1, L.nodes.length - 1), lanes = Math.max(1, L.lanes.length);
    const left = 96, right = 80, top = OFF + R + 24, bottom = OFF + R + 40;
    const col = Math.min(210, Math.max(112, (w - left - right) / columns));
    const room = lanes > 1 ? (h - top - bottom) / (lanes - 1) : 0;    // what each rail would get if all of them had to fit
    const laneH = lanes > 1 ? Math.min(170, Math.max(104, room)) : 0;
    // only a story with more rails than the panel can hold packs its empty rails closer together
    return buildMap(inv, rows, { r: R, off: OFF, col, laneH, left, right, top, bottom, stub: 26, compact: room < 104 ? 2 * R + 28 : undefined });
  }, [inv, rows, w, h]);

  // The camera frames what has been drawn so far and widens as the story grows, so the first steps
  // are not a few small shapes on an empty panel. A very long story is followed instead of shrunk, and
  // ends on the alert's own chain (logic.ts: camera).
  const cam = useMemo(() => (sc ? camera(sc, w, h, shown, rows.length) : { x: 0, y: 0, k: 1 }), [sc, w, h, shown, rows.length]);
  const lab = Math.max(1, Math.min(1.5, 0.74 / cam.k));
  // a name is shortened in the middle so it fits between its neighbours on the same side of the rail (two
  // columns apart); the caption and the tooltip keep the full name
  const nameChars = Math.max(9, Math.min(26, Math.floor((2 * (sc?.col ?? 210) - 14) / (7.6 * lab))));
  // a rail reaches only as far as its program has acted so far
  const reach = (y: number, x: number) => Math.max(x, ...(sc?.edges ?? []).filter((e) => e.at <= shown && e.sy === y).map((e) => e.tx),
    ...(sc?.nodes ?? []).filter((n) => n.at <= shown && n.kind !== "process" && Math.abs(n.y - y) <= OFF + 1).map((n) => n.x));

  return (
    <div ref={box} className="film">
      {sc && (
        <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`}>
          <defs>
            {INKS.map((ink: Ink) => (
              <marker key={ink} id={`arrow-${ink}`} viewBox="0 0 12 12" refX="10.5" refY="6" markerWidth="4.6" markerHeight="4.6" orient="auto-start-reverse">
                <path d="M 1 1.5 L 11 6 L 1 10.5 z" fill={INK_VAR[ink]} />
              </marker>
            ))}
            {sc.edges.map((e) => (
              <mask key={e.id} id={`m-${e.id}`} maskUnits="userSpaceOnUse" x={-200} y={-200} width={sc.width + 400} height={sc.height + 400}>
                <path d={e.d} className="film-reveal" data-on={shown >= e.at} pathLength={1} />
              </mask>
            ))}
            {sc.stubs.map((s, i) => (
              <mask key={s.id} id={`m-stub-${i}`} maskUnits="userSpaceOnUse" x={-200} y={-200} width={sc.width + 400} height={sc.height + 400}>
                <path d={s.d} className="film-reveal" data-on={shown >= s.at} pathLength={1} />
              </mask>
            ))}
          </defs>
          {/* --lab: names never get smaller than about 9 px on screen, however far the camera stands back */}
          <g className="film-cam" data-small={cam.k < 0.5} style={{ transform: `translate(${cam.x}px, ${cam.y}px) scale(${cam.k})`, ["--lab" as string]: lab }}>
            {sc.rails.map((r, i) => {
              const full = Math.max(1, sc.width - 24 - r.x), part = (reach(r.y, r.x) + 34 - r.x) / full;
              return <line key={i} x1={r.x} y1={r.y} x2={sc.width - 24} y2={r.y} className="film-rail" data-on={shown >= r.at}
                style={{ transformOrigin: `${r.x}px ${r.y}px`, transform: `scaleX(${Math.min(1, Math.max(0.001, part))})` }} />;
            })}
            {sc.stubs.map((s, i) => (
              <g key={s.id} onClick={() => onPick(s.at)} className="film-hit" data-told={shown >= s.at}>
                <g mask={`url(#m-stub-${i})`}><path d={s.d} fill="none" stroke={INK_VAR.gap} strokeWidth={3.2} strokeLinecap="round" strokeDasharray={DASH.gap} /></g>
                <g className="film-node" data-on={shown >= s.at} style={{ transformOrigin: `${s.qx}px ${s.qy}px` }}>
                  <circle cx={s.qx} cy={s.qy} r={13} className="film-unknown" />
                  <text x={s.qx} y={s.qy + 5.5} textAnchor="middle" className="film-q">?</text>
                </g>
              </g>
            ))}
            {sc.edges.map((e) => {
              const now = shown === e.at;
              return (
                <g key={e.id} data-id={e.id} data-chain={e.chain} className="film-edge film-hit" data-told={shown >= e.at} data-now={now} data-quiet={e.ink === "fact" && !e.chain} onClick={() => onPick(e.at)}>
                  {shown >= e.at && <path d={e.d} className="film-grab" />}
                  {now && <path d={e.d} className="film-halo" stroke={INK_VAR[e.ink]} />}
                  <g mask={`url(#m-${e.id})`}>
                    <path d={e.d} fill="none" stroke={INK_VAR[e.ink]} strokeWidth={e.ink === "fact" && !e.chain ? 2.1 : 3.2} strokeLinecap="round"
                      strokeDasharray={DASH[e.ink]} markerEnd={`url(#arrow-${e.ink})`} />
                  </g>
                  {now && (
                    <circle r={5.5} fill={INK_VAR[e.ink]} className="film-spark">
                      <animateMotion dur="0.85s" path={e.d} fill="freeze" begin="indefinite" calcMode="spline" keyTimes="0;1" keySplines="0.3 0 0.2 1"
                        ref={begin} />
                    </circle>
                  )}
                </g>
              );
            })}
            {sc.nodes.map((n) => {
              const Icon = NODE_ICON[n.icon] ?? Box;
              return (
                <g key={n.id} data-id={n.id} className="film-node" data-on={shown >= n.at} data-proc={n.kind === "process"} data-gap={n.gapAt !== null && shown >= n.gapAt} style={{ transformOrigin: `${n.x}px ${n.y}px` }}>
                  <rect x={n.x - R} y={n.y - R} width={R * 2} height={R * 2} rx={n.kind === "process" ? 9 : R} className="film-box" />
                  <Icon x={n.x - 10} y={n.y - 10} width={20} height={20} strokeWidth={1.7} className="film-icon" />
                  {/* the name on the side away from the rail: under a program or a thing below it, over a thing above it */}
                  <text x={n.x} y={n.side < 0 ? n.y - R - 8 : n.y + R + 5 + 12 * lab} textAnchor="middle" className="film-label">{shortName(n.short, n.kind === "process" ? 26 : nameChars)}<title>{n.short}</title></text>
                </g>
              );
            })}
            {/* the band word of a suspected link, above everything so no later line crosses it */}
            {sc.edges.filter((e) => e.label).map((e) => (
              <g key={`chip-${e.id}`} className="film-node film-hit" data-told={shown >= e.at} data-on={shown >= e.at} style={{ transformOrigin: `${e.lx}px ${e.ly}px` }} onClick={() => onPick(e.at)}>
                <g transform={`rotate(${e.ang} ${e.lx} ${e.ly})`}>
                  <rect x={e.lx - 44} y={e.ly - 11} width={88} height={22} rx={5} className="film-chip" />
                  <text x={e.lx} y={e.ly + 4.5} textAnchor="middle" className="film-chip-text">{e.label}</text>
                </g>
              </g>
            ))}
          </g>
        </svg>
      )}
    </div>
  );
}
