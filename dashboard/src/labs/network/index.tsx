// Labs page "Network view" (night-hunt): who talked to whom (programs -> destinations) and each pair's
// check-in rhythm. The rhythm score is the project's own beacon method with its frozen settings
// (engine/beacon.py, read-only). Data and words: engine/labs/network.py (/api/labs/network/...).
import { useMemo, useState } from "react";
import { Network } from "lucide-react";
import type { Lab, LabProps } from "../registry";
import { NextStrip, useAlertParam } from "../kit";
import { apiQuery, count, fileName, plural, shortTime, type WindowName } from "../hunts/logic";
import { AlertBanner, BigNumber, Notes, Panel, PivotLinks, Status, Term, WindowPicker, useJSON, useParam, useWindowParam, type AlertInView, type Meta } from "../hunts/shared";

interface Rhythm { regularity: number; beacon_score: number; checkins: number; median_gap: number; span_s: number; regular: boolean }
interface Pair {
  program: string; program_key: string; ip: string; port: number; dest: string; name: string | null; connections: number;
  first: string | null; last: string | null; rhythm: Rhythm | null; expected: string | null; unicast: boolean; guid: string | null; attempted: boolean;
}
interface View extends Meta {
  alert: AlertInView | null;
  pairs: Pair[]; programs: { program: string; connections: number; destinations: number; regular: number }[];
  graph: { programs: string[]; destinations: string[]; edges: { program: string; dest: string; connections: number; regular: boolean; regularity: number | null; attempted?: boolean }[];
    left_out: { programs: number; pairs: number } };
  notes: string[]; threshold: number | null; scored: boolean; truncated: boolean; ms: number;
  totals: { connections: number; pairs: number; programs: number; destinations: number; regular: number; attempted: number };
  firewall: { host: string; ports: number[]; source: string } | null;
}
interface Points extends Meta {
  connections: number; checkins: number; points: { t: string; gap: number }[]; truncated: boolean; median_gap?: number; spread?: number;
  histogram?: { from: number; to: number; n: number }[]; regularity?: number; regular?: boolean; threshold: number | null; note: string | null;
}

const WINDOWS: readonly WindowName[] = ["1h", "6h", "24h", "7d", "30d"];
const secs = (s: number) => (s >= 3600 ? `${(s / 3600).toFixed(1)} h` : s >= 120 ? `${(s / 60).toFixed(1)} min` : `${s.toFixed(s < 10 ? 1 : 0)} s`);
const keyOf = (p: { program: string; dest: string }) => `${p.program}|${p.dest}`;

function Picture({ g, picked, onPick }: { g: View["graph"]; picked: string | null; onPick: (program: string, dest: string) => void }) {
  const [hover, setHover] = useState<string | null>(null);
  const rows = Math.max(g.programs.length, g.destinations.length, 1);
  const H = rows * 26 + 20, W = 1000, xl = 300, xr = 700;
  const spread = (n: number) => (i: number) => (n <= 1 ? H / 2 : 16 + (i * (H - 32)) / (n - 1));
  const yP = spread(g.programs.length), yD = spread(g.destinations.length);
  const pi = new Map(g.programs.map((p, i) => [p, i])), di = new Map(g.destinations.map((d, i) => [d, i]));
  const active = (e: { program: string; dest: string }) => hover === e.program || hover === e.dest || picked === keyOf(e);
  const edges = [...g.edges].sort((a, b) => Number(a.regular) - Number(b.regular) || Number(active(a)) - Number(active(b)));
  return (
    <svg className="hn-chart hn-net" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Programs on the left, the addresses they connected to on the right">
      {edges.map((e) => {
        const y1 = yP(pi.get(e.program) ?? 0), y2 = yD(di.get(e.dest) ?? 0), on = active(e);
        return (
          <path key={keyOf(e)} d={`M${xl},${y1} C${(xl + xr) / 2},${y1} ${(xl + xr) / 2},${y2} ${xr},${y2}`} fill="none"
            stroke={e.regular ? "var(--ink-hypo)" : on ? "var(--accent)" : "var(--line-2)"} strokeOpacity={on || e.regular ? 1 : 0.7}
            strokeWidth={0.8 + Math.log10(Math.max(1, e.connections)) * 1.4} strokeDasharray={e.attempted ? "5 5" : undefined}
            style={{ cursor: "pointer" }} onClick={() => onPick(e.program, e.dest)}>
            <title>{`${fileName(e.program)} → ${e.dest}: ${e.connections} connections${e.regularity != null ? `, regularity ${e.regularity}` : ""}`}</title>
          </path>
        );
      })}
      {g.programs.map((p, i) => (
        <g key={p} onMouseEnter={() => setHover(p)} onMouseLeave={() => setHover(null)} style={{ cursor: "default" }}>
          <circle cx={xl} cy={yP(i)} r={4} fill="var(--tile)" />
          <text x={xl - 10} y={yP(i) + 4} textAnchor="end" className={hover === p ? "on" : undefined}>{fileName(p).slice(0, 34)}</text>
          <title>{p}</title>
        </g>
      ))}
      {g.destinations.map((d, i) => (
        <g key={d} onMouseEnter={() => setHover(d)} onMouseLeave={() => setHover(null)}>
          <circle cx={xr} cy={yD(i)} r={4} fill="var(--accent)" />
          <text x={xr + 10} y={yD(i) + 4} className={hover === d ? "on" : undefined}>{d}</text>
        </g>
      ))}
    </svg>
  );
}

function RhythmChart({ d }: { d: Points }) {
  const pts = d.points;
  if (pts.length < 2) return <p className="hn-empty">Too few check-ins to draw a rhythm ({d.checkins}).</p>;
  const W = 1000, H = 260, L = 64, R = 14, T = 12, B = 30;
  const xs = pts.map((p) => Date.parse(p.t)), gaps = pts.map((p) => Math.max(p.gap, 0.001));
  const x0 = Math.min(...xs), x1 = Math.max(...xs), lo = Math.min(...gaps), hi = Math.max(...gaps);
  const logy = hi / lo > 20;
  const fy = (g: number) => {
    const a = logy ? Math.log10(lo) : 0, b = logy ? Math.log10(hi) : hi * 1.1, v = logy ? Math.log10(g) : g;
    return T + (H - T - B) * (1 - (v - a) / ((b - a) || 1));
  };
  const fx = (t: number) => L + (W - L - R) * ((t - x0) / ((x1 - x0) || 1));
  const ticks = logy ? [lo, Math.sqrt(lo * hi), hi] : [0, hi / 2, hi];
  return (
    <svg className="hn-chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Seconds between check-ins over time">
      {ticks.map((t) => (
        <g key={t}><line x1={L} x2={W - R} y1={fy(Math.max(t, 0.001))} y2={fy(Math.max(t, 0.001))} stroke="var(--line)" />
          <text x={L - 8} y={fy(Math.max(t, 0.001)) + 4} textAnchor="end">{secs(t)}</text></g>
      ))}
      {d.median_gap != null && (
        <g><line x1={L} x2={W - R} y1={fy(Math.max(d.median_gap, 0.001))} y2={fy(Math.max(d.median_gap, 0.001))} stroke="var(--ink-hypo)" strokeDasharray="6 4" />
          <text x={W - R} y={fy(Math.max(d.median_gap, 0.001)) - 6} textAnchor="end" style={{ fill: "var(--ink-hypo)" }}>median {secs(d.median_gap)}</text></g>
      )}
      {xs.map((x, i) => <circle key={i} cx={fx(x)} cy={fy(gaps[i])} r={3.2} fill={d.regular ? "var(--ink-hypo)" : "var(--tile)"} fillOpacity={0.85} />)}
      <text x={L} y={H - 8}>{shortTime(pts[0].t)}</text>
      <text x={W - R} y={H - 8} textAnchor="end">{shortTime(pts[pts.length - 1].t)}</text>
    </svg>
  );
}

function Histogram({ bins }: { bins: { from: number; to: number; n: number }[] }) {
  const max = Math.max(1, ...bins.map((b) => b.n)), W = 1000, H = 120, bw = W / bins.length;
  return (
    <svg className="hn-chart" viewBox={`0 0 ${W} ${H + 20}`} role="img" aria-label="How often each gap length occurred">
      {bins.map((b, i) => (
        <rect key={i} x={i * bw + 1} width={bw - 2} y={H - (b.n / max) * H} height={(b.n / max) * H} fill="var(--tile)" rx={2}>
          <title>{`${secs(b.from)}–${secs(b.to)}: ${b.n}`}</title>
        </rect>
      ))}
      <text x={0} y={H + 16}>{secs(bins[0].from)}</text>
      <text x={W} y={H + 16} textAnchor="end">{secs(bins[bins.length - 1].to)}</text>
    </svg>
  );
}

export function NetworkPage({ params }: LabProps) {
  const [win, setWin] = useWindowParam(params, "24h");
  const [own, setOwn] = useState(false);
  const [picked, setPicked] = useState<string | null>(params.get("program") && params.get("dest") ? `${params.get("program")}|${params.get("dest")}` : null);
  const [onlyRegular, setOnlyRegular] = useState(false);
  const [alert, setAlert] = useAlertParam();                       // wave 3: "#/labs/network?alert=<id>"
  const [all, setAll] = useParam(params, "all", "");
  const q = apiQuery({ window: win, include_own: own, alert, only_alert: alert ? (all ? "false" : "true") : null });
  const { data: v, error, loading } = useJSON<View>(`/api/labs/network/?${q}`);
  const pairs = useMemo(() => (v?.pairs ?? []).filter((p) => !onlyRegular || p.rhythm?.regular), [v, onlyRegular]);
  const sel = v?.pairs.find((p) => keyOf(p) === picked) ?? v?.pairs.find((p) => p.rhythm) ?? v?.pairs[0] ?? null;
  // the chart reads the same stretch of time the page shows (an alert's run, or the chosen window)
  const span = v?.alert && !v.alert.missing ? { start: v.window.since, end: v.window.until } : { window: win };
  const pts = useJSON<Points>(sel ? `/api/labs/network/rhythm?${apiQuery({ image: sel.program, ip: sel.ip, port: sel.port, ...span })}` : null);
  const pick = (program: string, dest: string) => setPicked(`${program}|${dest}`);
  const pickWindow = (w: WindowName) => { if (alert) setAlert(null); setWin(w); };

  return (
    <div className="hn" data-hunt-page="network">
      <NextStrip current="network" alert={alert} />
      <p className="ua-hint">Every outgoing connection the recorder saw, as program → address. A program that "checks in" like a clock
        (the same gap again and again) is how remote-controlled malware usually keeps in touch: a <Term plain="a program phoning home on a timer">beacon</Term>.
        The rhythm chart shows those gaps.</p>
      <AlertBanner alert={v?.alert} words={v?.scope_words} onAll={(b) => { setAll(b ? "1" : null); if (b) setWin("all"); }} onClear={() => setAlert(null)} />
      <WindowPicker value={alert && v?.alert && !v.alert.missing ? ("" as WindowName) : win} onChange={pickWindow} choices={WINDOWS}
        includeOwn={own} onIncludeOwn={setOwn} meta={v} />
      <Status loading={loading && !v} error={error} />
      {v && (
        <>
          <div className="hn-counts">
            <BigNumber value={count(v.totals.programs)} label={plural(v.totals.programs, "program")} />
            <BigNumber value={count(v.totals.destinations)} label={plural(v.totals.destinations, "address", "addresses")} />
            <BigNumber value={count(v.totals.connections)} label={plural(v.totals.connections, "connection")} />
            <BigNumber value={v.scored ? count(v.totals.regular) : "-"}
              label={!v.scored ? "regular rhythms (not judged for windows over 8 days)"
                : v.totals.regular === 0 ? "regular rhythms: no program checked in like a clock" : "regular rhythms"} />
            {v.firewall && <BigNumber value={count(v.totals.attempted)} label="attempted only (the VM's firewall)" />}
          </div>
          <Notes notes={v.notes} />
          <div className="hn-grid2">
            <Panel title="Who talked to whom" intro={`Thicker line = more connections; amber = a regular rhythm. ${v.graph.left_out.pairs ? `${count(v.graph.left_out.pairs)} quieter pairs are in the table only.` : ""}`}>
              {v.graph.edges.length ? <Picture g={v.graph} picked={sel ? keyOf(sel) : null} onPick={pick} /> : <p className="hn-empty">No outgoing connections in this window.</p>}
            </Panel>
            <Panel title={sel ? `${fileName(sel.program)} → ${sel.dest}` : "Check-in rhythm"}
              intro="Each dot is one check-in: how many seconds after the previous one it came. A beacon draws a flat line; people and ordinary apps scatter. Dots far above the line are usually sleeps or restarts between runs (the score is taken per awake stretch)."
              right={sel?.rhythm ? <BigNumber value={sel.rhythm.regularity.toFixed(2)}
                label={`${sel.rhythm.regular ? "regular" : "gap regularity"} (regular ≥ ${v.threshold}; best awake stretch)`} />
                : <BigNumber value="-" label="not judged" />}>
              <Status loading={pts.loading && !pts.data} error={pts.error} />
              {pts.data && sel && (
                <>
                  <RhythmChart d={pts.data} />
                  {pts.data.histogram && pts.data.points.length >= 3 && <Histogram bins={pts.data.histogram} />}
                  <p className="hn-span">{count(pts.data.connections)} connections · {count(pts.data.checkins)} check-ins
                    {pts.data.median_gap != null && <> · median gap <b>{secs(pts.data.median_gap)}</b> · typical wobble <b>{secs(pts.data.spread ?? 0)}</b></>}
                    {sel.name && sel.name.trim() !== "-" && <> · name <b>{sel.name}</b></>}{" "}<PivotLinks host={v.host} pivots={[{ field: "Image", value: sel.program }, { field: "DestinationIp", value: sel.ip }]} /></p>
                </>
              )}
            </Panel>
          </div>
          <Panel title="Program → address pairs" intro="Regular rhythms first, then by regularity and connections. Click a row to draw its rhythm."
            right={<label className="hn-check"><input type="checkbox" checked={onlyRegular} onChange={(e) => setOnlyRegular(e.target.checked)} />only regular rhythms</label>}>
            <div className="hn-tablewrap">
              <table className="hn-table">
                <thead><tr><th>Program</th><th>Address</th><th>Name</th><th>Connections</th><th>Check-ins</th><th>Median gap</th><th>Regularity</th><th>Rhythm</th><th>First</th><th>Last</th></tr></thead>
                <tbody>
                  {pairs.slice(0, 300).map((p) => (
                    <tr key={keyOf(p)} onClick={() => pick(p.program, p.dest)} data-selected={sel && keyOf(sel) === keyOf(p) ? true : undefined} style={{ cursor: "pointer" }}>
                      <td className="hn-path" title={p.program}>{fileName(p.program)}</td>
                      <td className="hn-path">{p.dest}</td>
                      <td className="hn-path">{p.name ?? <span className="hn-dash">-</span>}</td>
                      <td className="hn-num">{count(p.connections)}</td>
                      <td className="hn-num">{p.rhythm ? count(p.rhythm.checkins) : <span className="hn-dash">-</span>}</td>
                      <td className="hn-num">{p.rhythm ? secs(p.rhythm.median_gap) : <span className="hn-dash">-</span>}</td>
                      <td className="hn-num">{p.rhythm ? p.rhythm.regularity.toFixed(2) : <span className="hn-dash" title="too few check-ins, too fast, or not a single address">not judged</span>}</td>
                      <td>{p.rhythm?.regular ? <span className="hn-tag" data-kind="added" title={p.expected ?? undefined}>{p.expected ? "regular · expected" : "regular"}</span> : null}
                        {p.attempted && <span className="hn-tag" data-kind="gap" title={v.firewall ? `The test VM's firewall lets out only ${v.firewall.host} on TCP ${v.firewall.ports.join(", ")}: this was blocked if that setup was in force` : undefined}>attempted</span>}</td>
                      <td className="hn-time">{shortTime(p.first)}</td>
                      <td className="hn-time">{shortTime(p.last)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {pairs.length > 300 && <p className="hn-more">Showing 300 of {count(pairs.length)} pairs.</p>}
          </Panel>
        </>
      )}
    </div>
  );
}

export const lab: Lab = {
  id: "network",
  title: "Network view",
  blurb: "Who talked to whom (program → address), with each pair's check-in rhythm: regular, clock-like timing is how beacons keep in touch.",
  icon: Network,
  Component: NetworkPage,
};
