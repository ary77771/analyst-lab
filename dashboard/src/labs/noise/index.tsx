// Labs page "Noise meter" (night-hunt, VISION idea 8): alerts shown per active hour on the laptop's ordinary
// weeks, v2 -> v3 -> v4. Every number and word comes from engine/labs/noise.py, which reads the committed
// official results at the commits that committed them. Counts only.
import { Gauge } from "lucide-react";
import type { Lab, LabProps } from "../registry";
import { count } from "../hunts/logic";
import { Panel, Status, useJSON } from "../hunts/shared";
import "../hunts/hunt.css";

interface Version {
  version: string; commit: string; path: string; week: string; code: string; ok: boolean; problem?: string;
  active_hours?: number; raised?: number; per_hour?: number; all_levels?: number; all_per_hour?: number;
  levels?: Record<string, number>; rules?: number; top_rule_share?: number;
}
interface Meter { versions: Version[]; words: Record<string, string> }

export function NoisePage(_: LabProps) {
  const { data: d, error, loading } = useJSON<Meter>("/api/labs/noise/");
  const ok = d?.versions.filter((v) => v.ok) ?? [];
  const max = Math.max(1, ...ok.map((v) => v.per_hour ?? 0));
  return (
    <div className="hn" data-hunt-page="noise">
      <Status loading={loading && !d} error={error} />
      {d && (
        <Panel title={d.words.title} intro={d.words.intro}>
          <div className="hn-noise">
            {d.versions.map((v) => (
              <div key={v.version} className="hn-noise-row" data-version={v.version}>
                <div className="hn-noise-name"><b>{v.version}</b><span>{v.code}</span></div>
                {v.ok ? (
                  <>
                    <div className="hn-noise-bar" title={`${count(v.raised)} alerts shown in ${v.active_hours} active hours`}>
                      <i style={{ width: `${Math.max(0.6, ((v.per_hour ?? 0) / max) * 100)}%` }} />
                    </div>
                    <div className="hn-noise-num"><b>{v.per_hour?.toFixed(1)}</b><span>{d.words.unit}</span></div>
                    <p className="hn-noise-sub">
                      {count(v.raised)} alerts in {v.active_hours} active hours · <b>{v.week}</b>
                      {v.top_rule_share != null && <> · {d.words.top_rule.replace("{share}", String(v.top_rule_share))}</>}
                      <br /><span className="hn-span">source: <code>{v.path}</code> at commit <code>{v.commit}</code></span>
                    </p>
                  </>
                ) : <p className="hn-note" data-kind="gap">{v.problem}</p>}
              </div>
            ))}
          </div>
          <p className="hn-noise-honest">{d.words.honest}</p>
          <p className="ua-hint">{d.words.active} {d.words.source}</p>
        </Panel>
      )}
    </div>
  );
}

export const lab: Lab = {
  id: "noise",
  title: "Noise meter",
  blurb: "How many alerts an analyst would see per hour on an ordinary laptop week: version 2, 3 and 4, read from the committed results.",
  icon: Gauge,
  Component: NoisePage,
};
