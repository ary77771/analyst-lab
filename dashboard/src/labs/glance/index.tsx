// The example lab (copy this folder to start one): the store this dashboard reads, in a few counted numbers.
// Back end: engine/labs/glance.py. Every word and number shown here comes from it.
import { Gauge } from "lucide-react";
import { LabNumber, LabPanel, LabState, useLab } from "../kit";
import type { Lab, LabProps } from "../registry";

interface Glance {
  words: Record<string, string>;
  events: number; hosts: number; programs: number; first: string | null; last: string | null; empty: boolean;
  alerts: number; shown: number; min_level: string; levels: { level: string; count: number }[];
}

const utc = (t: string | null) => (t ? `${t.slice(0, 10)} ${t.slice(11, 19)} UTC` : "?");

function GlanceLab(_: LabProps) {
  const { data: g, error, loading } = useLab<Glance>("/api/labs/glance");
  return (
    <LabState loading={loading} error={error}>
      {g && (
        <LabPanel title={g.words.title} hint={g.words.intro}>
          <LabState empty={g.empty && g.alerts === 0 ? g.words.empty : null}>
            <div className="lab-numbers">
              <LabNumber value={g.events} label={g.words.events} />
              <LabNumber value={g.hosts} label={g.words.hosts} />
              <LabNumber value={g.programs} label={g.words.programs} />
              <LabNumber value={g.alerts} label={g.words.alerts} />
              <LabNumber value={g.shown} label={`${g.words.shown} (${g.min_level})`} />
            </div>
            <p className="ua-hint">{g.words.span}: {utc(g.first)} to {utc(g.last)}</p>
            {g.levels.length > 0 && (
              <p className="ua-hint">{g.words.levels}: {g.levels.map((l) => `${l.level} ${l.count}`).join(" · ")}</p>
            )}
          </LabState>
        </LabPanel>
      )}
    </LabState>
  );
}

export const lab: Lab = {
  id: "glance",
  title: "Store at a glance",
  blurb: "How much this dashboard is looking at: records, machines, programs started and alerts, counted.",
  icon: Gauge,
  Component: GlanceLab,
};
