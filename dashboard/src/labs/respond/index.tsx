// Lab "What to do next" (engine/labs/respond.py): MITRE's published response steps for the techniques an
// alert's rule names: ATT&CK mitigations and D3FEND defensive techniques. Words and steps come from Python.
import { ListChecks } from "lucide-react";
import { LabPanel, LabState, NextStrip, useAlertParam, useLab } from "../kit";
import { labHref, type Lab, type LabProps } from "../registry";
import { fill } from "../_explain/logic";
import { AlertPicker, Level, type AlertRow } from "../_explain/shared";
import "./respond.css";

type W = Record<string, string> & { tactics: Record<string, string> };
interface Link { defence: string; defence_rel: string; artifact: string; attack_rel: string; attack_artifact: string }
interface Defence { id: string | null; name: string; definition: string; links: Link[]; more_links: number }
interface Mitigation { id: string; name: string; url: string; how: string; description: string }
interface Technique { id: string; name: string; url: string; description: string; mitigations: Mitigation[]; source?: "tags" | "reading" | null; reason?: string | null;
  d3fend: { via: string; count: number; url: string; tactics: { tactic: string; techniques: Defence[] }[] } | null }
export interface Next {
  words: W; alert: AlertRow; attack: { available: boolean; version: string | null }; d3fend: { available: boolean; version: string | null };
  techniques: Technique[]; rule_tags: string[];
}

/** MITRE's description cut after its first sentence (the rest folded): the first screen keeps the steps in view. */
export function splitFirst(text: string): [string, string] {
  const s = (text || "").trim();
  const m = s.match(/^(.+?[.!?])\s+(?=[A-Z(])/);
  return m ? [m[1], s.slice(m[0].length).trim()] : [s, ""];
}

function TechniqueSteps({ t, d }: { t: Technique; d: Next }) {
  const w = d.words;
  return (
    <section className="ua-panel lab-panel nx-tech">
      <div className="xp-row">
        <span className="xp-small xp-dim">{t.source === "reading" ? w.technique_reading : w.technique}</span>
        <a className="xp-chip" href={labHref("techniques", { technique: t.id })}>{t.id}</a>
        <h2 className="xp-title">{t.name}</h2><span className="xp-grow" />
        <a className="xp-link" href={t.url} target="_blank" rel="noreferrer">{w.open_mitre}</a>
      </div>
      {t.source === "reading" && t.reason ? <p className="xp-note" data-kind="declared">{t.reason.charAt(0).toUpperCase() + t.reason.slice(1)}.</p> : null}
      {(() => { const [first, rest] = splitFirst(t.description); return (
        <>{first ? <p className="xp-text">{first}</p> : null}
          {rest ? <details className="nx-more"><summary className="xp-small xp-dim">{w.technique_more ?? "more"}</summary><p className="xp-text">{rest}</p></details> : null}</>); })()}
      <div className="nx-cols">
        <div className="nx-col">
          <h3 className="xp-sub"><span className="xp-hint" title={w.attack_hint}>{w.mitigations}</span> <span className="xp-small xp-dim">· {fill(w.source_attack, { version: d.attack.version ?? "?" })}</span></h3>
          <p className="xp-small xp-dim">{w.mitigations_note}</p>
          {t.mitigations.length === 0 ? <p className="xp-small xp-muted">{w.no_mitigations}</p> : (
            <ol className="nx-steps">{t.mitigations.map((m) => (
              <li key={m.id} className="nx-mit">
                <div className="xp-row"><a className="xp-chip" href={m.url} target="_blank" rel="noreferrer">{m.id}</a><b>{m.name}</b></div>
                <p className="nx-how">{m.description || m.how}</p>
                {m.how && m.description ? <details className="nx-more"><summary className="xp-small xp-dim">{w.how_title ?? "more"}</summary><p className="xp-small xp-dim">{m.how}</p></details> : null}
              </li>))}</ol>)}
        </div>
        <div className="nx-col">
          <h3 className="xp-sub"><span className="xp-hint" title={w.d3fend_hint}>{w.d3fend}</span> {d.d3fend.version ? <span className="xp-small xp-dim">· {fill(w.source_d3fend, { version: d.d3fend.version })}</span> : null}</h3>
          {!d.d3fend.available ? <p className="xp-small xp-muted">{w.no_d3fend_data}</p> : !t.d3fend || t.d3fend.count === 0 ? <p className="xp-small xp-muted">{w.no_d3fend}</p> : (
            <>
              <p className="xp-small xp-dim">{w.d3fend_note}{" "}<a className="nx-ext" href={t.d3fend.url} target="_blank" rel="noreferrer">{w.open_d3fend}</a></p>
              {t.d3fend.via !== t.id ? <p className="xp-small xp-ink-gap">{fill(w.d3fend_via, { asked: t.id, via: t.d3fend.via })}</p> : null}
              {t.d3fend.tactics.map((g) => (
                <details key={g.tactic} className="nx-group" open={["Evict", "Isolate", "Restore"].includes(g.tactic)}>
                  <summary><b data-tactic={g.tactic}>{g.tactic}</b><span className="xp-dim"> · {w.tactics[g.tactic] ?? ""} · {g.techniques.length}</span></summary>
                  <ul className="nx-defs">{g.techniques.map((x) => (
                    <li key={x.name}>
                      <div className="xp-row">{x.id ? <code className="xp-chip">{x.id}</code> : null}<b>{x.name}</b></div>
                      {x.definition ? <p className="xp-small xp-muted">{x.definition}</p> : null}
                      {x.links.length || x.more_links ? <details className="nx-more"><summary className="xp-small xp-dim">{w.links_title ?? "more"}</summary>
                        {x.links.map((l, i) => <p key={i} className="nx-link xp-small xp-dim">{fill(w.link_words, { ...l })}</p>)}
                        {x.more_links ? <p className="nx-link xp-small xp-dim">{fill(w.more_links, { n: x.more_links })}</p> : null}</details> : null}
                    </li>))}</ul>
                </details>))}
            </>)}
        </div>
      </div>
    </section>
  );
}

export function NextView({ d }: { d: Next }) {
  const w = d.words;
  return (
    <>
      <LabPanel>
        <div className="xp-row"><Level level={d.alert.level} /><h2 className="xp-title">{d.alert.title}</h2>
          <span className="xp-small xp-dim xp-mono">{d.alert.time}</span></div>
        <p className="ua-hint">{w.intro}</p>
      </LabPanel>
      {!d.attack.available ? <p className="lab-state" data-kind="empty">{w.no_attack}</p>
        : d.techniques.length === 0 ? <p className="lab-state" data-kind="empty">{w.no_tags}</p>
        : d.techniques.map((t) => <TechniqueSteps key={t.id} t={t} d={d} />)}
      <p className="ua-hint">{w.legal}</p>
    </>
  );
}

function NextLab(_: LabProps) {
  const [alert] = useAlertParam();
  const { data, error, loading } = useLab<Next>(alert ? `/api/labs/respond/${encodeURIComponent(alert)}` : null);
  if (!alert) return <AlertPicker lab="respond" url="/api/labs/respond" />;
  return <><NextStrip current="respond" alert={alert} /><LabState loading={loading} error={error}>{data && <NextView d={data} />}</LabState></>;
}

export const lab: Lab = {
  id: "respond",
  title: "What to do next",
  blurb: "For one alert: MITRE's published response steps (ATT&CK mitigations, D3FEND defences), each with its source.",
  icon: ListChecks,
  Component: NextLab,
};
