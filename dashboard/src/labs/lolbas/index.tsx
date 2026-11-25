// Lab: Built-in tools check (LOLBAS) (night-tools, 2026-11-23). Windows' own programs that the LOLBAS project
// documents as misusable, as they ran in the recording, with the documented use each run resembles.
// Back end: engine/labs/lolbas.py (the catalogue's own words are shown as the catalogue's).
import { useState } from "react";
import { Wrench } from "lucide-react";
import { LabNumber, LabPanel, LabState, NextStrip, useAlertParam, useLab } from "../kit";
import { Thing } from "../_things";
import { AlertScope } from "../fileinspect/alertscope";
import { labHref, type Lab, type LabProps } from "../registry";
import "../fileinspect/fileinspect.css";
import { Jargon } from "../fileinspect/jargon";

interface Words { title: string; intro: string; none_seen_alert?: string; jargon?: Record<string, string>; resemble: string; resemble_note: string; renamed: string; odd_place: string; no_data: string; none_seen: string; source: string }
interface Use { score: number; matched: string[]; of: number; category: string | null; usecase: string | null; description: string | null; command: string | null; mitre: string | null; privileges: string | null }
interface Run {
  time: string | null; host: string | null; image: string; command_line: string | null; parent: string | null; user: string | null;
  renamed_from: string | null; documented_place: boolean | null; sha256: string | null; match: Use | null; nearest: Use | null;
}
export interface Tool {
  name: string; description: string | null; type: string; categories: string[]; mitre: string[]; page: string;
  runs: Run[]; times: number; resembling: number; renamed: number; odd_place: number;
}
interface Body {
  words: Words; state: "ready" | "no_data" | "error"; error?: string; tools: Tool[]; catalogue_size?: number; runs?: number; resembling?: number;
  alert?: { id: string; title: string } | null;
}

const utc = (t: string | null) => (t ? `${t.slice(0, 10)} ${t.slice(11, 19)} UTC` : "");
export const fill = (s: string, v: Record<string, string | number>) => s.replace(/\{(\w+)\}/g, (_, k) => String(v[k] ?? `{${k}}`));

function RunView({ r, words }: { r: Run; words: Words }) {
  const u = r.match;
  return (
    <div className="ft-run" data-resembles={u ? true : undefined}>
      <span className="ft-muted ft-runhead">{utc(r.time)}{r.host ? ` · ${r.host}` : ""}{r.parent ? <> · started by <Thing field="ParentImage" value={r.parent} host={r.host} role="parent program" /></> : ""}{r.user ? ` · ${r.user}` : ""}</span>
      <code>{r.command_line ?? r.image}</code>
      {r.renamed_from && <span className="ft-tag" data-on>{fill(words.renamed, { orig: r.renamed_from })}</span>}
      {r.documented_place === false && <span className="ft-tag" data-on title={r.image}>{words.odd_place}</span>}
      {u && (
        <span>
          <b>{u.category}</b>{u.mitre ? ` · ${u.mitre}` : ""}: {u.usecase ?? u.description} · {fill(words.resemble, { n: u.matched.length, of: u.of })}
          {u.command && <><br /><span className="ft-muted">documented: </span><code>{u.command}</code></>}
        </span>
      )}
      <span className="ft-muted ft-runhead">
        <Thing field="Image" value={r.image} host={r.host} role="program" />
        {r.sha256 && <><Thing kind="hash" value={r.sha256} host={r.host} role="fingerprint" />
          <a className="ft-a" href={labHref("fileinspect", { id: r.sha256 })}>open in the File inspector</a></>}
      </span>
    </div>
  );
}

function ToolView({ t, words }: { t: Tool; words: Words }) {
  const [open, setOpen] = useState(t.resembling > 0 || t.renamed > 0);
  return (
    <div className="ft-tool">
      <header>
        <b>{t.name}</b>
        <span>ran {t.times}×{t.resembling ? ` · ${t.resembling} resembling a documented use` : ""}</span>
        {t.categories.map((c) => <span key={c} className="ft-tag">{c}</span>)}
        <a className="ft-a" href={t.page} target="_blank" rel="noreferrer noopener">LOLBAS page</a>
        <button type="button" className="ft-btn" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "Hide runs" : "Show runs"}</button>
      </header>
      {t.description && <span className="ft-muted">{t.description}{t.mitre.length ? ` · ATT&CK ${t.mitre.join(", ")}` : ""}</span>}
      {open && t.runs.map((r, i) => <RunView key={`${r.time}-${i}`} r={r} words={words} />)}
    </div>
  );
}

function LolbasLab(_: LabProps) {
  const [alert, setAlert] = useAlertParam();
  const { data, error, loading } = useLab<Body>(alert ? `/api/labs/lolbas?alert=${encodeURIComponent(alert)}` : "/api/labs/lolbas");
  return (
    <div className="ft-details">
    <NextStrip current="lolbas" alert={alert} />
    <LabState loading={loading} error={error}>
      {data && (
        <LabPanel title={data.words.title} hint={data.words.intro}>
          <Jargon terms={data.words.jargon} />
          <AlertScope alert={alert} title={data.alert?.title} onClear={() => setAlert(null)} what="Windows' own tools" />
          {data.state === "no_data" && <p className="lab-state" data-kind="empty">{data.words.no_data}</p>}
          {data.state === "error" && <p className="lab-state" data-kind="error">{data.error}</p>}
          {data.state === "ready" && (
            <>
              <div className="lab-numbers">
                <LabNumber value={data.tools.length} label="catalogued tools that ran" />
                <LabNumber value={data.runs ?? 0} label="runs of them" />
                <LabNumber value={data.resembling ?? 0} label="runs resembling a documented use" />
                <LabNumber value={data.catalogue_size ?? 0} label="tools in the catalogue" />
              </div>
              <p className="ua-hint">{data.words.resemble_note}</p>
              {data.tools.length === 0 ? <p className="lab-state" data-kind="empty">{alert ? data.words.none_seen_alert ?? data.words.none_seen : data.words.none_seen}</p> :
                data.tools.map((t) => <ToolView key={t.name} t={t} words={data.words} />)}
            </>
          )}
          <p className="ua-hint">{data.words.source}</p>
        </LabPanel>
      )}
    </LabState>
    </div>
  );
}

export const lab: Lab = {
  id: "lolbas",
  title: "Built-in tools check",
  blurb: "Windows' own tools that can be misused (LOLBAS): which of them ran here, and whether a run looks like a documented misuse.",
  icon: Wrench,
  group: "far",
  Component: LolbasLab,
};
