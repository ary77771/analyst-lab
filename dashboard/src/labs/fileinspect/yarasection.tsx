// File check, YARA section (night-tools, night 2: the YARA page folded into the File inspector). Published YARA
// rules run over the file that is open, here on the laptop. Back end: engine/labs/yara.py; rule texts
// (description, author, licence) are the rule authors' own, shown as theirs. A rebuild is marked as not evidence.
import { LabPanel, LabState, useLab } from "../kit";
import { Jargon } from "./jargon";

interface Words { title: string; intro: string; jargon?: Record<string, string>; match_note: string; no_engine: string; no_rules: string; none_matched: string }
interface Status { state: "ready" | "no_engine" | "no_rules"; engine?: string | null; rules?: number; sets?: { name: string; rules: number; source: Record<string, string> }[] }
interface Pattern { id: string; hits: number; offsets: number[]; preview: string }
export interface Match {
  rule: string; namespace: string; set: string | null; tags: string[]; description?: string | null; author?: string | null;
  reference?: string | null; license?: string | null; score?: string | number | null; date?: string | null; patterns: Pattern[];
}
interface Scan { matches: Match[]; truncated: boolean; seconds: number; rebuild?: string }

export function MatchCard({ m }: { m: Match }) {
  return (
    <div className="ft-group">
      <b><code>{m.rule}</code>{m.set && <small className="ft-muted"> · {m.set}</small>}{m.score != null && <small className="ft-muted"> · score {m.score}</small>}</b>
      {m.description && <span>“{m.description}”</span>}
      <span className="ft-muted">
        {m.author ? `by ${m.author}` : "author not given"}{m.license ? ` · licence: ${m.license}` : ""}{m.date ? ` · ${m.date}` : ""}
        {m.reference && <> · <a href={m.reference} target="_blank" rel="noreferrer noopener">reference</a></>}
      </span>
      <div className="ft-chips">
        {m.patterns.map((p) => <code key={p.id} title={`at byte ${p.offsets.join(", ")}`}>{p.id} ×{p.hits}: {p.preview}</code>)}
      </div>
    </div>
  );
}

/** The YARA panel for one open file: rules loaded once by the back end, the file scanned when the panel shows. */
export function YaraSection({ id }: { id: string }) {
  const meta = useLab<{ words: Words; status: Status }>("/api/labs/yara");
  const ready = meta.data?.status.state === "ready";
  const scan = useLab<Scan>(ready ? `/api/labs/yara/scan/${encodeURIComponent(id)}` : null);
  const w = meta.data?.words, st = meta.data?.status;
  return (
    <LabPanel title="YARA: published pattern rules" hint={w?.intro}>
      <LabState loading={meta.loading} error={meta.error}>
        {w && st && (
          <>
            <Jargon terms={w.jargon} />
            {st.state !== "ready" ? <p className="ua-hint">{st.state === "no_engine" ? w.no_engine : w.no_rules}</p> : (
              <LabState loading={scan.loading} error={scan.error}>
                {scan.data && (
                  <>
                    {scan.data.rebuild && <p className="ft-lookalike" role="note">{scan.data.rebuild}</p>}
                    {scan.data.matches.length === 0 ? <p className="ft-summary-small">{w.none_matched}</p> :
                      scan.data.matches.map((m) => <MatchCard key={`${m.namespace}:${m.rule}`} m={m} />)}
                    <p className="ua-hint">
                      {st.engine} · {(st.sets ?? []).map((s) => `${s.name}${s.source.version ? ` ${s.source.version}` : ""} (${s.rules} rules)`).join(" · ")}
                      {` · ${scan.data.seconds} s`}{scan.data.truncated ? " · only the first 200 MB were scanned" : ""}
                    </p>
                  </>
                )}
              </LabState>
            )}
            <p className="ua-hint">{w.match_note}</p>
          </>
        )}
      </LabState>
    </LabPanel>
  );
}
