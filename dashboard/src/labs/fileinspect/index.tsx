// Lab: File inspector (night-tools, 2026-11-23). A program file looked at from the outside: fingerprints,
// signature, PE header, imports grouped by what they make possible, section randomness, text inside.
// Back end: engine/labs/fileinspect.py. Every claim word shown here comes from it (WORDS / summary).
import { useEffect, useMemo, useState } from "react";
import { FileSearch } from "lucide-react";
import { LabNumber, LabPanel, LabState, NextStrip, useAlertParam, useLab } from "../kit";
import { Thing } from "../_things";
import { AlertScope } from "./alertscope";
import { YaraSection } from "./yarasection";
import { labHref, type Lab, type LabProps } from "../registry";
import "./fileinspect.css";

export interface FileItem {
  id: string; name: string; recorded_path: string | null; host: string | null; sha256: string | null;
  kinds: string[]; first: string | null; last: string | null; times: number; match: string;
  match_words: string; inspectable: boolean; evidence?: boolean;
}
interface Words {
  title: string; intro: string; pick: string; pick_alert: string; no_alert_files: string; no_evidence?: string; rebuild?: string; where_from: string; imports_note: string; go_note: string; entropy_note: string;
  strings_note: string; noise_note: string; no_pe: string; not_installed: string; sig_off: string; sig_button: string;
  sections: Record<"hashes" | "signature" | "pe" | "imports" | "entropy" | "strings", string>;
}
interface Listing { words: Words; files: FileItem[]; lab_dirs: number; alert?: { id: string; title: string } | null; evidence_here?: boolean | null }
interface Section { name: string; size: number; virtual_size: number; entropy: number; executable: boolean; writable: boolean; high: boolean }
interface Group { key: string; title: string; means: string; functions: string[] }
interface Pe {
  pe: boolean | null; error?: string; embedded_signature?: boolean; machine?: string; kind?: string; built?: string | null; built_note?: string | null;
  go?: boolean; dlls?: { dll: string; count: number }[]; import_count?: number; groups?: Group[]; go_runtime_left_out?: number;
  sections?: Section[]; packer_sections?: string[]; packed_hint?: boolean;
}
interface Found { items: string[]; count: number; noise: number }
export interface Info {
  name: string; size: number; sha256: string; md5: string; truncated: boolean; summary: string; lookalike?: boolean;
  pe: Pe; strings: Record<"urls" | "ips" | "paths" | "registry", Found>;
  signature: { checked: boolean; reason?: string; can_check?: boolean; status?: string; type?: string; signer?: string; issuer?: string; timestamped?: boolean; os_binary?: boolean; valid?: boolean };
}

const STRING_KINDS: [keyof Info["strings"], string][] = [["urls", "Web addresses"], ["ips", "IP addresses"], ["paths", "Folder paths"], ["registry", "Registry keys"]];

export function bytes(n: number): string {
  const u = ["bytes", "KB", "MB", "GB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return i === 0 ? `${v} bytes` : `${v.toFixed(1)} ${u[i]}`;
}

const RANK: Record<string, number> = { sha256: 0, path: 0, lab: 1 };
/** Files the page lists: recorded files it can open first, then the lab's own files, then the rest; by name. */
export function sortFiles(files: FileItem[], q: string): FileItem[] {
  const s = q.trim().toLowerCase();
  return files
    .filter((f) => !s || f.name.toLowerCase().includes(s) || (f.sha256 ?? "").startsWith(s) || (f.recorded_path ?? "").toLowerCase().includes(s))
    .sort((a, b) => (RANK[a.match] ?? 2) - (RANK[b.match] ?? 2) || a.name.localeCompare(b.name));
}

function FileList({ files, selected, onPick, words, title }: { files: FileItem[]; selected: string | null; onPick: (id: string) => void; words: Words; title?: string }) {
  const [q, setQ] = useState("");
  const shown = useMemo(() => sortFiles(files, q), [files, q]);
  return (
    <LabPanel title={title ?? words.pick} hint={words.where_from}>
      <input className="ft-search" placeholder="Filter by name or SHA-256" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter files" />
      <ul className="ft-files" role="listbox" aria-label={words.pick}>
        {shown.map((f) => (
          <li key={f.id}>
            <button type="button" role="option" aria-selected={f.id === selected} className="ft-file" data-match={f.match}
              disabled={!f.inspectable} title={f.match_words} onClick={() => onPick(f.id)}>
              <b>{f.name}</b>
              <span>{f.kinds.join(" · ")}{f.times > 1 ? ` · ${f.times}×` : ""}{f.host ? ` · ${f.host}` : ""}</span>
              <em>{f.match_words}</em>
              {f.match === "name" && words.rebuild && <span className="ft-tag ft-rebuild">{words.rebuild}</span>}
            </button>
          </li>
        ))}
      </ul>
      {shown.length === 0 && <p className="ua-hint">No file matches.</p>}
    </LabPanel>
  );
}

function Hash({ label, value }: { label: string; value: string }) {
  return (
    <div className="ft-hash">
      <span>{label}</span>
      <code>{value}</code>
      <button type="button" onClick={() => navigator.clipboard?.writeText(value)} title={`Copy ${label}`}>Copy</button>
    </div>
  );
}

function Entropy({ s }: { s: Section }) {
  return (
    <tr data-high={s.high || undefined}>
      <td><code>{s.name || "(no name)"}</code></td>
      <td>{bytes(s.size)}</td>
      <td className="ft-flags">{s.executable ? "run" : ""}{s.writable ? " write" : ""}</td>
      <td className="ft-ent"><i style={{ width: `${(s.entropy / 8) * 100}%` }} /><b>{s.entropy.toFixed(2)}</b></td>
    </tr>
  );
}

function Details({ id, words }: { id: string; words: Words }) {
  const [sig, setSig] = useState(false);              // Windows' signature check only when asked (may go online)
  useEffect(() => setSig(false), [id]);
  const { data, error, loading } = useLab<{ file: FileItem; info: Info }>(
    `/api/labs/fileinspect/inspect/${encodeURIComponent(id)}${sig ? "?signature=true" : ""}`);
  return (
    <LabState loading={loading && !data} error={error}>
      {data && <InfoView file={data.file} info={data.info} words={words} onCheckSignature={() => setSig(true)} />}
    </LabState>
  );
}

export function InfoView({ file, info, words, onCheckSignature }: { file: FileItem; info: Info; words: Words; onCheckSignature?: () => void }) {
  const pe = info.pe, sig = info.signature;
  return (
    <div className="ft-details">
      <LabPanel>
        <div className="ft-title">
          <h2>{info.name}</h2>
          {!info.lookalike && <span data-match={file.match}>{file.match_words}</span>}
        </div>
        {info.lookalike && <p className="ft-lookalike" role="note">{file.match_words}.</p>}
        <p className="ft-summary">{info.summary}</p>
        <div className="lab-numbers">
          <LabNumber value={bytes(info.size)} label="size" />
          {pe.pe && <LabNumber value={pe.import_count ?? 0} label="imported functions" />}
          {pe.pe && <LabNumber value={pe.sections?.length ?? 0} label="sections" />}
          <LabNumber value={STRING_KINDS.reduce((n, [k]) => n + (info.strings[k]?.count ?? 0), 0)} label="addresses, paths and keys in its text" />
        </div>
        <div className="ft-links">
          <Thing kind="hash" value={info.sha256} label="Everything the recording holds with this fingerprint" role="this file's fingerprint" />
        </div>
      </LabPanel>

      <div className="ft-grid">
        <LabPanel title={words.sections.hashes}>
          <Hash label="SHA-256" value={info.sha256} />
          <Hash label="MD5" value={info.md5} />
          {file.recorded_path && <p className="ua-hint">Recorded as <code>{file.recorded_path}</code></p>}
        </LabPanel>

        <LabPanel title={words.sections.signature}>
          {!sig.checked ? (
            <>
              {pe.pe && <p className="ft-summary-small">{pe.embedded_signature ? "The file carries an embedded signature block." : "No embedded signature block in the file (Windows' own tools are usually signed in a catalog instead)."}</p>}
              <p className="ua-hint">{sig.reason}</p>
              {sig.can_check && onCheckSignature && <button type="button" className="ft-btn" onClick={onCheckSignature}>{words.sig_button}</button>}
            </>
          ) : (
            <dl className="ft-dl">
              <dt>Status</dt><dd data-ok={sig.valid || undefined}>{sig.status}</dd>
              <dt>Kind</dt><dd>{sig.type}</dd>
              {sig.signer && <><dt>Signer</dt><dd>{sig.signer}</dd></>}
              {sig.issuer && <><dt>Issued by</dt><dd>{sig.issuer}</dd></>}
              {sig.signer && <><dt>Time-stamped</dt><dd>{sig.timestamped ? "yes" : "no"}</dd></>}
            </dl>
          )}
        </LabPanel>

        <LabPanel title={words.sections.pe}>
          {pe.pe === false && <p className="ua-hint">{words.no_pe}</p>}
          {pe.pe === null && <p className="ua-hint">{pe.error}</p>}
          {pe.pe && (
            <dl className="ft-dl">
              <dt>Type</dt><dd>{pe.machine} {pe.kind}</dd>
              <dt>Built</dt><dd>{pe.built ?? "unknown"}{pe.built_note ? ` (${pe.built_note})` : ""}</dd>
              <dt>Libraries</dt><dd>{(pe.dlls ?? []).map((d) => `${d.dll} (${d.count})`).join(", ") || "none"}</dd>
            </dl>
          )}
          {pe.go && <p className="ua-hint">{words.go_note}</p>}
        </LabPanel>
      </div>

      {pe.pe && (
        <div className="ft-grid ft-grid-2">
          <LabPanel title={words.sections.imports} hint={words.imports_note}>
            {(pe.groups ?? []).length === 0 && <p className="ua-hint">None of the functions in the known groups.</p>}
            {(pe.groups ?? []).map((g) => (
              <div key={g.key} className="ft-group" data-key={g.key}>
                <b>{g.title}</b><span>{g.means}</span>
                <div className="ft-chips">{g.functions.map((f) => <code key={f}>{f}</code>)}</div>
              </div>
            ))}
            {!!pe.go_runtime_left_out && <p className="ua-hint">{pe.go_runtime_left_out} functions every Go program imports were left out.</p>}
          </LabPanel>
          <LabPanel title={words.sections.entropy} hint={words.entropy_note}>
            <table className="ft-table">
              <thead><tr><th>Section</th><th>Size</th><th>Access</th><th>Randomness (0 to 8)</th></tr></thead>
              <tbody>{(pe.sections ?? []).map((s, i) => <Entropy key={`${s.name}-${i}`} s={s} />)}</tbody>
            </table>
          </LabPanel>
        </div>
      )}

      <LabPanel title={words.sections.strings} hint={words.strings_note}>
        <div className="ft-strings">
          {STRING_KINDS.map(([k, label]) => {
            const f = info.strings[k];
            return (
              <div key={k}>
                <b>{label} <small>{f.count}{f.noise ? ` (+${f.noise} ${words.noise_note})` : ""}</small></b>
                {f.items.length === 0 ? <p className="ua-hint">none</p> : (
                  <ul>{f.items.map((s) => <li key={s}>{k === "ips" ? <Thing kind="ip" value={s.split(":")[0]} label={s} role="address in the file's text" /> : <code>{s}</code>}</li>)}</ul>
                )}
                {f.count > f.items.length && <p className="ua-hint">and {f.count - f.items.length} more</p>}
              </div>
            );
          })}
        </div>
      </LabPanel>
      <YaraSection id={file.id} />
    </div>
  );
}

function FileInspectLab({ params }: LabProps) {
  const [alert, setAlert] = useAlertParam();
  const { data, error, loading } = useLab<Listing>(alert ? `/api/labs/fileinspect?alert=${encodeURIComponent(alert)}` : "/api/labs/fileinspect");
  const [picked, setPicked] = useState<string | null>(params.get("id") ?? params.get("sha256"));
  const pick = (id: string) => {
    setPicked(id);
    try { history.replaceState(null, "", labHref("fileinspect", { id, alert })); } catch { /* address bar only */ }
  };
  // with an alert and nothing picked: open the first file that IS the evidence (exact content); never a rebuild by itself
  const first = alert ? data?.files.find((f) => f.inspectable && f.evidence) ?? null : null;
  const current = data?.files.find((f) => f.id === picked && f.inspectable) ?? first;
  return (
    <div className="ft-details">
      <NextStrip current="fileinspect" alert={alert} />
      <LabState loading={loading} error={error}>
        {data && (
          <>
            <AlertScope alert={alert} title={data.alert?.title} onClear={() => setAlert(null)} what="Programs and files" />
            {data.evidence_here === false && data.files.length > 0 && <p className="ft-lookalike" role="note">{data.words.no_evidence}</p>}
            <div className="ft-layout">
              <FileList files={data.files} selected={current?.id ?? null} onPick={pick} words={data.words} title={alert ? data.words.pick_alert : undefined} />
              {current ? <Details id={current.id} words={data.words} /> : (
                <p className="lab-state" data-kind="empty">
                  {alert && data.files.length === 0 ? data.words.no_alert_files : picked ? "That file has no copy here to open." : "Pick a file on the left."} {data.words.intro}
                </p>
              )}
            </div>
          </>
        )}
      </LabState>
    </div>
  );
}

export const lab: Lab = {
  id: "fileinspect",
  title: "File check",
  blurb: "Open a program the recording mentions: fingerprints, signature, what Windows functions it asks for, the text inside, and which published YARA rules fit.",
  icon: FileSearch,
  group: "far",
  Component: FileInspectLab,
};
