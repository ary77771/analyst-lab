// Lab: Process tree (night-tools, 2026-11-24). For one alert: which program started which, each with its full
// command line, user and start time; the alert's own programs marked, the lab's test machinery dimmed, the parts
// of a command line to read first highlighted. Back end: engine/labs/tree.py (every word from there).
import { useEffect, useState, type ReactNode } from "react";
import { GitBranch } from "lucide-react";
import { LabPanel, LabState, NextStrip, useAlertParam, useLab } from "../kit";
import { Thing } from "../_things";
import type { Lab, LabProps } from "../registry";
import "./tree.css";

interface Words {
  title: string; intro: string; pick: string; first: string; first_why: string; marks_note: string; not_recorded: string;
  harness: string; own: string; show_harness: string; none: string; kinds: Record<string, string>;
  show_full?: string; show_branch?: string; folded_note?: string;
}
export interface TreeNode {
  guid: string; name: string; image: string | null; cmd: string | null; user: string | null; time: string | null; pid: number | string | null;
  parent: string | null; children: string[]; depth: number; own: boolean; ancestor: boolean; harness: boolean; recorded: boolean;
  marks: [number, number, string][];
  /** In the alert's own branch (its programs, what they started, the program one level up); its depth there. */
  branch?: boolean; branch_depth?: number | null;
}
interface Body {
  words: Words; alerts: { id: string; title: string; level: string; time: string }[];
  alert: { id: string; title: string; host: string; time: string } | null;
  tree: { nodes: TreeNode[]; roots: string[]; focus: string | null; truncated: boolean; folded?: number } | null;
  first?: { guid: string; why: string };
  /** Set when the store is a replay still playing and has not reached the alert yet: said, then asked again. */
  waiting?: string;
}

export const RETRY_MS = 3000;

/** Ask again once, RETRY_MS from now; returns the cancel (the effect's clean-up). */
export function retryLater(retry: () => void, ms = RETRY_MS): () => void {
  const t = setTimeout(retry, ms);
  return () => clearTimeout(t);
}

/** The replay hasn't reached the alert yet: the words, and the page asks again by itself. */
export function Waiting({ text, retry }: { text: string; retry: () => void }) {
  useEffect(() => retryLater(retry), [text, retry]);
  return <p className="lab-state" data-kind="loading" role="status">{text}</p>;
}

const utc = (t: string | null) => (t ? `${t.slice(0, 10)} ${t.slice(11, 19)} UTC` : "");

/** A command line with its marked parts highlighted (the marks are Python's: [start, end, kind]). */
export function CmdLine({ cmd, marks, kinds }: { cmd: string | null; marks: TreeNode["marks"]; kinds: Record<string, string> }) {
  if (!cmd) return <code className="tr-cmd tr-none">(no command line recorded)</code>;
  const parts: ReactNode[] = [];
  let at = 0;
  marks.forEach(([s, e, k], i) => {
    if (s > at) parts.push(<span key={`t${i}`}>{cmd.slice(at, s)}</span>);
    parts.push(<mark key={`m${i}`} data-kind={k} title={kinds[k] ?? k}>{cmd.slice(s, e)}</mark>);
    at = e;
  });
  if (at < cmd.length) parts.push(<span key="end">{cmd.slice(at)}</span>);
  return <code className="tr-cmd">{parts}</code>;
}

/** The rows to show and how deep each sits: the alert's own branch (folded, the default) or the whole tree. */
export function shownNodes(nodes: TreeNode[], full: boolean): { n: TreeNode; depth: number }[] {
  if (full) return nodes.map((n) => ({ n, depth: n.depth }));
  return nodes.filter((n) => n.branch !== false).map((n) => ({ n, depth: n.branch_depth ?? n.depth }));
}

export function NodeRow({ n, words, host, first, depth = n.depth }: { n: TreeNode; words: Words; host: string | null; first: boolean; depth?: number }) {
  return (
    <li className="tr-node" data-own={n.own || undefined} data-harness={n.harness || undefined} data-first={first || undefined}
      style={{ marginLeft: `${depth * 1.75}rem` }}>
      <div className="tr-head">
        {n.recorded && n.image ? <Thing field="Image" value={n.image} host={host} role="program" label={n.name} />
          : <b className="tr-name">{n.name}</b>}
        {n.own && <span className="tr-tag" data-kind="own">{words.own}</span>}
        {n.harness && <span className="tr-tag" data-kind="harness">{words.harness}</span>}
        {!n.recorded && <span className="tr-tag" data-kind="gap" title={words.not_recorded}>start not recorded</span>}
        <span className="tr-meta">{utc(n.time)}{n.user ? ` · ${n.user}` : ""}{n.pid != null ? ` · PID ${n.pid}` : ""}</span>
      </div>
      <CmdLine cmd={n.cmd} marks={n.marks} kinds={words.kinds} />
      {!n.recorded && <p className="tr-note">{words.not_recorded}.</p>}
    </li>
  );
}

function TreeLab(_: LabProps) {
  const [alert, setAlert] = useAlertParam();
  const { data, error, loading, reload } = useLab<Body>(alert ? `/api/labs/tree?alert=${encodeURIComponent(alert)}` : "/api/labs/tree");
  const first = data?.tree?.nodes.find((n) => n.guid === data?.first?.guid) ?? null;
  const [full, setFull] = useState(false);              // folded to the alert's branch until asked (critique 3 #9)
  useEffect(() => setFull(false), [alert]);
  return (
    <div className="tr-page">
      <NextStrip current="tree" alert={alert} />
      {alert && data?.waiting && <Waiting text={data.waiting} retry={reload} />}
      <LabState loading={loading && !data?.waiting} error={error}>
        {data && (
          <>
            {!alert && (
              <LabPanel title={data.words.pick} hint={data.words.intro}>
                {data.alerts.length === 0 ? <p className="lab-state" data-kind="empty">No alert at or above the screens' level in this store.</p> : (
                  <ul className="tr-alerts">
                    {data.alerts.map((a) => (
                      <li key={a.id}><button type="button" className="tr-alert" onClick={() => setAlert(a.id)}>
                        <b>{a.title}</b><span>{a.level} · {utc(a.time)}</span>
                      </button></li>
                    ))}
                  </ul>
                )}
              </LabPanel>
            )}
            {alert && data.alert && data.tree && (
              <>
                <LabPanel title={data.alert.title} hint={data.words.intro}>
                  {first && data.first && (
                    <div className="tr-first">
                      <span className="tr-first-label">{data.words.first}:</span> <b>{first.name}</b>
                      <span className="tr-meta">({data.first.why})</span>
                      <CmdLine cmd={first.cmd} marks={first.marks} kinds={data.words.kinds} />
                    </div>
                  )}
                  <p className="ua-hint">{data.words.marks_note}</p>
                </LabPanel>
                <LabPanel>
                  {(data.tree.folded ?? 0) > 0 && (
                    <div className="tr-fold">
                      {!full && data.words.folded_note && <span className="ua-hint">{data.words.folded_note}</span>}
                      <button type="button" className="ua-btn tr-foldbtn" aria-pressed={full} onClick={() => setFull(!full)}>
                        {full ? data.words.show_branch : (data.words.show_full ?? "show the full chain ({n} more programs)").replace("{n}", String(data.tree.folded))}
                      </button>
                    </div>
                  )}
                  {data.tree.nodes.length === 0 ? <p className="lab-state" data-kind="empty">{data.words.none}</p> : (
                    <ol className="tr-tree">
                      {shownNodes(data.tree.nodes, full).map(({ n, depth }) => (
                        <NodeRow key={n.guid} n={n} depth={depth} words={data.words} host={data.alert!.host} first={n.guid === data.first?.guid} />
                      ))}
                    </ol>
                  )}
                  {data.tree.truncated && <p className="ua-hint">Only the first 200 programs are shown.</p>}
                </LabPanel>
              </>
            )}
          </>
        )}
      </LabState>
    </div>
  );
}

export const lab: Lab = {
  id: "tree",
  title: "Process tree",
  blurb: "Which program started which around an alert, each with its full command line, user and start time; the telling parts marked.",
  icon: GitBranch,
  group: "happened",
  Component: TreeLab,
};
