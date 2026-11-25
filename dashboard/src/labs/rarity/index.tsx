// Labs page "First seen / rare here" (night-hunt): stack counting. Every program, parent -> child pair
// and network destination counted over a period, rarest first; NEW = first seen in the focus at the
// period's end. Data and words: engine/labs/rarity.py (/api/labs/rarity/).
import { useState } from "react";
import { ScanSearch } from "lucide-react";
import type { Lab, LabProps } from "../registry";
import { NextStrip, useAlertParam } from "../kit";
import { apiQuery, count, shortTime, type WindowName } from "../hunts/logic";
import { AlertBanner, BigNumber, Notes, Panel, ResultTable, Status, Term, WindowPicker, useJSON, useParam, useWindowParam, type AlertInView, type Column, type Meta, type ResultRow } from "../hunts/shared";

type Kind = "programs" | "pairs" | "destinations";
interface Row extends ResultRow { new: boolean; alert?: boolean }
interface Stack extends Meta {
  alert: AlertInView | null;
  alert_items: { item: string; seen: number; rank: number; of: number; new: boolean }[];
  kind: Kind; title: string; item: string; explain: string; focus: string; can_mark_new: boolean;
  baseline: { since: string; until: string } | null;
  items: number; events: number; new: number; once: number; tail: { label: string; items: number }[];
  rows: Row[]; shown_of: number; truncated: boolean; notes: string[]; ms: number; cached: boolean; kinds: Record<Kind, string>;
}

const KINDS: Kind[] = ["programs", "pairs", "destinations"];
const KIND_WORDS: Record<Kind, string> = { programs: "Programs", pairs: "Parent → child", destinations: "Network destinations" };
const FOCUS = ["1h", "24h", "7d"] as const;
const PERIODS: readonly WindowName[] = ["24h", "7d", "30d", "all"];

function columns(kind: Kind, item: string): Column[] {
  const flag: Column = { key: "flag", label: "New?" };
  if (kind === "programs") return [{ key: "item", label: item, kind: "path" }, { key: "seen", label: "Times seen", kind: "num" }, flag];
  if (kind === "pairs") return [{ key: "item", label: item }, { key: "parent", label: "Parent file", kind: "path" }, { key: "seen", label: "Times seen", kind: "num" }, flag];
  return [{ key: "item", label: item, kind: "path" }, { key: "name", label: "Name (if recorded)", kind: "path" }, { key: "programs", label: "Programs", kind: "num" },
    { key: "seen", label: "Connections", kind: "num" }, flag];
}

function Tail({ tail, total }: { tail: Stack["tail"]; total: number }) {
  const max = Math.max(1, ...tail.map((t) => t.items));
  return (
    <div className="hn-tail" aria-label="How many items were seen how often">
      {tail.map((t) => (
        <div key={t.label} className="hn-tail-row">
          <span>{t.label}</span>
          <i><b style={{ width: `${(t.items / max) * 100}%` }} /></i>
          <em>{count(t.items)}{total ? ` · ${Math.round((t.items / total) * 100)} %` : ""}</em>
        </div>
      ))}
    </div>
  );
}

export function RarityPage({ params }: LabProps) {
  const [win, setWin] = useWindowParam(params, "7d");
  const [kindP, setKind] = useParam(params, "kind", "programs");
  const [focus, setFocus] = useParam(params, "focus", "24h");
  const [newOnly, setNewOnly] = useState(params.get("new") === "1");
  const kind = (KINDS as string[]).includes(kindP) ? (kindP as Kind) : "programs";
  const [alert, setAlert] = useAlertParam();                       // wave 3 / N2: "?alert=<id>" limits to its run
  const [all, setAll] = useParam(params, "all", "");
  const q = apiQuery({ kind, window: win, focus, new_only: newOnly, limit: 300, alert, only_alert: alert ? (all ? "false" : "true") : null });
  const { data, error, loading } = useJSON<Stack>(`/api/labs/rarity/?${q}`);
  const d = data && data.kind === kind ? data : null;
  const rows = (d?.rows ?? []).map((r) => ({ ...r, cells: { ...r.cells, flag: r.new ? "new" : "" } }));

  return (
    <div className="hn" data-hunt-page="rarity">
      <NextStrip current="rarity" alert={alert} />
      <AlertBanner alert={d?.alert} words={d?.scope_words} onAll={(b) => { setAll(b ? "1" : null); if (b) setWin("all"); }} onClear={() => setAlert(null)} />
      <p className="ua-hint"><Term plain="the rarer, the more interesting">Stack counting</Term>: count how often each program, parent
        → child pair and address happened on this machine, then read from the rarest up.</p>
      <div className="hn-bar">
        <div role="tablist" aria-label="What to count" className="hn-seg hn-words">
          {KINDS.map((k) => <button key={k} role="tab" aria-pressed={k === kind} onClick={() => setKind(k)}>{KIND_WORDS[k]}</button>)}
        </div>
        <WindowPicker value={d?.alert?.limited ? ("" as WindowName) : win} onChange={(nw) => { if (d?.alert?.limited) setAll("1"); setWin(nw); }} choices={PERIODS} meta={d} />
      </div>
      <div className="hn-bar">
        <span className="hn-span">Mark as <b>new</b> what the period first saw in its last</span>
        <div role="radiogroup" aria-label="New means first seen in the last" className="hn-seg">
          {FOCUS.map((f) => <button key={f} role="radio" aria-checked={f === focus} onClick={() => setFocus(f)}>{f}</button>)}
        </div>
        <label className="hn-check"><input type="checkbox" checked={newOnly} onChange={(e) => setNewOnly(e.target.checked)} />show only new</label>
      </div>
      <Status loading={loading && !d} error={error} />
      {d && (
        <div className="hn-split hn-split-wide">
          <Panel title="The long tail" intro="Most things repeat; the few seen once or twice sit at the top of the list.">
            <div className="hn-stats">
              <BigNumber value={count(d.items)} label={`different ${KIND_WORDS[kind].toLowerCase()}`} />
              <BigNumber value={count(d.once)} label="seen only once" />
              <BigNumber value={d.can_mark_new ? count(d.new) : "-"}
                label={d.baseline ? `new in the last ${d.focus}` : "new: no earlier recording to compare with"} />
            </div>
            <Tail tail={d.tail} total={d.items} />
            <p className="hn-span">{d.baseline
              ? <>Compared with: <b>{shortTime(d.baseline.since)}</b> to <b>{shortTime(d.baseline.until)}</b> UTC (what was recorded before the last {d.focus})</>
              : <>Compared with: nothing. This period has no recording from before its last {d.focus}.</>}</p>
          </Panel>
          <Panel title={`${d.title}, rarest first`} intro={d.explain}
            right={<span className="hn-span">{count(d.events)} {kind === "destinations" ? "connections" : "starts"} counted · {d.ms} ms{d.cached ? " (remembered)" : ""}</span>}>
            {d.alert_items?.length > 0 && (
              <p className="hn-alertbar">This alert's {kind === "pairs" ? "parent → program pairs" : "programs"} here: {d.alert_items.map((a, i) => (
                <span key={a.item}>{i > 0 && "; "}<b>{a.item.split("\\").pop()}</b> seen {count(a.seen)} time{a.seen === 1 ? "" : "s"}, rarest {count(a.rank)} of {count(a.of)}{a.new ? " (new)" : ""}</span>))}</p>
            )}
            <Notes notes={d.notes} />
            <ResultTable columns={columns(kind, d.item)} rows={rows} host={d.host} mark={(r) => ((r as Row).alert ? "alert" : (r as Row).new ? "new" : undefined)}
              empty={newOnly ? "Nothing was first seen at the end of this period." : undefined} />
            {d.truncated && <p className="hn-more">Showing the rarest {rows.length} of {count(d.shown_of)}.</p>}
          </Panel>
        </div>
      )}
    </div>
  );
}

export const lab: Lab = {
  id: "rarity",
  title: "First seen / rare here",
  blurb: "Stack counting: programs, parent → child pairs and network destinations ranked by how rarely this machine has seen them; new ones marked.",
  icon: ScanSearch,
  Component: RarityPage,
};
