// The case board (night-pivot, 2026-11-23). Back end: engine/labs/cases.py.
// Open a case, pin alerts / events / things / your own hypotheses (from here or from any lab), write notes,
// mark each hypothesis confirmed, ruled out or open, and read the pinned items on one timeline.
// The analyst's marks are the analyst's: they sit next to the grade the evidence gave, never replace it.
import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { BookMarked, FileDown, FileText, Pin, Plus, Printer, StickyNote, Trash2, X } from "lucide-react";
import type { Lab, LabProps } from "../registry";
import { NextStrip, useAlertParam } from "../kit";
import { PlusCase, Thing } from "../_things";
import { getJsonPatient, plainError } from "../_things/net";
import { rawQuery, utc } from "../pivot/links";
import type { Entity } from "../pivot/links";
import { activeCase, casesApi, isLeftover, pinFromParams, pinTo, setActiveCase, visibleCases, type CaseRow } from "./pin";
import "./cases.css";

type Status = "open" | "confirmed" | "ruled_out";
interface PinRow {
  id: string; type: "alert" | "event" | "entity" | "hypothesis"; ref: string; kind: string | null; label: string;
  time: string | null; host: string | null; added: string; snapshot: Record<string, unknown> | null;
}
interface Item { id: string; in_chain?: boolean; sentence?: string; what?: string; plain?: string; reason?: string; band_label?: string; alternative?: string | null; time?: string }
interface AlertReport { summary?: string; facts?: Item[]; hypotheses?: Item[]; gaps?: Item[]; error?: string }
interface CaseFull {
  id: string; title: string; summary: string; created: string; updated: string;
  pins: PinRow[]; notes: { id: string; text: string; time: string }[];
  marks: Record<string, { status: Status; note: string; time: string }>;
  alerts: Record<string, AlertReport | null>;
  timeline: { time: string; type: string; label: string; pin: string; kind: string | null; ref: string }[];
  status_words: Record<Status, string>;
}
interface AlertRow { id: string; title: string; level: string; time: string }
interface Inks { inks: Record<"fact" | "hypothesis" | "gap", { word: string; explain: string }> }

const TEXT = {
  cases: "Cases",
  newCase: "New case",
  newTitle: "New case name",
  newTitleHint: "Name a new case, e.g. downloaded tool on the test machine",
  create: "Create",
  none: "No case yet. Create one, then pin evidence to it from here or from any lab.",
  pick: "Pick a case on the left, or create one.",
  open: "open case",
  active: "Pins from other labs go to this case",
  makeActive: "Send pins here",
  summary: "What is this case about?",
  save: "Save",
  pinned: "Pinned evidence",
  pinAlert: "Pin an alert",
  pinAlertHint: "The alerts this dashboard shows, newest first.",
  pinBtn: "Pin",
  alreadyPinned: "pinned",
  alerts: "Alerts",
  events: "Events",
  things: "Things",
  hyps: "Your hypotheses",
  hypHint: "Write what you think happened; mark it when the evidence settles it.",
  hypPlaceholder: "e.g. the tool was copied in by the downloader",
  add: "Add",
  timeline: "Timeline of the pinned items",
  timelineHint: "Recorded times, oldest first. Your notes keep their own clock below.",
  noTimeline: "Nothing pinned has a recorded time yet.",
  notes: "Analyst notes",
  notePlaceholder: "Write a note…",
  noNotes: "No notes yet.",
  remove: "Remove",
  fromReport: "From the alert's report",
  reportMissing: "The report of this alert could not be built here",
  markLabel: "Your mark",
  exports: "Export",
  report: "Printable report",
  stix: "STIX 2.1 bundle",
  tsCsv: "Timesketch CSV",
  tsJsonl: "Timesketch JSONL",
  iocs: "IOCs only",
  sweep: "Sweep these IOCs",
  deleteCase: "Delete case",
  deleteAsk: "Move this case to recordings/cases/deleted/? (It is kept there, not erased.)",
  pinnedFrom: (label: string, title: string) => `Pinned “${label}” to “${title}”.`,
  offerTitle: "The alert you came from:",
  showDrafts: (n: number) => `Show ${n} draft${n === 1 ? "" : "s"} (untitled, not worked on)`,
  hideDrafts: "Hide drafts",
  offerPin: "Pin this alert to the open case",
  offerStart: "Start a case with this alert",
  offerNo: "Not now",
  busy: "Updating the case… (the first alert of a session can take a few seconds: its evidence graph is being built)",
  otherWay: "Other explanation:",
  moreFacts: (n: number) => `${n} more recorded links around it`,
  reportCounts: (f: number, h: number, g: number) => `${f} recorded links · ${h} hypotheses · ${g} gaps`,
};
const STATUS_ORDER: Status[] = ["open", "confirmed", "ruled_out"];

async function send<T>(url: string, method: string, body?: unknown): Promise<T> {
  const r = await fetch(url, { method, headers: body ? { "Content-Type": "application/json" } : undefined, body: body ? JSON.stringify(body) : undefined });
  if (!r.ok) throw new Error(String((await r.json().catch(() => null))?.detail ?? `${r.status} ${r.statusText}`));
  return (await r.json()) as T;
}

function Panel({ title, hint, children, className, actions }: { title: string; hint?: string; children: ReactNode; className?: string; actions?: ReactNode }) {
  return (
    <section className={`ua-panel cs-panel ${className ?? ""}`}>
      <header className="cs-panel-head"><h2>{title}</h2>{actions}</header>
      {hint && <p className="ua-hint">{hint}</p>}
      {children}
    </section>
  );
}

function Marker({ value, words, onChange }: { value: Status; words: Record<Status, string>; onChange: (s: Status) => void }) {
  return (
    <div className="cs-marker" role="radiogroup" aria-label={TEXT.markLabel}>
      {STATUS_ORDER.map((s) => (
        <button key={s} type="button" role="radio" aria-checked={value === s} data-status={s} data-on={value === s ? "1" : undefined}
          onClick={() => onChange(s)}>{words[s] ?? s}</button>
      ))}
    </div>
  );
}

function InkRow({ ink, label, children }: { ink: "fact" | "hypothesis" | "gap"; label: string; children: ReactNode }) {
  return (
    <li className="cs-ink" data-ink={ink}>
      <span className="cs-ink-tag" title={label}><span className={`ink-line ${ink === "fact" ? "solid" : ink === "hypothesis" ? "dashed" : "dotted"}`} />{label}</span>
      <div>{children}</div>
    </li>
  );
}

function AlertPin({ p, rep, c, inks, onMark, onRemove }: {
  p: PinRow; rep: AlertReport | null | undefined; c: CaseFull; inks: Inks["inks"] | null;
  onMark: (key: string, s: Status) => void; onRemove: () => void;
}) {
  const snap = (p.snapshot ?? {}) as { level?: string; reason?: string };
  const word = (k: "fact" | "hypothesis" | "gap") => inks?.[k]?.word ?? k;
  const facts = rep?.facts ?? [];
  const anyChain = facts.some((f) => f.in_chain);
  const chain = anyChain ? facts.filter((f) => f.in_chain) : facts.slice(0, 8);
  const rest = facts.filter((f) => !chain.includes(f));
  return (
    <li className="cs-alert">
      <div className="cs-row">
        <span className="ua-tag pv-level" data-level={snap.level}>{snap.level}</span>
        <b>{p.label}</b>
        <span className="ua-hint num">{utc(p.time)}</span>
        <a className="cs-link" href={`#a/story/${encodeURIComponent(p.ref)}`}>Story</a>
        <button className="cs-icon" type="button" onClick={onRemove} title={TEXT.remove}><X size={14} /></button>
      </div>
      {snap.reason && <p className="ua-hint">{snap.reason}</p>}
      {rep?.error ? <p className="ua-hint">{TEXT.reportMissing} ({rep.error}).</p> : rep && (
        <details className="cs-report" open>
          <summary>{TEXT.fromReport}: {TEXT.reportCounts(rep.facts?.length ?? 0, rep.hypotheses?.length ?? 0, rep.gaps?.length ?? 0)}</summary>
          <ul className="cs-inks">
            {rep.hypotheses?.map((h) => {
              const key = `h:${p.ref}:${h.id}`;
              const m = c.marks[key]?.status ?? "open";
              return (
                <InkRow key={h.id} ink="hypothesis" label={word("hypothesis")}>
                  <p>{h.sentence}{h.band_label ? <span className="ua-hint"> ({h.band_label})</span> : null}</p>
                  {h.alternative && <p className="ua-hint">{TEXT.otherWay} {h.alternative}</p>}
                  <Marker value={m} words={c.status_words} onChange={(s) => onMark(key, s)} />
                </InkRow>
              );
            })}
            {chain.map((f) => <InkRow key={f.id} ink="fact" label={word("fact")}><p>{f.sentence}</p></InkRow>)}
            {rep.gaps?.map((g) => <InkRow key={g.id} ink="gap" label={word("gap")}><p>{g.plain ?? g.what}</p></InkRow>)}
          </ul>
          {rest.length > 0 && (
            <details className="cs-more">
              <summary>{TEXT.moreFacts(rest.length)}</summary>
              <ul className="cs-inks">{rest.map((f) => <InkRow key={f.id} ink="fact" label={word("fact")}><p>{f.sentence}</p></InkRow>)}</ul>
            </details>
          )}
        </details>
      )}
    </li>
  );
}

function AlertPicker({ pinned, onPin }: { pinned: Set<string>; onPin: (a: AlertRow) => void }) {
  const [rows, setRows] = useState<AlertRow[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { getJsonPatient<AlertRow[]>("/api/alerts?limit=12").then(setRows).catch((e) => setErr(plainError(e))); }, []);
  return (
    <Panel title={TEXT.pinAlert} hint={TEXT.pinAlertHint}>
      {err ? <p className="lab-state" data-kind="error">{err}</p> : !rows ? <p className="ua-hint">…</p> : (
        <ul className="cs-list">{rows.map((a) => (
          <li key={a.id} className="cs-row">
            <span className="ua-tag pv-level" data-level={a.level}>{a.level}</span>
            <span className="cs-grow">{a.title}</span>
            <span className="ua-hint num">{utc(a.time)}</span>
            {pinned.has(a.id) ? <span className="ua-hint">{TEXT.alreadyPinned}</span>
              : <button className="ua-btn cs-small" type="button" onClick={() => onPin(a)}><Pin size={13} />{TEXT.pinBtn}</button>}
          </li>
        ))}</ul>
      )}
    </Panel>
  );
}

function CaseView({ id, active, onActive, onGone, onChanged, inks }: {
  id: string; active: boolean; onActive: () => void; onGone: () => void; onChanged: () => void; inks: Inks["inks"] | null;
}) {
  const [busy, setBusy] = useState(false);
  const [c, setC] = useState<CaseFull | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [summary, setSummary] = useState("");
  const [hyp, setHyp] = useState("");
  const [note, setNote] = useState("");
  const load = useCallback(() => {
    getJsonPatient<CaseFull>(`/api/labs/cases/${encodeURIComponent(id)}`)
      .then((x: CaseFull) => { setC(x); setSummary(x.summary); setErr(null); })
      .catch((e) => setErr(plainError(e)));
  }, [id]);
  useEffect(load, [load]);
  const act = (p: Promise<unknown>) => {
    setBusy(true);
    return p.then(load).then(onChanged).catch((e) => setErr(plainError(e))).finally(() => setBusy(false));
  };
  const base = `/api/labs/cases/${encodeURIComponent(id)}`;
  if (err && !c) return <p className="lab-state" data-kind="error" role="alert">{err}</p>;
  if (!c) return <p className="lab-state" data-kind="loading">…</p>;
  const by = (t: PinRow["type"]) => c.pins.filter((p) => p.type === t);
  const mark = (key: string, s: Status) => act(send(`${base}/marks`, "PUT", { key, status: s }));
  const unpin = (p: PinRow) => act(send(`${base}/pins/${p.id}`, "DELETE"));
  const addHyp = (e: FormEvent) => { e.preventDefault(); if (hyp.trim()) act(send(`${base}/pins`, "POST", { type: "hypothesis", ref: hyp.trim() }).then(() => setHyp(""))); };
  const addNote = (e: FormEvent) => { e.preventDefault(); if (note.trim()) act(send(`${base}/notes`, "POST", { text: note.trim() }).then(() => setNote(""))); };
  const pinnedAlerts = new Set(by("alert").map((p) => p.ref));
  return (
    <div className="cs-case">
      <section className="ua-panel cs-panel cs-head">
        <div className="cs-row">
          <BookMarked size={20} className="cs-accent" />
          <h2 className="cs-title">{c.title}</h2>
          {active ? <span className="ua-tag cs-active">{TEXT.active}</span>
            : <button className="ua-btn cs-small" type="button" onClick={onActive}>{TEXT.makeActive}</button>}
          <span className="cs-grow" />
          <button className="cs-icon" type="button" title={TEXT.deleteCase}
            onClick={() => { if (window.confirm(TEXT.deleteAsk)) send(base, "DELETE").then(onGone).catch((e) => setErr(plainError(e))); }}><Trash2 size={15} /></button>
        </div>
        <textarea className="cs-input cs-summary" value={summary} placeholder={TEXT.summary} rows={2}
          onChange={(e) => setSummary(e.target.value)} onBlur={() => summary !== c.summary && act(send(base, "PATCH", { summary }))} />
        <div className="cs-row cs-exports">
          <span className="ua-hint">{TEXT.exports}</span>
          <a className="ua-btn cs-small" href={`${base}/report`} target="_blank" rel="noreferrer"><Printer size={14} />{TEXT.report}</a>
          <a className="ua-btn cs-small" href={`${base}/stix`} download={`${c.id}.stix.json`}><FileDown size={14} />{TEXT.stix}</a>
          <a className="ua-btn cs-small" href={`${base}/timesketch.csv`} download={`${c.id}.timesketch.csv`}><FileText size={14} />{TEXT.tsCsv}</a>
          <a className="ua-btn cs-small" href={`${base}/timesketch.jsonl`} download={`${c.id}.timesketch.jsonl`}><FileText size={14} />{TEXT.tsJsonl}</a>
          <a className="ua-btn cs-small" href={`${base}/iocs.txt`} download={`${c.id}.iocs.txt`}><FileText size={14} />{TEXT.iocs}</a>
          <button className="ua-btn cs-small" type="button" onClick={() => {
            getJsonPatient<{ text: string }>(`${base}/iocs`).then((x) => {
              window.location.hash = `#/labs/sweep?${new URLSearchParams({ q: x.text })}`;
            }).catch((e) => setErr(plainError(e)));
          }}><FileDown size={14} />{TEXT.sweep}</button>
        </div>
        {err && <p className="lab-state" data-kind="error">{err}</p>}
        {busy && <p className="ua-hint cs-busy" role="status">{TEXT.busy}</p>}
      </section>

      <div className="cs-grid">
        <div className="cs-col">
          <Panel title={`${TEXT.pinned} (${c.pins.length})`}>
            {by("alert").length > 0 && <h3 className="cs-sub">{TEXT.alerts}</h3>}
            <ul className="cs-list">
              {by("alert").map((p) => <AlertPin key={p.id} p={p} rep={c.alerts[p.ref]} c={c} inks={inks} onMark={mark} onRemove={() => unpin(p)} />)}
            </ul>
            {by("event").length > 0 && <h3 className="cs-sub">{TEXT.events}</h3>}
            <ul className="cs-list">
              {by("event").map((p) => {
                const s = (p.snapshot ?? {}) as { summary?: string; entities?: Entity[] };
                return (
                  <li key={p.id} className="cs-item">
                    <div className="cs-row"><span className="ua-hint num">{utc(p.time)}</span><b className="cs-grow">{s.summary ?? p.label}</b>
                      <button className="cs-icon" type="button" onClick={() => unpin(p)} title={TEXT.remove}><X size={14} /></button></div>
                    <div className="pv-chips">{(s.entities ?? []).filter((e) => e.kind !== "process").map((e) => <Thing key={`${e.kind}|${e.value}`} kind={e.kind} value={e.value} role={e.role} />)}</div>
                  </li>
                );
              })}
            </ul>
            {by("entity").length > 0 && <h3 className="cs-sub">{TEXT.things}</h3>}
            <div className="pv-chips">
              {by("entity").map((p) => {
                const s = (p.snapshot ?? {}) as { events?: number };
                return (
                  <span key={p.id} className="cs-entity">
                    <Thing kind={p.kind ?? "file"} value={p.ref} count={s.events ?? null} />
                    <button className="cs-icon" type="button" onClick={() => unpin(p)} title={TEXT.remove}><X size={13} /></button>
                  </span>
                );
              })}
            </div>
          </Panel>

          <Panel title={TEXT.hyps} hint={TEXT.hypHint}>
            <ul className="cs-list">
              {by("hypothesis").map((p) => (
                <li key={p.id} className="cs-item cs-hyp">
                  <div className="cs-row"><span className="ink-line dashed cs-hypo-line" /><b className="cs-grow">{p.label}</b>
                    <button className="cs-icon" type="button" onClick={() => unpin(p)} title={TEXT.remove}><X size={14} /></button></div>
                  <Marker value={c.marks[`p:${p.id}`]?.status ?? "open"} words={c.status_words} onChange={(s) => mark(`p:${p.id}`, s)} />
                </li>
              ))}
            </ul>
            <form className="cs-row" onSubmit={addHyp}>
              <input className="cs-input cs-grow" value={hyp} onChange={(e) => setHyp(e.target.value)} placeholder={TEXT.hypPlaceholder} />
              <button className="ua-btn cs-small" type="submit"><Plus size={14} />{TEXT.add}</button>
            </form>
          </Panel>

          <AlertPicker pinned={pinnedAlerts} onPin={(a) => act(send(`${base}/pins`, "POST", { type: "alert", ref: a.id }))} />
        </div>

        <div className="cs-col">
          <Panel title={TEXT.timeline} hint={TEXT.timelineHint}>
            {c.timeline.length === 0 ? <p className="ua-hint">{TEXT.noTimeline}</p> : (
              <ol className="cs-timeline">
                {c.timeline.map((t) => (
                  <li key={t.pin} data-type={t.type}>
                    <span className="cs-dot" />
                    <span className="ua-hint num">{utc(t.time)}</span>
                    <span className="ua-tag">{t.type}</span>
                    {t.type === "entity" && t.kind ? <Thing kind={t.kind} value={t.ref} /> : <span className="cs-tl-label">{t.label}</span>}
                  </li>
                ))}
              </ol>
            )}
          </Panel>
          <Panel title={TEXT.notes}>
            {c.notes.length === 0 ? <p className="ua-hint">{TEXT.noNotes}</p> : (
              <ul className="cs-list">{c.notes.map((n) => (
                <li key={n.id} className="cs-note"><StickyNote size={14} className="cs-accent" />
                  <div className="cs-grow"><p>{n.text}</p><span className="ua-hint num">{utc(n.time)}</span></div>
                  <button className="cs-icon" type="button" onClick={() => act(send(`${base}/notes/${n.id}`, "DELETE"))} title={TEXT.remove}><X size={14} /></button>
                </li>
              ))}</ul>
            )}
            <form className="cs-row" onSubmit={addNote}>
              <textarea className="cs-input cs-grow" rows={2} value={note} onChange={(e) => setNote(e.target.value)} placeholder={TEXT.notePlaceholder} />
              <button className="ua-btn cs-small" type="submit"><Plus size={14} />{TEXT.add}</button>
            </form>
          </Panel>
        </div>
      </div>
    </div>
  );
}

interface AlertBrief { id: string; title: string; level: string; time: string }

/** The alert the address names (NextStrip's "Add to case" opens #/labs/cases?alert=<id>): offered for pinning,
 *  never pinned by just opening the page. */
function AlertOffer({ id, caseOpen, onPinned, onDismiss }: {
  id: string; caseOpen: boolean; onPinned: (c: { id: string; title: string }) => void; onDismiss: () => void;
}) {
  const [a, setA] = useState<AlertBrief | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setA(null); setErr(null);
    getJsonPatient<AlertBrief>(`/api/labs/cases/alert/${encodeURIComponent(id)}`)
      .then(setA).catch((e) => setErr(plainError(e)));
  }, [id]);
  if (err) return <p className="lab-state" data-kind="empty">{err}</p>;
  if (!a) return null;
  return (
    <section className="ua-panel cs-panel cs-offer" aria-label={TEXT.offerTitle}>
      <div className="cs-row">
        <span className="ua-hint">{TEXT.offerTitle}</span>
        <span className="ua-tag pv-level" data-level={a.level}>{a.level}</span>
        <b className="cs-grow">{a.title}</b>
        <span className="ua-hint num">{utc(a.time)}</span>
        {/* no case open: pinTo starts one, named after the run and this alert */}
        <PlusCase alert={a.id} label={a.title} time={a.time} text={caseOpen ? TEXT.offerPin : TEXT.offerStart} onPinned={onPinned} />
        <button className="cs-icon" type="button" onClick={onDismiss} title={TEXT.offerNo} aria-label={TEXT.offerNo}><X size={14} /></button>
      </div>
    </section>
  );
}

function CasesLab(_: LabProps) {
  const [alert, setAlert] = useAlertParam();
  // the query read from the address itself (one decoding only: a value may hold & + % =), as a string so an
  // effect runs once per address, not once per render of the shell
  const query = rawQuery(window.location.hash);
  const params = new URLSearchParams(query);
  const handled = useRef<string | null>(null);
  const [rows, setRows] = useState<CaseRow[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(params.get("case") ?? activeCase());
  const [active, setActive] = useState<string | null>(activeCase());
  const [title, setTitle] = useState("");
  const [toast, setToast] = useState<string | null>(null);
  const [ver, setVer] = useState(0);                     // bumped when a pin arrives from another lab
  const [showDrafts, setShowDrafts] = useState(false);
  const opened = useRef(false);                          // the analyst opened a case by hand on this page
  const [inks, setInks] = useState<Inks["inks"] | null>(null);
  const refresh = useCallback(() => casesApi.list().then((rs) => {
    setRows(rs);
    // a leftover draft is not opened by itself on arrival (critique-4); it stays in the list behind "Show drafts"
    const left = rs.find((r) => r.id === activeCase() && isLeftover(r));
    if (left) { setOpen((o) => (o === left.id && !opened.current ? null : o)); }
  }).catch((e) => setErr(plainError(e))), []);
  useEffect(() => { refresh(); fetch("/api/words").then((r) => r.json()).then((w: Inks) => setInks(w.inks)).catch(() => setInks(null)); }, [refresh]);
  useEffect(() => {
    if (handled.current === query) return;               // this address was already acted on
    handled.current = query;
    const q = new URLSearchParams(query);
    const p = pinFromParams(q);
    if (!p) { if (q.get("case")) setOpen(q.get("case")); return; }
    pinTo(p).then((c) => {
      setActive(activeCase()); setOpen(c.id); setVer((n) => n + 1); setToast(TEXT.pinnedFrom(p.label, c.title));
      const next = `?case=${encodeURIComponent(c.id)}`;
      handled.current = next.slice(1);                    // the new address needs no action of its own
      window.location.replace(`#/labs/cases${next}`);     // the pin address is gone (a reload or Back never pins again)
      refresh();
    }).catch((e) => setErr(plainError(e)));
  }, [query, refresh]);
  const create = (e: FormEvent) => {
    e.preventDefault();
    casesApi.create(title.trim()).then((c) => { setTitle(""); setOpen(c.id); setActiveCase(c.id); setActive(c.id); refresh(); }).catch((x) => setErr(plainError(x)));
  };
  const known = rows?.some((r) => r.id === open);
  const pinnedHere = (c: { id: string; title: string }) => {
    setActive(activeCase()); setOpen(c.id); setVer((n) => n + 1); refresh();
  };
  return (
    <div className="cs-wrap">
    <NextStrip current="cases" alert={alert} />
    {alert && <AlertOffer id={alert} caseOpen={!!active && !!rows?.some((r) => r.id === active && !isLeftover(r))} onPinned={pinnedHere}
      onDismiss={() => setAlert(null, "replace")} />}
    <div className="cs-page">
      <aside className="ua-panel cs-panel cs-cases">
        <header className="cs-panel-head"><h2>{TEXT.cases}</h2></header>
        <form className="cs-row" onSubmit={create}>
          <input className="cs-input cs-grow" value={title} onChange={(e) => setTitle(e.target.value)} placeholder={TEXT.newTitle} title={TEXT.newTitleHint} aria-label={TEXT.newTitleHint} />
          <button className="ua-btn cs-small" data-kind="primary" type="submit"><Plus size={14} />{TEXT.create}</button>
        </form>
        {err && <p className="lab-state" data-kind="error">{err}</p>}
        {rows && visibleCases(rows, showDrafts, open, active).length === 0 && <p className="ua-hint">{TEXT.none}</p>}
        <ul className="cs-list">
          {rows && visibleCases(rows, showDrafts, open, active).map((r) => (
            <li key={r.id}>
              <button type="button" className="cs-case-row" data-open={r.id === open ? "1" : undefined} onClick={() => { opened.current = true; setOpen(r.id); }} aria-label={`${TEXT.open} ${r.title}`}>
                <b>{r.title}</b>
                <span className="ua-hint num">{r.pins} pin{r.pins === 1 ? "" : "s"} · {r.notes} note{r.notes === 1 ? "" : "s"} · {utc(r.updated)}</span>
                {r.id === active && <Pin size={13} className="cs-accent" />}
              </button>
            </li>
          ))}
        </ul>
        {rows && rows.some((r) => r.draft) && (
          <button type="button" className="cs-link cs-drafts" onClick={() => setShowDrafts((x) => !x)}>
            {showDrafts ? TEXT.hideDrafts : TEXT.showDrafts(rows.filter((r) => r.draft).length)}
          </button>
        )}
      </aside>
      <div className="cs-main">
        {toast && <p className="cs-toast" role="status">{toast}</p>}
        {open && known ? (
          <CaseView key={`${open}:${ver}`} id={open} active={open === active} inks={inks}
            onActive={() => { setActiveCase(open); setActive(open); }} onChanged={refresh}
            onGone={() => { if (active === open) { setActiveCase(null); setActive(null); } setOpen(null); refresh(); }} />
        ) : <p className="lab-state" data-kind="empty">{TEXT.pick}</p>}
      </div>
    </div>
    </div>
  );
}

export const lab: Lab = {
  id: "cases",
  title: "Case board",
  blurb: "Collect alerts, events and things into a case, write notes, mark each hypothesis, and export a report.",
  icon: BookMarked,
  Component: CasesLab,
};
