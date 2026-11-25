"""Investigation report (package H, DESIGN 4.8): one HTML page per alert, built from the evidence
graph with Jinja2. No AI writes it: every sentence comes from a template and the graph, and every
fact and hypothesis cites the stored events it rests on.

    python -m engine.report --db <event store> --alerts <alert db> --alert <alert id> --out report.html

Sections: 1 summary, 2 the alert and why it fired, 3 timeline, 4 established facts (each citing
its events), 5 hypotheses (band, chance, reason, alternative explanation), 6 gaps, 7 limitations,
8 recommended next steps.

check_citations() is the report's own test (VERIFICATION_PLAN stage 12): every cited event must
exist in the store, every fact must cite at least one event, every hypothesis must carry a band,
a reason and an alternative explanation.

Reports quote program names, paths and addresses from the recording: a report about the laptop
is private (save it under recordings/, which is never committed); scenario reports from the VM
are fine to share.
"""

import argparse
import hashlib
import html
import os
import sqlite3
from collections import Counter
from datetime import datetime, timezone

import jinja2
import networkx as nx

from . import config
from . import confidence
from . import hubs as hubs_mod
from .alerts import AlertStore, declared_note
from .graph import Layer2, _resolve_seed, build_graph, parse_time, subgraph_around

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
DEFAULT_POOL = config.default_pool()


def layer2_from(pool):
    """Layer 2 (hypotheses) from the pool of normal rates; refused when the pool is missing, so a
    report never silently shows facts only."""
    if not pool or not os.path.exists(pool):
        raise SystemExit(f"no pool of normal rates at {pool} (python -m engine.confidence --build-pool "
                         f"--db <dev snapshot> --out {pool})")
    return Layer2.from_pool_file(pool)

# plain sentences for each kind of line (layer 0/1 facts and layer 2 hypotheses); unknown kinds
# fall back to "A —kind→ B", so a new kind never breaks a report
SENTENCES = {
    "started": "{u} started {v}",
    "connected_to": "{u} connected to {v}",
    "accepted_from": "{u} accepted a connection from {v}",
    "created": "{u} created {v}",
    "deleted": "{u} deleted {v}",
    "looked_up": "{u} looked up the name {v}",
    "ran_as": "{v} ran from the file {u}",
    "listen_started": "{u} started listening on {v}",
    "listen_stopped": "{u} stopped listening on {v}",
    "set_autostart": "{u} set the autostart entry {v}",
    "will_start": "the autostart entry {u} names {v} to start at logon",
    "download_marker": "{u} marked {v} as downloaded",
    "same_content": "{u} and {v} have the same content",
    # layer 2 (package F). report-next (debate 10, M1): "may have", never "probably": the number
    # behind a hypothesis is how rare a coincidence would be, not the chance it is true, and the
    # band's plain gloss (BAND_GLOSS) carries the strength
    "content_from": "the content of {v} may have come from {u}",
    "remote_command": "a connection from {u} may have made its receiver start {v}",
    "fetched_then_ran": "after contacting {u}, its program may have started {v}",
    "same_path_unknown_content": "{v} may have run from the file {u} (same path, content not proven)",
    "copy_of": "{v} may be a copy of {u}",
    "name_for_connection": "the connection to {v} may have been made for the name {u}",
    "started_with_file_argument": "{v} was started with the file {u} named on its command line",
}

# report-next (debate 10 plan v2): the plain words next to each band name
BAND_ORDER = {"high": 0, "medium": 1, "low": 2}
BAND_GLOSS = {"high": "strong link", "medium": "possible link", "low": "weak lead"}
TIMING_ROWS = ("T1", "T2", "T3")
# readable names of the recorded event types a citation can point at (M3); unknown ids fall back
# to "event N"
EVENT_NAMES = {1: "process start", 3: "network connection", 4: "Sysmon state change", 5: "process end",
               11: "file created", 13: "registry value set", 15: "file marked as downloaded",
               22: "name lookup", 26: "file deleted"}
AGENT_EVENT_NAMES = {"FILE_HASH": "file fingerprint", "PORT_LISTEN_START": "port opened",
                     "PORT_LISTEN_STOP": "port closed"}
# what an alert raised on a declared row (v4 F7/F8) fired on: the summary sentence and the banner
DECLARED_SENTENCES = {
    "script": "It fired on PowerShell code declared on powershell.exe's command line (not recorded: it may not have run).",
    "registry": "It fired on a registry change declared on reg.exe's command line (not recorded: it may have failed).",
}

LIMITATIONS = [
    "Only what Sysmon and our recorder saw is here: file events are recorded for programs, "
    "scripts and a few folders only, registry changes for autostart places only, and Sysmon does "
    "not record memory or the content of network traffic.",
    "A suspected link's number is the chance of a COINCIDENCE (an unrelated event landing in the "
    "same time window by luck), not the probability that the link is true.",
    "Grades come from rates measured on normal use; real activity is bursty, so some links are "
    "graded more confidently than they deserve (measured: see the confidence report).",
]
# shown for check-in rhythm alerts (source "beacon"; DESIGN 4.6 says the report states it)
BEACON_LIMITATION = ("The check-in rhythm rule sees one event per new connection: a program that keeps "
                     "one long-lived connection open and talks over it produces one event, so its rhythm "
                     "is invisible to this rule.")
# v4 F7: an alert raised on a registry change read from reg.exe's command line (engine/regcmd.py)
DECLARED_LIMITATION = ("This alert is about a registry change that was NOT recorded: it was read from the command "
                       "line of reg.exe, whose start is the recorded fact. The change may have failed (no rights, "
                       "wrong key); check the registry value itself before concluding it was made.")
# v4 F8: an alert raised on PowerShell code read from powershell.exe's command line (engine/pscmd.py)
DECLARED_SCRIPT_LIMITATION = ("This alert is about PowerShell code that was NOT recorded: it was read from the command "
                              "line of powershell.exe, whose start is the recorded fact. The code may not have run "
                              "(a syntax error, a block, an early exit), and code it built while running is not seen.")


def _declared_kind(alert):
    """None, "registry" or "script" for an alert raised on a declared row (v4 F7/F8)."""
    d = alert.details or {}
    if d.get("derived_from") != "command_line":
        return None
    return "script" if (d.get("declared") or {}).get("event_id") == 4104 else "registry"


def bounds_limitation(bounds) -> str:
    """The view-bounds sentence, from the frozen numbers (config.graph_view)."""
    minutes = bounds.window.total_seconds() / 60
    return (f"The view is bounded: {minutes:g} minutes around the alert, at most {bounds.max_depth} steps "
            f"and {bounds.max_nodes} nodes.")


def truncated_limitation(bounds) -> str:
    return f"This view hit the {bounds.max_nodes}-node limit: some related activity is not shown."


def label(G, node):
    """A short, readable name for a node."""
    d = G.nodes[node] if node in G else {}
    kind = d.get("kind") or node.split(":", 1)[0]
    if kind == "process":
        pid = f" (PID {d['pid']})" if d.get("pid") is not None else ""
        return f"{d.get('label') or 'an unknown program'}{pid}"
    if kind == "file":
        return d.get("label") or node.rsplit("\\", 1)[-1]
    if kind == "autostart":                  # the registry value's name, not its whole key path
        return d.get("label") or node.rsplit("\\", 1)[-1]
    parts = node.split(":", 2)
    return parts[2] if len(parts) == 3 else node


def sentence(G, u, v, kind):
    tmpl = SENTENCES.get(kind)
    if tmpl is None:
        return f"{label(G, u)} —{kind}→ {label(G, v)}"
    return tmpl.format(u=label(G, u), v=label(G, v))


def event_name(event) -> str:
    """'process start (Sysmon 1)', 'file fingerprint (recorder)' or 'event N' for an unknown id."""
    if event in AGENT_EVENT_NAMES:
        return f"{AGENT_EVENT_NAMES[event]} (recorder)"
    if event in EVENT_NAMES:
        return f"{EVENT_NAMES[event]} (Sysmon {event})"
    return f"event {event if event is not None else '?'}"


def _cite(evidence):
    """[{key, event, record, time, text}] for display and checking; `text` is the readable form
    ('process start (Sysmon 1), record 123'), the key stays the proof."""
    out = []
    for e in evidence or []:
        if e and e.get("key"):
            record = e.get("record_id") or e.get("seq")
            out.append({"key": e["key"], "event": e.get("event"), "record": record, "time": e.get("time"),
                        "text": f"{event_name(e.get('event'))}, record {record if record is not None else '?'}"})
    return out


def per_thousand(p, cfg) -> str:
    """A coincidence chance as a natural frequency (Gigerenzer & Hoffrage 1995): 'K in 1,000' with
    K = round(1000 p); 'fewer than 1 in 1,000' when K = 0. When rounding would cross a band edge
    (K reaching 10 or 100 while p is still below 0.01 or 0.10), decimals are added ('99.6 in 1,000'),
    so the words never contradict the band."""
    x = 1000 * p
    k = round(x)
    if k == 0:
        return "fewer than 1 in 1,000"
    if k >= 1000 and p < 1:
        return "more than 999 in 1,000"
    text = f"{k:,}"
    for edge in (cfg.band_high, cfg.band_medium):
        if p < edge and k >= 1000 * edge:
            d = 1
            while float(f"{x:.{d}f}") >= 1000 * edge and d < 9:
                d += 1
            text = f"{x:.{d}f}"
    return f"{text} in 1,000"


def _plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


def _seconds_apart(d):
    """Effect time minus cause time, in seconds, from the stored cause/effect evidence (never from
    the reason text); None when either is missing. Can be negative (Sysmon may stamp the effect up
    to 2 s before its cause)."""
    tc, te = parse_time((d.get("cause") or {}).get("time")), parse_time((d.get("effect") or {}).get("time"))
    return (te - tc).total_seconds() if tc is not None and te is not None else None


MEASURED_FROM = {"within-life": "this program's own activity while it ran",
                 # the pool is keyed by the program's file name only (confidence.Pool.rate)
                 "pool:program": "how often programs with the same file name did this on the lab laptop's normal "
                                 "days (borrowed)"}
# what raised a T1 band when the timing did not (graph.py F1: the download marker, alone or with a
# looked-up name), in plain words
BASIS_WORDS = {"download marker": "the program's own download mark (Windows' mark-of-the-web) naming this address "
                                  "and port",
               "download marker + lookup": "the program's own download mark (Windows' mark-of-the-web) naming a "
                                           "host name the program looked up for this address, and this port"}


def basis_words(basis) -> str:
    return BASIS_WORDS.get(basis) or f"the {basis}"


def measured_from(source):
    """The plain 'measured from' line for a timing grade's rate source (confidence.timing_grade)."""
    if source in MEASURED_FROM:
        return MEASURED_FROM[source]
    if source and source.startswith("pool:lifetime"):
        return "how often programs that run about as long did this on the lab laptop's normal days (borrowed)"
    if source and source.startswith("pool:"):
        return "the lab laptop's normal days (borrowed)"
    return None


def _timing_lines(d, u, v, G, H, cfg, chance_text, assessable, lead_only):
    """The plain block of a timing hypothesis (T1-T3: u = the endpoint, v = the effect), built only
    from stored fields."""
    row = d.get("row")
    who = lambda n: label(H if n in H else G, n)  # noqa: E731
    via, ep, eff = who(d.get("via")), who(u), who(v)
    lines = []
    dt = _seconds_apart(d)
    if dt is None:
        when = "close in time to when"
    elif round(abs(dt), 1) == 0:            # report v3: a 9 ms gap reads "within 0.1 s", never "0.0 s"
        when = f"within 0.1 s {'after' if dt >= 0 else 'before'}"
    else:
        when = f"{abs(dt):.1f} s {'after' if dt >= 0 else 'before'}"
    if row == "T1":
        lines.append(("Why we think so", f"{via} created {eff} {when} it connected to {ep}."))
    elif row == "T2":
        lines.append(("Why we think so", f"{via} started {eff} {when} it accepted a connection from {ep}."))
    else:
        lines.append(("Why we think so", f"{via} started {eff} {when} it connected to {ep}."))
    window = f"{cfg.window:g}"
    if not assessable:
        life = d.get("life_seconds")
        active = f"{life:.1f} s" if life is not None else "too briefly"
        lines.append(("How often by coincidence",
                      f"Timing can't grade this: the program was active {active}, shorter than the {window} s "
                      "window, so everything it did is 'close'."))
    elif chance_text is not None:
        n = d.get("n_causes") or 0
        times = chance_text if chance_text.startswith(("fewer", "more")) else f"about {chance_text}"
        span = f"{cfg.competing_span_seconds / 60:g} minutes"     # N counts causes within +-span of the linked one
        edges = f"{cfg.window_before_seconds:g} s before to {cfg.window_after_seconds:g} s after"
        where = (f"in the {window} s window around it ({edges})" if n == 1
                 else f"in the {window} s window ({edges}) around at least one of them")
        noun = "incoming connection" if row == "T2" else "connection"
        causes = (f"this {noun} (the program's only one in the {span} either side)" if n == 1
                  else f"this program's {_plural(n, noun)} in the {span} either side of this one")
        if row == "T1":
            what = (f"If {causes} had nothing to do with its files, a new file would still land {where} by chance")
        else:
            what = (f"If {causes} had nothing to do with the programs it starts, a program start would still land "
                    f"{where} by chance")
        if d.get("basis") not in (None, "formula"):
            head = "Timing alone (not what set the grade)"
        elif lead_only:
            head = "How often by coincidence (the formula's figure, too low on real use)"
        else:
            head = "How often by coincidence"
        # the x2.5 burst factor makes T1's figure cautious; for the leads-only rows real use gives
        # more even so (config/frozen.yaml leads_only), and a provisional graph has no factor at all
        if lead_only:
            caveat = " (the formula's figure; real use gives more)"
        elif d.get("provisional"):
            caveat = ""
        else:
            caveat = " (a deliberately cautious estimate)"
        lines.append((head, f"{what} {times} times{caveat}."))
    if d.get("basis") not in (None, "formula"):
        lines.append(("What set the grade", f"{basis_words(d['basis'])}, not the timing (see the facts). It is the "
                                            "program's own statement, not proof of the source."))
    if assessable and measured_from(d.get("lam_source")):
        lines.append(("Measured from", measured_from(d.get("lam_source")) + "."))
    if lead_only:
        formula = "the formula" if d.get("provisional") else "even this cautious formula"
        few = " (for incoming connections: too few data to say how much)" if row == "T2" else ""
        lines.append(("Only a lead", f"measured on the lab laptop, chance coincidences of program starts were more "
                                     f"common than {formula} allows{few}, so this link is never graded above 'low'."))
    return lines


def _chance_short(d, row, band_label, cfg, chance_text, lead_only):
    """Report v3 (debate 11, two-tier coincidence text): the SHORT line read first; the full line
    stays in `plain`. Its only figure is per_thousand's (chance_text). None when the formula did
    not set the grade (a download mark did) or timing can't assess the link: then no short line,
    and no number. The lean ("leans toward calling it coincidence") is said ONLY on T1 rows graded
    by the formula with the frozen burst factor (j2-a16: both T1 bands measured over-cautious);
    leads-only rows keep debate 10's "real use gives more"; a provisional graph says neither."""
    if chance_text is None or d.get("basis") not in (None, "formula") or not band_label:
        return None
    n = d.get("n_causes") or 1
    times = chance_text if chance_text.startswith(("fewer", "more")) else f"about {chance_text}"
    noun = "incoming connection" if row == "T2" else "connection"
    # review fix 7: for N > 1 the full line's own words ("at least one of", "in the 15 minutes either side")
    span = f"{cfg.competing_span_seconds / 60:g} minutes"
    where = (f"in this {cfg.window:g} s window" if n == 1 else
             f"in the {cfg.window:g} s window around at least one of its {n} {noun}s in the {span} either side")
    what = "A new file" if row == "T1" else "A program start"
    s = f"Timing alone: {band_label}. {what} lands {where} by chance {times} times, even when nothing is linked."
    if lead_only:
        s += " That is the formula's figure; real use gives more."
    elif row == "T1" and not d.get("provisional") and d.get("p1") is not None and d["p1"] >= cfg.band_high:
        # j2-a16 measured T1 only where p1 is in the medium or low band (none in high): no lean elsewhere
        s += " This estimate leans toward calling it coincidence."
    return s


def _hypothesis(item, d, u, v, G, H, cfg):
    """Adds the plain-words fields of one hypothesis (report-next M1/M2): stored fields only, never
    `lam` (it can be infinite, and the dashboard's model must stay JSON-safe)."""
    row = d.get("row")
    timing = row in TIMING_ROWS
    assessable = d.get("assessable")
    p = d.get("p")
    lead_only = bool(timing and cfg is not None and row in cfg.leads_only)
    chance_text = per_thousand(p, cfg) if (timing and assessable and p is not None and cfg is not None) else None
    item.update({"row": row, "lam_source": d.get("lam_source"), "assessable": assessable,
                 "timing_band": d.get("timing_band"), "life_seconds": d.get("life_seconds"), "p1": d.get("p1"),
                 "tied": d.get("tied"), "cause_time": (d.get("cause") or {}).get("time"),
                 "effect_time": (d.get("effect") or {}).get("time"),
                 "seconds_apart": _seconds_apart(d) if timing else None,
                 "band_label": BAND_GLOSS.get(item.get("band"), ""), "chance_text": chance_text,
                 "lead_only": lead_only})
    item["chance_short"] = (_chance_short(d, row, item["band_label"], cfg, chance_text, lead_only)
                            if timing and cfg is not None else None)
    if timing and cfg is not None:
        lines = _timing_lines(d, u, v, G, H, cfg, chance_text, assessable, lead_only)
    else:
        lines = [("Why we think so", d.get("reason") or "")]
    lines.append(("Other explanation", d.get("alternative") or ""))
    item["plain"] = [{"label": a, "text": b} for a, b in lines]
    details = [("Recorded reason (exact)", d.get("reason"))]
    if p is not None:
        details.append(("p, chance of a coincidence over all competing causes", f"{p:.6g}"))
    if d.get("p1") is not None:
        details.append(("p1, one cause's chance", f"{d['p1']:.6g}"))
    for name, key in (("rate source", "lam_source"), ("competing causes", "n_causes"), ("graded by", "basis"),
                      ("timing band", "timing_band"), ("provisional", "provisional_reason")):
        if d.get(key) is not None:
            details.append((name, str(d[key])))
    item["details"] = [{"label": a, "text": b} for a, b in details if b is not None]
    return item


def rank_key(h):
    """The one order of hypotheses (section 5, the summary's "highest-graded"): band, then the
    coincidence chance (only where the formula set the grade: a band set by a download marker, a
    link timing can't assess, or a leads-only row whose p is known to be too low, never ranks by p),
    then time, then the sentence."""
    p = (h.get("p") if (h.get("basis") == "formula" and h.get("assessable") is not False and not h.get("lead_only"))
         else None)
    return (BAND_ORDER.get(h.get("band"), 3), p is None, p if p is not None else 0.0, h.get("time") or "",
            h.get("sentence") or "")


def _time(t):
    return t.isoformat(timespec="seconds").replace("+00:00", "Z") if t else "?"


# -- report v3 (debate 11 tier 1): presentation fields shared by the report and the dashboard ------
def _precise(t):
    """The stored time at full precision (never cut to the second), None when missing."""
    return t.isoformat(timespec="microseconds").replace("+00:00", "Z") if t else None


def edge_id(u, v, k) -> str:
    """One id per graph edge, the same in build() and the dashboard's /api/alerts/{id}: derived from
    the edge itself (both ends + the multigraph key), never from its position in a list."""
    return "e" + hashlib.sha1(f"{u}\x1f{v}\x1f{k}".encode("utf-8")).hexdigest()[:12]


def gap_id(g) -> str:
    first = ((g.get("evidence") or [{}])[0] or {}).get("key") or ""
    return "g" + hashlib.sha1(f"{g['kind']}\x1f{g['node']}\x1f{first}".encode("utf-8")).hexdigest()[:12]


def short_namer(H):
    """label() without the PID when the program's name is unique among the programs in THIS view
    (debate 11: the uniqueness test runs on the view the screen shows, not the whole graph)."""
    names = Counter((d.get("label") or "").lower() for _, d in (H.nodes(data=True) if H is not None else [])
                    if d.get("kind") == "process" and d.get("label"))

    def short(n):
        d = H.nodes[n] if (H is not None and n in H) else {}
        if d.get("kind") == "process" and d.get("label") and names[d["label"].lower()] == 1:
            return d["label"]
        return label(H, n) if H is not None else n
    return short


# the short form of a sentence: SENTENCES with short names; one kind is also re-worded so that no
# step says "downloaded" (debate 11: a step never claims the download; the mark is the program's word)
SHORT_SENTENCES = {**SENTENCES,
                   "download_marker": "{u} put Windows' mark-of-the-web on {v} (the program's own statement of where "
                                      "it came from)"}


def short_sentence(short, u, v, kind):
    tmpl = SHORT_SENTENCES.get(kind)
    if tmpl is None:
        return f"{short(u)} —{kind}→ {short(v)}"
    return tmpl.format(u=short(u), v=short(v))


# icons: Python picks a NAME from this closed set, the front end only maps names to pictures. No
# download or danger names at all. "created" gets the neutral "item-created" unless the created
# fact carries the file's own fingerprint record (a FILE_HASH "ok"): then it is proven a file
EDGE_ICONS = {"started": "program-start", "connected_to": "connection-out", "accepted_from": "connection-in",
              "created": "item-created", "deleted": "item-deleted", "looked_up": "name-lookup",
              "ran_as": "program-file", "listen_started": "port-open", "listen_stopped": "port-closed",
              "set_autostart": "autostart", "will_start": "autostart", "download_marker": "mark",
              "same_content": "same-content"}
NODE_ICONS = {"process": "program", "file": "item", "endpoint": "address", "dns": "name", "port": "port",
              "autostart": "autostart"}
ICON_NAMES = frozenset(EDGE_ICONS.values()) | frozenset(NODE_ICONS.values()) | {
    "file-created", "file", "suspected", "unknown", "other"}


def edge_icon(H, v, d) -> str:
    if d.get("grade") == "hypothesis":
        return "suspected"
    if d.get("kind") == "created" and (d.get("fingerprint") or {}).get("key") and v in H and H.nodes[v].get("sha256"):
        return "file-created"
    return EDGE_ICONS.get(d.get("kind"), "other")


def node_icon(H, n) -> str:
    d = H.nodes[n]
    if d.get("kind") == "file" and d.get("sha256"):
        return "file"
    return NODE_ICONS.get(d.get("kind") or n.split(":", 1)[0], "other")


# gaps about what happened BEFORE the story: shown as "Before this:" rows at the top; every other
# gap kind stays at its node (a content_unknown gap belongs at its file)
BEFORE_GAPS = ("parent_unknown", "origin_unknown")
GAP_PLAIN = {
    "origin_unknown": "how {n} was started: its start was not recorded (it was already running, or it started "
                      "outside the recording)",
    "parent_unknown": "which program started {n}: its parent was not recorded (the parent started before recording "
                      "began)",
    "content_unknown": "what {n} contained: {reason}",
    "actor_unknown": "which program acted on {n}: {reason}",
    "owner_unknown": "which program opened {n}: {reason}",
}


def gap_plain(g, name) -> str:
    tmpl = GAP_PLAIN.get(g["kind"], "{what}: {n}: {reason}")
    return tmpl.format(n=name, reason=g.get("reason") or "", what=g["kind"].replace("_", " "))


def offset_text(dt):
    """'+1.2 s', '0.5 s before', 'within 0.1 s' (never '0.0 s'); None without a time."""
    if dt is None:
        return None
    if round(abs(dt), 1) == 0:
        return "within 0.1 s"
    return f"+{dt:.1f} s" if dt > 0 else f"{-dt:.1f} s before"


def _actor_of(H, u, v, d):
    """The program a row is about: a layer-2 link's `via`; the file-to-program matches (ran_as,
    same_content) are about the program; otherwise the acting process (u), else v if a process."""
    if d.get("layer") == 2 and d.get("via"):
        return d["via"]
    if d.get("kind") in ("ran_as", "same_content") and (H.nodes[v].get("kind") == "process"):
        return v
    if H.nodes[u].get("kind") == "process":
        return u
    if H.nodes[v].get("kind") == "process":
        return v
    return None


INK_RANK = {"fact": 1, "hypothesis": 2, "gap": 3}
_NO_TIME = datetime.min.replace(tzinfo=timezone.utc)


def causal_order(rows):
    """Rows in time order at FULL precision, with the causal rule (debate 11 round 3): a program's
    own rows never list above the fact that started it (Sysmon can stamp an effect up to 2 s before
    its cause), and a gap at a file or address never lists above the first fact about that node.
    Known solution: a DAG (the "started" row of P -> every row about P) sorted with
    networkx.lexicographical_topological_sort, keyed by the stored time; ties: "started" first,
    then facts, hypotheses, gaps, then the sentence. Never by record ids. Displayed times are the
    stored ones: only the position moves. rows: dicts with _t, _actor, _starts, _node, _ink, _text."""
    def key(i):
        r = rows[i]
        return (r["_t"] is None, r["_t"] or _NO_TIME, 0 if r["_starts"] else INK_RANK[r["_ink"]], r["_text"])
    D = nx.DiGraph()
    D.add_nodes_from(range(len(rows)))
    started_by = {}
    for i, r in enumerate(rows):
        if r["_starts"] is not None:
            started_by.setdefault(r["_starts"], i)
    first_fact_about = {}
    for i in sorted(range(len(rows)), key=key):
        r = rows[i]
        if r["_ink"] == "fact" and r["_v"] is not None:
            first_fact_about.setdefault(r["_v"], i)
    for i, r in enumerate(rows):
        for j in (started_by.get(r["_actor"]), started_by.get(r["_node"]) if r["_ink"] == "gap" else None,
                  first_fact_about.get(r["_node"]) if r["_ink"] == "gap" else None):
            if j is not None and j != i:
                D.add_edge(j, i)
    try:
        idx = list(nx.lexicographical_topological_sort(D, key=key))
    except nx.NetworkXUnfeasible:                     # a cycle cannot come from real data; fall back to time
        idx = sorted(range(len(rows)), key=key)
    return [rows[i] for i in idx]


MAX_STEPS = 10          # numbered steps on the verdict card; the rest are counted ("steps_more")


def _timeline_row(r):
    """One timeline row (section 3) from an ordered fact, hypothesis or at-node gap."""
    x, ink = r["item"], r["_ink"]
    if ink == "fact":
        text, short, grade = x["sentence"], x["short"], "fact"
    elif ink == "hypothesis":
        text, short, grade = x["sentence"], x["short"], f"hypothesis ({x['band']})"
    else:
        text, short, grade = f"unknown: {x['what']} ({x['where']})", f"unknown: {x['plain']}", "gap"
    return {"time": x["time"], "text": text, "short": short, "grade": grade, "ink": ink, "placement": "at",
            "id": x["id"], "order": x["order"], "time_precise": x["time_precise"], "t_offset_s": x["t_offset_s"],
            "offset_text": x["offset_text"], "icon": x["icon"], "in_chain": x["in_chain"]}


def _layout(H, short, edge_rows, before, ordered):
    """A lane and a full-precision order per node and edge, for a left-to-right time layout: one lane
    per program, in the order programs first appear in the causal order; a file, address or name
    sits in the lane of the program that first acted on it. Node order/offset = its first row's."""
    lanes, lane_of, node_first, node_offset = [], {}, {}, {}

    def new_lane(owner):
        lanes.append({"lane": len(lanes), "node_id": owner, "short": short(owner) if owner else None})
        return len(lanes) - 1

    def place(n, actor=None, other=None):
        if n is None or n in lane_of:
            return
        if H.nodes[n].get("kind") == "process":
            lane_of[n] = new_lane(n)
        elif actor in lane_of:
            lane_of[n] = lane_of[actor]
        elif other in lane_of:
            lane_of[n] = lane_of[other]
        else:
            lane_of[n] = new_lane(None)

    seq = [(g["order"], g["node_id"], None, None, None) for g in before]
    for r in ordered:
        x = r["item"]
        if r["_ink"] == "gap":
            seq.append((x["order"], x["node_id"], None, None, x["t_offset_s"]))
        else:
            seq.append((x["order"], x["u"], x["v"], r["_actor"], x["t_offset_s"]))
    for order, u, v, actor, dt in seq:
        place(actor)
        for n, other in ((u, v), (v, u)):
            if n is None:
                continue
            place(n, actor, other)
            node_first.setdefault(n, order)
            if dt is not None:
                node_offset.setdefault(n, dt)
    for n in H.nodes:
        place(n)
    nodes = [{"id": n, "short": short(n), "label": label(H, n), "kind": d.get("kind") or "?", "icon": node_icon(H, n),
              "lane": lane_of[n], "order": node_first.get(n), "t_offset_s": node_offset.get(n),
              "time_precise": _precise(d.get("start")) if d.get("kind") == "process" else None}
             for n, d in H.nodes(data=True)]
    edges = [{"id": x["id"], "u": x["u"], "v": x["v"], "kind": x["kind"], "grade": d.get("grade"), "band": d.get("band"),
              "lane": lane_of[actor if actor in lane_of else x["u"]], "order": x.get("order"),
              "time_precise": x["time_precise"], "t_offset_s": x.get("t_offset_s"), "icon": x["icon"],
              "short": x["short"], "in_chain": x.get("in_chain", False)} for x, d, actor in edge_rows]
    return {"lanes": lanes, "nodes": nodes, "edges": edges}


def _fact_order_key(f):
    """The Proven line's order: the full-precision causal order when build() set it (report v3),
    else (time, sentence) as in debate 10."""
    return (f["order"], "") if "order" in f else (f["time"], f["sentence"])


def view(G, seed, hubs=None, at=None, bounds=None):
    """The bounded view around a seed (DESIGN 4.7 steps 1-4), the same for the report, the
    dashboard and the graph checker: the bounds are ALWAYS the frozen ones (config.graph_view;
    `bounds` only lets a test pass another config's), and hubs (engine/hubs.py, the frozen list)
    are kept but not walked through."""
    bounds = bounds or config.graph_view()
    H = subgraph_around(G, seed, at=at, window=bounds.window, max_depth=bounds.max_depth, max_nodes=bounds.max_nodes,
                        expand=hubs_mod.expander(hubs) if hubs else None)
    return hubs_mod.mark(H, hubs) if hubs else H


def alert_seed(alert, G):
    """(seed, at) for an alert's view: the evidence event NEAREST to the alert's own time (a
    beacon's evidence can span more than the window; a correlation's keys are sorted, so "the
    first one" means nothing), and at = the alert time, so the view is centred on the alert.
    (None, None) when no evidence event is in the graph; at = None when the alert time is
    unreadable (the view is then centred on the seed)."""
    at = parse_time(alert.time)
    best = None
    for i, key in enumerate(alert.evidence):
        try:
            _, t = _resolve_seed(G, key)
        except KeyError:
            continue
        far = abs((t - at).total_seconds()) if (t is not None and at is not None) else float("inf")
        if best is None or far < best[0]:
            best = (far, i, key)
    return (best[2], at) if best else (None, None)


def alert_view(alert, G, hubs=None, bounds=None):
    """(seed, at, H) of an alert: the one view the report and the dashboard both show."""
    seed, at = alert_seed(alert, G)
    return seed, at, (view(G, seed, hubs, at=at, bounds=bounds) if seed else None)


def same_store(a, b) -> bool:
    """Do two paths name the same event store file?"""
    if os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b)):
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def build(alert, G, events_db=None, hubs=None, bounds=None, recorded_events_db=None):
    """The report's content (a plain dict, also what the dashboard shows). G = the full graph;
    hubs = the frozen hub list (config.hubs()), None = no hub suppression; bounds = the view
    bounds (default: the frozen ones); recorded_events_db = the store the alert was raised on
    (AlertStore keeps it): a warning when the report reads another one."""
    bounds = bounds or config.graph_view()
    seed, at, H = alert_view(alert, G, hubs, bounds)
    warnings = []
    if recorded_events_db and events_db and not same_store(recorded_events_db, events_db):
        warnings.append(f"This alert was raised on another event store ({os.path.basename(recorded_events_db)}) "
                        f"than the one read here ({os.path.basename(events_db)}): its evidence may be missing "
                        "or different.")
    facts, hyps = [], []
    cfg = None
    timing_effects, untimed_effects = {}, set()     # (row, effect key) -> p, as layer2_summary counts them
    leads_counted = False                           # a leads-only row's p (known too low) is in the sum
    short = short_namer(H)
    own = set(alert.evidence)
    rows, edge_rows = [], []                        # rows to order; every view edge (for the layout)
    if H is not None:
        for u, v, k, d in H.edges(keys=True, data=True):
            t = d.get("time")
            item = {"sentence": sentence(H, u, v, d.get("kind")), "kind": d.get("kind"), "time": _time(t),
                    "citations": _cite(d.get("evidence") or ([d["primary"]] if d.get("primary") else [])),
                    # report v3: the shared id, both ends, the label without a needless PID, full precision
                    "id": edge_id(u, v, k), "u": u, "v": v, "short": short_sentence(short, u, v, d.get("kind")),
                    "time_precise": _precise(t), "icon": edge_icon(H, v, d)}
            if item["icon"] == "file-created":
                item["icon_citation"] = _cite([d["fingerprint"]])[0]     # the record that proves "file"
            ink = d.get("grade") if d.get("grade") in ("fact", "hypothesis") else None
            edge_rows.append((item, d, _actor_of(H, u, v, d)))
            if ink:
                rows.append({"item": item, "_t": t, "_actor": _actor_of(H, u, v, d), "_v": v, "_node": None,
                             "_starts": v if (ink == "fact" and d.get("kind") == "started") else None,
                             "_ink": ink, "_text": item["sentence"]})
            if d.get("grade") == "fact":
                # the alert's chain: the same rule as the M4 Proven line (the fact cites the alert's own evidence)
                item["in_chain"] = any(c["key"] in own for c in item["citations"])
                facts.append(item)
            elif d.get("grade") == "hypothesis":
                item["in_chain"] = False             # the chain is facts only (debate 11: fact-only steps)
                item.update({"band": d.get("band"), "p": d.get("p"), "n_causes": d.get("n_causes"),
                             "reason": d.get("reason"), "alternative": d.get("alternative"),
                             "provisional": bool(d.get("provisional")),
                             "provisional_reason": d.get("provisional_reason"), "basis": d.get("basis")})
                if cfg is None and d.get("row") in TIMING_ROWS:
                    cfg = confidence.load_config()
                hyps.append(_hypothesis(item, d, u, v, G, H, cfg))
                if d.get("row") in TIMING_ROWS and d.get("p") is not None and d.get("effect"):
                    effect = (d["row"], d["effect"].get("key"))
                    if d.get("assessable"):
                        timing_effects.setdefault(effect, d["p"])
                        if hyps[-1]["lead_only"]:
                            leads_counted = True
                    else:
                        untimed_effects.add(effect)
    hyps.sort(key=rank_key)
    gaps, before = [], []
    if H is not None:
        for g in H.graph.get("gaps", []):
            node = g["node"]
            before_gap = g["kind"] in BEFORE_GAPS
            item = {"what": g["kind"].replace("_", " "), "where": label(H, node), "reason": g["reason"],
                    "time": _time(g.get("time")), "citations": _cite(g.get("evidence")),
                    "id": gap_id(g), "node_id": node, "kind": g["kind"],
                    "placement": "before" if before_gap else "at",
                    # review fix 6: a "Before this" gap's stored time is when the recording NOTICED the
                    # program (in S1 its end), never when it started: no time_precise, kept as noticed_time
                    "plain": gap_plain(g, short(node)), "time_precise": None if before_gap else _precise(g.get("time")),
                    "noticed_time": _precise(g.get("time")) if before_gap else None, "icon": "unknown",
                    "in_chain": False}
            gaps.append(item)
            if item["placement"] == "before":
                before.append(item)
            else:
                rows.append({"item": item, "_t": g.get("time"), "_actor": None, "_v": None, "_node": node,
                             "_starts": None, "_ink": "gap", "_text": item["plain"]})
    ordered = causal_order(rows)
    # "Before this" rows in the order their programs first appear in the story (not by noticed time)
    first_at = {}
    for i, r in enumerate(ordered):
        x = r["item"]
        for n in (r["_actor"], x.get("u"), x.get("v"), x.get("node_id")):
            if n is not None:
                first_at.setdefault(n, i)
    before.sort(key=lambda g: (first_at.get(g["node_id"], len(ordered)), g["plain"]))
    for i, g in enumerate(before):
        g.update(order=i, t_offset_s=None, offset_text=None)       # before the story: no offset is claimed
    for i, r in enumerate(ordered):
        r["item"]["order"] = len(before) + i
    facts = [r["item"] for r in ordered if r["_ink"] == "fact"]    # section 4 in the causal order
    gaps = before + [r["item"] for r in ordered if r["_ink"] == "gap"]
    # offsets are measured from the first step of the alert's chain (else from the first timed row)
    first = next((r for r in ordered if r["_ink"] == "fact" and r["item"]["in_chain"] and r["_t"] is not None), None)
    t0_from = "first chain step" if first else None
    if first is None:
        first = next((r for r in ordered if r["_t"] is not None), None)
        t0_from = "first timed row" if first else None
    t0 = first["_t"] if first else None
    offset_from = {"first chain step": "step 1", "first timed row": "the first row"}.get(t0_from)
    for r in ordered:
        dt = round((r["_t"] - t0).total_seconds(), 6) if (r["_t"] is not None and t0 is not None) else None
        r["item"].update(t_offset_s=dt, offset_text="start" if r is first else offset_text(dt))
    timeline = ([{"time": g["time"], "text": f"Before this: {gap_plain(g, g['where'])}",
                  "short": f"Before this: {g['plain']}", "grade": "gap", "ink": "gap", "placement": "before",
                  "id": g["id"], "order": g["order"], "time_precise": None, "noticed_time": g["noticed_time"],
                  "t_offset_s": None,
                  "offset_text": None, "icon": g["icon"], "in_chain": False} for g in before] +
                [_timeline_row(r) for r in ordered])
    steps_all, seen = [], set()
    for f in facts:
        if f["in_chain"] and f["sentence"] not in seen:          # identical sentences once, as in Proven
            seen.add(f["sentence"])
            steps_all.append({"n": len(steps_all) + 1, "id": f["id"], "text": f["short"], "sentence": f["sentence"],
                              "offset_text": f["offset_text"], "t_offset_s": f["t_offset_s"],
                              "time_precise": f["time_precise"], "icon": f["icon"], "citations": f["citations"]})
    steps = steps_all[:MAX_STEPS]
    limitations = list(LIMITATIONS) + [bounds_limitation(bounds)]
    if alert.source == "beacon":
        limitations.append(BEACON_LIMITATION)
    if _declared_kind(alert):
        limitations.append(DECLARED_SCRIPT_LIMITATION if _declared_kind(alert) == "script" else DECLARED_LIMITATION)
    limitations += warnings
    if H is not None and H.graph.get("truncated"):
        limitations.append(truncated_limitation(bounds))
    hub_count = Counter(label(H, n) for n, d in H.nodes(data=True) if d.get("hub")) if H is not None else Counter()
    hub_nodes = [f"{name} (x{k})" if k > 1 else name for name, k in sorted(hub_count.items())]
    if hub_count:
        limitations.append(f"{sum(hub_count.values())} busy common program(s) that start many different programs in "
                           f"normal use are shown but not followed further: {', '.join(hub_nodes)}. "
                           "Their other activity is left out on purpose; it can still matter.")
    if not hubs:
        limitations.append("Busy common programs were not set aside in this view: every link within the bounds was followed.")
    if any(h["provisional"] for h in hyps):
        limitations.append("Some timing grades here are provisional: they were made before the correction for bursty "
                           "activity was settled (technical details give the exact note).")
    if H is None:
        limitations.append("None of the alert's events could be placed in the evidence graph.")
    next_steps = _next_steps(alert, hyps, gaps)
    layer2 = (H.graph.get("layer2") or {}) if H is not None else {}
    return {"alert": {"title": alert.title, "rule": alert.rule_id, "source": alert.source, "level": alert.level,
                      "time": alert.time, "host": alert.host, "reason": alert.reason,
                      "author": (alert.details or {}).get("author"), "citations": _alert_citations(alert, G, H)},
            "verdict": dict(_verdict(alert, steps, steps_all, facts, hyps, gaps, own), offset_from=offset_from),
            "counts": {"facts": len(facts), "hypotheses": len(hyps), "gaps": len(gaps), "before": len(before),
                       "in_chain": sum(1 for f in facts if f["in_chain"]), "steps": len(steps_all),
                       "nodes": H.number_of_nodes() if H is not None else 0},
            "layout": dict(_layout(H, short, edge_rows, before, ordered) if H is not None
                           else {"lanes": [], "nodes": [], "edges": []},
                           t0=_precise(t0), t0_from=t0_from,
                           # review fix 9: what every offset is counted from, in words the page can show
                           offset_from=offset_from),
            "summary": _summary(alert, facts, hyps, gaps, H),
            "summary_lines": _summary_lines(alert, facts, hyps, gaps),
            "declared_banner": _declared_banner(alert),
            "timeline": timeline, "facts": facts, "hypotheses": hyps, "gaps": gaps,
            "limitations": limitations, "next_steps": next_steps,
            "graph": {"nodes": H.number_of_nodes() if H is not None else 0,
                      "truncated": bool(H is not None and H.graph.get("truncated")), "seed": seed,
                      "at": _time(at) if seed else None,
                      "hubs": hub_nodes, "hubs_not_followed": sum(hub_count.values()),
                      # expected number of hypotheses in this view that are pure coincidence (DESIGN 4.7)
                      "sigma_p": layer2.get("sigma_p") if H is not None else None,
                      # report-next S1: the footer's number, over the timing links timing CAN grade
                      # (counted once per effect, as layer2_summary does), and how many it can't
                      "sigma_p_assessable": layer2.get("sigma_p_assessable") if H is not None else None,
                      "timing_graded": len(timing_effects), "timing_not_assessable": len(untimed_effects),
                      "timing_includes_leads": leads_counted},
            "events_db": os.path.basename(events_db) if events_db else None,
            "warnings": warnings}


def _summary(alert, facts, hyps, gaps, H):
    strong = sum(1 for h in hyps if h["band"] == "high")
    s = f"The rule “{alert.title}” ({alert.level}) fired on {alert.host or 'this machine'} at {alert.time}. "
    if _declared_kind(alert):
        s += DECLARED_SENTENCES[_declared_kind(alert)] + " "
    s += f"Around it, the recording proves {len(facts)} link(s) as facts"
    if hyps:
        s += f", suggests {len(hyps)} more as hypotheses ({strong} graded high)"
    s += f", and {len(gaps)} thing(s) the evidence cannot show."
    return s


def _alert_citations(alert, G, H):
    """The alert's own evidence, named like every other citation (M3): {key, event, record, time,
    text}, found in the view first, then the full graph; a key the graph never placed keeps its
    key and says so (check_citations still checks it against the store)."""
    want, found = list(alert.evidence), {}

    def look(evs):
        for e in evs:
            if e and e.get("key") in need and e["key"] not in found:
                found[e["key"]] = e

    need = set(want)
    for graph in (H, G):
        if graph is None or len(found) == len(need):
            continue
        for _, _, d in graph.edges(data=True):
            look(d.get("evidence") or [])
            look([d.get("primary"), d.get("fingerprint")])
        for _, d in graph.nodes(data=True):
            look([d.get("start_evidence"), d.get("end_evidence")])
        for g in graph.graph.get("gaps", []):
            look(g.get("evidence") or [])
    out = []
    for k in want:
        if k in found:
            out.extend(_cite([found[k]]))
        else:
            out.append({"key": k, "event": None, "record": None, "time": None,
                        "text": "a recorded event the evidence graph does not place"})
    return out


# (not "each is a separate recorded event": a step can be an exact match between two records)
NO_LINK_TEXT = "that one step caused the next; each step is recorded on its own."


def _verdict(alert, steps, steps_all, facts, hyps, gaps, own):
    """The verdict card (debate 11 round 2b): the alert's title and level, the numbered fact-only
    steps (each with its own citations: they ARE section 4's items, by id), then one line each for
    proven / not proven / can't see. Never "downloaded/dropped/fetched": the steps say what was
    recorded ("connected to ...", "created ..."), and the link between them is the hypothesis."""
    chain_nodes = {n for f in facts if f["in_chain"] for n in (f["u"], f["v"])}
    if steps_all:
        more = len(steps_all) - len(steps)
        # section 4's own gloss: a step can be a layer-1 match (ran_as), not one recorded event
        proven = {"text": f"{_plural(len(steps), 'numbered step')}" + (f" (and {more} more in section 4)" if more else "")
                          + ", each one stated by a recorded event, or by an exact match between two records.",
                  "ids": [s["id"] for s in steps]}
    else:
        proven = {"text": "no recorded fact cites the alert's own events.", "ids": []}
    touching = [h for h in hyps if any(c["key"] in own for c in h["citations"])]     # rank order kept
    if touching:
        h, more = touching[0], len(touching) - 1
        not_proven = {"text": f"{h['short']} ({h['band_label'] or h['band']})"
                              + (f" (and {_plural(more, 'more suspected link')} about the alert's events in section 5)"
                                 if more else "") + ".", "id": h["id"], "band": h["band"], "more": more}
    elif hyps:
        not_proven = {"text": f"{_plural(len(hyps), 'suspected link')} nearby, none about the alert's own events.",
                      "id": None, "band": None, "more": 0}
    elif len(steps_all) >= 2:
        # review fix 1: with no suspected link at all, the card still says what the steps do NOT prove
        not_proven = {"text": NO_LINK_TEXT, "id": None, "band": None, "more": 0}
    else:
        not_proven = None
    # "Can't see": a gap at the chain's own programs, files or addresses first ("Before this" ones
    # before the others), then a "Before this" gap anywhere in the view, then any gap
    pick = list(dict.fromkeys([g["id"] for g in gaps if g["placement"] == "before" and g["node_id"] in chain_nodes] +
                              [g["id"] for g in gaps if g["node_id"] in chain_nodes] +
                              [g["id"] for g in gaps if g["placement"] == "before"] + [g["id"] for g in gaps]))
    by_id = {g["id"]: g for g in gaps}
    if pick:
        g, more = by_id[pick[0]], len(gaps) - 1
        cant_see = {"text": g["plain"] + (f" (and {_plural(more, 'more thing')} the recording can't show, in section 6)"
                                          if more else "") + ".", "id": g["id"], "more": more}
    else:
        cant_see = None
    return {"title": alert.title, "level": alert.level, "level_text": f"Alert level: {alert.level}",
            "host": alert.host, "time": alert.time, "steps": steps, "steps_more": len(steps_all) - len(steps),
            "proven": proven, "not_proven": not_proven, "cant_see": cant_see}


def _declared_banner(alert):
    """S4: {note, text} for an alert raised on a declared row (note = alerts.declared_note's own
    words), None otherwise."""
    kind = _declared_kind(alert)
    if not kind:
        return None
    return {"note": declared_note(alert).strip().removeprefix("(").removesuffix(")"), "kind": kind,
            "text": DECLARED_SENTENCES[kind]}


def _quote(h):
    """How the summary quotes a hypothesis's grade: the gloss, plus the coincidence count only where
    the formula set the grade and timing could assess it."""
    bits = [f"{h['band']}, {h['band_label']}"] if h.get("band_label") else [str(h.get("band"))]
    if h.get("basis") not in (None, "formula"):
        bits.append("grade set by the program's own download mark, not the timing"
                    if str(h["basis"]).startswith("download marker") else f"grade set by {basis_words(h['basis'])}")
    elif h.get("row") in TIMING_ROWS and not h.get("assessable"):
        bits.append("timing can't grade it")
    elif h.get("lead_only") and h.get("chance_text"):
        bits.append(f"a lead only; the formula's figure, about {h['chance_text']} by coincidence, is too low on real use")
    elif h.get("chance_text"):
        bits.append(f"about {h['chance_text']} by coincidence" if not h["chance_text"].startswith(("fewer", "more"))
                    else f"{h['chance_text']} by coincidence")
    return "; ".join(bits)


def _summary_lines(alert, facts, hyps, gaps, k=3):
    """M4: the bottom line first, naming things. Proven = facts citing one of the alert's own
    evidence events (identical sentences once), in (time, sentence) order, at most k; Suspected =
    counts by band + the highest-graded link (rank_key, the order section 5 uses); Unknown = the gap
    count + the first gap. Every named fact and hypothesis is the section's own item."""
    lines = [{"label": "Alert", "text": f"“{alert.title}” ({alert.level}) on {alert.host or 'this machine'} at "
                                        f"{alert.time}{declared_note(alert)}."}]
    own = set(alert.evidence)
    named, seen = [], set()
    for f in sorted(facts, key=_fact_order_key):
        if f["sentence"] in seen or not any(c["key"] in own for c in f["citations"]):
            continue
        seen.add(f["sentence"])
        named.append(f)
    shown = named[:k]
    if shown:
        # review fix 2: `named` IS the card's numbered steps (same rule, same order), so say which
        steps = ("the one numbered step" if len(named) == 1 else
                 f"all {len(named)} numbered steps" if len(named) == len(shown) else
                 f"the first {len(shown)} of the {len(named)} numbered steps")
        text = "; ".join(f["sentence"] for f in shown) + (f" ({len(shown)} of {len(facts)} facts: {steps}; each cites "
                                                         "recorded events, see section 4).")
    else:
        text = "no fact cites the alert's own events; see section 4."
    lines.append({"label": "Proven", "text": text, "facts": shown})
    if hyps:
        counts = Counter(h["band"] for h in hyps)
        parts = [_plural(counts[b], BAND_GLOSS[b]) for b in ("high", "medium", "low") if counts.get(b)]
        other = len(hyps) - sum(counts.get(b, 0) for b in BAND_GLOSS)
        if other:
            parts.append(_plural(other, "ungraded link"))
        top = hyps[0]                       # hyps are sorted by rank_key
        lines.append({"label": "Suspected", "text": f"{', '.join(parts)}. Highest-graded: “{top['sentence']}” "
                                                    f"({_quote(top)}).", "hypothesis": top})
    else:
        lines.append({"label": "Suspected", "text": "no suspected links in this view.", "hypothesis": None})
    if gaps:
        g = gaps[0]
        lines.append({"label": "Unknown", "text": f"{_plural(len(gaps), 'thing')} the evidence cannot show; the first: "
                                                  f"{g['what']} ({g['where']}): {g['reason']}.", "gap": g})
    else:
        lines.append({"label": "Unknown", "text": "nothing in this view was marked as unknown.", "gap": None})
    return lines


def _next_steps(alert, hyps, gaps, k=3):
    steps = ["Check the programs named in the facts: where they came from, who installed them, whether they are signed."]
    # S3: one step per medium-or-higher hypothesis, in section 5's order, each with its own
    # alternative explanation
    strong = [h for h in hyps if BAND_ORDER.get(h["band"], 3) <= BAND_ORDER["medium"] and h.get("alternative")][:k]
    for h in strong:
        steps.append(f"Rule out the other explanation for “{h['sentence']}”: {h['alternative']}.")
    if len(hyps) > len(strong):
        steps.append(("Check the other suspected links the same way, each against its other explanation "
                      if strong else "Check each suspected link against its other explanation ") +
                     "(start with the highest band).")
    kinds = {g["what"] for g in gaps}
    if "content unknown" in kinds:
        steps.append("Some files' content was not captured: if they still exist, fingerprint them now.")
    if "parent unknown" in kinds or "origin unknown" in kinds:
        steps.append("Some programs started before recording began: look at what ran at that machine's startup.")
    steps.append("If the activity is expected (an updater, an admin task), record it: a known updater can be listed as expected in the next frozen version (config/frozen.yaml).")
    return steps


def render(content) -> str:
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR), autoescape=True,
                             undefined=jinja2.StrictUndefined)
    return env.get_template("report.html.j2").render(r=content)


def check_citations(content, events: sqlite3.Connection) -> list:
    """Problems with the report's citations (empty list = the report passes)."""
    problems = []
    for section in ("facts", "hypotheses"):
        for item in content[section]:
            if section == "facts" and not item["citations"]:
                problems.append(f"fact without a source: {item['sentence']}")
            if section == "hypotheses":
                for need in ("band", "reason", "alternative"):
                    if not item.get(need):
                        problems.append(f"hypothesis without {need}: {item['sentence']}")
            for c in item["citations"]:
                if events.execute("SELECT 1 FROM events WHERE dedup_key = ?", (c["key"],)).fetchone() is None:
                    problems.append(f"cited event not in the store: {c['key']}")
    for c in content["alert"]["citations"]:
        if events.execute("SELECT 1 FROM events WHERE dedup_key = ?", (c["key"],)).fetchone() is None:
            problems.append(f"alert evidence not in the store: {c['key']}")
    return problems


def official_or_exit(pool, no_hubs=False):
    """In an official run (config.is_official()) refuse to start unless config.verify_official()
    finds nothing wrong (and hub suppression is on): FAIL lines, then exit 1."""
    if not config.is_official():
        return
    problems = config.verify_official(pool=pool)
    if no_hubs:
        problems.append("--no-hubs is not allowed in an official run")
    if problems:
        for p in problems:
            print(f"  FAIL  official run: {p}")
        raise SystemExit(1)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Write the HTML investigation report for one alert")
    ap.add_argument("--db", required=True, help="event store (read-only)")
    ap.add_argument("--alerts", required=True, help="alert database")
    ap.add_argument("--alert", required=True, help="alert id")
    ap.add_argument("--out", required=True)
    ap.add_argument("--host", help="build the graph for this machine only (needed for multi-machine stores)")
    ap.add_argument("--pool", default=DEFAULT_POOL, help="pool of normal rates for hypotheses (layer 2)")
    ap.add_argument("--no-hubs", action="store_true", help="switch hub suppression off (the frozen list is used otherwise)")
    a = ap.parse_args(argv)
    official_or_exit(a.pool, a.no_hubs)
    events = sqlite3.connect("file:" + os.path.abspath(a.db).replace("\\", "/") + "?mode=ro", uri=True)
    s = AlertStore(a.alerts)
    found = [x for x in s.read() if x.alert_id == a.alert]
    recorded = s.events_dbs().get(a.alert)
    s.close()
    if not found:
        raise SystemExit(f"no alert {a.alert}")
    alert = found[0]
    G = build_graph(events, host=a.host or alert.host or None, hypotheses=layer2_from(a.pool))
    content = build(alert, G, a.db, hubs=None if a.no_hubs else config.hubs(), recorded_events_db=recorded)
    for w in content["warnings"]:
        print("WARNING:", w)
    problems = check_citations(content, events)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(render(content))
    print(f"report written: {len(content['facts'])} facts, {len(content['hypotheses'])} hypotheses, "
          f"{len(content['gaps'])} gaps; citation check: {'PASS' if not problems else 'FAIL'}")
    for p in problems[:10]:
        print("  ", html.escape(p))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
