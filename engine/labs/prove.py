"""Lab "What would prove it?" (night 2026-11-24, night-explain; VISION's idea #1): for every SUSPECTED line
and every CAN'T-BE-KNOWN gap of an alert's story, the missing witness: the one record that would settle it,
and whether this lab's recorder could collect that kind of record at all.

    GET /api/labs/prove                  the whole table (every hypothesis and gap type the graph can emit)
                                         and what the Sysmon configuration collects
    GET /api/labs/prove/{alert_id}       the alert's own suspected lines and gaps, each with its witness

The table below is fixed and written by hand: one row per link or gap type of engine/graph.py (a test fails
when the graph gains a type without a row). Whether a witness "can be collected here" is NOT written by
hand: it is read from tools/sysmon/sysmon-config.xml (read-only) every time, so changing the config changes
the answer. "Analyst Lab's recorder" = the project's own agent (FILE_HASH, port records), always on.
Sysmon facts used: it records that a connection happened, never what it carried; it has no event for a
file being read or opened (Sysmon's event list, schema 4.91).

Switch off: delete this file (and dashboard/src/labs/prove/).
"""

import functools
import os
import re
import xml.etree.ElementTree as ET

from fastapi import APIRouter, HTTPException

from engine import labs

from ._explain_common import PICK_WORDS, alert_row, picker, plainer, short_cmd, short_sha

router = APIRouter(prefix="/api/labs/prove")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SYSMON_CONFIG = os.path.join(PROJECT_ROOT, "tools", "sysmon", "sysmon-config.xml")

# Sysmon's event elements (schema 4.91) -> event ids
EDGE_KINDS = ("origin_unknown", "parent_unknown")

SYSMON_ELEMENTS = {"ProcessCreate": [1], "FileCreateTime": [2], "NetworkConnect": [3], "ProcessTerminate": [5],
                   "DriverLoad": [6], "ImageLoad": [7], "CreateRemoteThread": [8], "RawAccessRead": [9],
                   "ProcessAccess": [10], "FileCreate": [11], "RegistryEvent": [12, 13, 14],
                   "FileCreateStreamHash": [15], "PipeEvent": [17, 18], "WmiEvent": [19, 20, 21], "DnsQuery": [22],
                   "FileDelete": [23], "ClipboardChange": [24], "ProcessTampering": [25], "FileDeleteDetected": [26]}


def sysmon(element, what):
    return {"kind": "sysmon", "element": element, "what": what}


def recorder(kind, what):
    return {"kind": "recorder", "type": kind, "what": what}


def elsewhere(what):
    return {"kind": "none", "what": what}


# kind (engine/graph.py) -> the missing witness. "witness" = the record that would make the line Proven;
# "sources" = where such a record could come from (the first that can be collected decides); "helps" =
# records that strengthen the line without proving it.
WITNESSES = {
    # hypotheses (layer 2, dashed)
    "content_from": {
        "row": "T1", "ink": "hypothesis",
        "witness": "The file's content seen inside that connection: the same bytes (or the same SHA-256) in a "
                   "capture of the network traffic or in a web proxy's log.",
        "sources": [elsewhere("a network packet capture or a web proxy log (Sysmon records that a connection "
                              "happened, never what it carried)")],
        "helps": [sysmon("FileCreateStreamHash", "Windows' download mark on the file (event 15), which names "
                                                 "the address it was downloaded from")]},
    "remote_command": {
        "row": "T2", "ink": "hypothesis",
        "witness": "The request that came in on that connection, showing it asked for that program to start.",
        "sources": [elsewhere("the receiving program's own log, or a network packet capture")], "helps": []},
    "fetched_then_ran": {
        "row": "T3", "ink": "hypothesis",
        "witness": "What the program received on that connection, showing it said to start the next program.",
        "sources": [elsewhere("a network packet capture or a web proxy log")], "helps": []},
    "same_path_unknown_content": {
        "row": "R1", "ink": "hypothesis",
        "witness": "A fingerprint (SHA-256) of the file taken right after it was written, equal to the fingerprint "
                   "of the program that was started from that path.",
        "sources": [recorder("FILE_HASH", "the recorder's fingerprint of new program and script files"),
                    sysmon("ProcessCreate", "the started program's fingerprint (event 1, Hashes)")],
        "helps": []},
    "copy_of": {
        "row": "R2", "ink": "hypothesis",
        "witness": "A record that the writing program READ the first file before it wrote the copy.",
        "sources": [elsewhere("Windows' file-access auditing (Security event 4663, needs an audit rule on the "
                              "folder); Sysmon has no event for a file being read")], "helps": []},
    "name_for_connection": {
        "row": "R3", "ink": "hypothesis",
        "witness": "The name the program asked the server for inside the connection (the TLS server name or the "
                   "HTTP Host header).",
        "sources": [elsewhere("a network packet capture or a web proxy log")],
        "helps": [sysmon("DnsQuery", "the program's own name lookup (event 22)")]},
    "started_with_file_argument": {
        "row": "R4", "ink": "hypothesis",
        "witness": "A record that the started program actually opened that file.",
        "sources": [elsewhere("Windows' file-access auditing (Security event 4663, needs an audit rule); Sysmon "
                              "has no event for a file being opened")], "helps": []},
    # gaps (dotted)
    "parent_unknown": {
        "row": "gap", "ink": "gap",
        "witness": "The parent program's own start record.",
        "sources": [sysmon("ProcessCreate", "program starts (event 1), but only from the moment Sysmon itself "
                                            "is running: a parent started earlier is never recorded")],
        "helps": []},
    "origin_unknown": {
        "row": "gap", "ink": "gap",
        "witness": "This program's own start record.",
        "sources": [sysmon("ProcessCreate", "program starts (event 1), but only from the moment Sysmon itself "
                                            "is running")], "helps": []},
    "actor_unknown": {
        "row": "gap", "ink": "gap",
        "witness": "Which program did it. Sysmon saw the action but could not name a program (Windows itself, "
                   "the kernel).",
        "sources": [elsewhere("kernel-level tracing (Windows' Event Tracing); Sysmon reports no program for these")],
        "helps": []},
    "content_unknown": {
        "row": "gap", "ink": "gap",
        "witness": "A fingerprint (SHA-256) of the file taken right after it was written.",
        "sources": [recorder("FILE_HASH", "the recorder's fingerprint of new program and script files (taken "
                                          "after the writer closes the file; missing when it came too late or failed)")],
        "helps": []},
    "owner_unknown": {
        "row": "gap", "ink": "gap",
        "witness": "Exactly one program that owned the listening port.",
        "sources": [recorder("PORT_LISTEN_START", "the recorder's listening-port records (owner by process id "
                                                  "and start time; ambiguous when it can't be pinned to one)")],
        "helps": []},
}

WORDS = {
    "title": "What would prove it?",
    "intro": "Suspected means likely but not proven. For each Suspected line and each gap: the record that would "
             "prove it, and whether this recorder can collect such a record at all.",
    "alternative": "Other explanation",
    "full_lines": "show the full command lines and fingerprint",
    **PICK_WORDS,
    "witness": "Would be proven by",
    "where": "Where such a record comes from",
    "helps": "Would make it stronger, not proven",
    "verdict": {
        "collected": "Collected here",
        "partly": "Collected here in part",
        "not_configured": "Not collected here: Sysmon can record it, this configuration has it switched off",
        "elsewhere": "Can't be collected here: it needs another kind of tool",
    },
    "verdict_note": {
        "collected": "This kind of record is collected: in this case it is missing (too early, too late, or never written).",
        "partly": "Collected only for some files, keys or programs (this configuration's filters).",
        "not_configured": "",
        "elsewhere": "",
    },
    "state": {"all": "all of them", "some": "only some ({n} filters)", "none": "switched off", "unset": "not set up",
              "recorder": "always on"},
    "recorder": "Analyst Lab's recorder",
    "another_tool": "Another kind of tool",
    "no_lines": "This alert's story has no Suspected line and no gap: everything in it is Proven.",
    "no_story": "The evidence graph could not be built for this alert here.",
    "table_title": "The whole table",
    "table_note": "Every kind of Suspected link and gap the evidence graph can draw. The text is fixed; 'collected "
                  "here' is read from the Sysmon configuration file each time.",
    "config_title": "What this Sysmon configuration collects",
    "config_file": "tools/sysmon/sysmon-config.xml",
    "lines": "Suspected lines and gaps in this alert's story",
    "harness_switch": "Show the test machinery",
    "harness_hidden": "Hidden: lines about the lab's own test machinery (its launcher, its report back to the laptop, "
                      "the VM's helper programs): {n}.",
    "edge_title": "Started before this recording began",
    "edge_note": "These programs were already running when the recording started (this recorder records every program "
                 "start, so their starts lie before its first record). That is the edge of this recording, not a blind "
                 "spot of the recorder.",
    "corroborating": "Corroborates, does not prove",
    "fingerprint_title": "Same fingerprint",
    "fingerprint_note": "The program was told to fetch a file with exactly this fingerprint (SHA-256), and the written "
                        "file has it: this makes the link stronger, not proven. Why it stays Suspected: the recorder "
                        "sees the connection and the file, never the bytes travelling between them.",
    "corroborating_note": "A recorded command line names the same address: it says what a program was asked to do, "
                          "not what it did.",
    "open_why": "Why is this suspicious?",
    "details": "details",
    "inks": {"hypothesis": "Suspected", "gap": "Can't be known"},
}


@functools.lru_cache(maxsize=4)
def _config(path, mtime):
    """{element: {"state": all|some|none, "rules": n}} from a Sysmon configuration file (read-only).
    Sysmon: onmatch="exclude" collects everything except what its rules name (no rules = everything);
    onmatch="include" collects only what its rules name (no rules = nothing)."""
    root = ET.parse(path).getroot()
    out = {}
    for el in root.iter():
        if el.tag not in SYSMON_ELEMENTS or "onmatch" not in el.attrib:
            continue
        rules = len(list(el))
        state = ("all" if rules == 0 else "most") if el.attrib["onmatch"] == "exclude" else ("some" if rules else "none")
        prev = out.get(el.tag)
        rank = {"none": 0, "some": 1, "most": 2, "all": 3}
        if prev is None or rank[state] > rank[prev["state"]]:
            out[el.tag] = {"state": state, "rules": rules}
    return out


def config(path=None):
    path = path or SYSMON_CONFIG
    if not os.path.exists(path):
        return None
    return _config(path, os.path.getmtime(path))


def source_state(src, cfg):
    """'all' / 'some' / 'none' / 'unset' for a Sysmon source, 'recorder' for ours, 'elsewhere' otherwise."""
    if src["kind"] == "recorder":
        return "recorder"
    if src["kind"] == "none":
        return "elsewhere"
    if cfg is None:
        return "unset"
    st = (cfg.get(src["element"]) or {}).get("state", "unset")
    return "all" if st == "most" else st


def verdict(row, cfg):
    """collected / partly / not_configured / elsewhere: the best of the row's sources."""
    states = [source_state(s, cfg) for s in row["sources"]]
    if any(s in ("all", "recorder") for s in states):
        return "collected"
    if "some" in states:
        return "partly"
    if any(s in ("none", "unset") for s in states):
        return "not_configured"
    return "elsewhere"


def explain_row(kind, cfg):
    row = WITNESSES.get(kind)
    if row is None:
        return None
    srcs = [dict(s, state=source_state(s, cfg), events=SYSMON_ELEMENTS.get(s.get("element"), [])) for s in row["sources"]]
    helps = [dict(s, state=source_state(s, cfg), events=SYSMON_ELEMENTS.get(s.get("element"), [])) for s in row["helps"]]
    return {"kind": kind, "row": row["row"], "ink": row["ink"], "witness": row["witness"], "sources": srcs,
            "helps": helps, "verdict": verdict(row, cfg)}


def table(cfg):
    return [explain_row(k, cfg) for k in WITNESSES]


def config_summary(cfg):
    if cfg is None:
        return []
    return [{"element": el, "events": SYSMON_ELEMENTS[el], "state": "all" if v["state"] == "most" else v["state"],
             "rules": v["rules"]} for el, v in sorted(cfg.items(), key=lambda x: SYSMON_ELEMENTS[x[0]][0])]


def lines_of(content, cfg):
    """The report's own Suspected lines and gaps (its words), each with its witness row."""
    out = []
    for h in content.get("hypotheses", []):
        out.append({"ink": "hypothesis", "id": h.get("id"), "kind": h.get("kind"), "text": h.get("sentence"), "band": h.get("band"),
                    "u": h.get("u"), "v": h.get("v"),
                    "alternative": h.get("alternative"), "time": h.get("time_precise") or h.get("time"),
                    "witness": explain_row(h.get("kind"), cfg)})
    starts_all = source_state(sysmon("ProcessCreate", ""), cfg) == "all"
    for g in content.get("gaps", []):
        # a program whose start is not in the recording, while this recorder records EVERY program start, began
        # before the recording did: the recording's edge, not a blind spot of the recorder
        edge = g.get("kind") in EDGE_KINDS and starts_all
        out.append({"ink": "gap", "id": g.get("id"), "kind": g.get("kind"), "text": plainer(g.get("plain") or g.get("what")), "band": None,
                    "alternative": None, "edge": edge,
                    # a "Before this" gap has no time of its own: its stored time is when the recording NOTICED it
                    "time": g.get("time_precise"), "noticed": g.get("noticed_time"),
                    "witness": explain_row(g.get("kind"), cfg)})
    return out


IP_PORT = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b")


def corroborate(con, host, lines, limit=5):
    """For each Suspected line that names an address (ip:port): the recorded command lines on this machine that
    name the same address. Corroborating, never proof: a command line says what a program was asked to do."""
    for line in lines:
        if line["ink"] != "hypothesis":
            continue
        fp = fingerprint_match(con, host, line)
        if fp:
            line["fingerprint"] = fp
        m = IP_PORT.search(line["text"] or "")
        if not m:
            continue
        ip, port = m.group(1), m.group(2)
        rows = con.execute("SELECT Image, ProcessId, CommandLine FROM events WHERE event_id = 1 AND host = ? "
                           "AND CommandLine LIKE ? ORDER BY time LIMIT ?", (host, f"%{ip}%{port}%", limit)).fetchall()
        line["corroborating"] = [{"image": r[0], "pid": r[1], "command_line": r[2], "command_short": short_cmd(r[2]),
                                  "names": f"{ip}:{port}"} for r in rows]
    return lines


def fingerprint_match(con, host, line):
    """For a "content came from that server" line: the written file's recorded SHA-256 (the recorder's FILE_HASH, or
    Sysmon's own Hashes when the file was started), and the recorded command lines that name exactly that SHA-256
    (compared ignoring case). A program told to fetch a file with this fingerprint, and a written file that has it:
    stronger, never proven (the grade is the engine's and stays as it is)."""
    if line.get("kind") != "content_from" or not str(line.get("v") or "").startswith("file:"):
        return None
    node = str(line["v"]).split(":", 2)[-1]              # graph file node: file:<host>:<path>[|<sha256>]
    path, _, sha = node.partition("|")
    if sha:                                              # the graph already tied this content to this path
        return _fingerprint_programs(con, host, path, sha)
    row = con.execute("SELECT sha256 FROM events WHERE type = 'FILE_HASH' AND hash_status = 'ok' AND host = ? "
                      "AND lower(TargetFilename) = lower(?) AND sha256 IS NOT NULL LIMIT 1", (host, path)).fetchone()
    sha = row[0] if row else None
    if not sha:
        r = con.execute("SELECT Hashes FROM events WHERE event_id = 1 AND host = ? AND lower(Image) = lower(?) "
                        "AND Hashes IS NOT NULL LIMIT 1", (host, path)).fetchone()
        m = re.search(r"SHA256=([0-9A-Fa-f]{64})", r[0]) if r else None
        sha = m.group(1) if m else None
    return _fingerprint_programs(con, host, path, sha) if sha else None


def _fingerprint_programs(con, host, path, sha):
    rows = con.execute("SELECT Image, ProcessId, CommandLine FROM events WHERE event_id = 1 AND host = ? "
                       "AND lower(CommandLine) LIKE ? ORDER BY time LIMIT 5", (host, f"%{sha.lower()}%")).fetchall()
    if not rows:
        return None
    return {"sha256": sha.upper(), "sha_short": short_sha(sha.upper()), "file": path,
            "programs": [{"image": r[0], "pid": r[1], "command_line": r[2], "command_short": short_cmd(r[2])} for r in rows]}


@router.get("")
def whole_table():
    cfg = config()
    return {**picker(labs.context()), "words": WORDS, "table": table(cfg), "config": config_summary(cfg)}


@router.get("/{alert_id}")
def prove(alert_id: str):
    ctx = labs.context()
    a = ctx.alert(alert_id)
    if a is None:
        raise HTTPException(status_code=404, detail="This alert isn't in this recording.")
    cfg = config()
    try:
        content = ctx.report(a)
        lines, story = lines_of(content, cfg), True
        from ._explain_common import harness_marks
        marks = harness_marks(ctx, content.get("hypotheses", []) + content.get("gaps", []))
        from ._explain_common import machinery_notes
        notes = machinery_notes(ctx, a.host, content.get("hypotheses", []) + content.get("gaps", []))
        for line in lines:
            line["harness"] = marks.get(line.get("id"))
            line["machinery"] = notes.get(line.get("id"))
        try:
            with ctx.reading() as con:
                corroborate(con, a.host, lines)
        except Exception:                         # corroboration is extra: the lines stand without it
            pass
    except Exception:
        lines, story = [], False
    return {"words": WORDS, "alert": alert_row(a), "story": story, "lines": lines, "config": config_summary(cfg)}
