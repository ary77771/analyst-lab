"""Shared by the night-explain labs (why, techniques, respond, moment), so each lab file can be deleted on
its own: the alert row they all show and the list of alerts their pickers offer."""

PICK_WORDS = {
    "pick": "Pick an alert",
    "no_alerts": "No alert at or above the level the screens show is in this alert database yet.",
}


import re

# the recorder's fingerprint statuses (agent/enrich.py) in plain words; the graph's gap sentence carries the code
HASH_STATUS = {
    "gone": "the file was gone before its fingerprint could be taken",
    "busy": "a program still had the file open, so its fingerprint was not taken in time",
    "unreadable": "the file could not be read to take its fingerprint",
    "too_large": "the file was too large to fingerprint",
    "directory": "it is a folder, which has no fingerprint",
}
_HASH_CODE = re.compile(r"fingerprint failed \(hash_status=(\w+)\)")


def plainer(text):
    """A story sentence with the recorder's internal codes put in plain words (the meaning is unchanged)."""
    if not text:
        return text
    return _HASH_CODE.sub(lambda m: HASH_STATUS.get(m.group(1), f"no fingerprint ({m.group(1)})"), text)


def alert_row(a):
    return {"id": a.alert_id, "title": a.title, "level": a.level, "time": a.time, "host": a.host,
            "source": a.source, "rule_id": a.rule_id, "reason": a.reason,
            "declared": (a.details or {}).get("derived_from") == "command_line"}


def picker(ctx, limit=300):
    """The alerts the screens show (newest first), for a lab's "pick an alert" list."""
    return {"words": PICK_WORDS, "alerts": [alert_row(a) for a in ctx.shown_alerts()[:limit]]}


def harness_marks(ctx, items):
    """{item id: plain reason} for the story items (facts, hypotheses) whose cited records are ALL the lab's own test
    machinery (engine/labs/_shared_defs.py: the launcher, the VM's helper programs, the report back to the laptop).
    Such a line is hidden by default behind "show the test machinery"; it is never deleted."""
    from . import _shared_defs as sd
    cache, out = {}, {}

    def reason(key):
        if key not in cache:
            ev = ctx.event(key)
            cache[key] = sd.harness_reason(ev) if ev else None
        return cache[key]

    for it in items:
        keys = [c["key"] for c in it.get("citations", []) if c.get("key")]
        if keys and it.get("id"):
            reasons = [reason(k) for k in keys]
            if all(reasons):
                out[it["id"]] = reasons[0]
    return out


# A program of the lab's own test machinery that the story names as a parent (on S1: the launcher powershell.exe that
# starts the scenario). The fact stays; the page says in plain words what that program is (PROOF 2026-11-24).
MACHINERY_WORDS = {
    "started_by": "started by the lab's own test launcher (the machinery that runs the test), not by a user",
    "is": "this program is the lab's own test launcher (the machinery that runs the test), not part of what is tested",
}


def process_machinery(con, host, node):
    """Why a story's process node ("proc:<host>:{GUID}") is the lab's own test machinery, or None. Judged on the
    program's own start record, or, when its start was never recorded, on what a child's start record says about
    it as the parent (ParentImage / ParentCommandLine): the same shared rule (_shared_defs.harness_reason)."""
    from . import _shared_defs as sd
    if not str(node or "").startswith("proc:"):
        return None
    guid = str(node).rsplit(":", 1)[-1]
    row = con.execute("SELECT Image, CommandLine, origin FROM events WHERE event_id = 1 AND host = ? "
                      "AND upper(ProcessGuid) = upper(?) LIMIT 1", (host, guid)).fetchone()
    if row:
        return sd.harness_reason({"Image": row[0], "CommandLine": row[1], "origin": row[2]})
    row = con.execute("SELECT ParentImage, ParentCommandLine FROM events WHERE event_id = 1 AND host = ? "
                      "AND upper(ParentProcessGuid) = upper(?) LIMIT 1", (host, guid)).fetchone()
    return sd.harness_reason({"Image": row[0], "CommandLine": row[1]}) if row else None


def machinery_notes(ctx, host, items):
    """{story item id: plain note} for items that name the lab's own test machinery as a program: a "started" link
    whose parent is it ("started by the lab's own test launcher ..., not by a user"), and a gap about it ("this
    program is the lab's own test launcher ..."). Read-only; a store that can't be read gives no notes."""
    out, cache = {}, {}
    try:
        with ctx.reading() as con:
            def is_machinery(node):
                if node not in cache:
                    cache[node] = process_machinery(con, host, node)
                return cache[node]
            for it in items:
                if not it.get("id"):
                    continue
                if it.get("kind") == "started" and is_machinery(it.get("u")):
                    out[it["id"]] = MACHINERY_WORDS["started_by"]
                elif it.get("node_id") and is_machinery(it.get("node_id")):
                    out[it["id"]] = MACHINERY_WORDS["is"]
    except Exception:
        return {}
    return out


_EXE = re.compile(r'^\s*(?:"[^"]*"|\S+)\s*')
_HEX64 = re.compile(r"\b([0-9A-Fa-f]{8})[0-9A-Fa-f]{56}\b")


def short_cmd(cmd, limit=90):
    """The telling part of a command line for the first screen: without the program's own path (the chip names it),
    a 64-character fingerprint cut to its first 8 characters, and at most `limit` characters. The full line stays
    one click away."""
    if not cmd:
        return None
    rest = _EXE.sub("", str(cmd), count=1).strip()
    rest = _HEX64.sub(lambda m: m.group(1) + "\u2026", rest)
    if len(rest) > limit:
        rest = rest[:limit - 1] + "\u2026"
    return rest or None


def short_sha(sha):
    """A 64-character fingerprint for the first screen: its first 8 characters and "\u2026" (the full one a click away)."""
    return (str(sha)[:8] + "\u2026") if sha and len(str(sha)) > 12 else sha

