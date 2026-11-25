"""Labs: test a claim (night 2026-11-24, builder night-pivot; VISION's idea #2 in docs/night/ideas.md).

The analyst (or the professor) builds one sentence from an alert's own story: [thing] [verb] [thing], e.g.
"fetch.exe started tool.exe" or "tool.exe got its content from 10.0.2.2:18765". The lab answers with one of
four answers, taken only from the evidence graph the Story screen and the report use (ctx.story):

  proven               a recorded fact says so: the records are cited, each one a pivot link;
  suspected            a hypothesis of the graph says so: its band, why, and the other explanation;
  contradicted         the record says otherwise: another program is recorded doing it, the thing already
                       existed before the subject started, or the event type is collected in full (read from
                       tools/sysmon/sysmon-config.xml) and none like it was recorded. The records are cited;
  can't be known       the witness that would settle it was never recorded (a gap): which one is said;
  no recorded evidence nothing recorded links them this way, and this kind of event is collected only in part
                       (or not at all), so its absence settles nothing. The answer says how much is collected.

It never answers "false" and never invents a link. Contradictions are checked on the whole recording (the
dashboard's full graph), not only on the alert's bounded view. VM data only (night rule 11, engine/labs/pivot.py). Read only.

    GET /api/labs/claim/alerts                      the alerts whose stories can be questioned
    GET /api/labs/claim/{alert}/parts               the story's things, the verbs, and suggested claims
    GET /api/labs/claim/{alert}/test?subject=&verb=&object=
"""

import re

from fastapi import APIRouter, HTTPException

from . import _shared_defs as sd
from . import pivot as pivot_mod

router = APIRouter(prefix="/api/labs/claim")

# verb -> (plain words, edges that would show it as (edge kind, "f" = subject->object / "r" = object->subject),
#          the gap that would make it unknowable: (on which node, gap kinds), the missing witness in plain words)
VERBS = {
    "started": ("started", [("started", "f"), ("fetched_then_ran", "f"), ("remote_command", "f")],
                ("object", {"parent_unknown", "origin_unknown"})),
    "ran_from": ("ran from the file", [("ran_as", "r"), ("same_path_unknown_content", "r")],
                 ("subject", {"origin_unknown"})),
    "started_with_file": ("was started with the file", [("started_with_file_argument", "r")],
                          ("subject", {"origin_unknown"})),
    "created": ("created", [("created", "f")], ("object", {"actor_unknown"})),
    "deleted": ("deleted", [("deleted", "f")], ("object", {"actor_unknown"})),
    "connected_to": ("connected to", [("connected_to", "f"), ("accepted_from", "f")], ("object", {"actor_unknown"})),
    "looked_up": ("looked up the name", [("looked_up", "f")], ("object", {"actor_unknown"})),
    "content_from": ("got its content from", [("content_from", "r"), ("copy_of", "r"), ("same_content", "f"),
                                               ("same_content", "r")], ("subject", {"content_unknown"})),
    "set_autostart": ("set the autostart entry", [("set_autostart", "f")], ("object", {"actor_unknown"})),
}
WITNESS = {
    "parent_unknown": "the record of who started it: its parent was already running before the recorder started, "
                      "so the parent's id is all zeros",
    "origin_unknown": "the record of this program's start: it was already running, or started outside the recording",
    "actor_unknown": "the acting program: Sysmon recorded this event without the program that did it",
    "content_unknown": "a fingerprint of the file's content: none was recorded, so its content cannot be compared",
    "owner_unknown": "the owner: no recorded program can be tied to it",
}
NO_EVIDENCE_WORD = "No recorded evidence"
CONTRA_WORD = "Contradicted by the record"
# verb -> the Sysmon element that would record it (the config decides how much of it is collected)
ELEMENT = {"started": "ProcessCreate", "created": "FileCreate", "deleted": "FileDeleteDetected",
           "connected_to": "NetworkConnect", "looked_up": "DnsQuery", "set_autostart": "RegistryEvent"}
COVERAGE_WORDS = {
    "all": "This kind of event is recorded in full on this machine",
    "some": "This kind of event is recorded only in part on this machine (the configuration's filters: e.g. file "
            "events only for programs, scripts and a few folders; registry changes only for autostart places), so "
            "a missing record settles nothing",
    "none": "This kind of event is not recorded on this machine at all, so a missing record settles nothing",
    "unknown": "How much of this kind of event is recorded here could not be read, so a missing record settles nothing",
}
NO_EVIDENCE_LEAD = "This is not the same as false. Nothing recorded supports the claim, and nothing recorded rules it out."
BAND_RANK = {"high": 0, "medium": 1, "low": 2}


def _context():
    from engine import labs
    return labs.context()


def coverage(verb, cfg=None):
    """all / some / none / unknown: how much of the event that would record `verb` the Sysmon config collects
    (engine/labs/prove.py reads tools/sysmon/sysmon-config.xml; "most" = all but some exclusions, not "all")."""
    el = ELEMENT.get(verb)
    if el is None:
        return "unknown"
    if cfg is None:
        try:
            from .prove import config
            cfg = config()
        except Exception:
            cfg = None
    if not cfg:
        return "unknown"
    st = (cfg.get(el) or {}).get("state")
    return {"all": "all", "most": "some", "some": "some", "none": "none"}.get(st, "none" if st is None else "unknown")


def _hms(tm):
    """'2026-10-30 20:01:31' from the one clock's ISO text (or a datetime); the store's clock is UTC."""
    if hasattr(tm, "strftime"):
        return tm.strftime("%Y-%m-%d %H:%M:%S")
    s = str(tm or "")
    return f"{s[:10]} {s[11:19]}" if len(s) >= 19 else (s or "?")


def edge_when(ctx, d):
    """When an edge's fact HAPPENED, on the one clock (engine/labs/_shared_defs.py: Sysmon's UtcTime first, else
    the record time) read from the records it cites; the graph's own time only when none can be read."""
    best = None
    for e in d.get("evidence") or ([d["primary"]] if d.get("primary") else []):
        key = (e or {}).get("key")
        row = None
        if key and ctx is not None:
            try:
                row = ctx.event(key)
            except Exception:
                row = None
        w = sd.when(row) if row else None
        if w and (best is None or w < best):
            best = w
    if best is None and d.get("time") is not None:
        tm = d["time"]
        best = sd.when_text(tm.isoformat() if hasattr(tm, "isoformat") else str(tm))
    return best


def _edges(G, u, v):
    return [d for _, d in (G[u][v].items() if G.has_edge(u, v) else [])]


def _started(G, n, ctx=None):
    """(time on the one clock, parent node, edge) of n's recorded start, or (None, None, None)."""
    for u, _, d in G.in_edges(n, data=True):
        if d.get("kind") == "started" and d.get("grade") == "fact":
            tm = edge_when(ctx, d)
            if tm is not None:
                return tm, u, d
    return None, None, None


def _first_seen(G, n, ctx=None):
    """(time on the one clock, edge) of the earliest recorded fact about n (its start, or anything it did or had
    done to it)."""
    best = (None, None)
    for u, v, d in list(G.in_edges(n, data=True)) + list(G.out_edges(n, data=True)):
        if d.get("grade") != "fact":
            continue
        tm = edge_when(ctx, d)
        if tm is not None and (best[0] is None or tm < best[0]):
            best = (tm, (u, v, d))
    return best

def _words():
    """The answer words: the three inks' own words (engine/dashboard/words.py) plus "No recorded evidence"."""
    try:
        from engine.dashboard.words import INKS
        ink = {k: v["word"] for k, v in INKS.items()}
    except Exception:
        ink = {"fact": "Proven", "hypothesis": "Suspected", "gap": "Can't be known"}
    from engine.report import BAND_GLOSS
    return ink, dict(BAND_GLOSS)


def node_entity(H, n):
    """The pivot (kind, value) of a graph node, or None."""
    d = H.nodes[n]
    kind = d.get("kind") or n.split(":", 1)[0]
    if kind == "process" and d.get("guid"):
        return {"kind": "process", "value": d["guid"]}
    if kind == "file" and d.get("path"):
        return {"kind": "file", "value": d["path"]}
    if kind == "endpoint" and d.get("ip"):
        return {"kind": "ip", "value": d["ip"]}
    if kind == "dns" and d.get("name"):
        return {"kind": "domain", "value": d["name"]}
    if kind == "autostart" and d.get("key"):
        return {"kind": "registry", "value": d["key"]}
    return None


def _label(H, n):
    from engine.report import label
    return label(H, n)


def _sentence(H, u, v, kind):
    from engine.report import sentence
    return sentence(H, u, v, kind)


def node_is_harness(ctx, G, n):
    """Is this node the lab's own test machinery (engine/labs/_shared_defs.py)? A program by its path and origin
    tag, then by the record of its start (its command line); an address by where it connects (the report back)."""
    d = G.nodes[n]
    kind = d.get("kind") or n.split(":", 1)[0]
    if kind == "endpoint":
        return sd.is_harness({"DestinationIp": d.get("ip"), "DestinationPort": d.get("port")})
    if kind != "process":
        return False
    if sd.is_harness({"Image": d.get("image"), "origin": d.get("origin")}):
        return True
    for _, _, e in G.in_edges(n, data=True):
        if e.get("kind") == "started" and ctx is not None:
            for ev in e.get("evidence") or []:
                try:
                    row = ctx.event((ev or {}).get("key"))
                except Exception:
                    row = None
                if row and sd.is_harness(row):
                    return True
    return False


KIND_WORDS = {"process": "program", "file": "file", "endpoint": "address", "dns": "name", "autostart": "autostart entry",
              "port": "listening port"}
PID = re.compile(r" \(PID \d+\)")


def plain_claim(text):
    """A claim as a person says it: without the process ids ("s1_fetch.exe connected to 10.0.2.2:18765")."""
    return PID.sub("", text or "")


def plain_label(H, n):
    """(plain words, pid or None) for the dropdowns: a program by its name, a file by its folder and name
    ("s1\\payload", never a bare fragment), an address as written."""
    d = H.nodes[n]
    kind = d.get("kind") or n.split(":", 1)[0]
    if kind == "process":
        return PID.sub("", _label(H, n)), d.get("pid")
    if kind == "file" and d.get("path"):
        parts = [x for x in re.split(r"[\\/]", d["path"]) if x]
        return "\\".join(parts[-2:]) if len(parts) > 1 else (parts[0] if parts else _label(H, n)), None
    return _label(H, n), None


def parts(H, ctx=None, machinery=True):
    """The things of a story (for the two dropdowns) and the verbs. Without `machinery`, the lab's own test
    machinery is left out of the dropdowns. Each thing has plain words: a program's PID only when two programs
    share a name."""
    nodes = []
    for n, d in H.nodes(data=True):
        if not machinery and node_is_harness(ctx, H, n):
            continue
        kind = d.get("kind") or n.split(":", 1)[0]
        words, pid = plain_label(H, n)
        nodes.append({"id": n, "label": _label(H, n), "kind": kind, "kind_word": KIND_WORDS.get(kind, kind),
                      "plain": words, "pid": pid,
                      "gaps": sorted({g["kind"] for g in d.get("gaps", [])}), "entity": node_entity(H, n)})
    seen = {}
    for x in nodes:
        seen[(x["kind"], x["plain"].lower())] = seen.get((x["kind"], x["plain"].lower()), 0) + 1
    for x in nodes:
        if x["pid"] is not None and seen[(x["kind"], x["plain"].lower())] > 1:
            x["plain"] = f"{x['plain']} (PID {x['pid']})"
    order = {"process": 0, "file": 1, "endpoint": 2, "dns": 3}
    nodes.sort(key=lambda x: (order.get(x["kind"], 9), x["plain"].lower()))
    verbs = [{"id": k, "word": w} for k, (w, _, _) in VERBS.items()]
    return nodes, verbs


def _citations(ctx, H, d):
    """The recorded events an edge cites, each with a plain summary and its pivot entities (VM data only)."""
    out = []
    ev = d.get("evidence") or ([d["primary"]] if d.get("primary") else [])
    for e in ev:
        key = (e or {}).get("key")
        if not key:
            continue
        row = None
        try:
            row = ctx.event(key)
        except Exception:
            row = None
        if row is not None and not pivot_mod.host_ok(row.get("host")):
            continue
        out.append({"key": key, "time": (row or {}).get("time"), "summary": pivot_mod.summary(row) if row else key,
                    "entities": [x for x in pivot_mod.entities_of(row) if x["kind"] != "process"] if row else []})
    return out


def contradictions(ctx, G, s, verb, o, cfg=None):
    """What the record says AGAINST "s verb o" (each with its cited records), or []. Only what records show:
    another recorded actor, a recorded order in time, or the absence of an event the config collects in full."""
    out = []
    L = lambda n: _label(G, n)

    def cite(d):
        return _citations(ctx, G, d)

    if verb == "started" and G.nodes[o].get("kind") == "process":
        t_o, parent, d = _started(G, o, ctx)
        if parent is not None and parent != s:
            out.append({"sentence": f"the record shows {L(parent)} started {L(o)}, and a program has one parent",
                        "time": str(t_o), "citations": cite(d)})
        t_s, _, ds = _started(G, s, ctx)
        seen_o, eo = _first_seen(G, o, ctx)
        if not out and t_s is not None and seen_o is not None and seen_o < t_s:
            out.append({"sentence": f"{L(o)} was already running at {_hms(seen_o)} UTC, before {L(s)} started at "
                                    f"{_hms(t_s)} UTC",
                        "time": str(seen_o), "citations": cite(eo[2]) + cite(ds)})
    elif verb in ("created", "deleted", "set_autostart"):
        kind = {"created": "created", "deleted": "deleted", "set_autostart": "set_autostart"}[verb]
        others = [(u, d) for u, _, d in G.in_edges(o, data=True)
                  if d.get("kind") == kind and d.get("grade") == "fact" and u != s]
        for u, d in others[:3]:
            out.append({"sentence": f"the record shows {_sentence(G, u, o, kind)}; nothing records {L(s)} doing it, "
                                    f"although such events are recorded for this {('key' if verb == 'set_autostart' else 'file')}",
                        "time": str(d.get("time") or ""), "citations": cite(d)})
    elif verb in ("connected_to", "looked_up") and coverage(verb, cfg) == "all":
        seen_s, es = _first_seen(G, s, ctx)
        kinds = ("connected_to", "accepted_from") if verb == "connected_to" else ("looked_up",)
        if seen_s is not None and not any(d.get("kind") in kinds for d in _edges(G, s, o)):
            what = "outgoing connection" if verb == "connected_to" else "name lookup"
            out.append({"sentence": f"every {what} is recorded on this machine (the configuration collects them in "
                                    f"full), {L(s)} is in the recording, and none from it to {L(o)} was recorded",
                        "coverage": COVERAGE_WORDS["all"], "time": str(seen_s), "citations": cite(es[2])})
    return out


def test(ctx, H, subject, verb, obj, G=None, cfg=None):
    """The answer to "subject verb object" in the story H (contradictions checked on the full graph G when
    given). Never "false"."""
    if verb not in VERBS:
        raise ValueError(f"verb must be one of {sorted(VERBS)}")
    if subject not in H or obj not in H:
        raise LookupError("both things must be part of this alert's story")
    if subject == obj:
        raise ValueError("pick two different things")
    ink, gloss = _words()
    word, matches, (gap_on, gap_kinds) = VERBS[verb]
    claim = f"{_label(H, subject)} {word} {_label(H, obj)}"
    pairs = []
    src = G if G is not None and subject in G and obj in G else H      # a link outside the alert's view counts too
    for kind, direction in matches:
        u, v = (subject, obj) if direction == "f" else (obj, subject)
        if src.has_edge(u, v):
            for k, d in src[u][v].items():
                if d.get("kind") == kind:
                    pairs.append((u, v, d))
    base = {"claim": claim, "subject": subject, "verb": verb, "object": obj,
            "subject_entity": node_entity(H, subject), "object_entity": node_entity(H, obj),
            "subject_plain": plain_label(H, subject)[0], "object_plain": plain_label(H, obj)[0]}

    facts = [p for p in pairs if p[2].get("grade") == "fact"]
    if facts:
        return {**base, "answer": "proven", "ink": "fact", "word": ink["fact"],
                "because": [{"sentence": _sentence(src, u, v, d.get("kind")), "time": str(d.get("time") or ""),
                             "citations": _citations(ctx, src, d)} for u, v, d in facts]}
    hyps = sorted((p for p in pairs if p[2].get("grade") != "fact"),
                  key=lambda p: BAND_RANK.get(p[2].get("band"), 9))
    if hyps:
        return {**base, "answer": "suspected", "ink": "hypothesis", "word": ink["hypothesis"],
                "because": [{"sentence": _sentence(src, u, v, d.get("kind")), "band": d.get("band"),
                             "band_word": gloss.get(d.get("band"), "no grade (too little data)"),
                             "reason": d.get("reason"), "alternative": d.get("alternative"),
                             "time": str(d.get("time") or ""), "citations": _citations(ctx, src, d)}
                            for u, v, d in hyps]}
    contra = contradictions(ctx, G if G is not None else H, subject, verb, obj, cfg)
    if contra:
        return {**base, "answer": "contradicted", "ink": "contra", "word": CONTRA_WORD, "because": contra}
    node = subject if gap_on == "subject" else obj
    gaps = [g for g in H.nodes[node].get("gaps", []) if g.get("kind") in gap_kinds]
    if gaps:
        return {**base, "answer": "unknown", "ink": "gap", "word": ink["gap"],
                "because": [{"sentence": f"{_label(H, node)}: {g.get('reason', '')}", "gap": g["kind"],
                             "missing": WITNESS.get(g["kind"], g["kind"]), "time": str(g.get("time") or ""),
                             "citations": _citations(ctx, H, {"evidence": g.get("evidence")})} for g in gaps]}
    also = []
    for u, v in ((subject, obj), (obj, subject)):
        if H.has_edge(u, v):
            for k, d in H[u][v].items():
                also.append({"sentence": _sentence(H, u, v, d.get("kind")),
                             "ink": "fact" if d.get("grade") == "fact" else "hypothesis"})
    cov = coverage(verb, cfg)
    note = NO_EVIDENCE_LEAD + " " + (COVERAGE_WORDS[cov] + "." if verb in ELEMENT else
                                     "This kind of link has no single recorded event that would settle it.")
    return {**base, "answer": "no_evidence", "ink": None, "word": NO_EVIDENCE_WORD, "note": note,
            "coverage": cov if verb in ELEMENT else None, "because": [], "also": also}


def _distance(t, when):
    """Seconds between the alert's moment and a time (both datetimes); far away when either is missing."""
    try:
        return abs((when - t).total_seconds())
    except Exception:
        return float("inf")


def suggestions(ctx, H, limit=5, t=None, G=None, machinery=True):
    """Up to four claims worth testing, one per answer where the story has one: a recorded link, a suspected
    link, a missing witness, and a claim nothing supports. Found in the graph, never written by hand; the
    ones nearest the alert's own moment `t` first."""
    out, seen = [], set()

    hidden = set() if machinery else {n for n in H.nodes if node_is_harness(ctx, H, n)}
    # a folder is a fragment to a reader ("deleted s1"): a suggestion names files with a name and an extension
    hidden |= {n for n, d in H.nodes(data=True)
               if (d.get("kind") == "file" and "." not in str(d.get("path") or n).replace("/", "\\").rsplit("\\", 1)[-1])}

    def take(s, verb, o):
        if s in hidden or o in hidden:
            return False
        try:
            a = test(ctx, H, s, verb, o, G=G)
        except (ValueError, LookupError):
            return False
        if a["answer"] in seen:
            return False
        seen.add(a["answer"])
        out.append({"subject": s, "verb": verb, "object": o, "claim": a["claim"], "plain": plain_claim(a["claim"]),
                    "answer": a["answer"], "word": a["word"]})
        return True

    kind_verbs = {}
    for verb, (_, matches, _) in VERBS.items():
        for kind, direction in matches:
            kind_verbs.setdefault(kind, []).append((verb, direction))
    # the telling verbs first (a program starting another, connecting out, writing a file), then the nearest
    telling = {"started": 0, "connected_to": 1, "created": 2, "content_from": 0, "fetched_then_ran": 1}
    edges = sorted(H.edges(keys=True, data=True),
                   key=lambda e: (telling.get(e[3].get("kind"), 5), _distance(t, e[3].get("time")),
                                  str(e[3].get("time") or ""), e[0], e[1]))
    for grade in ("fact", "hypothesis"):
        for u, v, k, d in edges:
            if (d.get("grade") == "fact") != (grade == "fact"):
                continue
            hit = False
            for verb, direction in kind_verbs.get(d.get("kind"), []):
                s, o = (u, v) if direction == "f" else (v, u)
                if take(s, verb, o):
                    hit = True
                    break
            if hit:
                break
    def near(n):
        times = [e[3].get("time") for e in H.in_edges(n, keys=True, data=True)] + \
                [e[3].get("time") for e in H.out_edges(n, keys=True, data=True)]
        return min([_distance(t, x) for x in times if x is not None] or [float("inf")])

    procs = sorted((n for n, d in H.nodes(data=True) if d.get("kind") == "process"), key=near)
    ends = sorted((n for n, d in H.nodes(data=True) if d.get("kind") == "endpoint"), key=near)
    for f, d in sorted(H.nodes(data=True), key=lambda x: near(x[0])):                    # a missing witness: where a file's content came from
        if d.get("kind") == "file" and any(g["kind"] == "content_unknown" for g in d.get("gaps", [])) and ends:
            if take(f, "content_from", ends[0]):
                break
    for n in procs:                                    # or: someone "started" a program whose parent is unknown
        if any(g["kind"] in ("parent_unknown", "origin_unknown") for g in H.nodes[n].get("gaps", [])):
            other = next((m for m in procs if m != n), None)
            if other and take(other, "started", n):
                break
    fits = {"process": ("started",), "endpoint": ("connected_to",), "file": ("deleted", "created")}
    want = {"contradicted", "no_evidence"}
    for s in procs:                                    # claims the record speaks against, or does not speak to:
        for o, d in H.nodes(data=True):                # a run and a thing no link joins (take() skips answers found)
            if want <= seen:
                break
            if o != s and not H.has_edge(s, o) and not H.has_edge(o, s):
                for verb in fits.get(d.get("kind"), ()):
                    take(s, verb, o)
        if want <= seen:
            break
    order = {"proven": 0, "suspected": 1, "contradicted": 2, "unknown": 3, "no_evidence": 4}
    return sorted(out, key=lambda x: order[x["answer"]])[:limit]


# -- routes ------------------------------------------------------------------------------------------------

def _story(ctx, alert_id, with_time=False):
    a = ctx.alert(alert_id)
    if a is None or not pivot_mod.host_ok(a.host):
        raise HTTPException(status_code=404, detail="no such alert")
    try:
        seed, t, H = ctx.story(a)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    if not seed or H is None or H.number_of_nodes() == 0:
        raise HTTPException(status_code=404, detail="this alert has no story to question (its events are not in the graph)")
    try:
        G = ctx.graph(a.host)                           # the whole recording, for "the record says otherwise"
    except Exception:
        G = None
    if G is not None and not all(n in G for n in H.nodes):
        G = None
    return (a, H, t, G) if with_time else (a, H, G)


@router.get("/alerts")
def claim_alerts():
    ctx = _context()
    try:
        rows = ctx.shown_alerts()
    except Exception:
        rows = ctx.alerts()
    return [{"id": a.alert_id, "title": a.title, "level": a.level, "time": a.time}
            for a in rows if pivot_mod.host_ok(a.host)][:200]


@router.get("/{alert_id}/parts")
def claim_parts(alert_id: str, machinery: bool = False):
    ctx = _context()
    a, H, t, G = _story(ctx, alert_id, with_time=True)
    nodes, verbs = parts(H, ctx, machinery)
    hidden = H.number_of_nodes() - len(nodes)
    ink, _ = _words()
    return {"alert": {"id": a.alert_id, "title": a.title, "level": a.level, "time": a.time}, "nodes": nodes,
            "verbs": verbs, "suggestions": suggestions(ctx, H, t=t, G=G, machinery=machinery),
            "machinery_hidden": hidden, "machinery_word": sd.WORDS["harness_switch"],
            "answers": {"proven": ink["fact"], "suspected": ink["hypothesis"], "contradicted": CONTRA_WORD,
                        "unknown": ink["gap"], "no_evidence": NO_EVIDENCE_WORD}}


@router.get("/{alert_id}/test")
def claim_test(alert_id: str, subject: str, verb: str, object: str):
    ctx = _context()
    a, H, G = _story(ctx, alert_id)
    try:
        return {**test(ctx, H, subject, verb, object, G=G), "alert": a.alert_id}
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
