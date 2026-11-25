"""The incident in one paragraph, at the top of the checklist ("I have an alert"; PROOF 2026-11-24).

Built by fixed templates from what the page already answers (no AI, no invented words): every part of every
sentence names its SOURCE (the checklist question it summarises, or the lab that computed it) and carries a status
that is never stronger than that source's own answer:

  - what happened: the alert's program, who started it, what it connected to, the file it wrote and that it then
    started that same file (each part only when its question answers Proven);
  - how sure: the story's own counts (the "How sure" step's numbers), the recording's edge named as such;
  - the suspected links, said as "likely, not proven", with the fingerprint corroboration from prove;
  - what is NOT in the story (autostarts, deletions), said as "not in its story", never "didn't happen";
  - where else its things appear ("Where else?", night-hunt's sweep), counting only what this recorder can see.

A missing part is left out, never guessed. Shared by the checklist only; deleting this file removes the paragraph.
"""

from datetime import datetime

WORDS = {
    "title": "In short",
    "hover": "From: {source}",
    "started_by_launcher": ", started by the lab's own test launcher,",
    "connected": " connected to {what}",
    "wrote": "{sep}wrote {what}",
    "started_same": "{sep}started that same file {secs} later",
    "started_other": "{sep}started {what}",
    "and_more": "{what} and {n} more",
    "sure": "Of the {total} lines of its story, {facts} {facts_verb} proven by a record, {hyps} suspected and {gaps} can't be known",
    "sure_edge": " (only how a program that was already running when this recording began was started)",
    "likely": "Likely but not proven: {sentence}",
    "fingerprint": " (the written file has exactly the fingerprint {program} was told to fetch)",
    "more_likely": "More suspected links are on the questions below: {n}",
    "machinery_left_out": "Left out here: suspected links about the lab's own test machinery: {n}",
    "not_in_story": "No {what} is in its story; this recorder sees only some of these",
    "persist_what": "autostart change",
    "deleted_what": "file deletion",
    "no_first": "No {what}",
    "or_rest": " or {what} is in its story; this recorder sees only some of these",
    "where_none": "None of its {n} things that this recorder can see (programs, files, addresses, fingerprints) shows up "
                  "anywhere else in this recording",
    "where_some": "{k} of its {n} things also show up in another run on this machine",
    "where_cant": " ({c} more can't be checked here)",
    "sources": {"sweep": "Where else? (another lab)", "prove": "What would prove it? (another lab)"},
}

# how strong a status is: a summary part may never be stronger than the answer it summarises
RANK = {"fact": 5, "listed": 4, "mixed": 3, "hypothesis": 2, "raised": 2, "unproven": 2, "gap": 1, "none": 0,
        "unchecked": 0, None: 0}


def _part(text, status, source):
    return {"text": text, "status": status, "source": source}


def _path(node):
    """The path of a graph file node ('file:<host>:<path>[|<sha256>]')."""
    return str(node).split(":", 2)[-1].partition("|")[0]


def _base(path):
    return str(path).replace("/", "\\").rsplit("\\", 1)[-1]


def name_of(node, names):
    """A plain name for a graph node: a program by its recorded image, a file by its file name, an address as is."""
    node = str(node or "")
    if node in names:
        return names[node]
    if node.startswith("file:"):
        return _base(_path(node))
    if node.startswith("net:"):
        return node.split(":", 2)[-1]
    return None


def _secs(t0, t1):
    try:
        a = datetime.fromisoformat(str(t0).replace("Z", "+00:00"))
        b = datetime.fromisoformat(str(t1).replace("Z", "+00:00"))
    except ValueError:
        return None
    s = (b - a).total_seconds()
    return f"{s:.1f} s" if s >= 0 else None


def _listed(items, w):
    return items[0] if len(items) == 1 else w["and_more"].format(what=items[0], n=len(items) - 1)


def what_happened(qs, content, names, scope_nodes, harness=(), launcher=(), folders=(), w=WORDS):
    """The first sentence: [program][, started by the lab's own test launcher,] connected to ..., wrote ... and
    started that same file N s later. Parts only from facts inside the alert's own programs ("it"), never the test
    machinery's lines, and only when the question that lists them answers Proven."""
    facts = [f for f in content.get("facts", []) if f.get("id") not in set(harness)]
    it = set(scope_nodes)
    ok = lambda key: (qs.get(key) or {}).get("status") == "fact"    # noqa: E731

    def acts(p):
        conns = [f for f in facts if f.get("kind") == "connected_to" and f.get("u") == p] if ok("network") else []
        writes = [f for f in facts if f.get("kind") == "created" and f.get("u") == p
                  and _path(f.get("v")).lower() not in folders] if ok("files") else []
        starts = [f for f in facts if f.get("kind") == "started" and f.get("u") == p and f.get("v") in it] if ok("what") else []
        return conns, writes, starts

    actors = sorted((p for p in it if name_of(p, names)), key=lambda p: -sum(len(x) for x in acts(p)))
    if not actors or not any(acts(actors[0])):
        return None
    p = actors[0]
    conns, writes, starts = acts(p)
    parts = [_part(name_of(p, names), "fact", "what")]
    if any(f.get("kind") == "started" and f.get("v") == p and f.get("id") in set(launcher) for f in content.get("facts", [])):
        parts.append(_part(w["started_by_launcher"], "fact", "who"))
    sep = lambda: "" if len(parts) == 1 or parts[-1]["text"].endswith(",") else ","   # noqa: E731
    if conns:
        parts.append(_part(w["connected"].format(what=_listed([name_of(f["v"], names) for f in conns], w)), "fact", "network"))
    if writes:
        parts.append(_part(w["wrote"].format(sep=sep() + " ", what=_listed([name_of(f["v"], names) for f in writes], w)),
                           "fact", "files"))
    if starts:
        # "that same file": the started program ran from a file this program wrote (the story's ran_as link)
        written = {f["v"]: f for f in writes}
        same = next(((s, r) for s in starts for r in content.get("facts", [])
                     if r.get("kind") == "ran_as" and r.get("v") == s["v"] and r.get("u") in written), None)
        lead = (sep() + " and ") if len(parts) > 1 else " "
        if same:
            secs = _secs(written[same[1]["u"]].get("time_precise"), same[0].get("time_precise"))
            text = w["started_same"].format(sep=lead, secs=secs) if secs else w["started_other"].format(
                sep=lead, what=name_of(same[0]["v"], names))
        else:
            text = w["started_other"].format(sep=lead, what=_listed([name_of(s["v"], names) for s in starts], w))
        parts.append(_part(text, "fact", "what"))
    parts[-1] = dict(parts[-1], text=parts[-1]["text"] + ".")
    return parts


def how_sure(qs, content, edge=0, w=WORDS):
    """The story's own counts (the same numbers as the "How sure" step), with the recording's edge named."""
    q = qs.get("sure")
    c = content.get("counts", {})
    f, h, g = c.get("facts", 0), c.get("hypotheses", 0), c.get("gaps", 0)
    if not q or not (f + h + g):
        return None
    text = w["sure"].format(total=f + h + g, facts=f, facts_verb="is" if f == 1 else "are", hyps=h, gaps=g)
    if g and edge and edge >= g:
        text += w["sure_edge"]
    return [_part(text + ".", q["status"], "sure")]


def suspected(qs, content, fingerprints=None, w=WORDS, limit=2, machinery=(), harness=()):
    """Each Suspected link (the story's own sentence), said as likely, not proven; the fingerprint match, if any.
    A link that touches the lab's own test machinery (its helper programs, its report back to the laptop) is not the
    incident: left out of the paragraph, and the count of those said."""
    if not qs.get("sure"):
        return []
    hyps = content.get("hypotheses", [])
    ours = [h for h in hyps if h.get("id") in set(harness) or h.get("u") in set(machinery) or h.get("v") in set(machinery)]
    real = [h for h in hyps if h not in ours]
    out = []
    for hyp in real[:limit]:
        text = w["likely"].format(sentence=(hyp.get("sentence") or "").strip().rstrip("."))
        fp = (fingerprints or {}).get(hyp.get("id"))
        parts = [_part(text, "hypothesis", "sure")]
        if fp and fp.get("programs"):
            parts.append(_part(w["fingerprint"].format(program=_base(fp["programs"][0].get("image") or "?")),
                               "hypothesis", "prove"))
        parts[-1] = dict(parts[-1], text=parts[-1]["text"] + ".")
        out.append(parts)
    tail = []
    if len(real) > limit:
        tail.append(w["more_likely"].format(n=len(real) - limit))
    if ours:
        tail.append(w["machinery_left_out"].format(n=len(ours)))
    if tail:
        out.append([_part("; ".join(tail) + ".", "hypothesis", "sure")])
    return out


def not_in_story(qs, w=WORDS):
    """Autostarts and deletions the story does NOT contain: said as "not in its story", never "didn't happen"."""
    none = [k for k in ("persist", "deleted") if (qs.get(k) or {}).get("status") == "none"]
    if not none:
        return None
    if len(none) == 1:
        return [_part(w["not_in_story"].format(what=w[f"{none[0]}_what"]) + ".", "none", none[0])]
    return [_part(w["no_first"].format(what=w["persist_what"]), "none", "persist"),
            _part(w["or_rest"].format(what=w["deleted_what"]) + ".", "none", "deleted")]


def where_else(sweep, w=WORDS):
    """From "Where else?": how many of the alert's own things show up in another run, counting only the things
    this recorder can see ("can't tell here" ones are said apart)."""
    if not sweep or not sweep.get("rows"):
        return None
    rows = [r for r in sweep["rows"] if not r.get("common")]
    seeable = [r for r in rows if r.get("verdict") != "cant_tell"]
    cant = len(rows) - len(seeable)
    away = [r for r in seeable if r.get("other_runs")]
    if not seeable:
        return None
    if away:
        text, status = w["where_some"].format(k=len(away), n=len(seeable)), "fact"
    else:
        text, status = w["where_none"].format(n=len(seeable)), "none"
    if cant:
        text += w["where_cant"].format(c=cant)
    return [_part(text + ".", status, "sweep")]


def summary(questions, content, names, scope_nodes, extra=None, w=WORDS):
    """The paragraph: a list of sentences, each a list of parts {text, status, source}. Pure over its inputs."""
    extra = extra or {}
    qs = {q["key"]: q for q in questions}
    sentences = [what_happened(qs, content, names, scope_nodes, extra.get("harness", ()), extra.get("launcher", ()),
                               extra.get("folders", ()), w),
                 how_sure(qs, content, extra.get("edge", 0), w),
                 *suspected(qs, content, extra.get("fingerprints"), w, machinery=extra.get("machinery", ()),
                            harness=extra.get("harness", ())),
                 not_in_story(qs, w),
                 where_else(extra.get("sweep"), w)]
    return [s for s in sentences if s]


def gather(ctx, a, content, cfg, programs, folders, harness, launcher):
    """The optional extras the paragraph uses, each from its own lab and each allowed to fail alone."""
    extra = {"harness": set(harness or ()), "launcher": set(launcher or ()), "folders": set(folders or ())}
    try:                                                        # the recording's edge and the fingerprint matches
        from . import prove
        lines = prove.lines_of(content, cfg)
        extra["edge"] = sum(1 for l in lines if l.get("edge"))
        with ctx.reading() as con:
            prove.corroborate(con, a.host, lines)
        extra["fingerprints"] = {l.get("id"): l["fingerprint"] for l in lines if l.get("fingerprint")}
    except Exception:
        pass
    try:                                                        # the test machinery among the suspected links
        from . import _shared_defs as sd
        from ._explain_common import process_machinery
        ends = {h.get(e) for h in content.get("hypotheses", []) for e in ("u", "v") if h.get(e)}
        mach = set()
        with ctx.reading() as con:
            for n in ends:
                n = str(n)
                if n.startswith("proc:") and process_machinery(con, a.host, n):
                    mach.add(n)
                elif n.startswith("net:"):
                    ip, _, port = n.split(":", 2)[-1].rpartition(":")
                    if sd.harness_reason({"DestinationIp": ip, "DestinationPort": port}):
                        mach.add(n)
        extra["machinery"] = mach
    except Exception:
        pass
    try:                                                        # night-hunt's "Where else?"
        from . import sweep
        extra["sweep"] = sweep.alert_sweep(a.alert_id)
    except Exception:
        pass
    names = {}
    for p in programs or []:
        if p.get("guid") and p.get("image"):
            names[f"proc:{a.host}:{p['guid']}"] = _base(p["image"])
    # graph nodes spell the GUID as recorded; match case-insensitively
    for f in content.get("facts", []):
        for e in ("u", "v"):
            n = str(f.get(e) or "")
            if n.startswith("proc:") and n not in names:
                hit = next((v for k, v in names.items() if k.upper() == n.upper()), None)
                if hit:
                    names[n] = hit
    return names, extra
