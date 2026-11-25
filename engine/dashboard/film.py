"""Which rows the Story screen's FILM tells (2026-11-20, PROOF's decision after the first real live run).

A live story can be long: 44 rows on 2026-11-20, most of them the test machine's own housekeeping
around a 4-step alert. The film then tells the alert's own chain. The REPORT under the film always
keeps every row, and the screen says so in a line that is never hidden.

The rule uses the story's own data only (ids, kinds, grades, the chain mark): never a program's name.
  - A story of up to FILM_WHOLE_ROWS rows is filmed whole (the recorded S1 stays as it is).
  - A longer one films:
      1. the alert's numbered steps: the facts report.build() marked `in_chain`;
      2. the programs next to them: the one that started a step's program, and the ones a step's
         program started (a recorded "started" fact). Not the brothers and sisters of a step's program:
         when the only thing a program does in the steps is start another one, its other children are
         left to the report (the sweep of 2026-11-21: a launcher that starts dozens of programs put
         eleven unrelated starts into a one-step film);
      3. every row (proven, suspected, can't be known) whose ends ALL lie among those things.
  - A long story with no numbered step (seen 2026-11-21: the "shell started by an unknown parent" alert,
    44 to 116 rows) starts instead from what the alert's own records are about: the things of the rows
    that cite one of the alert's own evidence records. Then 2 and 3 as above.
  - A long story with neither is filmed whole: there is nothing to choose by.
Nothing is renamed, merged or reordered: the film's rows are rows of report.build()'s timeline, in
its order. The film's map is the report's own layout cut down to the film's things, rails renumbered
top to bottom in the same order.
"""

FILM_WHOLE_ROWS = 20        # up to this many rows the film tells the whole story (the page's normal pace ends here too)

WORDS = {
    "note": "The film shows the {n} steps behind this alert and what links them. "
            "All {rows} recorded rows are in the report below.",
    "note_one": "The film shows the step behind this alert and what is linked to it. "
                "All {rows} recorded rows are in the report below.",
    "note_none": "The film shows what this alert is about and what is linked to it. "
                 "All {rows} recorded rows are in the report below.",
    # a story with no rows at all: the alert's records are not in the recording that is open (the sweep of
    # 2026-11-21 paired one run's alerts with another run's events: the screen showed an empty film and "0 proven")
    "empty": "There is no story to tell: none of this alert's records could be found in the recording that is open. "
             "The report below says what is known.",
    # "all N rows" must not read as "everything that happened": most big stories stop at the view's node limit
    "bounded": " The story itself stops at the view's size limit.",
    "film": "in the film",
    "story": "in the whole story",
}
INKS = ("fact", "hypothesis", "gap")


def _tally(rows):
    out = {ink: 0 for ink in INKS}
    for r in rows:
        if r.get("ink") in out:
            out[r["ink"]] += 1
    return out


def _about(content, edges, gap_node):
    """The things the alert's own records are about, for an alert with no numbered step: the ends of every
    row (proven, suspected or can't be known) that cites one of the alert's own evidence records."""
    own = {c.get("key") for c in (content.get("alert") or {}).get("citations") or []} - {None}
    if not own:
        return set()
    things = set()
    for kind in ("facts", "hypotheses", "gaps"):
        for x in content.get(kind) or []:
            if own & {c.get("key") for c in x.get("citations") or []}:
                e = edges.get(x["id"])
                things.update((e["u"], e["v"]) if e is not None else [gap_node.get(x["id"])])
    return things - {None}


def film_ids(content):
    """The ids of the timeline rows the film tells, in the timeline's order, and whether that is all of them."""
    timeline = content.get("timeline") or []
    everything = [r["id"] for r in timeline]
    if len(timeline) <= FILM_WHOLE_ROWS:
        return everything, True
    edges = {e["id"]: e for e in (content.get("layout") or {}).get("edges", [])}
    gap_node = {g["id"]: g.get("node_id") for g in content.get("gaps") or []}
    chain = {n for e in edges.values() if e.get("in_chain") for n in (e["u"], e["v"])}
    if not chain:
        chain = _about(content, edges, gap_node)
    if not chain:
        return everything, True
    # a program whose only part in the steps is to START another one: its other children are not the alert's
    acts = {e["u"] for e in edges.values() if e.get("in_chain") and e.get("kind") != "started"}
    acts |= {e["v"] for e in edges.values() if e.get("in_chain")}
    acts |= chain if not any(e.get("in_chain") for e in edges.values()) else set()     # no steps: what the alert is about
    near = set(chain)
    for e in edges.values():
        if e.get("kind") == "started" and e.get("grade") == "fact" and (e["v"] in chain or e["u"] in acts):
            near.update((e["u"], e["v"]))
    ids = []
    for r in timeline:
        e = edges.get(r["id"])
        if e is not None:
            if e["u"] in near and e["v"] in near:
                ids.append(r["id"])
        elif gap_node.get(r["id"]) in near:
            ids.append(r["id"])
    return ids, len(ids) == len(everything)


def film_layout(content, ids):
    """report.build()'s layout cut down to the film's rows: only their things, the rails that still hold
    a thing renumbered from the top in the same order. Every other key (t0, offset_from, ...) is kept."""
    layout = content.get("layout") or {}
    keep = set(ids)
    edges = [e for e in layout.get("edges", []) if e["id"] in keep]
    used = {n for e in edges for n in (e["u"], e["v"])}
    used.update(g.get("node_id") for g in content.get("gaps") or [] if g["id"] in keep)
    nodes = [n for n in layout.get("nodes", []) if n["id"] in used]
    lanes_used = sorted({n["lane"] for n in nodes})
    new = {old: i for i, old in enumerate(lanes_used)}
    lanes = [dict(l, lane=new[l["lane"]]) for l in layout.get("lanes", []) if l["lane"] in new]
    return dict(layout, lanes=lanes, nodes=[dict(n, lane=new[n["lane"]]) for n in nodes],
                edges=[dict(e, lane=new.get(e.get("lane"), e.get("lane"))) for e in edges])


def film_of(content):
    """What the Story screen needs to film this story: {whole, ids, rows, total, note, counts, story_counts,
    labels, layout}. `counts` = the film's rows by ink, `story_counts` = the whole timeline's: two sets,
    each named by `labels`, never mixed. `note` is the line the page keeps visible under the film: None
    when the film is the whole story, the cut's sentence when it is not, and a plain "no story" sentence
    when the story has no rows at all."""
    timeline = content.get("timeline") or []
    ids, whole = film_ids(content)
    keep = set(ids)
    steps = (content.get("counts") or {}).get("steps") or 0
    note = None
    if not timeline:
        note = WORDS["empty"]
    elif not whole:
        note = (WORDS["note_none"] if steps == 0 else WORDS["note_one"] if steps == 1 else WORDS["note"]).format(n=steps, rows=len(timeline))
        if (content.get("graph") or {}).get("truncated"):
            note += WORDS["bounded"]
    return {"whole": whole, "ids": ids, "rows": len(ids), "total": len(timeline), "note": note,
            "counts": _tally(r for r in timeline if r["id"] in keep), "story_counts": _tally(timeline),
            "labels": {"film": WORDS["film"], "story": WORDS["story"]},
            "layout": content.get("layout") if whole else film_layout(content, ids)}
