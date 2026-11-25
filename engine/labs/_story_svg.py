"""The attack story as ONE picture, for the case report's first page (night-pivot, 2026-11-24; PROOF's item).

Plain SVG drawn here, no library. Left to right: programs as boxes, files as notes (a folded corner), addresses
and names as rounded clouds. Every arrow is one link of the alert's own report (engine/report.py, the same
content the Story screen and the report use), drawn in its ink:
  solid green   a recorded fact (Proven)
  dashed amber  a suspected link (graded by the evidence graph)
  dotted grey   what the records cannot show (a gap): from a "?" into the thing it is about
What is drawn: the alert's chain of facts, the suspected links that touch it, the gaps on its things, and, greyed
out, the program that started the chain (labelled as the lab's test launcher when it is our own machinery).
Nothing else of the (much larger) story, so it stays one readable picture that fits an A4 page.
"""

from html import escape

W, H_BOX, GAP_X, GAP_Y, PAD = 168, 48, 72, 38, 16
INK = {"fact": ("#1b8a5a", None), "hypothesis": ("#a86e00", "7 5"), "gap": ("#8a8f98", "2 4")}
GAP_WORDS = {"origin_unknown": "start not recorded", "parent_unknown": "parent not recorded",
             "content_unknown": "no fingerprint", "actor_unknown": "no acting program", "owner_unknown": "no owner"}
ARC = 46                                                   # room above the boxes for links that skip a column
VERB = {"started": "started", "created": "created", "connected_to": "connected to", "accepted_from": "accepted from",
        "content_from": "content from?", "copy_of": "copy of?", "ran_as": "ran as", "deleted": "deleted",
        "looked_up": "looked up", "set_autostart": "set autostart", "fetched_then_ran": "then started?",
        "remote_command": "made it start?", "started_with_file_argument": "started with"}


def _kind(H, n):
    return (H.nodes[n].get("kind") if n in H else None) or n.split(":", 1)[0]


def _name(H, n):
    from engine.report import label
    import re
    return re.sub(r" \(PID \d+\)", "", label(H, n)) if n in H else n.rsplit(":", 1)[-1]


def _pid(H, n):
    return H.nodes[n].get("pid") if n in H and _kind(H, n) == "process" else None


def _is_harness(ctx, H, n):
    try:
        from .claim import node_is_harness
        return n in H and node_is_harness(ctx, H, n)
    except Exception:
        return False


def picture_edges(content, H, ctx=None):
    """[{u, v, kind, grade, context}] the picture draws, all taken from the alert's report `content` (and the story
    H only for the chain's starter): chain facts, suspected links touching the chain, gaps on chain things."""
    facts = [f for f in content.get("facts") or [] if f.get("u") and f.get("v")]
    chain = [f for f in facts if f.get("in_chain")] or facts[:6]
    nodes = {f["u"] for f in chain} | {f["v"] for f in chain}
    out = [{"u": f["u"], "v": f["v"], "kind": f.get("kind"), "grade": "fact", "context": False} for f in chain]
    for h in content.get("hypotheses") or []:
        if h.get("u") and h.get("v") and (h["u"] in nodes or h["v"] in nodes):
            out.append({"u": h["u"], "v": h["v"], "kind": h.get("kind"), "grade": "hypothesis", "context": False})
            nodes |= {h["u"], h["v"]}
    # the program that started the chain, greyed out (what came just before the alert's own story)
    for f in facts:
        if f.get("kind") == "started" and f["v"] in nodes and f["u"] not in nodes and not f.get("in_chain"):
            out.insert(0, {"u": f["u"], "v": f["v"], "kind": "started", "grade": "fact", "context": True})
            nodes.add(f["u"])
            break
    # machinery inside the chain (not the greyed starter) stays out
    machinery = {n for n in nodes if _is_harness(ctx, H, n)}
    out = [e for e in out if e["context"] or not (e["u"] in machinery or e["v"] in machinery)]
    drawn = {e["u"] for e in out} | {e["v"] for e in out}
    for g in content.get("gaps") or []:
        n = g.get("node_id")
        if n in drawn:
            out.append({"u": f"?:{n}", "v": n, "kind": "gap", "grade": "gap", "context": False,
                        "gap": g.get("kind"), "what": GAP_WORDS.get(g.get("kind"), g.get("what") or "unknown")})
    return out


def _columns(edges):
    """Longest-path depth over the RECORDED links (left to right in the story's own order); a suspected link never
    pushes a thing to the right (it is drawn between columns or bent around); gaps sit just left."""
    real = [e for e in edges if e["grade"] == "fact"]
    for e in edges:                                        # things reached only by a suspected link: one step right
        if e["grade"] == "hypothesis" and not any(e["v"] in (f["u"], f["v"]) for f in real):
            real.append({**e, "grade": "fact"})
    nodes = {e["u"] for e in real} | {e["v"] for e in real}
    nodes |= {e["u"] for e in edges if e["grade"] == "hypothesis"} | {e["v"] for e in edges if e["grade"] == "hypothesis"}
    depth = {n: 0 for n in nodes}
    for _ in range(len(nodes) + 1):
        changed = False
        for e in real:
            if depth.get(e["v"], 0) < depth.get(e["u"], 0) + 1 and depth.get(e["u"], 0) + 1 <= len(nodes):
                depth[e["v"]] = depth[e["u"]] + 1
                changed = True
        if not changed:
            break
    for e in edges:
        if e["grade"] == "gap":
            depth[e["u"]] = depth.get(e["v"], 0) - 1
    low = min(depth.values()) if depth else 0
    return {n: d - low for n, d in depth.items()}


def _box(kind, x, y, w, h, dim, harness):
    fill, stroke = ("#f4f5f7", "#b9bec6") if dim else ("#ffffff", "#3a4250")
    if kind == "file":
        c = 12
        return (f"<path d='M{x},{y} H{x + w - c} L{x + w},{y + c} V{y + h} H{x} Z' fill='{fill}' stroke='{stroke}' stroke-width='1.4'/>"
                f"<path d='M{x + w - c},{y} V{y + c} H{x + w}' fill='none' stroke='{stroke}' stroke-width='1.2'/>")
    if kind in ("endpoint", "dns"):
        return f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='{h / 2}' fill='{fill}' stroke='{stroke}' stroke-width='1.4'/>"
    if kind == "unknown":
        return f"<circle cx='{x + w / 2}' cy='{y + h / 2}' r='{h / 2 - 6}' fill='#ffffff' stroke='#8a8f98' stroke-width='1.4' stroke-dasharray='2 4'/>"
    dash = " stroke-dasharray='4 3'" if harness else ""
    return f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='6' fill='{fill}' stroke='{stroke}' stroke-width='1.6'{dash}/>"


def _cut(s, n=22):
    return s if len(s) <= n else s[: n - 1] + "…"


def story_picture(content, H, ctx=None):
    """{svg, edges, nodes}: the picture and exactly what it draws (tests check every arrow against the report)."""
    edges = picture_edges(content, H, ctx)
    if not [e for e in edges if e["grade"] != "gap"]:
        return {"svg": "", "edges": [], "nodes": []}
    col = _columns(edges)
    context = {e["u"] for e in edges if e["context"]}
    first = {}
    for i, e in enumerate(edges):
        for n in (e["u"], e["v"]):
            first.setdefault(n, i)
    rows = {}
    pos = {}
    arcs = any(e["grade"] != "gap" and abs(col[e["v"]] - col[e["u"]]) > 1 for e in edges)
    top = PAD + 18 + (ARC if arcs else 0)
    for n in sorted(col, key=lambda n: (col[n], first.get(n, 0))):
        r = rows.get(col[n], 0)
        rows[col[n]] = r + 1
        pos[n] = (PAD + col[n] * (W + GAP_X), top + r * (H_BOX + GAP_Y))
    width = PAD * 2 + (max(col.values()) + 1) * W + max(col.values()) * GAP_X
    height = top + PAD + max(rows.values()) * (H_BOX + GAP_Y) - GAP_Y + 10
    parts = [f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {width} {height}' class='story' role='img' "
             f"aria-label='The alert&#39;s story as a picture' font-family='Inter, system-ui, Segoe UI, sans-serif'>",
             "<defs>" + "".join(
                 f"<marker id='ah-{g}' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='7' markerHeight='7' orient='auto-start-reverse'>"
                 f"<path d='M0,0 L10,5 L0,10 z' fill='{c}'/></marker>" for g, (c, _) in INK.items()) + "</defs>"]
    nodes_out = []
    for n, (x, y) in pos.items():
        kind = "unknown" if n.startswith("?:") else _kind(H, n)
        dim = n in context
        harness = dim and _is_harness(ctx, H, n)
        parts.append(_box(kind, x, y, W, H_BOX, dim, harness))
        if kind == "unknown":
            text, sub = "?", ""            # (the circle is drawn by _box at the cell's centre)
            parts.append(f"<text x='{x + W / 2}' y='{y + H_BOX / 2 + 6}' text-anchor='middle' font-size='18' fill='#8a8f98'>?</text>")
        else:
            text = _name(H, n)
            pid = _pid(H, n)
            sub = ("the lab's test launcher" if harness else
                   ("started it" if dim else ({"process": f"program{f' · PID {pid}' if pid else ''}", "file": "file",
                                                 "endpoint": "address", "dns": "name"}.get(kind, kind))))
            ink = "#9aa0a8" if dim else "#16181d"
            parts.append(f"<text x='{x + 10}' y='{y + 21}' font-size='13' font-weight='600' fill='{ink}'>{escape(_cut(text))}</text>")
            parts.append(f"<text x='{x + 10}' y='{y + 38}' font-size='10.5' fill='#6b7280'>{escape(sub)}</text>")
        nodes_out.append({"id": n, "kind": kind, "name": text, "context": dim, "column": col[n]})
    edges_out = []
    for e in edges:
        (x1, y1), (x2, y2) = pos[e["u"]], pos[e["v"]]
        colour, dash = INK[e["grade"]]
        if e["context"]:
            colour = "#b9bec6"
        sx, sy, tx, ty = x1 + W, y1 + H_BOX / 2, x2, y2 + H_BOX / 2
        mx = (sx + tx) / 2
        anchor = "middle"
        if e["grade"] == "gap":                            # from the "?" into the thing; its words under the "?"
            sx = x1 + W / 2 + H_BOX / 2 - 6
            d = f"M{sx},{sy} L{tx - 2},{ty}"
            lx, ly = x1 + W / 2, y1 + H_BOX + 14
        elif x2 == x1:                                     # same column: a short straight arrow down (or up)
            sx = tx = x1 + W * 0.82
            sy, ty = (y1 + H_BOX, y2 - 2) if y2 > y1 else (y1, y2 + H_BOX + 2)
            d = f"M{sx},{sy} L{tx},{ty}"
            lx, ly, anchor = sx - 8, (sy + ty) / 2 + 4, "end"
        elif x2 - x1 > W + GAP_X:                          # skips a column: arc over the boxes
            sx, sy, tx, ty = x1 + W * 0.7, y1, x2 + W * 0.3, y2
            lift = top - ARC + 6
            d = f"M{sx},{sy} C{sx},{lift} {tx},{lift} {tx},{ty - 2}"
            lx, ly = (sx + tx) / 2, lift + 14
        else:
            d = f"M{sx},{sy} C{mx},{sy} {mx},{ty} {tx - 2},{ty}"
            lx, ly = mx, (sy + ty) / 2 - 6
        style = "solid" if dash is None else ("dashed" if e["grade"] == "hypothesis" else "dotted")
        attrs = f" stroke-dasharray='{dash}'" if dash else ""
        parts.append(f"<path d='{d}' fill='none' stroke='{colour}' stroke-width='2.2'{attrs} marker-end='url(#ah-{e['grade']})' "
                     f"data-grade='{e['grade']}' data-style='{style}'/>")
        word = e.get("what") if e["grade"] == "gap" else VERB.get(e["kind"], str(e["kind"]).replace("_", " "))
        tw = 6.2 * len(word) + 10
        rx0 = lx - tw / 2 if anchor == "middle" else (lx - tw + 5 if anchor == "end" else lx - 5)
        parts.append(f"<rect x='{rx0}' y='{ly - 12}' width='{tw}' height='16' rx='3' fill='#ffffff' opacity='0.92'/>"
                     f"<text x='{lx}' y='{ly}' text-anchor='{anchor}' font-size='11' fill='{colour}'>{escape(word)}</text>")
        edges_out.append({**e, "style": style})
    parts.append("</svg>")
    return {"svg": "".join(parts), "edges": edges_out, "nodes": nodes_out}


def for_alert(ctx, alert_id):
    """The picture of one pinned alert's story (its report content and story from the dashboard), or None."""
    try:
        a = ctx.alert(alert_id)
        if a is None:
            return None
        content = ctx.report(a)
        _, _, H = ctx.story(a)
    except Exception:
        return None
    pic = story_picture(content, H, ctx)
    return pic if pic["svg"] else None
