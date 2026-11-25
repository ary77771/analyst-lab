"""Lab "ATT&CK map" (night 2026-11-23, night-explain): the MITRE ATT&CK Enterprise matrix (tactics as
columns), lighting up the techniques our alerts hit, and what our loaded rules can see at all.

    GET /api/labs/techniques                the matrix: per technique, alerts hitting it and rules that name it
    GET /api/labs/techniques/{T1234[.001]}  one technique: MITRE's own description, its alerts, its rules

Which technique an alert "hits" comes ONLY from its rule's tags (`attack.t1059.001`, written by the rule's
author): this page does not decide it. Alerts whose rule has no technique tag (our Python rules, the
check-in rhythm rule, some community rules) are counted and listed as such, never placed on the map.
Coverage = every technique a rule for the events we record names in its tags (engine/labs/_rule_tags.py):
a tag says what the author meant the rule to see, not that it would catch every way of doing it.
ATT&CK data: downloads/night/attack/ (python -m engine.labs._fetch_attack); without it the page says so.

Switch off: delete this file (and dashboard/src/labs/techniques/).
"""

from collections import Counter, defaultdict

from fastapi import APIRouter, HTTPException

from engine import labs
from engine.alerts import LEVELS

from . import _attack, _rule_tags
from ._attack import rule_techniques
from ._own_tags import WORDS as OWN_WORDS, techniques_for_alert

router = APIRouter(prefix="/api/labs/techniques")

WORDS = {
    "title": "ATT&CK map",
    "intro": "MITRE ATT&CK, a public catalogue of the techniques intruders use, as a matrix: one column per goal "
             "(tactic), one box per technique. A box lights up when an alert points to that technique: its rule's own tags, "
             "or, for Analyst Lab's own rules, our reading of what the rule looks for.",
    "mode_alerts": "Alerts on this store",
    "mode_coverage": "What our rules can see",
    "mode_alerts_hint": "Lit: at least one alert shown on the screens comes from a rule tagged with this technique or one "
                        "of its sub-techniques, or from one of our own rules read as this technique (said as ours). The "
                        "number is how many alerts.",
    "mode_coverage_hint": "Lit: at least one rule for the events we record names this technique. The number is how many "
                          "rules. A tag says what the rule's author meant it to see, not that every way of doing it is seen.",
    "only_lit": "Only lit boxes",
    "all_levels": "Count every alert level (also below {min_level})",
    "all_levels_hint": "Now counting every alert in the database, also the lower levels the screens leave out "
                       "(they stay in the store for investigation; they don't raise an alert on the screens).",
    "empty_hint": "None of the alerts counted here comes from a rule that names a technique. Lower-level alerts often "
                  "do: try counting every alert level.",
    "floor_only": "Only rules that raise an alert (level {min_level} and up)",
    "alerts_tagged": "alerts placed on the map",
    "alerts_untagged": "alerts whose rule names no technique (not placed)",
    "alerts_reading": "of them placed by Analyst Lab's reading of its own rule",
    # the calm first screen (2026-11-24): a coverage check, not an alarm
    "calm_title": "What the alerts here point to",
    "calm_intro": "ATT&CK is MITRE's public catalogue of the techniques intruders use. This map checks which of them "
                  "the alerts here point to: a coverage check, not an alarm.",
    "calm_none": "No alert here points to a technique of the catalogue.",
    "calm_one": "1 alert",
    "calm_many": "{n} alerts",
    "calm_reading": "Placed by Analyst Lab's reading of its own rule: our rules carry no ATT&CK label of their own, so "
                    "this one is ours, not the rule's.",
    "show_matrix": "Show the full matrix and its settings",
    "reading_note": OWN_WORDS["reading"] + ": our own rules are placed by the technique each one looks for, said as ours.",
    "techniques_hit": "techniques hit",
    "techniques_covered": "techniques our rules name",
    "rules_ours": "rules for the events we record",
    "untagged_title": "Alerts not on the map",
    "untagged_note": "Their rules name no ATT&CK technique, and Analyst Lab's reading of its own rules gives them none "
                     "either (a rule that could mean several things is left unmapped): this page never guesses one.",
    "unknown_tags_title": "Tags this ATT&CK release does not know",
    "detail_alerts": "Alerts that point to this technique (by the rule's own tag, or by Analyst Lab's reading of its own rule)",
    "detail_rules": "Rules that name this technique",
    "detail_none": "No alert counted here points to this technique.",
    "detail_rules_more": "{shown} of {total} rules shown.",
    "subs": "sub-techniques",
    "open_mitre": "MITRE's page",
    "open_why": "Why?",
    "open_next": "What to do next",
    "no_data": "The ATT&CK data is not on this laptop yet: run python -m engine.labs._fetch_attack (it downloads "
               "MITRE's public file, about 55 MB, into downloads/night/attack/).",
    "legal": _attack.LEGAL,
    "version": "ATT&CK Enterprise {version}",
    "attack_hint": "ATT&CK: MITRE's public catalogue of the ways intruders work, each with an id like T1036.",
    "revoked_note": "A rule tag named {old}, which MITRE has replaced with {new}: counted under {new}.",
}


def _floor(ctx):
    return LEVELS.index(ctx.min_level())


def matrix(attack, alerts, rules, floor_index):
    """The matrix data (pure: tests call it with fixtures). alerts = Alert objects (already the shown ones);
    rules = _rule_tags.index() values; floor_index = LEVELS index of the alert floor."""
    unknown = {}
    rule_tech = {r["id"]: rule_techniques(attack, r["tags"], unknown) for r in rules}
    by_rule = {r["id"]: r for r in rules}
    hit = defaultdict(set)                         # technique -> alert ids (exact technique)
    untagged = Counter()
    by_reading = set()
    untagged_info = {}
    for a in alerts:
        techs = rule_tech.get(a.rule_id) or rule_techniques(attack, (by_rule.get(a.rule_id) or {}).get("tags", []), unknown)
        if not techs:
            techs, src, _ = techniques_for_alert(attack, a.rule_id, [])
            if techs:
                by_reading.add(a.alert_id)
        if not techs:
            untagged[a.rule_id] += 1
            untagged_info[a.rule_id] = {"rule_id": a.rule_id, "title": a.title, "source": a.source}
            continue
        for t in techs:
            hit[t].add(a.alert_id)
    cov_all, cov_floor = defaultdict(set), defaultdict(set)
    ours = [r for r in rules if r["ours"]]
    for r in ours:
        for t in rule_tech.get(r["id"], []):
            cov_all[t].add(r["id"])
            if LEVELS.index(r["level"]) >= floor_index if r["level"] in LEVELS else False:
                cov_floor[t].add(r["id"])

    def cell(tid):
        subs = sorted(s for s in attack.techniques if attack.techniques[s]["parent"] == tid)
        fam = [tid] + subs
        return {"id": tid, "name": attack.techniques[tid]["name"],
                "alerts": len(set().union(*(hit[x] for x in fam))),
                "rules": len(set().union(*(cov_all[x] for x in fam))),
                "rules_floor": len(set().union(*(cov_floor[x] for x in fam))),
                "subs": [{"id": s, "name": attack.techniques[s]["name"], "alerts": len(hit[s]), "rules": len(cov_all[s]),
                          "rules_floor": len(cov_floor[s])} for s in subs]}

    parents = [t for t in attack.techniques.values() if not t["sub"]]
    tactics = []
    for tac in attack.tactics:
        cells = [cell(t["id"]) for t in sorted(parents, key=lambda t: t["name"]) if tac["shortname"] in t["tactics"]]
        tactics.append({**tac, "techniques": cells})
    families = lambda d: {attack.techniques[t]["parent"] or t for t in d if d[t]}
    tagged_alerts = set().union(*hit.values()) if hit else set()
    return {
        "tactics": tactics,
        "totals": {"alerts_shown": len(alerts), "alerts_tagged": len(tagged_alerts), "alerts_untagged": sum(untagged.values()), "alerts_reading": len(by_reading),
                   "techniques_hit": len(families(hit)), "techniques_covered": len(families(cov_all)),
                   "techniques_covered_floor": len(families(cov_floor)), "rules_ours": len(ours),
                   "rules_tagged": sum(1 for r in ours if rule_tech.get(r["id"])), "techniques_total": len(parents)},
        "untagged": [dict(untagged_info[r], alerts=n) for r, n in untagged.most_common()],
        "unknown_tags": [{"tag": t, "note": n} for t, n in sorted(unknown.items())],
    }


def detail(attack, tid, alerts, rules, floor_index, max_rules=60):
    cur, note = attack.resolve(tid)
    if cur is None:
        return None
    t = attack.techniques[cur]
    fam = {cur} | {s for s in attack.techniques if attack.techniques[s]["parent"] == cur}
    by_rule = {r["id"]: r for r in rules}
    mine = []
    for a in alerts:
        techs, src, _ = techniques_for_alert(attack, a.rule_id, (by_rule.get(a.rule_id) or {}).get("tags", []))
        if fam & set(techs):
            mine.append({"id": a.alert_id, "title": a.title, "level": a.level, "time": a.time, "rule_id": a.rule_id,
                         "techniques": [x for x in techs if x in fam]})
    covering = [r for r in rules if r["ours"] and fam & set(rule_techniques(attack, r["tags"]))]
    covering.sort(key=lambda r: (-(LEVELS.index(r["level"]) if r["level"] in LEVELS else 0), r["title"] or ""))
    tac = [attack.tactic_by_short[s] for s in t["tactics"] if s in attack.tactic_by_short]
    return {"technique": {"id": cur, "asked": tid.upper(), "note": note, "name": t["name"], "full_name": attack.full_name(cur),
                          "url": t["url"], "description": _attack.plain(t["description"]),
                          "tactics": [{"id": x["id"], "name": x["name"]} for x in tac], "platforms": t["platforms"],
                          "parent": ({"id": t["parent"], "name": attack.name(t["parent"])} if t["parent"] else None),
                          "subs": [{"id": s, "name": attack.techniques[s]["name"]} for s in sorted(fam - {cur})]},
            "alerts": sorted(mine, key=lambda x: x["time"], reverse=True),
            "rules": [{"id": r["id"], "title": r["title"], "level": r["level"], "source": r["source"],
                       "raises": (LEVELS.index(r["level"]) >= floor_index) if r["level"] in LEVELS else False}
                      for r in covering[:max_rules]],
            "rules_total": len(covering)}


def _attack_info(attack):
    return {"available": attack is not None, "version": attack.version if attack else None,
            "techniques": len(attack.techniques) if attack else 0, "legal": _attack.LEGAL}


def _alerts(ctx, levels):
    """The alerts the map counts: what the screens show (default), or every level ("all")."""
    return ctx.alerts() if levels == "all" else ctx.shown_alerts()


@router.get("")
def techniques(levels: str = "shown"):
    ctx = labs.context()
    attack = _attack.load()
    out = {"words": WORDS, "attack": _attack_info(attack), "min_level": ctx.min_level(),
           "levels": "all" if levels == "all" else "shown"}
    if attack is None:
        return out
    out.update(matrix(attack, _alerts(ctx, levels), list(_rule_tags.index().values()), _floor(ctx)))
    return out


@router.get("/{technique_id}")
def technique(technique_id: str, levels: str = "shown"):
    ctx = labs.context()
    attack = _attack.load()
    if attack is None:
        raise HTTPException(status_code=503, detail=WORDS["no_data"])
    d = detail(attack, technique_id, _alerts(ctx, levels), list(_rule_tags.index().values()), _floor(ctx))
    if d is None:
        raise HTTPException(status_code=404, detail=f"{technique_id} is not a technique in ATT&CK {attack.version}")
    return {"words": WORDS, "attack": _attack_info(attack), **d}
