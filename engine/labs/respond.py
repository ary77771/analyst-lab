"""Lab "What to do next" (night 2026-11-23, night-explain): for one alert, the response steps MITRE
publishes for the techniques its rule names: ATT&CK's mitigations (with MITRE's own sentence on how each
applies to that technique) and D3FEND's defensive techniques (grouped by D3FEND tactic, each with the
artifact link that ties it to the technique).

    GET /api/labs/respond/{alert_id}

No invented advice: every step is MITRE's text with its id, release and link. An alert whose rule names no
ATT&CK technique gets no steps, and the page says why instead of guessing.
Data: downloads/night/attack/ (python -m engine.labs._fetch_attack) and downloads/night/d3fend/
(python -m engine.labs._fetch_d3fend).

Switch off: delete this file (and dashboard/src/labs/respond/).
"""

from fastapi import APIRouter, HTTPException

from engine import labs

from . import _attack, _d3fend, _rule_tags
from ._attack import rule_techniques  # noqa: F401  (kept for callers)
from ._own_tags import WORDS as OWN_WORDS, techniques_for_alert
from ._explain_common import PICK_WORDS, alert_row as _alert_row, picker

router = APIRouter(prefix="/api/labs/respond")

WORDS = {
    "title": "What to do next",
    "intro": "What MITRE publishes as response steps for this kind of attack, in MITRE's own words, each with its "
             "source. Only the short note after each D3FEND tactic and the order are Analyst Lab's reading.",
    **PICK_WORDS,
    "technique": "Technique named by the rule",
    "technique_reading": "Technique, by " + OWN_WORDS["reading"],
    "mitigations": "ATT&CK mitigations",
    "mitigations_note": "MITRE's mitigations for this technique, in MITRE's words.",
    "how_title": "how MITRE says it applies here",
    "technique_more": "MITRE's full description",
    "links_title": "how D3FEND links it to this technique",
    "no_mitigations": "MITRE lists no mitigation for this technique (often: it cannot be easily prevented with preventive "
                      "controls).",
    "d3fend": "D3FEND defensive techniques",
    "d3fend_note": "D3FEND links a defence to a technique through something both touch (a file, a process, a "
                   "credential...). Grouped by D3FEND's own tactics; the note after each tactic is Analyst Lab's reading.",
    "d3fend_via": "No D3FEND mapping for {asked}; shown for its parent technique {via}.",
    "no_d3fend": "D3FEND has no mapping for this technique.",
    "link_words": "{defence} {defence_rel} {artifact}; the technique {attack_rel} {attack_artifact}",
    "more_links": "+{n} more links",
    "tactics": {
        "Evict": "remove what the intruder put in place",
        "Isolate": "cut off what the intruder can reach",
        "Restore": "bring systems back to a good state",
        "Detect": "find more of the same activity",
        "Harden": "make it harder to do again",
        "Deceive": "lead an intruder into watched decoys",
        "Model": "know what you have, so the rest can work",
    },
    "no_tags": "This alert's rule names no ATT&CK technique (Analyst Lab's own Python rules and the check-in rhythm "
               "rule have no tags), so there is no published step to show. The Why page explains what it saw.",
    "no_attack": "The ATT&CK data is not on this laptop: python -m engine.labs._fetch_attack.",
    "no_d3fend_data": "The D3FEND data is not on this laptop: python -m engine.labs._fetch_d3fend.",
    "source_attack": "ATT&CK Enterprise {version}",
    "source_d3fend": "D3FEND {version}",
    "open_mitre": "MITRE's page",
    "open_d3fend": "D3FEND's page",
    "open_why": "Why is this suspicious?",
    "attack_hint": "ATT&CK: MITRE's public catalogue of the ways intruders work, each with an id like T1036.",
    "d3fend_hint": "D3FEND: MITRE's list of defences, each linked to the intruder techniques it counters.",
    "legal": f"{_attack.LEGAL} {_d3fend.LEGAL}",
}


def steps(alert, attack, d3fend, rules_by_id):
    """The response steps for one alert (pure: tests call it with fixtures)."""
    rule = rules_by_id.get(alert.rule_id) or {}
    techs, source, reasons = techniques_for_alert(attack, alert.rule_id, rule.get("tags", [])) if attack else ([], None, {})
    out = []
    for tid in techs:
        t = attack.techniques[tid]
        mits = []
        for m in attack.mitigates.get(tid, []):
            info = attack.mitigations.get(m["mitigation"])
            if info:
                mits.append({"id": info["id"], "name": info["name"], "url": info["url"], "how": _attack.plain(m["how"]),
                             "description": _attack.plain(info["description"], first_paragraph=True)})
        mits.sort(key=lambda x: x["id"])
        out.append({"id": tid, "name": attack.full_name(tid), "url": t["url"],
                    "description": _attack.plain(t["description"], first_paragraph=True),
                    "mitigations": mits, "d3fend": d3fend.for_technique(tid) if d3fend else None,
                    "source": source, "reason": reasons.get(tid)})
    return out


@router.get("")
def pick():
    return picker(labs.context())


@router.get("/{alert_id}")
def next_steps(alert_id: str):
    ctx = labs.context()
    a = ctx.alert(alert_id)
    if a is None:
        raise HTTPException(status_code=404, detail="This alert isn't in this recording.")
    attack, d3fend = _attack.load(), _d3fend.load()
    rules = _rule_tags.index()
    return {"words": WORDS, "alert": _alert_row(a),
            "attack": {"available": attack is not None, "version": attack.version if attack else None},
            "d3fend": {"available": d3fend is not None, "version": d3fend.version if d3fend else None},
            "techniques": steps(a, attack, d3fend, rules) if attack else [],
            "rule_tags": (rules.get(a.rule_id) or {}).get("tags", [])}
