"""Analyst Lab's own READING of its own rules in ATT&CK terms (night 2026-11-24, night-explain).

Sigma rules carry ATT&CK tags written by their authors. Our own Python rules (engine/own_rules.py) and the
check-in rhythm rule (engine/beacon.py) carry none, so on our own demo data the ATT&CK map and "What to do
next" had nothing to show. This table says which ATT&CK technique each of those rules looks for, with the
one-line reason, and every page that uses it says it is Analyst Lab's reading, never the rule's own tag.
The detectors are not changed (they stay frozen); this is a label next to them.

Only rules whose behaviour IS one technique are mapped; a rule that could be several things (file_churn:
cleanup or encryption; new_listener: many reasons to listen) stays unmapped and says so. A test checks every
id exists in the downloaded ATT&CK release and that every mapped rule exists.
"""

READING = {
    "analystlab.fetch_write_run": [("T1105", "it looks for a program that connects out, writes a program file, and that "
                                             "file is then started: a tool brought in from outside")],
    "analystlab.drop_run_delete": [("T1105", "a program file is written and started"),
                                   ("T1070.004", "and its file is deleted again afterwards")],
    "analystlab.create_send_wipe": [("T1070.004", "a program deletes files it created itself")],
    "analystlab.lookalike_name": [("T1036", "a program's name is a small typo away from a Windows program's name")],
    "analystlab.embedded_system_name": [("T1036", "a program's name hides a Windows program's name")],
    "analystlab.new_shell_parent": [("T1059", "a program started a command shell it never started here before")],
    "beacon": [("T1071", "a program contacts the same address at a steady rhythm (the usual ATT&CK mapping for "
                         "regular check-ins)")],
}
UNMAPPED = {"analystlab.file_churn": "could be cleanup or encryption: no single technique",
            "analystlab.new_listener": "a program may listen for many reasons: no single technique"}

WORDS = {
    "reading": "Analyst Lab's reading of its own rule (our rules carry no ATT&CK tag)",
    "reading_short": "our reading",
}


def reading_for(rule_id):
    """[(technique id, reason)] for one of our own rules, [] for any other rule."""
    return list(READING.get(rule_id, []))


def techniques_for_alert(attack, rule_id, tags, unknown=None):
    """(technique ids, source, reasons): from the rule's own ATT&CK tags ("tags") when it has any, else from
    Analyst Lab's reading of its own rule ("reading"), else ([], None, {})."""
    from ._attack import rule_techniques
    techs = rule_techniques(attack, tags or [], unknown)
    if techs:
        return techs, "tags", {}
    out, reasons = [], {}
    for tid, why in reading_for(rule_id):
        cur, _ = attack.resolve(tid)
        if cur and cur not in out:
            out.append(cur)
            reasons[cur] = why
    return (out, "reading", reasons) if out else ([], None, {})
