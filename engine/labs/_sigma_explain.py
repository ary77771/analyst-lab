"""Explain a Sigma rule against one event: which parts of the rule held, on which field values.

Used by the "Why is this suspicious?" lab (engine/labs/why.py). Read-only: the rule file is parsed with
pySigma (the same library engine/detect.py converts it with), never edited, and nothing is re-scored.

The detection engine runs the rule as SQL (pySigma's SQLite backend). This module walks the SAME parsed
rule (pySigma's own detection items, after its modifiers were applied) and checks each item in Python, so
the page can say which selection held and which characters of a field matched. The two can disagree only
where this module cannot check a value kind (said as "not checked", never guessed): the alert itself is
the engine's verdict; this is the explanation of it.

Matching follows Sigma (and engine/detect.py's `logs` view): text compares ignore case unless the rule
says `|cased`; `*` and `?` are wildcards; `|re` is a regular expression with its own flags.
"""

import fnmatch
import functools
import glob
import ipaddress
import os
import re

from sigma.collection import SigmaCollection
from sigma.conditions import (ConditionAND, ConditionIdentifier, ConditionNOT, ConditionOR, ConditionSelector)
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.types import (SigmaBool, SigmaCasedString, SigmaCIDRExpression, SigmaCompareExpression, SigmaExists,
                         SigmaExpansion, SigmaFieldReference, SigmaNull, SigmaNumber, SigmaRegularExpression,
                         SigmaString, SpecialChars)

from engine import detect

from . import _downloads

FIELD_MAP = {k.lower(): v for k, v in detect.FIELD_MAP.items()}        # EventID -> event_id, as the engine maps
MODIFIER_WORDS = {
    "contains": "contains", "startswith": "starts with", "endswith": "ends with", "all": "all of",
    "re": "matches the pattern", "cased": "exact case", "windash": "any dash form", "cidr": "in the network",
    "base64": "base64 of", "base64offset": "base64 (any offset) of", "exists": "is present",
    "gt": "greater than", "gte": "at least", "lt": "less than", "lte": "at most", "fieldref": "equals the field",
    "wide": "UTF-16 of", "utf16le": "UTF-16 of", "utf16": "UTF-16 of", "utf16be": "UTF-16BE of", "i": "ignore case",
    "m": "multi-line", "s": "dot matches newline", "neq": "is not",
}


# -- finding a rule's file ---------------------------------------------------------------------------------
def rule_folders():
    """Where rule files are looked for: the engine's own folders (community, ours), then the nearest
    downloaded SigmaHQ copy (a worktree has no downloads/ of its own)."""
    out = []
    for p in (detect.COMMUNITY_RULES, detect.OWN_RULES, _downloads.find("sigma/rules/windows")):
        if p and os.path.isdir(p) and os.path.abspath(p) not in [os.path.abspath(x) for x in out]:
            out.append(p)
    return out


_ID_LINE = re.compile(r"^(id|name):\s*['\"]?([^'\"\s#]+)", re.M)


@functools.lru_cache(maxsize=8)
def _index(folders):
    """{rule id or 'analystlab.<name>': path} over every .yml under `folders` (read once per folder set)."""
    out = {}
    for folder in folders:
        own = os.path.abspath(folder) == os.path.abspath(detect.OWN_RULES)
        for path in sorted(glob.glob(os.path.join(folder, "**", "*.yml"), recursive=True)):
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            for kind, value in _ID_LINE.findall(text):
                key = value if kind == "id" else (f"analystlab.{value}" if own else value)
                out.setdefault(key, path)
    return out


def find_rule_file(rule_id, hint=None, folders=None):
    """The file that defines `rule_id`: first a file named like the alert's `rule_file` detail, then an
    index of every rule file. None when it is not on this laptop."""
    folders = tuple(folders or rule_folders())
    if hint:
        for folder in folders:
            for path in glob.glob(os.path.join(folder, "**", os.path.basename(hint)), recursive=True):
                if load_rule(path, rule_id) is not None:
                    return path
    return _index(folders).get(rule_id)


@functools.lru_cache(maxsize=1)
def _filters():
    """The project's Sigma filter documents (rules/filters/), as engine/detect.load_rules applies them."""
    try:
        return tuple(detect.load_filters())
    except Exception:
        return ()


def load_rule(path, rule_id, filters=None):
    """The pySigma rule with this id (or analystlab.<name>) in the file, with its correlation's base rules
    resolved and the project's filters applied exactly as the engine does (detect.load_rules); None when the
    file does not hold it."""
    try:
        with open(path, encoding="utf-8") as f:
            collection = SigmaCollection.from_yaml(f.read())
        collection.resolve_rule_references()
        flt = list(_filters() if filters is None else filters)
        if flt:
            collection.apply_filters(flt)
    except Exception:
        return None
    for r in collection.rules:
        if str(r.id) == rule_id or (r.name and f"analystlab.{r.name}" == rule_id) or r.name == rule_id:
            return r
    return None


def is_filter(name):
    """A filter selection: named filter* by the rule's author, or _filt* by pySigma for a filter document."""
    return name.lower().startswith(("filter", "_filt"))


# -- describing a rule ---------------------------------------------------------------------------------------
def _mod_names(item):
    return [m.__name__.removeprefix("Sigma").removesuffix("Modifier") for m in item.modifiers]


_MOD_KEYS = {"Contains": "contains", "Startswith": "startswith", "Endswith": "endswith", "All": "all",
             "RegularExpression": "re", "CaseSensitive": "cased", "WindowsDash": "windash", "CIDR": "cidr",
             "Base64": "base64", "Base64Offset": "base64offset", "Exists": "exists", "GreaterThan": "gt",
             "GreaterThanEqual": "gte", "LessThan": "lt", "LessThanEqual": "lte", "FieldReference": "fieldref",
             "Wide": "wide", "RegularExpressionIgnoreCaseFlag": "i", "RegularExpressionMultilineFlag": "m",
             "RegularExpressionDotAllFlag": "s", "NotEqual": "neq"}


def modifiers(item):
    return [_MOD_KEYS.get(n, n.lower()) for n in _mod_names(item)]


def show_value(v):
    """A value as the rule file writes it (wildcards as * and ?)."""
    if isinstance(v, SigmaExpansion):
        return " | ".join(show_value(x) for x in v.values)
    if isinstance(v, SigmaRegularExpression):
        return getattr(v.regexp, "original", None) or str(v.regexp)
    if isinstance(v, SigmaString):                       # includes SigmaCasedString; built from its parts
        out = []                                        # (`original` is empty after some modifiers)
        for p in v.s:
            if p is SpecialChars.WILDCARD_MULTI:
                out.append("*")
            elif p is SpecialChars.WILDCARD_SINGLE:
                out.append("?")
            elif isinstance(p, str):
                out.append(p)
            else:
                out.append("%" + str(getattr(p, "name", "placeholder")) + "%")
        return "".join(out)
    if isinstance(v, SigmaNumber):
        return str(v.number)
    if isinstance(v, SigmaNull):
        return "(empty)"
    if isinstance(v, SigmaExists):
        return "present" if v.exists else "absent"
    if isinstance(v, SigmaCIDRExpression):
        return v.cidr
    if isinstance(v, SigmaCompareExpression):
        return str(v.number.number)
    if isinstance(v, SigmaFieldReference):
        return v.field
    if isinstance(v, SigmaBool):
        return "true" if v.boolean else "false"
    return str(v)


def _items(det):
    """Flatten a selection into (path, item) leaves; nested selections (a list of maps) are 'any of'."""
    out = []
    for it in det.detection_items:
        if isinstance(it, SigmaDetection):
            out.extend(_items(it))
        else:
            out.append(it)
    return out


def shown(item, v, mods=None):
    """A value as the page shows it: without the * the contains/startswith/endswith modifier added (the
    modifier is said in words next to it)."""
    mods = modifiers(item) if mods is None else mods
    text = show_value(v)
    if isinstance(v, (SigmaString, SigmaExpansion)) and not isinstance(v, SigmaRegularExpression):
        parts = [text] if not isinstance(v, SigmaExpansion) else text.split(" | ")
        cut = []
        for t in parts:
            if ("contains" in mods or "endswith" in mods) and t.startswith("*"):
                t = t[1:]
            if ("contains" in mods or "startswith" in mods) and t.endswith("*") and not t.endswith("\\*"):
                t = t[:-1]
            cut.append(t)
        text = " | ".join(cut)
    return text


def describe_item(item):
    mods = modifiers(item)
    return {"field": item.field, "modifiers": mods, "words": [MODIFIER_WORDS.get(m, m) for m in mods],
            "values": [shown(item, v, mods) for v in item.value],
            "match": "all" if item.value_linking is ConditionAND else "any",
            "negated": bool(getattr(item, "negated", False))}


def describe_selection(name, det):
    groups = []
    if det.item_linking is ConditionOR and all(isinstance(x, SigmaDetection) for x in det.detection_items):
        for sub in det.detection_items:                         # a list of maps: any one map
            groups.append([describe_item(i) for i in _items(sub)])
        linking = "any"
    else:
        groups.append([describe_item(i) for i in _items(det)])
        linking = "all" if det.item_linking is ConditionAND else "any"
    return {"name": name, "groups": groups, "group_linking": linking,
            "filter": is_filter(name)}


def describe(rule, path=None):
    """The rule in a readable shape: who wrote it, what it looks for, and its logic part by part."""
    out = {"title": rule.title, "id": str(rule.id) if rule.id else None, "name": rule.name,
           "description": (rule.description or "").strip(), "level": rule.level.name.lower() if rule.level else None,
           "status": rule.status.name.lower() if rule.status else None, "author": rule.author or "",
           "date": str(rule.date) if rule.date else None, "modified": str(rule.modified) if rule.modified else None,
           "references": [str(x) for x in (rule.references or [])],
           "falsepositives": [str(x) for x in (rule.falsepositives or [])],
           "tags": [f"{t.namespace}.{t.name}" for t in (rule.tags or [])],
           "file": os.path.basename(path) if path else None,
           "kind": "correlation" if isinstance(rule, SigmaCorrelationRule) else "sigma"}
    if isinstance(rule, SigmaCorrelationRule):
        out["correlation"] = {
            "type": getattr(rule.type, "name", str(rule.type)).lower(),
            "group_by": list(rule.group_by or []),
            "timespan": str(getattr(rule.timespan, "spec", rule.timespan)),
            "condition": {"op": getattr(getattr(rule.condition, "op", None), "name", None),
                          "count": getattr(rule.condition, "count", None),
                          "field": getattr(rule.condition, "fieldref", None)},
            "rules": [describe(ref.rule) for ref in rule.rules if isinstance(ref.rule, (SigmaRule, SigmaCorrelationRule))]}
        return out
    cat = rule.logsource.category
    eid = detect.CATEGORY_EVENT_ID.get(cat, detect.DECLARED_CATEGORY_EVENT_ID.get(cat))
    out["logsource"] = {"category": cat, "product": rule.logsource.product,
                        "event_ids": list(eid) if isinstance(eid, tuple) else ([eid] if eid is not None else [])}
    out["condition"] = list(rule.detection.condition)
    out["selections"] = [describe_selection(n, d) for n, d in rule.detection.detections.items()]
    return out


# -- checking a rule against one event -------------------------------------------------------------------------
def field_value(event, field):
    """The event's value for a Sigma field name (case-insensitive, with the engine's own renames)."""
    if field is None:
        return None, False
    want = FIELD_MAP.get(field.lower(), field).lower()
    for k, v in event.items():
        if k.lower() == want:
            return v, v is not None and v != ""
    return None, False


def _string_regex(s, cased):
    """A Sigma string (wildcards * ?) as a Python regex; each literal part is a group, for highlighting."""
    parts = []
    for p in s.s:
        if p is SpecialChars.WILDCARD_MULTI:
            parts.append(".*?")
        elif p is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        elif isinstance(p, str):
            parts.append("(" + re.escape(p) + ")")
        else:                                                   # a placeholder: cannot be checked here
            return None
    return re.compile("".join(parts), re.S | (0 if cased else re.I))


def check_value(v, value, present, cased, event):
    """(matched: True/False/None for 'not checked', [[start, end], ...] spans in str(value))."""
    if isinstance(v, SigmaExpansion):
        res = [check_value(x, value, present, cased, event) for x in v.values]
        hit = next((r for r in res if r[0]), None)
        if hit:
            return hit
        return (None, []) if any(r[0] is None for r in res) else (False, [])
    if isinstance(v, SigmaNull):
        return (not present), []
    if isinstance(v, SigmaExists):
        return (present == v.exists), []
    if not present:
        return False, []
    text = str(value)
    if isinstance(v, SigmaRegularExpression):
        flags = 0
        for f in v.flags or ():
            flags |= {"IGNORECASE": re.I, "MULTILINE": re.M, "DOTALL": re.S}.get(f.name, 0)
        try:
            m = re.compile(show_value(v), flags).search(text)
        except re.error:
            return None, []
        return (m is not None), ([[m.start(), m.end()]] if m and m.end() > m.start() else [])
    if isinstance(v, SigmaString):                         # includes SigmaCasedString
        rx = _string_regex(v, cased or isinstance(v, SigmaCasedString))
        if rx is None:
            return None, []
        m = rx.fullmatch(text)
        if not m:
            # a number stored as text against a plain number-looking string (e.g. EventID '1')
            return False, []
        return True, [[m.start(i), m.end(i)] for i in range(1, (m.lastindex or 0) + 1) if m.end(i) > m.start(i)]
    if isinstance(v, SigmaNumber):
        try:
            return float(text) == float(v.number), [[0, len(text)]]
        except ValueError:
            return False, []
    if isinstance(v, SigmaCompareExpression):
        try:
            x, n = float(text), float(v.number.number)
        except ValueError:
            return False, []
        op = v.op.name
        ok = {"LT": x < n, "LTE": x <= n, "GT": x > n, "GTE": x >= n, "NEQ": x != n}.get(op)
        return ok, ([[0, len(text)]] if ok else [])
    if isinstance(v, SigmaCIDRExpression):
        try:
            ok = ipaddress.ip_address(text.strip()) in v.network
        except ValueError:
            return False, []
        return ok, ([[0, len(text)]] if ok else [])
    if isinstance(v, SigmaBool):
        ok = text.strip().lower() in (("true", "1") if v.boolean else ("false", "0"))
        return ok, ([[0, len(text)]] if ok else [])
    if isinstance(v, SigmaFieldReference):
        other, there = field_value(event, v.field)
        ok = there and (text.lower() == str(other).lower() if not cased else text == str(other))
        return ok, ([[0, len(text)]] if ok else [])
    return None, []


def _merge_spans(spans):
    out = []
    for s, e in sorted(spans):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


def _tri_all(xs):
    xs = list(xs)
    if any(x is False for x in xs):
        return False
    return None if any(x is None for x in xs) else True


def _tri_any(xs):
    xs = list(xs)
    if any(x is True for x in xs):
        return True
    return None if any(x is None for x in xs) else False


def check_item(item, event):
    mods = modifiers(item)
    if item.field is None:                                       # keyword search: not done here
        return dict(describe_item(item), value=None, present=False, matched=None, spans=[], matched_values=[])
    value, present = field_value(event, item.field)
    cased = "cased" in mods
    res = [check_value(v, value, present, cased, event) for v in item.value]
    linking = _tri_all if item.value_linking is ConditionAND else _tri_any
    matched = linking(r[0] for r in res)
    if getattr(item, "negated", False) and matched is not None:
        matched = not matched
    spans = _merge_spans([s for r in res if r[0] for s in r[1]])
    return dict(describe_item(item), value=None if value is None else str(value), present=present, matched=matched,
                spans=spans, matched_values=[shown(item, v, mods) for v, r in zip(item.value, res) if r[0]])


def check_detection(det, event):
    """A selection's verdict and its items' results (groups = the maps of a list-of-maps selection)."""
    if det.item_linking is ConditionOR and all(isinstance(x, SigmaDetection) for x in det.detection_items):
        groups = [[check_item(i, event) for i in _items(sub)] for sub in det.detection_items]
        matched = _tri_any(_tri_all(i["matched"] for i in g) for g in groups)
        return matched, groups, "any"
    items = [check_item(i, event) if isinstance(i, SigmaDetectionItem) else None for i in _items(det)]
    linking = _tri_all if det.item_linking is ConditionAND else _tri_any
    return linking(i["matched"] for i in items), [items], "all" if det.item_linking is ConditionAND else "any"


def _condition(node, results):
    if isinstance(node, ConditionIdentifier):
        return results.get(node.identifier)
    if isinstance(node, ConditionNOT):
        r = _condition(node.args[0], results)
        return None if r is None else (not r)
    if isinstance(node, ConditionAND):
        return _tri_all(_condition(a, results) for a in node.args)
    if isinstance(node, ConditionOR):
        return _tri_any(_condition(a, results) for a in node.args)
    if isinstance(node, ConditionSelector):
        quantifier, pattern = (str(a) for a in node.args[:2])
        names = [n for n in results if not n.startswith("_")] if pattern == "them" else \
            [n for n in results if fnmatch.fnmatchcase(n, pattern)]
        vals = [results[n] for n in names]
        return (_tri_any if node.cond_class is ConditionOR else _tri_all)(vals)
    return None


def evaluate(rule, event):
    """Every selection of a simple rule checked against `event` (a dict of field -> value), and the
    rule's condition over them. matched: True / False / None ('could not be checked here')."""
    selections, results = [], {}
    for name, det in rule.detection.detections.items():
        matched, groups, linking = check_detection(det, event)
        results[name] = matched
        selections.append({"name": name, "matched": matched, "groups": groups, "group_linking": linking,
                           "filter": is_filter(name)})
    conditions = []
    for c in rule.detection.parsed_condition:
        try:
            conditions.append(_condition(c.parse(False), results))
        except Exception:
            conditions.append(None)
    matched = _tri_any(conditions)
    fields = sorted({i["field"] for s in selections if s["matched"] and not s["filter"]
                     for g in s["groups"] for i in g if i and i["matched"] and i["field"]})
    return {"matched": matched, "selections": selections, "matched_fields": fields}


def evaluate_any(rule, event):
    """A simple rule: evaluate(). A correlation: the first of its base rules that holds for this event
    (which base rule this event belongs to), with that rule's title."""
    if isinstance(rule, SigmaCorrelationRule):
        tried = []
        for ref in rule.rules:
            base = ref.rule
            if isinstance(base, SigmaRule):
                r = evaluate(base, event)
                r["base_rule"] = base.title
                if r["matched"]:
                    return r
                tried.append(r)
        return tried[0] if tried else {"matched": None, "selections": [], "matched_fields": [], "base_rule": None}
    return evaluate(rule, event)
