"""Everyday names for the lab's test runs (wave 3, W3-6): "S1" is shown as "S1 · Download and run".

Nothing is typed here. Each name is the title its scenario's own file gives it:
  - our own scenarios: `title:` in scenarios/<id>/ground_truth.yaml (the list the Run buttons already use);
  - blind scenarios whose answer sheet is in this folder: `title:` in docs/results/blind/<id>.yaml;
  - the two look-alike stories of the Proof screen: their titles in docs/results/v4/twin.json.
A run with no title in any of these has NO name here: the page then says "unnamed run", never a guess.

Not a lab (its name starts with "_", so the registry leaves it alone). Served inside GET /api/labs as
`run_names`, so no rehearsed endpoint changes. Reading these files must never break that listing: a file
that is missing or can't be read is skipped.
"""

import glob
import json
import os
import re

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ID = re.compile(r"^[a-z]+\d+[a-z]?$")              # s1, s2j, c1, b18
MAX = 120                                          # a title is one line, not a paragraph


def _clean(title):
    if not isinstance(title, str):
        return None
    title = " ".join(title.split())
    return title[:MAX] if title else None


def _yaml_title(path):
    try:
        import yaml
        with open(path, encoding="utf-8") as f:
            return _clean((yaml.safe_load(f) or {}).get("title"))
    except Exception:
        return None


def run_names(root=PROJECT_ROOT):
    """{run id in lower case: its scenario's own title}. Our own scenarios first, then blind sheets, then the
    Proof screen's look-alikes; the first title found for an id is kept."""
    names = {}

    def add(run_id, title):
        run_id = str(run_id or "").strip().lower()
        if ID.match(run_id) and title and run_id not in names:
            names[run_id] = title

    for path in sorted(glob.glob(os.path.join(root, "scenarios", "*", "ground_truth.yaml"))):
        add(os.path.basename(os.path.dirname(path)), _yaml_title(path))
    for path in sorted(glob.glob(os.path.join(root, "docs", "results", "blind", "*.yaml"))):
        name = os.path.basename(path)
        if name.count(".") == 1:                   # b1.yaml, not b1.original.yaml
            add(name.split(".")[0], _yaml_title(path))
    try:
        with open(os.path.join(root, "docs", "results", "v4", "twin.json"), encoding="utf-8") as f:
            for side in json.load(f).get("sides") or []:
                add(side.get("scenario"), _clean(side.get("title")))
    except Exception:
        pass
    return names
