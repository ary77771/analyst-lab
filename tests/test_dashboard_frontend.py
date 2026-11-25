"""Guards on the new dashboard's front end (debate 11).

1. Claim words never live in the front-end source: they come from Python (engine/dashboard/words.py,
   public.py, report.py). A grep over dashboard/src for banned words fails the build's tests.
2. The built page works offline: no http(s) URL in the built files except an allow-list of strings
   that are never fetched (XML namespaces, React's error-page link inside its error messages).
3. The font files are in the build (vendored, not fetched).
"""

import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "dashboard", "src")
BUILT = os.path.join(ROOT, "engine", "dashboard", "static", "app")

BANNED = re.compile(r"\b(probably|likely|safe|secure|all clear|all good|no threats?|clean|proven|detected|caught|malicious|attack(?:er)?)\b", re.I)
ALLOWED_URLS = {
    "http://www.w3.org/2000/svg", "http://www.w3.org/1998/Math/MathML", "http://www.w3.org/1999/xlink",
    "http://www.w3.org/XML/1998/namespace", "https://react.dev/errors/",
}


def src_files():
    for d, _, fs in os.walk(SRC):
        for f in fs:
            if f.endswith((".ts", ".tsx", ".css")):
                yield os.path.join(d, f)


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(^|[^:])//[^\n]*", r"\1", text)


LITERAL = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|`[^`]*`')
JSX_TEXT = re.compile(r">([^<>{}]+)<")


def visible_text(code):
    """What could reach the screen from the source: string literals and JSX text (not identifiers:
    `v.proven` is the name of a field Python sends, not a word the page writes)."""
    code = strip_comments(code)
    return [m.group(0) for m in LITERAL.finditer(code)] + [m.group(1) for m in JSX_TEXT.finditer(code)]


def test_no_claim_words_in_the_front_end_source():
    hits = []
    for p in src_files():
        with open(p, encoding="utf-8") as f:
            for text in visible_text(f.read()):
                for m in BANNED.finditer(text):
                    hits.append(f"{os.path.relpath(p, ROOT)}: {m.group(0)!r} in {text[:60]!r}")
    assert not hits, hits


def test_the_banned_word_check_can_fail():
    assert any(BANNED.search(t) for t in visible_text('const x = "All clear";'))
    assert any(BANNED.search(t) for t in visible_text('return <b>Safe</b>;'))                # JSX text
    assert any(BANNED.search(t) for t in visible_text('<Button title="detected">x</Button>'))  # a prop string
    assert not any(BANNED.search(t) for t in visible_text('// all clear in a comment is fine\nconst y = v.proven;'))


@pytest.mark.skipif(not os.path.isdir(BUILT), reason="dashboard not built (npm run build in dashboard/)")
def test_the_built_page_points_nowhere_online():
    found = set()
    for d, _, fs in os.walk(BUILT):
        for f in fs:
            if f.endswith((".js", ".css", ".html")):
                with open(os.path.join(d, f), encoding="utf-8", errors="replace") as fh:
                    found |= set(re.findall(r"https?://[^\s\"'`)<>]+", fh.read()))
    assert found <= ALLOWED_URLS, sorted(found - ALLOWED_URLS)


@pytest.mark.skipif(not os.path.isdir(BUILT), reason="dashboard not built")
def test_the_font_is_in_the_build():
    assets = os.listdir(os.path.join(BUILT, "assets"))
    assert any(a.startswith("inter-latin-400") and a.endswith(".woff2") for a in assets)
