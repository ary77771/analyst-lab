"""Every word on the new dashboard that says something about the evidence (debate 11).

The front end (dashboard/src) holds no claim words at all: it asks GET /api/words once and places
these texts. Keeping them here means they are written once, in Python, and tested (tests/
test_dashboard_words.py greps the front-end source for banned claim words).

The three inks keep debate 10's words: a fact is proven by a recorded event; a hypothesis is
"suspected: may be true, not proven" plus its band's plain word; a gap "can't be known from this
evidence". Never "likely", "probably", "safe" or "all clear".
"""

from fastapi import APIRouter

from .. import report as report_mod

INKS = {
    "fact": {"word": "Proven", "explain": "a recorded event says so"},
    "hypothesis": {"word": "Suspected", "explain": "may be true, not proven"},
    "gap": {"word": "Can't be known", "explain": "the recording cannot show this"},
}

# Short verb labels for graph lines (each line points from u to v, as in report.SENTENCES). Only
# facts get a verb; a suspected line is labelled with its ink word and band word instead.
VERBS = {
    "started": "started",
    "connected_to": "connected to",
    "accepted_from": "accepted from",
    "created": "created",
    "deleted": "deleted",
    "looked_up": "looked up",
    "ran_as": "ran as",
    "listen_started": "listened on",
    "listen_stopped": "stopped listening",
    "set_autostart": "set autostart",
    "will_start": "starts at logon",
    "download_marker": "marked downloaded",
    "same_content": "same content",
    "same_connection": "same connection",
}

WORDS = {
    "verbs": VERBS,
    "lanes": {"process": "Programs", "file": "Files", "endpoint": "Network"},
    "start_tag": "where the alert points",
    "tagline": "What happened, what is proven, what is only suspected, and what can't be known",
    "inks": INKS,
    "bands": dict(report_mod.BAND_GLOSS),          # high = strong link, medium = possible link, low = weak lead
    "band_not_assessable": "no grade (too little data)",
    "events": {str(k): v for k, v in report_mod.EVENT_NAMES.items()},
    "legend_title": "How to read the lines",
    "legend": [
        {"ink": "fact", "line": "solid", "text": "Proven: a recorded event says so"},
        {"ink": "hypothesis", "line": "dashed", "text": "Suspected: may be true, not proven (with how strong the link is)"},
        {"ink": "gap", "line": "dotted", "text": "Can't be known from this evidence"},
    ],
    "evidence_title": "The recorded proof",
    "evidence_hint": "Click a line or a sentence to see the recorded events behind it.",
    "evidence_role": "what this record shows",
    "public_badge": "PUBLIC DATA",
    "alert_level": "Alert level",
    "summary_title": "In short",
    "offset_note": "times counted from {ref}",
    "chain_note":"{n} of them are the alert's own numbered steps",
    "steps_title": "What the recording shows, in time order",
    "limits_title": "What this investigation cannot see",
    "no_alerts": "No alerts have been raised in this recording.",
    "raised_title": "Alerts raised (newest first)",
    "run_one": "Run S1 (download and run)",
    "run_three": "Run 3 tests in one boot (S1, S4, S5)",
    "run_three_hint": "Restores the prepared test machine and runs harmless test programs inside it: download and run "
                      "(S1), an unusual program chain (S4), file churn (S5). The machine takes about 8 minutes to start; "
                      "then the alerts land about a minute apart. A practice run, not one of the scored runs.",
    # the redesigned screens (2026-11-20): short headings; every number beside them comes from its own endpoint
    "live_notice": "The live test machine raised an alert",
    "live_label": "Live test machine",
    "replay_offer": "While the test machine starts: watch a recorded run",
    "story_pick": "Which alert",
    "proof": {
        "scores_title": "The old version (v3) against the new one (v4)",
        "twin_title": "Two programs that look alike",
        "strict_label": "of {n} without the community rules written with these same tests in mind",
    },
    "run_hint": "Restores the prepared test machine, runs the harmless S1 test program inside it, and "
                "checks what was recorded. The alert usually arrives about 9 minutes after the click "
                "(measured 2026-11-20).",
}


router = APIRouter()


@router.get("/api/words")
def words():
    """The fixed texts the front end shows (legend, inks, band words, event names, badges)."""
    return WORDS
