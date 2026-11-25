"""Refresh the `film` stored in each tests/fixtures/stories/*.json after the film rule changed on purpose
(engine/dashboard/film.py). The stories themselves are never changed here.

    python tests/fixtures/refresh_story_films.py
"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
from engine.dashboard.film import film_of  # noqa: E402

for path in sorted(glob.glob(os.path.join(HERE, "stories", "*.json"))):
    with open(path, encoding="utf-8") as f:
        story = json.load(f)
    story["film"] = film_of(story["report"])
    with open(path, "w", encoding="utf-8") as f:
        json.dump(story, f, separators=(",", ":"))
    print(f"{os.path.basename(path):34} {story['film']['rows']:4} of {story['film']['total']:4} rows in the film")
