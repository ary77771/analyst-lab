"""Package G: hub suppression (engine/hubs.py) - learning the list and using it in a view."""

import hashlib
import sqlite3

import pytest

from engine import config, hubs
from engine.graph import ZERO_GUID, subgraph_around
from tests.test_graph import P, graph, start

G1, G2, G3, G4, G5, G6 = ("{%08d-0000-0000-0000-000000000000}" % i for i in range(1, 7))
HUB, OTHER = r"C:\Windows\HubHost.EXE", r"C:\x\other.exe"
SHARE, FLOOR = 0.01, 2


def guid(prefix, i):
    return "{%d%07d-0000-0000-0000-000000000000}" % (prefix, i)


def learn_records():
    recs = [start(1, 0, G1, 10, HUB, ZERO_GUID)]
    recs += [start(2 + i, 1 + i, guid(1, i), 100 + i, rf"C:\x\Child{i}.exe", G1, 10, HUB) for i in range(3)]
    recs += [start(9, 4, guid(8, 0), 109, r"C:\y\child0.exe", G1, 10, HUB)]             # same NAME elsewhere: not new
    recs += [start(10 + i, 5 + i, guid(2, i), 200 + i, r"C:\x\worker.exe", G2, 20, r"C:\x\repeater.exe")
             for i in range(5)]                                                         # 5 copies of ONE child
    recs += [start(20 + i, 20 + i, guid(3, i), 300 + i, rf"C:\x\tool{i}.exe", G3, 30, r"C:\x\ours.exe",
                   origin="project") for i in range(4)]                                 # our own tools
    recs += [start(30 + i, 30 + i, guid(4, i), 400 + i, rf"C:\x\early{i}.exe", ZERO_GUID, 0, r"C:\x\before.exe")
             for i in range(4)]                                                         # parent unknown: a gap
    # a project-tagged parent whose children are tagged normal (claude.exe starting a browser)
    recs += [start(40, 40, G4, 500, r"C:\x\ours2.exe", ZERO_GUID, origin="project")]
    recs += [start(41 + i, 41 + i, guid(5, i), 510 + i, rf"C:\x\app{i}.exe", G4, 500, r"C:\x\ours2.exe")
             for i in range(3)]
    recs += [start(50 + i, 50 + i, guid(6, i), 600 + i, rf"C:\x\b{i}.exe", guid(7, i), 700 + i,
                   r"C:\Users\u\claude.exe") for i in range(3)]                         # unseen dev tool parent
    return recs


def counts_of(tmp_path, recs, until=None, name="g.db"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    graph(tmp_path, recs)
    return hubs.distinct_children(sqlite3.connect(str(tmp_path / name)), until)


def test_distinct_children_counts_names_not_copies_by_full_path(tmp_path):
    counts = counts_of(tmp_path, learn_records())
    assert counts[r"c:\windows\hubhost.exe"] == 3 and counts[r"c:\x\repeater.exe"] == 1
    assert counts[r"c:\x\child0.exe"] == 0                         # every program seen is counted
    for left_out in (r"c:\x\ours.exe", r"c:\x\before.exe", r"c:\x\ours2.exe", r"c:\users\u\claude.exe"):
        assert counts.get(left_out, 0) == 0


def test_paused_rows_and_until_are_left_out(tmp_path):
    recs = [start(1, 0, G1, 10, HUB, ZERO_GUID)] + \
           [start(2 + i, 10 * (i + 1), guid(1, i), 100 + i, rf"C:\x\c{i}.exe", G1, 10, HUB) for i in range(3)]
    recs[1]["paused"] = 1
    assert counts_of(tmp_path / "a", recs)[r"c:\windows\hubhost.exe"] == 2
    assert counts_of(tmp_path / "b", recs, until="2026-10-20T10:00:25")[r"c:\windows\hubhost.exe"] == 1


def test_missing_parent_guid_is_not_a_parent(tmp_path):
    r = start(1, 0, G1, 10, OTHER, ZERO_GUID, 9, r"C:\x\p.exe")
    r["data"].pop("ParentProcessGuid")
    assert r"c:\x\p.exe" not in counts_of(tmp_path, [r])


def test_top_share_cut_floor_ties_and_rounding():
    counts = {f"p{i}": 1 for i in range(147)} | {"a": 30, "b": 18, "c": 18}
    assert hubs.top_share(counts, SHARE, FLOOR) == ({"a", "b", "c"}, 18)    # 150 -> k = 2 (ceil); ties are in
    assert hubs.top_share({"a": 1, "b": 0}, SHARE, FLOOR) == (set(), 2)     # never below 2 children
    assert hubs.top_share({}, SHARE, FLOOR) == (set(), None)


def test_shells_are_never_hubs(tmp_path):
    recs = [start(1, 0, G1, 10, r"C:\Windows\System32\cmd.exe", ZERO_GUID)] + \
           [start(2 + i, 1 + i, guid(1, i), 100 + i, rf"C:\x\c{i}.exe", G1, 10, r"C:\Windows\System32\cmd.exe")
            for i in range(3)]
    graph(tmp_path, recs)
    learned = hubs.learn(sqlite3.connect(str(tmp_path / "g.db")), SHARE, FLOOR)
    assert learned["hubs"] == [] and learned["shells_left_out"] == 1
    hubs.save({**learned, "hubs": [r"C:\Windows\System32\cmd.exe"]}, str(tmp_path / "h.json"), "test")
    assert hubs.load(str(tmp_path / "h.json")) == frozenset()                # refused even if a file lists one


def test_save_load_round_trip_and_file_hash(tmp_path):
    graph(tmp_path, learn_records())
    learned = hubs.learn(sqlite3.connect(str(tmp_path / "g.db")), SHARE, FLOOR)
    digest = hubs.save(learned, str(tmp_path / "b" / "hubs.json"), "test")
    assert hubs.load(str(tmp_path / "b" / "hubs.json")) == frozenset(learned["hubs"])
    assert hashlib.sha256((tmp_path / "b" / "hubs.json").read_bytes()).hexdigest() == digest   # = Get-FileHash


def view_records(hub_image=HUB):
    """hubhost starts the seed's program A and, separately, B, which starts C."""
    return [start(1, 0, G1, 10, hub_image, ZERO_GUID),
            start(2, 10, G2, 11, OTHER, G1, 10, hub_image),    # A (the seed)
            start(3, 20, G3, 12, OTHER, G1, 10, hub_image),    # B: an unrelated sibling
            start(4, 30, G4, 13, OTHER, G3, 12, OTHER)]        # C


HUBS = frozenset({r"c:\windows\hubhost.exe"})


def test_a_hub_is_kept_but_not_walked_through(tmp_path):
    G, _ = graph(tmp_path, view_records())
    assert {P(G3), P(G4)} <= set(subgraph_around(G, P(G2)))            # without the list: B and C pulled in
    H = hubs.mark(subgraph_around(G, P(G2), expand=hubs.expander(HUBS)), HUBS)
    assert set(H) == {P(G1), P(G2)}                                    # mixed-case image still matches
    assert H.nodes[P(G1)].get("hub") is True and not H.nodes[P(G2)].get("hub")


def test_a_look_alike_name_in_another_folder_is_not_a_hub(tmp_path):
    G, _ = graph(tmp_path, view_records(hub_image=r"C:\Users\u\Downloads\hubhost.exe"))
    assert {P(G3), P(G4)} <= set(subgraph_around(G, P(G2), expand=hubs.expander(HUBS)))


def test_the_seed_is_walked_even_when_it_is_a_hub(tmp_path):
    G, _ = graph(tmp_path, view_records())
    H = hubs.mark(subgraph_around(G, P(G1), expand=hubs.expander(HUBS)), HUBS)
    assert {P(G2), P(G3), P(G4)} <= set(H) and not H.nodes[P(G1)].get("hub")


def frozen_with(tmp_path, rule):
    (tmp_path / "config").mkdir(exist_ok=True)
    f = tmp_path / "config" / "frozen.yaml"
    f.write_text("graph:\n  hub_rule: " + rule + "\n", encoding="utf-8")
    return str(f)


def test_config_hubs_checks_hash_settings_and_presence(tmp_path):
    learned = {"method": "distinct_children", "top_share": SHARE, "min_children": FLOOR, "hubs": [r"C:\A\X.exe"]}
    digest = hubs.save(learned, str(tmp_path / "b" / "hubs.json"), "test")
    ok = "{method: distinct_children, top_share: 0.01, min_children: 2, file: b/hubs.json, sha256: %s}"
    assert config.hubs(frozen_with(tmp_path, ok % digest)) == frozenset({r"c:\a\x.exe"})
    assert config.hubs(frozen_with(tmp_path, ok % digest.upper())) == frozenset({r"c:\a\x.exe"})  # Get-FileHash case
    with pytest.raises(ValueError):                                                    # learned with other settings
        config.hubs(frozen_with(tmp_path, (ok % digest).replace("top_share: 0.01", "top_share: 0.05")))
    with pytest.raises(ValueError):                                                    # no frozen hash
        config.hubs(frozen_with(tmp_path, "{method: distinct_children, top_share: 0.01, min_children: 2, file: b/hubs.json}"))
    with pytest.raises(ValueError):                                                    # a setting missing
        config.hubs(frozen_with(tmp_path, "{method: distinct_children, top_share: 0.01, file: b/hubs.json, sha256: x}"))
    missing = (ok % digest).replace("b/hubs.json", "b/missing.json")
    with pytest.raises(FileNotFoundError):                                             # never silently untrimmed
        config.hubs(frozen_with(tmp_path, missing))
    assert config.hubs(frozen_with(tmp_path, missing), allow_missing=True) is None
    (tmp_path / "b" / "hubs.json").write_text('{"hubs": ["a.exe", "b.exe"]}', encoding="utf-8")
    with pytest.raises(ValueError):                                                    # changed since frozen
        config.hubs(frozen_with(tmp_path, ok % digest))
    assert config.hubs(frozen_with(tmp_path, "null")) is None


def test_the_real_frozen_rule_is_complete():
    rule = config.hub_rule()
    assert rule["method"] == "distinct_children" and rule["sha256"]
