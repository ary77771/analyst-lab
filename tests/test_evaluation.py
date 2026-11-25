"""engine/evaluation.py: which evaluation a file belongs to, and the frozen-code gate of official work
(review 2026-11-13). The gate is tested on a throw-away git repository, never on this checkout."""

import subprocess

import pytest

from engine import evaluation as E
from tests.conftest import REAL_CODE_PROBLEMS


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "t@example.invalid")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / "engine").mkdir()
    (tmp_path / "engine" / "rule.py").write_text("X = 1\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "notes.md").write_text("a\n", encoding="utf-8")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "one")
    return tmp_path


def test_the_gate_needs_the_tag_and_exactly_the_frozen_code(repo):
    def gate():                                 # the project's own code only (the rules checkout: next test)
        return REAL_CODE_PROBLEMS("freeze-v2", str(repo), check_sigma=False)
    assert "does not exist yet" in gate()[0]
    git(repo, "tag", "freeze-v1")
    assert gate()                                                            # v1's tag never opens v2
    git(repo, "tag", "freeze-v2")
    assert gate() == []
    (repo / "docs" / "notes.md").write_text("results\n", encoding="utf-8")   # docs may change (results)
    git(repo, "commit", "-qam", "results")
    assert gate() == []
    (repo / "engine" / "rule.py").write_text("X = 2\n", encoding="utf-8")    # an uncommitted code edit
    assert any("not the frozen code" in p for p in gate())
    git(repo, "commit", "-qam", "tweak")                                     # committed after the tag: still not frozen
    assert any("not the frozen code" in p for p in gate())
    git(repo, "reset", "-q", "--hard", "freeze-v2")
    (repo / "tools").mkdir()
    (repo / "tools" / "new.py").write_text("", encoding="utf-8")             # an untracked code file
    assert any("untracked" in p for p in gate())


def test_version_of_reads_the_stamp_and_refuses_unknown_or_late_unstamped_files():
    assert E.version_of({}) == "v1" and E.version_of({"freeze": "freeze-v2"}) == "v2"
    assert E.version_of({}, when="2026-10-31T14:53:46+00:00") == "v1"
    assert E.version_of({}, when="20261031-145346.json") == "v1"
    with pytest.raises(ValueError, match="no freeze stamp"):
        E.version_of({}, when="2026-11-14T01:00:00+00:00")
    with pytest.raises(ValueError, match="no freeze stamp"):
        E.version_of({}, when="20261115-020000-abcd")
    with pytest.raises(ValueError, match="unknown freeze tag"):
        E.version_of({"freeze": "freeze-v9"})
    assert E.version_of({"freeze": "freeze-v2"}, when="2026-11-20") == "v2"


def test_the_community_rules_must_be_the_frozen_commit(repo):
    sigma = repo / "downloads" / "sigma"
    (sigma / "rules" / "windows").mkdir(parents=True)
    git(sigma, "init", "-q")
    git(sigma, "config", "user.email", "t@example.invalid")
    git(sigma, "config", "user.name", "t")
    (sigma / "rules" / "windows" / "r.yml").write_text("title: r\n", encoding="utf-8")
    (sigma / "regression_data").mkdir()
    (sigma / "regression_data" / "x.json").write_text("{}", encoding="utf-8")
    git(sigma, "add", "-A")
    git(sigma, "commit", "-q", "-m", "rules")
    head = subprocess.run(["git", "-C", str(sigma), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    (repo / "config").mkdir()
    (repo / "config" / "frozen.yaml").write_text("sigma:\n  rules_commit: 0000000000000000000000000000000000000000\n", encoding="utf-8")
    assert "not the frozen commit" in E.sigma_problems(str(repo))[0]
    (repo / "config" / "frozen.yaml").write_text(f"sigma:\n  rules_commit: {head}\n", encoding="utf-8")
    assert E.sigma_problems(str(repo)) == []
    (sigma / "regression_data" / "x.json").unlink()                         # outside rules/windows: does not matter
    assert E.sigma_problems(str(repo)) == []
    (sigma / "rules" / "windows" / "r.yml").write_text("title: changed\n", encoding="utf-8")
    assert "differ from the frozen commit" in E.sigma_problems(str(repo))[0]
    git(sigma, "checkout", "-q", "--", "rules/windows/r.yml")
    (sigma / "rules" / "windows" / "extra.yml").write_text("title: x\n", encoding="utf-8")
    assert "differ from the frozen commit" in E.sigma_problems(str(repo))[0]
    git(repo, "tag", "freeze-v2")
    assert REAL_CODE_PROBLEMS("freeze-v2", str(repo))                       # the gate includes the rules check


def test_the_real_rules_checkout_is_the_frozen_commit():
    import os
    if not os.path.isdir(os.path.join(E.ROOT, *E.SIGMA_DIR, ".git")):
        pytest.skip("SigmaHQ rules not fetched (tools/fetch_sigma_rules.ps1)")
    assert E.sigma_problems() == []