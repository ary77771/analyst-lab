"""engine/config.py: the chosen numbers are read from config/frozen.yaml, not hidden defaults."""

from engine import config


def test_min_level_and_own_rule_numbers_come_from_the_file(tmp_path):
    assert config.min_level() == "medium"
    p = config.own_rule_params()
    assert p["analystlab.fetch_write_run"]["window"] == 60.0
    assert p["analystlab.file_churn"] == {"window": 60.0, "created": 30, "deleted": 30, "level": "medium"}
    f = tmp_path / "frozen.yaml"
    f.write_text("sigma: {min_level: null}\nown_rules: {file_churn: {created: 50}}\n", encoding="utf-8")
    import pytest
    with pytest.raises(ValueError):
        config.min_level(str(f))                                   # not chosen yet: refuse
    assert config.own_rule_params(str(f)) == {"analystlab.file_churn": {"created": 50}}


def test_run_all_uses_the_file_numbers(tmp_path, monkeypatch):
    import sqlite3
    from engine import own_rules
    from tests.test_own_rules import churn
    from tests.test_detect import store
    con = sqlite3.connect(store(tmp_path, churn(30, 30, spread=50.0)))
    assert len(own_rules.run_all(con)) == 1                         # 30/30 from the file
    real = config.own_rule_params()                                   # one number changed in an otherwise real file
    monkeypatch.setattr(config, "own_rule_params", lambda: {**real, "analystlab.file_churn": {"created": 40}})
    assert own_rules.run_all(con) == []                             # a changed file number changes the result
