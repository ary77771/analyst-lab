import sys

import pytest

sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "tools"))
from keep_awake import ES_CONTINUOUS, ES_SYSTEM_REQUIRED, keep_awake  # noqa: E402


def test_requests_then_releases():
    calls = []
    with keep_awake(say=lambda m: None, setter=lambda f: calls.append(f) or True) as held:
        assert held
        assert calls == [ES_CONTINUOUS | ES_SYSTEM_REQUIRED]
    assert calls[-1] == ES_CONTINUOUS            # back to normal: system may sleep again


def test_released_even_when_the_series_crashes():
    calls = []
    with pytest.raises(RuntimeError):
        with keep_awake(say=lambda m: None, setter=lambda f: calls.append(f) or True):
            raise RuntimeError("run failed")
    assert calls[-1] == ES_CONTINUOUS


def test_refused_request_warns_and_releases_nothing():
    calls, said = [], []
    with keep_awake(say=said.append, setter=lambda f: calls.append(f) and False) as held:
        assert not held
    assert calls == [ES_CONTINUOUS | ES_SYSTEM_REQUIRED]
    assert "WARNING" in said[0]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows API")
def test_real_windows_call_is_accepted():
    with keep_awake(say=lambda m: None) as held:
        assert held
