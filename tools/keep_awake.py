"""Keep the laptop from idle-sleeping while a long VM series runs (found 2026-10-30: the laptop
sleeps after 20 min idle on AC, which would freeze an overnight batch half-way).

Uses Windows' documented SetThreadExecutionState: a "busy, don't sleep" request held by this
process only. No power setting is changed; the request ends with the `with` block (or when the
process exits). The display may still turn off; a closed lid or choosing Sleep still sleeps.
"""

import contextlib
import sys

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001


def _set(flags):
    """Returns True when Windows accepted the request (no-op, False, elsewhere)."""
    if sys.platform != "win32":
        return False
    import ctypes
    return bool(ctypes.windll.kernel32.SetThreadExecutionState(flags))


@contextlib.contextmanager
def keep_awake(say=print, setter=_set):
    held = setter(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
    say("keep-awake: laptop will not idle-sleep during this series" if held
        else "WARNING: keep-awake not available: the laptop may idle-sleep during this series")
    try:
        yield held
    finally:
        if held:
            setter(ES_CONTINUOUS)
