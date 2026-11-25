"""Keep the laptop awake while the test machine is working (2026-11-21).

Why: on 2026-11-21 a warm start took 18.5 minutes instead of 10 and left under 6 minutes for tests. The
laptop, on battery and untouched for three hours, had turned its screen off and gone into Modern Standby
(Windows' System log: "entering Modern Standby, Reason: Idle Timeout" at 17:22:20, out again at 17:39:58 on
a key press). VirtualBox's log of that run: "Guest seems to be unresponsive. Last heartbeat received 581
seconds ago". A frozen test machine during the demo is the worst thing that can happen to it.

How: the standard request a video player makes, SetThreadExecutionState. While a one-boot run or a warm
session is going, this process asks Windows to keep the system AND the screen on (on a Modern Standby
laptop the standby follows the screen going off, so the screen is the request that counts). When nothing
is going, the request is cleared.
  - Nothing is changed in Windows' settings; no powercfg; nothing persists. The request belongs to one
    thread of this process and is gone when that thread or the process ends.
  - It cannot stop a closed lid, the power button, or a critical battery. demo/preflight.py tells Yousif
    about the timers and about running on battery; those are his to set.
  - The request is made and cleared by ONE thread (Windows ties it to the calling thread), which looks
    every two seconds at what is going on. Any trouble finding that out counts as "nothing is going".
"""

import threading

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ES_DISPLAY_REQUIRED = 0x00000002
KEEP = ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED

WORDS = {"on": "the laptop is asked to stay awake, screen on, while the test machine is working",
         "off": "the stay-awake request is cleared"}


def windows_setter():
    """The real SetThreadExecutionState, or None where there is none (not Windows)."""
    try:
        import ctypes
        fn = ctypes.windll.kernel32.SetThreadExecutionState
        fn.argtypes, fn.restype = [ctypes.c_uint32], ctypes.c_uint32
        return fn
    except (AttributeError, OSError, ImportError):
        return None


class Keeper:
    """Asks for "stay awake" exactly while `working()` is true. `setter` is SetThreadExecutionState (or a
    stand-in). `asked` is what is requested right now: True, False, or None before the first look."""

    def __init__(self, working, setter, every=2.0, say=None):
        self.working, self.setter, self.every = working, setter, every
        self.say = say or (lambda *_: None)
        self.asked = None
        self._stop = threading.Event()

    def step(self):
        """One look: ask or clear if what is going on changed. Never raises."""
        try:
            want = bool(self.working())
        except Exception:
            want = False                          # not knowing is not a reason to keep a laptop awake
        if want != self.asked:
            try:
                self.setter(ES_CONTINUOUS | (KEEP if want else 0))
                self.asked = want
                self.say(WORDS["on"] if want else WORDS["off"])
            except Exception:
                pass
        return self.asked

    def clear(self):
        """Take the request back, whatever is going on (the end of the keeper's own thread)."""
        try:
            self.setter(ES_CONTINUOUS)
        except Exception:
            pass
        self.asked = False

    def run(self):
        try:
            while not self._stop.is_set():
                self.step()
                self._stop.wait(self.every)
        finally:
            self.clear()

    def start(self):
        threading.Thread(target=self.run, daemon=True, name="keep-awake").start()
        return self

    def stop(self):
        self._stop.set()
