"""Read a Windows event log channel with the standard Windows mechanisms:

- EvtSubscribe (pull mode): Windows signals us when new events arrive, no busy polling.
- Bookmarks (EvtCreateBookmark / EvtUpdateBookmark / EvtRenderBookmark): Windows' own way
  to remember the read position, so a restart resumes exactly after the last saved event.

Microsoft docs: "Subscribing to Events" and "Bookmarking Events" (Windows Event Log API).

Robustness rules:
- One event that can't be rendered or parsed never stops reading: it becomes a
  {"parse_error": ...} record (with its record number and raw XML when available) and the
  bookmark still moves past it.
- The bookmark is used in strict mode, so Windows reports an error instead of silently
  starting somewhere else if the bookmarked event no longer exists (log cleared or wrapped).
  A missing, stale or corrupt bookmark falls back to reading from the oldest event, which can
  only cause duplicates (removed later), never a loss, and is reported via `fallback_reason`.
"""

import re

import pywintypes
import win32event
import win32evtlog

from .parse import parse_event_xml

ERROR_NO_MORE_ITEMS = 259
ERROR_TIMEOUT = 1460
# ERROR_INVALID_OPERATION: Windows' answer to an EvtNext after "no more items" when nothing new
# arrived (probed 2026-10-17), so it means "nothing new". A subscription that is broken in a way
# that only ever answers this is caught by the agent's idle re-subscribe (main.IDLE_RESUBSCRIBE).
ERROR_STILL_NOTHING = 4317


class ChannelReader:
    """Delivers new events from one channel in batches, resuming from a saved bookmark."""

    def __init__(self, channel: str, bookmark_xml=None, start_at_oldest: bool = True,
                 query: str = "*", batch_size: int = 200):
        self.channel = channel
        self.query = query
        self.batch_size = batch_size
        self.resumed = False
        self.fallback_reason = None
        self._signal = win32event.CreateEvent(None, True, True, None)

        if bookmark_xml:
            try:
                self._bookmark = win32evtlog.EvtCreateBookmark(bookmark_xml)
                self._subscription = win32evtlog.EvtSubscribe(
                    channel,
                    win32evtlog.EvtSubscribeStartAfterBookmark | win32evtlog.EvtSubscribeStrict,
                    SignalEvent=self._signal, Query=query, Bookmark=self._bookmark,
                )
                self.resumed = True
                return
            except pywintypes.error as e:
                self.fallback_reason = f"bookmark unusable ({e.winerror}: {e.strerror}); reading from oldest event"
                start_at_oldest = True

        self._bookmark = win32evtlog.EvtCreateBookmark(None)
        flags = (win32evtlog.EvtSubscribeStartAtOldestRecord if start_at_oldest
                 else win32evtlog.EvtSubscribeToFutureEvents)
        self._subscription = win32evtlog.EvtSubscribe(channel, flags, SignalEvent=self._signal, Query=query)

    def wait(self, timeout_ms: int) -> bool:
        """Block until Windows signals new events (or the timeout passes). True = signalled.
        Call next_batch() only after True, as Microsoft's pull-subscription sample does: after
        "no more items", an EvtNext without the signal can fail with 4317 ("The operation
        identifier is not valid"), probed 2026-10-17. The signal starts set, so the first call
        reads any backlog."""
        return win32event.WaitForSingleObject(self._signal, timeout_ms) == win32event.WAIT_OBJECT_0

    def next_batch(self) -> list:
        """Return up to batch_size events (parsed, or parse_error records); [] when none wait."""
        handles = self._evt_next()
        if not handles:
            win32event.ResetEvent(self._signal)
            # An event arriving just before the reset would have its signal cleared and wait
            # for the next event; one more read closes that gap.
            try:
                handles = self._evt_next()
            except Exception:
                win32event.SetEvent(self._signal)   # failed: make sure the next pass reads again
                raise
            if not handles:
                return []

        events = []
        for handle in handles:
            events.append(self._read_one(handle))
            win32evtlog.EvtUpdateBookmark(self._bookmark, handle)
        return events

    def _evt_next(self):
        try:
            return win32evtlog.EvtNext(self._subscription, self.batch_size, 0)
        except pywintypes.error as e:
            if e.winerror in (ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT, ERROR_STILL_NOTHING):
                return ()
            raise

    def _read_one(self, handle) -> dict:
        xml = None
        try:
            xml = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
            return parse_event_xml(xml)
        except Exception as e:  # one bad event must never stop the agent
            record_id = None
            if xml:
                m = re.search(r"<EventRecordID>(\d+)<", xml)
                record_id = int(m.group(1)) if m else None
            return {"parse_error": f"{type(e).__name__}: {e}", "raw_xml": xml,
                    "record_id": record_id, "event_id": None, "provider": None,
                    "time": None, "channel": self.channel, "data": {}}

    def bookmark_xml(self) -> str:
        """The current read position, to be saved only after the batch is safely written."""
        return win32evtlog.EvtRender(self._bookmark, win32evtlog.EvtRenderBookmark)
