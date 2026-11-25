"""Listening-port snapshots. Sysmon records connections but not a program starting to
listen, so the agent lists TCP listening sockets (psutil) every few seconds and reports
what started or stopped listening since the previous snapshot.
"""

from datetime import datetime, timezone

import psutil


def listening_ports() -> dict:
    """{(ip, port): pid} for every TCP socket in LISTEN state."""
    result = {}
    for conn in psutil.net_connections(kind="tcp"):
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            result[(conn.laddr.ip, conn.laddr.port)] = conn.pid
    return result


def diff(before: dict, after: dict):
    """Return (started, stopped): lists of (ip, port, pid)."""
    started = [(ip, port, pid) for (ip, port), pid in after.items() if before.get((ip, port)) != pid]
    stopped = [(ip, port, pid) for (ip, port), pid in before.items() if after.get((ip, port)) != pid]
    return started, stopped


def process_image(pid):
    try:
        return psutil.Process(pid).exe() if pid else None
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def process_start(pid):
    """When the process started, as UTC text in Sysmon's own format ("YYYY-MM-DD HH:MM:SS.fff"),
    so the graph can tie a port to exactly the process whose event 1 has that UtcTime
    (a process number alone is reused; number + start time is unique). None if unknown."""
    try:
        if not pid:
            return None
        t = datetime.fromtimestamp(psutil.Process(pid).create_time(), timezone.utc)
        return t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
        return None
