"""Additions the agent makes to Sysmon events.

1. Origin tagging: marks events caused by our own project work (engine, tests, build tools,
   git, Claude, VirtualBox) as origin="project", so "normal use" statistics only reflect
   real use. A process counts as project activity if its program, command line or working
   folder (Sysmon's CurrentDirectory) is inside the project folder or VirtualBox, if it is a
   development tool listed in DEV_TOOLS, or if its parent process was project activity.
   The raw fields are kept, so tags can be recomputed later during analysis.
2. File hashing: Sysmon's FileCreate (event 11) has no hash, so for new executable or
   script files the agent computes a SHA-256 fingerprint (hashlib). Event 11 fires when a file
   is *created*, usually before its content is written, so hashing at once would fingerprint a
   partial file. The agent therefore opens the file with Windows' share mode "others may read,
   nobody may write" (CreateFile with FILE_SHARE_READ only): Windows refuses that while any
   program still has the file open for writing, so a successful open means writing is done.
   Until then the hash is retried (see agent/main.py), and the result is recorded as its own
   FILE_HASH event linked to the original event 11.
"""

import hashlib
import os

import pywintypes
import win32file

from .filetypes import should_hash

ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION = 2, 3, 5, 32

DEV_TOOLS = {"claude.exe"}  # Claude Code / desktop app
# Programs started by Claude that count as development work. Anything else Claude starts
# (e.g. a browser opened from a link) stays "normal" use.
DEV_CHILDREN = {"powershell.exe", "pwsh.exe", "cmd.exe", "conhost.exe", "git.exe", "bash.exe",
                "sh.exe", "node.exe", "python.exe", "pythonw.exe", "gh.exe", "wsl.exe", "chcp.com"}

MAX_HASH_BYTES = 100 * 1024 * 1024


class OriginTagger:
    def __init__(self, project_root: str, extra_prefixes=(), dev_tools: bool = True, strict: bool = False):
        # dev_tools=False on friends' laptops: their Claude use is normal use (friend package)
        self.dev_tools = DEV_TOOLS if dev_tools and not strict else frozenset()
        # strict (the lab VM, security review 2026-10-23): "our own tools" = programs that LIVE in
        # the project folder and their children; mentioning the folder in a command line or
        # starting in it no longer counts (a scenario could otherwise hide its whole process tree
        # with `cmd /c cd /d C:\LabTools & x.exe`), and no dev-tool names
        self.strict = strict
        self.prefixes = [os.path.normcase(os.path.abspath(project_root))]
        self.prefixes += [os.path.normcase(p) for p in extra_prefixes]
        self.project_guids = set()

    def is_inside(self, path: str) -> bool:
        """True if path is a project/VirtualBox folder or anything below it. Strict mode: never
        the project's recordings folder (data, not our programs: in the VM it is writable by the
        user, so a program copied there must not count as "our own tools", review 2026-10-23)."""
        if not path:
            return False
        path = os.path.normcase(path.strip().strip('"')).rstrip("\\")
        if self.strict:
            data = os.path.join(self.prefixes[0], "recordings")
            if path == data or path.startswith(data + "\\"):
                return False
        return any(path == p or path.startswith(p + "\\") for p in self.prefixes)

    def mentions(self, text: str) -> bool:
        """True if a command line refers to something inside the project/VirtualBox folders
        (the folder name followed by a path separator, quote, space or end of text)."""
        if not text:
            return False
        text = os.path.normcase(text)
        for p in self.prefixes:
            start = text.find(p)
            while start != -1:
                end = start + len(p)
                if end == len(text) or text[end] in '\\" ':
                    return True
                start = text.find(p, start + 1)
        return False

    def tag(self, event: dict) -> str:
        data = event.get("data", {})
        guid = data.get("ProcessGuid")
        is_project = (
            guid in self.project_guids
            or data.get("ParentProcessGuid") in self.project_guids
            or self.is_inside(data.get("Image"))
            or (not self.strict and self.mentions(data.get("CommandLine")))
            or (not self.strict and self.is_inside(data.get("CurrentDirectory")))
            or _basename(data.get("Image")) in self.dev_tools
            or (_basename(data.get("ParentImage")) in self.dev_tools
                and _basename(data.get("Image")) in DEV_CHILDREN)
        )
        # Claude itself is project activity, but it doesn't pass the tag to every child:
        # only DEV_CHILDREN (checked above) inherit it.
        is_claude = _basename(data.get("Image")) in self.dev_tools
        if event.get("event_id") == 1 and is_project and guid and not is_claude:
            self.project_guids.add(guid)
        if event.get("event_id") == 5 and guid in self.project_guids:
            self.project_guids.discard(guid)
        return "project" if is_project else "normal"


def _basename(path) -> str:
    return os.path.basename(path or "").lower()


def file_to_hash(event: dict):
    """The path to fingerprint for a Sysmon event 11 on an executable/script file, else None."""
    if event.get("event_id") != 11:
        return None
    path = event.get("data", {}).get("TargetFilename", "")
    return path if should_hash(path) else None


def hash_when_closed(path: str):
    """Fingerprint a file only once nobody is writing it.

    Returns (status, sha256, size, final_path): status "ok" with the hash and size; "busy" if a
    program still has it open for writing (try again later); "gone" if it no longer exists;
    "directory" if the new entry is a folder (Sysmon records folder creation as event 11 too;
    nothing to hash); "unreadable" or "too_large" otherwise. final_path is Windows' own full
    spelling of the path (GetFinalPathNameByHandle on the open file), so a path written in 8.3
    short form (ADMINI~1) can still be matched to a program's long path (decided 2026-10-17).
    """
    if os.path.isdir(path):
        return ("directory", None, None, None)
    try:
        # Share READ (others may read) and DELETE (others may delete/rename it while we hash),
        # but not WRITE: Windows refuses this open while any writer still has the file open.
        handle = win32file.CreateFile(path, win32file.GENERIC_READ,
                                      win32file.FILE_SHARE_READ | win32file.FILE_SHARE_DELETE, None,
                                      win32file.OPEN_EXISTING, win32file.FILE_ATTRIBUTE_NORMAL, None)
    except pywintypes.error as e:
        if e.winerror == ERROR_SHARING_VIOLATION:
            return ("busy", None, None, None)
        if e.winerror in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
            return ("gone", None, None, None)
        return ("unreadable", None, None, None)
    try:
        final = final_path(handle)
        size = win32file.GetFileSize(handle)
        if size > MAX_HASH_BYTES:
            return ("too_large", None, size, final)
        digest = hashlib.sha256()
        while True:
            _, chunk = win32file.ReadFile(handle, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        return ("ok", digest.hexdigest().upper(), size, final)
    except pywintypes.error:
        return ("unreadable", None, None, None)
    finally:
        handle.Close()


def final_path(handle):
    """Windows' full path of an open file (long names, real casing), without the \\\\?\\ prefix."""
    try:
        p = win32file.GetFinalPathNameByHandle(handle, 0)
    except pywintypes.error:
        return None
    if p.startswith("\\\\?\\UNC\\"):
        return "\\\\" + p[8:]
    return p[4:] if p.startswith("\\\\?\\") else p
