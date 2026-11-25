"""One shared definition of which files matter, used everywhere (agent hashing, the filter
simulation, and a test that checks the Sysmon config says the same thing).

Sysmon config v0.2 records file creation/deletion only for:
  - files ending in KEEP_EXTENSIONS (programs and scripts), anywhere, or
  - any file under a path containing one of KEEP_FOLDERS.

The agent fingerprints (FILE_HASH) a recorded new file when it has a KEEP_EXTENSIONS ending,
or when it is anywhere under an AnalystLab folder (scenario evidence). Other files in Downloads
and Startup are recorded but not fingerprinted (often large; personal documents).
"""

KEEP_EXTENSIONS = (".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".ps1", ".psm1", ".bat",
                   ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".py", ".jar", ".lnk")
KEEP_FOLDERS = ("\\Downloads\\", "\\Start Menu\\Programs\\Startup\\", "\\AnalystLab\\")
HASH_ALL_IN_FOLDER = "\\analystlab\\"


def is_recorded(path: str) -> bool:
    """Would Sysmon config v0.2 record a file event for this path? (case-insensitive)"""
    p = (path or "").lower()
    return p.endswith(KEEP_EXTENSIONS) or any(f.lower() in p for f in KEEP_FOLDERS)


def should_hash(path: str) -> bool:
    p = (path or "").lower()
    return p.endswith(KEEP_EXTENSIONS) or HASH_ALL_IN_FOLDER in p
