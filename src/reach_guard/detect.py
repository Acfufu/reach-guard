"""Bypass detector: scan shell history + running processes for DIRECT calls to
wrapped upstream binaries that did not go through reach-guard.

Wrapped set: agent-reach/twitter/bili/opencli/gh/yt-dlp/mcporter/curl.
gh is EXEMPT (GitHub route is intentionally unwrapped) and never flagged.
Zero-config patterns (curl r.jina.ai, mcporter call exa) are called out as
violations when done directly.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import List

from .config import WRAPPED_BINARIES, EXEMPT_BINS

WRAPPED_RE = re.compile(r"^\s*(" + "|".join(WRAPPED_BINARIES) + r")\b")
GUARDED_RE = re.compile(r"reach[_-]guard")
ZERO_CONFIG = [
    (re.compile(r"^\s*curl\s+[\"']?https?://r\.jina\.ai", re.I),
     "zero-config curl r.jina.ai (bypasses Jina reader guard)"),
    (re.compile(r"^\s*mcporter\s+call\s+exa\.", re.I),
     "zero-config mcporter call exa (bypasses Exa guard)"),
]

HISTORY_FILES = [
    os.path.expanduser("~/.zsh_history"),
    os.path.expanduser("~/.bash_history"),
    os.path.expanduser("~/.history"),
]


def _history_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # zsh extended-history format: ": <ts>:<dur>;command"
        m = re.match(r":\s*\d+(?::\d+)?;", line)
        if m:
            line = line[m.end():]
        out.append(line)
    return out


def scan_line(line: str) -> List[str]:
    """Return violation messages for a single history/command line."""
    if GUARDED_RE.search(line):
        return []
    findings = []
    m = WRAPPED_RE.match(line)
    if m:
        bin_name = m.group(1)
        if bin_name in EXEMPT_BINS:
            return []  # gh exempt: never flagged
        findings.append(f"direct call to wrapped binary {bin_name!r}: {line[:160]}")
    for rx, note in ZERO_CONFIG:
        if rx.match(line):
            findings.append(f"{note}: {line[:160]}")
    return findings


def scan_history() -> List[str]:
    findings = []
    for path in HISTORY_FILES:
        for line in _history_lines(path):
            findings.extend(scan_line(line))
    return findings


def _token_matches_wrapped(part: str) -> Optional[str]:
    base = os.path.basename(part)
    if base.endswith(".real"):
        base = base[:-5]
    if base in EXEMPT_BINS:
        return None
    if base in WRAPPED_BINARIES:
        return base
    return None


def scan_processes() -> List[str]:
    findings = []
    try:
        ps = subprocess.run(["ps", "-axo", "pid=,ppid=,command="],
                            capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return findings
    procs = {}
    for line in ps.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, ppid, cmd = parts
        procs[pid] = (ppid, cmd)

    def is_guarded(pid: str) -> bool:
        seen = set()
        while pid and pid not in seen:
            seen.add(pid)
            if pid not in procs:
                return False
            _, cmd = procs[pid]
            if GUARDED_RE.search(cmd):
                return True
            pid = procs[pid][0]
        return False

    for pid, (ppid, cmd) in procs.items():
        if GUARDED_RE.search(cmd):
            continue
        found = None
        for tok in cmd.split():
            m = _token_matches_wrapped(tok)
            if m:
                found = m
                break
        if found and not is_guarded(pid):
            findings.append(
                f"running process uses wrapped binary {found!r}: {cmd[:160]}")
    return findings


def main(args) -> int:
    findings = []
    findings += scan_history()
    findings += scan_processes()
    if not findings:
        print("bypass detector: no direct (unguarded) calls found. gh exempt: OK.")
        return 0
    print("bypass detector: DIRECT UNGUARDED CALLS DETECTED (violation):")
    for f in findings:
        print(f"  - {f}")
    return 1
