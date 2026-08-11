"""PATH shim installation for the wrapped binary set.

Installs ~/.local/bin/{agent-reach,twitter,bili,opencli,gh,yt-dlp,mcporter,curl}
as shims that exec `reach-guard run --as-bin <bin> -- "$@"`. Originals are
renamed to <bin>.real in the SAME directory (symlinks are moved, preserving the
target). Idempotent: already-installed shims are left untouched. System
binaries NOT in ~/.local/bin (curl, opencli, mcporter, yt-dlp) are never moved;
resolution falls back to PATH at run time (skipping the shim dir). Unknown
binary -> fail-closed exit 8.
"""

from __future__ import annotations

import os
import stat
import sys

from .config import WRAPPED_BINARIES
from .wrapper import find_real_binary

SHIM_DIR = os.environ.get("REACH_GUARD_SHIM_DIR",
                          os.path.expanduser("~/.local/bin"))

SHIM_TEMPLATE = """#!/bin/sh
# reach-guard PATH shim for {bin} (generated; idempotent). Do not edit.
{exec_line}
"""


def _exec_line() -> str:
    # Prefer the console script; fall back to `python -m reach_guard`.
    from shutil import which
    rg = which("reach-guard")
    if rg:
        return f'exec "{rg}" run --as-bin "$(basename "$0")" -- "$@"'
    py = sys.executable
    return (f'exec "{py}" -m reach_guard run '
            f'--as-bin "$(basename "$0")" -- "$@"')


def _is_guard_shim(path: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            head = f.read(512)
        return "reach-guard" in head or "reach_guard" in head
    except OSError:
        return False


def shim_status() -> dict:
    """bin -> 'shim' | 'real' | 'missing-shim-real' | 'absent'."""
    out = {}
    for b in WRAPPED_BINARIES:
        shim = os.path.join(SHIM_DIR, b)
        real = os.path.join(SHIM_DIR, b + ".real")
        if os.path.exists(shim) and _is_guard_shim(shim):
            out[b] = "shim"
        elif os.path.exists(shim):
            out[b] = "real"
        elif os.path.exists(real):
            out[b] = "missing-shim-real"
        else:
            out[b] = "absent"
    return out


def install_shims(dry_run: bool = False, verbose: bool = True) -> None:
    os.makedirs(SHIM_DIR, exist_ok=True)
    for b in WRAPPED_BINARIES:
        shim = os.path.join(SHIM_DIR, b)
        real = os.path.join(SHIM_DIR, b + ".real")
        if os.path.exists(shim) and _is_guard_shim(shim):
            if verbose:
                print(f"  {b}: already a reach-guard shim (skip)")
            continue
        if os.path.exists(real) and os.path.exists(shim):
            # shim exists but is not ours, and a .real exists already
            if verbose:
                print(f"  {b}: <bin>.real exists; overwriting shim")
        if os.path.exists(shim):
            # rename the original to <bin>.real (symlinks move whole link)
            if dry_run:
                print(f"  {b}: would rename {shim} -> {real}")
            else:
                os.rename(shim, real)
                print(f"  {b}: renamed original -> {real}")
        if dry_run:
            print(f"  {b}: would install shim {shim}")
            continue
        exec_line = _exec_line()
        content = SHIM_TEMPLATE.format(bin=b, exec_line=exec_line)
        with open(shim, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(shim, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP |
                 stat.S_IROTH | stat.S_IXOTH)
        if verbose:
            print(f"  {b}: shim installed -> reach-guard run")


def resolve_after_install(bin_name: str) -> str:
    """Resolution sanity used by doctor."""
    return find_real_binary(bin_name) or "<missing>"


def uninstall_shims(dry_run: bool = False, verbose: bool = True) -> None:
    """Remove reach-guard shims and restore originals.

    For each wrapped binary: if the shim exists AND is ours, restore
    <bin>.real -> <bin> when a .real exists (the original is preserved);
    otherwise (curl-style: system binary was never moved) only our shim is
    removed. Non-guard shims and absent shims are left untouched. Idempotent.
    """
    for b in WRAPPED_BINARIES:
        shim = os.path.join(SHIM_DIR, b)
        real = os.path.join(SHIM_DIR, b + ".real")
        if not os.path.exists(shim) or not _is_guard_shim(shim):
            continue
        if os.path.exists(real):
            if dry_run:
                print(f"  {b}: would restore {real} -> {shim}")
            else:
                os.remove(shim)
                os.rename(real, shim)
                if verbose:
                    print(f"  {b}: restored original -> {shim}")
        else:
            if dry_run:
                print(f"  {b}: would remove shim {shim}")
            else:
                os.remove(shim)
                if verbose:
                    print(f"  {b}: removed shim (no .real to restore)")
