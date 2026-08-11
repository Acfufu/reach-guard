"""Append-only state ledger (state.jsonl) with 60-day rotation and 0600 perms.

Every guarded invocation appends one line. `status` reads the ledger to report
quota usage, cooldowns, quarantines, bindings, and gate states. Corrupt lines
are skipped (never crash). Env values are never stored — only SHA-256 hashes.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Optional

from .config import CONFIG_DIR, CONFIG_FILE, STATE_DIR, STATE_FILE, LOCK_FILE

STATE_PERMS = 0o600
DIR_PERMS = 0o700


def ensure_dirs() -> None:
    os.makedirs(STATE_DIR, mode=DIR_PERMS, exist_ok=True)
    os.makedirs(os.path.join(STATE_DIR, "logs"), mode=DIR_PERMS, exist_ok=True)
    os.makedirs(os.path.join(STATE_DIR, "profiles"), mode=DIR_PERMS, exist_ok=True)
    os.makedirs(CONFIG_DIR, mode=DIR_PERMS, exist_ok=True)
    for p in (STATE_DIR, os.path.join(STATE_DIR, "logs"),
              os.path.join(STATE_DIR, "profiles"), CONFIG_DIR):
        try:
            os.chmod(p, DIR_PERMS)
        except OSError:
            pass
    if os.path.exists(STATE_FILE):
        try:
            os.chmod(STATE_FILE, STATE_PERMS)
        except OSError:
            pass
    if os.path.exists(CONFIG_FILE):
        try:
            os.chmod(CONFIG_FILE, STATE_PERMS)
        except OSError:
            pass


def _rotate_if_old(path: str, age_days: int = 60) -> None:
    if not os.path.exists(path):
        return
    age = time.time() - os.path.getmtime(path)
    if age > age_days * 86400:
        backup = path + ".1"
        try:
            os.replace(path, backup)
            os.chmod(backup, STATE_PERMS)
        except OSError:
            pass


def append_record(record: dict) -> None:
    ensure_dirs()
    _rotate_if_old(STATE_FILE)
    record.setdefault("ts", time.time())
    line = json.dumps(record, ensure_ascii=False) + "\n"
    with open(STATE_FILE, "a", encoding="utf-8") as f:
        f.write(line)
    try:
        os.chmod(STATE_FILE, STATE_PERMS)
    except OSError:
        pass


def read_records(since: Optional[float] = None) -> list:
    """Read all ledger records (primary + rotated .1). Corrupt lines skipped."""
    out = []
    files = [STATE_FILE]
    if os.path.exists(STATE_FILE + ".1"):
        files.append(STATE_FILE + ".1")
    for path in files:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue  # corrupt line: skip, never crash
                    if not isinstance(rec, dict):
                        continue
                    if since is not None and rec.get("ts", 0) < since:
                        continue
                    out.append(rec)
        except OSError:
            continue
    return out


def counts(platform: str, account_hash: str, since: float) -> int:
    return sum(
        1 for r in read_records()
        if r.get("platform") == platform and r.get("account_hash") == account_hash
        and r.get("ts", 0) >= since
    )


def count_batch(run_id: str) -> int:
    return sum(1 for r in read_records() if r.get("run_id") == run_id)


def all_calls_since(since: float) -> int:
    return sum(1 for r in read_records() if r.get("ts", 0) >= since)


def latest_call_ts(platform: Optional[str] = None, account_hash: Optional[str] = None) -> float:
    best = 0.0
    for r in read_records():
        if platform is not None and r.get("platform") != platform:
            continue
        if account_hash is not None and r.get("account_hash") != account_hash:
            continue
        ts = r.get("ts", 0) or 0
        if ts > best:
            best = ts
    return best


# ---------------------------------------------------------------------------
# Breaker persistence (cooldowns / quarantines / permanent)
# ---------------------------------------------------------------------------

def find_breaker(platform: str, account_hash: str) -> Optional[dict]:
    """Most recent breaker record for (platform, account_hash), if active."""
    best = None
    for r in read_records():
        if r.get("kind") != "breaker":
            continue
        if r.get("platform") != platform or r.get("account_hash") != account_hash:
            continue
        if best is None or (r.get("ts") or 0) > (best.get("ts") or 0):
            best = r
    return best


def find_platform_breaker(platform: str) -> Optional[dict]:
    best = None
    for r in read_records():
        if r.get("kind") != "breaker" or r.get("platform") != platform:
            continue
        if best is None or (r.get("ts") or 0) > (best.get("ts") or 0):
            best = r
    return best


def breaker_active(platform: str, account_hash: str, now: float) -> Optional[tuple]:
    """Return (tier, until_ts) if a breaker currently blocks, else None.

    Tiers: cooldown (platform 24h) / quarantine (account+platform until unlock)
    / permanent (account+platform, irreversible via CLI).
    """
    rec = find_breaker(platform, account_hash)
    if rec is None:
        rec = find_platform_breaker(platform)
    if rec is None:
        return None
    tier = rec.get("tier")
    until = rec.get("until", 0)
    if tier == "cooldown" and until and now < until:
        return (tier, until)
    if tier in ("quarantine", "permanent") and rec.get("active", False):
        return (tier, until)
    return None


def record_breaker(platform: str, account_hash: str, tier: str, signal: str,
                   until: float, active: bool = True) -> None:
    append_record({
        "kind": "breaker",
        "ts": time.time(),
        "platform": platform,
        "account_hash": account_hash,
        "tier": tier,
        "signal": signal,
        "until": until,
        "active": active,
    })


def unlock(platform: str, account_hash: str) -> bool:
    """Manual unlock for quarantine tier. Permanent cannot be unlocked."""
    rec = find_breaker(platform, account_hash)
    if rec is None:
        rec = find_platform_breaker(platform)
    if rec is None:
        return False
    if rec.get("tier") == "permanent":
        return False
    # deactivate by appending an override record with active=False
    append_record({
        "kind": "breaker",
        "ts": time.time(),
        "platform": platform,
        "account_hash": account_hash,
        "tier": rec.get("tier", "quarantine"),
        "signal": "manual unlock",
        "until": 0,
        "active": False,
    })
    return True


def list_breakers() -> list:
    best = {}
    for r in read_records():
        if r.get("kind") != "breaker":
            continue
        key = (r.get("platform"), r.get("account_hash"), r.get("tier"))
        if key not in best or (r.get("ts") or 0) > (best[key].get("ts") or 0):
            best[key] = r
    return list(best.values())


# ---------------------------------------------------------------------------
# Proxy binding persistence
# ---------------------------------------------------------------------------

def bind_account(platform: str, account_hash: str, proxy_url: str) -> None:
    append_record({
        "kind": "binding",
        "ts": time.time(),
        "platform": platform,
        "account_hash": account_hash,
        "proxy_url": proxy_url,
    })


def binding_for(platform: str, account_hash: str) -> Optional[dict]:
    best = None
    for r in read_records():
        if r.get("kind") != "binding":
            continue
        if r.get("platform") != platform or r.get("account_hash") != account_hash:
            continue
        if best is None or (r.get("ts") or 0) > (best.get("ts") or 0):
            best = r
    return best


# ---------------------------------------------------------------------------
# Twitter cookie rotation marker
# ---------------------------------------------------------------------------

def set_cred_marker(platform: str, cred_hash: str) -> None:
    append_record({
        "kind": "cred",
        "ts": time.time(),
        "platform": platform,
        "cred_hash": cred_hash,
    })


def last_cred_marker(platform: str) -> Optional[dict]:
    best = None
    for r in read_records():
        if r.get("kind") != "cred" or r.get("platform") != platform:
            continue
        if best is None or (r.get("ts") or 0) > (best.get("ts") or 0):
            best = r
    return best


def redact(value: str) -> str:
    """Redact anything that looks like a credential/token/cookie value."""
    if not value:
        return value
    out = re.sub(r"(?i)((?:auth[_\-]?token|ct0|cookie|token|key|secret|password)[=:\s])([^\s\"'&]+)",
                 r"\1[REDACTED]", value)
    out = re.sub(r"gho_[A-Za-z0-9_]+", "gho_[REDACTED]", out)
    return out
