"""Clock-based pacing with jitter + time-window gate.

Clock-base (not sleep chains) prevents drift across many calls. Each platform
enforces its own minimum interval plus random jitter; a global 5s interleave
applies between ANY two guarded calls. Time windows (TZ=Asia/Shanghai) deny
execution in default windows 23:00-09:00 and 19:00-22:00 -> exit 5. Clock
rollback is tolerated by clamping the computed wait to >= 0.
"""

from __future__ import annotations

import random
import time
import zoneinfo
from datetime import datetime
from typing import Optional

from .config import Config, QuotaError
from .state import latest_call_ts, all_calls_since

GLOBAL_INTERLEAVE = 5.0  # seconds between any two guarded calls

TZ = "Asia/Shanghai"


def _now_tz() -> datetime:
    try:
        return datetime.now(zoneinfo.ZoneInfo(TZ))
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        return datetime.now()


def _minutes_since_midnight(dt: datetime) -> int:
    return dt.hour * 60 + dt.minute


def in_deny_window(cfg: Config, platform: str, now_tz: Optional[datetime] = None) -> bool:
    dt = now_tz or _now_tz()
    mins = _minutes_since_midnight(dt)
    windows = cfg.platform(platform).get("windows") or cfg.time_windows
    for start, end in windows:
        if start <= end:
            if start <= mins < end:
                return True
        else:  # wraps midnight, e.g. 23:00-09:00
            if mins >= start or mins < end:
                return True
    return False


def required_wait(cfg: Config, platform: str, account_hash: str,
                  now: Optional[float] = None) -> float:
    """Seconds to wait before the next call (>= 0, clock-rollback safe)."""
    now = now or time.time()
    pcfg = cfg.platform(platform)
    if pcfg.get("proxy_mode") == "none" or platform == "github":
        return 0.0
    interval = float(pcfg.get("interval", 0))
    jitter = float(pcfg.get("jitter", 0))
    eff_interval = max(0.0, interval + random.uniform(-jitter, jitter))

    last_platform = latest_call_ts(platform=platform, account_hash=account_hash)
    last_global = latest_call_ts()

    wait_platform = max(0.0, eff_interval - (now - last_platform))
    wait_global = max(0.0, GLOBAL_INTERLEAVE - (now - last_global))
    return max(wait_platform, wait_global)


def enforce_time_window(cfg: Config, platform: str,
                        now_tz: Optional[datetime] = None) -> None:
    if in_deny_window(cfg, platform, now_tz):
        raise QuotaError(
            f"time window blocked (TZ={TZ}, platform={platform}): current window "
            f"is deny-listed; exit 5"
        )


def wait_for(cfg: Config, platform: str, account_hash: str,
             dry_run: bool = False) -> float:
    """Wait (or report) the required inter-call gap."""
    wait = required_wait(cfg, platform, account_hash)
    if dry_run:
        if wait > 0:
            print(f"[reach-guard dry-run] would wait {wait:.1f}s "
                  f"(pacing {platform})")
        return wait
    if wait > 0:
        time.sleep(wait)
    return wait
