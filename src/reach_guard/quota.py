"""Token-bucket quota: hourly + daily + session-batch, persisted via ledger.

- hourly = per-rolling-hour count (limit from strict table, hourly=daily/12 by
  design for auto-derived rows)
- daily  = per-rolling-day count
- batch  = calls within one `run` invocation (run_id); a run makes 1 call, so
  the batch gate only trips for runaway multi-call sessions (unit-testable)
Recovery time message says when the oldest counted call falls out of the window.
Rejection -> exit 5.
"""

from __future__ import annotations

import time
from typing import Optional

from .config import Config, QuotaError
from .state import counts, count_batch, read_records

HOUR = 3600.0
DAY = 86400.0


def _recovery_message(limit: int, window: float, since: float) -> str:
    records = [
        r for r in read_records()
        if r.get("ts", 0) >= since
    ]
    oldest = min((r.get("ts", 0) for r in records), default=0.0)
    recovery = oldest + window
    hhmm = time.strftime("%H:%M:%S", time.localtime(recovery))
    return f"quota exhausted ({limit}/{window/3600:.0f}h window); recovers ~{hhmm}"


def check_quota(cfg: Config, platform: str, account_hash: str,
                run_id: str, now: Optional[float] = None) -> None:
    now = now or time.time()
    pcfg = cfg.platform(platform)
    if platform == "github":
        return  # exempt
    hourly = int(pcfg.get("hourly", max(1, int(pcfg.get("daily", 0)) // 12)))
    daily = int(pcfg.get("daily", 0))
    batch = int(pcfg.get("batch", 1))

    h_count = counts(platform, account_hash, now - HOUR)
    if h_count >= hourly:
        raise QuotaError(
            _recovery_message(hourly, HOUR, now - HOUR)
            + f" (hourly limit {hourly}); exit 5"
        )
    d_count = counts(platform, account_hash, now - DAY)
    if d_count >= daily:
        raise QuotaError(
            _recovery_message(daily, DAY, now - DAY)
            + f" (daily limit {daily}); exit 5"
        )
    b_count = count_batch(run_id)
    if b_count >= batch:
        raise QuotaError(
            f"session-batch limit {batch} reached for this run; exit 5"
        )


def quota_usage(cfg: Config, platform: str, account_hash: str,
                now: Optional[float] = None) -> dict:
    now = now or time.time()
    pcfg = cfg.platform(platform)
    hourly = int(pcfg.get("hourly", max(1, int(pcfg.get("daily", 0)) // 12)))
    daily = int(pcfg.get("daily", 0))
    return {
        "hourly": (counts(platform, account_hash, now - HOUR), hourly),
        "daily": (counts(platform, account_hash, now - DAY), daily),
    }
