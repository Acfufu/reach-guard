"""Todo 5: clock-based pacing with jitter + time windows."""

import time
from datetime import datetime

import pytest

from reach_guard import pacing
from reach_guard.config import QuotaError, load_config


def test_required_wait_platform_interval():
    cfg = load_config()  # v2ex interval 5, jitter 2
    last = time.time() - 1
    from reach_guard import state
    state.append_record({"ts": last, "platform": "v2ex", "account_hash": "h1"})
    w = pacing.required_wait(cfg, "v2ex", "h1")
    # interval 5 +/- jitter 2 -> wait between 2 and 6s
    assert 1.0 <= w <= 7.0


def test_no_wait_when_fresh():
    cfg = load_config()
    from reach_guard import state
    state.append_record({"ts": time.time() - 60, "platform": "v2ex",
                         "account_hash": "h1"})
    assert pacing.required_wait(cfg, "v2ex", "h1") == 0.0


def test_clock_rollback_safe():
    cfg = load_config()
    from reach_guard import state
    future = time.time() + 3600  # clock "moved back" relative to ledger
    state.append_record({"ts": future, "platform": "v2ex", "account_hash": "h1"})
    w = pacing.required_wait(cfg, "v2ex", "h1")
    assert w >= 0.0  # clamped, never negative


def test_100_call_jitter_spread():
    cfg = load_config()
    from reach_guard import state
    waits = []
    for _ in range(100):
        state.append_record({"ts": time.time() - 5, "platform": "v2ex",
                             "account_hash": "h1"})
        waits.append(pacing.required_wait(cfg, "v2ex", "h1"))
    assert len(set(round(w, 1) for w in waits)) > 5  # jitter present


def test_global_interleave_5s():
    cfg = load_config()
    from reach_guard import state
    # recent call on a DIFFERENT platform must still enforce 5s global gap
    state.append_record({"ts": time.time() - 1, "platform": "bilibili",
                         "account_hash": "h1"})
    w = pacing.required_wait(cfg, "v2ex", "h2")
    assert w >= 3.99  # global 5s interleave applies cross-platform


def test_time_window_deny_exit5():
    cfg = load_config()
    d = datetime(2026, 8, 11, 23, 15)
    assert pacing.in_deny_window(cfg, "v2ex", d) is True
    with pytest.raises(QuotaError):
        pacing.enforce_time_window(cfg, "v2ex", d)


def test_time_window_allow_midday():
    cfg = load_config()
    d = datetime(2026, 8, 11, 12, 0)
    assert pacing.in_deny_window(cfg, "v2ex", d) is False


def test_deny_windows_default_present():
    cfg = load_config()
    assert cfg.time_windows == [(23 * 60, 9 * 60), (19 * 60, 22 * 60)]
