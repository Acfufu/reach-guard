"""Todo 6: token-bucket quota (hourly + daily + batch)."""

import time

import pytest

from reach_guard import quota
from reach_guard.config import QuotaError, load_config
from reach_guard import state


def _seed(cfg, platform, account, n, since_ago=100):
    ts = time.time() - since_ago
    for i in range(n):
        state.append_record({"ts": ts + i, "platform": platform,
                             "account_hash": account, "run_id": "seed",
                             "exit": 0})


def test_within_quota_ok():
    cfg = load_config()
    quota.check_quota(cfg, "v2ex", "anonymous", "runA")  # v2ex daily 500


def test_hourly_exceeded_exit5():
    cfg = load_config()  # v2ex hourly 41
    _seed(cfg, "v2ex", "h1", 41, since_ago=1800)
    with pytest.raises(QuotaError) as ei:
        quota.check_quota(cfg, "v2ex", "h1", "runB")
    assert "exit 5" in str(ei.value)


def test_daily_exceeded_exit5():
    cfg = load_config()  # v2ex daily 500
    _seed(cfg, "v2ex", "h1", 500, since_ago=12 * 3600)
    with pytest.raises(QuotaError):
        quota.check_quota(cfg, "v2ex", "h1", "runC")


def test_batch_exceeded_exit5():
    cfg = load_config()  # v2ex batch 20
    _seed(cfg, "v2ex", "h1", 20, since_ago=100)
    with pytest.raises(QuotaError) as ei:
        quota.check_quota(cfg, "v2ex", "h1", "seed")  # same run_id as seeds
    assert "session-batch" in str(ei.value)


def test_recovery_message_has_time():
    cfg = load_config()
    _seed(cfg, "v2ex", "h1", 41, since_ago=1800)
    try:
        quota.check_quota(cfg, "v2ex", "h1", "runD")
    except QuotaError as e:
        assert "recovers" in str(e)
        assert "exit 5" in str(e)


def test_old_calls_not_counted():
    cfg = load_config()
    _seed(cfg, "v2ex", "h1", 500, since_ago=2 * 86400)
    quota.check_quota(cfg, "v2ex", "h1", "runE")  # outside 24h window


def test_github_exempt():
    cfg = load_config()
    quota.check_quota(cfg, "github", "anonymous", "runF")  # never blocks


def test_quota_usage_report():
    cfg = load_config()
    _seed(cfg, "v2ex", "h1", 3, since_ago=100)
    u = quota.quota_usage(cfg, "v2ex", "h1")
    assert u["hourly"][0] == 3
    assert u["daily"][0] == 3
