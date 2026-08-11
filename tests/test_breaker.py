"""Todo 7: risk-signal circuit breaker (triple mapping + whitelist)."""

import time

import pytest

from reach_guard import breaker, state
from reach_guard.config import BreakerError, load_config


def _cfg():
    return load_config()


def _enforce(cfg, platform, signal_text, args=("search", "x"), rc=0,
             anonymous=False, account="h1", stdout=None, stderr=None):
    out = stdout if stdout is not None else signal_text
    err = stderr or ""
    breaker.enforce(cfg, platform, account, args, out, err, rc, anonymous)


def test_cooldown_signal_exit7():
    cfg = _cfg()
    with pytest.raises(BreakerError) as ei:
        _enforce(cfg, "bilibili", "412 风控校验失败")
    assert "exit 7" in str(ei.value)
    tier, until = state.breaker_active("bilibili", "h1", time.time())
    assert tier == "cooldown"
    assert until - time.time() >= 23 * 3600


def test_permanent_signal_exit7():
    cfg = _cfg()
    with pytest.raises(BreakerError) as ei:
        _enforce(cfg, "twitter", "your account has been suspended")
    assert "permanent" in str(ei.value)
    assert state.breaker_active("twitter", "h1", time.time())[0] == "permanent"


def test_quarantine_second_strike():
    cfg = _cfg()
    # strike 1 -> cooldown
    with pytest.raises(BreakerError):
        _enforce(cfg, "bilibili", "412", account="q1")
    # strike 2 within 7d -> quarantine
    with pytest.raises(BreakerError) as ei:
        _enforce(cfg, "bilibili", "412 again", account="q1")
    assert "quarantin" in str(ei.value).lower()
    assert state.breaker_active("bilibili", "q1", time.time())[0] == "quarantine"


def test_whitelist_douyin_hotsearch_not_tripped():
    cfg = _cfg()
    # anonymous douyin hotsearch "请先登录" must NOT trip
    result = breaker.scan(cfg, "douyin", ["hotsearch"],
                          "请先登录", "", 0, anonymous=True)
    assert result is None


def test_whitelist_weibo_anon_432():
    cfg = _cfg()
    assert breaker.scan(cfg, "weibo", ["search", "x"], "432", "", 0,
                        anonymous=True) is None
    # non-anonymous 432 still trips
    assert breaker.scan(cfg, "weibo", ["search", "x"], "432", "", 0,
                        anonymous=False) is not None


def test_whitelist_xhs_expiry_anon():
    cfg = _cfg()
    assert breaker.scan(cfg, "xiaohongshu", ["search", "x"],
                        "登录已过期", "", 0, anonymous=True) is None


def test_200_empty_heuristic():
    cfg = _cfg()
    assert breaker.scan(cfg, "douyin", ["search", "x"], "", "", 0,
                        anonymous=False) == "200-empty-heuristic"
    # non-empty output does not trigger
    assert breaker.scan(cfg, "douyin", ["search", "x"], "data", "", 0,
                        anonymous=False) is None


def test_breaker_preflight_blocks():
    cfg = _cfg()
    state.record_breaker("bilibili", "h1", "cooldown", "412", time.time() + 3600)
    with pytest.raises(BreakerError):
        breaker.check_before_run(cfg, "bilibili", "h1")
    # cooldown is platform-wide: other accounts also blocked
    with pytest.raises(BreakerError):
        breaker.check_before_run(cfg, "bilibili", "someone-else")
    # other platform unaffected
    breaker.check_before_run(cfg, "v2ex", "h1")


def test_numeric_signal_requires_digit_boundary():
    """Bare numeric codes must not match inside unicode escapes or progress
    meters: v2ex content '\u5403' (吃) contains '403' but must not trip; an
    HTTP 'error: 403' status must trip."""
    cfg = _cfg()
    assert breaker.scan(cfg, "v2ex", ["curl"],
                        '{"content": "\\u5403\\u5403 吃"}', "", 0,
                        anonymous=True) is None
    assert breaker.scan(cfg, "v2ex", ["curl"],
                        "The requested URL returned error: 403", "", 0,
                        anonymous=True) is not None
    assert breaker.scan(cfg, "v2ex", ["curl"],
                        '{"code": 403, "msg": "rate limited"}', "", 0,
                        anonymous=True) is not None


def test_progress_meter_noise_never_trips():
    cfg = _cfg()
    meter = ("  0   429    0   429     0     0  154k      0 --:--:-- "
             "--:--:-- --:--:-- 154k")
    assert breaker.scan(cfg, "v2ex", ["curl"], "", meter, 0,
                        anonymous=True) is None
    # a real error line is preserved and trips
    assert breaker.scan(cfg, "v2ex", ["curl"], "",
                        "curl: (22) The requested URL returned error: 429", 0,
                        anonymous=True) is not None
