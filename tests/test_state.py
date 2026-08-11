"""Todo 3: append-only state ledger, rotation, perms, corrupt-line tolerance."""

import json
import os
import time

from reach_guard import state
from reach_guard.config import STATE_FILE, STATE_DIR


def _rec(**kw):
    r = {"ts": time.time(), "platform": "bilibili", "account_hash": "anon",
         "proxy_ip": "", "bin": "bili", "command": "search x", "exit": 0}
    r.update(kw)
    return r


def test_append_read_roundtrip():
    state.append_record(_rec(platform="v2ex", exit=0))
    state.append_record(_rec(platform="v2ex", exit=8))
    recs = state.read_records()
    assert len(recs) == 2
    assert recs[0]["platform"] == "v2ex"
    assert recs[1]["exit"] == 8


def test_file_mode_0600():
    state.append_record(_rec())
    assert (os.stat(STATE_FILE).st_mode & 0o777) == 0o600


def test_dir_mode_0700():
    assert (os.stat(STATE_DIR).st_mode & 0o777) == 0o700


def test_corrupt_line_skipped():
    state.append_record(_rec())
    with open(STATE_FILE, "a") as f:
        f.write("{not json\n")
        f.write("garbage\n")
    state.append_record(_rec(platform="v2ex"))
    recs = state.read_records()
    assert len(recs) == 2  # corrupt lines skipped, no crash


def test_counts_window():
    now = time.time()
    state.append_record(_rec(ts=now - 50, platform="v2ex", account_hash="h1"))
    state.append_record(_rec(ts=now - 5000, platform="v2ex", account_hash="h1"))
    assert state.counts("v2ex", "h1", now - 10000) == 2
    assert state.counts("v2ex", "h1", now - 1000) == 1
    assert state.counts("v2ex", "other", now - 10000) == 0


def test_batch_count_by_run_id():
    state.append_record(_rec(run_id="R1"))
    state.append_record(_rec(run_id="R1"))
    state.append_record(_rec(run_id="R2"))
    assert state.count_batch("R1") == 2
    assert state.count_batch("R2") == 1


def test_rotation_to_dot1(tmp_path):
    state.append_record(_rec())
    old = state.STATE_FILE
    past = time.time() - 61 * 86400
    os.utime(old, (past, past))
    state.append_record(_rec(platform="v2ex"))
    assert os.path.exists(old + ".1")
    recs = state.read_records()
    assert len(recs) == 2


def test_breaker_cooldown_roundtrip():
    h = "a" * 64
    state.record_breaker("bilibili", h, "cooldown", "412", time.time() + 3600)
    tier, until = state.breaker_active("bilibili", h, time.time())
    assert tier == "cooldown"
    assert until > time.time()


def test_breaker_expired_not_active():
    h = "b" * 64
    state.record_breaker("bilibili", h, "cooldown", "412", time.time() - 10)
    assert state.breaker_active("bilibili", h, time.time()) is None


def test_unlock_clears_quarantine():
    h = "c" * 64
    state.record_breaker("twitter", h, "quarantine", "429", 0, active=True)
    assert state.breaker_active("twitter", h, time.time())[0] == "quarantine"
    assert state.unlock("twitter", h) is True
    assert state.breaker_active("twitter", h, time.time()) is None


def test_permanent_cannot_unlock():
    h = "d" * 64
    state.record_breaker("twitter", h, "permanent", "suspended", 0, active=True)
    assert state.unlock("twitter", h) is False


def test_binding_roundtrip():
    h = "e" * 64
    state.bind_account("twitter", h, "http://1.2.3.4:8080")
    b = state.binding_for("twitter", h)
    assert b and b["proxy_url"] == "http://1.2.3.4:8080"


def test_redact_credentials():
    s = "token=secret123 cookie=abc123; TWITTER_AUTH_TOKEN=xyz gho_abc123"
    out = state.redact(s)
    assert "secret123" not in out
    assert "abc123" not in out
    assert "xyz" not in out
    assert "gho_abc123" not in out
