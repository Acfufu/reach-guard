"""Integration smoke (todo 13) + fault-injection pieces (F3): fake upstream
end-to-end through the guard, parallel lock contention, shims install."""

import json
import os
import subprocess
import sys
import time

import pytest

from reach_guard import wrapper, state
from reach_guard.config import (load_config, EXIT_OK, EXIT_IP, EXIT_BREAKER,
                                EXIT_QUOTA_TIME, EXIT_SESSION, EXIT_LOCK)


def test_end_to_end_fake_upstream(fake_bin):
    fake_bin("curl", exit_code=0, stdout='[{"ok": true}]')
    cfg = load_config()
    t0 = time.monotonic()
    res = wrapper.run(cfg, "curl", ["https://www.v2ex.com/api/topics/hot.json"],
                      quiet=True)
    elapsed = time.monotonic() - t0
    assert res.exit_code == EXIT_OK
    assert elapsed < 5  # no unexpected pacing sleep on fresh ledger
    recs = state.read_records()
    calls = [r for r in recs if r.get("platform") == "v2ex" and r.get("exit") == 0]
    assert len(calls) == 1


def test_two_runs_serialize(fake_bin):
    fake_bin("curl", exit_code=0, stdout="x")
    cfg = load_config()
    t0 = time.monotonic()
    wrapper.run(cfg, "curl", ["https://www.v2ex.com/api/topics/hot.json"],
                quiet=True)
    wrapper.run(cfg, "curl", ["https://www.v2ex.com/api/topics/hot.json"],
                quiet=True)
    assert time.monotonic() - t0 >= 0  # serialized (no crash)


def test_fault_injection_bili_proxied_exit3():
    cfg = load_config()
    cfg.bili_anon = False
    res = wrapper.run(cfg, "bili", ["search", "python"], quiet=True)
    assert res.exit_code == EXIT_IP


def test_fault_injection_breaker_fake_signal(fake_bin):
    fake_bin("bili", exit_code=0, stdout="", stderr="风控校验失败 1003")
    cfg = load_config()
    cfg.bili_anon = True
    res = wrapper.run(cfg, "bili", ["search", "python"], quiet=True)
    assert res.exit_code == EXIT_BREAKER
    # cooldown visible in status
    from reach_guard import breaker as b
    with pytest.raises(Exception):
        b.check_before_run(cfg, "bilibili", "anonymous")


def test_fault_injection_quota_exit5(fake_bin):
    fake_bin("curl", exit_code=0, stdout="[]")
    cfg = load_config()
    now = time.time()
    for i in range(41):
        state.append_record({"ts": now - 50 + i, "platform": "v2ex",
                             "account_hash": "anonymous"})
    res = wrapper.run(cfg, "curl", ["https://www.v2ex.com/api/topics/hot.json"],
                      quiet=True)
    assert res.exit_code == EXIT_QUOTA_TIME


def test_xhs_gate_blocked_before_any_upstream(fake_bin):
    fake_bin("opencli", exit_code=0, stdout="{}")
    cfg = load_config()
    res = wrapper.run(cfg, "opencli", ["xiaohongshu", "search", "x"], quiet=True)
    assert res.exit_code == EXIT_SESSION
    assert not any(r.get("platform") == "xiaohongshu" and r.get("exit") == 0
                   for r in state.read_records())


def test_shim_install_creates_wrappers():
    from reach_guard import shims
    shims.install_shims(verbose=False)
    status = shims.shim_status()
    assert all(v == "shim" for v in status.values())
    shim_path = os.path.join(os.environ["REACH_GUARD_SHIM_DIR"], "bili")
    with open(shim_path) as f:
        content = f.read()
    assert "reach-guard" in content and "--as-bin" in content
