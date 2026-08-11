"""Todo 10: guarded dispatch wrapper + shims behavior."""

import json
import os
import subprocess
import sys
import time

import pytest

from reach_guard import wrapper
from reach_guard.config import (load_config, EXIT_OK, EXIT_UPSTREAM,
                                EXIT_SESSION, EXIT_IP, EXIT_BREAKER,
                                EXIT_QUOTA_TIME, EXIT_CONFIG)
from reach_guard import state


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    # never hit the real network from wrapper tests (no proxies configured)
    monkeypatch.setenv("XHS_COOKIE", "")


def _run(cfg, bin_name, args, **kw):
    return wrapper.run(cfg, bin_name, args, **kw)


def test_happy_v2ex_curl(fake_bin):
    fake_bin("curl", exit_code=0,
             stdout='[{"node": {"title": "hello v2ex"}}]')
    cfg = load_config()
    res = _run(cfg, "curl", ["https://www.v2ex.com/api/topics/hot.json"])
    assert res.exit_code == EXIT_OK
    recs = state.read_records()
    assert any(r.get("platform") == "v2ex" and r.get("exit") == 0 for r in recs)


def test_missing_binary_exit8():
    cfg = load_config()  # no fake bili planted
    cfg.bili_anon = True
    res = _run(cfg, "bili", ["search", "x"])
    assert res.exit_code == EXIT_UPSTREAM


def test_unknown_binary_exit8():
    cfg = load_config()
    res = _run(cfg, "weirdbin", [])
    assert res.exit_code == EXIT_UPSTREAM


def test_dry_run_no_execution(fake_bin, tmp_path):
    marker = tmp_path / "ran"
    shim_dir = os.environ["REACH_GUARD_SHIM_DIR"]
    with open(os.path.join(shim_dir, "curl.real"), "w") as f:
        f.write("#!/bin/sh\n"
                f"touch {marker}\n"
                "exit 0\n")
    os.chmod(os.path.join(shim_dir, "curl.real"), 0o755)
    cfg = load_config()
    res = _run(cfg, "curl", ["https://www.v2ex.com/api/topics/hot.json"],
               dry_run=True)
    assert res.exit_code == EXIT_OK
    assert not marker.exists()


def test_xhs_no_cookie_exit6():
    cfg = load_config()
    res = _run(cfg, "opencli", ["xiaohongshu", "search", "x"])
    assert res.exit_code == EXIT_SESSION


def test_bili_non_anon_exit3():
    cfg = load_config()
    cfg.bili_anon = False
    res = _run(cfg, "bili", ["search", "python"])
    assert res.exit_code == EXIT_IP


def test_bili_anon_ok(fake_bin):
    fake_bin("bili", exit_code=0, stdout="ok: true")
    cfg = load_config()
    cfg.bili_anon = True
    res = _run(cfg, "bili", ["search", "python"])
    assert res.exit_code == EXIT_OK


def test_twitter_no_proxy_exit3(monkeypatch, write_config):
    monkeypatch.setenv("TWITTER_AUTH_TOKEN", "t")
    monkeypatch.setenv("TWITTER_CT0", "c")
    from reach_guard import session as s
    chash = s.account_identity("twitter", {"TWITTER_AUTH_TOKEN": "t",
                                           "TWITTER_CT0": "c"}, False)
    write_config("accounts:\n  twitter:\n    - label: burner\n      hash: "
                 + chash + "\n")
    cfg = load_config()
    res = _run(cfg, "twitter", ["search", "x"], quiet=True)
    assert res.exit_code == EXIT_IP  # fail-closed: no proxy on this machine


def test_breaker_wins_over_upstream_zero(fake_bin):
    fake_bin("bili", exit_code=0, stdout="", stderr="412 风控校验失败")
    cfg = load_config()
    cfg.bili_anon = True
    res = _run(cfg, "bili", ["search", "python"])
    assert res.exit_code == EXIT_BREAKER  # breaker wins even on exit 0


def test_breaker_wins_over_upstream_error(fake_bin):
    fake_bin("bili", exit_code=3, stdout="suspended", stderr="")
    cfg = load_config()
    cfg.bili_anon = True
    res = _run(cfg, "bili", ["search", "python"])
    assert res.exit_code == EXIT_BREAKER  # breaker beats upstream error


def test_upstream_error_exit8(fake_bin):
    fake_bin("bili", exit_code=2, stdout="boom")
    cfg = load_config()
    cfg.bili_anon = True
    res = _run(cfg, "bili", ["search", "python"])
    assert res.exit_code == EXIT_UPSTREAM
    assert res.upstream_exit == 2


def test_quota_exit5(fake_bin):
    fake_bin("curl", exit_code=0, stdout="[]")
    cfg = load_config()
    now = time.time()
    for i in range(41):
        state.append_record({"ts": now - 100 + i, "platform": "v2ex",
                             "account_hash": "anonymous", "run_id": "seed"})
    res = _run(cfg, "curl", ["https://www.v2ex.com/api/topics/hot.json"])
    assert res.exit_code == EXIT_QUOTA_TIME


def test_time_window_exit5(fake_bin, monkeypatch):
    fake_bin("curl", exit_code=0, stdout="[]")
    cfg = load_config()
    monkeypatch.setattr(wrapper.pacing, "in_deny_window",
                        lambda c, p, t=None: True)
    res = _run(cfg, "curl", ["https://www.v2ex.com/api/topics/hot.json"])
    assert res.exit_code == EXIT_QUOTA_TIME


def test_write_gate_exit6(fake_bin):
    fake_bin("bili", exit_code=0, stdout="ok")
    cfg = load_config()
    cfg.bili_anon = True
    res = _run(cfg, "bili", ["comment", "42"])  # write keyword
    assert res.exit_code == EXIT_SESSION
    res2 = _run(cfg, "bili", ["comment", "42"], allow_write=True)
    assert res2.exit_code == EXIT_OK


def test_gh_exempt_passthrough(fake_bin):
    fake_bin("gh", exit_code=0, stdout="rate data")
    cfg = load_config()
    res = _run(cfg, "gh", ["api", "rate_limit"])
    assert res.exit_code == EXIT_OK
    recs = state.read_records()
    assert any(r.get("exempt") is True and r.get("platform") == "github"
               for r in recs)


def test_opencli_meta_passthrough(fake_bin):
    fake_bin("opencli", exit_code=0, stdout="adapter list")
    cfg = load_config()
    res = _run(cfg, "opencli", ["list"])
    assert res.exit_code == EXIT_OK


def test_sigint_records_interrupted(fake_bin, write_config):
    write_config("bilibili:\n  anon: true\n")
    shim_dir = os.environ["REACH_GUARD_SHIM_DIR"]
    with open(os.path.join(shim_dir, "bili.real"), "w") as f:
        f.write("#!/bin/sh\nsleep 30\n")
    os.chmod(os.path.join(shim_dir, "bili.real"), 0o755)
    cfg = load_config()
    cfg.bili_anon = True
    # run via CLI subprocess so we can SIGINT it
    py = sys.executable
    env = dict(os.environ)
    env["REACH_GUARD_CONFIG_DIR"] = os.environ["REACH_GUARD_CONFIG_DIR"]
    env["REACH_GUARD_STATE_DIR"] = os.environ["REACH_GUARD_STATE_DIR"]
    env["REACH_GUARD_SHIM_DIR"] = shim_dir
    proc = subprocess.Popen(
        [py, "-m", "reach_guard", "run", "bili", "search", "x"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=os.path.join(os.path.dirname(__file__), "..", "src"))
    time.sleep(1.5)
    proc.send_signal(2)  # SIGINT
    proc.wait(timeout=10)
    recs = state.read_records()
    assert any(r.get("interrupted") is True for r in recs)


def test_find_real_binary_prefers_dot_real(fake_bin):
    fake_bin("curl", exit_code=0, stdout="")
    path = wrapper.find_real_binary("curl")
    assert path and path.endswith("curl.real")
