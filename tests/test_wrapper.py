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
    # curl allowlisted-host route (meta passthrough): no time window / quota
    # gates, so this subprocess test is deterministic at any wall-clock time.
    write_config("bilibili:\n  anon: true\n")
    shim_dir = os.environ["REACH_GUARD_SHIM_DIR"]
    with open(os.path.join(shim_dir, "curl.real"), "w") as f:
        f.write("#!/bin/sh\nsleep 30\n")
    os.chmod(os.path.join(shim_dir, "curl.real"), 0o755)
    cfg = load_config()
    cfg.bili_anon = True
    # run via CLI subprocess so we can SIGINT it
    py = sys.executable
    env = dict(os.environ)
    env["REACH_GUARD_CONFIG_DIR"] = os.environ["REACH_GUARD_CONFIG_DIR"]
    env["REACH_GUARD_STATE_DIR"] = os.environ["REACH_GUARD_STATE_DIR"]
    env["REACH_GUARD_SHIM_DIR"] = shim_dir
    proc = subprocess.Popen(
        [py, "-m", "reach_guard", "run", "curl", "https://r.jina.ai/x"],
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


# ---------------------------------------------------------------------------
# P0-4: credential argv scrubbing (stderr dispatch line + ledger command)
# ---------------------------------------------------------------------------

def test_scrub_positional_key_value():
    out = wrapper._scrub_command(["--twitter-cookies", "SECRET1", "search", "x"])
    assert "SECRET1" not in out
    assert "--twitter-cookies ***" in out


def test_scrub_equals_form():
    assert wrapper._scrub_command(["--xhs-cookies=SECRET2"]) == "--xhs-cookies=***"
    assert wrapper._scrub_command(["--token=a=b"]) == "--token=***"


def test_scrub_case_insensitive_key():
    assert wrapper._scrub_command(["--TOKEN=SECRET3"]) == "--TOKEN=***"
    out = wrapper._scrub_command(["--Twitter-Cookies", "SECRET4"])
    assert "SECRET4" not in out and "***" in out


def test_scrub_all_sensitive_keys():
    args = ["--twitter-cookies", "VAL1", "--xhs-cookies", "VAL2",
            "--youtube-cookies", "VAL3", "--github-token", "VAL4",
            "--groq-key", "VAL5", "--openai-key", "VAL6", "--proxy", "VAL7",
            "--auth_token", "VAL8", "--ct0", "VAL9", "--password", "VAL10",
            "--token", "VAL11", "--cookie", "VAL12", "--cookies", "VAL13"]
    out = wrapper._scrub_command(args)
    for v in ("VAL1", "VAL2", "VAL3", "VAL4", "VAL5", "VAL6", "VAL7",
              "VAL8", "VAL9", "VAL10", "VAL11", "VAL12", "VAL13"):
        assert v not in out
    assert out.count("***") == 13


def test_scrub_false_positive_protection():
    """A value is only redacted when it follows a sensitive key."""
    assert wrapper._scrub_command(["403"]) == "403"
    assert wrapper._scrub_command(["\\u5403"]) == "\\u5403"
    assert wrapper._scrub_command(["search", "python", "403", "\\u5403"]) \
        == "search python 403 \\u5403"
    assert "***" not in wrapper._scrub_command(["--limit", "10", "--json"])


def test_scrub_long_benign_list_unaffected():
    args = ["search", "python", "--limit", "10", "--json", "--sort", "top",
            "keyword", "page", "2"]
    assert wrapper._scrub_command(args) == " ".join(args)


def test_stderr_dispatch_line_scrubbed(fake_bin, capsys):
    fake_bin("gh", exit_code=0, stdout="ok")
    cfg = load_config()
    wrapper.run(cfg, "gh", ["api", "--token", "TOPSCRET"], quiet=False)
    err = capsys.readouterr().err
    assert "TOPSCRET" not in err
    assert "***" in err


def test_ledger_command_scrubbed(fake_bin):
    fake_bin("gh", exit_code=0, stdout="ok")
    cfg = load_config()
    wrapper.run(cfg, "gh", ["api", "--token", "LEDGERSECRET"])
    for r in state.read_records():
        assert "LEDGERSECRET" not in json.dumps(r)
    assert any("***" in r.get("command", "") for r in state.read_records())


def test_ledger_never_contains_raw_configure_creds(fake_bin):
    fake_bin("agent-reach", exit_code=0, stdout="")
    cfg = load_config()
    wrapper.run(cfg, "agent-reach",
                ["configure", "--xhs-cookies", "RAWCOOKIE123"])
    for r in state.read_records():
        assert "RAWCOOKIE123" not in json.dumps(r)


def test_scrub_403_value_after_key(fake_bin, capsys):
    fake_bin("gh", exit_code=0, stdout="ok")
    cfg = load_config()
    wrapper.run(cfg, "gh", ["api", "--token", "403"], quiet=False)
    err = capsys.readouterr().err
    assert "403" not in err  # redacted because it followed a sensitive key


# ---------------------------------------------------------------------------
# Recursion guard: a wrapped real binary that re-execs its own name via PATH
# (opencli spawns helper children; gh self-executes) must not re-enter the
# shim/guard forever. Same-bin re-entry executes the real binary directly;
# different-bin nesting (agent-reach -> bili) stays fully guarded.
# ---------------------------------------------------------------------------

def _make_popen_capture(monkeypatch, calls):
    class FakePopen:
        def __init__(self, argv, **kwargs):
            calls.append((argv, kwargs.get("env")))
            self.returncode = 0

        def communicate(self):
            return b"", b""

        def wait(self):
            return 0

    monkeypatch.setattr(wrapper.subprocess, "Popen", FakePopen)


def test_self_recursion_same_bin_bypasses_guard(fake_bin, monkeypatch, capsys):
    fake_bin("gh", exit_code=0, stdout="gh version 1.0")
    calls = []
    _make_popen_capture(monkeypatch, calls)
    monkeypatch.setenv("REACH_GUARD_DISPATCH_BIN", "gh")
    cfg = load_config()
    res = wrapper.run(cfg, "gh", ["--version"])
    assert res.exit_code == EXIT_OK
    assert "self-recursion bypass" in capsys.readouterr().err
    # exactly one hop, straight to the real binary — no guard re-entry
    assert len(calls) == 1
    argv = calls[0][0]
    assert argv[0].endswith("gh.real") and argv[1:] == ["--version"]
    # the bypass hop writes no ledger records
    recs = state.read_records()
    assert not any(r.get("bin") == "gh" for r in recs)


def test_self_recursion_different_bin_still_guarded(fake_bin, monkeypatch,
                                                    capsys):
    fake_bin("gh", exit_code=0, stdout="gh version 1.0")
    calls = []
    _make_popen_capture(monkeypatch, calls)
    monkeypatch.setenv("REACH_GUARD_DISPATCH_BIN", "agent-reach")
    cfg = load_config()
    res = wrapper.run(cfg, "gh", ["--version"])
    assert res.exit_code == EXIT_OK
    assert "self-recursion bypass" not in capsys.readouterr().err
    assert len(calls) == 1


def test_self_recursion_missing_real_exit8(monkeypatch, capsys):
    monkeypatch.setenv("REACH_GUARD_DISPATCH_BIN", "gh")
    monkeypatch.setattr(wrapper, "find_real_binary", lambda bin_name: None)
    cfg = load_config()
    res = wrapper.run(cfg, "gh", ["--version"])
    assert res.exit_code == EXIT_UPSTREAM
