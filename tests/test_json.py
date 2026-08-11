"""Phase 0 P0-2: `status --json` / `doctor --json` pinned whitelist schema.

The schema NEVER carries command strings, argv, ledger entries, or
credentials. If a field has no data it is null/absent per schema — no
invented fields.
"""

import datetime
import json
import time

from reach_guard.cli import main as cli_main
from reach_guard.config import (load_config, DEFAULT_PLATFORMS,
                                WRAPPED_BINARIES)
from reach_guard import state


def _main(*argv):
    return cli_main(list(argv))


TOP_KEYS = {"schema_version", "guard_version", "shims", "platforms",
            "quotas", "breakers", "time_window"}
PLATFORM_KEYS = {"status", "reason", "proxy_configured", "account_bound"}
QUOTA_KEYS = {"used_h", "limit_h", "used_d", "limit_d"}
BREAKER_KEYS = {"tier", "until"}
FORBIDDEN_KEYS = {"command", "argv", "args", "run_id", "ledger", "credentials",
                  "account_hash", "proxy_url", "secret", "password", "env"}


def _json_of(capsys):
    return json.loads(capsys.readouterr().out)


def _walk_assert_no_forbidden(node):
    if isinstance(node, dict):
        for k, v in node.items():
            assert k not in FORBIDDEN_KEYS, f"forbidden key {k!r} in JSON"
            _walk_assert_no_forbidden(v)
    elif isinstance(node, list):
        for it in node:
            _walk_assert_no_forbidden(it)


# ---------------------------------------------------------------------------
# schema shape
# ---------------------------------------------------------------------------

def test_status_json_schema_pinned(capsys):
    assert _main("status", "--json") == 0
    data = _json_of(capsys)
    assert set(data) == TOP_KEYS
    assert data["schema_version"] == 1
    assert data["guard_version"] == "0.1.1"
    assert set(data["shims"]) == set(WRAPPED_BINARIES)
    assert set(data["shims"].values()) <= {"shim", "real", "absent"}
    assert set(data["platforms"]) == set(DEFAULT_PLATFORMS)
    for pl, ent in data["platforms"].items():
        assert set(ent) == PLATFORM_KEYS
        assert ent["status"] in ("ok", "fail-closed")
        assert ent["reason"] in ("ok", "proxy", "cookie", "allowlist")
        assert isinstance(ent["proxy_configured"], bool)
        assert isinstance(ent["account_bound"], bool)
    assert set(data["quotas"]) == set(DEFAULT_PLATFORMS)
    for pl, q in data["quotas"].items():
        assert set(q) == QUOTA_KEYS
        assert all(isinstance(q[k], int) for k in q)
    assert set(data["breakers"]) == set(DEFAULT_PLATFORMS)
    for pl, b in data["breakers"].items():
        assert set(b) == BREAKER_KEYS
        assert b["tier"] in ("cooldown", "quarantine", "permanent", None)
        assert b["until"] is None or datetime.datetime.fromisoformat(b["until"])
    assert set(data["time_window"]) == {"enabled", "now_denied"}
    assert isinstance(data["time_window"]["enabled"], bool)
    assert isinstance(data["time_window"]["now_denied"], bool)


def test_doctor_json_emits_same_schema(capsys):
    assert _main("doctor", "--json") == 0
    data = _json_of(capsys)
    assert set(data) == TOP_KEYS
    assert data["schema_version"] == 1
    assert set(data["platforms"]) == set(DEFAULT_PLATFORMS)


def test_status_json_whitelist_only(capsys):
    """The JSON contains ONLY the pinned schema keys — no command/argv/credential
    fields anywhere in the tree."""
    assert _main("status", "--json") == 0
    data = _json_of(capsys)
    _walk_assert_no_forbidden(data)


def test_status_json_never_echoes_ledger(capsys):
    """A ledger record's command/argv must never leak into the JSON."""
    state.append_record({"ts": time.time(), "kind": "call",
                         "platform": "v2ex", "account_hash": "anonymous",
                         "command": "search SECRETMARKER123",
                         "bin": "curl", "exit": 0})
    assert _main("status", "--json") == 0
    raw = capsys.readouterr().out
    assert "SECRETMARKER123" not in raw
    assert "search" not in json.loads(raw)["quotas"]["v2ex"].values()


# ---------------------------------------------------------------------------
# platform status semantics (controlled env, no CLI stdout)
# ---------------------------------------------------------------------------

def test_report_platform_status_default():
    cfg = load_config()
    from reach_guard import report
    data = report.status_json(cfg, env={})
    pl = data["platforms"]
    # exempt + anon/optional-binding platforms run ok
    assert pl["github"]["status"] == "ok"
    assert pl["v2ex"]["status"] == "ok"
    assert pl["reddit"]["status"] == "ok"
    assert pl["youtube"]["status"] == "ok"
    # cookie-required platforms fail closed at the cookie gate (wrapper order)
    assert pl["xiaohongshu"]["status"] == "fail-closed"
    assert pl["xiaohongshu"]["reason"] == "cookie"
    assert pl["twitter"]["reason"] == "cookie"
    assert pl["instagram"]["reason"] == "cookie"
    # anon-ok platforms fail closed at binding when no proxy is configured
    assert pl["douyin"]["reason"] == "proxy"
    assert pl["bilibili"]["reason"] == "proxy"  # reject mode, bili_anon off
    assert pl["wechat"]["reason"] == "proxy"
    assert pl["douyin"]["proxy_configured"] is False
    assert pl["github"]["account_bound"] is False


def test_report_platform_status_with_proxy_creds_no_account(write_config):
    write_config("proxy:\n  - url: http://user:pass@1.2.3.4:8080\n")
    cfg = load_config()
    from reach_guard import report
    data = report.status_json(cfg, env={"XHS_COOKIE": "c",
                                        "TWITTER_AUTH_TOKEN": "t",
                                        "TWITTER_CT0": "c"})
    pl = data["platforms"]
    assert pl["xiaohongshu"]["proxy_configured"] is True
    # cookie gate passes now; allowlist (exit 6) is the next blocker
    assert pl["xiaohongshu"]["reason"] == "allowlist"
    assert pl["twitter"]["reason"] == "allowlist"
    assert pl["v2ex"]["status"] == "ok"
    assert pl["douyin"]["status"] == "ok"


def test_report_platform_status_all_ok(write_config):
    write_config("proxy:\n  - url: http://user:pass@1.2.3.4:8080\n"
                 "accounts:\n"
                 "  xiaohongshu:\n"
                 "    - label: burner\n"
                 "      hash: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
    cfg = load_config()
    from reach_guard import report
    data = report.status_json(cfg, env={"XHS_COOKIE": "c"})
    pl = data["platforms"]["xiaohongshu"]
    assert pl["account_bound"] is True
    assert pl["status"] == "ok"
    assert pl["reason"] == "ok"


def test_report_bili_anon_waives_proxy(write_config):
    write_config("bilibili:\n  anon: true\n")
    cfg = load_config()
    from reach_guard import report
    data = report.status_json(cfg, env={})
    assert data["platforms"]["bilibili"]["status"] == "ok"


# ---------------------------------------------------------------------------
# quotas / breakers / time window
# ---------------------------------------------------------------------------

def test_status_json_quotas_reflect_usage(capsys):
    now = time.time()
    for i in range(3):
        state.append_record({"ts": now - 10 + i, "platform": "v2ex",
                             "account_hash": "anonymous", "run_id": "r"})
    assert _main("status", "--json") == 0
    data = _json_of(capsys)
    q = data["quotas"]["v2ex"]
    assert q["used_h"] == 3
    assert q["used_d"] == 3
    assert q["limit_h"] == DEFAULT_PLATFORMS["v2ex"]["hourly"]
    assert q["limit_d"] == DEFAULT_PLATFORMS["v2ex"]["daily"]
    assert data["quotas"]["github"]["limit_h"] == \
        DEFAULT_PLATFORMS["github"]["hourly"]


def test_status_json_breakers(capsys):
    state.record_breaker("bilibili", "a" * 64, "cooldown", "412",
                         time.time() + 3600)
    state.record_breaker("twitter", "b" * 64, "quarantine", "429",
                         0, active=True)
    assert _main("status", "--json") == 0
    br = _json_of(capsys)["breakers"]
    assert br["bilibili"]["tier"] == "cooldown"
    datetime.datetime.fromisoformat(br["bilibili"]["until"])
    assert br["twitter"]["tier"] == "quarantine"
    assert br["twitter"]["until"] is None  # indefinite: null per schema
    assert br["v2ex"]["tier"] is None
    assert br["v2ex"]["until"] is None


def test_status_json_time_window(monkeypatch, capsys):
    from reach_guard import pacing
    monkeypatch.setattr(pacing, "in_deny_window", lambda c, p, t=None: True)
    assert _main("status", "--json") == 0
    tw = _json_of(capsys)["time_window"]
    assert tw["enabled"] is True
    assert tw["now_denied"] is True
    monkeypatch.setattr(pacing, "in_deny_window", lambda c, p, t=None: False)
    assert _main("status", "--json") == 0
    assert _json_of(capsys)["time_window"]["now_denied"] is False


# ---------------------------------------------------------------------------
# config error paths (JSON mode: stderr only, no stdout, same exit codes)
# ---------------------------------------------------------------------------

def test_status_json_config_error(capsys, write_config):
    write_config("bogus_key: 1\n")
    assert _main("status", "--json") == 2
    assert capsys.readouterr().out == ""


def test_doctor_json_config_error(capsys, write_config):
    write_config("bogus_key: 1\n")
    assert _main("doctor", "--json") == 2
    assert capsys.readouterr().out == ""
