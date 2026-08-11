"""Todo 9: account allowlist, write gate, cookie gate, profiles."""

import os
import sys

import pytest

from reach_guard import session
from reach_guard.config import SessionError, load_config


def test_write_gate_blocked():
    with pytest.raises(SessionError):
        session.check_write_gate(["publish", "note"], allow_write=False)


def test_write_gate_allowed_with_flag():
    session.check_write_gate(["publish", "note"], allow_write=True)


def test_write_gate_read_ok():
    session.check_write_gate(["search", "python"], allow_write=False)


def test_xhs_requires_fresh_cookie():
    cfg = load_config()
    env = {}
    with pytest.raises(SessionError) as ei:
        session.check_cookie_gate(cfg, "xiaohongshu", env)
    assert "XHS_COOKIE" in str(ei.value)


def test_xhs_cookie_present():
    cfg = load_config()
    env = {"XHS_COOKIE": "fresh-cookie"}
    creds, anon, h = session.check_cookie_gate(cfg, "xiaohongshu", env)
    assert anon is False
    assert creds["XHS_COOKIE"] == "fresh-cookie"
    assert h != "anonymous"


def test_twitter_missing_creds_exit6():
    cfg = load_config()
    with pytest.raises(SessionError):
        session.check_cookie_gate(cfg, "twitter", {})


def test_twitter_creds_present():
    cfg = load_config()
    env = {"TWITTER_AUTH_TOKEN": "t1", "TWITTER_CT0": "c1"}
    creds, anon, h = session.check_cookie_gate(cfg, "twitter", env)
    assert anon is False
    assert len(h) == 64


def test_bili_non_anon_rejected_at_proxy_layer():
    cfg = load_config()
    cfg.bili_anon = False
    # cookie gate passes anonymously; the PROXY layer refuses (exit 3) because
    # bili-cli aiohttp ignores env proxy
    creds, anon, h = session.check_cookie_gate(cfg, "bilibili", {})
    assert anon is True and h == "anonymous"
    from reach_guard.proxy_layer import verify_binding
    from reach_guard.config import IPError
    import pytest as _p
    with _p.raises(IPError):
        verify_binding(cfg, "bilibili", h, None, anonymous=anon, live=False)


def test_bili_anon_ok():
    cfg = load_config()
    cfg.bili_anon = True
    creds, anon, h = session.check_cookie_gate(cfg, "bilibili", {})
    assert anon is True and h == "anonymous"


def test_allowlist_rejects_unregistered():
    cfg = load_config()
    with pytest.raises(SessionError):
        session.check_allowlist(cfg, "twitter", "f" * 64, anonymous=False)


def test_allowlist_accepts_registered(write_config):
    write_config("accounts:\n  twitter:\n    - label: burner\n      hash: "
                 + "f" * 64 + "\n")
    cfg = load_config()
    assert session.check_allowlist(cfg, "twitter", "f" * 64, False) == "burner"


def test_allowlist_anonymous_always_ok():
    cfg = load_config()
    assert session.check_allowlist(cfg, "v2ex", "anonymous", True) == "anonymous"


def test_twitter_rotation_warning_no_spam(capsys):
    cfg = load_config()
    session.twitter_rotation_warning(cfg, {"TWITTER_AUTH_TOKEN": "x",
                                           "TWITTER_CT0": "y"})
    err = capsys.readouterr().err
    assert "rotate" not in err


def test_account_identity_hash():
    env = {"TWITTER_AUTH_TOKEN": "abc", "TWITTER_CT0": "def"}
    creds = {k: env[k] for k in ("TWITTER_AUTH_TOKEN", "TWITTER_CT0")}
    h1 = session.account_identity("twitter", creds, False)
    h2 = session.account_identity("twitter", dict(sorted(creds.items())), False)
    assert h1 == h2
    assert len(h1) == 64
    assert session.account_identity("v2ex", {}, True) == "anonymous"
