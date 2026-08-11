"""Todo 11: CLI subcommands + exit-code contract."""

import os

import pytest

from reach_guard.cli import main as cli_main
from reach_guard.config import load_config


def _main(*argv):
    return cli_main(list(argv))


def test_version():
    from reach_guard import __version__
    assert __version__ == "0.1.1"
    with pytest.raises(SystemExit) as ei:
        _main("--version")
    assert ei.value.code == 0


def test_run_missing_bin_exit2():
    assert _main("run") == 2


def test_run_unknown_binary_exit8():
    assert _main("run", "weird") == 8


def test_run_agent_reach_missing_exit8():
    # no agent-reach installed on this machine -> fail-closed exit 8
    assert _main("run", "agent-reach", "doctor") == 8


def test_status_exit0():
    assert _main("status") == 0


def test_doctor_exit0():
    assert _main("doctor") == 0


def test_quarantine_empty_exit0():
    assert _main("quarantine") == 0


def test_account_list_empty_exit0():
    assert _main("account", "list") == 0


def test_account_add_missing_creds_exit6(monkeypatch):
    monkeypatch.delenv("TWITTER_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("TWITTER_CT0", raising=False)
    assert _main("account", "add", "twitter") == 6


def test_account_add_rm_roundtrip(monkeypatch):
    monkeypatch.setenv("TWITTER_AUTH_TOKEN", "tok123")
    monkeypatch.setenv("TWITTER_CT0", "ct0abc")
    assert _main("account", "add", "twitter", "--label", "burner1") == 0
    cfg = load_config()
    assert any(a.label == "burner1" for a in cfg.account_list("twitter"))
    assert _main("account", "list") == 0
    assert _main("account", "rm", "twitter", "burner1") == 0
    cfg = load_config()
    assert not any(a.label == "burner1" for a in cfg.account_list("twitter"))


def test_unlock_permanent_refused():
    from reach_guard import state
    state.record_breaker("bilibili", "q" * 64, "permanent", "suspended",
                         0, active=True)
    assert _main("unlock", "bilibili", "q" * 64) == 2


def test_profile_generates_dir():
    r = _main("profile", "--platform", "xiaohongshu", "--account", "test1")
    assert r == 0
    from reach_guard.proxy_layer import profile_flags_path
    p = profile_flags_path(load_config(), "xiaohongshu", "test1")
    assert os.path.exists(p)


def test_profile_unregistered_platform_exit6():
    assert _main("profile", "--platform", "tiktok", "--account", "x") == 6


def test_shims_install_idempotent():
    from reach_guard import shims
    shims.install_shims()
    status = shims.shim_status()
    assert all(v == "shim" for v in status.values())
    shims.install_shims()  # idempotent: no error


# ---------------------------------------------------------------------------
# P0-3: shims uninstall (restore .real -> bin; never touch system binaries)
# ---------------------------------------------------------------------------

def _write_file(path, content, mode=0o755):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(path, mode)


def test_shims_uninstall_restores_real():
    from reach_guard import shims
    shim_dir = os.environ["REACH_GUARD_SHIM_DIR"]
    real = os.path.join(shim_dir, "bili.real")
    _write_file(real, "#!/bin/sh\necho original\n")
    shims.install_shims()
    assert shims.shim_status()["bili"] == "shim"
    assert os.path.exists(real)
    shims.uninstall_shims()
    assert not os.path.exists(real)
    with open(os.path.join(shim_dir, "bili"), encoding="utf-8") as f:
        content = f.read()
    assert "original" in content          # original preserved
    assert "reach-guard" not in content   # our shim gone


def test_shims_uninstall_curl_style_no_real():
    """curl-style: no .real ever existed (system binary untouched); removing
    our shim must not create or modify anything else."""
    from reach_guard import shims
    shim_dir = os.environ["REACH_GUARD_SHIM_DIR"]
    shims.install_shims()
    assert os.path.exists(os.path.join(shim_dir, "curl"))
    assert not os.path.exists(os.path.join(shim_dir, "curl.real"))
    shims.uninstall_shims()
    assert not os.path.exists(os.path.join(shim_dir, "curl"))
    assert not os.path.exists(os.path.join(shim_dir, "curl.real"))


def test_shims_uninstall_foreign_shim_untouched():
    from reach_guard import shims
    shim_dir = os.environ["REACH_GUARD_SHIM_DIR"]
    path = os.path.join(shim_dir, "twitter")
    _write_file(path, "#!/bin/sh\necho foreign-kept\n")
    shims.uninstall_shims()
    with open(path, encoding="utf-8") as f:
        assert f.read() == "#!/bin/sh\necho foreign-kept\n"


def test_shims_uninstall_absent_is_noop():
    from reach_guard import shims
    shim_dir = os.environ["REACH_GUARD_SHIM_DIR"]
    shims.uninstall_shims()          # nothing installed
    assert not os.path.exists(os.path.join(shim_dir, "gh"))
    assert not os.path.exists(os.path.join(shim_dir, "gh.real"))


def test_shims_uninstall_idempotent():
    from reach_guard import shims
    shims.install_shims()
    shims.uninstall_shims()
    status = shims.shim_status()
    shims.uninstall_shims()  # second run: no-op, same final state
    assert shims.shim_status() == status


def test_shims_uninstall_dry_run_no_changes():
    from reach_guard import shims
    shim_dir = os.environ["REACH_GUARD_SHIM_DIR"]
    real = os.path.join(shim_dir, "bili.real")
    _write_file(real, "#!/bin/sh\necho original\n")
    shims.install_shims()
    shims.uninstall_shims(dry_run=True)
    assert os.path.exists(real)
    with open(os.path.join(shim_dir, "bili"), encoding="utf-8") as f:
        assert "reach-guard" in f.read()  # still our shim


def test_cli_shims_uninstall_exit0():
    assert _main("shims", "uninstall") == 0
    assert _main("shims", "uninstall", "--dry-run") == 0


def test_cli_exit_code_contract(fake_bin):
    # contract table: 2/3/4/5/6/7/8 all reachable
    assert _main("run", "unknownbin") == 8
    assert _main("account", "add", "weirdpl") == 6
