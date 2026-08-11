import os
import shlex
import tempfile

_BASE = tempfile.mkdtemp(prefix="reach-guard-test-")
os.environ["REACH_GUARD_CONFIG_DIR"] = os.path.join(_BASE, "config")
os.environ["REACH_GUARD_STATE_DIR"] = os.path.join(_BASE, "state")
os.environ["REACH_GUARD_SHIM_DIR"] = os.path.join(_BASE, "bin")

import pytest

from reach_guard import config as cfgmod
from reach_guard import state as statemod


@pytest.fixture(autouse=True)
def _clean():
    statemod.ensure_dirs()
    for p in (statemod.STATE_FILE, statemod.STATE_FILE + ".1",
              cfgmod.CONFIG_FILE):
        if os.path.exists(p):
            os.remove(p)
    shim_dir = os.environ["REACH_GUARD_SHIM_DIR"]
    if os.path.isdir(shim_dir):
        for fn in os.listdir(shim_dir):
            if fn.endswith(".real"):
                os.remove(os.path.join(shim_dir, fn))
    yield


@pytest.fixture(autouse=True)
def _no_time_window(monkeypatch):
    # Tests must not depend on the wall clock: the deny window is real
    # (23:00-09:00 + 19:00-22:00 Asia/Shanghai) and would flake the suite at
    # night. Pin the clock to midday so in_deny_window() is False by default;
    # tests targeting the window pass an explicit datetime or monkeypatch
    # in_deny_window themselves (later monkeypatch.setattr wins).
    from datetime import datetime
    from zoneinfo import ZoneInfo
    from reach_guard import pacing
    fixed = datetime(2026, 8, 11, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
    monkeypatch.setattr(pacing, "_now_tz", lambda: fixed)


@pytest.fixture
def write_config():
    def _write(text: str):
        os.makedirs(cfgmod.CONFIG_DIR, exist_ok=True)
        with open(cfgmod.CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(text)
    return _write


@pytest.fixture
def fake_bin():
    def _make(name: str, exit_code: int = 0, stdout: str = "",
              stderr: str = "", shell: bool = True):
        shim_dir = os.environ["REACH_GUARD_SHIM_DIR"]
        os.makedirs(shim_dir, exist_ok=True)
        real = os.path.join(shim_dir, name + ".real")
        if shell:
            script = "#!/bin/sh\n"
            if stdout:
                script += f"printf '%s\\n' {shlex.quote(stdout)}\n"
            if stderr:
                script += f"printf '%s\\n' {shlex.quote(stderr)} >&2\n"
            script += f"exit {exit_code}\n"
        else:
            script = f"import sys\nsys.exit({exit_code})\n"
        with open(real, "w", encoding="utf-8") as f:
            f.write(script)
        os.chmod(real, 0o755)
        return real
    return _make
