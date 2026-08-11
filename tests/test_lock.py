"""Todo 4: serial lock — two processes serialize; timeout -> exit 4."""

import os
import subprocess
import sys
import time

import pytest

from reach_guard.config import LockTimeoutError, load_config, LOCK_FILE
from reach_guard.lock import SerialLock


def test_lock_acquire_release():
    lk = SerialLock(timeout=5)
    lk.acquire()
    lk.release()


def test_second_lock_waits_then_gets_it():
    cfg = load_config()
    import threading
    held = threading.Event()
    release = threading.Event()

    def holder():
        with SerialLock(timeout=10):
            held.set()
            release.wait(10)

    t = threading.Thread(target=holder)
    t.start()
    held.wait(10)
    start = time.monotonic()
    lk = SerialLock(timeout=10)
    lk.acquire()
    elapsed = time.monotonic() - start
    release.set()
    lk.release()
    t.join(10)
    assert elapsed >= 0.05


def test_lock_timeout_exit4():
    a = SerialLock(timeout=1)
    a.acquire()
    try:
        b = SerialLock(timeout=0.3)
        with pytest.raises(LockTimeoutError):
            b.acquire()
    finally:
        a.release()


def test_two_processes_serialize(tmp_path):
    """Two real processes holding the lock concurrently must serialize."""
    code = (
        "import sys,time\n"
        "sys.path.insert(0, %r)\n"
        "from reach_guard.lock import SerialLock\n"
        "from reach_guard.config import load_config\n"
        "cfg=load_config()\n"
        "with SerialLock(timeout=10) as lk:\n"
        "    time.sleep(0.5)\n"
    ) % (os.path.join(os.path.dirname(__file__), "..", "src"))
    py = sys.executable
    procs = [subprocess.Popen([py, "-c", code]) for _ in range(2)]
    t0 = time.monotonic()
    for p in procs:
        p.wait(timeout=30)
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.95  # serialized: 2 x 0.5s
