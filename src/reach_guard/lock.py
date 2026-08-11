"""Global serial lock (fcntl.flock) — global concurrency is hard 1.

Every guarded invocation acquires guard.lock before anything else. Contention
queues (waits), with an expected-wait message; timeout -> exit 4.
"""

from __future__ import annotations

import fcntl
import os
import sys
import time

from .config import LOCK_FILE, LockTimeoutError, Config
from .state import ensure_dirs


class SerialLock:
    def __init__(self, timeout: float = 120.0):
        self.timeout = timeout
        self._fd: int = -1

    def acquire(self, verbose: bool = True) -> None:
        ensure_dirs()
        fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
        self._fd = fd
        deadline = time.monotonic() + self.timeout
        waited = 0.0
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if verbose and waited > 0:
                    print(f"[reach-guard] waited {waited:.1f}s for serial lock",
                          file=sys.stderr)
                return
            except OSError:
                now = time.monotonic()
                if now >= deadline:
                    os.close(fd)
                    self._fd = -1
                    raise LockTimeoutError(
                        f"serial lock timeout after {self.timeout:.0f}s "
                        f"(another reach-guard invocation holds it); exit 4"
                    )
                if verbose and int(now - (deadline - self.timeout)) % 2 == 0:
                    pass
                time.sleep(0.1)
                waited = now - (deadline - self.timeout)

    def release(self) -> None:
        if self._fd >= 0:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1

    def __enter__(self) -> "SerialLock":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()


def lock(config: Config) -> SerialLock:
    return SerialLock(timeout=config.lock_timeout)
