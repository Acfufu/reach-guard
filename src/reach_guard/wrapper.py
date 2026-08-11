"""Guarded dispatch wrapper: the single enforced entry for all wrapped
binaries.

Order (strict): serial lock -> time window -> IP/binding verify -> quota ->
pacing -> cookie gate -> execute upstream -> risk-signal scan -> ledger.
stdout/stderr are captured, scanned for risk signals, then replayed verbatim
(transparent passthrough). SIGINT is forwarded to the child and the ledger
records `interrupted`. Missing binary -> exit 8 + install hint. Dry-run
pre-flights the whole chain without executing the upstream.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import time
import uuid
from typing import Optional

from . import state
from .config import (Config, UpstreamError, SessionError, QuotaError,
                     IPError, BreakerError, LockTimeoutError,
                     EXIT_OK, EXIT_UPSTREAM, EXIT_SESSION, EXIT_QUOTA_TIME,
                     EXIT_IP, EXIT_LOCK, EXIT_BREAKER, resolve_platform)
from .lock import SerialLock
from . import pacing, quota as quota_mod, breaker as breaker_mod
from .proxy_layer import pick_proxy, verify_binding, build_env, profile_flags_path
from . import session as session_mod


def _install_hint(bin_name: str) -> str:
    if bin_name == "agent-reach":
        return ("agent-reach is not installed. Install: pipx install "
                "https://github.com/Panniantong/agent-reach/archive/main.zip "
                "(see docs/install.md), then re-run `reach-guard shims install`.")
    return f"{bin_name} binary not found; install it or check PATH."


# Keys whose argv VALUES are redacted before any stderr print or ledger write.
_SENSITIVE_KEYS = (
    "twitter-cookies", "xhs-cookies", "youtube-cookies", "github-token",
    "groq-key", "openai-key", "proxy", "auth_token", "ct0", "password",
    "token", "cookie", "cookies",
)


def _scrub_command(args: list) -> str:
    """Join args for display/ledger, redacting sensitive-key VALUES only.

    Redacts both `key value` (positional) and `key=value` forms, case-
    insensitive; the key itself is never redacted, and a value is only ever
    redacted when it follows a sensitive key (no content sniffing).
    """
    s = " ".join(args)
    keys = "|".join(re.escape(k) for k in _SENSITIVE_KEYS)
    s = re.sub(rf"(?i)(\b(?:{keys})\s*=\s*)[^\s]+", r"\1***", s)
    s = re.sub(rf"(?i)(\b(?:{keys})\b)(\s+)[^\s]+", r"\1\2***", s)
    return s


def find_real_binary(bin_name: str) -> Optional[str]:
    """Locate the real upstream binary behind a shim.

    1. <shim_dir>/<bin>.real (renamed original backup)
    2. PATH lookup that skips the shim directory AND the production shim dir
       (~/.local/bin), so tests/fakes can never fall through to a real binary
       that is itself wrapped in production.
    """
    shim_dir = os.environ.get("REACH_GUARD_SHIM_DIR",
                              os.path.expanduser("~/.local/bin"))
    prod_shim = os.path.expanduser("~/.local/bin")
    real = os.path.join(shim_dir, bin_name + ".real")
    if os.path.exists(real):
        return real
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d:
            continue
        d = os.path.expanduser(d)
        if os.path.realpath(d) == os.path.realpath(shim_dir):
            continue
        if os.path.realpath(d) == os.path.realpath(prod_shim):
            continue
        cand = os.path.join(d, bin_name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


class RunResult:
    def __init__(self, exit_code: int, upstream_exit: Optional[int] = None):
        self.exit_code = exit_code
        self.upstream_exit = upstream_exit


def run(cfg: Config, bin_name: str, args: list, *,
        dry_run: bool = False, allow_write: bool = False,
        quiet: bool = False) -> RunResult:
    """Full guarded dispatch. Returns RunResult(exit_code, upstream_exit)."""
    run_id = uuid.uuid4().hex[:12]

    if not quiet:
        print(f"[reach-guard] guarded dispatch bin={bin_name} "
              f"args={_scrub_command(args)}", file=sys.stderr)

    # ---- self-recursion bypass -------------------------------------------
    # Wrapped real binaries sometimes re-exec their own name via PATH (opencli
    # spawns helper children; gh self-executes). Without this, the shim would
    # redirect that self-exec back into guard forever — an infinite fork bomb.
    # Same-bin re-entry execs the real binary directly (the outer dispatch
    # already ran every gate); different-bin nesting (agent-reach -> bili)
    # still goes through the full guarded path below.
    if os.environ.get("REACH_GUARD_DISPATCH_BIN") == bin_name:
        return _run_self_recursion(bin_name, args, dry_run, quiet)

    # ---- resolve platform (fail-closed on unknown) -----------------------
    try:
        platform, exempt, meta, _reason = resolve_platform(bin_name, args, cfg)
    except (UpstreamError, SessionError) as e:
        print(f"[reach-guard] {e}", file=sys.stderr)
        return RunResult(EXIT_UPSTREAM if isinstance(e, UpstreamError)
                         else EXIT_SESSION)

    # ---- gh exempt: log-only passthrough ---------------------------------
    if exempt and bin_name == "gh":
        return _run_exempt(cfg, bin_name, args, run_id, dry_run)

    # meta commands (opencli list, agent-reach doctor, mcporter list, ...)
    if meta or platform is None:
        return _run_meta(cfg, bin_name, args, run_id, dry_run)

    # ---- serial lock (exit 4) -------------------------------------------
    lock = SerialLock(timeout=cfg.lock_timeout)
    try:
        lock.acquire()
    except LockTimeoutError as e:
        print(f"[reach-guard] {e}", file=sys.stderr)
        return RunResult(EXIT_LOCK)
    try:
        return _run_guarded(cfg, bin_name, platform, args, run_id,
                            dry_run, allow_write)
    finally:
        lock.release()


def _run_self_recursion(bin_name: str, args: list, dry_run: bool,
                        quiet: bool) -> RunResult:
    """Same-bin re-entry: exec the real binary directly, no guard logic.

    The outer dispatch already ran every gate; re-running them here would
    loop forever when the real binary re-execs itself through the shim.
    """
    real = find_real_binary(bin_name)
    if not real:
        print(f"[reach-guard] {_install_hint(bin_name)}", file=sys.stderr)
        return RunResult(EXIT_UPSTREAM)
    if dry_run:
        print(f"[reach-guard dry-run] self-recursion bypass: {real} "
              f"{_scrub_command(args)}")
        return RunResult(EXIT_OK)
    if not quiet:
        print(f"[reach-guard] self-recursion bypass: exec {real} directly",
              file=sys.stderr)
    env = dict(os.environ)
    env["REACH_GUARD_DISPATCH_BIN"] = bin_name
    try:
        proc = subprocess.Popen([real] + list(args), env=env, stdin=None)
        rc = proc.wait()
    except OSError as e:
        print(f"[reach-guard] failed to execute {real}: {e}", file=sys.stderr)
        return RunResult(EXIT_UPSTREAM)
    return RunResult(EXIT_OK if rc == 0 else EXIT_UPSTREAM, upstream_exit=rc)


def _run_exempt(cfg: Config, bin_name: str, args: list, run_id: str,
                dry_run: bool) -> RunResult:
    print("[reach-guard] github EXEMPT route: passthrough with logging only "
          "(no pacing/quota/binding)", file=sys.stderr)
    real = find_real_binary(bin_name)
    if not real:
        print(f"[reach-guard] {_install_hint(bin_name)}", file=sys.stderr)
        return RunResult(EXIT_UPSTREAM)
    meta = {"run_id": run_id, "platform": "github", "account_hash": "anonymous",
            "bin": bin_name, "command": _scrub_command(args), "exempt": True,
            "dry_run": dry_run}
    state.append_record(dict(meta, ts=time.time(), interrupted=False, exit=None))
    if dry_run:
        print("[reach-guard dry-run] would run:", real, _scrub_command(args))
        return RunResult(EXIT_OK)
    rc = _exec_passthrough(real, args, run_id, meta, cfg, bin_name)
    return RunResult(EXIT_OK if rc == 0 else EXIT_UPSTREAM, upstream_exit=rc)


def _run_meta(cfg: Config, bin_name: str, args: list, run_id: str,
              dry_run: bool) -> RunResult:
    print("[reach-guard] management/meta command passthrough (no platform "
          "traffic), logged only", file=sys.stderr)
    real = find_real_binary(bin_name)
    if not real:
        print(f"[reach-guard] {_install_hint(bin_name)}", file=sys.stderr)
        return RunResult(EXIT_UPSTREAM)
    meta = {"run_id": run_id, "platform": "meta", "account_hash": "anonymous",
            "bin": bin_name, "command": _scrub_command(args), "meta": True,
            "dry_run": dry_run}
    state.append_record(dict(meta, ts=time.time(), interrupted=False, exit=None))
    if dry_run:
        print("[reach-guard dry-run] would run:", real, _scrub_command(args))
        return RunResult(EXIT_OK)
    rc = _exec_passthrough(real, args, run_id, meta, cfg, bin_name)
    return RunResult(EXIT_OK if rc == 0 else EXIT_UPSTREAM, upstream_exit=rc)


def _run_guarded(cfg, bin_name, platform, args, run_id, dry_run,
                 allow_write) -> RunResult:
    pcfg = cfg.platform(platform)

    # ---- time window (exit 5) -------------------------------------------
    try:
        pacing.enforce_time_window(cfg, platform)
    except QuotaError as e:
        print(f"[reach-guard] {e}", file=sys.stderr)
        return RunResult(EXIT_QUOTA_TIME)

    # ---- session gate: cookie gate + account allowlist + write gate ------
    # Session-hard gates (xhs fresh cookie, twitter creds, write gate) run
    # BEFORE binding so a missing cookie yields exit 6 even without a proxy.
    try:
        creds, anonymous, account_hash = session_mod.check_cookie_gate(cfg, platform)
        account_label = session_mod.check_allowlist(cfg, platform, account_hash,
                                                    anonymous)
        session_mod.check_write_gate(args, allow_write)
        if platform == "twitter" and creds:
            session_mod.twitter_rotation_warning(cfg, creds)
    except SessionError as e:
        print(f"[reach-guard] {e}", file=sys.stderr)
        return RunResult(EXIT_SESSION)

    # ---- breaker pre-flight (exit 7 wins over everything) ----------------
    try:
        breaker_mod.check_before_run(cfg, platform, account_hash)
    except BreakerError as e:
        print(f"[reach-guard] {e}", file=sys.stderr)
        return RunResult(EXIT_BREAKER)

    # ---- proxy binding + egress + geo (exit 3) ---------------------------
    proxy = pick_proxy(cfg, platform, account_hash)
    try:
        proxy_url = verify_binding(cfg, platform, account_hash, proxy,
                                   anonymous=anonymous, live=not dry_run)
    except IPError as e:
        print(f"[reach-guard] {e}", file=sys.stderr)
        return RunResult(EXIT_IP)
    if proxy_url and not dry_run:
        state.bind_account(platform, account_hash, proxy_url)

    # ---- quota (exit 5) --------------------------------------------------
    try:
        quota_mod.check_quota(cfg, platform, account_hash, run_id)
    except QuotaError as e:
        print(f"[reach-guard] {e}", file=sys.stderr)
        return RunResult(EXIT_QUOTA_TIME)

    # ---- pacing (wait or dry-run report) ---------------------------------
    pacing.wait_for(cfg, platform, account_hash, dry_run=dry_run)

    # ---- find upstream binary (exit 8) -----------------------------------
    real = find_real_binary(bin_name)
    if not real:
        print(f"[reach-guard] {_install_hint(bin_name)}", file=sys.stderr)
        return RunResult(EXIT_UPSTREAM)

    # profile requirement for profile-mode backends
    if pcfg.get("proxy_mode") == "profile" and platform in (
            "xiaohongshu", "instagram", "facebook", "weibo", "douyin", "xueqiu"):
        if not os.path.exists(profile_flags_path(cfg, platform, account_hash)):
            print(f"[reach-guard] {platform} requires an OpenCLI Chrome "
                  f"profile; run `reach-guard profile --platform {platform} "
                  f"--account {account_label}`; fail-closed (exit 3)",
                  file=sys.stderr)
            return RunResult(EXIT_IP)

    env = build_env(cfg, platform, proxy_url)

    meta = {"run_id": run_id, "platform": platform,
            "account_hash": account_hash, "account": account_label,
            "proxy_ip": proxy_url or "", "bin": bin_name,
            "command": _scrub_command(args), "allow_write": allow_write}

    if dry_run:
        print(f"[reach-guard dry-run] ALL GATES PASSED: platform={platform} "
              f"account={account_label} proxy={proxy_url or 'none'} bin={real}")
        state.append_record(dict(meta, ts=time.time(), dry_run=True,
                                 interrupted=False))
        return RunResult(EXIT_OK)

    # ---- execute + capture + replay --------------------------------------
    rc, out, err, interrupted = _exec_capture(real, args, run_id, meta, env, bin_name)
    if interrupted:
        state.append_record(dict(meta, ts=time.time(), interrupted=True, exit=rc))
        print("[reach-guard] interrupted by SIGINT (forwarded to upstream); "
              "ledger marked interrupted", file=sys.stderr)
        return RunResult(130, upstream_exit=rc)
    if out:
        sys.stdout.write(out)
        sys.stdout.flush()
    if err:
        sys.stderr.write(err)
        sys.stderr.flush()

    # ---- risk-signal scan (breaker; exit 7 wins over upstream error) -----
    try:
        breaker_mod.enforce(cfg, platform, account_hash, args,
                            out, err, rc, anonymous)
    except BreakerError as e:
        print(f"[reach-guard] {e}", file=sys.stderr)
        return RunResult(EXIT_BREAKER, upstream_exit=rc)

    # ---- ledger: record outcome ------------------------------------------
    state.append_record(dict(meta, ts=time.time(), interrupted=False, exit=rc))
    return RunResult(EXIT_OK if rc == 0 else EXIT_UPSTREAM, upstream_exit=rc)


def _exec_capture(real: str, args: list, run_id: str, meta: dict,
                  env: dict, bin_name: str) -> tuple:
    """Run upstream in its own session, capture output, forward SIGINT to the
    whole child group (terminal Ctrl-C semantics). Returns (rc, out, err,
    interrupted)."""
    # Marker lets a re-entered dispatch tell same-bin self-recursion (bypass)
    # from legitimate different-bin nesting (guard normally).
    env["REACH_GUARD_DISPATCH_BIN"] = bin_name
    interrupted = [False]
    try:
        proc = subprocess.Popen([real] + list(args), env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=None, start_new_session=True)
    except OSError as e:
        print(f"[reach-guard] failed to execute {real}: {e}", file=sys.stderr)
        state.append_record(dict(meta, ts=time.time(), interrupted=False,
                                 exit="spawn-failed"))
        return (EXIT_UPSTREAM, "", f"failed to execute {real}: {e}\n", False)

    def _sigint(signum, frame):
        interrupted[0] = True
        try:
            os.killpg(proc.pid, signal.SIGINT)
        except OSError:
            try:
                proc.send_signal(signal.SIGINT)
            except OSError:
                pass

    old = signal.signal(signal.SIGINT, _sigint)
    try:
        out, err = proc.communicate()
    finally:
        signal.signal(signal.SIGINT, old)
    rc = proc.returncode
    return rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), \
        interrupted[0]


def _exec_passthrough(real: str, args: list, run_id: str, meta: dict,
                      cfg: Config, bin_name: str) -> int:
    # exempt/meta paths carry no platform proxy semantics; pass env through as-is
    env = dict(os.environ)
    rc, out, err, interrupted = _exec_capture(real, args, run_id, meta, env,
                                              bin_name)
    if interrupted:
        state.append_record(dict(meta, ts=time.time(), interrupted=True,
                                 exit=rc))
        return rc
    if out:
        sys.stdout.write(out)
        sys.stdout.flush()
    if err:
        sys.stderr.write(err)
        sys.stderr.flush()
    state.append_record(dict(meta, ts=time.time(), interrupted=False, exit=rc))
    return rc
