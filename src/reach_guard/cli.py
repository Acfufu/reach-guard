"""reach-guard CLI: run|doctor|status|dry-run|profile|account|unlock|quarantine
|shims|detect|version.

Exit-code contract: 0 ok / 2 config / 3 IP / 4 lock / 5 quota·time-window /
6 session / 7 breaker / 8 upstream missing·error. Breaker wins over upstream
error. main() returns the exit code; console_script maps it to sys.exit.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Optional

from . import __version__
from .config import (Config, ConfigError, UnregisteredPlatformError,
                     SessionError, EXIT_OK, EXIT_CONFIG, EXIT_IP, EXIT_LOCK,
                     EXIT_QUOTA_TIME, EXIT_SESSION, EXIT_BREAKER, EXIT_UPSTREAM,
                     WRAPPED_BINARIES, CRED_ENV, PROXY_PROFILE,
                     DEFAULT_PLATFORMS, DEFAULT_TIME_WINDOWS)
from .config import load_config, CONFIG_FILE, CONFIG_DIR
from . import state
from . import shims as shims_mod
from .wrapper import run as wrapper_run, find_real_binary
from . import session as session_mod
from . import pacing, quota as quota_mod
from .proxy_layer import pick_proxy, verify_binding, generate_profile
from . import detect as detect_mod


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reach-guard",
        description="strict-mode enforcement wrapper for agent-reach upstream "
                    "binaries (serial lock / pacing / quota / proxy binding / "
                    "circuit breaker).",
    )
    p.add_argument("--version", action="version", version=f"reach-guard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="guarded dispatch of a wrapped binary")
    run_p.add_argument("--as-bin", dest="as_bin", help="binary name (shim mode)")
    run_p.add_argument("--dry-run", action="store_true", help="pre-flight, no execution")
    run_p.add_argument("--allow-write", action="store_true",
                       help="explicitly allow write operations")
    run_p.add_argument("--quiet", action="store_true")
    run_p.add_argument("args", nargs=argparse.REMAINDER,
                       help="<bin> <upstream args...> (or -- <args> in shim mode)")

    sub.add_parser("doctor", help="health check of guard + upstream")
    sub.add_parser("status", help="strict-mode status, quotas, breakers, ledger")
    dr = sub.add_parser("dry-run", help="alias for `run --dry-run`")
    dr.add_argument("--as-bin", dest="as_bin")
    dr.add_argument("--allow-write", action="store_true")
    dr.add_argument("args", nargs=argparse.REMAINDER)

    pf = sub.add_parser("profile", help="generate per-account OpenCLI Chrome profile")
    pf.add_argument("--platform", required=True)
    pf.add_argument("--account", required=True, help="account label or hash")
    pf.add_argument("--proxy-url", default="")

    acc = sub.add_parser("account", help="account allowlist (env-credential hashes only)")
    acc_sub = acc.add_subparsers(dest="acc_cmd", required=True)
    add_p = acc_sub.add_parser("add", help="register current env credential")
    add_p.add_argument("platform")
    add_p.add_argument("--label", default="")
    acc_sub.add_parser("list")
    rm_p = acc_sub.add_parser("rm")
    rm_p.add_argument("platform")
    rm_p.add_argument("account", help="label or hash prefix")

    un = sub.add_parser("unlock", help="manual unlock (quarantine tier only)")
    un.add_argument("platform")
    un.add_argument("account", help="account label or hash")

    sub.add_parser("quarantine", help="list active breakers/quarantines")

    sh = sub.add_parser("shims", help="PATH shim management")
    sh_sub = sh.add_subparsers(dest="shim_cmd", required=True)
    inst = sh_sub.add_parser("install", help="install/refresh PATH shims")
    inst.add_argument("--dry-run", action="store_true")
    sh_sub.add_parser("status", help="shim status per binary")

    sub.add_parser("detect", help="scan for direct (unguarded) upstream calls")
    return p


def _run_args(args: list, as_bin: Optional[str], dry_run: bool,
              allow_write: bool, quiet: bool = False) -> int:
    args = list(args)
    if args and args[0] == "--":
        args = args[1:]
    if as_bin:
        bin_name = as_bin
    else:
        if not args:
            print("reach-guard run: missing <bin> (one of "
                  + ", ".join(WRAPPED_BINARIES) + ")", file=sys.stderr)
            return EXIT_CONFIG
        bin_name = args.pop(0)
    cfg = load_config()
    try:
        res = wrapper_run(cfg, bin_name, args, dry_run=dry_run,
                          allow_write=allow_write, quiet=quiet)
    except (ConfigError, UnregisteredPlatformError) as e:
        print(f"[reach-guard] config error: {e}", file=sys.stderr)
        return EXIT_CONFIG
    return res.exit_code


def _cmd_doctor() -> int:
    print("== reach-guard doctor ==")
    # config
    try:
        cfg = load_config()
        print("config        : OK (strict mode, built-in table)")
        print(f"  platforms   : {len(cfg.platforms)} strict rows "
              f"(incl. v2ex public API)")
    except ConfigError as e:
        print(f"config        : FAIL ({e})")
        return EXIT_CONFIG
    except UnregisteredPlatformError as e:
        print(f"config        : FAIL ({e})")
        return EXIT_SESSION

    # state dirs + perms
    state.ensure_dirs()
    perms_ok = True
    log_dir = os.path.join(state.STATE_DIR, "logs")
    profile_root = os.path.join(state.STATE_DIR, "profiles")
    for p in (state.STATE_DIR, log_dir, profile_root):
        try:
            mode = os.stat(p).st_mode & 0o777
            if mode != 0o700:
                perms_ok = False
                print(f"  {p}: mode {oct(mode)} (want 0700)")
        except OSError as e:
            perms_ok = False
            print(f"  {p}: {e}")
    if os.path.exists(state.STATE_FILE):
        mode = os.stat(state.STATE_FILE).st_mode & 0o777
        if mode != 0o600:
            perms_ok = False
            print(f"  {state.STATE_FILE}: mode {oct(mode)} (want 0600)")
    print(f"state dirs    : {'OK (0700/0600)' if perms_ok else 'CHECK PERMS'}")

    # shims
    print("shims         :")
    for b, s in shims_mod.shim_status().items():
        mark = "OK" if s == "shim" else ("absent" if s == "absent" else s)
        print(f"  {b:12s}: {mark}")

    # real binaries behind shims
    print("upstream binaries:")
    for b in WRAPPED_BINARIES:
        real = find_real_binary(b)
        print(f"  {b:12s}: {real or '<missing -> exit 8 on guarded run>'}")

    # time window now
    now = pacing._now_tz()
    denied = [pl for pl in cfg.platforms if pacing.in_deny_window(cfg, pl, now)]
    print(f"time window   : now={now.strftime('%H:%M %Z')}; denied={denied or 'none'}")

    # breakers
    bl = state.list_breakers()
    print(f"breakers      : {len(bl)} record(s)")

    # bili anon
    print(f"bilibili.anon : {cfg.bili_anon} (false -> proxied bili-cli refuses exit 3)")

    # proxy configured?
    print(f"proxy pool    : {len(cfg.proxies)} proxy(ies) configured")
    if not cfg.proxies:
        print("  NOTE: no proxy configured; binding-required platforms fail "
              "closed with exit 3 (expected on this machine)")

    # real agent-reach doctor, if installed (via meta passthrough)
    real_ar = find_real_binary("agent-reach")
    if real_ar:
        print("\n-- real agent-reach doctor --")
        return wrapper_run(cfg, "agent-reach", ["doctor"], quiet=True).exit_code
    print("\nagent-reach binary not installed; install hint:")
    print("  pipx install https://github.com/Panniantong/agent-reach/archive/main.zip")
    return EXIT_OK


def _cmd_status() -> int:
    try:
        cfg = load_config()
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return EXIT_CONFIG
    now = time.time()
    print("== reach-guard status (STRICT mode — default & only) ==")
    print(f"strict table   : {len(cfg.platforms)} platforms, all active")
    print(f"  serial lock   : ACTIVE (fcntl.flock global, concurrency=1)")
    print(f"  global gap    : ACTIVE (>=5s between any two calls)")
    print(f"  time windows  : ACTIVE {cfg.time_windows or DEFAULT_TIME_WINDOWS} "
          f"(TZ=Asia/Shanghai)")
    print(f"  quota buckets : ACTIVE (hourly+daily+batch per strict table)")
    print(f"  circuit break : ACTIVE (cooldown24h/quarantine/permanent + "
          f"200-empty heuristic)")
    print(f"  proxy binding : ACTIVE ({len(cfg.proxies)} proxies; egress check "
          f"via {cfg.egress_endpoint})")
    print(f"  geo-match     : ACTIVE ({cfg.geo_endpoint})")
    print(f"  backend-matrix: ACTIVE (env/profile/docker/reject)")
    print(f"  cookie gates  : ACTIVE (xhs per-session fresh; twitter/bili "
          f"explicit env only)")
    print(f"  allowlist     : ACTIVE ({sum(len(v) for v in cfg.accounts.values())} "
          f"registered accounts)")
    print(f"  write gate    : ACTIVE (writes need --allow-write)")
    print(f"  bypass detect : ACTIVE (`reach-guard detect`)")
    print()
    print("platforms:")
    for pl in sorted(cfg.platforms):
        p = cfg.platform(pl)
        print(f"  {pl:12s} interval={p['interval']}s jitter=±{p['jitter']}s "
              f"q(h/d/b)={p['hourly']}/{p['daily']}/{p['batch']} "
              f"ip={p['ip']} proxy={p['proxy_mode']}")
    print()
    print("active breakers:")
    bl = state.list_breakers()
    active = 0
    for r in bl:
        if r.get("active"):
            active += 1
            print(f"  {r.get('platform')} {r.get('tier')} signal={r.get('signal')!r} "
                  f"account={r.get('account_hash', '')[:12]}")
    if not active:
        print("  none")
    print()
    print("quota usage (last hour/day, per platform):")
    for pl in sorted(cfg.platforms):
        if pl == "github":
            continue
        h, d = quota_mod.quota_usage(cfg, pl, "anonymous", now).values()
        print(f"  {pl:12s} hourly {h[0]}/{h[1]}  daily {d[0]}/{d[1]}")
    print()
    print("recent ledger (last 5):")
    recs = state.read_records(since=now - 3600 * 24)[-5:]
    for r in recs:
        print(f"  {time.strftime('%m-%d %H:%M', time.localtime(r.get('ts', 0)))} "
              f"{r.get('kind', 'call')} {r.get('platform')} exit={r.get('exit')}")
    return EXIT_OK


def _cmd_profile(args) -> int:
    try:
        cfg = load_config()
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return EXIT_CONFIG
    platform = args.platform
    account = args.account
    try:
        pcfg = cfg.platform(platform)
    except UnregisteredPlatformError as e:
        print(e, file=sys.stderr)
        return EXIT_SESSION

    proxy = None
    if args.proxy_url:
        from .config import ProxyEntry
        proxy = ProxyEntry(url=args.proxy_url)
    else:
        proxy = pick_proxy(cfg, platform, account)

    if pcfg.get("proxy_mode") != PROXY_PROFILE:
        print(f"note: {platform} uses proxy_mode={pcfg.get('proxy_mode')}; "
              f"profile generation is informational only", file=sys.stderr)

    prof_dir = generate_profile(cfg, platform, account, proxy,
                                account_label=account)
    print(f"profile generated: {prof_dir} (0700)")
    flags = os.path.join(prof_dir, "profile.flags")
    with open(flags, "r", encoding="utf-8") as f:
        print(f.read())

    if not proxy:
        print("egress verification SKIPPED: no proxy configured "
              "(documented; binding-required runs fail closed exit 3)")
    else:
        from .proxy_layer import resolve_egress_ip
        ip = resolve_egress_ip(cfg, proxy.url)
        print(f"egress IP via proxy: {ip}")
    return EXIT_OK


def _cmd_account(args) -> int:
    try:
        cfg = load_config()
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return EXIT_CONFIG
    cmd = args.acc_cmd
    if cmd == "list":
        if not cfg.accounts:
            print("no accounts registered")
            return EXIT_OK
        for pl, accs in sorted(cfg.accounts.items()):
            for a in accs:
                print(f"  {pl:12s} {a.label:20s} hash={a.hash[:16]}...")
        return EXIT_OK
    platform = args.platform
    try:
        cfg.platform(platform)
    except UnregisteredPlatformError as e:
        print(e, file=sys.stderr)
        return EXIT_SESSION
    vars_needed = CRED_ENV.get(platform, [])
    if not vars_needed:
        print(f"note: {platform} has no credential env var; it runs anonymous "
              f"(no allowlist entry needed)", file=sys.stderr)
        if cmd == "rm":
            return _account_rm(cfg, platform, args.account)
        return EXIT_OK
    if cmd == "rm":
        return _account_rm(cfg, platform, args.account)
    # add: hash current env credential
    creds = session_mod.read_creds(platform)
    missing = [v for v in vars_needed if not creds.get(v)]
    if missing:
        print(f"account add {platform}: env credentials missing: "
              + ", ".join(missing), file=sys.stderr)
        print("Export the credential in the current shell first "
              "(value is hashed, never stored).", file=sys.stderr)
        return EXIT_SESSION
    joined = "|".join(f"{k}={v}" for k, v in sorted(creds.items()))
    chash = session_mod.sha256(joined)
    label = args.label or platform + "-" + chash[:8]
    return _account_write(cfg, platform, label, chash)


def _account_write(cfg: Config, platform: str, label: str, chash: str) -> int:
    # write accounts back into config.yaml (safe subset emitter)
    accounts = dict(cfg.accounts)
    lst = [a for a in accounts.get(platform, []) if a.hash != chash]
    lst.append({"label": label, "hash": chash, "platform": platform})
    accounts[platform] = lst
    _emit_config(accounts)
    print(f"registered {platform} account {label!r} (hash {chash[:16]}...); "
          f"stored in {CONFIG_FILE}")
    return EXIT_OK


def _account_rm(cfg: Config, platform: str, account: str) -> int:
    accounts = dict(cfg.accounts)
    lst = accounts.get(platform, [])
    new = [a for a in lst
           if a.label != account and not a.hash.startswith(account)]
    if len(new) == len(lst):
        print(f"account {account!r} not found for {platform}", file=sys.stderr)
        return EXIT_CONFIG
    accounts[platform] = new
    _emit_config(accounts)
    print(f"removed {platform} account {account!r}")
    return EXIT_OK


def _emit_config(accounts: dict) -> None:
    """Rewrite config.yaml preserving existing sections minimally. Safe subset
    YAML emitter (no anchors/aliases). Keeps accounts section; merges into
    existing file's other keys when possible by re-emitting defaults structure."""
    state.ensure_dirs()
    payload = {"accounts": {k: [{"label": a["label"], "hash": a["hash"]}
                               for a in v] for k, v in accounts.items() if v}}
    # merge with existing config if present (only accounts section mutated)
    existing = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                from .config import _parse_yaml
                existing = _parse_yaml(f.read())
        except Exception:
            existing = {}
    existing["accounts"] = payload["accounts"]
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        _dump_yaml(existing, f)
    os.chmod(CONFIG_FILE, 0o600)


def _dump_yaml(data, f, indent: int = 0):
    pad = "  " * indent
    for k, v in data.items():
        if isinstance(v, dict):
            f.write(f"{pad}{k}:\n")
            _dump_yaml(v, f, indent + 1)
        elif isinstance(v, list):
            if not v:
                f.write(f"{pad}{k}: []\n")
                continue
            f.write(f"{pad}{k}:\n")
            for item in v:
                if isinstance(item, dict):
                    items = list(item.items())
                    if not items:
                        f.write(f"{pad}  - {{}}\n")
                        continue
                    first_key, first_val = items[0]
                    f.write(f"{pad}  - {first_key}: {_yaml_scalar(first_val)}\n")
                    for extra_key, extra_val in items[1:]:
                        f.write(f"{pad}    {extra_key}: {_yaml_scalar(extra_val)}\n")
                elif isinstance(item, list):
                    f.write(f"{pad}  - {_yaml_scalar(item)}\n")
                else:
                    f.write(f"{pad}  - {_yaml_scalar(item)}\n")
        else:
            f.write(f"{pad}{k}: {_yaml_scalar(v)}\n")


def _yaml_scalar(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if any(c in s for c in "#:{}[],&*?|>!%@`\"'") or s.strip() != s:
        return '"' + s.replace('"', '\\"') + '"'
    return s


def _cmd_unlock(args) -> int:
    try:
        cfg = load_config()
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return EXIT_CONFIG
    platform = args.platform
    account = args.account
    # resolve hash: exact label match in allowlist, else treat as hash
    chash = account
    for a in cfg.account_list(platform):
        if a.label == account or a.hash.startswith(account):
            chash = a.hash
            break
    ok = state.unlock(platform, chash)
    if not ok:
        print(f"cannot unlock: no active breaker for {platform} {account}, "
              f"or the tier is permanent (irreversible by design)", file=sys.stderr)
        return EXIT_CONFIG
    print(f"unlocked {platform} account {account} (quarantine cleared)")
    return EXIT_OK


def _cmd_quarantine() -> int:
    bl = state.list_breakers()
    if not bl:
        print("no breaker records")
        return EXIT_OK
    for r in bl:
        print(f"{r.get('platform'):12s} {r.get('tier'):10s} active={r.get('active')} "
              f"signal={r.get('signal')!r} account={r.get('account_hash', '')[:12]}")
    return EXIT_OK


def _cmd_shims(args) -> int:
    if args.shim_cmd == "status":
        for b, s in shims_mod.shim_status().items():
            print(f"  {b:12s}: {s}")
        return EXIT_OK
    shims_mod.install_shims(dry_run=args.dry_run)
    return EXIT_OK


def main(argv: Optional[list] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "run":
            return _run_args(args.args, args.as_bin, args.dry_run,
                             args.allow_write, quiet=args.quiet)
        if args.cmd == "dry-run":
            return _run_args(args.args, args.as_bin, True, args.allow_write)
        if args.cmd == "doctor":
            return _cmd_doctor()
        if args.cmd == "status":
            return _cmd_status()
        if args.cmd == "profile":
            return _cmd_profile(args)
        if args.cmd == "account":
            return _cmd_account(args)
        if args.cmd == "unlock":
            return _cmd_unlock(args)
        if args.cmd == "quarantine":
            return _cmd_quarantine()
        if args.cmd == "shims":
            return _cmd_shims(args)
        if args.cmd == "detect":
            return detect_mod.main(args)
    except BrokenPipeError:
        return EXIT_OK
    return EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())
