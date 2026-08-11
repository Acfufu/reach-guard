"""Machine-readable status report (P0-2 pinned whitelist schema).

`status_json(cfg)` emits ONLY the pinned schema: shims / platforms / quotas /
breakers / time_window. The schema NEVER carries command strings, argv,
ledger records, or credentials; fields without data are null/absent per
schema. `status --json` and `doctor --json` both emit exactly this object.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from . import __version__
from . import pacing, shims as shims_mod, state
from . import quota as quota_mod
from .config import Config

SCHEMA_VERSION = 1


def _platform_status(cfg: Config, platform: str,
                     env: Mapping[str, str]) -> dict[str, Any]:
    """Static gate summary for one platform.

    status/reason mirror the wrapper gate order (cookie gate -> allowlist ->
    proxy binding), so the reason is the FIRST blocker a guarded run would
    hit. `env` is the credential environment snapshot.
    """
    pcfg = cfg.platform(platform)
    anonymous = bool(pcfg.get("anon_allowed", False))
    proxy_configured = bool(cfg.proxies)
    account_bound = bool(cfg.account_list(platform))
    base = {"proxy_configured": proxy_configured,
            "account_bound": account_bound}

    if platform == "github":  # exempt route: logging-only passthrough
        return dict(base, status="ok", reason="ok")

    if not anonymous:
        required = list(pcfg.get("creds", []))
        if required and not all(env.get(v) for v in required):
            return dict(base, status="fail-closed", reason="cookie")
        if not required:
            return dict(base, status="fail-closed", reason="cookie")
        if not account_bound:
            return dict(base, status="fail-closed", reason="allowlist")

    mode = pcfg.get("proxy_mode")
    ip_required = pcfg.get("ip") == "required"
    if mode == "reject":
        if cfg.bili_anon:
            return dict(base, status="ok", reason="ok")
        return dict(base, status="fail-closed", reason="proxy")
    if mode == "docker":
        if not cfg.xhs_mcp_docker_network:
            return dict(base, status="fail-closed", reason="proxy")
        if ip_required and not proxy_configured:
            return dict(base, status="fail-closed", reason="proxy")
    elif ip_required and not proxy_configured:
        return dict(base, status="fail-closed", reason="proxy")
    return dict(base, status="ok", reason="ok")


def _breaker_summary(cfg: Config, now: float) -> dict[str, Any]:
    out = {}
    newest = {}
    for r in state.list_breakers():
        rp = r.get("platform")
        if rp not in newest or (r.get("ts") or 0) > (newest[rp].get("ts") or 0):
            newest[rp] = r
    for pl in sorted(cfg.platforms):
        r = newest.get(pl)
        if r is None:
            out[pl] = {"tier": None, "until": None}
            continue
        tier = r.get("tier")
        until = r.get("until", 0)
        active = (tier == "cooldown" and until and now < until) or \
                 (tier in ("quarantine", "permanent") and r.get("active", False))
        out[pl] = {
            "tier": tier if active else None,
            "until": (datetime.fromtimestamp(until, tz=timezone.utc)
                      .isoformat() if active and until else None),
        }
    return out


def status_json(cfg: Config,
                env: Optional[Mapping[str, str]] = None) -> dict[str, Any]:
    env = os.environ if env is None else env
    now = time.time()

    shims = {}
    for b, s in shims_mod.shim_status().items():
        shims[b] = "absent" if s == "missing-shim-real" else s

    platforms = {pl: _platform_status(cfg, pl, env)
                 for pl in sorted(cfg.platforms)}

    quotas = {}
    for pl in sorted(cfg.platforms):
        u = quota_mod.quota_usage(cfg, pl, "anonymous", now)
        quotas[pl] = {"used_h": u["hourly"][0], "limit_h": u["hourly"][1],
                      "used_d": u["daily"][0], "limit_d": u["daily"][1]}

    denied = any(pacing.in_deny_window(cfg, pl) for pl in cfg.platforms)

    return {
        "schema_version": SCHEMA_VERSION,
        "guard_version": __version__,
        "shims": shims,
        "platforms": platforms,
        "quotas": quotas,
        "breakers": _breaker_summary(cfg, now),
        "time_window": {"enabled": bool(cfg.time_windows),
                        "now_denied": denied},
    }
