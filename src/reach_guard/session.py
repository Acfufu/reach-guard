"""Account session layer: allowlist (env-credential hashes only), write gate,
upstream cookie gate, per-account Chrome profiles.

- Account allowlist stores SHA-256 hashes of env credentials — never plaintext.
  `reach-guard account add/rm/list` manages it.
- Reads are default; write operations (publish/post/follow/send/favorite/
  comment/delete/upload) require --allow-write else exit 6.
- Upstream cookie gate: twitter-cli/bili-cli must have explicit env credentials
  (no browser-cookie3 auto-extraction); missing -> exit 6 + Cookie-Editor guide.
- xhs: fresh XHS_COOKIE must be re-injected every session; missing -> exit 6.
  Not persisted.
- twitter: 24h rotation warning when the same credential hash is reused.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Optional, Tuple

from .config import (Config, SessionError, WRITE_KEYWORDS, CRED_ENV)
from . import state
from .proxy_layer import generate_profile, profile_flags_path

COOKIE_EDITOR_GUIDE = (
    "Export cookies manually with the Cookie-Editor extension, then inject via "
    "env: export {envvar}=... (values are never printed or stored)"
)


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def cred_env_vars(platform: str) -> list:
    return list(CRED_ENV.get(platform, []))


def read_creds(platform: str, env: Optional[dict] = None) -> dict:
    """Return {envvar: value} for credential vars present in env. Never logs."""
    env = env if env is not None else os.environ
    out = {}
    for var in cred_env_vars(platform):
        v = env.get(var, "")
        if v:
            out[var] = v
    return out


def write_op_in_args(args: list) -> Optional[str]:
    argstr = " ".join(args)
    m = WRITE_KEYWORDS.search(argstr)
    return m.group(0).lower() if m else None


def check_write_gate(args: list, allow_write: bool) -> None:
    kw = write_op_in_args(args)
    if kw and not allow_write:
        raise SessionError(
            f"write operation keyword {kw!r} detected in args; reads are "
            f"default, writes need explicit --allow-write; exit 6"
        )


def account_identity(platform: str, creds: dict, anonymous: bool) -> str:
    """account_hash: sha256 of the joined credential values, or 'anonymous'."""
    if anonymous or not creds:
        return "anonymous"
    joined = "|".join(f"{k}={v}" for k, v in sorted(creds.items()))
    return sha256(joined)


def check_cookie_gate(cfg: Config, platform: str, env: Optional[dict] = None
                      ) -> Tuple[dict, bool, str]:
    """Enforce cookie gate. Returns (creds, anonymous, account_hash).

    Raises SessionError (exit 6) when explicit credentials are required but
    missing, or when the xhs cookie is not freshly injected per session.
    """
    env = env if env is not None else os.environ
    pcfg = cfg.platform(platform)
    anon_allowed = pcfg.get("anon_allowed", False)
    creds = read_creds(platform, env)

    if platform == "xiaohongshu":
        if not creds.get("XHS_COOKIE"):
            raise SessionError(
                "xiaohongshu requires a FRESH XHS_COOKIE injected per session "
                "(expires ~10min / ~10 requests; 24h rotation reminders are "
                "ineffective). Re-export before each run. " + COOKIE_EDITOR_GUIDE
                .replace("{envvar}", "XHS_COOKIE") + "; exit 6"
            )
        return creds, False, account_identity(platform, creds, False)

    if platform == "twitter":
        missing = [v for v in ("TWITTER_AUTH_TOKEN", "TWITTER_CT0") if not creds.get(v)]
        if missing:
            raise SessionError(
                "twitter requires explicit env credentials; missing "
                + ", ".join(missing) + ". " + COOKIE_EDITOR_GUIDE
                .replace("{envvar}", "TWITTER_AUTH_TOKEN")
                + " (browser-cookie3 auto-extraction is forbidden); exit 6"
            )
        return creds, False, account_identity(platform, creds, False)

    if platform == "bilibili":
        # bili-cli needs no cookie env; the PROXY layer arbitrates anon vs
        # proxied (exit 3) via config.bilibili.anon. Identity is anonymous in
        # both modes.
        return {}, True, "anonymous"

    if not creds:
        if anon_allowed:
            return {}, True, "anonymous"
        raise SessionError(
            f"{platform} requires explicit env credentials and none were "
            f"provided; " + COOKIE_EDITOR_GUIDE.replace("{envvar}",
            cred_env_vars(platform)[0] if cred_env_vars(platform) else "COOKIE")
            + "; exit 6"
        )
    return creds, False, account_identity(platform, creds, False)


def check_allowlist(cfg: Config, platform: str, account_hash: str,
                    anonymous: bool) -> str:
    """Verify account hash against the allowlist. Returns account label."""
    if anonymous:
        return "anonymous"
    for a in cfg.account_list(platform):
        if a.hash == account_hash:
            return a.label
    raise SessionError(
        f"account {account_hash[:12]}... is not in the allowlist for "
        f"{platform}; only dedicated burner accounts allowed "
        f"(`reach-guard account add {platform}`); exit 6"
    )


def twitter_rotation_warning(cfg: Config, creds: dict) -> None:
    """Warn when the same twitter credential hash is reused for >24h."""
    joined = "|".join(f"{k}={v}" for k, v in sorted(creds.items()))
    h = sha256(joined)
    prev = state.last_cred_marker("twitter")
    if prev and prev.get("cred_hash") == h:
        if time.time() - (prev.get("ts") or 0) > 86400:
            print("[reach-guard] WARNING: same twitter cookie set reused for "
                  ">24h; rotate it (export fresh TWITTER_AUTH_TOKEN/TWITTER_CT0)",
                  file=__import__("sys").stderr)
    state.set_cred_marker("twitter", h)


def ensure_profile(cfg: Config, platform: str, account_hash: str,
                   account_label: str, proxy_url: str) -> Optional[str]:
    """Ensure a per-account profile dir exists for profile-required backends.
    Returns profile dir or None."""
    from .config import PROXY_PROFILE
    if cfg.platform(platform).get("proxy_mode") != PROXY_PROFILE:
        return None
    from .proxy_layer import generate_profile as _gen
    from .config import ProxyEntry
    proxy = None
    if proxy_url:
        proxy = ProxyEntry(url=proxy_url)
    return _gen(cfg, platform, account_hash, proxy, account_label)
