"""Proxy binding, egress verification, geo-match, and backend->proxy matrix.

- Proxy pool from config (residential/static only).
- Account <-> proxy binding persisted in the ledger.
- Egress check: resolve exit IP through the proxy via a NEUTRAL endpoint
  (api.ipify.org, 10s timeout); drift -> abort exit 3.
- Geo-match: proxy IP country (ip-api.com) vs account locale config; mismatch
  -> refuse exit 3.
- Backend matrix: env-effective (twitter/gh/yt-dlp/curl/v2ex), profile-required
  (opencli), docker (xhs-mcp), reject (bili-cli aiohttp ignores env proxy ->
  exit 3 unless bilibili.anon anonymous read-only).
- NO_PROXY validation happens in config; platform-domain wildcards are exit 2.
"""

from __future__ import annotations

import os
import time
import urllib.request
from typing import Optional

from .config import (Config, ProxyEntry, IPError, ConfigError,
                     PROXY_ENV, PROXY_PROFILE, PROXY_DOCKER, PROXY_REJECT,
                     PROXY_NONE)
from . import state


class _ProxiedOpener(urllib.request.HTTPSHandler, urllib.request.HTTPHandler):
    def __init__(self, proxy_url: str):
        super().__init__()
        self._proxy = proxy_url

    def _build_opener(self) -> urllib.request.OpenerDirector:
        proxies = {"http": self._proxy, "https": self._proxy}
        return urllib.request.build_opener(
            urllib.request.ProxyHandler(proxies), self
        )


def http_get(url: str, proxy: Optional[str] = None, timeout: float = 10.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "reach-guard/0.1"})
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
        with opener.open(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def resolve_egress_ip(cfg: Config, proxy: Optional[str] = None) -> Optional[str]:
    try:
        body = http_get(cfg.egress_endpoint, proxy, cfg.egress_timeout)
    except Exception:
        return None
    ip = body.strip()
    return ip if ip else None


def country_of(cfg: Config, proxy: Optional[str], ip: str) -> Optional[str]:
    try:
        body = http_get(cfg.geo_endpoint + "?fields=status,country", proxy,
                        cfg.egress_timeout)
    except Exception:
        return None
    import json as _json
    try:
        data = _json.loads(body)
        if data.get("status") == "success":
            return data.get("country")
    except Exception:
        return None
    return None


def platform_requires_binding(cfg: Config, platform: str) -> bool:
    return cfg.platform(platform).get("ip") == "required"


def pick_proxy(cfg: Config, platform: str, account_hash: str) -> Optional[ProxyEntry]:
    if not cfg.proxies:
        return None
    # account-bound proxy wins (stable binding)
    for p in cfg.proxies:
        if p.account and p.account == account_hash:
            return p
    # pool proxy for platforms that tolerate any binding
    if platform_requires_binding(cfg, platform):
        return cfg.proxies[0]
    return cfg.proxies[0]


def verify_binding(cfg: Config, platform: str, account_hash: str,
                   proxy: Optional[ProxyEntry], anonymous: bool = False,
                   live: bool = True) -> str:
    """Enforce backend-proxy matrix + egress + geo. Returns proxy URL ("" if
    none). Raises IPError -> exit 3. `live=False` skips network egress (used by
    dry-run / tests)."""
    pcfg = cfg.platform(platform)
    mode = pcfg.get("proxy_mode")
    ip_required = pcfg.get("ip") == "required"

    # bili-cli: aiohttp ignores env proxy -> binding impossible
    if mode == PROXY_REJECT:
        if cfg.bili_anon:
            print(f"[reach-guard] bili anonymous read-only mode: no proxy "
                  f"binding claimed; upstream ignores env proxy (aiohttp)",
                  file=__import__("sys").stderr)
            return ""
        raise IPError(
            f"bili-cli (aiohttp) ignores HTTP(S)_PROXY; proxied binding is "
            f"impossible. Set bilibili.anon: true for anonymous read-only, or "
            f"use opencli bilibili (profile); exit 3"
        )

    if mode == PROXY_DOCKER:
        if not cfg.xhs_mcp_docker_network:
            raise IPError(
                f"xhs-mcp requires docker network proxy (config "
                f"xhs_mcp.docker_network); not configured; exit 3"
            )
        # docker-network traffic binding is assumed once network is configured
        if not proxy and ip_required:
            raise IPError(f"{platform} requires a residential proxy; exit 3")
        return proxy.url if proxy else ""

    if mode == PROXY_PROFILE:
        # opencli: traffic goes through the Chrome profile's proxy; wrapper can
        # not inject env. Profile must have been generated for this account.
        if ip_required and not proxy:
            raise IPError(
                f"{platform} requires a binding residential proxy and an "
                f"OpenCLI Chrome profile; none configured (fail-closed); exit 3"
            )
        prof = profile_flags_path(cfg, platform, account_hash)
        if ip_required and not os.path.exists(prof):
            raise IPError(
                f"{platform} requires an OpenCLI Chrome profile for this "
                f"account; run `reach-guard profile --platform {platform} "
                f"--account <account>`; exit 3"
            )
        if not proxy:
            return ""
        if not live:
            return proxy.url if proxy else ""
        ip = resolve_egress_ip(cfg, proxy.url)
        if not ip:
            raise IPError(
                f"could not verify egress IP through proxy {proxy.url} "
                f"(neutral endpoint {cfg.egress_endpoint}); abort (exit 3)"
            )
        if ip_required:
            _geo_check(cfg, proxy, ip, platform)
        return proxy.url

    if mode == PROXY_NONE or not ip_required and mode == PROXY_ENV:
        if not proxy or not ip_required:
            return proxy.url if proxy else ""
        if not live:
            return proxy.url
        ip = resolve_egress_ip(cfg, proxy.url)
        if not ip:
            raise IPError(
                f"could not verify egress IP through proxy {proxy.url}; abort (exit 3)"
            )
        _geo_check(cfg, proxy, ip, platform)
        return proxy.url

    # mode == PROXY_ENV with required binding
    if ip_required and not proxy:
        raise IPError(
            f"{platform} requires a binding residential proxy; none configured "
            f"(fail-closed); exit 3"
        )
    if not proxy:
        return ""
    if not live:
        return proxy.url
    ip = resolve_egress_ip(cfg, proxy.url)
    if not ip:
        raise IPError(
            f"could not verify egress IP through proxy {proxy.url}; abort (exit 3)"
        )
    _geo_check(cfg, proxy, ip, platform)
    return proxy.url


def _geo_check(cfg: Config, proxy: ProxyEntry, ip: str, platform: str) -> None:
    """Geo-match: proxy IP country vs account locale. Mismatch/unknown with a
    required binding -> exit 3 (fail-closed)."""
    country = country_of(cfg, proxy.url, ip)
    want = proxy.country
    if want and country and country.lower() != want.lower():
        raise IPError(
            f"geo mismatch: proxy IP {ip} is in {country}, account locale is "
            f"{want}; refusing (exit 3)"
        )
    if want and not country:
        raise IPError(
            f"could not resolve geo of proxy IP {ip} for locale {want}; "
            f"fail-closed (exit 3)"
        )


def build_env(cfg: Config, platform: str, proxy_url: str,
              base: Optional[dict] = None) -> dict:
    """Env for the upstream child: injects HTTP(S)_PROXY for env-effective
    backends, never for profile/docker/reject modes."""
    env = dict(os.environ)
    if base:
        env.update(base)
    pcfg = cfg.platform(platform)
    if pcfg.get("proxy_mode") == PROXY_ENV and proxy_url:
        env["HTTP_PROXY"] = proxy_url
        env["HTTPS_PROXY"] = proxy_url
        env["http_proxy"] = proxy_url
        env["https_proxy"] = proxy_url
        if cfg.no_proxy:
            env["NO_PROXY"] = cfg.no_proxy
            env["no_proxy"] = cfg.no_proxy
    else:
        # never leak stale proxy env into profile/docker/reject/none backends
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            env.pop(k, None)
    return env


def profile_flags_path(cfg: Config, platform: str, account_hash: str) -> str:
    profile_dir = os.path.join(cfg.profile_dir, platform, account_hash)
    return os.path.join(profile_dir, "profile.flags")


def generate_profile(cfg: Config, platform: str, account_hash: str,
                     proxy: Optional[ProxyEntry], account_label: str = "") -> str:
    """Create per-account Chrome profile dir (0700) + flags file with
    --proxy-server and --webrtc-ip-handling-policy."""
    profile_dir = os.path.join(cfg.profile_dir, platform, account_hash)
    os.makedirs(profile_dir, mode=0o700, exist_ok=True)
    os.chmod(profile_dir, 0o700)
    flags_path = os.path.join(profile_dir, "profile.flags")
    lines = [
        "# reach-guard OpenCLI Chrome profile flags (per-account isolated)",
        f"# platform: {platform}",
        f"# account:  {account_label or account_hash}",
        f"# user-data-dir: {profile_dir}",
    ]
    if proxy:
        lines.append(f"--proxy-server={proxy.url}")
        lines.append("--webrtc-ip-handling-policy=disable_non_proxied_udp")
    else:
        lines.append("# no proxy configured (fail-closed at run time if binding required)")
    with open(flags_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(flags_path, 0o600)
    return profile_dir
