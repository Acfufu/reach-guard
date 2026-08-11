"""Strict-mode configuration for reach-guard.

The strict platform table is built in (DEFAULT_PLATFORMS) and is the ONLY mode.
~/.config/reach-guard/config.yaml may override quotas / proxy pool / account
allowlist / time windows / lock timeout. Unknown keys and illegal values fail
closed (exit 2). Platforms not registered in the built-in table are rejected
(exit 6). The package is stdlib-only, so YAML support is a documented safe
subset (nested maps, dash lists, scalars, comments, quoted strings; no anchors,
aliases, or multi-line scalars).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Exit codes (contract with cli.py / wrapper.py)
# ---------------------------------------------------------------------------
EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_IP = 3
EXIT_LOCK = 4
EXIT_QUOTA_TIME = 5
EXIT_SESSION = 6
EXIT_BREAKER = 7
EXIT_UPSTREAM = 8


class ConfigError(Exception):
    """Invalid configuration -> exit 2."""


class UnregisteredPlatformError(Exception):
    """Platform not in strict table -> exit 6."""


class SessionError(Exception):
    """Session/allowlist/cookie-gate failure -> exit 6."""


class QuotaError(Exception):
    """Quota or time-window rejection -> exit 5."""


class LockTimeoutError(Exception):
    """Serial-lock timeout -> exit 4."""


class BreakerError(Exception):
    """Circuit breaker tripped -> exit 7."""


class IPError(Exception):
    """Proxy binding / egress / geo mismatch -> exit 3."""


class UpstreamError(Exception):
    """Missing upstream binary or upstream failure -> exit 8."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Proxy binding strategy per backend.
PROXY_ENV = "env"        # HTTP(S)_PROXY injection works (twitter/gh/yt-dlp/curl/v2ex)
PROXY_PROFILE = "profile"  # Chrome profile must carry proxy (opencli)
PROXY_DOCKER = "docker"  # xhs-mcp docker network carries proxy
PROXY_REJECT = "reject"  # binding impossible -> exit 3 unless anonymous mode
PROXY_NONE = "none"      # no proxy required

# The wrapped binary set (PATH shims -> reach-guard run).
WRAPPED_BINARIES = [
    "agent-reach", "twitter", "bili", "opencli",
    "gh", "yt-dlp", "mcporter", "curl",
]

# GitHub is the exempt route: gh shim passes through with logging only.
EXEMPT_BINS = {"gh"}

# curl hosts allowed as plain passthrough (non-platform traffic, logged only).
CURL_ALLOWLIST_HOSTS = {"r.jina.ai", "api.ipify.org", "v2ex.com"}

# opencli management commands (no platform traffic) -> passthrough with logging.
OPENCLI_META_COMMANDS = {
    "list", "profile", "doctor", "help", "--help", "-h", "--version", "-V",
}

# mcporter meta commands -> passthrough with logging.
MCPORTER_META_COMMANDS = {"list", "help", "--help", "-h", "--version", "-V"}

# Write-operation keywords -> require --allow-write.
WRITE_KEYWORDS = re.compile(
    r"\b(publish|post|follow|send|favorite|comment|delete|upload)\b", re.I
)

# Global permanent (ban-class) signal keywords; platform lists may extend.
PERMANENT_SIGNAL_RE = re.compile(
    r"封号|封禁|冻结|永久|blocked|banned|suspended|locked|受限|attestation|验证异常",
    re.I,
)

# Context whitelist: benign text on anonymous/guest endpoints that must NOT
# trip the breaker. (platform, args_regex, signal_regex, anonymous_only)
SIGNAL_WHITELIST = [
    ("douyin", r"hotsearch", r"请先登录", True),
    ("weibo", r".*", r"432", True),
    ("xiaohongshu", r".*", r"登录已过期|cookie.{0,6}过期|请求过于频繁", True),
]

# Default deny time windows (minutes since midnight, TZ=Asia/Shanghai):
# 23:00-09:00 and 19:00-22:00.
DEFAULT_TIME_WINDOWS = [(23 * 60, 9 * 60), (19 * 60, 22 * 60)]

# curl URL host -> platform mapping (used when bin == curl).
HOST_PLATFORM = {
    "v2ex.com": "v2ex",
    "www.v2ex.com": "v2ex",
    "xiaohongshu.com": "xiaohongshu",
    "www.xiaohongshu.com": "xiaohongshu",
    "xhslink.com": "xiaohongshu",
    "douyin.com": "douyin",
    "www.douyin.com": "douyin",
    "weibo.com": "weibo",
    "weibo.cn": "weibo",
    "bilibili.com": "bilibili",
    "www.bilibili.com": "bilibili",
    "b23.tv": "bilibili",
    "x.com": "twitter",
    "twitter.com": "twitter",
    "instagram.com": "instagram",
    "www.instagram.com": "instagram",
    "facebook.com": "facebook",
    "www.facebook.com": "facebook",
    "reddit.com": "reddit",
    "www.reddit.com": "reddit",
    "linkedin.com": "linkedin",
    "www.linkedin.com": "linkedin",
    "youtube.com": "youtube",
    "www.youtube.com": "youtube",
    "youtu.be": "youtube",
    "weixin.sogou.com": "wechat",
    "sogou.com": "wechat",
    "xueqiu.com": "xueqiu",
    "www.xueqiu.com": "xueqiu",
    "xiaoyuzhoufm.com": "xiaoyuzhou",
    "www.xiaoyuzhoufm.com": "xiaoyuzhou",
    "github.com": "github",
    "api.github.com": "github",
    "raw.githubusercontent.com": "github",
}

# opencli adapter name -> platform.
OPENCLI_PLATFORM = {
    "xiaohongshu": "xiaohongshu",
    "douyin": "douyin",
    "weibo": "weibo",
    "bilibili": "bilibili",
    "twitter": "twitter",
    "x": "twitter",
    "instagram": "instagram",
    "facebook": "facebook",
    "reddit": "reddit",
    "youtube": "youtube",
    "xueqiu": "xueqiu",
    "xiaoyuzhou": "xiaoyuzhou",
    "linkedin": "linkedin",
}

# ---------------------------------------------------------------------------
# Strict platform table (default, only mode). Values = most conservative.
# ---------------------------------------------------------------------------

def _p(interval, jitter, hourly, daily, batch, signals, ip,
       proxy_mode, backend, anon_allowed=False, creds=None,
       windows=None, permanent=None, hourly_override=None):
    return {
        "interval": interval,          # seconds, minimum spacing
        "jitter": jitter,              # +/- seconds random jitter
        "hourly": hourly,              # quota per rolling hour
        "daily": daily,                # quota per rolling day
        "batch": batch,                # max operations per run invocation
        "signals": list(signals),      # cooldown-class risk signals (regex)
        "permanent": list(permanent or []),  # platform ban-class additions
        "ip": ip,                      # required | optional | none
        "proxy_mode": proxy_mode,      # env | profile | docker | reject | none
        "backend": backend,
        "anon_allowed": anon_allowed,  # anonymous read-only permitted
        "creds": list(creds or []),    # env vars required by cookie gate
        "windows": windows,            # per-platform deny windows override
    }


DEFAULT_PLATFORMS = {
    "xiaohongshu": _p(
        10, 3, 5, 50, 10,
        ["461", "124", "验证码", "AI操作", "登录已过期", "请求过于频繁", "406"],
        "required", PROXY_PROFILE, "opencli; xhs-mcp(docker); xhs-cli(reject)",
        anon_allowed=False, creds=["XHS_COOKIE"],
    ),
    "douyin": _p(
        30, 10, 8, 100, 30,
        ["2483", "account blocked", "请先登录"],
        "required", PROXY_PROFILE, "opencli(profile)",
        anon_allowed=True, creds=[],
    ),
    "weibo": _p(
        30, 10, 8, 100, 30,
        ["432", "异常冻结", "频繁", "geetest", "验证码"],
        "required", PROXY_PROFILE, "opencli(profile)",
        anon_allowed=True, creds=[],
    ),
    "bilibili": _p(
        10, 3, 16, 200, 50,
        ["412", "-352", "风控校验失败", "1003", "-401"],
        "required", PROXY_REJECT, "bili-cli(aiohttp: env ignored)",
        anon_allowed=True, creds=[],
    ),
    "twitter": _p(
        60, 20, 4, 50, 10,
        ["封号", "受限", "429", "异常"],
        "required", PROXY_ENV, "twitter-cli(env)",
        anon_allowed=False, creds=["TWITTER_AUTH_TOKEN", "TWITTER_CT0"],
        permanent=["account suspended", "suspended"],
    ),
    "instagram": _p(
        60, 20, 2, 20, 5,
        ["429", "login required", "请重新登录"],
        "required", PROXY_PROFILE, "opencli(profile)",
        anon_allowed=False, creds=[],
    ),
    "facebook": _p(
        60, 20, 2, 20, 5,
        ["429", "checkpoint", "异常登录"],
        "required", PROXY_PROFILE, "opencli(profile)",
        anon_allowed=False, creds=[],
    ),
    "reddit": _p(
        30, 10, 8, 100, 20,
        ["403", "blocked", "rate"],
        "optional", PROXY_ENV, "rdt-cli(env, unverified); opencli(profile)",
        anon_allowed=True, creds=[],
    ),
    "linkedin": _p(
        60, 20, 2, 20, 5,
        ["受限", "异常", "请验证"],
        "required", PROXY_ENV, "mcp-server-linkedin(env; undici unverified)",
        anon_allowed=False, creds=[],
    ),
    "youtube": _p(
        30, 10, 8, 100, 20,
        ["机器人校验", "429"],
        "optional", PROXY_ENV, "yt-dlp(env); opencli(profile)",
        anon_allowed=True, creds=[],
    ),
    "wechat": _p(
        30, 10, 4, 50, 10,
        ["-2041", "-2012", "验证码", "风控"],
        "required", PROXY_ENV, "curl(env)",
        anon_allowed=True, creds=[],
    ),
    "xueqiu": _p(
        30, 10, 4, 50, 10,
        ["400", "风控"],
        "required", PROXY_PROFILE, "opencli(profile)",
        anon_allowed=True, creds=[],
    ),
    "xiaoyuzhou": _p(
        30, 10, 4, 50, 10,
        ["401", "token 失效"],
        "required", PROXY_ENV, "curl script(env)",
        anon_allowed=True, creds=[],
    ),
    # GitHub: exempt route (gh passthrough, no pacing/quota/binding).
    "github": _p(
        0, 0, 5000, 5000, 100,
        [],
        "none", PROXY_NONE, "gh(env) EXEMPT",
        anon_allowed=True, creds=[],
    ),
    # V2EX: low-risk public API (approved scope addition).
    "v2ex": _p(
        5, 2, 41, 500, 20,
        ["429", "403"],
        "optional", PROXY_ENV, "curl(env)",
        anon_allowed=True, creds=[],
    ),
}

# Account credential env var per platform (allowlist hashing + cookie gate).
CRED_ENV = {
    "xiaohongshu": ["XHS_COOKIE"],
    "twitter": ["TWITTER_AUTH_TOKEN", "TWITTER_CT0"],
    "bilibili": [],          # bili-cli: anonymous read-only, or rejected
    "instagram": [],
    "facebook": [],
    "weibo": [],
    "douyin": [],
    "reddit": [],
    "linkedin": [],
    "youtube": [],
    "wechat": [],
    "xueqiu": [],
    "xiaoyuzhou": [],
    "github": [],
    "v2ex": [],
}

# Backend resolution for `reach-guard run doctor`.
BACKEND_DOCTOR = {
    "bilibili": "bili-cli (aiohttp, ignores env proxy; anonymous only)",
    "twitter": "twitter-cli (env)",
    "github": "gh CLI (exempt)",
    "v2ex": "curl public API (env)",
    "youtube": "yt-dlp (env)",
    "default": "opencli Chrome profile / docker / unverified",
}


@dataclass
class ProxyEntry:
    url: str
    ptype: str = "residential"   # only residential/static accepted
    country: str = ""
    account: str = ""

    def validate(self) -> None:
        if self.ptype not in ("residential", "static"):
            raise ConfigError(
                f"proxy type must be residential or static, got {self.ptype!r}"
            )
        if not re.match(r"^https?://", self.url):
            raise ConfigError(f"proxy url must start with http(s)://, got {self.url!r}")


@dataclass
class AccountEntry:
    label: str
    hash: str
    platform: str = ""


@dataclass
class Config:
    platforms: dict = field(default_factory=lambda: dict(DEFAULT_PLATFORMS))
    proxies: list = field(default_factory=list)          # list[ProxyEntry]
    accounts: dict = field(default_factory=dict)         # platform -> list[AccountEntry]
    time_windows: list = field(default_factory=lambda: list(DEFAULT_TIME_WINDOWS))
    lock_timeout: float = 120.0
    egress_endpoint: str = "https://api.ipify.org"
    geo_endpoint: str = "http://ip-api.com/json/"
    egress_timeout: float = 10.0
    bili_anon: bool = False
    xhs_mcp_docker_network: str = ""
    no_proxy: str = ""
    profile_dir: str = ""        # set at load time (state dir)

    # ---- lookups ----------------------------------------------------------
    def platform(self, name: str) -> dict:
        if name not in self.platforms:
            raise UnregisteredPlatformError(
                f"platform {name!r} is not in the strict table; refusing (exit 6)"
            )
        return self.platforms[name]

    def proxy_for(self, platform: str, account_hash: str) -> Optional[ProxyEntry]:
        """Stable account<->proxy binding: first proxy claiming this account
        hash, else first proxy matching the platform's account label."""
        for p in self.proxies:
            if p.account and p.account == account_hash:
                return p
        # account-bound proxies keyed by label hash match already handled above;
        # a pool proxy without an explicit binding is used for unbound platforms.
        return None

    def account_list(self, platform: str) -> list:
        return self.accounts.get(platform, [])

    def is_allowed_account(self, platform: str, cred_hash: str) -> bool:
        return any(a.hash == cred_hash for a in self.account_list(platform))


# ---------------------------------------------------------------------------
# Minimal YAML subset parser (stdlib only). Supports: comments, nested maps,
# dash lists, scalars (int/float/bool/null/quoted/plain), blank lines.
# Not supported: anchors, aliases, multi-line scalars, flow collections.
# ---------------------------------------------------------------------------

class YamlError(ConfigError):
    pass


def _parse_flow_list(token: str):
    """Parse a flow list like [a, b, "c d"] into Python values."""
    inner = token.strip()
    if not (inner.startswith("[") and inner.endswith("]")):
        return None
    inner = inner[1:-1]
    parts = []
    buf = ""
    quote = None
    for ch in inner:
        if quote:
            if ch == quote:
                quote = None
            buf += ch
        elif ch in "\"'":
            quote = ch
            buf += ch
        elif ch == ",":
            parts.append(buf.strip())
            buf = ""
        else:
            buf += ch
    if buf.strip():
        parts.append(buf.strip())
    return [_parse_scalar(p) for p in parts if p != ""]


def _parse_scalar(token: str) -> Any:
    token = token.strip()
    if not token:
        return None
    flow = _parse_flow_list(token)
    if flow is not None:
        return flow
    if (token.startswith('"') and token.endswith('"')) or \
       (token.startswith("'") and token.endswith("'")):
        return token[1:-1]
    if token in ("null", "~"):
        return None
    if token in ("true", "True"):
        return True
    if token in ("false", "False"):
        return False
    if re.fullmatch(r"-?\d+", token):
        return int(token)
    if re.fullmatch(r"-?\d+\.\d+", token):
        return float(token)
    return token


def _strip_comment(line: str) -> str:
    out = ""
    quote = None
    for ch in line:
        if quote:
            out += ch
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            out += ch
        elif ch == "#":
            break
        else:
            out += ch
    return out.rstrip()


def _parse_yaml(text: str) -> dict:
    """Parse the documented safe YAML subset (maps, dash lists, flow lists,
    scalars, comments, quoted strings) via recursive descent."""
    lines = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        lines.append((indent, line.strip()))

    def parse_block(idx: int, indent: int):
        node: dict = {}
        idx = _parse_into(idx, indent, node)
        return node, idx

    def _parse_into(idx: int, indent: int, target: dict):
        while idx < len(lines):
            i, line = lines[idx]
            if i != indent:
                break
            if line.startswith("- "):
                break
            key, _, val = line.partition(":")
            key = key.strip()
            if not key:
                raise YamlError(f"malformed line: {line!r}")
            val = val.strip()
            if val == "":
                if idx + 1 < len(lines) and lines[idx + 1][0] > i:
                    child, idx = parse_value(idx + 1, lines[idx + 1][0])
                    target[key] = child
                else:
                    target[key] = None
                    idx += 1
            else:
                target[key] = _parse_scalar(val)
                idx += 1
        return idx

    def parse_list(idx: int, indent: int):
        lst = []
        while idx < len(lines):
            i, line = lines[idx]
            if i < indent:
                break
            if i > indent:
                raise YamlError(f"unexpected indentation at line {line!r}")
            if not line.startswith("- "):
                break
            item_text = line[2:].strip()
            if item_text == "":
                if idx + 1 < len(lines) and lines[idx + 1][0] > i:
                    child, idx = parse_value(idx + 1, lines[idx + 1][0])
                    lst.append(child)
                else:
                    lst.append(None)
                    idx += 1
            elif ":" in item_text and not item_text.startswith(("'", '"')):
                key, _, val = item_text.partition(":")
                key = key.strip()
                val = val.strip()
                entry: dict = {}
                if val == "":
                    if idx + 1 < len(lines) and lines[idx + 1][0] > i:
                        child, idx = parse_value(idx + 1, lines[idx + 1][0])
                        entry[key] = child
                    else:
                        entry[key] = None
                        idx += 1
                else:
                    entry[key] = _parse_scalar(val)
                    idx += 1
                lst.append(entry)
                if idx < len(lines) and lines[idx][0] > i:
                    idx = _parse_into(idx, lines[idx][0], entry)
            else:
                lst.append(_parse_scalar(item_text))
                idx += 1
        return lst, idx

    def parse_value(idx: int, indent: int):
        i, line = lines[idx]
        if line.startswith("- "):
            return parse_list(idx, indent)
        return parse_block(idx, indent)

    if not lines:
        return {}
    root, _ = parse_block(0, lines[0][0])
    return root


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

CONFIG_DIR = os.environ.get("REACH_GUARD_CONFIG_DIR",
                            os.path.expanduser("~/.config/reach-guard"))
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.yaml")
STATE_DIR = os.environ.get("REACH_GUARD_STATE_DIR",
                           os.path.expanduser("~/.local/share/reach-guard"))
STATE_FILE = os.path.join(STATE_DIR, "state.jsonl")
LOCK_FILE = os.path.join(STATE_DIR, "guard.lock")
LOG_DIR = os.path.join(STATE_DIR, "logs")
PROFILE_ROOT = os.path.join(STATE_DIR, "profiles")

# Keys config.yaml is allowed to touch (strict: no platform definition).
_OVERRIDE_KEYS = {
    "platforms", "proxy", "accounts", "time_windows", "lock_timeout",
    "egress_endpoint", "geo_endpoint", "egress_timeout", "bilibili",
    "xhs_mcp", "no_proxy",
}
# Per-platform keys allowed to override.
_PLATFORM_KEYS = {"interval", "jitter", "hourly", "daily", "batch",
                  "signals", "ip", "proxy_mode", "backend",
                  "anon_allowed", "creds", "windows", "permanent"}


def _validate_platform_override(name: str, over: dict) -> dict:
    for k in over:
        if k not in _PLATFORM_KEYS:
            raise ConfigError(
                f"config.yaml platform[{name}] unknown key {k!r} "
                f"(allowed: {sorted(_PLATFORM_KEYS)})"
            )
    if name not in DEFAULT_PLATFORMS:
        raise UnregisteredPlatformError(
            f"config.yaml defines platform {name!r} which is not in the strict "
            f"table; new platforms require a code change (exit 6)"
        )
    base = dict(DEFAULT_PLATFORMS[name])
    for k, v in over.items():
        if v is None:
            continue
        if k == "signals":
            if not isinstance(v, list):
                raise ConfigError(f"platform[{name}].signals must be a list")
            base["signals"] = [str(s) for s in v]
        elif k == "permanent":
            if not isinstance(v, list):
                raise ConfigError(f"platform[{name}].permanent must be a list")
            base["permanent"] = [str(s) for s in v]
        elif k == "creds":
            if not isinstance(v, list):
                raise ConfigError(f"platform[{name}].creds must be a list")
            base["creds"] = [str(s) for s in v]
        elif k == "windows":
            if not isinstance(v, list):
                raise ConfigError(f"platform[{name}].windows must be a list")
            base["windows"] = [tuple(w) for w in v]
        elif k in ("interval", "jitter", "hourly", "daily", "batch"):
            if not isinstance(v, (int, float)) or v < 0:
                raise ConfigError(f"platform[{name}].{k} must be a non-negative number")
            base[k] = int(v) if k not in ("interval", "jitter") else float(v)
        elif k in ("ip", "proxy_mode", "backend"):
            base[k] = str(v)
        elif k == "anon_allowed":
            if not isinstance(v, bool):
                raise ConfigError(f"platform[{name}].anon_allowed must be bool")
            base["anon_allowed"] = v
        else:
            raise ConfigError(f"platform[{name}].{k} unsupported override")
    return base


def _validate_accounts(raw: Any) -> dict:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError("accounts must be a map platform -> list of {label, hash}")
    out = {}
    for platform, entries in raw.items():
        if platform not in DEFAULT_PLATFORMS:
            raise UnregisteredPlatformError(
                f"accounts for unregistered platform {platform!r} (exit 6)"
            )
        if not isinstance(entries, list):
            raise ConfigError(f"accounts[{platform}] must be a list")
        accs = []
        for e in entries:
            if not isinstance(e, dict):
                raise ConfigError(f"accounts[{platform}] entry must be a map")
            label = e.get("label")
            chash = e.get("hash")
            if not label or not isinstance(chash, str) or not chash:
                raise ConfigError(
                    f"accounts[{platform}] entry needs non-empty label and hash"
                )
            if not re.fullmatch(r"[0-9a-f]{64}", chash):
                raise ConfigError(
                    f"accounts[{platform}][{label}] hash must be sha256 hex (64 chars)"
                )
            accs.append(AccountEntry(label=str(label), hash=chash, platform=platform))
        out[platform] = accs
    return out


def load_config(path: Optional[str] = None) -> Config:
    cfg = Config()
    cfg.profile_dir = PROFILE_ROOT
    p = path or CONFIG_FILE
    if not os.path.exists(p):
        return cfg  # built-in strict defaults
    try:
        with open(p, "r", encoding="utf-8") as f:
            raw = _parse_yaml(f.read())
    except YamlError as e:
        raise ConfigError(f"config.yaml parse error: {e}")
    if not isinstance(raw, dict):
        raise ConfigError("config.yaml must be a mapping at the top level")

    for k in raw:
        if k not in _OVERRIDE_KEYS:
            raise ConfigError(
                f"config.yaml unknown top-level key {k!r} "
                f"(allowed: {sorted(_OVERRIDE_KEYS)})"
            )

    if "platforms" in raw and raw["platforms"] is not None:
        if not isinstance(raw["platforms"], dict):
            raise ConfigError("platforms must be a map")
        for name, over in raw["platforms"].items():
            if over is None:
                over = {}
            if not isinstance(over, dict):
                raise ConfigError(f"platforms[{name}] must be a map")
            cfg.platforms[name] = _validate_platform_override(name, over)

    if "proxy" in raw and raw["proxy"] is not None:
        plist = raw["proxy"] if isinstance(raw["proxy"], list) else [raw["proxy"]]
        for e in plist:
            if not isinstance(e, dict) or not e.get("url"):
                raise ConfigError("each proxy entry needs a url")
            pe = ProxyEntry(
                url=str(e["url"]),
                ptype=str(e.get("type", "residential")),
                country=str(e.get("country", "")),
                account=str(e.get("account", "")),
            )
            pe.validate()
            cfg.proxies.append(pe)

    if "accounts" in raw:
        cfg.accounts = _validate_accounts(raw["accounts"])

    if "time_windows" in raw and raw["time_windows"] is not None:
        tw = raw["time_windows"]
        if not isinstance(tw, list) or not tw or not all(
            isinstance(w, list) and len(w) == 2 for w in tw
        ):
            raise ConfigError("time_windows must be a list of [start_min, end_min]")
        cfg.time_windows = [tuple(int(a) for a in w) for w in tw]

    for key, cvt in (
        ("lock_timeout", float),
        ("egress_timeout", float),
    ):
        if key in raw and raw[key] is not None:
            try:
                cfg.__dict__[key] = cvt(raw[key])
            except (TypeError, ValueError):
                raise ConfigError(f"{key} must be a number")

    for key in ("egress_endpoint", "geo_endpoint"):
        if key in raw and raw[key] is not None:
            cfg.__dict__[key] = str(raw[key])

    if "no_proxy" in raw and raw["no_proxy"] is not None:
        cfg.no_proxy = str(raw["no_proxy"])
        _validate_no_proxy(cfg.no_proxy)

    bili = raw.get("bilibili") if isinstance(raw.get("bilibili"), dict) else {}
    if isinstance(bili, dict) and "anon" in bili:
        if not isinstance(bili["anon"], bool):
            raise ConfigError("bilibili.anon must be bool")
        cfg.bili_anon = bili["anon"]

    xhs = raw.get("xhs_mcp") if isinstance(raw.get("xhs_mcp"), dict) else {}
    if isinstance(xhs, dict) and "docker_network" in xhs:
        cfg.xhs_mcp_docker_network = str(xhs["docker_network"])

    return cfg


def _validate_no_proxy(no_proxy: str) -> None:
    """NO_PROXY must not carry platform-domain wildcards (would bypass guard
    semantics at the network layer)."""
    domains = {d.strip().lower() for d in no_proxy.split(",") if d.strip()}
    for domain in domains:
        bare = domain.lstrip(".*").lstrip(".")
        for host, platform in HOST_PLATFORM.items():
            if bare and (host == bare or host.endswith("." + bare)):
                raise ConfigError(
                    f"NO_PROXY contains {domain!r} which matches platform host "
                    f"{host!r} ({platform}); refusing config (exit 2)"
                )


def resolve_platform(bin_name: str, args: list, cfg: Config) -> tuple:
    """Resolve (platform|None, exempt: bool, meta: bool, reason: str).

    bin_name comes from argv[0] (shim) or the run subcommand. args = argv[1:].
    Raises UnregisteredPlatformError / UpstreamError per fail-closed rules.
    """
    if bin_name == "gh":
        return "github", True, False, "github exempt route"
    if bin_name == "curl":
        return _curl_platform(args, cfg)
    if bin_name == "yt-dlp":
        url = next((a for a in args if a.startswith(("http://", "https://"))), "")
        if any(h in url for h in ("bilibili.com", "b23.tv")):
            raise UnregisteredPlatformError(
                "yt-dlp must not be used for Bilibili (use `bili`); exit 6"
            )
        return "youtube", False, False, "yt-dlp -> youtube"
    if bin_name == "mcporter":
        return _mcporter_platform(args, cfg)
    if bin_name == "opencli":
        return _opencli_platform(args, cfg)
    if bin_name == "agent-reach":
        # agent-reach is the router; commands route per its subcommand.
        cmd = args[0] if args else ""
        if cmd in ("doctor", "install", "check-update", "configure", "--help",
                   "-h", "--version", "-V", "help"):
            return None, False, True, "agent-reach management command"
        return None, False, False, "agent-reach routed command (treated as generic)"
    if bin_name == "twitter":
        return "twitter", False, False, "twitter-cli"
    if bin_name == "bili":
        return "bilibili", False, False, "bili-cli"
    raise UpstreamError(
        f"unknown wrapped binary {bin_name!r}; fail-closed (exit 8)"
    )


def _curl_platform(args: list, cfg: Config):
    url = next((a for a in args if a.startswith(("http://", "https://"))), "")
    if not url:
        return None, False, True, "curl with no URL (meta)"
    host = url.split("/")[2].lower()
    bare = host.split(":")[0]
    bare = bare.removeprefix("www.")
    # platform-mapped hosts first (v2ex.com -> guarded v2ex platform)
    for h, platform in HOST_PLATFORM.items():
        if bare == h or bare.endswith("." + h.removeprefix("www.")):
            return platform, False, False, f"curl host {bare} -> {platform}"
    if bare in CURL_ALLOWLIST_HOSTS:
        return None, False, False, f"curl allowlisted host {bare} (passthrough)"
    raise UpstreamError(
        f"curl host {bare!r} not mapped to a platform and not allowlisted; "
        f"fail-closed (exit 8)"
    )


def _mcporter_platform(args: list, cfg: Config):
    cmd = args[0] if args else ""
    if cmd in MCPORTER_META_COMMANDS or cmd in ("doctor",):
        return None, False, True, "mcporter meta command"
    if cmd == "call":
        tool = args[1] if len(args) > 1 else ""
        if tool.startswith("exa."):
            return "websearch", False, False, "mcporter exa web search"
        raise UnregisteredPlatformError(
            f"mcporter tool {tool!r} not in allowlist (only exa.*); exit 6"
        )
    raise UnregisteredPlatformError(
        f"mcporter subcommand {cmd!r} not recognized; exit 6"
    )


def _opencli_platform(args: list, cfg: Config):
    sub = args[0] if args else ""
    if sub in OPENCLI_META_COMMANDS:
        return None, False, True, "opencli meta command"
    if sub in OPENCLI_PLATFORM:
        return OPENCLI_PLATFORM[sub], False, False, f"opencli {sub}"
    raise UnregisteredPlatformError(
        f"opencli adapter {sub!r} not in the strict table; exit 6"
    )
