"""Risk-signal circuit breaker.

Signal -> tier mapping is a (platform, signal-regex, tier) table. Tiers:
  cooldown   : 24h platform-wide
  quarantine : account+platform isolation; 2nd strike within 7 days; manual
               `reach-guard unlock`
  permanent  : ban-class keywords; irreversible via CLI
Context whitelist (benign anonymous/guest text) is evaluated FIRST and never
trips the breaker. 200-empty heuristic: douyin expected-data command that
exits 0 with empty stdout is treated as a cooldown signal. When a breaker
trips and the upstream also errors, the breaker wins (exit 7).
"""

from __future__ import annotations

import re
import time
from typing import Optional

from .config import (Config, PERMANENT_SIGNAL_RE, SIGNAL_WHITELIST,
                     BreakerError)
from . import state

COOLDOWN_HOURS = 24.0
QUARANTINE_LOOKBACK_DAYS = 7


def _compiled_signals(platform: str, cfg: Config) -> list:
    pcfg = cfg.platform(platform)
    pats = list(pcfg.get("signals", []))
    for s in pcfg.get("permanent", []):
        pats.append(s)  # platform ban-class additions also matched here
    out = []
    for p in pats:
        pat = re.escape(p) if not _is_regex(p) else p
        if re.fullmatch(r"-?\d+", p):
            # bare numeric HTTP/risk codes must be digit-bounded, otherwise
            # they false-positive inside unicode escapes (\u5403 -> 5403) and
            # curl progress-meter byte counts
            pat = rf"(?<!\d){pat}(?!\d)"
        out.append(re.compile(pat, re.I))
    return out


def _is_regex(p: str) -> bool:
    # heuristic: strings containing regex metacharacters are treated as regex
    return bool(re.search(r"[.*+?^${}()|[\]\\]", p))


def _whitelisted(cfg: Config, platform: str, args: list, signal_text: str,
                 anonymous: bool) -> bool:
    argstr = " ".join(args)
    for (wp, arg_re, sig_re, anon_only) in SIGNAL_WHITELIST:
        if wp != platform:
            continue
        if anon_only and not anonymous:
            continue
        if re.search(arg_re, argstr, re.I) and re.search(sig_re, signal_text, re.I):
            return True
    return False


_METER_CHUNK = re.compile(r"^[\d\s%:.\-kK]+$")
_METER_MARK = re.compile(r"--:--:--|\d+\.?\d*[kK]")


def _strip_progress_noise(text: str) -> str:
    """Drop curl progress-meter \r-chunks (numeric-column blocks carrying
    timing/speed markers) from the scan input so transient byte/speed values
    never trip numeric signals. Bare numeric lines (e.g. a lone status code)
    are preserved."""
    chunks = text.split("\r")
    kept = []
    for c in chunks:
        s = c.strip()
        if _METER_CHUNK.match(s) and _METER_MARK.search(s):
            continue
        kept.append(c)
    return "\n".join(kept)


def scan(cfg: Config, platform: str, args: list, stdout: str, stderr: str,
         exit_code: int, anonymous: bool) -> Optional[str]:
    """Return matched signal string, or None. Checks whitelist -> permanent ->
    cooldown -> 200-empty heuristic."""
    combined = _strip_progress_noise(f"{stdout}\n{stderr}")
    if _whitelisted(cfg, platform, args, combined, anonymous):
        return None

    if PERMANENT_SIGNAL_RE.search(combined):
        return "PERMANENT:" + _first(PERMANENT_SIGNAL_RE, combined)

    for sig in _compiled_signals(platform, cfg):
        m = sig.search(combined)
        if m:
            return m.group(0)

    # 200-empty honeypot: douyin expected-data command, exit 0, empty stdout
    if platform == "douyin" and exit_code == 0 and not stdout.strip():
        return "200-empty-heuristic"
    return None


def _first(rx: re.Pattern, text: str) -> str:
    m = rx.search(text)
    return m.group(0) if m else rx.pattern


def enforce(cfg: Config, platform: str, account_hash: str, args: list,
            stdout: str, stderr: str, exit_code: int, anonymous: bool,
            now: Optional[float] = None) -> None:
    """Scan and, if tripped, apply tier + raise BreakerError (exit 7)."""
    now = now or time.time()
    signal = scan(cfg, platform, args, stdout, stderr, exit_code, anonymous)
    if not signal:
        return

    if signal.startswith("PERMANENT:"):
        state.record_breaker(platform, account_hash, "permanent",
                             signal.removeprefix("PERMANENT:"), until=0)
        raise BreakerError(
            f"permanent ban-class signal matched ({platform}): "
            f"{signal!r}; account isolated permanently; exit 7"
        )

    # cooldown vs quarantine: 2nd strike on same (account, platform) in 7d
    prev = state.find_breaker(platform, account_hash)
    strike2 = (prev is not None and prev.get("tier") == "cooldown"
               and (prev.get("ts") or 0) >= now - QUARANTINE_LOOKBACK_DAYS * 86400
               and prev.get("active", True))
    if strike2:
        state.record_breaker(platform, account_hash, "quarantine",
                             signal, until=0, active=True)
        raise BreakerError(
            f"2nd risk strike on {platform} within 7d: {signal!r}; account "
            f"quarantined (run `reach-guard unlock {platform} <account>`); exit 7"
        )

    until = now + COOLDOWN_HOURS * 3600
    state.record_breaker(platform, account_hash, "cooldown", signal,
                         until=until, active=True)
    raise BreakerError(
        f"risk signal on {platform}: {signal!r}; platform cooldown 24h "
        f"(until {time.strftime('%m-%d %H:%M', time.localtime(until))}); exit 7"
    )


def check_before_run(cfg: Config, platform: str, account_hash: str,
                     now: Optional[float] = None) -> None:
    """Pre-flight: refuse if a breaker is active (exit 7 wins)."""
    now = now or time.time()
    active = state.breaker_active(platform, account_hash, now)
    if active:
        tier, until = active
        if tier == "permanent":
            raise BreakerError(
                f"account permanently isolated ({platform}); exit 7"
            )
        if tier == "quarantine":
            raise BreakerError(
                f"account quarantined ({platform}); run `reach-guard unlock`; exit 7"
            )
        raise BreakerError(
            f"platform {platform} in cooldown until "
            f"{time.strftime('%m-%d %H:%M', time.localtime(until))}; exit 7"
        )
