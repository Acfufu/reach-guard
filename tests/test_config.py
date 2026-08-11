"""Todo 2: config schema, strict defaults, YAML override, validation."""

import pytest

from reach_guard.config import (ConfigError, UnregisteredPlatformError,
                                load_config, DEFAULT_PLATFORMS, DEFAULT_TIME_WINDOWS,
                                resolve_platform, UpstreamError, CONFIG_FILE)


def test_no_config_uses_builtin_defaults():
    cfg = load_config()
    assert cfg.platforms == DEFAULT_PLATFORMS
    assert cfg.time_windows == DEFAULT_TIME_WINDOWS
    assert cfg.platform("xiaohongshu")["interval"] == 10
    assert cfg.platform("v2ex")["daily"] == 500  # approved addition


def test_minimal_config_loads(write_config):
    write_config("lock_timeout: 30\nbilibili:\n  anon: true\n")
    cfg = load_config()
    assert cfg.lock_timeout == 30
    assert cfg.bili_anon is True


def test_quota_override_applies(write_config):
    write_config("platforms:\n  v2ex:\n    daily: 100\n    interval: 5\n")
    cfg = load_config()
    assert cfg.platform("v2ex")["daily"] == 100
    assert cfg.platform("v2ex")["interval"] == 5


def test_unknown_top_level_key_exit2(write_config):
    write_config("bogus_key: 1\n")
    with pytest.raises(ConfigError):
        load_config()


def test_invalid_value_exit2(write_config):
    write_config("lock_timeout: not-a-number\n")
    with pytest.raises(ConfigError):
        load_config()


def test_platform_unknown_key_exit2(write_config):
    write_config("platforms:\n  v2ex:\n    nope: 1\n")
    with pytest.raises(ConfigError):
        load_config()


def test_unregistered_platform_exit6(write_config):
    write_config("platforms:\n  tiktok:\n    daily: 10\n")
    with pytest.raises(UnregisteredPlatformError):
        load_config()


def test_accounts_validation(write_config):
    write_config("accounts:\n  twitter:\n    - label: burner\n      hash: " + "a" * 64 + "\n")
    cfg = load_config()
    assert cfg.account_list("twitter")[0].label == "burner"


def test_accounts_bad_hash_exit2(write_config):
    write_config("accounts:\n  twitter:\n    - label: burner\n      hash: short\n")
    with pytest.raises(ConfigError):
        load_config()


def test_accounts_unregistered_platform_exit6(write_config):
    write_config("accounts:\n  tiktok:\n    - label: x\n      hash: " + "b" * 64 + "\n")
    with pytest.raises(UnregisteredPlatformError):
        load_config()


def test_proxy_residential_only(write_config):
    write_config("proxy:\n  - url: http://1.2.3.4:8080\n    type: residential\n")
    assert len(load_config().proxies) == 1


def test_proxy_datacenter_rejected(write_config):
    write_config("proxy:\n  - url: http://1.2.3.4:8080\n    type: datacenter\n")
    with pytest.raises(ConfigError):
        load_config()


def test_time_windows_override(write_config):
    write_config("time_windows:\n  - [0, 1440]\n")
    assert load_config().time_windows == [(0, 1440)]


def test_no_proxy_platform_wildcard_exit2(write_config):
    write_config("no_proxy: \"*.bilibili.com,foo.com\"\n")
    with pytest.raises(ConfigError):
        load_config()


def test_no_proxy_safe_passthrough(write_config):
    write_config("no_proxy: \"localhost,127.0.0.1\"\n")
    assert load_config().no_proxy == "localhost,127.0.0.1"


def test_resolve_platform_bili():
    cfg = load_config()
    p, ex, meta, _ = resolve_platform("bili", ["search", "python"], cfg)
    assert p == "bilibili" and ex is False and meta is False


def test_resolve_opencli_xhs():
    cfg = load_config()
    p, _, _, _ = resolve_platform("opencli", ["xiaohongshu", "search", "x"], cfg)
    assert p == "xiaohongshu"


def test_resolve_opencli_unknown_exit6():
    cfg = load_config()
    with pytest.raises(UnregisteredPlatformError):
        resolve_platform("opencli", ["tiktok", "x"], cfg)


def test_resolve_curl_v2ex_guarded():
    cfg = load_config()
    p, ex, meta, _ = resolve_platform(
        "curl", ["https://www.v2ex.com/api/topics/hot.json"], cfg)
    assert p == "v2ex" and meta is False


def test_resolve_curl_jina_passthrough():
    cfg = load_config()
    p, _, _, _ = resolve_platform("curl", ["https://r.jina.ai/example.com"], cfg)
    assert p is None


def test_resolve_curl_unknown_host_exit8():
    cfg = load_config()
    with pytest.raises(UpstreamError):
        resolve_platform("curl", ["https://evil.example.com/x"], cfg)


def test_resolve_gh_exempt():
    cfg = load_config()
    p, ex, meta, _ = resolve_platform("gh", ["api", "rate_limit"], cfg)
    assert p == "github" and ex is True


def test_ytdlp_bili_refused():
    cfg = load_config()
    with pytest.raises(UnregisteredPlatformError):
        resolve_platform("yt-dlp", ["https://www.bilibili.com/video/BV1xx"], cfg)


def test_unknown_binary_exit8():
    cfg = load_config()
    with pytest.raises(UpstreamError):
        resolve_platform("weird", [], cfg)
