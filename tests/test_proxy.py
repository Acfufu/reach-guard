"""Todo 8: proxy binding, backend matrix, geo-match, profile generation."""

import os

import pytest

from reach_guard import proxy_layer
from reach_guard.config import (Config, ProxyEntry, IPError, load_config,
                                PROXY_ENV, PROXY_PROFILE)


def _proxy_cfg():
    cfg = load_config()
    cfg.proxies = [ProxyEntry(url="http://1.2.3.4:8080", country="US",
                              account="h1")]
    return cfg


def test_bili_reject_exit3():
    cfg = load_config()
    cfg.bili_anon = False
    with pytest.raises(IPError) as ei:
        proxy_layer.verify_binding(cfg, "bilibili", "h1", None, live=False)
    assert "exit 3" in str(ei.value)


def test_bili_anon_passes():
    cfg = load_config()
    cfg.bili_anon = True
    url = proxy_layer.verify_binding(cfg, "bilibili", "h1", None,
                                     anonymous=True, live=False)
    assert url == ""


def test_profile_mode_no_proxy_exit3():
    cfg = load_config()
    cfg.proxies = []
    with pytest.raises(IPError):
        proxy_layer.verify_binding(cfg, "xiaohongshu", "h1", None, live=False)


def test_profile_mode_missing_profile_file_exit3():
    cfg = _proxy_cfg()
    with pytest.raises(IPError):
        proxy_layer.verify_binding(cfg, "xiaohongshu", "h1",
                                   cfg.proxies[0], live=False)


def test_env_mode_required_no_proxy_exit3():
    cfg = load_config()
    cfg.proxies = []
    with pytest.raises(IPError):
        proxy_layer.verify_binding(cfg, "twitter", "h1", None, live=False)


def test_env_mode_optional_no_proxy_ok():
    cfg = load_config()
    cfg.proxies = []
    url = proxy_layer.verify_binding(cfg, "reddit", "h1", None, live=False)
    assert url == ""


def test_env_mode_with_proxy_live_false():
    cfg = _proxy_cfg()
    url = proxy_layer.verify_binding(cfg, "twitter", "h1", cfg.proxies[0],
                                     live=False)
    assert url == "http://1.2.3.4:8080"


def test_geo_mismatch_rejected():
    cfg = _proxy_cfg()
    with pytest.raises(IPError):
        _geo_check_with(cfg, "CN")


def test_geo_match_ok():
    cfg = _proxy_cfg()
    _geo_check_with(cfg, "US")  # matches proxy.country, no raise


def _geo_check_with(cfg, country):
    from reach_guard import proxy_layer as pl
    orig = pl.country_of
    pl.country_of = lambda c, p, ip: country
    try:
        pl._geo_check(cfg, cfg.proxies[0], "8.8.8.8", "twitter")
    finally:
        pl.country_of = orig


def test_build_env_injects_proxy():
    cfg = load_config()
    env = proxy_layer.build_env(cfg, "v2ex", "http://p:8080")
    assert env["HTTP_PROXY"] == "http://p:8080"
    assert env["HTTPS_PROXY"] == "http://p:8080"


def test_build_env_strips_for_profile_mode():
    cfg = load_config()
    base = {"HTTP_PROXY": "http://junk:9", "HTTPS_PROXY": "http://junk:9"}
    env = proxy_layer.build_env(cfg, "xiaohongshu", "", base)
    assert "HTTP_PROXY" not in env
    assert "HTTPS_PROXY" not in env


def test_build_env_no_proxy_injected():
    cfg = load_config()
    cfg.no_proxy = "localhost"
    env = proxy_layer.build_env(cfg, "v2ex", "http://p:8080")
    assert env["NO_PROXY"] == "localhost"


def test_docker_mode_requires_network_config(write_config):
    write_config("platforms:\n  xiaohongshu:\n    proxy_mode: docker\n")
    cfg = load_config()
    cfg.proxies = [ProxyEntry(url="http://1.2.3.4:8080")]
    cfg.xhs_mcp_docker_network = ""
    with pytest.raises(IPError):
        proxy_layer.verify_binding(cfg, "xiaohongshu", "h1",
                                   cfg.proxies[0], live=False)


def test_docker_mode_configured_passes_live_false(write_config):
    write_config("platforms:\n  xiaohongshu:\n    proxy_mode: docker\n")
    cfg = load_config()
    cfg.proxies = [ProxyEntry(url="http://1.2.3.4:8080")]
    cfg.xhs_mcp_docker_network = "xhs-net"
    url = proxy_layer.verify_binding(cfg, "xiaohongshu", "h1",
                                     cfg.proxies[0], live=False)
    assert url == "http://1.2.3.4:8080"


def test_generate_profile_0700(tmp_path):
    cfg = load_config()
    cfg.profile_dir = str(tmp_path)
    prof = proxy_layer.generate_profile(cfg, "xiaohongshu", "h1",
                                        ProxyEntry(url="http://1.2.3.4:8080"),
                                        account_label="burner")
    assert os.path.isdir(prof)
    assert (os.stat(prof).st_mode & 0o777) == 0o700
    flags = os.path.join(prof, "profile.flags")
    with open(flags) as f:
        content = f.read()
    assert "--proxy-server=http://1.2.3.4:8080" in content
    assert "--webrtc-ip-handling-policy=disable_non_proxied_udp" in content
    assert "user-data-dir" in content
    assert (os.stat(flags).st_mode & 0o777) == 0o600
