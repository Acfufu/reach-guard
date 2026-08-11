"""Todo 12: bypass detector — direct calls flagged, gh exempt, no false
positives on guarded lines."""

from reach_guard import detect


def test_flags_direct_bili():
    assert any("bili" in f for f in detect.scan_line("bili search python -n 5"))


def test_flags_direct_agent_reach():
    assert any("agent-reach" in f for f in detect.scan_line("agent-reach doctor --json"))


def test_flags_zero_config_jina():
    assert any("r.jina.ai" in f for f in detect.scan_line(
        'curl -s "https://r.jina.ai/example.com"'))


def test_flags_zero_config_mcporter_exa():
    assert any("mcporter call exa" in f for f in detect.scan_line(
        'mcporter call exa.web_search_exa query="x"'))


def test_gh_exempt_no_false_positive():
    assert detect.scan_line("gh search repos x --sort stars") == []


def test_guarded_line_not_flagged():
    assert detect.scan_line("reach-guard run bili search python") == []
    assert detect.scan_line("~/.local/bin/bili.real search x") == []


def test_curl_allowlisted_not_flagged_as_bypass():
    # reach-guard-mediated curl is fine; direct curl to v2ex via guard is fine too
    assert detect.scan_line("reach-guard run curl https://www.v2ex.com/api") == []


def test_scan_history_empty_no_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(detect, "HISTORY_FILES", [str(tmp_path / "none")])
    assert detect.scan_history() == []


def test_main_returns_0_clean(capsys, monkeypatch, tmp_path):
    from reach_guard.cli import main as cli_main
    import argparse
    monkeypatch.setattr(detect, "HISTORY_FILES", [str(tmp_path / "empty")])
    args = argparse.Namespace()
    rc = detect.main(args)
    out = capsys.readouterr().out
    assert rc == 0
    assert "no direct" in out
