"""Quiet, verbose, and summary output for redact."""

import sys
from pathlib import Path


def test_summary_line_default_run(redact_mod, workdir, monkeypatch, capsys):
    Path("a.txt").write_text("ip=10.0.0.1\n", encoding="utf-8")
    Path("b.txt").write_text("plain\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "a.txt", "b.txt"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Summary:" in out
    assert "redacted=" in out
    assert "errors=0" in out


def test_quiet_only_summary_on_stdout(redact_mod, workdir, monkeypatch, capsys):
    Path("a.txt").write_text("ip=10.0.0.1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "-q", "a.txt"])
    redact_mod.main()
    out = capsys.readouterr().out.strip().splitlines()
    # Quiet: no per-file chatter; summary still printed
    assert any(line.startswith("Summary:") for line in out)
    assert not any("Redacted file written" in line for line in out)


def test_verbose_shows_match_detail(redact_mod, workdir, monkeypatch, capsys):
    Path("a.txt").write_text("ip=10.0.0.1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "-v", "a.txt"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Redacted file written" in out
    assert "IP: 10.0.0.1" in out or "matches:" in out


def test_quiet_and_verbose_conflict(redact_mod, workdir, monkeypatch, capsys):
    Path("a.txt").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "-q", "-v", "a.txt"])
    try:
        redact_mod.main()
        raised = False
    except SystemExit as exc:
        raised = True
        assert exc.code == 2
    assert raised
    assert "Cannot combine" in capsys.readouterr().err


def test_dry_run_summary(redact_mod, workdir, monkeypatch, capsys):
    Path("a.txt").write_text("ip=1.1.1.1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "-n", "a.txt"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Summary:" in out
    assert "would_redact=" in out
