"""NEW vs REUSED secrets on dry-run and --new-only mode."""

import sys
from pathlib import Path

import yaml


def test_classify_matches_new_and_reused(redact_mod, workdir):
    reverse = {"1.1.1.1": "IP_existing"}
    content = "a=1.1.1.1 b=8.8.8.8"
    new, reused = redact_mod.classify_matches(
        content, redact_mod.DEFAULT_PATTERNS, reverse
    )
    assert ("IP", "8.8.8.8") in new
    assert any(t[0] == "IP" and t[1] == "1.1.1.1" and t[2] == "IP_existing" for t in reused)


def test_dry_run_labels_new_and_reused(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text(
        "IP_old: 1.1.1.1\n",
        encoding="utf-8",
    )
    Path("x.txt").write_text("a=1.1.1.1 b=9.9.9.9\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "-n", "x.txt"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "NEW IP: 9.9.9.9" in out
    assert "REUSED IP: 1.1.1.1 -> IP_old" in out
    assert "new=" in out and "reused=" in out


def test_dry_run_new_only_hides_reused(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text(
        "IP_old: 1.1.1.1\n",
        encoding="utf-8",
    )
    Path("x.txt").write_text("a=1.1.1.1 b=9.9.9.9\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "-n", "--new-only", "x.txt"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "NEW IP: 9.9.9.9" in out
    assert "REUSED" not in out


def test_new_only_skips_file_without_new_secrets(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text(
        "IP_old: 1.1.1.1\n",
        encoding="utf-8",
    )
    Path("x.txt").write_text("only=1.1.1.1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "--new-only", "x.txt"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Skipped (no new secrets)" in out
    assert not Path("redacted/x.txt").exists()
    # Dictionary unchanged
    assert yaml.safe_load(Path("redacted/dictionary.yaml").read_text(encoding="utf-8")) == {
        "IP_old": "1.1.1.1"
    }


def test_new_only_writes_when_new_secret_present(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text(
        "IP_old: 1.1.1.1\n",
        encoding="utf-8",
    )
    Path("x.txt").write_text("a=1.1.1.1 b=9.9.9.9\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "--new-only", "x.txt"])
    redact_mod.main()
    text = Path("redacted/x.txt").read_text(encoding="utf-8")
    assert "1.1.1.1" not in text
    assert "9.9.9.9" not in text
    assert "IP_old" in text
    d = yaml.safe_load(Path("redacted/dictionary.yaml").read_text(encoding="utf-8"))
    assert "1.1.1.1" in d.values()
    assert "9.9.9.9" in d.values()
