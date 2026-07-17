"""CLI management of redacted/patterns.yaml via `redact patterns`."""

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


def run_redact(*args, cwd):
    return subprocess.run(
        [sys.executable, "-m", "redactor.redact", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def test_patterns_init_writes_defaults(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "init"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Wrote built-in patterns" in out
    assert Path("redacted/patterns.yaml").is_file()
    data = yaml.safe_load(Path("redacted/patterns.yaml").read_text(encoding="utf-8"))
    assert data == redact_mod.DEFAULT_PATTERNS


def test_patterns_init_refuses_overwrite_without_force(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/patterns.yaml").write_text("ONLY: 'x'\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "init"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "already exists" in capsys.readouterr().err
    assert yaml.safe_load(Path("redacted/patterns.yaml").read_text(encoding="utf-8")) == {
        "ONLY": "x"
    }


def test_patterns_init_force_overwrites(redact_mod, workdir, monkeypatch):
    Path("redacted").mkdir()
    Path("redacted/patterns.yaml").write_text("ONLY: 'x'\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "init", "--force"])
    redact_mod.main()
    data = yaml.safe_load(Path("redacted/patterns.yaml").read_text(encoding="utf-8"))
    assert data == redact_mod.DEFAULT_PATTERNS


def test_patterns_list_shows_builtins_when_missing(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "list"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "built-in defaults" in out
    assert "EMAIL" in out
    assert "GOV" in out


def test_patterns_list_yaml(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "list", "--yaml"])
    redact_mod.main()
    data = yaml.safe_load(capsys.readouterr().out)
    assert data == redact_mod.DEFAULT_PATTERNS


def test_patterns_add_creates_from_defaults(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["redact", "patterns", "add", "CUSTOM", r"secret-\d+"],
    )
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Added" in out
    data = yaml.safe_load(Path("redacted/patterns.yaml").read_text(encoding="utf-8"))
    assert data["CUSTOM"] == r"secret-\d+"
    assert "EMAIL" in data  # seeded from defaults


def test_patterns_add_updates_existing(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "init"])
    redact_mod.main()
    capsys.readouterr()
    monkeypatch.setattr(
        sys,
        "argv",
        ["redact", "patterns", "add", "IP", r"\b\d+\.\d+\.\d+\.\d+\b"],
    )
    redact_mod.main()
    assert "Updated" in capsys.readouterr().out
    data = yaml.safe_load(Path("redacted/patterns.yaml").read_text(encoding="utf-8"))
    assert data["IP"] == r"\b\d+\.\d+\.\d+\.\d+\b"
    # Order preserved: IP still first among defaults
    assert list(data.keys())[0] == "IP"


def test_patterns_add_rejects_bad_regex(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "add", "BAD", "("])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "Invalid regex" in capsys.readouterr().err
    assert not Path("redacted/patterns.yaml").exists()


def test_patterns_remove(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "init"])
    redact_mod.main()
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "remove", "GOV"])
    redact_mod.main()
    assert "Removed" in capsys.readouterr().out
    data = yaml.safe_load(Path("redacted/patterns.yaml").read_text(encoding="utf-8"))
    assert "GOV" not in data
    assert "EMAIL" in data


def test_patterns_remove_unknown_errors(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "init"])
    redact_mod.main()
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "remove", "NOPE"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err


def test_patterns_remove_missing_file_errors(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "remove", "IP"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_load_patterns_uses_file_when_present(redact_mod, workdir):
    Path("redacted").mkdir()
    Path("redacted/patterns.yaml").write_text(
        "ONLYIP: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'\n",
        encoding="utf-8",
    )
    loaded = redact_mod.load_patterns()
    assert list(loaded.keys()) == ["ONLYIP"]
    assert re.findall(loaded["ONLYIP"], "x 1.2.3.4 y") == ["1.2.3.4"]


def test_load_patterns_falls_back_to_defaults(redact_mod, workdir):
    assert redact_mod.load_patterns() == redact_mod.DEFAULT_PATTERNS


def test_load_patterns_rejects_invalid_file(redact_mod, workdir, capsys):
    Path("redacted").mkdir()
    Path("redacted/patterns.yaml").write_text("NOT_A_MAP\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        redact_mod.load_patterns()
    assert exc.value.code == 1
    assert "Invalid patterns config" in capsys.readouterr().err


def test_redact_uses_custom_patterns_only(redact_mod, workdir, monkeypatch):
    Path("redacted").mkdir()
    Path("redacted/patterns.yaml").write_text(
        "TAG: 'SECRET-\\d+'\n",
        encoding="utf-8",
    )
    Path("doc.txt").write_text(
        "SECRET-99 and 10.0.0.1 and a@b.co\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["redact", "doc.txt"])
    redact_mod.main()
    redacted = Path("redacted/doc.txt").read_text(encoding="utf-8")
    assert "SECRET-99" not in redacted
    assert re.search(r"TAG_[0-9a-f]{8}", redacted)
    # IP/email not in custom config → left alone
    assert "10.0.0.1" in redacted
    assert "a@b.co" in redacted


def test_cli_subprocess_patterns_roundtrip(workdir):
    r = run_redact("patterns", "init", cwd=workdir)
    assert r.returncode == 0, r.stderr
    r = run_redact("patterns", "add", "HEX", r"\b0x[0-9a-f]+\b", cwd=workdir)
    assert r.returncode == 0, r.stderr
    r = run_redact("patterns", "list", cwd=workdir)
    assert r.returncode == 0
    assert "HEX" in r.stdout
    r = run_redact("patterns", "remove", "HEX", cwd=workdir)
    assert r.returncode == 0, r.stderr
    data = yaml.safe_load(Path(workdir, "redacted/patterns.yaml").read_text(encoding="utf-8"))
    assert "HEX" not in data
