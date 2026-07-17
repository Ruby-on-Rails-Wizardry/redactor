"""Help and version commands for redact."""

import subprocess
import sys

import pytest


def run_redact(*args):
    return subprocess.run(
        [sys.executable, "-m", "redactor.redact", *args],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("flag", ["version", "--version", "-V"])
def test_version_flags_via_main(redact_mod, monkeypatch, capsys, flag):
    monkeypatch.setattr(sys, "argv", ["redact", flag])
    redact_mod.main()
    assert capsys.readouterr().out.strip() == f"redact {redact_mod.__version__}"


def test_help_command(redact_mod, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "help"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "usage: redact" in out
    assert "patterns" in out
    assert "exclude" in out
    assert "allowlist" in out
    assert "version" in out
    assert "dry-run" in out or "-n" in out
    assert "directories" in out.lower() or "directory" in out.lower()
    assert "examples:" in out
    assert ".git" in out
    assert "stderr" in out or "error" in out.lower()


def test_help_flag(redact_mod, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "--help"])
    redact_mod.main()
    assert "usage: redact" in capsys.readouterr().out


def test_help_patterns_subcommand(redact_mod, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "help", "patterns"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code in (0, None)
    text = capsys.readouterr().out + capsys.readouterr().err
    assert "patterns" in text
    assert "init" in text or "list" in text


def test_help_patterns_add(redact_mod, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "help", "patterns", "add"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code in (0, None)
    text = capsys.readouterr().out + capsys.readouterr().err
    assert "add" in text.lower()
    assert "regex" in text.lower() or "name" in text.lower()


def test_cli_subprocess_version_and_help():
    v = run_redact("version")
    assert v.returncode == 0, v.stderr
    assert v.stdout.startswith("redact ")

    h = run_redact("help")
    assert h.returncode == 0, h.stderr
    assert "usage: redact" in h.stdout

    hv = run_redact("-V")
    assert hv.returncode == 0, hv.stderr
    assert hv.stdout.strip() == v.stdout.strip()
