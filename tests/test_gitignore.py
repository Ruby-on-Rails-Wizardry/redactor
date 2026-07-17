"""Ensure redacted/ is kept out of git via .gitignore."""

from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "content, expected",
    [
        ("redacted/\n", True),
        ("redacted\n", True),
        ("/redacted/\n", True),
        ("**/redacted/\n", True),
        ("foo/redacted\n", True),
        (".venv/\n", False),
        ("# redacted/\n", False),
        ("!redacted/\n", False),
        ("redacted_backup/\n", False),
        ("", False),
    ],
)
def test_redacted_in_gitignore(redact_mod, content, expected):
    assert redact_mod.redacted_in_gitignore(content) is expected


def test_ensure_adds_entry_when_missing(redact_mod, workdir, capsys):
    Path(".gitignore").write_text(".venv/\n", encoding="utf-8")
    assert redact_mod.ensure_redacted_gitignored() is True
    text = Path(".gitignore").read_text(encoding="utf-8")
    assert "redacted/" in text
    assert text.startswith(".venv/\n")
    assert "Added 'redacted/'" in capsys.readouterr().out


def test_ensure_noop_when_already_present(redact_mod, workdir, capsys):
    Path(".gitignore").write_text(".venv/\nredacted/\n", encoding="utf-8")
    before = Path(".gitignore").read_text(encoding="utf-8")
    assert redact_mod.ensure_redacted_gitignored() is False
    assert Path(".gitignore").read_text(encoding="utf-8") == before
    assert capsys.readouterr().out == ""


def test_ensure_creates_gitignore_if_missing(redact_mod, workdir, capsys):
    assert not Path(".gitignore").exists()
    assert redact_mod.ensure_redacted_gitignored() is True
    assert Path(".gitignore").read_text(encoding="utf-8") == "redacted/\n"
    assert "Added 'redacted/'" in capsys.readouterr().out


def test_ensure_accepts_redacted_without_slash(redact_mod, workdir):
    Path(".gitignore").write_text("redacted\n", encoding="utf-8")
    assert redact_mod.ensure_redacted_gitignored() is False


def test_redact_file_adds_gitignore_entry(redact_mod, workdir, monkeypatch):
    import sys

    Path("doc.txt").write_text("ip=1.2.3.4\n", encoding="utf-8")
    assert not Path(".gitignore").exists()
    monkeypatch.setattr(sys, "argv", ["redact", "doc.txt"])
    redact_mod.main()
    assert Path(".gitignore").is_file()
    assert redact_mod.redacted_in_gitignore(
        Path(".gitignore").read_text(encoding="utf-8")
    )


def test_patterns_init_adds_gitignore_entry(redact_mod, workdir, monkeypatch):
    import sys

    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "init"])
    redact_mod.main()
    assert redact_mod.redacted_in_gitignore(
        Path(".gitignore").read_text(encoding="utf-8")
    )


def test_repo_gitignore_includes_redacted():
    """Project .gitignore should ignore redacted/ so secrets are not committed."""
    root = Path(__file__).resolve().parents[1]
    text = (root / ".gitignore").read_text(encoding="utf-8")
    # Inline the same rules as production without loading the script
    lines = [
        line.strip().rstrip("/")
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert "redacted" in lines or any(line.endswith("/redacted") for line in lines)
