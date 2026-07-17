"""Unit and CLI-level tests for bin/unredact."""

import subprocess
import sys
from pathlib import Path

import pytest
import yaml



def test_unredact_content_replaces_placeholders(unredact_mod):
    content = "Hello EMAIL_aabbccdd at IP_11223344"
    dictionary = {
        "EMAIL_aabbccdd": "a@b.co",
        "IP_11223344": "1.2.3.4",
    }
    assert unredact_mod.unredact_content(content, dictionary) == "Hello a@b.co at 1.2.3.4"


def test_unredact_content_leaves_unknown_placeholders(unredact_mod):
    content = "keep EMAIL_unknown as-is"
    assert unredact_mod.unredact_content(content, {}) == content


def test_load_dictionary_missing_exits(unredact_mod, workdir, capsys):
    with pytest.raises(SystemExit) as exc:
        unredact_mod.load_dictionary()
    assert exc.value.code == 1
    assert "Dictionary file not found" in capsys.readouterr().err


def test_get_redacted_content_from_file(unredact_mod, workdir):
    path = Path("redacted/x.txt")
    path.parent.mkdir(parents=True)
    path.write_text("secret-placeholder\n", encoding="utf-8")
    assert unredact_mod.get_redacted_content(path) == "secret-placeholder\n"


def test_get_redacted_content_from_stdin(unredact_mod, workdir, monkeypatch):
    lines = iter(["line1", "line2"])

    def fake_input():
        try:
            return next(lines)
        except StopIteration as exc:
            raise EOFError from exc

    monkeypatch.setattr("builtins.input", fake_input)
    content = unredact_mod.get_redacted_content(Path("missing.txt"))
    assert content == "line1\nline2"


def test_main_requires_argument(unredact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["unredact"])
    with pytest.raises(SystemExit) as exc:
        unredact_mod.main()
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "Usage:" in out
    assert "directory" in out.lower() or "directories" in out.lower()
    assert "dictionary.yaml" in out
    assert ".git" in out
    assert "stderr" in out or "non-zero" in out or "failed" in out


def test_main_restores_file(unredact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text(
        yaml.safe_dump({"IP_deadbeef": "9.9.9.9", "EMAIL_cafebabe": "z@z.z"}),
        encoding="utf-8",
    )
    Path("redacted/out.txt").write_text(
        "host IP_deadbeef mail EMAIL_cafebabe\n",
        encoding="utf-8",
    )
    # original path may not exist yet; unredact writes it
    monkeypatch.setattr(sys, "argv", ["unredact", "out.txt"])
    unredact_mod.main()

    restored = Path("out.txt").read_text(encoding="utf-8")
    assert restored == "host 9.9.9.9 mail z@z.z\n"
    assert "Restored file written to:" in capsys.readouterr().out


def test_main_restores_multiple_files(unredact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text(
        yaml.safe_dump({"IP_deadbeef": "9.9.9.9"}),
        encoding="utf-8",
    )
    Path("redacted/a.txt").write_text("IP_deadbeef\n", encoding="utf-8")
    Path("redacted/b.txt").write_text("x IP_deadbeef y\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["unredact", "a.txt", "b.txt"])
    unredact_mod.main()

    assert Path("a.txt").read_text(encoding="utf-8") == "9.9.9.9\n"
    assert Path("b.txt").read_text(encoding="utf-8") == "x 9.9.9.9 y\n"
    out = capsys.readouterr().out
    assert "a.txt" in out and "b.txt" in out


def test_main_restores_directory_recursively(unredact_mod, workdir, monkeypatch):
    Path("app/cfg").mkdir(parents=True)
    Path("redacted/app/cfg").mkdir(parents=True)
    Path("redacted/dictionary.yaml").write_text(
        yaml.safe_dump({"IP_aabb": "1.2.3.4"}),
        encoding="utf-8",
    )
    Path("redacted/app/cfg/x.env").write_text("IP_aabb\n", encoding="utf-8")
    Path("redacted/app/y.txt").write_text("z IP_aabb\n", encoding="utf-8")
    # originals can be missing; unredact recreates them
    monkeypatch.setattr(sys, "argv", ["unredact", "app"])
    unredact_mod.main()

    assert Path("app/cfg/x.env").read_text(encoding="utf-8") == "1.2.3.4\n"
    assert Path("app/y.txt").read_text(encoding="utf-8") == "z 1.2.3.4\n"


def test_cli_subprocess_unredact(workdir):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text(
        "IP_aabbccdd: 1.1.1.1\n",
        encoding="utf-8",
    )
    Path("redacted/cli.txt").write_text("IP_aabbccdd\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "redactor.unredact", "cli.txt"],
        cwd=workdir,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert Path("cli.txt").read_text(encoding="utf-8") == "1.1.1.1\n"
