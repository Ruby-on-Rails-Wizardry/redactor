"""Binary skip, decode errors, and continue-on-error behavior."""

import sys
from pathlib import Path

import pytest


def test_is_binary_extension(redact_mod):
    assert redact_mod.is_binary_extension(Path("photo.PNG"))
    assert redact_mod.is_binary_extension(Path("a/b/c.pdf"))
    assert not redact_mod.is_binary_extension(Path("notes.txt"))
    assert not redact_mod.is_binary_extension(Path("app.js"))


def test_looks_like_binary_content_null_bytes(redact_mod, workdir):
    Path("blob.bin").write_bytes(b"hello\x00world")
    assert redact_mod.looks_like_binary_content(Path("blob.bin"))
    Path("text.txt").write_text("hello world\n", encoding="utf-8")
    assert not redact_mod.looks_like_binary_content(Path("text.txt"))


def test_redact_skips_image_extension(redact_mod, workdir, monkeypatch, capsys):
    Path("pic.png").write_bytes(b"\x89PNG\r\n\x1a\nfake")
    Path("ok.txt").write_text("ip=1.2.3.4\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "pic.png", "ok.txt"])
    redact_mod.main()
    err = capsys.readouterr().err
    assert "Skipping binary file: pic.png" in err
    assert Path("redacted/ok.txt").is_file()
    assert not Path("redacted/pic.png").exists()


def test_redact_skips_null_byte_file(redact_mod, workdir, monkeypatch, capsys):
    # No binary extension, but contains NUL
    Path("data.datx").write_bytes(b"abc\x00def")
    Path("plain.txt").write_text("mail=a@b.co\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "data.datx", "plain.txt"])
    redact_mod.main()
    err = capsys.readouterr().err
    assert "Skipping binary file: data.datx" in err
    assert Path("redacted/plain.txt").is_file()
    assert not Path("redacted/data.datx").exists()


def test_redact_skips_invalid_utf8(redact_mod, workdir, monkeypatch, capsys):
    Path("bad.txt").write_bytes(b"\xff\xfe not utf8 \x80")
    Path("good.txt").write_text("token=ok\nTOKEN=abc123\n", encoding="utf-8")
    # Avoid .bin extension so we hit decode path; still no null if careful
    # Use latin1 invalid as utf-8 without null
    Path("bad2.txt").write_bytes(bytes([0xC3, 0x28]))  # invalid UTF-8 sequence
    monkeypatch.setattr(sys, "argv", ["redact", "bad2.txt", "good.txt"])
    redact_mod.main()
    captured = capsys.readouterr()
    assert "Skipping binary/non-UTF-8 file: bad2.txt" in captured.err or (
        "Error:" in captured.err and "bad2.txt" in captured.err
    )
    assert Path("redacted/good.txt").is_file()


def test_default_excludes_include_image_globs(redact_mod):
    assert "PNG" in redact_mod.DEFAULT_EXCLUDES
    assert redact_mod.DEFAULT_EXCLUDES["PNG"] == "**/*.png"
    assert "PDF" in redact_mod.DEFAULT_EXCLUDES
    assert "MP4" in redact_mod.DEFAULT_EXCLUDES
    assert "GIT" in redact_mod.DEFAULT_EXCLUDES
    assert ".git" in redact_mod.DEFAULT_EXCLUDES["GIT"]
    assert "GIT_DIR" in redact_mod.DEFAULT_EXCLUDES


def test_binary_extension_always_skipped_without_exclude_file(
    redact_mod, workdir, monkeypatch, capsys
):
    Path("shot.jpg").write_bytes(b"\xff\xd8\xfffakejpeg")
    Path("note.txt").write_text("host=8.8.8.8\n", encoding="utf-8")
    assert not Path("redacted/exclude.yaml").exists()
    monkeypatch.setattr(sys, "argv", ["redact", "shot.jpg", "note.txt"])
    redact_mod.main()
    assert "Skipping binary file: shot.jpg" in capsys.readouterr().err
    assert Path("redacted/note.txt").is_file()


def test_unredact_continues_after_missing_redacted(
    unredact_mod, workdir, monkeypatch, capsys
):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text(
        "IP_aa: 1.1.1.1\n",
        encoding="utf-8",
    )
    Path("redacted/ok.txt").write_text("IP_aa\n", encoding="utf-8")
    # missing.txt has no redacted copy
    monkeypatch.setattr(sys, "argv", ["unredact", "ok.txt", "missing.txt"])
    with pytest.raises(SystemExit) as exc:
        unredact_mod.main()
    assert exc.value.code == 1
    assert Path("ok.txt").read_text(encoding="utf-8") == "1.1.1.1\n"
    err = capsys.readouterr().err
    assert "missing.txt" in err or "Redacted file not found" in err
    assert "Completed with" in err
