"""Easy / high-value coverage for exclude validation, CLI flags, and edge paths."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from redactor.paths import (
    filter_included,
    path_has_skipped_dir,
    path_matches_glob,
    walk_files,
)


# --- validate / load excludes ---


def test_validate_excludes_rejects_empty_and_bad_names(redact_mod):
    with pytest.raises(ValueError, match="empty"):
        redact_mod.validate_excludes({})
    with pytest.raises(ValueError, match="invalid exclude name"):
        redact_mod.validate_excludes({"  ": "*.log"})
    with pytest.raises(ValueError, match="non-empty glob"):
        redact_mod.validate_excludes({"X": "  "})


def test_load_excludes_file_empty(redact_mod, workdir):
    Path("redacted").mkdir()
    Path("redacted/exclude.yaml").write_text("", encoding="utf-8")
    assert redact_mod.load_excludes_file() == {}
    Path("redacted/exclude.yaml").write_text("null\n", encoding="utf-8")
    assert redact_mod.load_excludes_file() == {}


def test_exclude_list_yaml(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "init"])
    redact_mod.main()
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "list", "--yaml"])
    redact_mod.main()
    data = yaml.safe_load(capsys.readouterr().out)
    assert "GIT" in data


def test_exclude_add_rejects_blank_name_and_glob(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "add", "   ", "*.log"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "non-empty" in capsys.readouterr().err

    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "add", "X", "  "])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "Glob must be non-empty" in capsys.readouterr().err


def test_exclude_add_updates_existing(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "add", "LOG", "*.log"])
    redact_mod.main()
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "add", "LOG", "**/*.log"])
    redact_mod.main()
    assert "Updated" in capsys.readouterr().out
    data = yaml.safe_load(Path("redacted/exclude.yaml").read_text(encoding="utf-8"))
    assert data["LOG"] == "**/*.log"


def test_exclude_remove_missing_file(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "remove", "X"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_exclude_remove_unknown_without_ignore(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "init"])
    redact_mod.main()
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "remove", "NOPE"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_exclude_remove_last_entry_leaves_empty(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/exclude.yaml").write_text("ONLY: '*.x'\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "remove", "ONLY"])
    redact_mod.main()
    err = capsys.readouterr().err
    assert "no excludes left" in err
    assert yaml.safe_load(Path("redacted/exclude.yaml").read_text(encoding="utf-8")) == {}


# --- paths ---


def test_walk_files_skips_root_under_git_component(workdir):
    Path("repo/.git/objects").mkdir(parents=True)
    Path("repo/.git/objects/x").write_text("x\n", encoding="utf-8")
    # Root path contains .git as a component
    assert walk_files(Path("repo/.git/objects")) == []
    assert path_has_skipped_dir(Path("repo/.git/objects/x"))


def test_path_matches_glob_empty_pattern():
    assert path_matches_glob(Path("a.txt"), "") is False
    assert path_matches_glob(Path("a.txt"), "   ") is False


def test_path_matches_glob_dir_starstar():
    assert path_matches_glob(Path("vendor/pkg/x.py"), "vendor/**") is True
    assert path_matches_glob(Path("vendor"), "vendor/**") is True


def test_filter_included_empty_globs_keeps_all():
    paths = [Path("a"), Path("b")]
    kept, skipped = filter_included(paths, [])
    assert kept == paths
    assert skipped == []


# --- CLI flag parsing ---


def test_cli_exclude_equals_and_include_equals(redact_mod, workdir, monkeypatch, capsys):
    Path("keep.env").write_text("TOKEN=abcdef\n", encoding="utf-8")
    Path("drop.log").write_text("TOKEN=abcdef\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "redact",
            "--include=**/*.env",
            "--exclude=*.log",
            "keep.env",
            "drop.log",
        ],
    )
    redact_mod.main()
    out = capsys.readouterr().out
    assert Path("redacted/keep.env").is_file()
    assert "Not included: drop.log" in out or not Path("redacted/drop.log").exists()


def test_cli_exclude_requires_argument(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "--exclude"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 2
    assert "requires a glob" in capsys.readouterr().err


def test_cli_include_requires_argument(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "-i"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 2
    assert "requires a glob" in capsys.readouterr().err


def test_cli_flags_only_prints_help(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "-n", "-q"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "usage:" in capsys.readouterr().out.lower()


def test_cli_version_in_file_parse_path(redact_mod, workdir, monkeypatch, capsys):
    # -V handled before file loop when alone; when mixed as only flag after empty files:
    monkeypatch.setattr(sys, "argv", ["redact", "--version"])
    redact_mod.main()
    assert "redact" in capsys.readouterr().out


# --- output / new-only / empty patterns ---


def test_output_mode_rejects_quiet_and_verbose(redact_mod):
    with pytest.raises(ValueError, match="Cannot combine"):
        redact_mod.OutputMode(quiet=True, verbose=True)


def test_dry_run_new_only_would_skip_reused_only(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text("IP_x: 1.1.1.1\n", encoding="utf-8")
    Path("x.txt").write_text("only=1.1.1.1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "-n", "--new-only", "-v", "x.txt"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Would skip (no new secrets)" in out
    assert "reused only" in out or "skipped_no_new=" in out


def test_dry_run_new_only_no_matches_at_all(redact_mod, workdir, monkeypatch, capsys):
    Path("plain.txt").write_text("nothing sensitive\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "-n", "--new-only", "plain.txt"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Would skip (no new secrets)" in out or "no matches" in out


def test_verbose_shows_reused_on_write(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text("IP_old: 1.1.1.1\n", encoding="utf-8")
    Path("x.txt").write_text("a=1.1.1.1 b=8.8.8.8\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "-v", "x.txt"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "REUSED IP: 1.1.1.1 -> IP_old" in out
    assert "NEW IP: 8.8.8.8" in out


def test_empty_patterns_warns_in_batch(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/patterns.yaml").write_text("{}\n", encoding="utf-8")
    Path("a.txt").write_text("10.0.0.1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "a.txt"])
    redact_mod.main()
    assert "no patterns configured" in capsys.readouterr().err


def test_redact_file_direct_binary_extension(redact_mod, workdir, capsys):
    Path("x.png").write_bytes(b"\x89PNG")
    d, r, status = redact_mod.redact_file(Path("x.png"))
    assert status == "skipped"
    assert "Skipping binary file" in capsys.readouterr().err


def test_new_only_skip_no_matches_counts(redact_mod, workdir, monkeypatch, capsys):
    Path("plain.txt").write_text("hi\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "--new-only", "plain.txt"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Skipped (no new secrets)" in out
    assert not Path("redacted/plain.txt").exists()


# --- unredact continue on error ---


def test_unredact_batch_continues_on_decode_error(unredact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text("IP_a: 1.1.1.1\n", encoding="utf-8")
    Path("redacted/good.txt").write_text("IP_a\n", encoding="utf-8")
    # Invalid UTF-8 → UnicodeDecodeError while reading redacted content
    Path("redacted/bad.txt").write_bytes(b"\xff\xfe not utf-8")
    monkeypatch.setattr(sys, "argv", ["unredact", "good.txt", "bad.txt"])
    with pytest.raises(SystemExit) as exc:
        unredact_mod.main()
    assert exc.value.code == 1
    assert Path("good.txt").read_text(encoding="utf-8") == "1.1.1.1\n"
    err = capsys.readouterr().err
    assert "bad.txt" in err
    assert "Completed with" in err


def test_exclude_list_with_entries_not_yaml(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/exclude.yaml").write_text("LOG: '*.log'\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "list"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "LOG" in out
    assert "*.log" in out
