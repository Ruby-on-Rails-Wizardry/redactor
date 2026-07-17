"""Coverage for validation, empty configs, and less-common CLI paths."""

import sys
from pathlib import Path

import pytest
import yaml


# --- validate_patterns / load_patterns_file ---


def test_validate_patterns_rejects_non_mapping(redact_mod):
    with pytest.raises(ValueError, match="mapping"):
        redact_mod.validate_patterns(["not", "a", "map"])


def test_validate_patterns_rejects_empty_mapping(redact_mod):
    with pytest.raises(ValueError, match="empty"):
        redact_mod.validate_patterns({})


def test_validate_patterns_rejects_blank_name(redact_mod):
    with pytest.raises(ValueError, match="invalid pattern name"):
        redact_mod.validate_patterns({"  ": r"\d+"})


def test_validate_patterns_rejects_empty_regex(redact_mod):
    with pytest.raises(ValueError, match="non-empty regex"):
        redact_mod.validate_patterns({"X": ""})


def test_validate_patterns_rejects_bad_regex(redact_mod):
    with pytest.raises(ValueError, match="not a valid regex"):
        redact_mod.validate_patterns({"X": "("})


def test_load_patterns_file_empty_yaml(redact_mod, workdir):
    Path("redacted").mkdir()
    Path("redacted/patterns.yaml").write_text("", encoding="utf-8")
    assert redact_mod.load_patterns_file() == {}

    Path("redacted/patterns.yaml").write_text("{}\n", encoding="utf-8")
    assert redact_mod.load_patterns_file() == {}


def test_load_patterns_file_null_yaml(redact_mod, workdir):
    Path("redacted").mkdir()
    Path("redacted/patterns.yaml").write_text("null\n", encoding="utf-8")
    assert redact_mod.load_patterns_file() == {}


# --- patterns CLI edge cases ---


def test_patterns_list_empty_file(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/patterns.yaml").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "list"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "(no patterns)" in out


def test_patterns_add_empty_name(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "add", "   ", r"\d+"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "non-empty" in capsys.readouterr().err


def test_patterns_remove_ignore_missing(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "init"])
    redact_mod.main()
    capsys.readouterr()
    monkeypatch.setattr(
        sys,
        "argv",
        ["redact", "patterns", "remove", "NOPE", "--ignore-missing"],
    )
    redact_mod.main()
    assert "nothing to do" in capsys.readouterr().out


def test_patterns_remove_last_pattern_leaves_empty_file(
    redact_mod, workdir, monkeypatch, capsys
):
    Path("redacted").mkdir()
    Path("redacted/patterns.yaml").write_text("ONLY: 'x'\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "remove", "ONLY"])
    redact_mod.main()
    err = capsys.readouterr().err
    assert "no patterns left" in err
    assert yaml.safe_load(Path("redacted/patterns.yaml").read_text(encoding="utf-8")) == {}


def test_patterns_list_invalid_file_exits(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/patterns.yaml").write_text("- not a map\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "patterns", "list"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "mapping" in capsys.readouterr().err


# --- redact edge cases ---


def test_redact_file_standalone_owns_dictionary(redact_mod, workdir, capsys):
    Path("solo.txt").write_text("ip=8.8.8.8\n", encoding="utf-8")
    redact_mod.redact_file(Path("solo.txt"))
    out = capsys.readouterr().out
    assert "dictionary.yaml" in out
    assert "8.8.8.8" not in Path("redacted/solo.txt").read_text(encoding="utf-8")


def test_redact_file_missing_raises(redact_mod, workdir):
    with pytest.raises(FileNotFoundError, match="File not found"):
        redact_mod.redact_file(Path("gone.txt"))


def test_redact_with_empty_patterns_warns(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/patterns.yaml").write_text("{}\n", encoding="utf-8")
    Path("keep.txt").write_text("10.0.0.1 stays\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "keep.txt"])
    redact_mod.main()
    captured = capsys.readouterr()
    assert "no patterns configured" in captured.err
    assert Path("redacted/keep.txt").read_text(encoding="utf-8") == "10.0.0.1 stays\n"


def test_redact_file_standalone_empty_patterns_warns(redact_mod, workdir, capsys):
    Path("redacted").mkdir()
    Path("redacted/patterns.yaml").write_text("{}\n", encoding="utf-8")
    Path("keep2.txt").write_text("plain\n", encoding="utf-8")
    redact_mod.redact_file(Path("keep2.txt"))
    assert "no patterns configured" in capsys.readouterr().err


def test_redact_empty_directory_errors(redact_mod, workdir, monkeypatch, capsys):
    Path("empty").mkdir()
    monkeypatch.setattr(sys, "argv", ["redact", "empty"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "No files to redact" in capsys.readouterr().err


def test_redact_option_among_files_errors(redact_mod, workdir, monkeypatch):
    Path("a.txt").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "a.txt", "--weird"])
    with pytest.raises(SystemExit):
        redact_mod.main()


def test_redact_unknown_flag_exits(redact_mod, workdir, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["redact", "--not-a-real-flag"])
    with pytest.raises(SystemExit):
        redact_mod.main()


# --- unredact edge cases ---


def test_unredact_missing_redacted_no_paste(unredact_mod, workdir):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text("IP_x: '1.1.1.1'\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="Redacted file not found"):
        unredact_mod.unredact_file(Path("missing.txt"), allow_paste=False)


def test_unredact_file_loads_dictionary_when_not_passed(unredact_mod, workdir):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text("IP_x: '2.2.2.2'\n", encoding="utf-8")
    Path("redacted/t.txt").write_text("IP_x\n", encoding="utf-8")
    unredact_mod.unredact_file(Path("t.txt"))
    assert Path("t.txt").read_text(encoding="utf-8") == "2.2.2.2\n"


def test_unredact_missing_path_errors(unredact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["unredact", "no-such-tree"])
    with pytest.raises(SystemExit) as exc:
        unredact_mod.main()
    assert exc.value.code == 1
    assert "File not found" in capsys.readouterr().err


def test_unredact_empty_dir_no_redacted_errors(unredact_mod, workdir, monkeypatch, capsys):
    Path("empty").mkdir()
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["unredact", "empty"])
    with pytest.raises(SystemExit) as exc:
        unredact_mod.main()
    assert exc.value.code == 1
    assert "No files to unredact" in capsys.readouterr().err


def test_unredact_unknown_flag(unredact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["unredact", "--nope"])
    with pytest.raises(SystemExit) as exc:
        unredact_mod.main()
    assert exc.value.code == 1
    assert "Usage:" in capsys.readouterr().err


def test_unredact_help_flag(unredact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["unredact", "--help"])
    with pytest.raises(SystemExit) as exc:
        unredact_mod.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "Usage:" in out
    assert "Examples:" in out
    assert "redacted/" in out
    assert ".git" in out


def test_unredact_from_redacted_file_only(unredact_mod, workdir, monkeypatch):
    """Original path missing, but redacted/<file> exists as a single file."""
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text("IP_z: '9.9.9.9'\n", encoding="utf-8")
    Path("redacted/only.txt").write_text("IP_z\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["unredact", "only.txt"])
    unredact_mod.main()
    assert Path("only.txt").read_text(encoding="utf-8") == "9.9.9.9\n"
