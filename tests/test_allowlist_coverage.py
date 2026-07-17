"""Coverage for allowlist CLI edge paths and rule matching."""

import sys
from pathlib import Path

import pytest
import yaml


def test_allowlist_init_refuses_overwrite(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/allowlist.yaml").write_text("X: 'y'\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "init"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "already exists" in capsys.readouterr().err


def test_allowlist_init_force(redact_mod, workdir, monkeypatch):
    Path("redacted").mkdir()
    Path("redacted/allowlist.yaml").write_text("X: 'y'\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "init", "--force"])
    redact_mod.main()
    data = yaml.safe_load(Path("redacted/allowlist.yaml").read_text(encoding="utf-8"))
    assert data == redact_mod.DEFAULT_ALLOWLIST


def test_allowlist_list_yaml_and_builtins(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "list", "--yaml"])
    redact_mod.main()
    data = yaml.safe_load(capsys.readouterr().out)
    assert "LOCALHOST_V4" in data


def test_allowlist_list_empty_file(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/allowlist.yaml").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "list"])
    redact_mod.main()
    assert "(no allowlist entries)" in capsys.readouterr().out


def test_allowlist_add_blank_name_value(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "add", "  ", "x"])
    with pytest.raises(SystemExit):
        redact_mod.main()
    assert "non-empty" in capsys.readouterr().err

    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "add", "N", ""])
    with pytest.raises(SystemExit):
        redact_mod.main()
    assert "non-empty" in capsys.readouterr().err


def test_allowlist_remove_missing_file(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "remove", "X"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_allowlist_remove_ignore_missing(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "init"])
    redact_mod.main()
    capsys.readouterr()
    monkeypatch.setattr(
        sys,
        "argv",
        ["redact", "allowlist", "remove", "NOPE", "--ignore-missing"],
    )
    redact_mod.main()
    assert "nothing to do" in capsys.readouterr().out


def test_allowlist_remove_unknown_errors(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "init"])
    redact_mod.main()
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "remove", "NOPE"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_allowlist_remove_last_entry(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/allowlist.yaml").write_text("ONLY: 'unique-val'\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "remove", "ONLY"])
    redact_mod.main()
    assert "empty" in capsys.readouterr().err
    assert yaml.safe_load(Path("redacted/allowlist.yaml").read_text(encoding="utf-8")) == {}


def test_load_allowlist_invalid_file(redact_mod, workdir, capsys):
    Path("redacted").mkdir()
    Path("redacted/allowlist.yaml").write_text("- not a map\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        redact_mod.load_allowlist()
    assert exc.value.code == 1
    assert "Invalid allowlist" in capsys.readouterr().err


def test_validate_allowlist_rejects_bad_shape(redact_mod):
    with pytest.raises(ValueError, match="mapping"):
        redact_mod.validate_allowlist(["x"])
    with pytest.raises(ValueError, match="empty"):
        redact_mod.validate_allowlist({})


def test_allowlist_values_passthrough(redact_mod):
    m = {"A": "1"}
    assert redact_mod.allowlist_values(m) is m
    # default load returns a dict with defaults when no file
    loaded = redact_mod.allowlist_values()
    assert "LOCALHOST_V4" in loaded


def test_help_mentions_allowlist(redact_mod, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "help"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "allowlist" in out


def test_extract_match_values_full_match_no_groups(redact_mod):
    vals = list(redact_mod.extract_match_values(r"hello", "say hello there"))
    assert vals == ["hello"]


def test_oserror_during_redact_continues(redact_mod, workdir, monkeypatch, capsys):
    Path("ok.txt").write_text("ip=8.8.8.8\n", encoding="utf-8")
    Path("gone.txt").write_text("ip=1.2.3.4\n", encoding="utf-8")

    real_read = redact_mod.read_text_file

    def flaky_read(path):
        if path.name == "gone.txt":
            raise OSError("simulated I/O failure")
        return real_read(path)

    monkeypatch.setattr(redact_mod, "read_text_file", flaky_read)
    monkeypatch.setattr(sys, "argv", ["redact", "ok.txt", "gone.txt"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "gone.txt" in err
    assert Path("redacted/ok.txt").is_file()
