"""Exclude config CLI and dry-run redaction."""

import sys
from pathlib import Path

import pytest
import yaml

from redactor.paths import filter_excluded, is_excluded, path_matches_glob


# --- glob matching ---


@pytest.mark.parametrize(
    "path, pattern, expected",
    [
        ("app.min.js", "*.min.js", True),
        ("src/app.min.js", "*.min.js", True),
        ("src/app.min.js", "**/*.min.js", True),
        ("src/app.js", "*.min.js", False),
        ("vendor/pkg/x.py", "vendor/**", True),
        ("lib/x.py", "vendor/**", False),
        ("package-lock.json", "**/package-lock.json", True),
        ("a/package-lock.json", "**/package-lock.json", True),
    ],
)
def test_path_matches_glob(path, pattern, expected):
    assert path_matches_glob(Path(path), pattern) is expected


def test_filter_excluded(workdir):
    paths = [Path("ok.txt"), Path("x.min.js"), Path("src/y.min.js")]
    kept, skipped = filter_excluded(paths, ["**/*.min.js"])
    assert [p.as_posix() for p in kept] == ["ok.txt"]
    assert [p.as_posix() for p in skipped] == ["x.min.js", "src/y.min.js"]


# --- exclude CLI ---


def test_exclude_init_writes_defaults(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "init"])
    redact_mod.main()
    assert "Wrote built-in excludes" in capsys.readouterr().out
    data = yaml.safe_load(Path("redacted/exclude.yaml").read_text(encoding="utf-8"))
    assert data == redact_mod.DEFAULT_EXCLUDES


def test_exclude_init_refuses_overwrite(redact_mod, workdir, monkeypatch, capsys):
    Path("redacted").mkdir()
    Path("redacted/exclude.yaml").write_text("X: '*.x'\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "init"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "already exists" in capsys.readouterr().err


def test_exclude_list_none_when_missing(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "list"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "none" in out
    assert "(no excludes)" in out


def test_exclude_add_and_list(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["redact", "exclude", "add", "VENDOR", "vendor/**"],
    )
    redact_mod.main()
    capsys.readouterr()
    data = yaml.safe_load(Path("redacted/exclude.yaml").read_text(encoding="utf-8"))
    assert data == {"VENDOR": "vendor/**"}

    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "list"])
    redact_mod.main()
    assert "VENDOR" in capsys.readouterr().out


def test_exclude_remove(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "init"])
    redact_mod.main()
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "remove", "MINJS"])
    redact_mod.main()
    data = yaml.safe_load(Path("redacted/exclude.yaml").read_text(encoding="utf-8"))
    assert "MINJS" not in data
    assert "MAP" in data


def test_exclude_remove_ignore_missing(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "exclude", "init"])
    redact_mod.main()
    capsys.readouterr()
    monkeypatch.setattr(
        sys,
        "argv",
        ["redact", "exclude", "remove", "NOPE", "--ignore-missing"],
    )
    redact_mod.main()
    assert "nothing to do" in capsys.readouterr().out


def test_load_excludes_rejects_invalid(redact_mod, workdir, capsys):
    Path("redacted").mkdir()
    Path("redacted/exclude.yaml").write_text("- not a map\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        redact_mod.load_excludes()
    assert exc.value.code == 1
    assert "Invalid exclude config" in capsys.readouterr().err


def test_redact_respects_exclude_file(redact_mod, workdir, monkeypatch, capsys):
    Path("src").mkdir()
    Path("src/app.js").write_text("ip=10.0.0.1\n", encoding="utf-8")
    Path("src/app.min.js").write_text("ip=10.0.0.2\n", encoding="utf-8")
    Path("redacted").mkdir()
    Path("redacted/exclude.yaml").write_text("MINJS: '**/*.min.js'\n", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["redact", "src"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Excluded: src/app.min.js" in out
    assert Path("redacted/src/app.js").is_file()
    assert not Path("redacted/src/app.min.js").exists()
    assert "10.0.0.1" not in Path("redacted/src/app.js").read_text(encoding="utf-8")


# --- dry-run ---


def test_dry_run_shows_matches_without_writes(redact_mod, workdir, monkeypatch, capsys):
    Path("secret.env").write_text(
        "host=10.1.2.3\ncontact=a@b.co\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["redact", "--dry-run", "secret.env"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Dry run:" in out
    assert "Would redact: secret.env" in out
    assert "IP: 10.1.2.3" in out
    assert "EMAIL: a@b.co" in out
    assert "Dry run complete" in out
    assert not Path("redacted/secret.env").exists()
    assert not Path("redacted/dictionary.yaml").exists()


def test_dry_run_short_flag(redact_mod, workdir, monkeypatch, capsys):
    Path("x.txt").write_text("no secrets here\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "-n", "x.txt"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Would redact: x.txt" in out
    assert "(no matches)" in out
    assert not Path("redacted").exists() or not Path("redacted/x.txt").exists()


def test_dry_run_does_not_mutate_existing_dictionary(
    redact_mod, workdir, monkeypatch, capsys
):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text(
        "IP_old: 1.1.1.1\n",
        encoding="utf-8",
    )
    before = Path("redacted/dictionary.yaml").read_text(encoding="utf-8")
    Path("y.txt").write_text("ip=9.9.9.9\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "-n", "y.txt"])
    redact_mod.main()
    assert Path("redacted/dictionary.yaml").read_text(encoding="utf-8") == before
    assert not Path("redacted/y.txt").exists()


def test_dry_run_respects_excludes(redact_mod, workdir, monkeypatch, capsys):
    Path("a.txt").write_text("10.0.0.1\n", encoding="utf-8")
    Path("b.min.js").write_text("10.0.0.2\n", encoding="utf-8")
    Path("redacted").mkdir()
    Path("redacted/exclude.yaml").write_text("MINJS: '**/*.min.js'\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "--dry-run", "a.txt", "b.min.js"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Excluded: b.min.js" in out
    assert "Would redact: a.txt" in out
    assert "Would redact: b.min.js" not in out


def test_cli_exclude_flag(redact_mod, workdir, monkeypatch, capsys):
    Path("keep.txt").write_text("ip=10.0.0.1\n", encoding="utf-8")
    Path("skip.log").write_text("ip=10.0.0.2\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["redact", "--exclude", "*.log", "keep.txt", "skip.log"],
    )
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Excluded: skip.log" in out
    assert Path("redacted/keep.txt").is_file()
    assert not Path("redacted/skip.log").exists()


def test_cli_include_flag(redact_mod, workdir, monkeypatch, capsys):
    Path("a.env").write_text("TOKEN=abc\n", encoding="utf-8")
    Path("b.txt").write_text("TOKEN=xyz\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["redact", "--include", "**/*.env", "a.env", "b.txt"],
    )
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Not included: b.txt" in out
    assert Path("redacted/a.env").is_file()
    assert not Path("redacted/b.txt").exists()


def test_cli_exclude_and_include_combined(redact_mod, workdir, monkeypatch, capsys):
    Path("cfg").mkdir()
    Path("cfg/a.env").write_text("TOKEN=a1\n", encoding="utf-8")
    Path("cfg/b.env").write_text("TOKEN=b1\n", encoding="utf-8")
    Path("cfg/c.txt").write_text("TOKEN=c1\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "redact",
            "--include",
            "**/*.env",
            "--exclude",
            "**/b.env",
            "cfg",
        ],
    )
    redact_mod.main()
    out = capsys.readouterr().out
    assert "Excluded: cfg/b.env" in out or Path("redacted/cfg/a.env").is_file()
    assert Path("redacted/cfg/a.env").is_file()
    assert not Path("redacted/cfg/b.env").exists()
    assert not Path("redacted/cfg/c.txt").exists()
