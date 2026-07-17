"""Unit and CLI-level tests for redact."""

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml



def test_generate_placeholder_format(redact_mod):
    placeholder = redact_mod.generate_placeholder("EMAIL")
    assert re.fullmatch(r"EMAIL_[0-9a-f]{8}", placeholder)


def test_generate_placeholder_unique(redact_mod):
    a = redact_mod.generate_placeholder("IP")
    b = redact_mod.generate_placeholder("IP")
    assert a != b


def test_ensure_redacted_path_creates_parents(redact_mod, workdir):
    original = Path("nested/dir/file.txt")
    redacted = redact_mod.ensure_redacted_path(original)
    assert redacted == Path("redacted/nested/dir/file.txt")
    assert redacted.parent.is_dir()


def test_load_dictionary_missing_returns_empty(redact_mod, workdir):
    assert redact_mod.load_dictionary() == {}


def test_save_and_load_dictionary_roundtrip(redact_mod, workdir):
    data = {"EMAIL_deadbeef": "a@b.co"}
    redact_mod.save_dictionary(data)
    assert Path("redacted/dictionary.yaml").is_file()
    assert redact_mod.load_dictionary() == data


def test_main_requires_argument(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    # argparse help on stdout when no args
    captured = capsys.readouterr()
    assert "usage:" in captured.out.lower() or "usage:" in captured.err.lower()


def test_main_missing_file(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "nope.txt"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "File not found" in capsys.readouterr().err


def test_main_redacts_patterns_and_writes_outputs(redact_mod, workdir, monkeypatch, capsys):
    source = Path("sample.env")
    source.write_text(
        "\n".join(
            [
                "host=10.0.0.5",
                "contact=alice@example.com",
                "API_KEY=sk-test-key",
                "TOKEN=tok123",
                "PASSWORD=hunter2",
                "site=cdc.gov",
                "plain=nothing-sensitive",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["redact", "sample.env"])
    redact_mod.main()

    out = capsys.readouterr().out
    assert "Redacted file written to:" in out

    redacted = Path("redacted/sample.env").read_text(encoding="utf-8")
    assert "10.0.0.5" not in redacted
    assert "alice@example.com" not in redacted
    assert "sk-test-key" not in redacted
    assert "tok123" not in redacted
    assert "hunter2" not in redacted
    assert "cdc.gov" not in redacted
    assert "nothing-sensitive" in redacted
    assert re.search(r"IP_[0-9a-f]{8}", redacted)
    assert re.search(r"EMAIL_[0-9a-f]{8}", redacted)
    assert re.search(r"APIKEY_[0-9a-f]{8}", redacted)
    assert re.search(r"TOKEN_[0-9a-f]{8}", redacted)
    assert re.search(r"PASSWORD_[0-9a-f]{8}", redacted)
    assert re.search(r"GOV_[0-9a-f]{8}", redacted)

    dictionary = yaml.safe_load(Path("redacted/dictionary.yaml").read_text(encoding="utf-8"))
    assert set(dictionary.values()) >= {
        "10.0.0.5",
        "alice@example.com",
        "sk-test-key",
        "tok123",
        "hunter2",
        "cdc.gov",
    }


def test_main_reuses_existing_placeholder(redact_mod, workdir, monkeypatch):
    Path("redacted").mkdir()
    Path("redacted/dictionary.yaml").write_text(
        "EMAIL_fixed001: alice@example.com\n",
        encoding="utf-8",
    )
    Path("a.txt").write_text("alice@example.com\n", encoding="utf-8")
    Path("b.txt").write_text("alice@example.com again\n", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["redact", "a.txt"])
    redact_mod.main()
    monkeypatch.setattr(sys, "argv", ["redact", "b.txt"])
    redact_mod.main()

    assert "EMAIL_fixed001" in Path("redacted/a.txt").read_text(encoding="utf-8")
    assert "EMAIL_fixed001" in Path("redacted/b.txt").read_text(encoding="utf-8")
    dictionary = yaml.safe_load(Path("redacted/dictionary.yaml").read_text(encoding="utf-8"))
    email_placeholders = [k for k, v in dictionary.items() if v == "alice@example.com"]
    assert email_placeholders == ["EMAIL_fixed001"]


def test_email_takes_precedence_over_gov_in_addresses(redact_mod, workdir, monkeypatch):
    Path("mail.txt").write_text("user@agency.gov and bare agency.gov\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "mail.txt"])
    redact_mod.main()

    redacted = Path("redacted/mail.txt").read_text(encoding="utf-8")
    dictionary = yaml.safe_load(Path("redacted/dictionary.yaml").read_text(encoding="utf-8"))
    by_value = {v: k for k, v in dictionary.items()}

    assert "user@agency.gov" in by_value
    assert by_value["user@agency.gov"].startswith("EMAIL_")
    assert "agency.gov" in by_value
    assert by_value["agency.gov"].startswith("GOV_")
    assert by_value["user@agency.gov"] in redacted
    assert by_value["agency.gov"] in redacted


def test_cli_subprocess_redact(workdir):
    Path("cli.txt").write_text("ip=127.0.0.1\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "redactor.redact", "cli.txt"],
        cwd=workdir,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "127.0.0.1" not in Path("redacted/cli.txt").read_text(encoding="utf-8")


def test_main_redacts_multiple_files(redact_mod, workdir, monkeypatch, capsys):
    Path("a.txt").write_text("ip=10.0.0.1\n", encoding="utf-8")
    Path("b.txt").write_text("ip=10.0.0.1 email=a@b.co\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "a.txt", "b.txt"])
    redact_mod.main()

    out = capsys.readouterr().out
    assert "redacted/a.txt" in out
    assert "redacted/b.txt" in out
    assert "dictionary.yaml" in out

    a = Path("redacted/a.txt").read_text(encoding="utf-8")
    b = Path("redacted/b.txt").read_text(encoding="utf-8")
    assert "10.0.0.1" not in a
    assert "10.0.0.1" not in b
    assert "a@b.co" not in b

    dictionary = yaml.safe_load(Path("redacted/dictionary.yaml").read_text(encoding="utf-8"))
    by_value = {v: k for k, v in dictionary.items()}
    # Same value shares one placeholder across the batch
    assert by_value["10.0.0.1"] in a
    assert by_value["10.0.0.1"] in b


def test_main_multiple_files_missing_any_fails(redact_mod, workdir, monkeypatch, capsys):
    Path("ok.txt").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "ok.txt", "missing.txt"])
    with pytest.raises(SystemExit) as exc:
        redact_mod.main()
    assert exc.value.code == 1
    assert "File not found: missing.txt" in capsys.readouterr().err
    assert not Path("redacted/ok.txt").exists()


def test_main_redacts_directory_recursively(redact_mod, workdir, monkeypatch, capsys):
    Path("app/cfg").mkdir(parents=True)
    Path("app/cfg/a.env").write_text("host=10.0.0.9\n", encoding="utf-8")
    Path("app/readme.txt").write_text("mail=ops@example.com\n", encoding="utf-8")
    Path("app/.git/hooks").mkdir(parents=True)
    Path("app/.git/hooks/x").write_text("10.0.0.9\n", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["redact", "app"])
    redact_mod.main()

    assert Path("redacted/app/cfg/a.env").is_file()
    assert Path("redacted/app/readme.txt").is_file()
    assert not Path("redacted/app/.git/hooks/x").exists()
    assert "10.0.0.9" not in Path("redacted/app/cfg/a.env").read_text(encoding="utf-8")
    assert "ops@example.com" not in Path("redacted/app/readme.txt").read_text(
        encoding="utf-8"
    )
