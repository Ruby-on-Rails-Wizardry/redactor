"""Allowlist CLI and redaction integration."""

import sys
from pathlib import Path

import yaml


def test_allowlist_init_and_list(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "init"])
    redact_mod.main()
    assert Path("redacted/allowlist.yaml").is_file()
    data = yaml.safe_load(Path("redacted/allowlist.yaml").read_text(encoding="utf-8"))
    assert data == redact_mod.DEFAULT_ALLOWLIST

    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "list"])
    redact_mod.main()
    out = capsys.readouterr().out
    assert "127.0.0.1" in out
    assert "LOCALHOST_V4" in out


def test_allowlist_add_remove(redact_mod, workdir, monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["redact", "allowlist", "add", "SAFE_IP", "10.255.255.1"],
    )
    redact_mod.main()
    data = yaml.safe_load(Path("redacted/allowlist.yaml").read_text(encoding="utf-8"))
    assert data["SAFE_IP"] == "10.255.255.1"
    assert "LOCALHOST_V4" in data  # seeded from defaults

    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["redact", "allowlist", "remove", "SAFE_IP"])
    redact_mod.main()
    data = yaml.safe_load(Path("redacted/allowlist.yaml").read_text(encoding="utf-8"))
    assert "SAFE_IP" not in data


def test_redact_respects_default_allowlist(redact_mod, workdir, monkeypatch):
    Path("net.txt").write_text("loop 127.0.0.1 public 8.8.8.8\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redact", "net.txt"])
    redact_mod.main()
    text = Path("redacted/net.txt").read_text(encoding="utf-8")
    assert "127.0.0.1" in text
    assert "8.8.8.8" not in text
