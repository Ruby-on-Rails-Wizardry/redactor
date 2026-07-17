"""End-to-end redact → unredact restores the original content."""

import subprocess
import sys
from pathlib import Path

SAMPLE = """\
# demo config (fake secrets only)
server=192.168.10.20
admin=ops@example.org
API_KEY=demo-api-key-001
TOKEN=demo-token-002
PASSWORD=demo-password-003
portal=www.example.gov
note=safe text remains
"""


def _run(module: str, *args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def test_redact_unredact_roundtrip(workdir):
    source = Path("config.env")
    source.write_text(SAMPLE, encoding="utf-8")
    original = source.read_text(encoding="utf-8")

    redact = _run("redactor.redact", "config.env", cwd=workdir)
    assert redact.returncode == 0, redact.stderr + redact.stdout

    redacted_path = Path("redacted/config.env")
    assert redacted_path.is_file()
    redacted = redacted_path.read_text(encoding="utf-8")
    assert redacted != original
    assert "192.168.10.20" not in redacted
    assert "ops@example.org" not in redacted
    assert "demo-api-key-001" not in redacted
    assert "safe text remains" in redacted

    # Simulate sending the original away: wipe it before restore
    source.write_text("wiped\n", encoding="utf-8")

    unredact = _run("redactor.unredact", "config.env", cwd=workdir)
    assert unredact.returncode == 0, unredact.stderr + unredact.stdout
    assert source.read_text(encoding="utf-8") == original


def test_redact_unredact_multi_and_dir_subprocess(workdir):
    Path("cfg").mkdir()
    Path("cfg/one.env").write_text("API_KEY=k-one-long\n", encoding="utf-8")
    Path("cfg/two.env").write_text("API_KEY=k-one-long\nTOKEN=t-two-ok\n", encoding="utf-8")
    Path("root.txt").write_text("see 172.16.0.1\n", encoding="utf-8")

    r = _run("redactor.redact", "cfg", "root.txt", cwd=workdir)
    assert r.returncode == 0, r.stderr + r.stdout
    assert "k-one-long" not in Path("redacted/cfg/one.env").read_text(encoding="utf-8")
    assert "t-two-ok" not in Path("redacted/cfg/two.env").read_text(encoding="utf-8")
    assert "172.16.0.1" not in Path("redacted/root.txt").read_text(encoding="utf-8")

    # Same API key shares placeholder across files
    d = Path("redacted/dictionary.yaml").read_text(encoding="utf-8")
    assert "k-one-long" in d

    Path("cfg/one.env").write_text("x\n", encoding="utf-8")
    Path("cfg/two.env").write_text("y\n", encoding="utf-8")
    Path("root.txt").write_text("z\n", encoding="utf-8")

    u = _run("redactor.unredact", "cfg", "root.txt", cwd=workdir)
    assert u.returncode == 0, u.stderr + u.stdout
    assert "k-one-long" in Path("cfg/one.env").read_text(encoding="utf-8")
    assert "t-two-ok" in Path("cfg/two.env").read_text(encoding="utf-8")
    assert "172.16.0.1" in Path("root.txt").read_text(encoding="utf-8")
