"""Path expansion for files and recursive directories."""

from pathlib import Path

from redactor.paths import ALWAYS_SKIP_DIR_NAMES, SKIP_DIR_NAMES, expand_paths, walk_files


def test_walk_files_nested(workdir):
    Path("proj/a").mkdir(parents=True)
    Path("proj/b/c").mkdir(parents=True)
    Path("proj/a/one.txt").write_text("1\n", encoding="utf-8")
    Path("proj/b/c/two.txt").write_text("2\n", encoding="utf-8")
    Path("proj/b/c/three.env").write_text("3\n", encoding="utf-8")

    found = walk_files(Path("proj"))
    assert [p.as_posix() for p in found] == [
        "proj/a/one.txt",
        "proj/b/c/three.env",
        "proj/b/c/two.txt",
    ]


def test_walk_skips_redacted_and_vcs(workdir):
    Path("tree/src").mkdir(parents=True)
    Path("tree/src/ok.txt").write_text("ok\n", encoding="utf-8")
    Path("tree/redacted/secret.txt").mkdir(parents=True)
    # redacted is a dir name under tree — should be pruned
    Path("tree/redacted").mkdir(exist_ok=True)
    Path("tree/redacted/nope.txt").write_text("no\n", encoding="utf-8")
    Path("tree/.git/objects").mkdir(parents=True)
    Path("tree/.git/objects/x").write_text("x\n", encoding="utf-8")
    Path("tree/__pycache__").mkdir(parents=True)
    Path("tree/__pycache__/mod.pyc").write_text("pyc\n", encoding="utf-8")

    found = {p.as_posix() for p in walk_files(Path("tree"))}
    assert found == {"tree/src/ok.txt"}
    assert "redacted" in SKIP_DIR_NAMES
    assert ".git" in SKIP_DIR_NAMES
    assert ".git" in ALWAYS_SKIP_DIR_NAMES


def test_walk_skips_git_when_git_is_root(workdir):
    Path(".git/objects").mkdir(parents=True)
    Path(".git/HEAD").write_text("ref: refs/heads/master\n", encoding="utf-8")
    Path(".git/objects/pack").mkdir(parents=True)
    Path(".git/objects/pack/x").write_text("blob\n", encoding="utf-8")
    assert walk_files(Path(".git")) == []
    files, missing = expand_paths([".git"])
    assert files == []
    assert missing == []


def test_expand_paths_skips_paths_under_git(workdir):
    Path("proj/.git/objects").mkdir(parents=True)
    Path("proj/.git/objects/x").write_text("x\n", encoding="utf-8")
    Path("proj/app.txt").write_text("ok\n", encoding="utf-8")
    files, missing = expand_paths(["proj"])
    assert missing == []
    assert [p.as_posix() for p in files] == ["proj/app.txt"]


def test_expand_paths_mix_file_and_dir(workdir):
    Path("solo.txt").write_text("s\n", encoding="utf-8")
    Path("d/sub").mkdir(parents=True)
    Path("d/sub/f.txt").write_text("f\n", encoding="utf-8")

    files, missing = expand_paths(["solo.txt", "d"])
    assert missing == []
    assert [p.as_posix() for p in files] == ["solo.txt", "d/sub/f.txt"]


def test_expand_paths_missing(workdir):
    files, missing = expand_paths(["nope.txt"])
    assert files == []
    assert missing == [Path("nope.txt")]


def test_expand_paths_unredact_from_redacted_tree(workdir):
    Path("redacted/app/cfg").mkdir(parents=True)
    Path("redacted/app/cfg/a.env").write_text("IP_x\n", encoding="utf-8")
    Path("redacted/app/cfg/b.env").write_text("IP_y\n", encoding="utf-8")

    files, missing = expand_paths(["app"], unredact=True)
    assert missing == []
    assert [p.as_posix() for p in files] == ["app/cfg/a.env", "app/cfg/b.env"]


def test_walk_includes_symlink_to_file(workdir):
    Path("real.txt").write_text("hi\n", encoding="utf-8")
    Path("link.txt").symlink_to("real.txt")
    Path("dir").mkdir()
    Path("dir/link.txt").symlink_to("../real.txt")
    found = {p.as_posix() for p in walk_files(Path("dir"))}
    assert "dir/link.txt" in found


def test_expand_paths_dedupes_overlapping_file_and_dir(workdir):
    Path("d").mkdir()
    Path("d/a.txt").write_text("a\n", encoding="utf-8")
    files, missing = expand_paths(["d/a.txt", "d"])
    assert missing == []
    assert [p.as_posix() for p in files] == ["d/a.txt"]


def test_expand_paths_unredact_dir_without_redacted_tree(workdir):
    Path("empty").mkdir()
    files, missing = expand_paths(["empty"], unredact=True)
    assert files == []
    assert missing == []


def test_expand_paths_unredact_missing_file_via_redacted_file(workdir):
    Path("redacted").mkdir()
    Path("redacted/ghost.txt").write_text("x\n", encoding="utf-8")
    files, missing = expand_paths(["ghost.txt"], unredact=True)
    assert missing == []
    assert files == [Path("ghost.txt")]


def test_roundtrip_directory_tree(workdir):
    """Full directory redact → unredact integration via expand_paths consumers."""
    from redactor.redact import redact_files
    from redactor.unredact import unredact_files

    Path("proj/nested").mkdir(parents=True)
    Path("proj/a.txt").write_text("ip=10.9.8.7\n", encoding="utf-8")
    Path("proj/nested/b.txt").write_text("mail=z@example.org\n", encoding="utf-8")
    originals = {
        "proj/a.txt": Path("proj/a.txt").read_text(encoding="utf-8"),
        "proj/nested/b.txt": Path("proj/nested/b.txt").read_text(encoding="utf-8"),
    }

    redact_files(["proj"])
    assert "10.9.8.7" not in Path("redacted/proj/a.txt").read_text(encoding="utf-8")
    assert "z@example.org" not in Path("redacted/proj/nested/b.txt").read_text(
        encoding="utf-8"
    )

    Path("proj/a.txt").write_text("wiped\n", encoding="utf-8")
    Path("proj/nested/b.txt").write_text("wiped\n", encoding="utf-8")
    unredact_files(["proj"])
    for rel, content in originals.items():
        assert Path(rel).read_text(encoding="utf-8") == content
