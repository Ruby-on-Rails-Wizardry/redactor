"""Expand CLI path arguments into a list of files (recursing into directories)."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path, PurePosixPath

# Directory names never processed as content (any path component).
# Includes VCS, virtualenvs, caches. ".git" is always ignored.
ALWAYS_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        "node_modules",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".eggs",
        "dist",
        "build",
    }
)

# Also prune a top-level/nested "redacted/" workspace when walking sources.
# Not in ALWAYS_SKIP so we can still walk redacted/<tree> for unredact discovery.
SKIP_DIR_NAMES = ALWAYS_SKIP_DIR_NAMES | frozenset({"redacted"})


def path_has_skipped_dir(path: Path) -> bool:
    """True if any path component is a hard-skipped dir (e.g. .git, node_modules)."""
    return any(part in ALWAYS_SKIP_DIR_NAMES for part in Path(path).parts)


def walk_files(directory: Path) -> list[Path]:
    """Return regular files under directory, sorted, pruning SKIP_DIR_NAMES.

    Also skips walking when the root itself is a skipped directory name
    (e.g. ``redact .git`` or ``redact redacted`` yields no files).
    """
    root = Path(directory)
    if root.name in SKIP_DIR_NAMES:
        return []
    if path_has_skipped_dir(root):
        return []
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIR_NAMES)
        base = Path(dirpath)
        for name in sorted(filenames):
            path = base / name
            # Includes regular files and symlinks to files
            if path.is_file() and not path_has_skipped_dir(path):
                found.append(path)
    return found


def expand_paths(raw_paths, *, unredact: bool = False) -> tuple[list[Path], list[Path]]:
    """Expand file and directory arguments into concrete file paths.

    Returns (files, missing) where missing paths could not be resolved.

    For unredact, if an original directory is gone but ``redacted/<path>`` exists
    as a directory, files are discovered from the redacted tree and mapped back
    to original-relative paths.
    """
    files: list[Path] = []
    missing: list[Path] = []
    seen: set[Path] = set()

    def add_file(path: Path) -> None:
        # Normalize for dedupe without forcing absolute redacted/ outputs
        key = path
        if key not in seen:
            seen.add(key)
            files.append(path)

    def add_from_redacted_tree(original_root: Path) -> bool:
        """Map redacted/<original_root>/... files back to original-relative paths."""
        redacted_root = Path("redacted") / original_root
        if not redacted_root.is_dir():
            return False
        for redacted_file in walk_files(redacted_root):
            try:
                rel = redacted_file.relative_to("redacted")
            except ValueError:
                continue
            add_file(rel)
        return True

    for raw in raw_paths:
        path = Path(raw)
        # Never process .git / venv / etc. as inputs (or anything under them)
        if path.name in ALWAYS_SKIP_DIR_NAMES or path_has_skipped_dir(path):
            continue
        # Explicit "redacted" root is the tool workspace — do not redact it as source
        if path.name == "redacted" and not unredact:
            continue

        if path.is_file():
            add_file(path)
            continue

        if path.is_dir():
            for file_path in walk_files(path):
                add_file(file_path)
            # Unredact: also pick up files that exist only under redacted/<path>/
            if unredact:
                add_from_redacted_tree(path)
            continue

        if unredact:
            redacted_root = Path("redacted") / path
            if redacted_root.is_dir():
                add_from_redacted_tree(path)
                continue
            if redacted_root.is_file():
                add_file(path)
                continue

        if not path.exists():
            missing.append(path)
        else:
            # Exists but is neither a normal file nor directory (fifo, etc.)
            missing.append(path)

    return files, missing


def path_matches_glob(path: Path, pattern: str) -> bool:
    """True if path matches a glob (supports * and ** via Path.match / fnmatch)."""
    pattern = pattern.replace("\\", "/").strip()
    if not pattern:
        return False
    posix = path.as_posix()
    name = path.name

    # Patterns to try: as given, and without a leading **/ so root-level files match.
    variants = [pattern]
    if pattern.startswith("**/"):
        variants.append(pattern[3:])

    for pat in variants:
        try:
            if PurePosixPath(posix).match(pat) or PurePosixPath(name).match(pat):
                return True
        except ValueError:
            pass
        if fnmatch.fnmatch(posix, pat) or fnmatch.fnmatch(name, pat):
            return True
        # fnmatch has no **; match the trailing segment against the filename / path
        if "**/" in pat:
            tail = pat.split("**/")[-1]
            if fnmatch.fnmatch(name, tail) or fnmatch.fnmatch(posix, tail):
                return True
            if fnmatch.fnmatch(posix, "*/" + tail) or fnmatch.fnmatch(posix, "*/*/" + tail):
                return True
        # "*.ext" matches any depth by filename
        if pat.startswith("*.") and "/" not in pat and fnmatch.fnmatch(name, pat):
            return True
        # "dir/**" matches anything under dir/
        if pat.endswith("/**"):
            prefix = pat[:-3].rstrip("/")
            if posix == prefix or posix.startswith(prefix + "/"):
                return True
    return False


def is_excluded(path: Path, globs) -> bool:
    """True if path matches any exclude glob."""
    for pattern in globs:
        if path_matches_glob(path, pattern):
            return True
    return False


def filter_excluded(paths, globs) -> tuple[list[Path], list[Path]]:
    """Split paths into (kept, skipped) according to exclude globs."""
    if not globs:
        return list(paths), []
    kept: list[Path] = []
    skipped: list[Path] = []
    for path in paths:
        if is_excluded(path, globs):
            skipped.append(path)
        else:
            kept.append(path)
    return kept, skipped
