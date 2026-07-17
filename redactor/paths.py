"""Expand CLI path arguments into a list of files (recursing into directories)."""

from __future__ import annotations

import os
from pathlib import Path

# Directory names skipped while walking (not when given as an explicit file path).
SKIP_DIR_NAMES = frozenset(
    {
        "redacted",
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


def walk_files(directory: Path) -> list[Path]:
    """Return regular files under directory, sorted, pruning SKIP_DIR_NAMES."""
    root = Path(directory)
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIR_NAMES)
        base = Path(dirpath)
        for name in sorted(filenames):
            path = base / name
            # Includes regular files and symlinks to files
            if path.is_file():
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
