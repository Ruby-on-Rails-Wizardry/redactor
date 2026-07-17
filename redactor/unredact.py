"""Restore sensitive values from redacted files using the placeholder dictionary."""

import sys
import yaml
from pathlib import Path

from redactor.paths import expand_paths


DICT_PATH = Path('redacted/dictionary.yaml')

USAGE = """\
Usage: unredact [-h] path [path ...]

Restore original values from redacted copies using redacted/dictionary.yaml.

Arguments:
  path          Original file or directory path (not the redacted/ path).
                Multiple paths allowed. Directories are walked recursively
                (same skip rules as redact: redacted/, .git/, node_modules/, …).
                If an original tree is missing, files are discovered under
                redacted/<path>/ when present.

Behavior:
  Reads each redacted file from redacted/<path>, substitutes placeholders
  using the dictionary, and writes the restored content to <path>.

  With a single expanded file, if the redacted copy is missing you can paste
  content on stdin (end with EOF). With multiple files, a missing redacted
  copy is an error.

Examples:
  unredact config.env
  unredact a.txt b.env src/
  unredact project/          # restore a whole tree

Dictionary: {dict_path} (required; created by redact).
""".format(dict_path=DICT_PATH)


def load_dictionary():
    if DICT_PATH.exists():
        with open(DICT_PATH, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    print(f"Dictionary file not found: {DICT_PATH}", file=sys.stderr)
    sys.exit(1)


def get_redacted_content(redacted_path, allow_paste=True):
    if redacted_path.exists():
        with open(redacted_path, 'r', encoding='utf-8') as f:
            return f.read()
    if not allow_paste:
        print(f"Redacted file not found: {redacted_path}", file=sys.stderr)
        sys.exit(1)
    print(f"Redacted file not found: {redacted_path}")
    print(
        "Please paste the redacted content below. "
        "End input with EOF (Ctrl+D on Linux/macOS, Ctrl+Z on Windows):"
    )
    lines = []
    try:
        while True:
            line = input()
            lines.append(line)
    except EOFError:
        pass
    return '\n'.join(lines)


def unredact_content(content, dictionary):
    for placeholder, original in dictionary.items():
        content = content.replace(placeholder, original)
    return content


def unredact_file(original_path, dictionary=None, allow_paste=True):
    """Restore one file from redacted/<path> using the dictionary."""
    original_path = Path(original_path)
    redacted_path = Path('redacted') / original_path

    if dictionary is None:
        dictionary = load_dictionary()

    redacted_content = get_redacted_content(redacted_path, allow_paste=allow_paste)
    restored_content = unredact_content(redacted_content, dictionary)

    original_path.parent.mkdir(parents=True, exist_ok=True)
    with open(original_path, 'w', encoding='utf-8') as outfile:
        outfile.write(restored_content)

    print(f"Restored file written to: {original_path}")


def unredact_files(paths):
    """Restore one or more files or directories.

    Directories are walked recursively. Paste-from-stdin is only allowed when
    the expanded result is a single file.
    """
    files, missing = expand_paths(paths, unredact=True)
    if missing:
        for path in missing:
            print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)
    if not files:
        print("No files to unredact.", file=sys.stderr)
        sys.exit(1)

    dictionary = load_dictionary()
    allow_paste = len(files) == 1
    for original_path in files:
        unredact_file(original_path, dictionary=dictionary, allow_paste=allow_paste)


def print_usage(file=None):
    print(USAGE, end='', file=file if file is not None else sys.stdout)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv in (['-h'], ['--help']):
        print_usage()
        sys.exit(0 if argv else 1)

    if any(arg.startswith('-') for arg in argv):
        print_usage(file=sys.stderr)
        sys.exit(1)

    unredact_files(argv)


if __name__ == "__main__":
    main()
