"""Redact sensitive values from files and manage redaction patterns."""

import argparse
import re
import sys
import uuid
import yaml

from pathlib import Path

from redactor import __version__
from redactor.paths import expand_paths



# Built-in defaults used when redacted/patterns.yaml is missing.
# Order matters: patterns are applied top-to-bottom.
DEFAULT_PATTERNS = {
    'IP': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    'APIKEY': r'(?<=API_KEY=)[A-Za-z0-9-_]+',
    'TOKEN': r'(?<=TOKEN=)[A-Za-z0-9-_]+',
    'PASSWORD': r'(?<=PASSWORD=)[^\s]+',
    'GOV': r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+gov\b',
}

# Alias for tests and callers that expect the historical name.
patterns = DEFAULT_PATTERNS

DICT_PATH = Path('redacted/dictionary.yaml')
PATTERNS_PATH = Path('redacted/patterns.yaml')
GITIGNORE_PATH = Path('.gitignore')
REDACTED_GITIGNORE_ENTRY = 'redacted/'


def generate_placeholder(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def redacted_in_gitignore(content):
    """True if .gitignore content already ignores the redacted/ directory."""
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or line.startswith('!'):
            continue
        # Common forms: redacted, redacted/, /redacted, /redacted/, **/redacted/
        normalized = line.rstrip('/')
        if normalized in ('redacted', '/redacted', '**/redacted'):
            return True
        if normalized.endswith('/redacted'):
            return True
    return False


def ensure_redacted_gitignored():
    """Ensure redacted/ is listed in .gitignore (creates the file if needed).

    Returns True if an entry was added, False if already present.
    """
    if GITIGNORE_PATH.exists():
        text = GITIGNORE_PATH.read_text(encoding='utf-8')
        if redacted_in_gitignore(text):
            return False
        prefix = '' if text.endswith('\n') or text == '' else '\n'
        GITIGNORE_PATH.write_text(
            text + prefix + REDACTED_GITIGNORE_ENTRY + '\n',
            encoding='utf-8',
        )
    else:
        GITIGNORE_PATH.write_text(REDACTED_GITIGNORE_ENTRY + '\n', encoding='utf-8')
    print(f"Added {REDACTED_GITIGNORE_ENTRY!r} to {GITIGNORE_PATH}")
    return True


def ensure_redacted_workspace():
    """Create redacted/ and make sure it is gitignored."""
    Path('redacted').mkdir(parents=True, exist_ok=True)
    ensure_redacted_gitignored()


def load_dictionary():
    if DICT_PATH.exists():
        with open(DICT_PATH, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    return {}


def save_dictionary(dictionary):
    ensure_redacted_workspace()
    with open(DICT_PATH, 'w', encoding='utf-8') as f:
        yaml.safe_dump(dictionary, f, default_flow_style=False, sort_keys=False)


def ensure_redacted_path(original_path):
    ensure_redacted_workspace()
    redacted_path = Path('redacted') / original_path
    redacted_path.parent.mkdir(parents=True, exist_ok=True)
    return redacted_path


def validate_patterns(data):
    """Return a validated ordered dict of name -> regex string, or raise ValueError."""
    if not isinstance(data, dict):
        raise ValueError("patterns config must be a mapping of NAME: regex")
    if not data:
        raise ValueError("patterns config is empty")

    validated = {}
    for name, regex in data.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"invalid pattern name: {name!r}")
        if not isinstance(regex, str) or not regex:
            raise ValueError(f"pattern {name!r} must be a non-empty regex string")
        try:
            re.compile(regex)
        except re.error as exc:
            raise ValueError(f"pattern {name!r} is not a valid regex: {exc}") from exc
        validated[name.strip()] = regex
    return validated


def load_patterns_file():
    """Load and validate patterns from PATTERNS_PATH. Raises ValueError/OSError.

    An empty mapping is allowed (redact will match nothing).
    """
    with open(PATTERNS_PATH, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    if data is None or data == {}:
        return {}
    return validate_patterns(data)


def save_patterns(patterns_map):
    """Write patterns map to PATTERNS_PATH (creates redacted/ as needed)."""
    validated = validate_patterns(patterns_map)
    ensure_redacted_workspace()
    with open(PATTERNS_PATH, 'w', encoding='utf-8') as f:
        yaml.safe_dump(validated, f, default_flow_style=False, sort_keys=False)
    return validated


def load_patterns():
    """Effective patterns: file if present, otherwise built-in defaults."""
    if PATTERNS_PATH.exists():
        try:
            return load_patterns_file()
        except ValueError as exc:
            print(f"Invalid patterns config ({PATTERNS_PATH}): {exc}", file=sys.stderr)
            sys.exit(1)
    return dict(DEFAULT_PATTERNS)


def cmd_patterns_init(args):
    if PATTERNS_PATH.exists() and not args.force:
        print(f"Patterns file already exists: {PATTERNS_PATH}", file=sys.stderr)
        print("Use --force to overwrite with built-in defaults.", file=sys.stderr)
        sys.exit(1)
    save_patterns(DEFAULT_PATTERNS)
    print(f"Wrote built-in patterns to: {PATTERNS_PATH}")


def cmd_patterns_list(args):
    if PATTERNS_PATH.exists():
        patterns_map = load_patterns_file()
        source = str(PATTERNS_PATH)
    else:
        patterns_map = dict(DEFAULT_PATTERNS)
        source = "built-in defaults (run: redact patterns init)"

    if args.yaml:
        yaml.safe_dump(patterns_map, sys.stdout, default_flow_style=False, sort_keys=False)
        return

    print(f"Source: {source}")
    if not patterns_map:
        print("(no patterns)")
        return
    width = max(len(name) for name in patterns_map)
    for name, regex in patterns_map.items():
        print(f"{name.ljust(width)}  {regex}")


def cmd_patterns_add(args):
    name = args.name.strip()
    if not name:
        print("Pattern name must be non-empty.", file=sys.stderr)
        sys.exit(1)

    regex = args.regex
    try:
        re.compile(regex)
    except re.error as exc:
        print(f"Invalid regex: {exc}", file=sys.stderr)
        sys.exit(1)

    if PATTERNS_PATH.exists():
        patterns_map = load_patterns_file()
    else:
        patterns_map = dict(DEFAULT_PATTERNS)

    created = name not in patterns_map
    patterns_map[name] = regex
    save_patterns(patterns_map)
    action = "Added" if created else "Updated"
    print(f"{action} pattern {name!r} in {PATTERNS_PATH}")


def cmd_patterns_remove(args):
    name = args.name.strip()
    if not PATTERNS_PATH.exists():
        print(f"Patterns file not found: {PATTERNS_PATH}", file=sys.stderr)
        print("Run: redact patterns init", file=sys.stderr)
        sys.exit(1)

    patterns_map = load_patterns_file()
    if name not in patterns_map:
        if args.ignore_missing:
            print(f"Pattern {name!r} not present; nothing to do.")
            return
        print(f"Pattern not found: {name!r}", file=sys.stderr)
        sys.exit(1)

    del patterns_map[name]
    if not patterns_map:
        print("Warning: no patterns left; redacting will match nothing.", file=sys.stderr)
        # Allow empty file: write empty mapping without validate_patterns empty check
        ensure_redacted_workspace()
        with open(PATTERNS_PATH, 'w', encoding='utf-8') as f:
            yaml.safe_dump({}, f, default_flow_style=False, sort_keys=False)
    else:
        save_patterns(patterns_map)

    print(f"Removed pattern {name!r} from {PATTERNS_PATH}")


def _redact_content(content, active_patterns, dictionary, reverse_dict):
    """Apply patterns to content, updating dictionary/reverse_dict in place."""
    for key, pattern in active_patterns.items():
        for match in set(re.findall(pattern, content)):
            if match in reverse_dict:
                placeholder = reverse_dict[match]
            else:
                placeholder = generate_placeholder(key)
                dictionary[placeholder] = match
                reverse_dict[match] = placeholder
            content = content.replace(match, placeholder)
    return content


def redact_file(input_path: Path, active_patterns=None, dictionary=None, reverse_dict=None):
    """Redact a single file. Optionally reuse shared patterns/dictionary for batch runs."""
    input_path = Path(input_path)
    if not input_path.exists():
        print(f"File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    owns_dictionary = dictionary is None
    if active_patterns is None:
        active_patterns = load_patterns()
        if not active_patterns:
            print("Warning: no patterns configured; writing file unchanged.", file=sys.stderr)
    if dictionary is None:
        dictionary = load_dictionary()
    if reverse_dict is None:
        reverse_dict = {v: k for k, v in dictionary.items()}

    with open(input_path, 'r', encoding='utf-8') as infile:
        content = infile.read()

    content = _redact_content(content, active_patterns, dictionary, reverse_dict)

    redacted_path = ensure_redacted_path(input_path)
    with open(redacted_path, 'w', encoding='utf-8') as outfile:
        outfile.write(content)

    if owns_dictionary:
        save_dictionary(dictionary)
        print(f"Placeholder dictionary updated at: {DICT_PATH}")

    print(f"Redacted file written to: {redacted_path}")
    return dictionary, reverse_dict


def redact_files(input_paths):
    """Redact one or more files or directories, sharing placeholders across the batch.

    Directories are walked recursively (skipping names like redacted/, .git/, etc.).
    """
    paths, missing = expand_paths(input_paths)
    if missing:
        for path in missing:
            print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)
    if not paths:
        print("No files to redact.", file=sys.stderr)
        sys.exit(1)

    active_patterns = load_patterns()
    if not active_patterns:
        print("Warning: no patterns configured; writing files unchanged.", file=sys.stderr)

    dictionary = load_dictionary()
    reverse_dict = {v: k for k, v in dictionary.items()}

    for input_path in paths:
        redact_file(
            input_path,
            active_patterns=active_patterns,
            dictionary=dictionary,
            reverse_dict=reverse_dict,
        )

    save_dictionary(dictionary)
    print(f"Placeholder dictionary updated at: {DICT_PATH}")


def print_version():
    print(f'redact {__version__}')


def run_help(parser, topics):
    """Show top-level or nested command help.

    Examples:
      redact help
      redact help patterns
      redact help patterns add
    """
    if not topics:
        parser.print_help()
        return
    # argparse prints help and exits 0 when -h is present.
    parser.parse_args(list(topics) + ['-h'])


def build_parser():
    parser = argparse.ArgumentParser(
        prog='redact',
        description=(
            'Redact sensitive values from files and directories, '
            'or manage redaction patterns.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
examples:
  redact config.env                 redact one file → redacted/config.env
  redact a.txt b.env src/           multiple files and/or directories
  redact patterns init              write built-in patterns to {PATTERNS_PATH}
  redact patterns list              show effective patterns
  redact patterns add GOV '\\b...gov\\b'
  redact help patterns              help for the patterns command

Outputs under redacted/ (cwd-relative). Uses {PATTERNS_PATH} when present;
otherwise built-in defaults. Directory walks skip redacted/, .git/,
node_modules/, virtualenvs, and similar paths.
""",
    )
    parser.add_argument(
        '-V',
        '--version',
        action='version',
        version=f'%(prog)s {__version__}',
    )
    sub = parser.add_subparsers(dest='command')

    sub.add_parser(
        'help',
        help='Show help (optionally for a subcommand: help patterns add)',
    )
    sub.add_parser('version', help=f'Show version ({__version__})')

    patterns_parser = sub.add_parser(
        'patterns',
        help='List, add, remove, or initialize redaction patterns',
        description=(
            f'Manage {PATTERNS_PATH} (name → regex). '
            'Order matters: patterns are applied top-to-bottom.'
        ),
    )
    patterns_sub = patterns_parser.add_subparsers(dest='patterns_command', required=True)

    p_init = patterns_sub.add_parser(
        'init',
        help=f'Write built-in defaults to {PATTERNS_PATH}',
    )
    p_init.add_argument(
        '--force',
        action='store_true',
        help='Overwrite an existing patterns file',
    )
    p_init.set_defaults(func=cmd_patterns_init)

    p_list = patterns_sub.add_parser(
        'list',
        help='Show effective patterns (file if present, else built-ins)',
    )
    p_list.add_argument(
        '--yaml',
        action='store_true',
        help='Print patterns as YAML',
    )
    p_list.set_defaults(func=cmd_patterns_list)

    p_add = patterns_sub.add_parser(
        'add',
        help='Add or update a pattern (creates config from defaults if missing)',
    )
    p_add.add_argument('name', help='Pattern name / placeholder prefix (e.g. EMAIL)')
    p_add.add_argument('regex', help='Python regular expression (quote for the shell)')
    p_add.set_defaults(func=cmd_patterns_add)

    p_remove = patterns_sub.add_parser(
        'remove',
        help='Remove a pattern from the config file',
    )
    p_remove.add_argument('name', help='Pattern name to remove')
    p_remove.add_argument(
        '--ignore-missing',
        action='store_true',
        help='Do not error if the pattern is not defined',
    )
    p_remove.set_defaults(func=cmd_patterns_remove)

    parser.add_argument(
        'files',
        nargs='*',
        metavar='path',
        help=(
            'File(s) or directory(ies) to redact. Directories are walked '
            'recursively. Writes under redacted/ and updates dictionary.yaml.'
        ),
    )
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    if not argv:
        parser.print_help()
        sys.exit(1)

    head = argv[0]

    if head in ('-h', '--help'):
        parser.print_help()
        return

    if head in ('-V', '--version'):
        print_version()
        return

    if head == 'help':
        run_help(parser, argv[1:])
        return

    if head == 'version':
        print_version()
        return

    # Prefer explicit subcommands; otherwise treat remaining args as files to redact.
    if head == 'patterns':
        args = parser.parse_args(argv)
        try:
            args.func(args)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            sys.exit(1)
        return

    if head.startswith('-'):
        # Unknown flags: let argparse report usage / handle known options.
        args = parser.parse_args(argv)
        if not args.files:
            parser.print_help()
            sys.exit(1)
        redact_files(args.files)
        return

    # One or more file paths (none of the reserved subcommands).
    if any(arg.startswith('-') for arg in argv):
        parser.error(f"unexpected option among files: {' '.join(argv)}")

    redact_files(argv)


if __name__ == "__main__":
    main()
