"""Redact sensitive values from files and manage redaction patterns."""

import argparse
import fnmatch
import ipaddress
import re
import sys
import uuid
import yaml

from pathlib import Path

from redactor import __version__
from redactor.paths import expand_paths, filter_excluded, filter_included

# Built-in defaults used when redacted/patterns.yaml is missing.
# Order matters: patterns are applied top-to-bottom.
# Capturing groups may mark the secret value; the engine uses the first non-empty group
# (or the full match if there are no groups). See extract_match_values().

# Valid IPv4 octets (0–255), not merely "digits with dots".
_IPV4_OCTET = r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
# Flexible assignment: KEY = value / KEY: value with optional quotes.
# Unquoted minimum length varies by pattern (see each use).
def _assign_value(min_len: int) -> str:
    return (
        r'(?:"([^"\n]+)"|\'([^\'\n]+)\'|'
        rf'([^\s#\'",;]{{{min_len},}}))'
    )


DEFAULT_PATTERNS = {
    # Shape-based (no env key required) — run early for dense secret material.
    'PEM': (
        r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----'
        r'[\s\S]*?'
        r'-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----'
    ),
    'JWT': (
        r'\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b'
    ),
    'AWSKEY': r'\b(AKIA[0-9A-Z]{16})\b',
    # AWS secret access key: prefer labeled assignment (40-char base64 is too FP-prone alone).
    'AWSSECRET': (
        rf'(?i)\b(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*'
        rf'(?:"([^"\n]+)"|\'([^\'\n]+)\'|([A-Za-z0-9/+=]{{40}}))'
    ),
    # Vendor token prefixes (GitHub, GitLab, Stripe, Slack).
    'GHTOKEN': r'\b(gh[pousr]_[A-Za-z0-9_]{20,})\b',
    'GLPAT': r'\b(glpat-[A-Za-z0-9_\-]{20,})\b',
    'STRIPE': r'\b(sk_(?:live|test)_[A-Za-z0-9]{16,})\b',
    'SLACK': r'\b(xox[baprs]-[A-Za-z0-9-]{10,})\b',
    'BEARER': r'(?i)\bBearer\s+([A-Za-z0-9._\-+=/]{8,})',
    # HTTP headers that commonly carry secrets (value only).
    'HEADER': (
        r'(?i)\b(?:X-Api-Key|X-API-Key|Api-Key|API-Key|Private-Token|'
        r'PRIVATE-TOKEN|X-Auth-Token|X-Access-Token|X-Gitlab-Token|'
        r'X-CSRF-Token|X-CSRFToken)\s*[:=]\s*'
        rf'{_assign_value(6)}'
    ),
    'BASICAUTH': (
        r'(?i)\bAuthorization\s*:\s*Basic\s+([A-Za-z0-9+/=]{8,})'
    ),
    # URL / connection-string userinfo: scheme://user:pass@host
    'URLCREDS': (
        r'(?i)\b(?:https?|ftp|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|'
        r'redis|rediss|amqp|amqps|mqtt|mqtts?)://'
        r'((?:[^:@/\s\'"]+):(?:[^@/\s\'"]+))@'
    ),
    # Assignment-style credentials (broader key names + =/:)
    'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    'APIKEY': (
        rf'(?i)\b(?:API[_-]?KEY|apiKey)\s*[=:]\s*{_assign_value(8)}'
    ),
    'TOKEN': (
        rf'(?i)\b(?:TOKEN|ACCESS_TOKEN|AUTH_TOKEN|API_TOKEN)\s*[=:]\s*{_assign_value(6)}'
    ),
    'PASSWORD': (
        rf'(?i)\b(?:PASSWORD|PASSWD|DB_PASSWORD|MYSQL_PWD)\s*[=:]\s*{_assign_value(4)}'
    ),
    'IP': rf'\b(?:{_IPV4_OCTET}\.){{3}}{_IPV4_OCTET}\b',
    # Practical IPv6 forms (full, compressed, loopback).
    # Use hex/colon lookarounds: \b fails before ':' (both non-word chars).
    'IP6': (
        r'(?i)(?<![0-9a-f:])(?:'
        r'(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}'
        r'|(?:[0-9a-f]{1,4}:){1,7}:'
        r'|:(?::[0-9a-f]{1,4}){1,7}'
        r'|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}'
        r'|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}'
        r'|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}'
        r'|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}'
        r'|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}'
        r'|[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})'
        r'|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}'
        r'|::1'
        r')(?![0-9a-f:])'
    ),
    'GOV': r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+gov\b',
}

# Safe values never redacted when using built-in allowlist (or after allowlist init).
# Entries may be exact strings, globs (* ?), or IPv4/IPv6 CIDR (e.g. 10.0.0.0/8).
DEFAULT_ALLOWLIST = {
    'LOCALHOST_V4': '127.0.0.1',
    'UNSPECIFIED_V4': '0.0.0.0',
    'BROADCAST_V4': '255.255.255.255',
    'LOCALHOST_V6': '::1',
    'DOC_TEST_NET_1': '192.0.2.1',
    'DOC_TEST_NET_2': '198.51.100.1',
    'DOC_TEST_NET_3': '203.0.113.1',
    # Documentation / test nets (RFC 5737) as CIDR — optional broader skip
    'DOC_TEST_NET_1_CIDR': '192.0.2.0/24',
    'DOC_TEST_NET_2_CIDR': '198.51.100.0/24',
    'DOC_TEST_NET_3_CIDR': '203.0.113.0/24',
}

# Extensions always treated as binary/image (skipped even without exclude.yaml).
BINARY_EXTENSIONS = frozenset(
    {
        # images
        '.png',
        '.jpg',
        '.jpeg',
        '.gif',
        '.webp',
        '.ico',
        '.bmp',
        '.tif',
        '.tiff',
        '.heic',
        '.heif',
        '.raw',
        '.psd',
        # audio / video
        '.mp3',
        '.mp4',
        '.m4a',
        '.wav',
        '.flac',
        '.ogg',
        '.webm',
        '.avi',
        '.mov',
        '.mkv',
        '.wmv',
        # fonts
        '.woff',
        '.woff2',
        '.ttf',
        '.otf',
        '.eot',
        # archives / packages
        '.zip',
        '.gz',
        '.tgz',
        '.bz2',
        '.xz',
        '.7z',
        '.rar',
        '.tar',
        '.jar',
        '.war',
        # documents (opaque)
        '.pdf',
        '.doc',
        '.docx',
        '.xls',
        '.xlsx',
        '.ppt',
        '.pptx',
        # compiled / binary
        '.exe',
        '.dll',
        '.so',
        '.dylib',
        '.o',
        '.a',
        '.pyc',
        '.pyo',
        '.class',
        '.wasm',
        '.bin',
        '.dat',
        '.sqlite',
        '.db',
        '.pkl',
        '.pickle',
    }
)

# Starter exclude globs written by `redact exclude init`.
# Binary extensions are always skipped; these are additional defaults for init.
DEFAULT_EXCLUDES = {
    # VCS / tooling (also hard-skipped via paths.SKIP_DIR_NAMES)
    'GIT': '**/.git/**',
    'GIT_DIR': '.git/**',
    'MINJS': '**/*.min.js',
    'MAP': '**/*.map',
    'PYC': '**/*.pyc',
    'LOCK_NPM': '**/package-lock.json',
    'LOCK_PNPM': '**/pnpm-lock.yaml',
    # images
    'PNG': '**/*.png',
    'JPG': '**/*.jpg',
    'JPEG': '**/*.jpeg',
    'GIF': '**/*.gif',
    'WEBP': '**/*.webp',
    'ICO': '**/*.ico',
    'BMP': '**/*.bmp',
    'TIF': '**/*.tif',
    'TIFF': '**/*.tiff',
    # audio / video
    'MP3': '**/*.mp3',
    'MP4': '**/*.mp4',
    'WAV': '**/*.wav',
    'WEBM': '**/*.webm',
    'MOV': '**/*.mov',
    # fonts
    'WOFF': '**/*.woff',
    'WOFF2': '**/*.woff2',
    'TTF': '**/*.ttf',
    # archives
    'ZIP': '**/*.zip',
    'GZ': '**/*.gz',
    'TAR': '**/*.tar',
    # docs / opaque
    'PDF': '**/*.pdf',
    'DOCX': '**/*.docx',
    'XLSX': '**/*.xlsx',
}

# Alias for tests and callers that expect the historical name.
patterns = DEFAULT_PATTERNS

DICT_PATH = Path('redacted/dictionary.yaml')
PATTERNS_PATH = Path('redacted/patterns.yaml')
EXCLUDE_PATH = Path('redacted/exclude.yaml')
ALLOWLIST_PATH = Path('redacted/allowlist.yaml')
GITIGNORE_PATH = Path('.gitignore')
REDACTED_GITIGNORE_ENTRY = 'redacted/'


def generate_placeholder(prefix, existing=None, max_attempts=64):
    """Return a unique placeholder like PREFIX_a1b2c3d4.

    If *existing* is provided (set/dict of keys already in use), regenerate on
    collision. Raises RuntimeError if uniqueness cannot be achieved within
    max_attempts (extremely unlikely with 8 hex digits).
    """
    existing = existing if existing is not None else ()
    for _ in range(max_attempts):
        placeholder = f"{prefix}_{uuid.uuid4().hex[:8]}"
        if placeholder not in existing:
            return placeholder
    raise RuntimeError(
        f"Unable to generate unique placeholder for prefix {prefix!r} "
        f"after {max_attempts} attempts"
    )


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


def validate_excludes(data):
    """Return validated ordered dict of name -> glob string, or raise ValueError."""
    if not isinstance(data, dict):
        raise ValueError("exclude config must be a mapping of NAME: glob")
    if not data:
        raise ValueError("exclude config is empty")

    validated = {}
    for name, glob in data.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"invalid exclude name: {name!r}")
        if not isinstance(glob, str) or not glob.strip():
            raise ValueError(f"exclude {name!r} must be a non-empty glob string")
        validated[name.strip()] = glob.strip()
    return validated


def load_excludes_file():
    """Load and validate excludes from EXCLUDE_PATH. Empty mapping allowed."""
    with open(EXCLUDE_PATH, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    if data is None or data == {}:
        return {}
    return validate_excludes(data)


def save_excludes(excludes_map):
    """Write excludes map to EXCLUDE_PATH."""
    validated = validate_excludes(excludes_map)
    ensure_redacted_workspace()
    with open(EXCLUDE_PATH, 'w', encoding='utf-8') as f:
        yaml.safe_dump(validated, f, default_flow_style=False, sort_keys=False)
    return validated


def load_excludes():
    """Effective excludes: file if present, otherwise none (empty).

    Unlike patterns, missing exclude.yaml means no path excludes — only the
    built-in directory skip list in paths.walk_files applies.
    """
    if EXCLUDE_PATH.exists():
        try:
            return load_excludes_file()
        except ValueError as exc:
            print(f"Invalid exclude config ({EXCLUDE_PATH}): {exc}", file=sys.stderr)
            sys.exit(1)
    return {}


def exclude_globs(excludes_map=None):
    """Return list of glob strings from an excludes mapping."""
    if excludes_map is None:
        excludes_map = load_excludes()
    return list(excludes_map.values())


def cmd_exclude_init(args):
    if EXCLUDE_PATH.exists() and not args.force:
        print(f"Exclude file already exists: {EXCLUDE_PATH}", file=sys.stderr)
        print("Use --force to overwrite with built-in defaults.", file=sys.stderr)
        sys.exit(1)
    save_excludes(DEFAULT_EXCLUDES)
    print(f"Wrote built-in excludes to: {EXCLUDE_PATH}")


def cmd_exclude_list(args):
    if EXCLUDE_PATH.exists():
        excludes_map = load_excludes_file()
        source = str(EXCLUDE_PATH)
    else:
        excludes_map = {}
        source = f"none (run: redact exclude init → {EXCLUDE_PATH})"

    if args.yaml:
        yaml.safe_dump(excludes_map, sys.stdout, default_flow_style=False, sort_keys=False)
        return

    print(f"Source: {source}")
    if not excludes_map:
        print("(no excludes)")
        return
    width = max(len(name) for name in excludes_map)
    for name, glob in excludes_map.items():
        print(f"{name.ljust(width)}  {glob}")


def cmd_exclude_add(args):
    name = args.name.strip()
    if not name:
        print("Exclude name must be non-empty.", file=sys.stderr)
        sys.exit(1)

    glob = args.glob.strip()
    if not glob:
        print("Glob must be non-empty.", file=sys.stderr)
        sys.exit(1)

    if EXCLUDE_PATH.exists():
        excludes_map = load_excludes_file()
    else:
        excludes_map = {}

    created = name not in excludes_map
    excludes_map[name] = glob
    save_excludes(excludes_map)
    action = "Added" if created else "Updated"
    print(f"{action} exclude {name!r} in {EXCLUDE_PATH}")


def cmd_exclude_remove(args):
    name = args.name.strip()
    if not EXCLUDE_PATH.exists():
        print(f"Exclude file not found: {EXCLUDE_PATH}", file=sys.stderr)
        print("Run: redact exclude init", file=sys.stderr)
        sys.exit(1)

    excludes_map = load_excludes_file()
    if name not in excludes_map:
        if args.ignore_missing:
            print(f"Exclude {name!r} not present; nothing to do.")
            return
        print(f"Exclude not found: {name!r}", file=sys.stderr)
        sys.exit(1)

    del excludes_map[name]
    if not excludes_map:
        print("Warning: no excludes left.", file=sys.stderr)
        ensure_redacted_workspace()
        with open(EXCLUDE_PATH, 'w', encoding='utf-8') as f:
            yaml.safe_dump({}, f, default_flow_style=False, sort_keys=False)
    else:
        save_excludes(excludes_map)

    print(f"Removed exclude {name!r} from {EXCLUDE_PATH}")


def validate_allowlist(data):
    """Return validated ordered dict of name -> rule string, or raise ValueError.

    Rules may be exact strings, shell-style globs (* ?), or CIDR networks.
    """
    if not isinstance(data, dict):
        raise ValueError("allowlist config must be a mapping of NAME: string")
    if not data:
        raise ValueError("allowlist config is empty")

    validated = {}
    for name, value in data.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"invalid allowlist name: {name!r}")
        if not isinstance(value, str) or value == '':
            raise ValueError(f"allowlist {name!r} must be a non-empty string")
        rule = value.strip()
        # Validate CIDR entries early so bad config fails at load time.
        if '/' in rule and not any(ch in rule for ch in '*?['):
            try:
                ipaddress.ip_network(rule, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"allowlist {name!r} is not a valid CIDR or IP network: {exc}"
                ) from exc
        validated[name.strip()] = rule
    return validated


def allowlist_rule_matches(value: str, rule: str) -> bool:
    """True if *value* is covered by an allowlist *rule* (exact, glob, or CIDR)."""
    if value == rule:
        return True
    # Glob (path-style or simple shell patterns)
    if any(ch in rule for ch in '*?['):
        if fnmatch.fnmatch(value, rule):
            return True
    # CIDR / network
    if '/' in rule:
        try:
            network = ipaddress.ip_network(rule, strict=False)
            addr = ipaddress.ip_address(value)
            if addr in network:
                return True
        except ValueError:
            pass
    return False


def is_allowlisted(value: str, allowlist) -> bool:
    """True if value matches any allowlist rule.

    *allowlist* may be a dict of name→rule, or an iterable of rule strings.
    """
    if not allowlist:
        return False
    rules = allowlist.values() if isinstance(allowlist, dict) else allowlist
    for rule in rules:
        if allowlist_rule_matches(value, rule):
            return True
    return False


def load_allowlist_file():
    with open(ALLOWLIST_PATH, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    if data is None or data == {}:
        return {}
    return validate_allowlist(data)


def save_allowlist(allowlist_map):
    validated = validate_allowlist(allowlist_map)
    ensure_redacted_workspace()
    with open(ALLOWLIST_PATH, 'w', encoding='utf-8') as f:
        yaml.safe_dump(validated, f, default_flow_style=False, sort_keys=False)
    return validated


def load_allowlist():
    """Effective allowlist map: file if present, otherwise built-in defaults."""
    if ALLOWLIST_PATH.exists():
        try:
            return load_allowlist_file()
        except ValueError as exc:
            print(f"Invalid allowlist config ({ALLOWLIST_PATH}): {exc}", file=sys.stderr)
            sys.exit(1)
    return dict(DEFAULT_ALLOWLIST)


def allowlist_values(allowlist_map=None):
    """Return allowlist map (name → rule). Kept for callers; prefer is_allowlisted()."""
    if allowlist_map is None:
        return load_allowlist()
    return allowlist_map


def cmd_allowlist_init(args):
    if ALLOWLIST_PATH.exists() and not args.force:
        print(f"Allowlist file already exists: {ALLOWLIST_PATH}", file=sys.stderr)
        print("Use --force to overwrite with built-in defaults.", file=sys.stderr)
        sys.exit(1)
    save_allowlist(DEFAULT_ALLOWLIST)
    print(f"Wrote built-in allowlist to: {ALLOWLIST_PATH}")


def cmd_allowlist_list(args):
    if ALLOWLIST_PATH.exists():
        allow_map = load_allowlist_file()
        source = str(ALLOWLIST_PATH)
    else:
        allow_map = dict(DEFAULT_ALLOWLIST)
        source = "built-in defaults (run: redact allowlist init)"

    if args.yaml:
        yaml.safe_dump(allow_map, sys.stdout, default_flow_style=False, sort_keys=False)
        return

    print(f"Source: {source}")
    if not allow_map:
        print("(no allowlist entries)")
        return
    width = max(len(name) for name in allow_map)
    for name, value in allow_map.items():
        print(f"{name.ljust(width)}  {value}")


def cmd_allowlist_add(args):
    name = args.name.strip()
    if not name:
        print("Allowlist name must be non-empty.", file=sys.stderr)
        sys.exit(1)
    value = args.value
    if value == '':
        print("Allowlist value must be non-empty.", file=sys.stderr)
        sys.exit(1)

    if ALLOWLIST_PATH.exists():
        allow_map = load_allowlist_file()
    else:
        allow_map = dict(DEFAULT_ALLOWLIST)

    created = name not in allow_map
    allow_map[name] = value
    save_allowlist(allow_map)
    action = "Added" if created else "Updated"
    print(f"{action} allowlist {name!r} in {ALLOWLIST_PATH}")


def cmd_allowlist_remove(args):
    name = args.name.strip()
    if not ALLOWLIST_PATH.exists():
        print(f"Allowlist file not found: {ALLOWLIST_PATH}", file=sys.stderr)
        print("Run: redact allowlist init", file=sys.stderr)
        sys.exit(1)

    allow_map = load_allowlist_file()
    if name not in allow_map:
        if args.ignore_missing:
            print(f"Allowlist entry {name!r} not present; nothing to do.")
            return
        print(f"Allowlist entry not found: {name!r}", file=sys.stderr)
        sys.exit(1)

    del allow_map[name]
    if not allow_map:
        print("Warning: allowlist is empty.", file=sys.stderr)
        ensure_redacted_workspace()
        with open(ALLOWLIST_PATH, 'w', encoding='utf-8') as f:
            yaml.safe_dump({}, f, default_flow_style=False, sort_keys=False)
    else:
        save_allowlist(allow_map)
    print(f"Removed allowlist {name!r} from {ALLOWLIST_PATH}")


def extract_match_values(pattern, content):
    """Yield secret strings from pattern matches in content.

    If the pattern has capturing groups, the first non-empty group is used
    (so assignment patterns can capture only the value). Otherwise the full
    match is used (PEM blocks, plain IPs, etc.).
    """
    try:
        compiled = re.compile(pattern)
    except re.error:
        compiled = re.compile(pattern, re.MULTILINE)
    for m in compiled.finditer(content):
        if m.lastindex:
            value = None
            for i in range(1, m.lastindex + 1):
                g = m.group(i)
                if g:
                    value = g
                    break
            if value is None:
                value = m.group(0)
        else:
            value = m.group(0)
        if value:
            yield value


def collect_matches(content, active_patterns, allowlist=None):
    """Return list of (pattern_name, matched_text) without mutating content."""
    found = []
    for key, pattern in active_patterns.items():
        for match in sorted(set(extract_match_values(pattern, content))):
            if is_allowlisted(match, allowlist):
                continue
            found.append((key, match))
    return found


def classify_matches(content, active_patterns, reverse_dict, allowlist=None):
    """Split matches into new secrets vs already-mapped (reused) dictionary values.

    Returns (new_matches, reused_matches) where each item is
    (pattern_name, matched_text) and reused items may include the existing
    placeholder as a third element for display: (name, text, placeholder).
    """
    new_matches = []
    reused_matches = []
    for key, match in collect_matches(content, active_patterns, allowlist=allowlist):
        if match in reverse_dict:
            reused_matches.append((key, match, reverse_dict[match]))
        else:
            new_matches.append((key, match))
    return new_matches, reused_matches


class RunStats:
    """Counters for a redact batch (summary line)."""

    def __init__(self):
        self.redacted = 0
        self.would_redact = 0
        self.excluded = 0
        self.not_included = 0
        self.skipped_binary = 0
        self.errors = 0
        self.no_matches = 0
        self.new_secrets = 0
        self.reused_secrets = 0
        self.skipped_no_new = 0

    def summary_line(self, dry_run=False):
        if dry_run:
            parts = [
                f"would_redact={self.would_redact}",
                f"no_matches={self.no_matches}",
            ]
        else:
            parts = [f"redacted={self.redacted}"]
        parts.extend(
            [
                f"new={self.new_secrets}",
                f"reused={self.reused_secrets}",
                f"skipped_no_new={self.skipped_no_new}",
                f"excluded={self.excluded}",
                f"not_included={self.not_included}",
                f"skipped_binary={self.skipped_binary}",
                f"errors={self.errors}",
            ]
        )
        return "Summary: " + ", ".join(parts)


class OutputMode:
    """quiet / default / verbose printing for redact runs."""

    def __init__(self, quiet=False, verbose=False):
        if quiet and verbose:
            raise ValueError("Cannot combine --quiet and --verbose")
        self.quiet = quiet
        self.verbose = verbose

    def info(self, msg):
        if not self.quiet:
            print(msg)

    def detail(self, msg):
        if self.verbose and not self.quiet:
            print(msg)

    def summary(self, msg):
        """Always print (including --quiet) so CI gets a one-line result."""
        print(msg)

    def error(self, msg):
        print(msg, file=sys.stderr)


def is_binary_extension(path: Path) -> bool:
    """True if path has a known binary/image/audio/archive extension."""
    return path.suffix.lower() in BINARY_EXTENSIONS


def looks_like_binary_content(path: Path, sample_size: int = 8192) -> bool:
    """Heuristic: NUL bytes in the first sample_size bytes ⇒ binary."""
    with open(path, 'rb') as handle:
        chunk = handle.read(sample_size)
    return b'\x00' in chunk


def read_text_file(path: Path) -> str:
    """Read path as UTF-8 text, or raise UnicodeDecodeError / OSError."""
    with open(path, 'r', encoding='utf-8') as infile:
        return infile.read()


def _redact_content(content, active_patterns, dictionary, reverse_dict, allowlist=None):
    """Apply patterns to content, updating dictionary/reverse_dict in place."""
    for key, pattern in active_patterns.items():
        for match in set(extract_match_values(pattern, content)):
            if is_allowlisted(match, allowlist):
                continue
            if match in reverse_dict:
                placeholder = reverse_dict[match]
            else:
                placeholder = generate_placeholder(key, existing=dictionary)
                dictionary[placeholder] = match
                reverse_dict[match] = placeholder
            content = content.replace(match, placeholder)
    return content


def redact_file(
    input_path: Path,
    active_patterns=None,
    dictionary=None,
    reverse_dict=None,
    dry_run=False,
    new_only=False,
    allowlist=None,
    out=None,
    stats=None,
):
    """Redact a single file. Optionally reuse shared patterns/dictionary for batch runs.

    Raises FileNotFoundError if the path is missing. Skips binary files (logs to
    stderr and returns without writing). Other I/O or decode errors propagate
    so batch callers can log and continue.

    When new_only is True, files with no secrets absent from the dictionary are
    skipped (no write). Known secrets are still replaced with existing placeholders
    when a file is written because it contains at least one new secret.
    """
    out = out or OutputMode()
    stats = stats if stats is not None else RunStats()
    input_path = Path(input_path)
    if not input_path.exists():
        raise FileNotFoundError(f"File not found: {input_path}")

    owns_dictionary = dictionary is None
    if active_patterns is None:
        active_patterns = load_patterns()
        if not active_patterns:
            out.error("Warning: no patterns configured; writing file unchanged.")
    if dictionary is None:
        dictionary = load_dictionary()
    if reverse_dict is None:
        reverse_dict = {v: k for k, v in dictionary.items()}
    if allowlist is None:
        allowlist = load_allowlist()

    if is_binary_extension(input_path):
        out.error(f"Skipping binary file: {input_path}")
        stats.skipped_binary += 1
        return dictionary, reverse_dict, "skipped"

    if looks_like_binary_content(input_path):
        out.error(f"Skipping binary file: {input_path}")
        stats.skipped_binary += 1
        return dictionary, reverse_dict, "skipped"

    content = read_text_file(input_path)
    new_matches, reused_matches = classify_matches(
        content, active_patterns, reverse_dict, allowlist=allowlist
    )
    stats.new_secrets += len(new_matches)
    stats.reused_secrets += len(reused_matches)

    if dry_run:
        show_new = new_matches
        show_reused = [] if new_only else reused_matches
        if new_only and not show_new:
            out.info(f"Would skip (no new secrets): {input_path}")
            if reused_matches:
                out.detail(f"  reused only: {len(reused_matches)}")
            stats.skipped_no_new += 1
            if not reused_matches:
                stats.no_matches += 1
            return dictionary, reverse_dict, "dry"

        out.info(f"Would redact: {input_path}")
        if not show_new and not show_reused:
            out.info("  (no matches)")
            stats.no_matches += 1
        else:
            stats.would_redact += 1
            for key, match in show_new:
                out.info(f"  NEW {key}: {match}")
            for item in show_reused:
                key, match, placeholder = item
                out.info(f"  REUSED {key}: {match} -> {placeholder}")
        return dictionary, reverse_dict, "dry"

    if new_only and not new_matches:
        stats.skipped_no_new += 1
        if not reused_matches:
            stats.no_matches += 1
        out.info(f"Skipped (no new secrets): {input_path}")
        out.detail(f"  reused={len(reused_matches)}")
        return dictionary, reverse_dict, "skipped"

    content = _redact_content(
        content, active_patterns, dictionary, reverse_dict, allowlist=allowlist
    )

    redacted_path = ensure_redacted_path(input_path)
    with open(redacted_path, 'w', encoding='utf-8') as outfile:
        outfile.write(content)

    if owns_dictionary:
        save_dictionary(dictionary)
        out.info(f"Placeholder dictionary updated at: {DICT_PATH}")

    if new_matches or reused_matches:
        stats.redacted += 1
        out.info(f"Redacted file written to: {redacted_path}")
        out.detail(f"  new={len(new_matches)} reused={len(reused_matches)}")
        if out.verbose:
            for key, match in new_matches:
                out.detail(f"  NEW {key}: {match}")
            for key, match, placeholder in reused_matches:
                out.detail(f"  REUSED {key}: {match} -> {placeholder}")
    else:
        stats.no_matches += 1
        out.info(f"Redacted file written to: {redacted_path}")
        out.detail(f"  (no matches in {input_path})")
    return dictionary, reverse_dict, "written"


def redact_files(
    input_paths,
    dry_run=False,
    extra_excludes=None,
    includes=None,
    quiet=False,
    verbose=False,
    new_only=False,
):
    """Redact one or more files or directories, sharing placeholders across the batch.

    Directories are walked recursively (skipping names like redacted/, .git/, etc.).
    Path excludes from redacted/exclude.yaml plus optional CLI --exclude globs are
    applied after expansion. Optional --include globs keep only matching paths.
    Per-file errors are logged to stderr; processing continues. Exit status is
    non-zero if any path failed.
    """
    out = OutputMode(quiet=quiet, verbose=verbose)
    stats = RunStats()
    extra_excludes = list(extra_excludes or [])
    includes = list(includes or [])

    paths, missing = expand_paths(input_paths)
    for path in missing:
        out.error(f"Error: File not found: {path}")
        stats.errors += 1

    excludes_map = load_excludes()
    globs = exclude_globs(excludes_map) + extra_excludes
    paths, skipped = filter_excluded(paths, globs)
    for path in skipped:
        stats.excluded += 1
        out.info(f"Excluded: {path}")
        out.detail(f"  (matched exclude glob)")

    if includes:
        paths, not_included = filter_included(paths, includes)
        for path in not_included:
            stats.not_included += 1
            out.info(f"Not included: {path}")

    # Always drop known binary/image extensions (even without exclude.yaml)
    remaining = []
    for path in paths:
        if is_binary_extension(path):
            out.error(f"Skipping binary file: {path}")
            stats.skipped_binary += 1
        else:
            remaining.append(path)
    paths = remaining

    if not paths:
        out.summary(stats.summary_line(dry_run=dry_run))
        if stats.errors:
            out.error(f"Completed with {stats.errors} error(s).")
            sys.exit(1)
        out.error("No files to redact.")
        sys.exit(1)

    active_patterns = load_patterns()
    if not active_patterns:
        out.error("Warning: no patterns configured; writing files unchanged.")

    if dry_run:
        out.info(f"Dry run: {len(paths)} file(s) (no writes)")

    dictionary = load_dictionary()
    reverse_dict = {v: k for k, v in dictionary.items()}
    allowlist = load_allowlist()
    wrote_any = False

    for input_path in paths:
        try:
            _d, _r, status = redact_file(
                input_path,
                active_patterns=active_patterns,
                dictionary=dictionary,
                reverse_dict=reverse_dict,
                dry_run=dry_run,
                new_only=new_only,
                allowlist=allowlist,
                out=out,
                stats=stats,
            )
            if status == "written":
                wrote_any = True
        except FileNotFoundError as exc:
            out.error(f"Error: {exc}")
            stats.errors += 1
        except UnicodeDecodeError:
            out.error(f"Skipping binary/non-UTF-8 file: {input_path}")
            stats.skipped_binary += 1
        except OSError as exc:
            out.error(f"Error: {input_path}: {exc}")
            stats.errors += 1
        except Exception as exc:  # noqa: BLE001 — keep batch going
            out.error(f"Error: {input_path}: {exc}")
            stats.errors += 1

    if dry_run:
        out.info("Dry run complete; no files or dictionary written.")
        out.summary(stats.summary_line(dry_run=True))
        if stats.errors:
            out.error(f"Completed with {stats.errors} error(s).")
            sys.exit(1)
        return

    if wrote_any:
        save_dictionary(dictionary)
        out.info(f"Placeholder dictionary updated at: {DICT_PATH}")

    out.summary(stats.summary_line(dry_run=False))
    if stats.errors:
        out.error(f"Completed with {stats.errors} error(s).")
        sys.exit(1)


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
            'or manage patterns and path excludes.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
examples:
  redact config.env                 redact one file → redacted/config.env
  redact -n src/                    dry-run a tree (show matches, no writes)
  redact --exclude 'vendor/**' src/
  redact --include '**/*.env' .
  redact a.txt b.env src/           multiple files and/or directories
  redact patterns init              write built-in patterns to {PATTERNS_PATH}
  redact patterns add GOV '\\b...gov\\b'
  redact exclude init               write starter path globs to {EXCLUDE_PATH}
  redact allowlist init             write safe defaults (127.0.0.1, doc IPs, …)
  redact help patterns              help for the patterns command

behavior (cwd-relative outputs under redacted/):
  patterns   {PATTERNS_PATH} if present, else built-ins (PEM, JWT, AWSKEY,
             tokens, HEADER, BASICAUTH, URLCREDS, EMAIL, APIKEY, …, IP, IP6, GOV)
  allowlist  {ALLOWLIST_PATH} if present, else built-ins (exact/glob/CIDR)
  excludes   {EXCLUDE_PATH} globs plus optional --exclude (repeatable)
  includes   optional --include (repeatable); if set, keep only matching paths
  always     skip .git/ and other VCS/venv/cache dirs; skip binary/image
             extensions and non-UTF-8 / NUL-byte files
  errors     log to stderr and continue; exit 1 if any path failed
  dry-run    -n / --dry-run shows matches only (no writes); labels NEW vs REUSED
  new-only   --new-only only act on secrets not already in the dictionary
  output     -q quiet (summary + errors); -v verbose (per-match detail)
""",
    )
    parser.add_argument(
        '-V',
        '--version',
        action='version',
        version=f'%(prog)s {__version__}',
    )
    parser.add_argument(
        '-n',
        '--dry-run',
        action='store_true',
        help='Show matches only; do not write redacted files or dictionary',
    )
    parser.add_argument(
        '-q',
        '--quiet',
        action='store_true',
        help='Minimal stdout (summary line only); errors still go to stderr',
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Extra detail (e.g. match counts and values when redacting)',
    )
    parser.add_argument(
        '--new-only',
        action='store_true',
        help=(
            'Only treat secrets not already in the dictionary as actionable; '
            'skip files with no new secrets (dry-run lists NEW only)'
        ),
    )
    parser.add_argument(
        '-e',
        '--exclude',
        action='append',
        default=[],
        metavar='GLOB',
        dest='cli_excludes',
        help='Exclude paths matching GLOB (repeatable; combined with exclude.yaml)',
    )
    parser.add_argument(
        '-i',
        '--include',
        action='append',
        default=[],
        metavar='GLOB',
        dest='cli_includes',
        help='Only include paths matching GLOB (repeatable; if any, others are skipped)',
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

    exclude_parser = sub.add_parser(
        'exclude',
        help='List, add, remove, or initialize path exclude globs',
        description=(
            f'Manage {EXCLUDE_PATH} (name → glob). Matching paths are skipped '
            f'when redacting. If the file is missing, no extra globs apply — '
            f'but .git/, other tool dirs, and binary/image extensions are still '
            f'always skipped. Run `exclude init` for starter globs (includes '
            f'.git/**, images, archives, …).'
        ),
    )
    exclude_sub = exclude_parser.add_subparsers(dest='exclude_command', required=True)

    e_init = exclude_sub.add_parser(
        'init',
        help=f'Write starter excludes to {EXCLUDE_PATH}',
    )
    e_init.add_argument(
        '--force',
        action='store_true',
        help='Overwrite an existing exclude file',
    )
    e_init.set_defaults(func=cmd_exclude_init)

    e_list = exclude_sub.add_parser(
        'list',
        help='Show effective excludes (file if present, else none)',
    )
    e_list.add_argument(
        '--yaml',
        action='store_true',
        help='Print excludes as YAML',
    )
    e_list.set_defaults(func=cmd_exclude_list)

    e_add = exclude_sub.add_parser(
        'add',
        help='Add or update an exclude glob (creates empty config if missing)',
    )
    e_add.add_argument('name', help='Exclude name (e.g. VENDOR)')
    e_add.add_argument('glob', help="Glob pattern (e.g. 'vendor/**' or '**/*.min.js')")
    e_add.set_defaults(func=cmd_exclude_add)

    e_remove = exclude_sub.add_parser(
        'remove',
        help='Remove an exclude from the config file',
    )
    e_remove.add_argument('name', help='Exclude name to remove')
    e_remove.add_argument(
        '--ignore-missing',
        action='store_true',
        help='Do not error if the exclude is not defined',
    )
    e_remove.set_defaults(func=cmd_exclude_remove)

    allow_parser = sub.add_parser(
        'allowlist',
        help='List, add, remove, or initialize never-redact string allowlist',
        description=(
            f'Manage {ALLOWLIST_PATH} (name → rule). Rules may be exact strings, '
            f'globs (* ?), or CIDR networks (e.g. 10.0.0.0/8). Matching values '
            f'are never redacted. If the file is missing, built-in defaults apply '
            f'(localhost and RFC 5737 documentation IPs/CIDRs).'
        ),
    )
    allow_sub = allow_parser.add_subparsers(dest='allowlist_command', required=True)

    a_init = allow_sub.add_parser(
        'init',
        help=f'Write built-in allowlist to {ALLOWLIST_PATH}',
    )
    a_init.add_argument(
        '--force',
        action='store_true',
        help='Overwrite an existing allowlist file',
    )
    a_init.set_defaults(func=cmd_allowlist_init)

    a_list = allow_sub.add_parser(
        'list',
        help='Show effective allowlist (file if present, else built-ins)',
    )
    a_list.add_argument(
        '--yaml',
        action='store_true',
        help='Print allowlist as YAML',
    )
    a_list.set_defaults(func=cmd_allowlist_list)

    a_add = allow_sub.add_parser(
        'add',
        help='Add or update an allowlist string (seeds defaults if file missing)',
    )
    a_add.add_argument('name', help='Entry name (e.g. LOCALHOST_V4)')
    a_add.add_argument(
        'value',
        help='Exact string, glob (* ?), or CIDR that must never be redacted',
    )
    a_add.set_defaults(func=cmd_allowlist_add)

    a_remove = allow_sub.add_parser(
        'remove',
        help='Remove an allowlist entry from the config file',
    )
    a_remove.add_argument('name', help='Entry name to remove')
    a_remove.add_argument(
        '--ignore-missing',
        action='store_true',
        help='Do not error if the entry is not defined',
    )
    a_remove.set_defaults(func=cmd_allowlist_remove)

    parser.add_argument(
        'files',
        nargs='*',
        metavar='path',
        help=(
            'File(s) or directory(ies) to redact. Directories are walked '
            'recursively. Writes under redacted/ and updates dictionary.yaml '
            'unless --dry-run.'
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

    # Config management subcommands (must not treat file paths as subcommands)
    if head in ('patterns', 'exclude', 'allowlist'):
        args = parser.parse_args(argv)
        try:
            args.func(args)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            sys.exit(1)
        return

    # File redaction: parse flags manually so paths are not confused with subcommands.
    dry_run = False
    quiet = False
    verbose = False
    new_only = False
    files = []
    cli_excludes = []
    cli_includes = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ('-n', '--dry-run'):
            dry_run = True
            i += 1
        elif arg in ('-q', '--quiet'):
            quiet = True
            i += 1
        elif arg in ('-v', '--verbose'):
            verbose = True
            i += 1
        elif arg == '--new-only':
            new_only = True
            i += 1
        elif arg in ('-e', '--exclude'):
            if i + 1 >= len(argv):
                print(f"Option {arg} requires a glob argument.", file=sys.stderr)
                sys.exit(2)
            cli_excludes.append(argv[i + 1])
            i += 2
        elif arg.startswith('--exclude='):
            cli_excludes.append(arg.split('=', 1)[1])
            i += 1
        elif arg in ('-i', '--include'):
            if i + 1 >= len(argv):
                print(f"Option {arg} requires a glob argument.", file=sys.stderr)
                sys.exit(2)
            cli_includes.append(argv[i + 1])
            i += 2
        elif arg.startswith('--include='):
            cli_includes.append(arg.split('=', 1)[1])
            i += 1
        elif arg in ('-h', '--help'):
            parser.print_help()
            return
        elif arg in ('-V', '--version'):
            print_version()
            return
        elif arg.startswith('-'):
            print(f"Unknown option: {arg}", file=sys.stderr)
            parser.print_help()
            sys.exit(2)
        else:
            files.append(arg)
            i += 1

    if quiet and verbose:
        print("Cannot combine --quiet and --verbose.", file=sys.stderr)
        sys.exit(2)

    if not files:
        parser.print_help()
        sys.exit(1)
    redact_files(
        files,
        dry_run=dry_run,
        extra_excludes=cli_excludes,
        includes=cli_includes,
        quiet=quiet,
        verbose=verbose,
        new_only=new_only,
    )


if __name__ == "__main__":
    main()
