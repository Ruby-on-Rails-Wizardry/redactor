"""Pattern matching for sensitive values in redact."""

import re

import pytest


@pytest.mark.parametrize(
    "text, expected",
    [
        ("host 192.168.1.1 is up", ["192.168.1.1"]),
        ("no ip here", []),
        ("10.0.0.1 and 8.8.8.8", ["10.0.0.1", "8.8.8.8"]),
        ("invalid 999.999.999.999 ignored", []),
        ("almost 256.1.1.1 and 1.2.3.4", ["1.2.3.4"]),
        ("0.0.0.0 and 255.255.255.255", ["0.0.0.0", "255.255.255.255"]),
    ],
)
def test_ip_pattern(redact_mod, text, expected):
    assert sorted(
        redact_mod.extract_match_values(redact_mod.DEFAULT_PATTERNS["IP"], text)
    ) == sorted(expected)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("loop ::1 ok", ["::1"]),
        ("full 2001:0db8:85a3:0000:0000:8a2e:0370:7334 x", [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ]),
        ("compressed 2001:db8::1 end", ["2001:db8::1"]),
    ],
)
def test_ip6_pattern(redact_mod, text, expected):
    got = list(redact_mod.extract_match_values(redact_mod.DEFAULT_PATTERNS["IP6"], text))
    for exp in expected:
        assert exp in got


@pytest.mark.parametrize(
    "text, expected",
    [
        ("mail me at alice@example.com please", ["alice@example.com"]),
        ("user.name+tag@sub.domain.org", ["user.name+tag@sub.domain.org"]),
        ("not an email", []),
    ],
)
def test_email_pattern(redact_mod, text, expected):
    assert list(
        redact_mod.extract_match_values(redact_mod.DEFAULT_PATTERNS["EMAIL"], text)
    ) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("API_KEY=abc123-def", ["abc123-def"]),
        ("API_KEY=secret_value_99", ["secret_value_99"]),
        ("api_key: supersecretvalue", ["supersecretvalue"]),
        ("apiKey = 'quoted-key-ok'", ["quoted-key-ok"]),
        ('API_KEY: "json-style-key"', ["json-style-key"]),
        ("API_KEY=short", []),  # too short (< 8 unquoted)
        ("api_key=lowercase_long_enough", ["lowercase_long_enough"]),
        ("no key here", []),
    ],
)
def test_apikey_pattern(redact_mod, text, expected):
    assert list(
        redact_mod.extract_match_values(redact_mod.DEFAULT_PATTERNS["APIKEY"], text)
    ) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("TOKEN=tok_abc123", ["tok_abc123"]),
        ("TOKEN=abcdef", ["abcdef"]),
        ("access_token: bearer-value", ["bearer-value"]),
        ("TOKEN=xyz", []),  # too short (< 6)
        ("token=longenough", ["longenough"]),  # case-insensitive TOKEN
        ("TOKEN=longenough", ["longenough"]),
    ],
)
def test_token_pattern(redact_mod, text, expected):
    assert list(
        redact_mod.extract_match_values(redact_mod.DEFAULT_PATTERNS["TOKEN"], text)
    ) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("PASSWORD=s3cret!", ["s3cret!"]),
        ("PASSWORD=has spaces? no", []),  # "has" is too short
        ('PASSWORD="quoted secret"', ["quoted secret"]),
        ("db_password: hunter2", ["hunter2"]),
        ("PASSWORD=ab", []),  # too short
        ("password=longenough", ["longenough"]),
    ],
)
def test_password_pattern(redact_mod, text, expected):
    assert list(
        redact_mod.extract_match_values(redact_mod.DEFAULT_PATTERNS["PASSWORD"], text)
    ) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("Visit cdc.gov today", ["cdc.gov"]),
        ("https://www.fda.gov/path", ["www.fda.gov"]),
        ("sub.agency.example.gov", ["sub.agency.example.gov"]),
        ("my-agency.gov", ["my-agency.gov"]),
        ("gov alone", []),
        (".gov", []),
    ],
)
def test_gov_pattern(redact_mod, text, expected):
    assert list(
        redact_mod.extract_match_values(redact_mod.DEFAULT_PATTERNS["GOV"], text)
    ) == expected


def test_email_matches_full_address_including_gov(redact_mod):
    text = "contact user@agency.gov for help"
    emails = list(
        redact_mod.extract_match_values(redact_mod.DEFAULT_PATTERNS["EMAIL"], text)
    )
    assert emails == ["user@agency.gov"]


def test_awskey_pattern(redact_mod):
    text = "key=AKIAIOSFODNN7EXAMPLE and noise"
    assert list(
        redact_mod.extract_match_values(redact_mod.DEFAULT_PATTERNS["AWSKEY"], text)
    ) == ["AKIAIOSFODNN7EXAMPLE"]


def test_jwt_pattern(redact_mod):
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "signaturepartgoeshere01"
    )
    text = f"auth={jwt}"
    assert list(
        redact_mod.extract_match_values(redact_mod.DEFAULT_PATTERNS["JWT"], text)
    ) == [jwt]


def test_bearer_pattern(redact_mod):
    text = "Authorization: Bearer ghp_exampleTokenValue99"
    assert list(
        redact_mod.extract_match_values(redact_mod.DEFAULT_PATTERNS["BEARER"], text)
    ) == ["ghp_exampleTokenValue99"]


def test_pem_pattern(redact_mod):
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PZGFwO\n"
        "-----END RSA PRIVATE KEY-----"
    )
    text = f"key material\n{pem}\ntrailing"
    got = list(redact_mod.extract_match_values(redact_mod.DEFAULT_PATTERNS["PEM"], text))
    assert len(got) == 1
    assert got[0].startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert got[0].endswith("-----END RSA PRIVATE KEY-----")


def test_allowlist_skips_localhost(redact_mod):
    content = "a=127.0.0.1 b=8.8.8.8"
    matches = redact_mod.collect_matches(
        content,
        {"IP": redact_mod.DEFAULT_PATTERNS["IP"]},
        allowlist=redact_mod.allowlist_values(redact_mod.DEFAULT_ALLOWLIST),
    )
    assert matches == [("IP", "8.8.8.8")]
