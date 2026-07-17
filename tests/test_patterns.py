"""Pattern matching for sensitive values in redact."""

import re

import pytest


@pytest.mark.parametrize(
    "text, expected",
    [
        ("host 192.168.1.1 is up", ["192.168.1.1"]),
        ("no ip here", []),
        ("10.0.0.1 and 8.8.8.8", ["10.0.0.1", "8.8.8.8"]),
    ],
)
def test_ip_pattern(redact_mod, text, expected):
    assert sorted(re.findall(redact_mod.DEFAULT_PATTERNS["IP"], text)) == sorted(expected)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("mail me at alice@example.com please", ["alice@example.com"]),
        ("user.name+tag@sub.domain.org", ["user.name+tag@sub.domain.org"]),
        ("not an email", []),
    ],
)
def test_email_pattern(redact_mod, text, expected):
    assert re.findall(redact_mod.DEFAULT_PATTERNS["EMAIL"], text) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("API_KEY=abc123-def", ["abc123-def"]),
        ("API_KEY=secret_value_99", ["secret_value_99"]),
        ("api_key=lowercase_ignored", []),
        ("no key here", []),
    ],
)
def test_apikey_pattern(redact_mod, text, expected):
    assert re.findall(redact_mod.DEFAULT_PATTERNS["APIKEY"], text) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("TOKEN=tok_abc123", ["tok_abc123"]),
        ("TOKEN=xyz", ["xyz"]),
        ("token=ignored", []),
    ],
)
def test_token_pattern(redact_mod, text, expected):
    assert re.findall(redact_mod.DEFAULT_PATTERNS["TOKEN"], text) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("PASSWORD=s3cret!", ["s3cret!"]),
        ("PASSWORD=has spaces? no", ["has"]),
        ("password=ignored", []),
    ],
)
def test_password_pattern(redact_mod, text, expected):
    assert re.findall(redact_mod.DEFAULT_PATTERNS["PASSWORD"], text) == expected


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
    assert re.findall(redact_mod.DEFAULT_PATTERNS["GOV"], text) == expected


def test_email_matches_full_address_including_gov(redact_mod):
    text = "contact user@agency.gov for help"
    emails = re.findall(redact_mod.DEFAULT_PATTERNS["EMAIL"], text)
    assert emails == ["user@agency.gov"]
