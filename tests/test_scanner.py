"""Tests for the SecretShield scanning engine.

Covers T-2 (detection), T-4 (no false alarm on documented fakes) and
T-5 (nothing in a finding holds a full secret).
"""
from pathlib import Path

import pytest

from app.scanner import (
    BLOCKING_SEVERITIES,
    is_allowlisted_path,
    redact,
    scan_text,
    shannon_entropy,
    summarize,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# Fake values, invented for tests. They authenticate nothing.
FAKE_AWS_KEY = "AKIA4SHIELDDEMO7QZXK"
FAKE_GH_TOKEN = "ghp_1A2b3C4d5E6f7G8h9I0jK1L2m3N4o5P6q7R8"


# --- T-2: detection ---------------------------------------------------------

def test_detects_aws_access_key():
    findings = scan_text(f'AWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY}"', "config.py")
    assert len(findings) == 1
    assert findings[0]["rule"] == "aws-access-key"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["file"] == "config.py"
    assert findings[0]["line"] == 1


def test_detects_github_token():
    findings = scan_text(f'token = "{FAKE_GH_TOKEN}"')
    assert any(f["rule"] == "github-token" for f in findings)


def test_detects_private_key_header():
    findings = scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n")
    assert any(f["rule"] == "private-key" for f in findings)


def test_reports_the_correct_line_number():
    text = "\n".join(["import os", "", f'KEY = "{FAKE_AWS_KEY}"', "print(KEY)"])
    findings = scan_text(text, "src/app.py")
    assert findings[0]["line"] == 3


def test_blocking_status_for_a_critical_finding():
    findings = scan_text(f'KEY = "{FAKE_AWS_KEY}"')
    assert summarize(findings) == "FAIL"


def test_low_severity_only_warns():
    findings = scan_text('password = "letmein99"')
    assert findings and all(f["severity"] == "Low" for f in findings)
    assert summarize(findings) == "PASS"


def test_leaky_fixture_is_flagged():
    findings = scan_text((FIXTURES / "leaky_config.py").read_text(), "fixtures/leaky_config.py")
    rules = {f["rule"] for f in findings}
    assert "aws-access-key" in rules
    assert "github-token" in rules
    assert summarize(findings) == "FAIL"


# --- T-4: no false alarms ---------------------------------------------------

def test_clean_code_passes():
    findings = scan_text((FIXTURES / "safe_config.py").read_text(), "fixtures/safe_config.py")
    assert findings == []
    assert summarize(findings) == "PASS"


@pytest.mark.parametrize(
    "line",
    [
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',   # AWS's published example
        'API_KEY = "your_api_key_here"',
        'TOKEN = "changeme"',
        'URL = "postgres://${DB_USER}:${DB_PASSWORD}@host/db"',
    ],
)
def test_documented_placeholders_are_ignored(line):
    assert scan_text(line) == []


def test_allow_marker_skips_a_line():
    assert scan_text(f'KEY = "{FAKE_AWS_KEY}"  # secretshield:allow') == []


def test_low_entropy_value_is_not_a_generic_key():
    assert scan_text('api_key = "aaaaaaaaaaaaaaaaaa"') == []


def test_fixture_and_test_paths_are_allowlisted():
    assert is_allowlisted_path("fixtures/leaky_config.py")
    assert is_allowlisted_path("tests/test_scanner.py")
    assert is_allowlisted_path("./docs/guide.md")
    assert not is_allowlisted_path("src/config.py")
    assert not is_allowlisted_path("app/main.py")


# --- T-5: redaction ---------------------------------------------------------

def test_redact_keeps_only_the_edges():
    masked = redact(FAKE_AWS_KEY)
    assert masked.startswith("AKIA")
    assert masked.endswith(FAKE_AWS_KEY[-4:])
    assert "*" in masked
    assert FAKE_AWS_KEY not in masked


def test_short_values_are_fully_masked():
    assert redact("abc123") == "******"


def test_no_finding_contains_the_raw_secret():
    text = f'AWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY}"\nGITHUB_TOKEN = "{FAKE_GH_TOKEN}"'
    findings = scan_text(text, "config.py")
    assert findings
    blob = repr(findings)
    assert FAKE_AWS_KEY not in blob
    assert FAKE_GH_TOKEN not in blob


def test_every_finding_carries_fix_steps():
    findings = scan_text(f'KEY = "{FAKE_AWS_KEY}"')
    assert all(f["remediation"] for f in findings)


# --- engine details ---------------------------------------------------------

def test_entropy_separates_random_from_repetitive():
    assert shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0
    assert shannon_entropy("Kp7xQm2LvR9tNw4Z") > 3.0


def test_severities_are_known_values():
    findings = scan_text(f'KEY = "{FAKE_AWS_KEY}"\npassword = "hunter2pass"')
    assert all(f["severity"] in {"Critical", "High", "Low"} for f in findings)
    assert BLOCKING_SEVERITIES == {"High", "Critical"}


def test_duplicate_matches_are_reported_once():
    findings = scan_text(f'a = "{FAKE_AWS_KEY}"')
    assert len(findings) == 1
