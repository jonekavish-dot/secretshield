"""SecretShield scanning engine.

Finds secret-like values in text, masks them and attaches fix steps.
A finding NEVER contains the full secret: only a masked value.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath

SEVERITY_ORDER = {"Low": 1, "High": 2, "Critical": 3}
BLOCKING_SEVERITIES = {"High", "Critical"}

MAX_LINE_LENGTH = 5000
ALLOW_MARKER = "secretshield:allow"

# Values containing these hints are treated as obvious placeholders / documented fakes.
PLACEHOLDER_HINTS = ("example", "changeme", "placeholder", "your_", "your-", "xxxx", "${")

# Paths that hold deliberate dummy data (kept in sync with .gitleaks.toml).
ALLOWLISTED_DIRS = ("fixtures", "tests", "docs")
ALLOWLISTED_FILES = (".gitleaks.toml",)

DEFAULT_REMEDIATION = (
    "Remove the value from the code, load it from an environment variable, "
    "rotate the credential, and purge it from Git history if it was already pushed."
)

REMEDIATION = {
    "aws-access-key": (
        "Delete the key from the code and read it from an environment variable "
        "(AWS_ACCESS_KEY_ID). Deactivate and rotate the key in AWS IAM. "
        "If it was pushed, purge it from history with git filter-repo."
    ),
    "aws-secret-key": (
        "Remove the secret key, load it from an environment variable or AWS Secrets Manager, "
        "and rotate it in AWS IAM straight away."
    ),
    "github-token": (
        "Revoke the token in GitHub Settings > Developer settings, create a new one, "
        "and store it in an environment variable or GitHub Actions secret."
    ),
    "private-key": (
        "Remove the private key file from the repository, generate a new key pair, "
        "and keep the new private key outside Git."
    ),
    "stripe-live-key": "Roll the key in the Stripe dashboard and load the new one from an environment variable.",
    "slack-token": "Revoke the token in Slack, issue a new one, and keep it in an environment variable.",
    "secretshield-token": "Generate a new ingest token on the server and update the GitHub Actions secret.",
    "generic-api-key": (
        "Move the value to an environment variable, add its name (not the value) to .env.example, "
        "and rotate the key with the provider."
    ),
    "hardcoded-password": (
        "Do not keep passwords in code. Read it from an environment variable or a secrets manager."
    ),
}


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    pattern: re.Pattern
    group: int = 1
    min_entropy: float = 0.0


RULES: tuple[Rule, ...] = (
    Rule("aws-access-key", "Critical", re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b")),
    Rule(
        "aws-secret-key",
        "Critical",
        re.compile(r"(?i)aws.{0,30}?secret.{0,30}?['\"]([A-Za-z0-9/+=]{40})['\"]"),
    ),
    Rule("github-token", "Critical", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b")),
    Rule(
        "private-key",
        "Critical",
        re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)"),
    ),
    Rule("stripe-live-key", "Critical", re.compile(r"\b(sk_live_[A-Za-z0-9]{16,})\b")),
    Rule("slack-token", "High", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b")),
    Rule("secretshield-token", "High", re.compile(r"\b(sshield_[a-f0-9]{32})\b")),
    Rule(
        "generic-api-key",
        "High",
        re.compile(
            r"(?i)\b(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)\b"
            r"\s*[:=]\s*['\"]([A-Za-z0-9_\-/+=]{16,})['\"]"
        ),
        min_entropy=3.0,
    ),
    Rule(
        "hardcoded-password",
        "Low",
        re.compile(r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]"),
    ),
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def redact(value: str) -> str:
    """Mask a secret, keeping at most the first 4 and last 4 characters."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def ensure_redacted(value: str) -> str:
    """Make sure a client-supplied value is masked; re-mask it if it is not."""
    value = (value or "")[:64]
    visible = sum(1 for ch in value if ch != "*")
    if "*" in value and visible <= 8:
        return value
    return redact(value)


def remediation_for(rule_id: str) -> str:
    return REMEDIATION.get(rule_id, DEFAULT_REMEDIATION)


def severity_for_rule(rule_id: str) -> str:
    """Severity for rule ids that come from Gitleaks (which has no severity of its own)."""
    rid = (rule_id or "").lower()
    if any(k in rid for k in ("aws", "private-key", "github", "gitlab", "stripe", "gcp", "azure")):
        return "Critical"
    return "High"


def is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


def is_allowlisted_path(path: str) -> bool:
    norm = path.replace("\\", "/").removeprefix("./")
    posix = PurePosixPath(norm)
    if posix.parts and posix.parts[0] in ALLOWLISTED_DIRS:
        return True
    return posix.name in ALLOWLISTED_FILES


def scan_text(text: str, filename: str = "input") -> list[dict]:
    """Return findings for a block of text. No finding holds the full secret."""
    best: dict[tuple[int, str], dict] = {}
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line[:MAX_LINE_LENGTH]
        if ALLOW_MARKER in line:
            continue
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                value = match.group(rule.group)
                if is_placeholder(value):
                    continue
                if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
                    continue
                finding = {
                    "file": filename,
                    "line": lineno,
                    "rule": rule.id,
                    "severity": rule.severity,
                    "redacted_value": redact(value),
                    "remediation": remediation_for(rule.id),
                }
                key = (lineno, value)
                current = best.get(key)
                if current is None or SEVERITY_ORDER[rule.severity] > SEVERITY_ORDER[current["severity"]]:
                    best[key] = finding
    return sorted(best.values(), key=lambda f: (f["line"], f["rule"]))


def summarize(findings: list[dict]) -> str:
    """FAIL if any finding is Critical or High; Low findings only warn."""
    return "FAIL" if any(f["severity"] in BLOCKING_SEVERITIES for f in findings) else "PASS"
