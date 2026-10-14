"""The repository must pass its own gate.

A project that ships a secret scanner cannot be the project whose own pipeline
fails on day one. This caught a real bug: sample keys embedded in the dashboard
UI and the demo script.
"""
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_the_repository_passes_its_own_scan():
    result = subprocess.run(
        [sys.executable, "scripts/secretshield_scan.py", "--all"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        "SecretShield's own repository failed its own scan:\n" + result.stdout
    )


def test_the_demo_fixture_is_still_detected():
    """The demo relies on fixtures/demo_leak.py being flagged when forced."""
    result = subprocess.run(
        [sys.executable, "scripts/secretshield_scan.py",
         "--paths", "fixtures/demo_leak.py", "--force"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "aws-access-key" in result.stdout
    assert "github-token" in result.stdout


def test_no_env_file_is_committed():
    assert not (REPO / ".env").exists() or ".env" in (REPO / ".gitignore").read_text()
