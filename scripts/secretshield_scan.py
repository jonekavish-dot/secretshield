#!/usr/bin/env python3
"""SecretShield scan command: used by the pre-commit hook and by CI.

Modes
  --staged          scan files staged for commit (pre-commit hook)
  --all             scan every tracked file in the working tree (CI)
  --paths A B C     scan the given paths

It runs Gitleaks when the binary is available and always runs the built-in
engine, so the gate still works on a machine without Gitleaks installed.

Exit codes: 0 = clean or warnings only, 1 = Critical/High finding, 2 = usage error.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scanner import (  # noqa: E402
    ensure_redacted,
    is_allowlisted_path,
    remediation_for,
    scan_text,
    severity_for_rule,
    summarize,
)

BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".whl", ".so", ".dylib", ".dll", ".exe", ".woff", ".woff2", ".ttf",
    ".otf", ".mp4", ".mp3", ".db", ".sqlite", ".sqlite3",
}
MAX_FILE_BYTES = 2_000_000

RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
BOLD = "\033[1m"
OFF = "\033[0m"


def colour(text: str, code: str) -> str:
    if os.getenv("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"{code}{text}{OFF}"


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=False
    )
    return result.stdout if result.returncode == 0 else ""


def staged_files() -> list[str]:
    out = git("diff", "--cached", "--name-only", "--diff-filter=ACMR")
    return [line.strip() for line in out.splitlines() if line.strip()]


def tracked_files() -> list[str]:
    out = git("ls-files")
    return [line.strip() for line in out.splitlines() if line.strip()]


def scannable(path: str, ignore_allowlist: bool = False) -> bool:
    p = Path(path)
    if not p.is_file():
        return False
    if p.suffix.lower() in BINARY_SUFFIXES:
        return False
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            return False
    except OSError:
        return False
    return ignore_allowlist or not is_allowlisted_path(path)


def read_text(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def run_gitleaks(paths: list[str], ignore_allowlist: bool = False) -> list[dict]:
    """Run Gitleaks over the given paths; return findings, or [] if unavailable."""
    binary = shutil.which("gitleaks")
    if not binary or not paths:
        return []
    repo_root = Path(__file__).resolve().parent.parent
    config = repo_root / ".gitleaks.toml"
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "gitleaks.json"
        cmd = [binary, "detect", "--no-git", "--redact", "--report-format", "json",
               "--report-path", str(report), "--exit-code", "0"]
        if config.exists():
            cmd += ["--config", str(config)]
        cmd += ["--source", "."]
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=180)
        except (OSError, subprocess.SubprocessError) as exc:
            print(colour(f"note: Gitleaks could not run ({exc}); using the built-in engine", YELLOW))
            return []
        if not report.exists():
            return []
        try:
            raw = json.loads(report.read_text() or "[]")
        except (OSError, json.JSONDecodeError):
            return []

    wanted = {str(Path(p)) for p in paths}
    findings = []
    for item in raw or []:
        rel = str(Path(str(item.get("File", "")).removeprefix("./")))
        if rel not in wanted or (not ignore_allowlist and is_allowlisted_path(rel)):
            continue
        rule = str(item.get("RuleID", "gitleaks"))
        findings.append({
            "file": rel,
            "line": int(item.get("StartLine", 0) or 0),
            "rule": rule,
            "severity": severity_for_rule(rule),
            # Gitleaks runs with --redact, so Secret is already masked; re-mask defensively.
            "redacted_value": ensure_redacted(str(item.get("Secret", "")) or "********"),
            "remediation": remediation_for(rule),
            "engine": "gitleaks",
        })
    return findings


def dedupe(findings: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for f in findings:
        key = (f["file"], f["line"], f["rule"])
        seen.setdefault(key, f)
    return sorted(seen.values(), key=lambda f: (f["file"], f["line"], f["rule"]))


def scan_paths(paths: list[str], ignore_allowlist: bool = False) -> list[dict]:
    targets = [p for p in paths if scannable(p, ignore_allowlist)]
    findings: list[dict] = list(run_gitleaks(targets, ignore_allowlist))
    for path in targets:
        text = read_text(path)
        if text is None:
            continue
        for finding in scan_text(text, path):
            finding["engine"] = "builtin"
            findings.append(finding)
    return dedupe(findings)


def print_report(findings: list[dict], status: str) -> None:
    banner = colour("SecretShield", BOLD)
    if not findings:
        print(f"{banner} {colour('PASS', GREEN)} no secrets found")
        return

    word = colour("SECRET DETECTED", RED) if status == "FAIL" else colour("WARNING", YELLOW)
    print(f"\n{banner} {word}\n")
    for f in findings:
        tone = RED if f["severity"] in ("Critical", "High") else YELLOW
        print(f"  {colour(f['file'] + ':' + str(f['line']), BOLD)}")
        print(f"    rule      {f['rule']}  ({colour(f['severity'], tone)})")
        print(f"    value     {f['redacted_value']}")
        print(f"    fix       {f.get('remediation', '')}")
        print()
    if status == "FAIL":
        print(colour("  Commit blocked. Remove the secret and commit again.", RED))
        print("  Need to bypass in an emergency? git commit --no-verify  (CI will still fail)\n")
    else:
        print(colour("  Low-severity findings only: not blocking.\n", YELLOW))


def main() -> int:
    parser = argparse.ArgumentParser(description="SecretShield scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--staged", action="store_true", help="scan staged files")
    group.add_argument("--all", action="store_true", help="scan all tracked files")
    group.add_argument("--paths", nargs="+", help="scan the given paths")
    parser.add_argument("--json", dest="json_out", help="write a JSON report to this path")
    parser.add_argument("--quiet", action="store_true", help="suppress the text report")
    parser.add_argument(
        "--force",
        action="store_true",
        help="scan even allowlisted paths such as fixtures/ (used by the demo)",
    )
    args = parser.parse_args()

    if args.staged:
        paths = staged_files()
    elif args.all:
        paths = tracked_files()
    else:
        paths = args.paths

    findings = scan_paths(paths, ignore_allowlist=args.force)
    status = summarize(findings)

    if not args.quiet:
        print_report(findings, status)

    if args.json_out:
        report = {
            "status": status,
            "repo": os.getenv("GITHUB_REPOSITORY", ""),
            "commit": os.getenv("GITHUB_SHA", git("rev-parse", "HEAD").strip()),
            "branch": os.getenv("GITHUB_REF_NAME", git("rev-parse", "--abbrev-ref", "HEAD").strip()),
            "scanned_files": len(paths),
            "findings": findings,
        }
        out = Path(args.json_out)
        if out.parent != Path(""):
            out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2))
        if not args.quiet:
            print(f"  Report written to {out}\n")

    return 1 if status == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
