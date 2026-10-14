#!/usr/bin/env python3
"""Upload a SecretShield JSON report to the live service.

Used by CI. A failure to upload never changes the gate's own result (NFR-5):
this script always exits 0 and only prints a warning.

Usage: upload_report.py report.json
Environment: SECRETSHIELD_URL, SECRETSHIELD_TOKEN
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

TIMEOUT = 15


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: upload_report.py <report.json>")
        return 0

    base = (os.getenv("SECRETSHIELD_URL") or "").rstrip("/")
    token = os.getenv("SECRETSHIELD_TOKEN") or ""
    if not base or not token:
        print("SecretShield: no service URL or token set; skipping the upload.")
        return 0

    try:
        report = json.loads(open(sys.argv[1], encoding="utf-8").read())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"SecretShield: could not read the report ({exc}); skipping the upload.")
        return 0

    # Send only the redacted fields the API accepts.
    payload = {
        "repo": report.get("repo", ""),
        "commit": report.get("commit", ""),
        "branch": report.get("branch", ""),
        "message": report.get("message", ""),
        "findings": [
            {
                "file": f.get("file", ""),
                "line": int(f.get("line", 0) or 0),
                "rule": f.get("rule", ""),
                "severity": f.get("severity", "High"),
                "redacted_value": f.get("redacted_value", "********"),
                "remediation": f.get("remediation"),
            }
            for f in report.get("findings", [])
        ],
    }

    request = urllib.request.Request(
        f"{base}/api/reports",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-Ingest-Token": token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            body = json.loads(response.read().decode() or "{}")
        print(f"SecretShield: report uploaded (scan {body.get('scan_id')}, {body.get('status')}).")
    except urllib.error.HTTPError as exc:
        print(f"SecretShield: the service rejected the report (HTTP {exc.code}). The gate result stands.")
    except Exception as exc:  # noqa: BLE001 - never fail the build on an upload problem
        print(f"SecretShield: could not reach the service ({exc}). The gate result stands.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
