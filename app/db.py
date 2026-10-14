"""SQLite storage for scans and their redacted findings."""
from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    repo          TEXT    NOT NULL,
    commit_sha    TEXT    NOT NULL,
    branch        TEXT    NOT NULL DEFAULT '',
    message       TEXT    NOT NULL DEFAULT '',
    status        TEXT    NOT NULL CHECK (status IN ('PASS', 'FAIL')),
    finding_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    file           TEXT,
    line           INTEGER,
    rule           TEXT,
    severity       TEXT,
    redacted_value TEXT,
    remediation    TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def db_path() -> str:
    return os.getenv("DB_PATH", "data/secretshield.db")


def migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the first deployment.

    A database created before `message` existed keeps its rows; the column is
    added with an empty default rather than dropping scan history.
    """
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
    if "message" not in columns:
        conn.execute("ALTER TABLE scans ADD COLUMN message TEXT NOT NULL DEFAULT ''")


def connect() -> sqlite3.Connection:
    path = db_path()
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    migrate(conn)
    conn.commit()
    return conn


def save_report(
    repo: str,
    commit: str,
    branch: str,
    status: str,
    findings: list[dict],
    message: str = "",
) -> int:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with closing(connect()) as conn, conn:
        cur = conn.execute(
            "INSERT INTO scans (timestamp, repo, commit_sha, branch, message, status, finding_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (timestamp, repo, commit, branch, message, status, len(findings)),
        )
        scan_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO findings (scan_id, file, line, rule, severity, redacted_value, remediation) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    scan_id,
                    f["file"],
                    f["line"],
                    f["rule"],
                    f["severity"],
                    f["redacted_value"],
                    f.get("remediation"),
                )
                for f in findings
            ],
        )
    return int(scan_id)


def list_reports(limit: int = 50) -> list[dict]:
    with closing(connect()) as conn:
        scans = [
            dict(row)
            for row in conn.execute(
                "SELECT id, timestamp, repo, commit_sha, branch, message, status, finding_count "
                "FROM scans ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        ]
        for scan in scans:
            scan["findings"] = [
                dict(row)
                for row in conn.execute(
                    "SELECT file, line, rule, severity, redacted_value, remediation "
                    "FROM findings WHERE scan_id = ? ORDER BY line, id",
                    (scan["id"],),
                )
            ]
    return scans
