"""A database created before `message` existed must keep its scan history.

The server already holds real scans from the demo, so adding a column must
migrate rather than reset.
"""
import importlib
import sqlite3

OLD_SCHEMA = """
CREATE TABLE scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    repo          TEXT    NOT NULL,
    commit_sha    TEXT    NOT NULL,
    branch        TEXT    NOT NULL DEFAULT '',
    status        TEXT    NOT NULL CHECK (status IN ('PASS', 'FAIL')),
    finding_count INTEGER NOT NULL DEFAULT 0
);
"""


def test_existing_rows_survive_the_message_column_being_added(tmp_path, monkeypatch):
    path = tmp_path / "old.db"

    # A database as it existed before this change, with one scan in it.
    old = sqlite3.connect(path)
    old.executescript(OLD_SCHEMA)
    old.execute(
        "INSERT INTO scans (timestamp, repo, commit_sha, branch, status, finding_count) "
        "VALUES ('2026-10-14T06:00:00+00:00', 'jonekavish-dot/secretshield', 'f94efd8', "
        "'main', 'PASS', 0)"
    )
    old.commit()
    old.close()

    monkeypatch.setenv("DB_PATH", str(path))
    from app import db
    importlib.reload(db)

    reports = db.list_reports()
    assert len(reports) == 1, "the existing scan was lost"
    assert reports[0]["commit_sha"] == "f94efd8"
    assert reports[0]["message"] == ""

    # And new rows can carry a message.
    db.save_report("jonekavish-dot/secretshield", "abc1234", "main", "PASS", [], "fix the dashboard")
    newest = db.list_reports()[0]
    assert newest["message"] == "fix the dashboard"
    assert len(db.list_reports()) == 2


def test_migration_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "fresh.db"))
    from app import db
    importlib.reload(db)
    db.save_report("r", "c", "main", "PASS", [], "first")
    db.save_report("r", "c", "main", "PASS", [], "second")
    assert len(db.list_reports()) == 2
