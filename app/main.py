"""SecretShield web service: report ingest API, Scan now API and dashboard."""
from __future__ import annotations

import hmac
import logging
import os
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import db
from .scanner import (
    SEVERITY_ORDER,
    ensure_redacted,
    remediation_for,
    scan_text,
    summarize,
)

STATIC_DIR = Path(__file__).parent / "static"


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("secretshield")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    logger.addHandler(stream)
    log_path = os.getenv("LOG_PATH", "logs/secretshield.log")
    try:
        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
    except OSError:
        logger.warning("Log file %s is not writable; logging to console only", log_path)
    return logger


log = setup_logging()

app = FastAPI(title="SecretShield", version="1.0.0")


class FindingIn(BaseModel):
    """A finding as uploaded by CI. Unknown fields (for example a raw secret) are dropped."""

    file: str = Field(max_length=500)
    line: int = Field(ge=0)
    rule: str = Field(max_length=100)
    severity: str = Field(max_length=20)
    redacted_value: str = Field(max_length=200)
    remediation: str | None = Field(default=None, max_length=1000)


class ReportIn(BaseModel):
    repo: str = Field(max_length=200)
    commit: str = Field(max_length=64)
    branch: str = Field(default="", max_length=200)
    findings: list[FindingIn] = Field(default_factory=list, max_length=500)


class ScanIn(BaseModel):
    text: str = Field(max_length=200_000)
    filename: str = Field(default="pasted-text", max_length=200)


def check_token(token: str | None) -> None:
    expected = os.getenv("INGEST_TOKEN", "")
    if not expected:
        log.error("Report rejected: INGEST_TOKEN is not configured on the server")
        raise HTTPException(status_code=503, detail="Ingest token is not configured")
    if not token or not hmac.compare_digest(token.encode(), expected.encode()):
        log.warning("Report rejected: missing or invalid token")
        raise HTTPException(status_code=401, detail="Invalid or missing token")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/reports", status_code=201)
def ingest_report(report: ReportIn, x_ingest_token: str | None = Header(default=None)) -> dict:
    check_token(x_ingest_token)
    findings = []
    for item in report.findings:
        data = item.model_dump()
        if data["severity"] not in SEVERITY_ORDER:
            data["severity"] = "High"
        data["redacted_value"] = ensure_redacted(data["redacted_value"])
        data["remediation"] = data["remediation"] or remediation_for(data["rule"])
        findings.append(data)
    status = summarize(findings)
    scan_id = db.save_report(report.repo, report.commit, report.branch, status, findings)
    log.info(
        "Report stored: scan=%s repo=%s commit=%s status=%s findings=%d",
        scan_id,
        report.repo,
        report.commit[:7],
        status,
        len(findings),
    )
    return {"scan_id": scan_id, "status": status, "findings": len(findings)}


@app.get("/api/reports")
def list_reports(limit: int = 50) -> list[dict]:
    return db.list_reports(max(1, min(limit, 200)))


@app.post("/api/scan")
def scan_now(body: ScanIn) -> JSONResponse:
    """Scan pasted text. The text is never stored or logged."""
    findings = scan_text(body.text, body.filename)
    status = summarize(findings)
    log.info("Scan now: status=%s findings=%d", status, len(findings))
    return JSONResponse(
        {"status": status, "findings": findings},
        headers={"Cache-Control": "no-store"},
    )


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
