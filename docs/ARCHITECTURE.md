# Architecture

## The three gates

```
                        DEVELOPER'S LAPTOP
  ┌──────────────────────────────────────────────────────────────┐
  │   git commit                                                 │
  │        │                                                     │
  │        ▼                                                     │
  │   ┌─────────────────────────────┐                            │
  │   │ GATE 1  pre-commit hook     │  secret found              │
  │   │ scripts/secretshield_scan   ├──────────────► COMMIT      │
  │   │ --staged                    │                BLOCKED     │
  │   └──────────────┬──────────────┘                            │
  │                  │ clean                                     │
  │                  ▼                                           │
  │              git push                                        │
  └──────────────────┼───────────────────────────────────────────┘
                     │
                     ▼
                         GITHUB
  ┌──────────────────────────────────────────────────────────────┐
  │   ┌─────────────────────────────┐                            │
  │   │ GATE 2  GitHub Actions      │  secret found              │
  │   │ gitleaks + built-in engine  ├──────────────► PIPELINE    │
  │   │ scan --all --json           │                FAILS       │
  │   └──────────────┬──────────────┘                            │
  │                  │ POST /api/reports                         │
  │                  │ X-Ingest-Token (Actions secret)           │
  └──────────────────┼───────────────────────────────────────────┘
                     │  redacted JSON only
                     ▼
                    AWS EC2  (Docker Compose)
  ┌──────────────────────────────────────────────────────────────┐
  │   ┌────────────┐      ┌──────────────────┐     ┌──────────┐  │
  │   │  Nginx :80 │─────►│  FastAPI :8000   │────►│  SQLite  │  │
  │   │  proxy     │      │  GATE 3 service  │     │  volume  │  │
  │   └────────────┘      └──────────────────┘     └──────────┘  │
  │          ▲                     │                             │
  │          │                     ├── /          dashboard      │
  │          │                     ├── /api/scan  Scan now       │
  │          │                     └── /health                   │
  └──────────┼───────────────────────────────────────────────────┘
             │
       judges, team  (public internet)
```

## Why three gates

| Gate | Catches | Can it be skipped? |
| --- | --- | --- |
| Pre-commit hook | A secret before it ever enters Git history | Yes, with `git commit --no-verify` |
| CI gate | Anything that reached GitHub, including bypassed hooks | No: it runs on GitHub, not the laptop |
| Live service | Nothing by itself; it records and displays | Not a gate for the repo, it is the evidence trail |

The hook is fast and friendly. The CI gate is the one that actually enforces.

## Request paths

| Path | Method | Caller | Auth | Notes |
| --- | --- | --- | --- | --- |
| `/api/reports` | POST | GitHub Actions | `X-Ingest-Token` | Stores a redacted report |
| `/api/reports` | GET | Dashboard | none | Read-only history |
| `/api/scan` | POST | Scan now page | none | In-memory only, `Cache-Control: no-store` |
| `/health` | GET | Monitoring, judges | none | Container health check |

## Data model

```
scans                                findings
  id              INTEGER PK           id              INTEGER PK
  timestamp       TEXT (UTC ISO)       scan_id         INTEGER FK → scans.id
  repo            TEXT                 file            TEXT
  commit_sha      TEXT                 line            INTEGER
  branch          TEXT                 rule            TEXT
  status          PASS | FAIL          severity        Critical | High | Low
  finding_count   INTEGER              redacted_value  TEXT  ← masked, always
                                       remediation     TEXT
```

No table has a column for a raw secret. There is nowhere to put one.

## The scanning engine

Two engines run and their findings are merged and de-duplicated by
`(file, line, rule)`:

1. **Gitleaks** with `.gitleaks.toml`, run with `--redact` so its output is masked
   before it reaches us. This is the industry-standard scanner the problem asks for.
2. **A built-in Python engine** (`app/scanner.py`) with nine rules. It means the gate
   still works on a machine without Gitleaks installed, and it is what powers the
   Scan now page and the unit tests.

### Rules

| Rule | Severity | Blocks? |
| --- | --- | --- |
| `aws-access-key` | Critical | yes |
| `aws-secret-key` | Critical | yes |
| `github-token` | Critical | yes |
| `private-key` | Critical | yes |
| `stripe-live-key` | Critical | yes |
| `slack-token` | High | yes |
| `secretshield-token` | High | yes |
| `generic-api-key` (entropy ≥ 3.0) | High | yes |
| `hardcoded-password` | Low | warns only |

### Keeping false alarms down

- **Entropy check.** `api_key = "aaaaaaaaaaaaaaaa"` is not flagged; a random-looking
  string of the same length is.
- **Placeholder hints.** Values containing `example`, `changeme`, `placeholder`,
  `your_`, `xxxx` or `${...}` are skipped.
- **Path allowlist.** `fixtures/`, `tests/`, `docs/`, `.env.example` and
  `.gitleaks.toml` hold deliberate dummy data and are not scanned in normal runs.
  `--force` overrides this for the demo.
- **Line marker.** A line ending in `# secretshield:allow` is skipped, for the rare
  true exception.

## Redaction

`redact()` keeps the first four and last four characters and masks the middle:
`AKIA4SHIELDDEMO7QZXK` becomes `AKIA************QZXK`. Values of eight characters or
fewer are masked completely.

The API re-masks on the way in as well (`ensure_redacted`). If a modified client
posted a raw secret to `/api/reports`, the service would mask it before storage.
A test asserts this.
