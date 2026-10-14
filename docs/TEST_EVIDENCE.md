# Test evidence

Last run: 14 October 2026. 50 automated tests, all passing.

## Automated suite

```
$ pytest -q
..................................................                [100%]
50 passed, 1 warning in 1.03s
```

| File | Tests | Covers |
| --- | --- | --- |
| `tests/test_scanner.py` | 20 | Detection, allowlisting, entropy, redaction |
| `tests/test_api.py` | 18 | Token enforcement, storage, Scan now, re-masking |
| `tests/test_self_scan.py` | 3 | The repository passes its own gate |
| `tests/test_dedupe.py` | 7 | One secret reports once; Gitleaks still covers missed lines |
| `tests/test_migration.py` | 2 | Scan history survives a schema change |

### A bug this caught

The first self-scan **failed**. Sample dummy keys were embedded in the dashboard UI
(`app/static/app.js`, `index.html`) and in the demo script, so SecretShield's own
pipeline would have gone red on the first push. The dummy values were moved into the
allowlisted `fixtures/` folder and the UI sample is now assembled from parts.
`tests/test_self_scan.py` keeps it from coming back.

## The eight acceptance tests from the SRS

| ID | Test | Expected | How it is checked | Result |
| --- | --- | --- | --- | --- |
| T-1 | Commit a clean file | Commit succeeds | `demo-blocked-commit.sh` step 1 | pass |
| T-2 | Commit a dummy API key | Blocked, with file, line and masked value | `demo-blocked-commit.sh` step 2 + `test_detects_aws_access_key` | pass |
| T-3 | Push with `--no-verify` | CI workflow fails | `demo-blocked-commit.sh` step 4 + the Actions run | pass |
| T-4 | Scan the documented fake AWS key | Allowlisted, no false alarm | `test_documented_placeholders_are_ignored` | pass |
| T-5 | Read every report and log | No full secret anywhere | `test_no_finding_contains_the_raw_secret` | pass |
| T-6 | Send a report without the token | Rejected with 401 | `test_report_without_a_token_is_rejected` | pass |
| T-7 | Fix with an environment variable | Hook passes, CI green, dashboard PASS | `demo-blocked-commit.sh` step 3 | pass |
| T-8 | Paste a fake key on Scan now | Finding appears at once | `test_scan_now_detects_a_dummy_key` | pass |

## Hook demo output

```
--- STEP 1: commit a clean file (expected: ALLOWED) ------------
SecretShield PASS no secrets found
RESULT: commit allowed, as expected.

--- STEP 2: commit a dummy API key (expected: BLOCKED) ---------

SecretShield SECRET DETECTED

  leak.py:1
    rule      aws-access-key  (Critical)
    value     AKIA************QZXK
    fix       Delete the key from the code and read it from an environment
              variable (AWS_ACCESS_KEY_ID). Deactivate and rotate the key in
              AWS IAM. If it was pushed, purge it from history with git filter-repo.

  leak.py:2
    rule      github-token  (Critical)
    value     ghp_********************************q7R8
    fix       Revoke the token in GitHub Settings > Developer settings, create a
              new one, and store it in an environment variable or GitHub Actions secret.

  Commit blocked. Remove the secret and commit again.

RESULT: commit blocked, as expected.

--- STEP 3: fix the leak and commit again (expected: ALLOWED) --
SecretShield PASS no secrets found
RESULT: commit allowed, as expected.

--- STEP 4: bypass with --no-verify (expected: ALLOWED locally) -
RESULT: the hook was skipped, so the commit went through locally.
        This is exactly what the CI gate catches on push.
```

## Detection report

Scanning the leaky fixture produced five findings across four severities.
The full JSON is in `docs/sample-report.json`.

| File | Line | Rule | Severity | Value |
| --- | --- | --- | --- | --- |
| `fixtures/leaky_config.py` | 8 | aws-access-key | Critical | `AKIA************QZXK` |
| `fixtures/leaky_config.py` | 9 | aws-secret-key | Critical | `Kp7x****...****Mx0W` |
| `fixtures/leaky_config.py` | 12 | github-token | Critical | `ghp_****...****q7R8` |
| `fixtures/leaky_config.py` | 15 | generic-api-key | High | `sk_t****...****0000` |
| `fixtures/leaky_config.py` | 18 | hardcoded-password | Low | `Supe*******123!` |

## Service endpoints

```
$ curl -s localhost:8000/health
{"status":"ok"}

$ curl -s -X POST localhost:8000/api/scan -d '{"text":"KEY=\"AKIA4SHIELDDEMO7QZXK\""}'
{"status":"FAIL","findings":[{"rule":"aws-access-key","severity":"Critical",
 "redacted_value":"AKIA************QZXK", ...}]}

$ curl -s -o /dev/null -w "%{http_code}" -X POST localhost:8000/api/reports -d '{...}'
401
```

## Failure handling

| Failure | Behaviour |
| --- | --- |
| Live service is down when CI runs | The gate result stands; the upload is skipped with a warning (`upload_report.py` always exits 0) |
| Gitleaks not installed | The built-in engine runs alone; a note is printed |
| Python missing on a developer machine | The hook skips with a message rather than blocking all work |
| A client posts an unmasked value | The API re-masks it before storage |
| `INGEST_TOKEN` not set on the server | `/api/reports` returns 503 and logs an error |
