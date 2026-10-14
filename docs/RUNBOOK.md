# Execution runbook

The single ordered plan: who does what, when. Tick as you go.

## The team

| Role | Owns | GitHub |
| --- | --- | --- |
| **Lead + DevOps** — Kavish | AWS account, EC2, Docker, Nginx, CI workflow, deployment | `jonekavish-dot` |
| **Backend** — Gowshik | Scanner engine, API, database, unit tests | `gowshikgunal22` |
| **Frontend + docs** — Pranesh | Dashboard, Scan now page, README, architecture diagram, test evidence | `kvpranesh` |

Kavish owns the AWS account, so he is the only one who touches the server. The other
two never need AWS credentials — that is the point of the ingest token.

---

## Phase 0 — Before the event

Mandatory: rule 7 requires accounts, tools and deployment environments prepared in
advance. This is where most teams lose marks.

### Everyone

- [ ] `python3 --version` returns 3.10 or newer
- [ ] `git --version` works
- [ ] Repository cloned, `pip install -r requirements-dev.txt`
- [ ] `pytest -q` green (39 tests)
- [ ] `bash scripts/install-hook.sh`
- [ ] `bash scripts/demo-blocked-commit.sh` watched end to end
- [ ] Can explain `app/scanner.py`, `scripts/secretshield_scan.py` and the CI workflow out loud

### Kavish — repository

- [ ] Repo created and pushed to `jonekavish-dot/secretshield`
- [ ] Gowshik and Pranesh added: **Settings → Collaborators → Add people** (`gowshikgunal22`, `kvpranesh`), both accept the email invite
- [ ] Branch protection off, or CI will block your own demo pushes

### Kavish — AWS

- [ ] EC2 instance launched: Ubuntu 24.04, `t3.micro`, key pair saved and `chmod 400`
- [ ] Security group: **SSH 22 from My IP** and **HTTP 80 from `0.0.0.0/0`**
- [ ] Elastic IP allocated **and associated** (without it the IP changes on reboot)
- [ ] `bash scripts/deploy-aws.sh` run on the server
- [ ] Ingest token copied somewhere safe

### Kavish — wire CI to the server

- [ ] `SECRETSHIELD_URL` = `http://<ELASTIC-IP>` (no trailing slash)
- [ ] `SECRETSHIELD_TOKEN` = the `sshield_…` token

Both at **Settings → Secrets and variables → Actions**.

### Verify the whole loop

- [ ] `curl http://<ELASTIC-IP>/health` returns `{"status":"ok"}`
- [ ] Dashboard opens **on a phone with Wi-Fi off**
- [ ] A test push turns the Actions run green
- [ ] The report appears on the dashboard with masked values

---

## Phase 1 — The night before

- [ ] Laptops charged, chargers packed, phone hotspot ready
- [ ] `curl http://<ELASTIC-IP>/health` still ok
- [ ] Backup evidence captured: screenshots of the green CI run, the blocked commit, the dashboard
- [ ] Demo rehearsed out loud twice, under 3 minutes, with the timer running

---

## Phase 2 — Event day

| Time | Focus | Lead |
| --- | --- | --- |
| 8:45–9:15 | Registration and environment verification. Show the live dashboard and a green CI run. | Kavish |
| 9:15–9:30 | Select **Problem 22**. | Kavish |
| 9:30–10:15 | Core gate: repo, `.gitleaks.toml`, hook blocking a dummy key. `pytest -q`. Screenshot the block. | Gowshik |
| 10:15–11:15 | CI gate: workflow fails on a dummy key, report uploads, dashboard shows it masked. | Kavish |
| 11:15–12:20 | Polish: Scan now page, README, architecture diagram as an image, test evidence. | Pranesh |
| 12:20–1:30 | Lunch. Code must be deploy-ready before you leave the table. | — |
| 1:30–2:10 | Deploy and verify from another network. Full end-to-end run. | Kavish |
| 2:10–2:30 | Submit and rehearse. | All |

Deploy during the 1:30 slot:

```bash
ssh -i secretshield-key.pem ubuntu@<ELASTIC-IP>
cd secretshield && git pull && sudo docker compose up -d --build
curl localhost/health
```

Work through the code together during the build window rather than only pushing it.
Judges will point at a file and ask what it does. A working minimum beats unfinished
extras, so protect what already works.

---

## Phase 3 — The demo, 3 minutes

| Step | What happens | Who |
| --- | --- | --- |
| 1 | Clean repo and live dashboard on screen. One line: three gates, one missed check is never enough. | Kavish |
| 2 | Add a dummy key, `git commit` → blocked with file, line, masked value and fix | Kavish |
| 3 | `git commit --no-verify` and push → CI fails, report lands on the dashboard | Gowshik on the browser |
| 4 | Switch to an environment variable → commit passes, CI green | Kavish |
| 5 | Hand the Scan now page to a judge, let them paste their own fake key | Pranesh |

Close on the redaction point: a scanner that prints secrets into its own logs is itself
a leak, so nothing here ever stores a full credential.

Likely questions and who answers:

| Question | Answer | Who |
| --- | --- | --- |
| "What if I skip the hook?" | CI catches it; that is the whole point of gate 2 | Kavish |
| "How do you avoid false positives?" | Entropy threshold, placeholder hints, path allowlist, line marker | Gowshik |
| "Is the secret stored anywhere?" | No. Masked at detection, re-masked at the API, and a test proves it | Gowshik |
| "What if the server is down?" | The gate still passes or fails correctly; only the upload is skipped | Kavish |
| "What does this file do?" | Open it and read it | whoever owns it |

---

## If something breaks

| Problem | Do this |
| --- | --- |
| Dashboard unreachable | `sudo docker compose restart`; if still down, demo the hook and CI and explain the service-down path is deliberate |
| Site loads on the server but not outside | Security group is missing HTTP 80 from `0.0.0.0/0` |
| `permission denied` on Docker | `exit`, SSH back in; the group change needs a new login |
| CI "could not reach the service" | `SECRETSHIELD_URL` wrong, has a trailing slash, or uses `https` with no certificate |
| CI "rejected the report (401)" | `SECRETSHIELD_TOKEN` does not match the server's `.env` |
| CI slow | Keep a previous green run open in another tab |
| Venue Wi-Fi dies | Phone hotspot; fall back to `uvicorn app.main:app` locally |
| A question you cannot answer | Say you will check, then open the file. Better than guessing. |

---

## Submission

- [ ] Repository link
- [ ] Live URL
- [ ] README, architecture diagram, test evidence in the repo
- [ ] Demo rehearsed once more, out loud, under 3 minutes
