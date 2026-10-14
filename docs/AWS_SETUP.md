# Deployment guide: AWS and GitHub

Everything you need to do by hand, in order. Budget about 25 minutes the first time.
Do all of this **before the event**, as the rules require.

---

## Part 1 — AWS EC2 (about 15 minutes)

### Step 1. Launch the instance

1. Sign in to the AWS Console and go to **EC2 → Instances → Launch instances**.
2. Fill in:
   - **Name:** `secretshield`
   - **AMI:** Ubuntu Server 24.04 LTS (free-tier eligible)
   - **Instance type:** `t3.micro` (or `t2.micro` if that is the free-tier type in your region)
3. **Key pair:** click *Create new key pair*, name it `secretshield-key`, type RSA, format `.pem`.
   The file downloads once. Keep it; you cannot download it again.
4. Leave storage at the default 8 GB gp3.

### Step 2. Network settings (this is the part people get wrong)

In the **Network settings** panel click **Edit**, then add two inbound rules:

| Type | Port | Source | Why |
| --- | --- | --- | --- |
| SSH | 22 | My IP | So you can log in |
| HTTP | 80 | Anywhere (`0.0.0.0/0`) | So judges can open the dashboard |

If HTTP from anywhere is missing, the site will not load from outside and you lose
the 25% deployment marks. Click **Launch instance**.

### Step 3. Give it a fixed address

The public IP changes every time the instance restarts, which will break your demo.

1. Go to **EC2 → Elastic IPs → Allocate Elastic IP address → Allocate**.
2. Select it → **Actions → Associate Elastic IP address** → choose your `secretshield` instance → **Associate**.
3. Write the address down. This is your demo URL.

### Step 4. Connect and deploy

On your laptop:

```bash
chmod 400 secretshield-key.pem
ssh -i secretshield-key.pem ubuntu@<YOUR-ELASTIC-IP>
```

Then on the server:

```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/<your-username>/secretshield.git
cd secretshield
bash scripts/deploy-aws.sh
```

The script installs Docker, generates an ingest token, builds the containers and
starts everything. **Copy the token it prints** — you need it in Part 2.

> If you see a Docker permission error, run `exit`, SSH back in, and run the script again.

### Step 5. Check it from outside

Open `http://<YOUR-ELASTIC-IP>/` in a browser, then check it again on your phone
**with Wi-Fi off**. If it loads on mobile data, it is genuinely public.

```bash
curl http://<YOUR-ELASTIC-IP>/health     # {"status":"ok"}
```

---

## Part 2 — GitHub (about 10 minutes)

### Step 6. Push the code

```bash
cd secretshield
git init
git add .
git commit -m "SecretShield: secret-leak detection"
git branch -M main
git remote add origin https://github.com/<your-username>/secretshield.git
git push -u origin main
```

### Step 7. Add the two Actions secrets

In the repository: **Settings → Secrets and variables → Actions → New repository secret**.

| Name | Value |
| --- | --- |
| `SECRETSHIELD_URL` | `http://<YOUR-ELASTIC-IP>` (no trailing slash) |
| `SECRETSHIELD_TOKEN` | the `sshield_…` token from Step 4 |

This is the safe-handling rule in practice: the token reaches CI through GitHub's
secret store, never through the repository.

### Step 8. Check that the pipeline runs

Open the **Actions** tab. The `SecretShield secret scan` workflow should run on your
push and finish green. Open the run and check the summary: it reports the files
scanned and any findings.

### Step 9. Install the hook on every laptop

Each team member runs this once in their clone:

```bash
bash scripts/install-hook.sh
```

---

## Part 3 — Rehearse the demo

```bash
bash scripts/demo-blocked-commit.sh
```

This runs the whole blocked-commit story in a throwaway repository, so you can
practise without touching your real one.

---

## Costs

A `t3.micro` on the 12-month free tier costs nothing. Outside the free tier, it is
roughly 8 to 10 USD a month. An Elastic IP is free **while it is attached to a running
instance** and billed hourly when it is not. After the event:

```bash
# On the server
sudo docker compose down
```

Then in the console: **terminate the instance** and **release the Elastic IP**, or you
will keep paying for the address.

---

## If something breaks

| Symptom | Fix |
| --- | --- |
| Site does not load from outside | Security group is missing HTTP port 80 from `0.0.0.0/0` |
| Site loads on the server but not outside | Check with `curl localhost/health` on the box; if that works it is the security group |
| `permission denied` on Docker | `exit`, SSH back in (the group change needs a new login) |
| CI says "could not reach the service" | `SECRETSHIELD_URL` is wrong, has a trailing slash, or uses `https` on a server with no certificate |
| CI says "the service rejected the report (HTTP 401)" | `SECRETSHIELD_TOKEN` does not match the server's `.env` |
| Containers not running | `sudo docker compose ps` then `sudo docker compose logs -f` |

An upload failure never changes the gate result: the pipeline still fails on a real
secret, it just cannot record the report.

---

## Optional: HTTPS

Only if you have a domain name and spare time. Point the domain at the Elastic IP, then:

```bash
sudo apt-get install -y certbot
sudo docker compose stop nginx
sudo certbot certonly --standalone -d your-domain.com
```

Then mount the certificates into the Nginx container and add a `listen 443 ssl` block.
Plain HTTP over port 80 satisfies the event requirement, so do not let this eat your
build time.
