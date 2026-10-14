#!/usr/bin/env bash
# Demo: prove the pre-commit hook blocks a dummy API key.
# Creates a throwaway Git repository, installs the hook, and tries two commits.
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="$(mktemp -d)"
trap 'rm -rf "$DEMO_DIR"' EXIT

echo "=============================================="
echo " SecretShield demo: pre-commit hook"
echo " Sandbox: $DEMO_DIR"
echo "=============================================="

cd "$DEMO_DIR"
git init -q
git config user.email "demo@secretshield.local"
git config user.name "SecretShield Demo"

mkdir -p scripts app hooks
cp "$PROJECT_ROOT/scripts/secretshield_scan.py" scripts/
cp -r "$PROJECT_ROOT/app/scanner.py" app/
touch app/__init__.py
cp "$PROJECT_ROOT/.gitleaks.toml" .
cp "$PROJECT_ROOT/hooks/pre-commit" .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

git add -A >/dev/null 2>&1
git commit -qm "scaffold" --no-verify >/dev/null 2>&1

echo
echo "--- STEP 1: commit a clean file (expected: ALLOWED) ------------"
cat > settings.py <<'EOF'
import os
API_KEY = os.environ["API_KEY"]
EOF
git add settings.py
if git commit -qm "add settings"; then
  echo "RESULT: commit allowed, as expected."
else
  echo "RESULT: UNEXPECTED - the clean commit was blocked."
fi

echo
echo "--- STEP 2: commit a dummy API key (expected: BLOCKED) ---------"
# The dummy credentials live in fixtures/ so this script holds no key-shaped text.
cp "$PROJECT_ROOT/fixtures/demo_leak.py" leak.py
git add leak.py
if git commit -qm "add aws key"; then
  echo "RESULT: UNEXPECTED - the commit went through."
  exit 1
else
  echo "RESULT: commit blocked, as expected."
fi

echo
echo "--- STEP 3: fix the leak and commit again (expected: ALLOWED) --"
cp "$PROJECT_ROOT/fixtures/demo_fixed.py" leak.py
git add leak.py
if git commit -qm "read credentials from the environment"; then
  echo "RESULT: commit allowed, as expected."
else
  echo "RESULT: UNEXPECTED - the fixed commit was blocked."
  exit 1
fi

echo
echo "--- STEP 4: bypass with --no-verify (expected: ALLOWED locally) -"
cp "$PROJECT_ROOT/fixtures/demo_leak.py" sneaky.py
git add sneaky.py
git commit -qm "bypass the hook" --no-verify
echo "RESULT: the hook was skipped, so the commit went through locally."
echo "        This is exactly what the CI gate catches on push."

echo
echo "=============================================="
echo " Demo complete."
echo "=============================================="
