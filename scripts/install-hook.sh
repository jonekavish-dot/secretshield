#!/usr/bin/env bash
# Install the SecretShield pre-commit hook into this repository.
# Usage: bash scripts/install-hook.sh
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK_DIR="$(git rev-parse --git-path hooks)"
HOOK_PATH="$HOOK_DIR/pre-commit"

mkdir -p "$HOOK_DIR"

if [ -f "$HOOK_PATH" ] && ! grep -q "SecretShield" "$HOOK_PATH" 2>/dev/null; then
  cp "$HOOK_PATH" "$HOOK_PATH.backup"
  echo "Existing hook backed up to pre-commit.backup"
fi

cp "$REPO_ROOT/hooks/pre-commit" "$HOOK_PATH"
chmod +x "$HOOK_PATH"

echo "SecretShield pre-commit hook installed at $HOOK_PATH"
echo "Test it with:  bash scripts/demo-blocked-commit.sh"
