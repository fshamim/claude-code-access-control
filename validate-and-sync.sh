#!/usr/bin/env bash
# validate-and-sync.sh
# ====================
# Safe workflow for deploying access control updates:
#   1. Runs the full test suite against the skill source YAML.
#   2. If all tests pass, syncs YAML + hook files to ~/.claude/hooks/access-control/.
#   3. If any test fails, aborts — nothing is synced.
#
# Usage:
#   ./validate-and-sync.sh            # Test + sync on pass
#   ./validate-and-sync.sh --dry-run  # Test only, never sync
#   ./validate-and-sync.sh --quiet    # Suppress per-test output, show summary only

set -euo pipefail

# ============================================================================
# PATHS
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$SCRIPT_DIR/.claude/skills/access-control"
HOOKS_SRC="$SKILL_DIR/hooks/access-control-python"
YAML_SRC="$SKILL_DIR/access-control-list.yaml"
TEST_SCRIPT="$HOOKS_SRC/run-all-tests.py"
DEPLOY_DIR="$HOME/.claude/hooks/access-control"

# ============================================================================
# ARGS
# ============================================================================

DRY_RUN=false
QUIET_FLAG=""

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --quiet|-q) QUIET_FLAG="--quiet" ;;
  esac
done

# ============================================================================
# CHECKS
# ============================================================================

if ! command -v uv &>/dev/null; then
  echo "ERROR: 'uv' not found. Install it: curl -LsSf https://astral.sh/uv/install.sh | sh"
  exit 1
fi

if [[ ! -f "$YAML_SRC" ]]; then
  echo "ERROR: access-control-list.yaml not found at: $YAML_SRC"
  exit 1
fi

if [[ ! -f "$TEST_SCRIPT" ]]; then
  echo "ERROR: run-all-tests.py not found at: $TEST_SCRIPT"
  exit 1
fi

# ============================================================================
# STEP 1: RUN TESTS
# ============================================================================

echo ""
echo "======================================================================"
echo "  Claude Code Access Control: Validate & Sync"
echo "======================================================================"
echo "  Source : $SKILL_DIR"
echo "  Deploy : $DEPLOY_DIR"
if $DRY_RUN; then
  echo "  Mode   : DRY RUN (tests only, no sync)"
fi
echo "======================================================================"

echo ""
echo "--- Step 1: Running test suite ---"
echo ""

# Run tests; capture exit code without triggering set -e
set +e
uv run "$TEST_SCRIPT" $QUIET_FLAG
TEST_EXIT=$?
set -e

if [[ $TEST_EXIT -ne 0 ]]; then
  echo ""
  echo "======================================================================"
  echo "  SYNC ABORTED: Tests failed."
  echo "  Fix the failures above, then re-run validate-and-sync.sh."
  echo "======================================================================"
  exit 1
fi

# ============================================================================
# STEP 2: SYNC
# ============================================================================

if $DRY_RUN; then
  echo ""
  echo "======================================================================"
  echo "  DRY RUN: All tests passed. Skipping sync (--dry-run)."
  echo "======================================================================"
  exit 0
fi

echo ""
echo "--- Step 2: Syncing to $DEPLOY_DIR ---"
echo ""

mkdir -p "$DEPLOY_DIR"

# Sync YAML
cp "$YAML_SRC" "$DEPLOY_DIR/access-control-list.yaml"
echo "  Copied  access-control-list.yaml"

# Sync all hook .py files
for src_file in "$HOOKS_SRC"/*.py; do
  filename="$(basename "$src_file")"
  cp "$src_file" "$DEPLOY_DIR/$filename"
  echo "  Copied  $filename"
done

echo ""
echo "======================================================================"
echo "  Sync complete!"
echo "  Deployed to: $DEPLOY_DIR"
echo ""
echo "  Restart Claude Code for changes to take effect."
echo "======================================================================"
