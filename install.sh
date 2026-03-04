#!/usr/bin/env bash
# Claude Code Access Control — Installer
#
# Remote install (once published to GitHub):
#   curl -fsSL https://raw.githubusercontent.com/fshamim/claude-code-access-control/main/install.sh | bash
#
# Local install (from cloned repo):
#   ./install.sh

set -e

# ─── Configuration ─────────────────────────────────────────────────────────────
# Update REPO to your GitHub raw URL before publishing
REPO="https://raw.githubusercontent.com/fshamim/claude-code-access-control/main"
DEPLOY_DIR="$HOME/.claude/hooks/access-control"
SETTINGS_FILE="$HOME/.claude/settings.json"

HOOK_FILES=(
    "bash-tool-access-control.py"
    "edit-tool-access-control.py"
    "write-tool-access-control.py"
    "read-tool-access-control.py"
)

# ─── Colors ────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

echo ""
echo -e "${BOLD}  Claude Code Access Control — Installer${NC}"
echo "  ──────────────────────────────────────────"
echo ""

# ─── Detect local vs remote mode ───────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$(pwd)}")" 2>/dev/null && pwd || pwd)"
SKILL_DIR="$SCRIPT_DIR/.claude/skills/access-control"

if [[ -f "$SKILL_DIR/access-control-list.yaml" ]]; then
    LOCAL_MODE=true
    info "Local mode — copying from $SKILL_DIR"
else
    LOCAL_MODE=false
    command -v curl >/dev/null 2>&1 || error "curl is required. Install it and retry."
    info "Remote mode — downloading from GitHub"
    if [[ "$REPO" == *"YOUR_USERNAME"* ]]; then
        error "REPO URL not configured. Edit install.sh and set the correct GitHub URL."
    fi
fi

# ─── Check / install uv ────────────────────────────────────────────────────────
if ! command -v uv >/dev/null 2>&1; then
    warn "uv not found — installing..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # Try common uv install paths
    for p in "$HOME/.cargo/bin" "$HOME/.local/bin"; do
        [[ -f "$p/uv" ]] && export PATH="$p:$PATH" && break
    done
    command -v uv >/dev/null 2>&1 || error "uv install failed. Install manually: https://docs.astral.sh/uv/getting-started/installation/"
fi
info "uv $(uv --version)"

# ─── Create deploy directory ───────────────────────────────────────────────────
mkdir -p "$DEPLOY_DIR"
info "Deploy directory: $DEPLOY_DIR"

# ─── Copy or download hook files ───────────────────────────────────────────────
if [[ "$LOCAL_MODE" == true ]]; then
    HOOKS_SRC="$SKILL_DIR/hooks/access-control-python"
    for f in "${HOOK_FILES[@]}"; do
        cp "$HOOKS_SRC/$f" "$DEPLOY_DIR/$f"
        chmod +x "$DEPLOY_DIR/$f"
        info "Copied $f"
    done
    cp "$SKILL_DIR/access-control-list.yaml" "$DEPLOY_DIR/access-control-list.yaml"
    info "Copied access-control-list.yaml"
else
    HOOKS_SRC="$REPO/.claude/skills/access-control/hooks/access-control-python"
    for f in "${HOOK_FILES[@]}"; do
        curl -fsSL "$HOOKS_SRC/$f" -o "$DEPLOY_DIR/$f"
        chmod +x "$DEPLOY_DIR/$f"
        info "Downloaded $f"
    done
    curl -fsSL "$REPO/.claude/skills/access-control/access-control-list.yaml" \
        -o "$DEPLOY_DIR/access-control-list.yaml"
    info "Downloaded access-control-list.yaml"
fi

# ─── Merge ~/.claude/settings.json ─────────────────────────────────────────────
mkdir -p "$HOME/.claude"

python3 - "$DEPLOY_DIR" "$SETTINGS_FILE" <<'PYTHON'
import json, os, sys

deploy_dir = sys.argv[1]
settings_file = sys.argv[2]

LLM_PROMPT = (
    "You are a security reviewer evaluating a bash command for destructive potential. "
    "Analyze this command: $ARGUMENTS\n\n"
    "BLOCK if the command would:\n"
    "- Delete, remove, or destroy files/directories recursively or in bulk\n"
    "- Overwrite or corrupt critical system files, configs, or data\n"
    "- Cause irreversible data loss\n"
    "- Execute destructive operations via find, xargs, or loops\n"
    "- Wipe, format, or damage filesystems\n\n"
    "ALLOW if the command is:\n"
    "- Read-only (cat, ls, grep, find without -delete/-exec rm)\n"
    "- Safe write operations to non-critical paths\n"
    "- Standard development commands (git status, npm install, etc.)\n"
    "- Precise SQL DELETE with a specific ID in WHERE clause\n\n"
    "Respond with JSON: {\"decision\": \"approve\" or \"block\", \"reason\": \"brief explanation\"}"
)

new_hooks = [
    {"matcher": "Bash", "hooks": [
        {"type": "command", "command": f"uv run {deploy_dir}/bash-tool-access-control.py", "timeout": 5},
        {"type": "prompt", "prompt": LLM_PROMPT, "timeout": 10},
    ]},
    {"matcher": "Edit",  "hooks": [{"type": "command", "command": f"uv run {deploy_dir}/edit-tool-access-control.py",  "timeout": 5}]},
    {"matcher": "Write", "hooks": [{"type": "command", "command": f"uv run {deploy_dir}/write-tool-access-control.py", "timeout": 5}]},
    {"matcher": "Read",  "hooks": [{"type": "command", "command": f"uv run {deploy_dir}/read-tool-access-control.py",  "timeout": 5}]},
    {"matcher": "Grep",  "hooks": [{"type": "command", "command": f"uv run {deploy_dir}/read-tool-access-control.py",  "timeout": 5}]},
]

new_deny = [
    "Bash(rm -rf /*:*)",
    "Bash(rm -rf ~/*:*)",
    "Bash(sudo rm -rf:*)",
    "Bash(mkfs:*)",
    "Bash(dd if=* of=/dev/*:*)",
]
new_ask = [
    "Bash(git push --force:*)",
    "Bash(git reset --hard:*)",
]

# Load existing settings or start fresh
if os.path.exists(settings_file):
    with open(settings_file) as f:
        settings = json.load(f)
    print(f"[!] Merging with existing {settings_file}")
else:
    settings = {}
    print(f"[+] Creating {settings_file}")

# Merge PreToolUse hooks (skip if matcher already registered)
hooks = settings.setdefault("hooks", {})
pre = hooks.setdefault("PreToolUse", [])
existing_matchers = {entry.get("matcher") for entry in pre}
added = []
for h in new_hooks:
    if h["matcher"] not in existing_matchers:
        pre.append(h)
        added.append(h["matcher"])
    else:
        print(f"    Skipped {h['matcher']} hook (already registered — merge manually if needed)")

if added:
    print(f"    Added hooks: {', '.join(added)}")

# Merge permissions
perms = settings.setdefault("permissions", {})
deny = perms.setdefault("deny", [])
ask  = perms.setdefault("ask", [])
for d in new_deny:
    if d not in deny:
        deny.append(d)
for a in new_ask:
    if a not in ask:
        ask.append(a)

with open(settings_file, "w") as f:
    json.dump(settings, f, indent=2)
print(f"[✓] Settings written to {settings_file}")
PYTHON

# ─── Done ──────────────────────────────────────────────────────────────────────
echo ""
info "Installation complete"
echo ""
echo "  ┌──────────────────────────────────────────────────────────┐"
echo "  │  IMPORTANT: Restart Claude Code for hooks to take effect  │"
echo "  └──────────────────────────────────────────────────────────┘"
echo ""
echo "  Verify:   /hooks in Claude Code"
echo "  Test:     /rogue in Claude Code"
echo "  Rules:    $DEPLOY_DIR/access-control-list.yaml"
echo ""
