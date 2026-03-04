---
model: opus
description: Provide manual guidance for configuring Access Control without automated workflows
---

# Purpose

Explain how to manually configure the Access Control security hooks system. Provides documentation and guidance without executing automated workflows — for users who prefer direct control.

## Instructions

- First ask what the user wants to learn about
- Provide clear, detailed explanations
- Show exact file paths and formats
- Include copy-paste examples
- Do NOT execute any installation or modification commands
- This is purely educational/documentation

## Workflow

### Step 1: Understand User's Goal

1. Use AskUserQuestion:

```
Question: "What would you like to learn about Access Control?"
Options:
- Understand the system architecture
- Learn how to edit access-control-list.yaml
- Learn how to edit settings.json
- Learn how to test the hooks
- See all file locations
```

### Branch A: System Architecture

2. **If "Understand the system architecture"**:

---

## Access Control Architecture

### Overview

Access Control uses Claude Code's **hook system** to intercept tool calls before execution. It provides defense-in-depth across five tools:

```
┌─────────────────────────────────────────────┐
│           Claude Code Tool Call              │
└─────────────────────────────────────────────┘
                      │
    ┌────────┬─────────┼──────────┬────────┐
    ▼        ▼         ▼          ▼        ▼
┌──────┐ ┌──────┐ ┌───────┐ ┌──────┐ ┌──────┐
│ Bash │ │ Edit │ │ Write │ │ Read │ │ Grep │
└──┬───┘ └──┬───┘ └───┬───┘ └──┬───┘ └──┬───┘
   │        │         │         │        │
   ▼        ▼         ▼         ▼        ▼
PreToolUse hooks (block or ask before execution)
   │
   ▼
Exit 0 = Allow   Exit 2 = BLOCK   JSON = ASK
```

### Hook Types

1. **bash-tool-access-control.py**
   - Structured rule matching (no regex)
   - Evasion bypass detection (eval, base64-decode+exec, find-exec)
   - Path protection for zero-access, read-only, and no-delete paths

2. **edit-tool-access-control.py** — blocks edits to zero-access and read-only paths

3. **write-tool-access-control.py** — blocks writes to zero-access and read-only paths

4. **read-tool-access-control.py** — blocks reads/grep from zero-access paths

### Rule Matching (bash hook)

Rules in `access-control-list.yaml` use structured fields instead of regex:

| Field         | Logic   | Description                                   |
|---------------|---------|-----------------------------------------------|
| `command`     | exact/glob | Matches command name (token 0)             |
| `subcommand`  | exact   | Matches second token (e.g. `push` in `git push`) |
| `flags`       | OR      | ANY of listed flags must be present           |
| `args`        | AND     | ALL listed args must be present               |
| `contains`    | substr  | Substring must be in the full command         |
| `excludes`    | substr  | Substring must NOT be in the full command     |
| `contains_all`| AND     | All substrings must be present                |

### Evasion Bypass Detectors

These run automatically before rule matching:
- **eval** — blocked unconditionally
- **base64 -d + execution** — blocked when decode is combined with shell execution
- **find -exec [dangerous]** — blocked when -exec is followed by cat, cp, curl, etc.

---

### Branch B: Editing access-control-list.yaml

3. **If "Learn how to edit access-control-list.yaml"**:

---

## Editing access-control-list.yaml

### File Location

- **Global**: `~/.claude/hooks/access-control/access-control-list.yaml`
- **Project**: `.claude/hooks/access-control/access-control-list.yaml`

### File Structure

```yaml
bashToolRules:
  - id: rm-recursive-or-force
    command: rm
    flags: ["-rf", "-fr", "-r", "-R", "--recursive"]
    reason: rm with recursive or force flags
    action: block   # block | ask

zeroAccessPaths:
  - ~/.ssh/
  - ~/.aws/

readOnlyPaths:
  - /etc/
  - ~/.bashrc

noDeletePaths:
  - .claude/
  - README.md
```

### Adding a Blocked Rule

```yaml
bashToolRules:
  # ... existing rules ...
  - id: npm-publish
    command: npm
    args: ["publish"]
    reason: npm publish blocked for safety
    action: block
```

### Adding a Protected Path

```yaml
# For secrets (block ALL access including reads)
zeroAccessPaths:
  - ~/.my-secrets/

# For configs (allow reads, block writes)
readOnlyPaths:
  - /my/config/dir/

# For important files (allow everything except delete)
noDeletePaths:
  - ./important-data/
```

### Validation

After editing, validate YAML syntax:
```bash
python -c "import yaml; yaml.safe_load(open('access-control-list.yaml'))"
```

---

### Branch C: Editing settings.json

4. **If "Learn how to edit settings.json"**:

---

## Editing settings.json

### File Locations

| Level | Path |
|-------|------|
| Global | `~/.claude/settings.json` |
| Project | `.claude/settings.json` |
| Project Personal | `.claude/settings.local.json` |

### Full Configuration

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "uv run \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/access-control/bash-tool-access-control.py",
            "timeout": 5
          }
        ]
      },
      {
        "matcher": "Edit",
        "hooks": [
          {
            "type": "command",
            "command": "uv run \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/access-control/edit-tool-access-control.py",
            "timeout": 5
          }
        ]
      },
      {
        "matcher": "Write",
        "hooks": [
          {
            "type": "command",
            "command": "uv run \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/access-control/write-tool-access-control.py",
            "timeout": 5
          }
        ]
      },
      {
        "matcher": "Read",
        "hooks": [
          {
            "type": "command",
            "command": "uv run \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/access-control/read-tool-access-control.py",
            "timeout": 5
          }
        ]
      },
      {
        "matcher": "Grep",
        "hooks": [
          {
            "type": "command",
            "command": "uv run \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/access-control/read-tool-access-control.py",
            "timeout": 5
          }
        ]
      }
    ]
  },
  "permissions": {
    "deny": [
      "Bash(rm -rf /*:*)",
      "Bash(sudo rm -rf:*)"
    ],
    "ask": [
      "Bash(git push --force:*)",
      "Bash(git reset --hard:*)"
    ]
  }
}
```

---

### Branch D: Testing Hooks

5. **If "Learn how to test the hooks"**:

---

## Testing Access Control Hooks

### Verify Hooks are Registered

In Claude Code, run:
```
/hooks
```

You should see PreToolUse hooks listed for Bash, Edit, Write, Read, and Grep.

### Manual Hook Testing

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | \
  uv run .claude/hooks/access-control/bash-tool-access-control.py

echo $?  # Should print 2 (blocked)
```

### Interactive Tester

```bash
cd .claude/hooks/access-control
uv run test-access-control.py -i
```

### CLI Testing

```bash
# Test bash hook blocks rm -rf
uv run test-access-control.py bash Bash "rm -rf /tmp" --expect-blocked

# Test read hook blocks zero-access path
uv run test-access-control.py read Read "~/.ssh/id_rsa" --expect-blocked

# Test bash allows safe command
uv run test-access-control.py bash Bash "ls -la" --expect-allowed
```

---

### Branch E: File Locations

6. **If "See all file locations"**:

---

## File Locations Reference

### Global Installation

```
~/.claude/
├── settings.json
└── hooks/
    └── access-control/
        ├── bash-tool-access-control.py
        ├── edit-tool-access-control.py
        ├── write-tool-access-control.py
        ├── read-tool-access-control.py
        └── access-control-list.yaml
```

### Project Installation

```
your-project/
└── .claude/
    ├── settings.json
    ├── settings.local.json          # Personal overrides (gitignored)
    └── hooks/
        └── access-control/
            ├── bash-tool-access-control.py
            ├── edit-tool-access-control.py
            ├── write-tool-access-control.py
            ├── read-tool-access-control.py
            └── access-control-list.yaml
```

### Settings Precedence

1. **Managed settings** (Enterprise) — highest
2. **Local project** (`.claude/settings.local.json`)
3. **Shared project** (`.claude/settings.json`)
4. **User global** (`~/.claude/settings.json`) — lowest

---

## Report

Present the requested information clearly with code blocks for copy-paste convenience.

**Note**: This workflow provides documentation only. No files are modified during this workflow.
