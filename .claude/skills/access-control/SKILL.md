---
name: Access Control
description: Install, configure, and manage the Claude Code Access Control security hooks system. Use when user mentions access control, security hooks, protected paths, blocked commands, install security, or modify protection settings.
---

# Access Control Skill

Defense-in-depth protection system for Claude Code. Blocks dangerous commands and protects sensitive files via PreToolUse hooks.

## Overview

This skill helps users deploy and manage the Access Control security system, which provides:

- **Structured Rule Blocking**: Blocks dangerous bash commands using explicit, auditable rules (no regex)
- **Evasion Detection**: Detects bypass attempts — `eval`, `base64 -d` + exec, `find -exec` with dangerous commands
- **Ask Rules**: Triggers confirmation dialog for risky-but-valid operations (`action: ask`)
- **Path Protection Levels**:
  - `zeroAccessPaths` - No access at all (secrets/credentials)
  - `readOnlyPaths` - Read allowed, modifications blocked
  - `noDeletePaths` - All operations except delete

## Skill Structure

```
.claude/skills/access-control/
├── SKILL.md                          # This file
├── access-control-list.yaml          # Security rules (single source of truth)
├── cookbook/
│   ├── install_access_control_ag_workflow.md
│   ├── modify_access_control_ag_workflow.md
│   ├── manual_control_access_control_ag_workflow.md
│   ├── list_access_controls.md
│   └── test_access_control.md
├── hooks/
│   └── access-control-python/        # Python/UV implementation
│       ├── bash-tool-access-control.py
│       ├── edit-tool-access-control.py
│       ├── write-tool-access-control.py
│       ├── read-tool-access-control.py
│       ├── python-settings.json
│       └── test-access-control.py
└── test-prompts/                     # Test prompts for validation
    ├── rogue_v1.md
    ├── rogue_v2.md
    ├── rogue_v3.md
    └── rogue_v4.md
```

## After Installation

The install workflow copies hooks and creates settings based on the chosen level:

### Global Hooks
```
~/.claude/
├── settings.json                      # Hook configuration
└── hooks/
    └── access-control/
        ├── access-control-list.yaml
        ├── bash-tool-access-control.py
        ├── edit-tool-access-control.py
        ├── write-tool-access-control.py
        └── read-tool-access-control.py
```

### Project Hooks
```
<agents current working directory>/
└── .claude/
    ├── settings.json                  # Hook configuration (shared)
    └── hooks/
        └── access-control/
            ├── access-control-list.yaml
            ├── bash-tool-access-control.py
            ├── edit-tool-access-control.py
            ├── write-tool-access-control.py
            └── read-tool-access-control.py
```

### Project Personal Hooks
```
<agents current working directory>/
└── .claude/
    ├── settings.local.json            # Personal overrides (gitignored)
    └── hooks/
        └── access-control/
            ├── access-control-list.yaml
            ├── bash-tool-access-control.py
            ├── edit-tool-access-control.py
            ├── write-tool-access-control.py
            └── read-tool-access-control.py
```

---

## Cookbook

Based on what the user says, read and execute the appropriate workflow.

### Installation Pathway

**Trigger phrases**: "install access control", "setup security hooks", "deploy access control", "add protection"

**Workflow**: Read and execute [cookbook/install_access_control_ag_workflow.md](cookbook/install_access_control_ag_workflow.md)

### Modification Pathway

**Trigger phrases**: "help me modify access control", "update protection", "change blocked paths", "add restricted directory"

**Workflow**: Read and execute [cookbook/modify_access_control_ag_workflow.md](cookbook/modify_access_control_ag_workflow.md)

### Manual Control Pathway

**Trigger phrases**: "how do I manually update", "explain access control config", "show me the settings"

**Workflow**: Read and execute [cookbook/manual_control_access_control_ag_workflow.md](cookbook/manual_control_access_control_ag_workflow.md)

### Testing Pathway

**Trigger phrases**:
  - "test access control"
  - "run access control tests"
  - "verify hooks are working"
  - "access control test this command <x>"
  - "access control test this read to this path <x>"
  - "access control test this write to this path <x>"

**Workflow**: Read and execute [cookbook/test_access_control.md](cookbook/test_access_control.md)

### Direct Command Pathway

**Trigger phrases**: "add /secret to zero access paths", "block command Y", "update global read only paths to include X"

**Action**: Execute immediately without prompts — the user knows the system.

**Examples**:
- "add ~/.credentials to zero access paths" → Edit access-control-list.yaml directly
- "block the command 'npm publish'" → Add rule to bashToolRules
- "make /var/log read only" → Add to readOnlyPaths

---

## Quick Reference

### Settings File Locations

| Level            | Path                          | Scope                      |
| ---------------- | ----------------------------- | -------------------------- |
| Global           | `~/.claude/settings.json`     | All projects               |
| Project          | `.claude/settings.json`       | Current project (shared)   |
| Project Personal | `.claude/settings.local.json` | Current project (personal) |

### Path Protection Levels

| Type              | Read | Write | Edit | Delete | Use Case                |
| ----------------- | ---- | ----- | ---- | ------ | ----------------------- |
| `zeroAccessPaths` | No   | No    | No   | No     | Secrets, credentials    |
| `readOnlyPaths`   | Yes  | No    | No   | No     | System configs, history |
| `noDeletePaths`   | Yes  | Yes   | Yes  | No     | Important project files |

### Tool Coverage

| Tool  | Hook                          | What it checks              |
| ----- | ----------------------------- | --------------------------- |
| Bash  | bash-tool-access-control.py   | Commands, paths, evasion    |
| Edit  | edit-tool-access-control.py   | File paths being edited     |
| Write | write-tool-access-control.py  | File paths being written    |
| Read  | read-tool-access-control.py   | File paths being read       |
| Grep  | read-tool-access-control.py   | Search paths                |

### Exit Codes

| Code | Meaning                              |
| ---- | ------------------------------------ |
| 0    | Allow operation                      |
| 0    | Ask (JSON output triggers dialog)    |
| 2    | Block operation                      |

### Runtime Requirements

| Implementation | Runtime     | Install Command                                       |
| -------------- | ----------- | ----------------------------------------------------- |
| Python         | UV (Astral) | `curl -LsSf https://astral.sh/uv/install.sh \| sh`   |

---

## Testing

Use the test prompts in [test-prompts/](test-prompts/) to validate the hooks:

- `rogue_v1.md` - Tests `rm -rf` blocking (bashToolRules)
- `rogue_v2.md` - Tests `find -delete` blocking (noDeletePaths)
- `rogue_v4.md` - Tests simple command blocking (`chmod`)

Run a test:
```
/project:test-prompts/rogue_v1
```

---

## Related Files

- [cookbook/install_access_control_ag_workflow.md](cookbook/install_access_control_ag_workflow.md) - Installation workflow
- [cookbook/modify_access_control_ag_workflow.md](cookbook/modify_access_control_ag_workflow.md) - Modification workflow
- [cookbook/manual_control_access_control_ag_workflow.md](cookbook/manual_control_access_control_ag_workflow.md) - Manual guidance
- [cookbook/list_access_controls.md](cookbook/list_access_controls.md) - List all configurations
- [cookbook/test_access_control.md](cookbook/test_access_control.md) - Test all hooks
- [hooks/access-control-python/](hooks/access-control-python/) - Python implementation
