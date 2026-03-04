---
model: opus
description: List all Access Control configurations across global, project, and personal levels
---

# Purpose

Display a summary of all Access Control security configurations across all settings levels (global, project, project personal).

## Variables

GLOBAL_SETTINGS: ~/.claude/settings.json
GLOBAL_ACL: ~/.claude/hooks/access-control/access-control-list.yaml
PROJECT_SETTINGS: .claude/settings.json
PROJECT_ACL: .claude/hooks/access-control/access-control-list.yaml
LOCAL_SETTINGS: .claude/settings.local.json

## Instructions

- Check each settings level for existence
- Read access-control-list.yaml at each level if it exists
- Present a consolidated view of all protections
- Clearly indicate which levels are active vs not configured

## Workflow

1. Check which levels have Access Control installed:
   - Global: Check if `~/.claude/hooks/access-control/access-control-list.yaml` exists
   - Project: Check if `.claude/hooks/access-control/access-control-list.yaml` exists
   - Personal: Check if `.claude/settings.local.json` exists and references access-control hooks

2. For each installed level, read the access-control-list.yaml and extract:
   - `bashToolRules` - blocked command rules
   - `zeroAccessPaths` - no access paths
   - `readOnlyPaths` - read-only paths
   - `noDeletePaths` - no-delete paths

3. Present the consolidated report

## Report

---

## Access Control Configuration Summary

### Global Level (`~/.claude/`)

**Status**: [Installed / Not Configured]

[If installed:]
**Zero Access Paths** (no operations allowed):
- [list paths or "None configured"]

**Read Only Paths** (read allowed, no modifications):
- [list paths or "None configured"]

**No Delete Paths** (all operations except delete):
- [list paths or "None configured"]

**Blocked Command Rules**: [count] rules
- [list first 5 rule IDs with reasons, or "None configured"]
- [if more than 5: "... and [N] more"]

---

### Project Level (`.claude/`)

**Status**: [Installed / Not Configured]

[Same format as Global]

---

### Project Personal Level (`.claude/settings.local.json`)

**Status**: [Installed / Not Configured]

[Same format as Global]

---

### Protection Summary

| Level | Zero Access | Read Only | No Delete | Command Rules |
|-------|-------------|-----------|-----------|---------------|
| Global | [count] | [count] | [count] | [count] |
| Project | [count] | [count] | [count] | [count] |
| Personal | [count] | [count] | [count] | [count] |

---

**Note**: Hooks at all levels run in parallel. If any level blocks an operation, it is blocked.
