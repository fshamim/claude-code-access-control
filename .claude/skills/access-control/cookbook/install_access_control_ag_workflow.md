---
model: opus
description: Interactive workflow to install the Access Control security hooks system
---

# Purpose

Guide the user through installing the Access Control security hooks system at their chosen settings level (global, project, or project personal). Uses interactive prompts to determine preferences and handle conflicts.

## Variables

SKILL_DIR: .claude/skills/access-control
ACL_FILE: SKILL_DIR/access-control-list.yaml
GLOBAL_SETTINGS: ~/.claude/settings.json
PROJECT_SETTINGS: .claude/settings.json
LOCAL_SETTINGS: .claude/settings.local.json

## Instructions

- Use the AskUserQuestion tool at each decision point to guide the user
- Check for existing settings before installation
- Handle merge/overwrite conflicts gracefully
- Copy hook files and the access-control-list.yaml together
- Verify installation by checking file existence after copy

## Workflow

### Step 1: Determine Installation Level

1. Use AskUserQuestion to ask the user where they want to install:

```
Question: "Where would you like to install Access Control?"
Options:
- Global (affects all projects) - ~/.claude/settings.json
- Project (shared with team) - .claude/settings.json
- Project Personal (just for you) - .claude/settings.local.json
```

2. Store the chosen path as TARGET_SETTINGS

### Step 2: Check for Existing Settings

3. Use the Read tool to check if TARGET_SETTINGS exists

4. **If settings file does NOT exist**: Proceed to Step 3 (Fresh Install)

5. **If settings file EXISTS**: Use AskUserQuestion:

```
Question: "Existing settings found at [TARGET_SETTINGS]. How would you like to proceed?"
Options:
- Merge (combine existing hooks with access-control)
- Overwrite (replace with access-control settings)
- Stop (cancel installation)
```

6. Handle the response:
   - **Merge**: Read existing file, merge hooks arrays, write combined result
   - **Overwrite**: Proceed to Step 3 (Fresh Install)
   - **Stop**: Report "Installation cancelled" and exit workflow

### Step 3: Install Hook Files

7. Determine target hooks directory based on TARGET_SETTINGS:
   - Global: `~/.claude/hooks/access-control/`
   - Project/Local: `.claude/hooks/access-control/`

8. Create target hooks directory if it doesn't exist:
```bash
mkdir -p [TARGET_HOOKS_DIR]
```

9. Copy hook scripts from skill directory:
```bash
cp [SKILL_DIR]/hooks/access-control-python/*.py [TARGET_HOOKS_DIR]/
```

10. Copy the access-control-list.yaml from skill root:
```bash
cp [ACL_FILE] [TARGET_HOOKS_DIR]/
```

### Step 4: Install Settings Configuration

11. Read the settings template:
    - `${SKILL_DIR}/hooks/access-control-python/python-settings.json`

12. **For Fresh Install or Overwrite**:
    - Write the settings template to TARGET_SETTINGS
    - Update hook command paths to match TARGET_HOOKS_DIR

13. **For Merge**:
    - Parse existing settings JSON
    - Parse template settings JSON
    - Merge hooks.PreToolUse arrays (append access-control hooks)
    - Merge permissions.deny and permissions.ask arrays
    - Write merged result to TARGET_SETTINGS

### Step 5: Verify Installation

14. Verify all files exist:
```bash
ls -la [TARGET_HOOKS_DIR]/
```

15. Verify settings file was created/updated:
```bash
cat [TARGET_SETTINGS] | head -20
```

16. Make hook scripts executable:
```bash
chmod +x [TARGET_HOOKS_DIR]/*.py 2>/dev/null || true
```

### Step 6: Display Runtime Install Instructions

17. Display install command for UV:

```
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Step 7: Restart Reminder

18. **IMPORTANT**: After all installation steps are complete, you MUST tell the user:

> **Restart your agent for these changes to take effect.**

This is critical — hooks are only loaded at agent startup.

### Step 8: Show Configuration Summary

19. Read and execute [list_access_controls.md](list_access_controls.md) to display all active Access Control configurations across all levels.

## Report

Present the installation summary:

## Access Control Installation Complete

**Installation Level**: [Global/Project/Project Personal]
**Settings File**: `[TARGET_SETTINGS]`
**Hooks Directory**: `[TARGET_HOOKS_DIR]`
**Runtime**: Python/UV

### Files Installed
- `bash-tool-access-control.py` - Command rule blocking + evasion detection
- `edit-tool-access-control.py` - Edit path protection
- `write-tool-access-control.py` - Write path protection
- `read-tool-access-control.py` - Read/Grep path protection
- `access-control-list.yaml` - Security rules and protected paths

### Runtime Setup

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### IMPORTANT

**Restart your agent for these changes to take effect.**

### Next Steps
1. Run `/hooks` to verify hooks are registered
2. Customize `access-control-list.yaml` to add your own protected paths or rules

### Test the Installation
```
Try running: rm -rf /tmp/test
Expected: Command should be blocked by access control hooks
```
