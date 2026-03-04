---
model: opus
description: Interactive workflow to modify existing Access Control security settings
---

# Purpose

Guide the user through modifying their Access Control security configuration. Allows adding/removing protected paths, adding/removing rules, and adjusting protection levels.

## Variables

SKILL_DIR: .claude/skills/access-control
GLOBAL_SETTINGS: ~/.claude/settings.json
GLOBAL_ACL: ~/.claude/hooks/access-control/access-control-list.yaml
PROJECT_SETTINGS: .claude/settings.json
PROJECT_ACL: .claude/hooks/access-control/access-control-list.yaml
LOCAL_SETTINGS: .claude/settings.local.json

## Instructions

- Use the AskUserQuestion tool at each decision point
- Always verify settings exist before attempting modifications
- If no settings found, redirect to install workflow
- Validate YAML syntax after modifications
- Show before/after comparison for user confirmation

## Workflow

### Step 1: Determine Settings Level

1. Use AskUserQuestion:

```
Question: "Which settings level do you want to modify?"
Options:
- Global (all projects) - ~/.claude/
- Project (shared with team) - .claude/
- Project Personal - .claude/settings.local.json
```

2. Set paths based on choice:
   - **Global**: SETTINGS=`~/.claude/settings.json`, ACL=`~/.claude/hooks/access-control/access-control-list.yaml`
   - **Project**: SETTINGS=`.claude/settings.json`, ACL=`.claude/hooks/access-control/access-control-list.yaml`
   - **Local**: SETTINGS=`.claude/settings.local.json`, ACL=`.claude/hooks/access-control/access-control-list.yaml`

### Step 2: Verify Installation Exists

3. Use Read tool to check if SETTINGS and ACL files exist

4. **If either file doesn't exist**:
   - Report: "Access Control is not installed at this level."
   - Use AskUserQuestion:
   ```
   Question: "Would you like to install Access Control now?"
   Options:
   - Yes, install it
   - No, cancel
   ```
   - If Yes: Read and execute [install_access_control_ag_workflow.md](install_access_control_ag_workflow.md)
   - If No: Exit workflow

5. **If both files exist**: Continue to Step 3

### Step 3: Determine Modification Type

6. Use AskUserQuestion:

```
Question: "What would you like to modify?"
Options:
- Add/Remove Protected Paths (restrict file/directory access)
- Add/Remove Blocked Commands (block specific bash commands)
- View Current Configuration
```

### Branch A: Modify Protected Paths

7. **If "Add/Remove Protected Paths"**: Use AskUserQuestion:

```
Question: "What action would you like to take?"
Options:
- Add a new protected path
- Remove an existing protected path
- List all protected paths
```

8. **Add new protected path**:
   a. Use AskUserQuestion:
   ```
   Question: "What protection level should this path have?"
   Options:
   - Zero Access (no operations allowed - for secrets/credentials)
   - Read Only (can read, cannot modify - for configs)
   - No Delete (can read/write/edit, cannot delete - for important files)
   ```

   b. Use AskUserQuestion (text input expected via "Other"):
   ```
   Question: "Enter the path to protect (e.g., ~/.aws/, /etc/passwd, ./config/):"
   Options:
   - ~/.ssh/ (SSH keys)
   - ~/.aws/ (cloud credentials)
   - Other (enter custom path)
   ```

   c. Read current access-control-list.yaml

   d. Add path to appropriate section:
      - Zero Access → `zeroAccessPaths`
      - Read Only → `readOnlyPaths`
      - No Delete → `noDeletePaths`

   e. Write updated access-control-list.yaml

   f. Show confirmation with before/after

9. **Remove protected path**:
   a. Read access-control-list.yaml and list all protected paths
   b. Use AskUserQuestion to select path to remove
   c. Remove path from appropriate section
   d. Write updated access-control-list.yaml

10. **List protected paths**:
    a. Read access-control-list.yaml
    b. Display formatted list of all paths by category

### Branch B: Modify Blocked Commands

11. **If "Add/Remove Blocked Commands"**: Use AskUserQuestion:

```
Question: "What action would you like to take?"
Options:
- Add a new blocked command rule
- Remove an existing rule
- List all blocked rules
```

12. **Add new blocked rule**:
    a. Use AskUserQuestion:
    ```
    Question: "How would you like to specify the command to block?"
    Options:
    - Enter exact command name (e.g., "terraform", "fly")
    - Describe in natural language (I'll create the rule)
    ```

    b. **If exact command**:
       - Ask for command name (token[0])
       - Ask for subcommand if needed
       - Ask for flags or args if needed
       - Ask for reason/description
       - Ask for action: block or ask

    c. **If natural language**:
       - Parse description
       - Generate appropriate structured rule
       - Show rule to user for confirmation

    d. Read access-control-list.yaml

    e. Add to `bashToolRules`:
    ```yaml
    - id: [generated-id]
      command: [command]
      reason: [user_reason]
      action: block
    ```

    f. Write updated access-control-list.yaml

13. **Remove rule**:
    a. Read access-control-list.yaml and list all rules
    b. Use AskUserQuestion to select rule to remove
    c. Remove rule
    d. Write updated access-control-list.yaml

### Branch C: View Configuration

14. **If "View Current Configuration"**:
    a. Read access-control-list.yaml
    b. Read settings.json
    c. Display formatted configuration

### Step 4: Confirm and Apply Changes

15. After any modification, show the change:

```
## Proposed Change

**File**: [ACL file path]

**Before**:
[relevant section before]

**After**:
[relevant section after]
```

16. Use AskUserQuestion:
```
Question: "Apply this change?"
Options:
- Yes, apply
- No, cancel
```

17. **If Yes**: Write the changes
18. **If No**: Discard changes and report cancellation

### Step 5: Restart Reminder

19. **IMPORTANT**: After any modifications are applied, you MUST tell the user:

> **Restart your agent for these changes to take effect.**

## Report

## Access Control Configuration Updated

**Settings Level**: [Global/Project/Project Personal]
**Modification Type**: [Path Protection/Command Blocking/View]

### Changes Made

[For Path Protection]
**Action**: Added/Removed path
**Path**: `[path]`
**Protection Level**: [Zero Access/Read Only/No Delete]

[For Command Blocking]
**Action**: Added/Removed rule
**Rule ID**: [id]
**Reason**: [reason]

### Current Configuration Summary

**Zero Access Paths** (no operations):
- [list paths]

**Read Only Paths** (read only):
- [list paths]

**No Delete Paths** (no delete):
- [list paths]

**Blocked Command Rules**: [count] rules

### IMPORTANT

**Restart your agent for these changes to take effect.**

Run `/hooks` after restart to verify the changes are active.
