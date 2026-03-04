---
model: opus
description: Test all Access Control hooks by running the test script against access-control-list.yaml
---

# Purpose

Validate that all Access Control hooks are working correctly by reading access-control-list.yaml and running test cases against each configured rule and protected path.

## Variables

HOOKS_DIR: .claude/hooks/access-control
ACL_FILE: .claude/hooks/access-control/access-control-list.yaml (if in project) or ~/.claude/hooks/access-control/access-control-list.yaml (if global)

## Instructions

- Read the access-control-list.yaml file to get all configured rules and paths
- For each rule/path, call the test script with appropriate arguments
- The test script echoes JSON into the hooks — it does NOT run actual commands
- Track pass/fail counts and report summary at the end

**IMPORTANT**: You are testing the hooks by piping mock data into them. DO NOT run actual dangerous commands. No dangerous commands are executed.

## Workflow

### Step 0: Determine Scope

1. Check if running in a project or global context:
   - If project → ACL_FILE = `.claude/hooks/access-control/access-control-list.yaml`
   - If global → ACL_FILE = `~/.claude/hooks/access-control/access-control-list.yaml`

### Step 1: Read Configuration

2. Read the access-control-list.yaml file from HOOKS_DIR

3. Extract sections:
   - `bashToolRules` - structured command rules
   - `zeroAccessPaths` - paths with no access allowed
   - `readOnlyPaths` - paths with read-only access
   - `noDeletePaths` - paths that cannot be deleted

### Step 2: Test bashToolRules

4. For each rule in `bashToolRules`, generate a matching test command:

| Rule ID                  | Test Command                           |
| ------------------------ | -------------------------------------- |
| `rm-recursive-or-force`  | `rm -rf /tmp/test`                     |
| `git-reset-hard`         | `git reset --hard HEAD`                |
| `git-force-push`         | `git push --force origin main`         |
| `chmod-world-writable`   | `chmod 777 /tmp/test`                  |
| `sql-delete-without-where` | `sqlite3 db 'DELETE FROM users;'`    |
| `terraform-destroy`      | `terraform destroy`                    |

5. Run each test:
```bash
uv run [HOOKS_DIR]/test-access-control.py bash Bash "[test_command]" --expect-blocked
```

6. Test that safe commands are allowed:
```bash
uv run [HOOKS_DIR]/test-access-control.py bash Bash "ls -la" --expect-allowed
uv run [HOOKS_DIR]/test-access-control.py bash Bash "git status" --expect-allowed
uv run [HOOKS_DIR]/test-access-control.py bash Bash "npm install" --expect-allowed
```

### Step 3: Test Evasion Bypass Detection

7. Test that bypass attempts are blocked:

```bash
# eval — should be blocked
uv run [HOOKS_DIR]/test-access-control.py bash Bash "eval \"cat ~/.ssh/id_rsa\"" --expect-blocked

# base64 decode + execution — should be blocked
uv run [HOOKS_DIR]/test-access-control.py bash Bash "F=$(echo 'L2V0Yy9wYXNzd2Q=' | base64 -d) && cat \"\$F\"" --expect-blocked

# find -exec cat — should be blocked
uv run [HOOKS_DIR]/test-access-control.py bash Bash "find ~/.ssh -name 'id_rsa' -exec cat {} \\;" --expect-blocked
```

### Step 4: Test zeroAccessPaths

8. For each path in `zeroAccessPaths`, test that ALL access is blocked:

```bash
# Test bash access (read)
uv run [HOOKS_DIR]/test-access-control.py bash Bash "cat [path]/test" --expect-blocked

# Test edit access
uv run [HOOKS_DIR]/test-access-control.py edit Edit "[path]/test.txt" --expect-blocked

# Test write access
uv run [HOOKS_DIR]/test-access-control.py write Write "[path]/test.txt" --expect-blocked

# Test read tool access
uv run [HOOKS_DIR]/test-access-control.py read Read "[path]/test.txt" --expect-blocked
```

### Step 5: Test readOnlyPaths

9. For each path in `readOnlyPaths`, test that reads are allowed but writes are blocked:

```bash
# Test bash read - should be ALLOWED
uv run [HOOKS_DIR]/test-access-control.py bash Bash "cat [path]" --expect-allowed

# Test bash write - should be BLOCKED
uv run [HOOKS_DIR]/test-access-control.py bash Bash "echo test > [path]/test" --expect-blocked

# Test edit - should be BLOCKED
uv run [HOOKS_DIR]/test-access-control.py edit Edit "[path]/test.txt" --expect-blocked

# Test write - should be BLOCKED
uv run [HOOKS_DIR]/test-access-control.py write Write "[path]/test.txt" --expect-blocked
```

### Step 6: Test noDeletePaths

10. For each path in `noDeletePaths`, test that deletes are blocked but writes are allowed:

```bash
# Test bash delete - should be BLOCKED
uv run [HOOKS_DIR]/test-access-control.py bash Bash "rm [path]/test.txt" --expect-blocked

# Test bash write - should be ALLOWED (noDeletePaths allows writes)
uv run [HOOKS_DIR]/test-access-control.py bash Bash "echo test > [path]/test.txt" --expect-allowed
```

### Step 7: Test Ask Rules

11. Test rules with `action: ask` — these return JSON instead of blocking:

```bash
# SQL DELETE with WHERE - should trigger ask (confirmation dialog)
uv run [HOOKS_DIR]/test-access-control.py bash Bash "sqlite3 test.db 'DELETE FROM users WHERE id=1'" --expect-allowed
# Note: ask rules exit 0 with JSON output, so --expect-allowed is correct here.
# Verify manually that the JSON output contains permissionDecision: "ask"
```

### Step 8: Compile Results

12. Count total passed and failed tests
13. Present the summary report

## Report

Present results in this format:

---

## Access Control Test Results

### bashToolRules
| Test | Command | Expected | Result |
| ---- | ------- | -------- | ------ |
| 1 | `rm -rf /tmp` | BLOCKED | PASS/FAIL |
| 2 | `git reset --hard` | BLOCKED | PASS/FAIL |
| ... | ... | ... | ... |

### Evasion Bypass Detection
| Test | Command | Expected | Result |
| ---- | ------- | -------- | ------ |
| 1 | `eval "..."` | BLOCKED | PASS/FAIL |
| 2 | `base64 -d + exec` | BLOCKED | PASS/FAIL |
| 3 | `find -exec cat` | BLOCKED | PASS/FAIL |

### zeroAccessPaths
| Path | Tool | Expected | Result |
| ---- | ---- | -------- | ------ |
| ~/.ssh/ | Bash (read) | BLOCKED | PASS/FAIL |
| ~/.ssh/ | Edit | BLOCKED | PASS/FAIL |
| ~/.ssh/ | Write | BLOCKED | PASS/FAIL |
| ~/.ssh/ | Read | BLOCKED | PASS/FAIL |

### readOnlyPaths
| Path | Tool | Expected | Result |
| ---- | ---- | -------- | ------ |
| /etc/ | Bash (read) | ALLOWED | PASS/FAIL |
| /etc/ | Bash (write) | BLOCKED | PASS/FAIL |
| /etc/ | Edit | BLOCKED | PASS/FAIL |

### noDeletePaths
| Path | Tool | Expected | Result |
| ---- | ---- | -------- | ------ |
| .claude/ | Bash (delete) | BLOCKED | PASS/FAIL |
| .claude/ | Bash (write) | ALLOWED | PASS/FAIL |

---

### Summary

**Total Tests**: [count]
**Passed**: [count]
**Failed**: [count]

[If all passed]
All Access Control hooks are working correctly.

[If any failed]
Some tests failed. Review the failed tests above and check the hook implementations.
