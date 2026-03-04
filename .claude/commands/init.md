---
description: Initialize a new agent on the claude-code-access-control codebase
allowed-tools: Bash, Read, Glob
---

# Goal

You are getting initialized on the Claude Code Access Control codebase. Your job is to understand the project structure and hook configuration so you can work effectively.

## Instructions

- Do NOT modify any files - this is read-only
- Summarize what you learn, don't dump raw file contents
- Focus on: PreToolUse hooks, access-control-list.yaml rules, protected paths

## Workflow

- `git ls-files`
- Read `README.md`
- Read `.claude/skills/access-control/SKILL.md`
- Read `ai_docs/*.md` (unless there are more than 3 files, then just read ai_docs/README.md)

## Output
Tell the user you're oriented and summarize what you learned.
