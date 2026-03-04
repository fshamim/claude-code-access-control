# /// script
# requires-python = ">=3.8"
# dependencies = ["pyyaml"]
# ///
"""
Claude Code Access Control - Bash Hook
=======================================

Blocks dangerous commands before execution via PreToolUse hook.
Loads rules from access-control-list.yaml for easy customization.

Exit codes:
  0 = Allow command (or JSON output with permissionDecision)
  2 = Block command (stderr fed back to Claude)

JSON output for ask rules:
  {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "..."}}
"""

import json
import sys
import os
import fnmatch
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional

import yaml


# ============================================================================
# OPERATION PATTERNS - used for path protection checks (not user-configurable)
# ============================================================================
# {path} will be replaced with the escaped path at runtime

import re

WRITE_PATTERNS = [
    (r'>\s*{path}', "write"),
    (r'\btee\s+(?!.*-a).*{path}', "write"),
]

APPEND_PATTERNS = [
    (r'>>\s*{path}', "append"),
    (r'\btee\s+-a\s+.*{path}', "append"),
    (r'\btee\s+.*-a.*{path}', "append"),
]

EDIT_PATTERNS = [
    (r'\bsed\s+-i.*{path}', "edit"),
    (r'\bperl\s+-[^\s]*i.*{path}', "edit"),
    (r'\bawk\s+-i\s+inplace.*{path}', "edit"),
]

MOVE_COPY_PATTERNS = [
    (r'\bmv\s+.*\s+{path}', "move"),
    (r'\bcp\s+.*\s+{path}', "copy"),
]

DELETE_PATTERNS = [
    (r'\brm\s+.*{path}', "delete"),
    (r'\bunlink\s+.*{path}', "delete"),
    (r'\brmdir\s+.*{path}', "delete"),
    (r'\bshred\s+.*{path}', "delete"),
]

PERMISSION_PATTERNS = [
    (r'\bchmod\s+.*{path}', "chmod"),
    (r'\bchown\s+.*{path}', "chown"),
    (r'\bchgrp\s+.*{path}', "chgrp"),
]

TRUNCATE_PATTERNS = [
    (r'\btruncate\s+.*{path}', "truncate"),
    (r':\s*>\s*{path}', "truncate"),
]

# Combined patterns for read-only paths (block ALL modifications)
READ_ONLY_BLOCKED = (
    WRITE_PATTERNS +
    APPEND_PATTERNS +
    EDIT_PATTERNS +
    MOVE_COPY_PATTERNS +
    DELETE_PATTERNS +
    PERMISSION_PATTERNS +
    TRUNCATE_PATTERNS
)

# Patterns for no-delete paths (block ONLY delete operations)
NO_DELETE_BLOCKED = DELETE_PATTERNS


# ============================================================================
# CONFIGURATION LOADING
# ============================================================================

def get_config_path() -> Path:
    """Get path to access-control-list.yaml, checking multiple locations."""
    # 1. Check project hooks directory (installed location)
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if project_dir:
        project_config = Path(project_dir) / ".claude" / "hooks" / "access-control" / "access-control-list.yaml"
        if project_config.exists():
            return project_config

    # 2. Check script's own directory (installed location)
    script_dir = Path(__file__).parent
    local_config = script_dir / "access-control-list.yaml"
    if local_config.exists():
        return local_config

    # 3. Check skill root directory (development location)
    skill_root = script_dir.parent.parent / "access-control-list.yaml"
    if skill_root.exists():
        return skill_root

    return local_config  # Default, even if it doesn't exist


def load_config() -> Dict[str, Any]:
    """Load rules from YAML config file."""
    config_path = get_config_path()

    if not config_path.exists():
        print(f"Warning: Config not found at {config_path}", file=sys.stderr)
        return {"bashToolRules": [], "zeroAccessPaths": [], "readOnlyPaths": [], "noDeletePaths": []}

    with open(config_path, "r") as f:
        return yaml.safe_load(f) or {}


# ============================================================================
# COMMAND TOKENIZER
# ============================================================================

def tokenize_command(command: str) -> List[str]:
    """Tokenize a shell command, respecting single and double quoted strings."""
    tokens = []
    current = ""
    in_quote: Optional[str] = None

    for char in command:
        if in_quote:
            if char == in_quote:
                in_quote = None
            else:
                current += char
        elif char in ('"', "'"):
            in_quote = char
        elif char in (' ', '\t'):
            if current:
                tokens.append(current)
                current = ""
        else:
            current += char

    if current:
        tokens.append(current)

    return tokens


def is_flag(token: str) -> bool:
    """Check if a token is a flag (starts with -)."""
    return token.startswith('-')


# ============================================================================
# STRUCTURED RULE MATCHING
# ============================================================================

def match_rule(command: str, tokens: List[str], rule: Dict[str, Any]) -> bool:
    """Check if a command matches a structured rule.

    Rule fields (all optional except at least one matcher must be set):
      command      - Exact or glob match on tokens[0]
      subcommand   - Exact match on tokens[1]
      flags        - ANY of these flags must be present in remaining tokens (OR)
      args         - ALL of these must match some non-flag arg (AND, glob ok)
      contains     - Substring must be present in full command (case-insensitive)
      excludes     - Substring must NOT be present in full command
      contains_all - All substrings must be present in full command
    """
    if not tokens:
        return False

    # 1. Match command (token[0]) — supports glob
    cmd = rule.get("command", "")
    if cmd:
        t0 = tokens[0].lower()
        cmd_lower = cmd.lower()
        if '*' in cmd or '?' in cmd:
            if not fnmatch.fnmatch(t0, cmd_lower):
                return False
        else:
            if t0 != cmd_lower:
                return False

    # 2. Match subcommand (token[1]) — exact
    subcommand = rule.get("subcommand", "")
    if subcommand:
        if len(tokens) < 2:
            return False
        if tokens[1].lower() != subcommand.lower():
            return False

    # Split remaining tokens into flags and positional args
    start_idx = 2 if subcommand else 1
    remaining = tokens[start_idx:]
    flags_in_cmd = [t for t in remaining if is_flag(t)]
    args_in_cmd = [t for t in remaining if not is_flag(t)]

    # 3. Match flags — ANY of listed flags must be present (OR logic)
    rule_flags = rule.get("flags", [])
    if rule_flags:
        if not any(f in flags_in_cmd for f in rule_flags):
            return False

    # 4. Match args — ALL listed args must match some positional arg (AND logic, glob ok)
    rule_args = rule.get("args", [])
    if rule_args:
        for rule_arg in rule_args:
            rule_arg_lower = rule_arg.lower()
            args_lower = [a.lower() for a in args_in_cmd]
            if '*' in rule_arg or '?' in rule_arg:
                if not any(fnmatch.fnmatch(a, rule_arg_lower) for a in args_lower):
                    return False
            else:
                if rule_arg_lower not in args_lower:
                    return False

    # 5. Contains — substring match in full command (case-insensitive)
    contains = rule.get("contains", "")
    if contains:
        if contains.lower() not in command.lower():
            return False

    # 6. Excludes — must NOT be in full command
    excludes = rule.get("excludes", "")
    if excludes:
        if excludes.lower() in command.lower():
            return False

    # 7. Contains all — all substrings must be present
    for substr in rule.get("contains_all", []):
        if substr.lower() not in command.lower():
            return False

    return True


# ============================================================================
# EVASION BYPASS DETECTORS
# ============================================================================

def check_evasion_bypasses(command: str, tokens: List[str]) -> Tuple[bool, str]:
    """Detect known bypass techniques that circumvent normal rule matching.

    These run before rule matching to catch evasion attempts early.
    """
    if not tokens:
        return False, ""

    cmd_lower = command.lower()

    # Bypass 1: eval — block unconditionally
    # eval with any dynamic string is inherently unsafe
    if tokens[0].lower() == "eval":
        return True, "eval is not permitted (access control policy)"

    # Bypass 2: base64 decode + execution construct
    # e.g. F=$(echo "BASE64" | base64 -d) && cat "$F"
    if "base64" in cmd_lower and ("-d" in cmd_lower or "--decode" in cmd_lower):
        execution_constructs = ["$(", "`", "&&", "||", "|", "exec ", "sh ", "bash ", "source "]
        if any(construct in cmd_lower for construct in execution_constructs):
            return True, "base64 decode combined with command execution (evasion attempt detected)"

    # Bypass 3: find -exec with dangerous operations
    # e.g. find /path -name "id_rsa" -exec cat {} \;
    if tokens[0].lower() == "find":
        dangerous_exec_cmds = {
            "cat", "cp", "mv", "base64", "curl", "wget", "nc", "netcat",
            "ssh", "scp", "python", "python3", "perl", "ruby", "sh", "bash",
            "tee", "dd", "openssl",
        }
        for i, token in enumerate(tokens):
            if token in ("-exec", "-execdir"):
                exec_tokens = []
                for j in range(i + 1, len(tokens)):
                    if tokens[j] in (";", "\\;", "+"):
                        break
                    exec_tokens.append(tokens[j])
                if exec_tokens and exec_tokens[0].lower() in dangerous_exec_cmds:
                    return True, (
                        f"find -exec with '{exec_tokens[0]}' is not permitted "
                        f"(evasion attempt detected)"
                    )

    return False, ""


# ============================================================================
# PATH CHECKING (for zeroAccessPaths / readOnlyPaths / noDeletePaths)
# ============================================================================

def is_glob_pattern(pattern: str) -> bool:
    """Check if pattern contains glob wildcards."""
    return '*' in pattern or '?' in pattern or '[' in pattern


def glob_to_regex(glob_pattern: str) -> str:
    """Convert a glob pattern to a regex pattern for matching in commands."""
    result = ""
    for char in glob_pattern:
        if char == '*':
            result += r'[^\s/]*'
        elif char == '?':
            result += r'[^\s/]'
        elif char in r'\.^$+{}[]|()':
            result += '\\' + char
        else:
            result += char
    return result


def check_path_patterns(
    command: str,
    path: str,
    patterns: List[Tuple[str, str]],
    path_type: str,
) -> Tuple[bool, str]:
    """Check command against operation patterns for a specific path."""
    if is_glob_pattern(path):
        glob_regex = glob_to_regex(path)
        for pattern_template, operation in patterns:
            try:
                cmd_prefix = pattern_template.replace("{path}", "")
                if cmd_prefix and re.search(cmd_prefix + glob_regex, command, re.IGNORECASE):
                    return True, f"Blocked: {operation} operation on {path_type} {path}"
            except re.error:
                continue
    else:
        expanded = os.path.expanduser(path)
        escaped_expanded = re.escape(expanded)
        escaped_original = re.escape(path)

        for pattern_template, operation in patterns:
            pattern_expanded = pattern_template.replace("{path}", escaped_expanded)
            pattern_original = pattern_template.replace("{path}", escaped_original)
            try:
                if re.search(pattern_expanded, command, re.IGNORECASE) or \
                   re.search(pattern_original, command, re.IGNORECASE):
                    return True, f"Blocked: {operation} operation on {path_type} {path}"
            except re.error:
                continue

    return False, ""


# ============================================================================
# MAIN CHECK
# ============================================================================

def check_command(command: str, config: Dict[str, Any]) -> Tuple[bool, bool, str]:
    """Check if command should be blocked or requires confirmation.

    Returns: (blocked, ask, reason)
      - blocked=True, ask=False  → Block the command
      - blocked=False, ask=True  → Show confirmation dialog
      - blocked=False, ask=False → Allow the command
    """
    tokens = tokenize_command(command)

    # 1. Evasion bypass detectors (run first)
    evasion_blocked, evasion_reason = check_evasion_bypasses(command, tokens)
    if evasion_blocked:
        return True, False, f"Blocked: {evasion_reason}"

    # 2. Structured bash tool rules
    for rule in config.get("bashToolRules", []):
        if match_rule(command, tokens, rule):
            action = rule.get("action", "block")
            reason = rule.get("reason", "Blocked by access control rule")
            if action == "ask":
                return False, True, reason
            else:
                return True, False, f"Blocked: {reason}"

    # 3. Zero-access paths — block ANY operation referencing them
    for zero_path in config.get("zeroAccessPaths", []):
        if is_glob_pattern(zero_path):
            glob_regex = glob_to_regex(zero_path)
            try:
                if re.search(glob_regex, command, re.IGNORECASE):
                    return True, False, f"Blocked: zero-access pattern {zero_path} (no operations allowed)"
            except re.error:
                continue
        else:
            expanded = os.path.expanduser(zero_path)
            escaped_expanded = re.escape(expanded)
            escaped_original = re.escape(zero_path)
            if re.search(escaped_expanded, command, re.IGNORECASE) or \
               re.search(escaped_original, command, re.IGNORECASE):
                return True, False, f"Blocked: zero-access path {zero_path} (no operations allowed)"

    # 4. Read-only paths — block all modifications
    for readonly in config.get("readOnlyPaths", []):
        blocked, reason = check_path_patterns(command, readonly, READ_ONLY_BLOCKED, "read-only path")
        if blocked:
            return True, False, reason

    # 5. No-delete paths — block only deletions
    for no_delete in config.get("noDeletePaths", []):
        blocked, reason = check_path_patterns(command, no_delete, NO_DELETE_BLOCKED, "no-delete path")
        if blocked:
            return True, False, reason

    return False, False, ""


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:
    config = load_config()

    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        sys.exit(1)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    if tool_name != "Bash":
        sys.exit(0)

    command = tool_input.get("command", "")
    if not command:
        sys.exit(0)

    is_blocked, should_ask, reason = check_command(command, config)

    if is_blocked:
        print(f"SECURITY: {reason}", file=sys.stderr)
        print(f"Command: {command[:100]}{'...' if len(command) > 100 else ''}", file=sys.stderr)
        sys.exit(2)
    elif should_ask:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": reason,
            }
        }
        print(json.dumps(output))
        sys.exit(0)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
