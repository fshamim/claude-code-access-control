# /// script
# requires-python = ">=3.8"
# dependencies = ["pyyaml"]
# ///
"""
Access Control Test Runner - Python/UV
=======================================

Tests access control hooks via CLI or interactive mode.

Usage:
  # Interactive mode
  uv run test-access-control.py -i
  uv run test-access-control.py --interactive

  # CLI mode - test a single command or path
  uv run test-access-control.py <hook> <tool_name> <command_or_path> [--expect-blocked|--expect-allowed]

Examples:
  # Interactive mode
  uv run test-access-control.py -i

  # Test bash hook blocks rm -rf
  uv run test-access-control.py bash Bash "rm -rf /tmp" --expect-blocked

  # Test edit hook blocks zero-access path
  uv run test-access-control.py edit Edit "~/.ssh/id_rsa" --expect-blocked

  # Test bash allows safe command
  uv run test-access-control.py bash Bash "ls -la" --expect-allowed

  # Test read hook blocks secret file
  uv run test-access-control.py read Read "~/.ssh/id_rsa" --expect-blocked

Exit codes:
  0 = Test passed (expectation matched)
  1 = Test failed (expectation not matched)
"""

import subprocess
import json
import sys
import os
import fnmatch
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import yaml

# Import check_command and related from the bash hook (avoids duplication)
import importlib.util

spec = importlib.util.spec_from_file_location(
    "bash_tool",
    Path(__file__).parent / "bash-tool-access-control.py"
)
bash_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bash_tool)

READ_ONLY_BLOCKED = bash_tool.READ_ONLY_BLOCKED
NO_DELETE_BLOCKED = bash_tool.NO_DELETE_BLOCKED


def is_glob_pattern(pattern: str) -> bool:
    return '*' in pattern or '?' in pattern or '[' in pattern


def match_path(file_path: str, pattern: str) -> bool:
    """Match file path against pattern, supporting prefix and glob matching."""
    expanded_pattern = os.path.expanduser(pattern)
    normalized = os.path.normpath(file_path)
    expanded_normalized = os.path.expanduser(normalized)

    if is_glob_pattern(pattern):
        basename = os.path.basename(expanded_normalized)
        basename_lower = basename.lower()
        pattern_lower = pattern.lower()
        expanded_pattern_lower = expanded_pattern.lower()

        if fnmatch.fnmatch(basename_lower, expanded_pattern_lower):
            return True
        if fnmatch.fnmatch(basename_lower, pattern_lower):
            return True
        if fnmatch.fnmatch(expanded_normalized.lower(), expanded_pattern_lower):
            return True
        return False
    else:
        if expanded_normalized.startswith(expanded_pattern) or \
           expanded_normalized == expanded_pattern.rstrip('/'):
            return True
        return False


# ============================================================================
# CONFIG LOADING
# ============================================================================

def get_script_dir() -> Path:
    return Path(__file__).parent


def get_config_path() -> Path:
    """Get path to access-control-list.yaml."""
    script_dir = get_script_dir()

    local_config = script_dir / "access-control-list.yaml"
    if local_config.exists():
        return local_config

    skill_root = script_dir.parent.parent / "access-control-list.yaml"
    if skill_root.exists():
        return skill_root

    return local_config


def load_config() -> Dict[str, Any]:
    config_path = get_config_path()

    if not config_path.exists():
        return {"bashToolRules": [], "zeroAccessPaths": [], "readOnlyPaths": [], "noDeletePaths": []}

    with open(config_path, "r") as f:
        return yaml.safe_load(f) or {}


# ============================================================================
# DIRECT CHECKING (for interactive mode — no subprocess needed)
# ============================================================================

def check_bash_command(command: str, config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Check bash command using the bash hook's logic. Returns (blocked_or_ask, reasons)."""
    blocked, ask, reason = bash_tool.check_command(command, config)
    if blocked:
        return True, [reason]
    if ask:
        return True, [f"ASK: {reason}"]
    return False, []


def check_file_path(file_path: str, config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Check file path for Edit/Write/Read tools. Returns (blocked, reasons)."""
    reasons = []

    for zero_path in config.get("zeroAccessPaths", []):
        if match_path(file_path, zero_path):
            reasons.append(f"zero-access path: {zero_path}")

    for readonly in config.get("readOnlyPaths", []):
        if match_path(file_path, readonly):
            reasons.append(f"read-only path: {readonly}")

    return len(reasons) > 0, reasons


def check_read_path(file_path: str, config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Check file path for Read/Grep tools. Returns (blocked, reasons)."""
    reasons = []

    for zero_path in config.get("zeroAccessPaths", []):
        if match_path(file_path, zero_path):
            reasons.append(f"zero-access path: {zero_path}")

    return len(reasons) > 0, reasons


# ============================================================================
# INTERACTIVE MODE
# ============================================================================

def print_banner():
    print("\n" + "=" * 60)
    print("  Access Control Interactive Tester")
    print("=" * 60)
    print("  Test commands and paths against security rules.")
    print("  Type 'quit' or 'q' to exit.")
    print("=" * 60 + "\n")


def prompt_tool_selection() -> Optional[str]:
    print("Select tool to test:")
    print("  [1] Bash  - Test shell commands")
    print("  [2] Edit  - Test file paths for edit operations")
    print("  [3] Write - Test file paths for write operations")
    print("  [4] Read  - Test file paths for read/grep operations")
    print("  [q] Quit")
    print()

    while True:
        choice = input("Tool [1/2/3/4/q]> ").strip().lower()

        if choice in ('q', 'quit'):
            return None
        elif choice in ('1', 'bash'):
            return 'Bash'
        elif choice in ('2', 'edit'):
            return 'Edit'
        elif choice in ('3', 'write'):
            return 'Write'
        elif choice in ('4', 'read'):
            return 'Read'
        else:
            print("Invalid choice. Enter 1, 2, 3, 4, or q.")


def run_interactive_mode():
    config = load_config()
    print_banner()

    bash_rules = len(config.get("bashToolRules", []))
    zero_paths = len(config.get("zeroAccessPaths", []))
    readonly_paths = len(config.get("readOnlyPaths", []))
    nodelete_paths = len(config.get("noDeletePaths", []))
    print(f"Loaded: {bash_rules} bash rules, {zero_paths} zero-access, {readonly_paths} read-only, {nodelete_paths} no-delete paths\n")

    while True:
        tool = prompt_tool_selection()
        if tool is None:
            print("\nGoodbye!")
            break

        print()
        prompt_text = "Command> " if tool == 'Bash' else "Path> "

        try:
            user_input = input(prompt_text).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not user_input or user_input.lower() in ('q', 'quit'):
            print("\nGoodbye!")
            break

        if tool == 'Bash':
            blocked, reasons = check_bash_command(user_input, config)
        elif tool == 'Read':
            blocked, reasons = check_read_path(user_input, config)
        else:
            blocked, reasons = check_file_path(user_input, config)

        print()
        if blocked:
            print(f"\033[91mBLOCKED\033[0m - {len(reasons)} rule(s) matched:")
            for reason in reasons:
                print(f"   - {reason}")
        else:
            print(f"\033[92mALLOWED\033[0m - No rules matched")
        print()


# ============================================================================
# CLI MODE
# ============================================================================

def get_hook_path(hook_type: str) -> Path:
    hooks = {
        "bash": "bash-tool-access-control.py",
        "edit": "edit-tool-access-control.py",
        "write": "write-tool-access-control.py",
        "read": "read-tool-access-control.py",
    }
    if hook_type not in hooks:
        print(f"Error: Unknown hook type '{hook_type}'. Use: {list(hooks.keys())}")
        sys.exit(1)
    return get_script_dir() / hooks[hook_type]


def build_tool_input(tool_name: str, value: str) -> dict:
    if tool_name == "Bash":
        return {"command": value}
    elif tool_name in ("Edit", "Write", "Read"):
        return {"file_path": os.path.expanduser(value)}
    else:
        return {"command": value}


def run_test(hook_type: str, tool_name: str, value: str, expectation: str) -> bool:
    hook_path = get_hook_path(hook_type)
    tool_input = build_tool_input(tool_name, value)

    input_json = json.dumps({
        "tool_name": tool_name,
        "tool_input": tool_input,
    })

    try:
        result = subprocess.run(
            ["uv", "run", str(hook_path)],
            input=input_json,
            capture_output=True,
            text=True,
            timeout=10,
        )
        exit_code = result.returncode
        stderr = result.stderr.strip()
    except subprocess.TimeoutExpired:
        print("TIMEOUT")
        return False
    except Exception as e:
        print(f"ERROR: {e}")
        return False

    blocked = exit_code == 2
    expect_blocked = expectation == "blocked"
    passed = blocked == expect_blocked

    expected = "BLOCKED" if expect_blocked else "ALLOWED"
    actual = "BLOCKED" if blocked else "ALLOWED"

    if passed:
        print(f"PASS: {expected} - {value}")
    else:
        print(f"FAIL: Expected {expected}, got {actual} - {value}")
        if stderr:
            print(f"  stderr: {stderr[:200]}")

    return passed


def main():
    if len(sys.argv) >= 2 and sys.argv[1].lower() in ('-i', '--interactive'):
        run_interactive_mode()
        sys.exit(0)

    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    hook_type = sys.argv[1].lower()
    tool_name = sys.argv[2]
    value = sys.argv[3]

    expectation = "blocked"
    if len(sys.argv) > 4:
        flag = sys.argv[4].lower()
        if flag == "--expect-allowed":
            expectation = "allowed"
        elif flag == "--expect-blocked":
            expectation = "blocked"

    passed = run_test(hook_type, tool_name, value, expectation)
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
