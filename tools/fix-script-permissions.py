#!/usr/bin/env python3
"""
Automatically fix executable permissions for all script files.

This script makes all shell and Python scripts executable in git,
preventing permission denied errors in CI/CD pipelines.
"""

import os
import subprocess
import sys
from pathlib import Path


def run_git_command(cmd):
    """Run a git command."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERROR: {' '.join(cmd)}", file=sys.stderr)
        print(f"STDERR: {e.stderr}", file=sys.stderr)
        return False


def get_script_files():
    """Get all shell and Python script files."""
    script_patterns = [
        ".github/actions/*/*.sh",
        ".github/actions/*/*.py",
        "scripts/workflows/*.sh",
        "scripts/workflows/lib/*.sh",
        "tools/*.py",
    ]

    excludes = [
        "node_modules",
        ".venv",
        "venv",
    ]

    script_files = []
    repo_root = Path.cwd()

    for pattern in script_patterns:
        for file_path in repo_root.glob(pattern):
            if any(exclude in str(file_path) for exclude in excludes):
                continue
            if file_path.is_file():
                script_files.append(str(file_path))

    return sorted(script_files)


def check_file_mode(file_path):
    """Check if a file has executable mode in git."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--stage", file_path],
            capture_output=True,
            text=True,
            check=True,
        )

        output = result.stdout.strip()
        if not output:
            return None

        file_mode = output.split()[0]
        return file_mode == "100755"
    except subprocess.CalledProcessError:
        return None


def main():
    """Fix executable permissions for all script files."""
    script_files = get_script_files()

    if not script_files:
        print("[OK] No script files found")
        return 0

    print(f"Checking {len(script_files)} script files...")
    print()

    files_to_fix = []

    for file_path in script_files:
        mode_ok = check_file_mode(file_path)

        if mode_ok is None:
            print(f"[SKIP] {file_path} (not in git)")
        elif mode_ok:
            print(f"[OK] {file_path}")
        else:
            print(f"[FAIL] {file_path}")
            files_to_fix.append(file_path)

    print()

    if not files_to_fix:
        print("[OK] All script files already have executable permissions!")
        return 0

    print(f"Fixing {len(files_to_fix)} files...")
    print()

    for file_path in files_to_fix:
        if run_git_command(["git", "update-index", "--chmod=+x", file_path]):
            print(f"[OK] Fixed: {file_path}")
        else:
            print(f"[FAIL] Failed to fix: {file_path}")
            return 1

    print()
    print("=" * 70)
    print(f"[OK] Successfully fixed {len(files_to_fix)} files!")
    print("=" * 70)
    print()
    print("Changes have been staged. Review with: git diff --cached")
    print('Commit with: git commit -m "fix: Correct script executable permissions"')
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
