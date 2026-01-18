#!/usr/bin/env python3
"""
Check that all script files have proper executable permissions in git.

This prevents the 'Permission denied' error when GitHub Actions runners
execute bash/shell scripts and Python scripts.

Exit codes:
  0 - All scripts have proper permissions
  1 - Some scripts are missing executable permissions
  2 - Error running git command
"""

import os
import subprocess
import sys
from pathlib import Path


def run_git_command(cmd):
    """Run a git command and return output."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=os.getcwd(), check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Git command failed: {' '.join(cmd)}", file=sys.stderr)
        print(f"STDERR: {e.stderr}", file=sys.stderr)
        return None


def get_script_files():
    """Get all shell and Python script files that should be executable."""
    script_patterns = [
        ".github/actions/*/*.sh",
        ".github/actions/*/*.py",
        "scripts/workflows/*.sh",
        "scripts/workflows/lib/*.sh",
        "tools/*.py",
    ]

    # Exclude specific directories/files
    excludes = [
        "node_modules",
        ".venv",
        "venv",
    ]

    script_files = []
    repo_root = Path.cwd()

    for pattern in script_patterns:
        for file_path in repo_root.glob(pattern):
            # Skip if in exclude list
            if any(exclude in str(file_path) for exclude in excludes):
                continue
            if file_path.is_file():
                script_files.append(str(file_path))

    return sorted(script_files)


def check_file_mode(file_path):
    """
    Check if a file has executable mode in git.

    Returns:
      True if file has executable mode (100755)
      False if file has regular mode (100644)
      None if file is not tracked in git
    """
    # Get file mode from git
    cmd = ["git", "ls-files", "--stage", file_path]
    output = run_git_command(cmd)

    if not output:
        # File not in git index
        return None

    # Parse git ls-files output: "100644 blob_hash stage_number filename"
    parts = output.split()
    if not parts:
        return None

    file_mode = parts[0]

    # Check if executable (100755)
    if file_mode == "100755":
        return True
    elif file_mode == "100644":
        return False
    else:
        return None


def main():
    """Check all script files have executable permissions."""
    script_files = get_script_files()

    if not script_files:
        print("[OK] No script files found to check")
        return 0

    print(f"Checking permissions for {len(script_files)} script files...")
    print()

    failed_files = []

    for file_path in script_files:
        mode_ok = check_file_mode(file_path)

        if mode_ok is None:
            # File not tracked in git, skip
            print(f"[SKIP] {file_path} (not in git index)")
            continue
        elif mode_ok:
            print(f"[OK] {file_path}")
        else:
            print(f"[FAIL] {file_path} - MISSING executable bit")
            failed_files.append(file_path)

    print()

    if failed_files:
        print("=" * 70)
        print("ERROR: The following script files are missing executable permissions")
        print("=" * 70)
        print()
        print("These files need to be marked as executable in git:")
        for file_path in failed_files:
            print(f"  {file_path}")
        print()
        print("To fix, run:")
        print("  python tools/fix-script-permissions.py")
        print()
        print("Or manually:")
        for file_path in failed_files:
            print(f"  git update-index --chmod=+x {file_path}")
        print()
        return 1

    print("[OK] All script files have proper executable permissions!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
