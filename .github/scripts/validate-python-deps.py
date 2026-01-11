#!/usr/bin/env python3
"""Validate that all Python imports match declared dependencies.

This script helps catch missing dependencies in pyproject.toml by:
1. Parsing all import statements from source code
2. Checking if imported packages are declared in pyproject.toml
3. Failing CI if critical imports are missing

Run this in CI after installing dependencies to ensure everything is declared.
"""

import argparse
import ast
import sys
from pathlib import Path
from typing import Set

# Map of package import names to PyPI package names
IMPORT_TO_PACKAGE = {
    "agent_framework": "agent-framework",
    "agent_framework_ag_ui": "agent-framework-ag-ui",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "pydantic": "pydantic",
    "pydantic_settings": "pydantic-settings",
    "sqlalchemy": "sqlalchemy",
    "azure": "azure-identity",  # Simplified - azure has many subpackages
    "structlog": "structlog",
    "tenacity": "tenacity",
    "httpx": "httpx",
    "yt_dlp": "yt-dlp",
    "opentelemetry": "opentelemetry-api",  # Simplified - has many subpackages
    "pytest": "pytest",
    "shared": None,  # Local package
    "api": None,  # Local package
}

# Critical packages that MUST be present (not optional)
CRITICAL_PACKAGES = {
    "agent-framework",
    "agent-framework-ag-ui",
    "fastapi",
    "uvicorn",
}


class ImportVisitor(ast.NodeVisitor):
    """AST visitor to extract import statements."""

    def __init__(self):
        self.imports: Set[str] = set()

    def visit_Import(self, node):
        """Visit import statements like: import foo"""
        for alias in node.names:
            # Get the top-level package name
            package = alias.name.split(".")[0]
            self.imports.add(package)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """Visit from ... import statements"""
        if node.module:
            # Get the top-level package name
            package = node.module.split(".")[0]
            self.imports.add(package)
        self.generic_visit(node)


def extract_imports_from_file(file_path: Path) -> Set[str]:
    """Extract all import package names from a Python file."""
    try:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))
        visitor = ImportVisitor()
        visitor.visit(tree)
        return visitor.imports
    except SyntaxError:
        print(f"Warning: Syntax error in {file_path}, skipping")
        return set()
    except Exception as e:
        print(f"Warning: Error parsing {file_path}: {e}, skipping")
        return set()


def extract_dependencies_from_pyproject(pyproject_path: Path) -> Set[str]:
    """Extract declared dependencies from pyproject.toml."""
    import re

    content = pyproject_path.read_text(encoding="utf-8")
    dependencies = set()

    # Find dependencies array (handles multi-line)
    in_deps = False
    for line in content.splitlines():
        if "dependencies = [" in line or (in_deps and "]" not in line):
            in_deps = True
            # Extract package names from quotes
            matches = re.findall(r'"([a-zA-Z0-9_-]+)', line)
            dependencies.update(matches)
        if in_deps and "]" in line:
            in_deps = False

    return dependencies


def main():
    parser = argparse.ArgumentParser(description="Validate Python dependencies")
    parser.add_argument("src_dir", type=Path, help="Source directory to scan")
    parser.add_argument("pyproject", type=Path, help="Path to pyproject.toml")
    parser.add_argument(
        "--critical-only",
        action="store_true",
        help="Only check critical dependencies",
    )
    args = parser.parse_args()

    # Extract all imports from source files
    print(f"Scanning {args.src_dir} for imports...")
    all_imports = set()
    for py_file in args.src_dir.rglob("*.py"):
        if "__pycache__" in str(py_file):
            continue
        imports = extract_imports_from_file(py_file)
        all_imports.update(imports)

    # Map imports to package names
    required_packages = set()
    for imp in all_imports:
        package = IMPORT_TO_PACKAGE.get(imp)
        if package:  # None means it's a local package
            required_packages.add(package)

    print(f"Found {len(required_packages)} required packages")

    # Extract declared dependencies
    declared_deps = extract_dependencies_from_pyproject(args.pyproject)
    print(f"Found {len(declared_deps)} declared dependencies")

    # Check for missing dependencies
    if args.critical_only:
        missing = CRITICAL_PACKAGES - declared_deps
        check_set = CRITICAL_PACKAGES
    else:
        missing = required_packages - declared_deps
        check_set = required_packages

    if missing:
        print("\n❌ MISSING DEPENDENCIES:")
        for pkg in sorted(missing):
            print(f"  - {pkg}")
        print(f"\nAdd these to {args.pyproject} dependencies array")
        return 1

    print(f"\n✅ All {len(check_set)} required dependencies are declared")
    return 0


if __name__ == "__main__":
    sys.exit(main())
