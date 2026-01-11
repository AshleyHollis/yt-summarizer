#!/usr/bin/env python3
"""Parse YAML file(s) and exit non-zero if there's a parse error.

Usage: parse_yaml.py <file>
"""
import sys
import yaml

if len(sys.argv) < 2:
    print("Usage: parse_yaml.py <manifest-file>")
    sys.exit(2)

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as f:
        list(yaml.safe_load_all(f))
except Exception as e:
    print("YAML parse error:", e)
    sys.exit(1)

print("YAML parse OK")
