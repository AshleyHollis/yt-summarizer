#!/usr/bin/env python3
"""
Validate kustomize manifest CPU requests/limits against a threshold.

Usage:
  validate_kustomize.py --file <manifest.yaml> --max-cpu <millicpu> [--name <overlay>]

This script sums container cpu requests for Deployment/StatefulSet/DaemonSet resources,
scaled by replicas, and fails (exit 2) if total requested CPU exceeds max cpu (in mCPU).
"""
import argparse
import sys
from pathlib import Path
import yaml


def parse_cpu(cpu_str: str) -> int:
    """Return millicpu integer for CPU string like '100m', '0.5', '1'."""
    if cpu_str is None:
        return 0
    cpu_str = str(cpu_str).strip()
    if cpu_str.endswith('m'):
        return int(cpu_str[:-1])
    try:
        # Decimal CPU value -> convert to millicpu
        val = float(cpu_str)
        return int(val * 1000)
    except ValueError:
        raise ValueError(f"Unrecognized CPU format: {cpu_str}")


def get_replicas(resource: dict) -> int:
    # Default to 1 if not specified for pod-like resources
    return int(resource.get('spec', {}).get('replicas', 1))


def cpu_from_container(container: dict) -> int:
    reqs = container.get('resources', {}).get('requests', {})
    cpu = reqs.get('cpu') or reqs.get('CPU')
    return parse_cpu(cpu) if cpu else 0


def validate_manifest(path: Path) -> (int, dict):
    total_cpu = 0
    per_kind = {}

    docs = list(yaml.safe_load_all(path.read_text(encoding='utf-8')))
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get('kind')
        if kind not in ('Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'ReplicaController'):
            continue
        meta = doc.get('metadata', {})
        name = meta.get('name', '<unnamed>')
        replicas = get_replicas(doc)
        template = doc.get('spec', {}).get('template', {})
        spec = template.get('spec', {})
        containers = spec.get('containers', [])
        pod_cpu = 0
        for c in containers:
            pod_cpu += cpu_from_container(c)
        resource_cpu = pod_cpu * replicas
        total_cpu += resource_cpu
        per_kind[f"{kind}/{name}"] = {
            'replicas': replicas,
            'pod_cpu_m': pod_cpu,
            'total_cpu_m': resource_cpu,
        }
    return total_cpu, per_kind


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--file', required=True, help='YAML file to inspect (kustomize build output)')
    p.add_argument('--max-cpu', type=int, required=True, help='Max allowed CPU in millicpu (e.g., 1500)')
    p.add_argument('--name', default='overlay', help='Overlay name for messages')
    args = p.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"ERROR: file not found: {path}")
        sys.exit(3)

    total_cpu, per_kind = validate_manifest(path)

    print(f"Validation for overlay '{args.name}': total_requested_cpu = {total_cpu} mCPU, max_allowed = {args.max_cpu} mCPU")
    if not per_kind:
        print("No workload resources (Deployment/StatefulSet/DaemonSet) found to validate.")
    else:
        print("Resource breakdown:")
        for k, v in per_kind.items():
            print(f"  {k}: replicas={v['replicas']} pod_cpu={v['pod_cpu_m']}m total={v['total_cpu_m']}m")

    if total_cpu > args.max_cpu:
        print(f"ERROR: total requested CPU {total_cpu}m exceeds max allowed {args.max_cpu}m")
        sys.exit(2)
    print("OK: CPU requests are within the configured threshold.")
    sys.exit(0)


if __name__ == '__main__':
    main()
