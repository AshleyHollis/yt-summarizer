#!/usr/bin/env python3
"""
Generate preview kustomization.yaml with proper YAML formatting.

Usage:
  generate_preview_kustomization.py --pr-number <number> --image-tag <tag> --acr-server <server> --output <file>

This script generates a properly formatted kustomization.yaml for the preview overlay.
"""
import argparse
import sys
from datetime import datetime, timezone
import yaml


#!/usr/bin/env python3
"""
Generate preview kustomization.yaml with proper YAML formatting.

Usage:
  generate_preview_kustomization.py --pr-number <number> --image-tag <tag> --acr-server <server> --output <file>

This script generates a properly formatted kustomization.yaml for the preview overlay.
"""
import argparse
import sys
from datetime import datetime, timezone
import yaml


def generate_kustomization(pr_number: str, image_tag: str, acr_server: str) -> dict:
    """Generate the kustomization dictionary structure."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        'apiVersion': 'kustomize.config.k8s.io/v1beta1',
        'kind': 'Kustomization',
        'metadata': {
            'annotations': {
                'config.kubernetes.io/local-config': 'true'
            }
        },
        'namespace': f'preview-pr-{pr_number}',
        'resources': [
            '../../base',
            'resource-quota.yaml',
            'limit-range.yaml'
        ],
        'patches': [
            {'path': 'patches/configmap-patch.yaml'},
            {'path': 'patches/ingress-patch.yaml'},
            # Resource requests/limits lowered for preview
            {
                'target': {
                    'group': 'apps',
                    'version': 'v1',
                    'kind': 'Deployment',
                    'name': 'api'
                },
                'patch': [
                    {
                        'op': 'replace',
                        'path': '/spec/template/spec/containers/0/resources',
                        'value': {
                            'requests': {'cpu': '25m', 'memory': '64Mi'},
                            'limits': {'cpu': '150m', 'memory': '256Mi'}
                        }
                    }
                ]
            },
            {
                'target': {
                    'group': 'apps',
                    'version': 'v1',
                    'kind': 'Deployment',
                    'name': 'transcribe-worker'
                },
                'patch': [
                    {
                        'op': 'replace',
                        'path': '/spec/template/spec/containers/0/resources',
                        'value': {
                            'requests': {'cpu': '25m', 'memory': '64Mi'},
                            'limits': {'cpu': '150m', 'memory': '256Mi'}
                        }
                    }
                ]
            },
            {
                'target': {
                    'group': 'apps',
                    'version': 'v1',
                    'kind': 'Deployment',
                    'name': 'summarize-worker'
                },
                'patch': [
                    {
                        'op': 'replace',
                        'path': '/spec/template/spec/containers/0/resources',
                        'value': {
                            'requests': {'cpu': '25m', 'memory': '64Mi'},
                            'limits': {'cpu': '150m', 'memory': '256Mi'}
                        }
                    }
                ]
            },
            {
                'target': {
                    'group': 'apps',
                    'version': 'v1',
                    'kind': 'Deployment',
                    'name': 'embed-worker'
                },
                'patch': [
                    {
                        'op': 'replace',
                        'path': '/spec/template/spec/containers/0/resources',
                        'value': {
                            'requests': {'cpu': '25m', 'memory': '64Mi'},
                            'limits': {'cpu': '150m', 'memory': '256Mi'}
                        }
                    }
                ]
            },
            {
                'target': {
                    'group': 'apps',
                    'version': 'v1',
                    'kind': 'Deployment',
                    'name': 'relationships-worker'
                },
                'patch': [
                    {
                        'op': 'replace',
                        'path': '/spec/template/spec/containers/0/resources',
                        'value': {
                            'requests': {'cpu': '25m', 'memory': '64Mi'},
                            'limits': {'cpu': '150m', 'memory': '256Mi'}
                        }
                    }
                ]
            },
            # Minimal replicas for preview
            {
                'target': {
                    'group': 'apps',
                    'version': 'v1',
                    'kind': 'Deployment',
                    'name': 'api'
                },
                'patch': [
                    {
                        'op': 'replace',
                        'path': '/spec/replicas',
                        'value': 1
                    }
                ]
            },
            {
                'target': {
                    'group': 'apps',
                    'version': 'v1',
                    'kind': 'Deployment',
                    'name': 'transcribe-worker'
                },
                'patch': [
                    {
                        'op': 'replace',
                        'path': '/spec/replicas',
                        'value': 1
                    }
                ]
            },
            {
                'target': {
                    'group': 'apps',
                    'version': 'v1',
                    'kind': 'Deployment',
                    'name': 'summarize-worker'
                },
                'patch': [
                    {
                        'op': 'replace',
                        'path': '/spec/replicas',
                        'value': 1
                    }
                ]
            },
            {
                'target': {
                    'group': 'apps',
                    'version': 'v1',
                    'kind': 'Deployment',
                    'name': 'embed-worker'
                },
                'patch': [
                    {
                        'op': 'replace',
                        'path': '/spec/replicas',
                        'value': 1
                    }
                ]
            },
            {
                'target': {
                    'group': 'apps',
                    'version': 'v1',
                    'kind': 'Deployment',
                    'name': 'relationships-worker'
                },
                'patch': [
                    {
                        'op': 'replace',
                        'path': '/spec/replicas',
                        'value': 1
                    }
                ]
            },
            {'path': 'patches/api-deployment-patch.yaml'},
            # Patch ExternalSecrets to use ClusterSecretStore
            {
                'target': {
                    'group': 'external-secrets.io',
                    'version': 'v1beta1',
                    'kind': 'ExternalSecret',
                    'name': 'db-credentials'
                },
                'patch': [
                    {'op': 'replace', 'path': '/spec/secretStoreRef/kind', 'value': 'ClusterSecretStore'},
                    {'op': 'replace', 'path': '/spec/secretStoreRef/name', 'value': 'azure-keyvault-cluster'}
                ]
            },
            {
                'target': {
                    'group': 'external-secrets.io',
                    'version': 'v1beta1',
                    'kind': 'ExternalSecret',
                    'name': 'openai-credentials'
                },
                'patch': [
                    {'op': 'replace', 'path': '/spec/secretStoreRef/kind', 'value': 'ClusterSecretStore'},
                    {'op': 'replace', 'path': '/spec/secretStoreRef/name', 'value': 'azure-keyvault-cluster'}
                ]
            },
            {
                'target': {
                    'group': 'external-secrets.io',
                    'version': 'v1beta1',
                    'kind': 'ExternalSecret',
                    'name': 'storage-credentials'
                },
                'patch': [
                    {'op': 'replace', 'path': '/spec/secretStoreRef/kind', 'value': 'ClusterSecretStore'},
                    {'op': 'replace', 'path': '/spec/secretStoreRef/name', 'value': 'azure-keyvault-cluster'}
                ]
            },
            # Delete SecretStore (preview uses ClusterSecretStore)
            {
                'target': {
                    'group': 'external-secrets.io',
                    'version': 'v1beta1',
                    'kind': 'SecretStore',
                    'name': 'azure-keyvault'
                },
                'patch': {
                    '$patch': 'delete',
                    'apiVersion': 'external-secrets.io/v1beta1',
                    'kind': 'SecretStore',
                    'metadata': {'name': 'azure-keyvault'}
                }
            },
            # Strip federated identity annotations from ServiceAccount
            {
                'target': {
                    'kind': 'ServiceAccount',
                    'name': 'yt-summarizer-sa'
                },
                'patch': [
                    {'op': 'remove', 'path': '/metadata/annotations/azure.workload.identity~1client-id'},
                    {'op': 'remove', 'path': '/metadata/annotations/azure.workload.identity~1tenant-id'}
                ]
            },
            # Use default SA for migration job
            {
                'target': {
                    'group': 'batch',
                    'version': 'v1',
                    'kind': 'Job',
                    'name': 'db-migration'
                },
                'patch': [
                    {'op': 'replace', 'path': '/spec/template/spec/serviceAccountName', 'value': 'default'}
                ]
            }
        ],
        'images': [
            {
                'name': 'yt-summarizer-api',
                'newName': f'{acr_server}/yt-summarizer-api',
                'newTag': image_tag
            },
            {
                'name': 'yt-summarizer-workers',
                'newName': f'{acr_server}/yt-summarizer-workers',
                'newTag': image_tag
            }
        ],
        'labels': [
            {
                'pairs': {
                    'app.kubernetes.io/part-of': 'yt-summarizer-preview',
                    'preview.pr-number': pr_number
                }
            }
        ]
    }


def main():
    parser = argparse.ArgumentParser(description='Generate preview kustomization.yaml')
    parser.add_argument('--pr-number', required=True, help='PR number')
    parser.add_argument('--image-tag', required=True, help='Image tag')
    parser.add_argument('--acr-server', required=True, help='ACR server')
    parser.add_argument('--output', required=True, help='Output file path')

    args = parser.parse_args()

    kustomization = generate_kustomization(args.pr_number, args.image_tag, args.acr_server)

    # Write with proper YAML formatting
    with open(args.output, 'w', encoding='utf-8') as f:
        # Write header comments
        f.write(f'# Preview overlay - updated by GitHub Actions\n')
        f.write(f'# PR: #{args.pr_number}\n')
        f.write(f'# Image Tag: {args.image_tag}\n')
        f.write(f'# Updated: {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}\n')
        f.write('\n')

        # Use yaml.dump with proper formatting
        yaml.dump(kustomization, f, default_flow_style=False, sort_keys=False, indent=2, allow_unicode=True)

    print(f'Generated kustomization.yaml at {args.output}')


if __name__ == '__main__':
    main()