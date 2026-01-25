# Option 2: Improve readiness stability (preview)

Goal: reduce Argo CD wait timeouts by making the API pod reach Ready faster and more reliably during rollouts.

Observed failure
- Preview app was Synced but Health=Progressing; readiness probes failed briefly (connection refused on /health/ready), then recovered.
- Argo sync wait timed out at 180s even though the app later became Healthy.

Resolution (preview + base)
- Updated API readinessProbe in `k8s/base-preview/api-deployment.yaml` and `k8s/base/api-deployment.yaml`:
  - initialDelaySeconds: 15
  - periodSeconds: 5
  - failureThreshold: 6
- Added startupProbe to delay readiness checks until the API is up:
  - path: /health/live
  - periodSeconds: 5
  - failureThreshold: 30
- Updated API readiness logic to be more resilient to transient DB latency:
  - Cache last successful DB check for 15s (configurable)
  - Apply a hard timeout for DB connect during readiness
  - Background DB init retry after startup failure so readiness can recover

Notes
- This is not a pipeline timeout change; it changes when Kubernetes marks pods Ready.
- Readiness still requires DB init to complete; it just avoids flapping on short DB blips.
