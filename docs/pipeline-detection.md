# Pipeline Detection & Preview Behavior

Purpose
-------
Short reference describing how CI and Preview decide when to run, what triggers image builds vs deployments, and how to force a preview.

Quick summary
-------------
- CI: decides which jobs to run using `scripts/ci/detect-changes.ps1` → outputs `changed_areas` (push and PR events). Jobs use `contains()` on `changed_areas` to opt-in.
- Preview: runs per PR and uses `.github/actions/detect-pr-code-changes` which uses `git merge-base` + `git diff` to compute actual PR changes. It emits `needs_image_build` and `needs_deployment`.
- Force: Add the label `preview` or `force-preview` to a PR, or use `workflow_dispatch` input `force_deploy: true` to force a preview.

What counts as an image build trigger
------------------------------------
These patterns must match between CI and Preview (single source of truth recommended):
- `services/api/**`
- `services/workers/**`
- `services/shared/**`
- `apps/web/**`
- Any `Dockerfile*`, `docker-compose*.yml`, `.dockerignore`

What counts as a deployment trigger
----------------------------------
- Everything in image build triggers, plus:
- `k8s/**` (Kubernetes manifests)

Key behaviors
-------------
- Docs-only PRs: by default, both CI and Preview skip builds/deploys (no images or preview created).
- K8s-only PRs: Preview will redeploy using existing image tags (no new images needed).
- Service code changes: CI builds images and publishes an `image-tag` artifact; Preview waits for CI to finish (pull_request flow) and then deploys using that tag.
- Forced deploy: When forced, Preview will deploy even if `needs_image_build` is `false` (maintainer override). If images are not built, preview uses the existing production image tags.

Maintenance & best practices
----------------------------
- Keep the trigger patterns in sync; prefer a single config file (`.github/detection-config.yml`) to avoid drift.
- Add a CI parity-check job that fails if the two detectors diverge.
- To add a new service/area:
  1. Add pattern to `scripts/ci/detect-changes.ps1` and to the Preview action patterns.
  2. Add job conditions in workflows using `contains(needs.detect-changes.outputs.changed_areas, '<area>')`.
  3. Add tests validating expected behavior.

Where to look in the repo
-------------------------
- CI detection: `scripts/ci/detect-changes.ps1`
- Preview PR detection: `.github/actions/detect-pr-code-changes/action.yml`
- CI workflow (uses detection outputs): `.github/workflows/ci.yml`
- Preview workflow: `.github/workflows/preview.yml`

Questions or want me to also add a parity-check script and CI job?
