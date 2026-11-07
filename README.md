# Shared CI/CD Workflows

Reusable GitHub Actions workflows for multi-language security auditing, container builds, and registry pushes.

## Structure

```
.github/workflows/     Reusable workflows (called by app repos)
scripts/               check-vulns.py and check-secrets.sh (run by CI and by the workstation)
examples/              Drop-in caller for app repos (app-ci.yml)
runner/                Self-hosted GitHub Actions runner setup (ARC)
```

## Security & Quality Checks

Auto-detects project language or specify explicitly. Supports comma-separated values for monorepos (e.g. `go,node`).

| Language | Lint | Format | Tests |
|----------|------|--------|-------|
| Node.js | `eslint` (if configured) | - | - |
| Go | - | - | `go test` |
| Python (uv) | `ruff check` | `ruff format` | `pytest` |

Vulnerability scanning is not part of this job; `vuln-check.yml` does it.

### Python pipeline (uv-based)

Reads tool config from `pyproject.toml` (`[tool.ruff]`, `[tool.isort]`, `[tool.pytest]`).
Installs `--group dev` dependencies so all dev tools are available.

Pipeline order:
1. `uv sync --frozen --group dev`
2. `ruff check .` - lint
3. `ruff format --check .` - formatting
4. `isort --check-only .` - import sorting (if in dev deps)
5. `pytest` - tests (if in dev deps)
6. `uv lock --check` - lockfile integrity

## Shared Workflows

### `build-and-push.yml`

Full pipeline: language detection -> lint -> test -> Docker build -> push to registry.

**Inputs:**

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `runner-label` | yes | - | Self-hosted runner label (ARC scale set name) |
| `image-name` | yes | - | Docker image name |
| `language` | no | `auto` | `node`, `go`, `python`, or comma-separated |
| `dockerfile` | no | `./Dockerfile` | Dockerfile path |
| `context` | no | `.` | Docker build context |
| `registry` | no | `localhost:5000` | Container registry (use IP for DinD) |
| `audit-level` | no | `high` | Deprecated, accepted and ignored |
| `skip-audit` | no | `false` | Skip the lint and test job |
| `node-working-directory` | no | `.` | Working dir for Node.js (monorepo support) |
| `go-working-directory` | no | `.` | Working dir for Go, i.e. where `go.mod` lives (multi-image repo support) |

### `vuln-check.yml`
The pull request gate for known vulnerabilities. Runs `scripts/check-vulns.py`
from this repository's main branch against the caller's checkout. It blocks
on high or critical advisories in dependencies that ship: `npm audit
--omit=dev` for each `package-lock.json`, the uv project without its dev
group, hashed requirements locks as written (other requirements files are
resolved first), and Go code reachable per `govulncheck`. Dev and test
findings are printed, not blocking, unless `all-deps: true`. pip-audit and
govulncheck carry no severity, so the script looks each advisory up in OSV
and GitHub's advisory database; a finding with no known severity blocks.

```yaml
  vuln-check:
    uses: munhiny/berty-cicd/.github/workflows/vuln-check.yml@main
    with:
      runner-label: arc-runner-my-app
```

Accepted risks go in `.vuln-ignore` at the repository root, one per line,
with an expiry after which the line stops applying:

```
GHSA-xxxx-xxxx-xxxx 2026-12-31 parser not reachable from the server; upgrade blocked on upstream
```

Run it locally from any repository:

```bash
python3 <path-to-berty-cicd>/scripts/check-vulns.py          # exit 0 clean, 1 blocking, 2 could not run
python3 <path-to-berty-cicd>/scripts/test_check_vulns.py     # its offline tests
```

### `sync-image-sha.yml`

Post-build: opens (or updates) a pull request against a GitOps repo that
bumps a manifest's image tag to the commit SHA that was just built and
pushed. Intended to run as a job in the same workflow as
`build-and-push.yml`, after the build succeeds.

Only the newest image of an app waits to deploy: when it opens a pull request
it closes any older open bump pull request for the same app (branch
`k8s/bump-<first image name>-<12-char sha>`). In munhiny/berty-k8s a bump
pull request that changes nothing but image tags merges itself once its CI
is green (`.github/workflows/auto-merge-image-bumps.yml` there), so a merge
to an app's main deploys the new image without a manual step.

**Inputs:**

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `runner-label` | yes | - | Self-hosted runner label (ARC scale set name) |
| `gitops-repo` | yes | - | GitOps repo to open the pull request against, e.g. `owner/repo` |
| `manifest-path` | yes | - | Path within the GitOps repo to the manifest, e.g. `apps/my-app/app.yaml` |
| `image-name` | yes | - | Image name as it appears in the manifest, e.g. `my-app`; several names separated by spaces are pinned to the same SHA in one pull request (e.g. `my-app-backend my-app-frontend`) |
| `registry-host` | yes | - | Registry host prefix as written in the manifest, e.g. `registry.local:5000` |
| `image-sha` | no | `github.sha` | Full 40-character commit SHA to pin the manifest to |

**Secrets:**

| Secret | Required | Description |
|--------|----------|--------------|
| `gitops-token` | no | Fine-grained PAT for the GitOps repo. If empty, the sync is skipped with a warning annotation instead of failing the run. |

**Activating the sync (one-time, per caller repo):**

1. Create a fine-grained personal access token scoped to the GitOps repo
   only, with permissions: Contents (read and write), Pull requests
   (read and write).
2. In the caller repo (not the GitOps repo), add the token as a repository
   secret, e.g. `K8S_SYNC_TOKEN` (Settings > Secrets and variables >
   Actions > New repository secret).
3. Pass it through in the caller workflow as shown below. Until the
   secret exists, every run emits a `::warning::` annotation and exits 0
   without touching the GitOps repo - the sync job is safe to wire in
   ahead of time.

**Behavior notes:**

- The branch name is content-addressed (`<image-name>-<first-12-chars-of-sha>`),
  so re-running the sync for the same commit updates the existing pull
  request instead of opening a duplicate.
- If the manifest is already pinned to the target SHA, the job exits
  successfully with a `::notice::` annotation and opens no pull request -
  this is the expected steady state when a build re-runs without a code
  change.
- The job never merges the pull request it opens; that still goes through
  the GitOps repo's normal branch protection and review.

Example caller job (add alongside the `build` job in the same workflow):

```yaml
jobs:
  build:
    uses: <owner>/cicd/.github/workflows/build-and-push.yml@main
    with:
      runner-label: arc-runner-my-app
      image-name: my-app
      registry: ${{ vars.REGISTRY }}

  sync:
    needs: build
    if: github.ref == 'refs/heads/main'
    uses: <owner>/cicd/.github/workflows/sync-image-sha.yml@main
    with:
      runner-label: arc-runner-my-app
      gitops-repo: <owner>/k8s
      manifest-path: apps/my-app/app.yaml
      image-name: my-app
      registry-host: registry.local:5000
    secrets:
      gitops-token: ${{ secrets.K8S_SYNC_TOKEN }}
```

## Usage

### `app-ci.yml`

One call for an app repository: build, vulnerability check and image sync.
The jobs are `build` (build-and-push.yml), `vuln` (vuln-check.yml) and `sync`
(sync-image-sha.yml, only on a push to main, after `build`). The runner is
`arc-runner-<app>` unless `runner-label` is set.

```yaml
jobs:
  ci:
    uses: munhiny/berty-cicd/.github/workflows/app-ci.yml@main
    with:
      app: my-app
      manifest-path: apps/my-app/app.yaml
    secrets:
      k8s-sync-token: ${{ secrets.K8S_SYNC_TOKEN }}
```

**Inputs:**

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `app` | yes | - | Image name as in the manifest; names the runner `arc-runner-<app>` |
| `manifest-path` | yes | - | Manifest path in the GitOps repo holding the image line |
| `runner-label` | no | `arc-runner-<app>` | ARC scale set, when the repository and image names differ |
| `language` | no | `auto` | `node`, `go`, `python`, or comma-separated |
| `context` | no | `.` | Docker build context |
| `dockerfile` | no | `./Dockerfile` | Dockerfile path |
| `node-working-directory` | no | `.` | Working dir for Node.js |
| `go-working-directory` | no | `.` | Working dir for Go |
| `platforms` | no | empty | Comma-separated build platforms; empty is single-arch |
| `registry` | no | `vars.REGISTRY` | Registry the build pushes to |
| `registry-host` | no | `registry.local:5000` | Registry host as written in the manifest |
| `gitops-repo` | no | `munhiny/berty-k8s` | GitOps repository for the bump pull request |
| `audit-level`, `skip-audit` | no | `high`, `false` | Passed through to build-and-push.yml |

**Secrets:** `k8s-sync-token` (optional) is passed to sync-image-sha.yml as
`gitops-token`; unset, the sync is skipped with a warning. The wrapper does
not fit a repository with its own test jobs gating the build, or one that
builds several images; those keep calling the three workflows directly (see
the sections above). `examples/app-ci.yml` is the caller to copy.

## Scripts

- `scripts/check-vulns.py`: the vulnerability gate (see `vuln-check.yml`).
- `scripts/check-secrets.sh [--profile code|network] <base-ref>`: scans files
  changed since `<base-ref>` for secret assignments and private key blocks
  (the `network` profile adds MAC addresses and `psk=`). Exit 0 clean, 1
  violations, 2 misuse. Run by CI and from the workstation.

This repository's own CI (`.github/workflows/ci.yml`) runs the offline tests
of `check-vulns.py` and shellchecks `scripts/*.sh`.

## Self-hosted Runner

See `runner/README.md` for deploying GitHub Actions runners on Kubernetes via ARC (Actions Runner Controller).
