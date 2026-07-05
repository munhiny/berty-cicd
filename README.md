# Shared CI/CD Workflows

Reusable GitHub Actions workflows for multi-language security auditing, container builds, and registry pushes.

## Structure

```
.github/workflows/     Reusable workflows (called by app repos)
workflows/shared/      Source copies of shared workflows
examples/              Drop-in CI configs for app repos
runner/                Self-hosted GitHub Actions runner setup (ARC)
```

## Security & Quality Checks

Auto-detects project language or specify explicitly. Supports comma-separated values for monorepos (e.g. `go,node`).

| Language | Security | Lint | Format | Tests |
|----------|----------|------|--------|-------|
| Node.js | `npm audit` | `eslint` (if configured) | — | — |
| Go | `govulncheck` | — | — | `go test` |
| Python (uv) | `pip-audit` | `ruff check` | `ruff format` | `pytest` |

### Python pipeline (uv-based)

Reads tool config from `pyproject.toml` (`[tool.ruff]`, `[tool.isort]`, `[tool.pytest]`).
Installs `--group dev` dependencies so all dev tools are available.

Pipeline order:
1. `uv sync --frozen --group dev`
2. `ruff check .` — lint
3. `ruff format --check .` — formatting
4. `isort --check-only .` — import sorting (if in dev deps)
5. `pytest` — tests (if in dev deps)
6. `pip-audit` — vulnerability scan
7. `uv lock --check` — lockfile integrity

## Shared Workflows

### `build-and-push.yml`

Full pipeline: language detection → security audit → lint → test → Docker build → push to registry.

**Inputs:**

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `runner-label` | yes | — | Self-hosted runner label (ARC scale set name) |
| `image-name` | yes | — | Docker image name |
| `language` | no | `auto` | `node`, `go`, `python`, or comma-separated |
| `dockerfile` | no | `./Dockerfile` | Dockerfile path |
| `context` | no | `.` | Docker build context |
| `registry` | no | `localhost:5000` | Container registry (use IP for DinD) |
| `audit-level` | no | `high` | npm audit severity threshold |
| `skip-audit` | no | `false` | Skip audit step |
| `node-working-directory` | no | `.` | Working dir for Node.js (monorepo support) |
| `go-working-directory` | no | `.` | Working dir for Go, i.e. where `go.mod` lives (multi-image repo support) |

### `security-audit.yml`

Standalone audit workflow (also used internally by `build-and-push.yml`).

### `deploy-notify.yml`

Post-build: verify image in registry, trigger GitOps reconciliation, report status.

### `sync-image-sha.yml`

Post-build: opens (or updates) a pull request against a GitOps repo that
bumps a manifest's image tag to the commit SHA that was just built and
pushed. Intended to run as a job in the same workflow as
`build-and-push.yml`, after the build succeeds.

**Inputs:**

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `runner-label` | yes | - | Self-hosted runner label (ARC scale set name) |
| `gitops-repo` | yes | - | GitOps repo to open the pull request against, e.g. `owner/repo` |
| `manifest-path` | yes | - | Path within the GitOps repo to the manifest, e.g. `apps/my-app/app.yaml` |
| `image-name` | yes | - | Image name as it appears in the manifest, e.g. `my-app` |
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

In your app repo, create `.github/workflows/ci.yml`:

### Node.js app
```yaml
jobs:
  ci:
    uses: <owner>/cicd/.github/workflows/build-and-push.yml@main
    with:
      runner-label: arc-runner-my-node-app
      image-name: my-node-app
      language: node
```

### Go app
```yaml
jobs:
  ci:
    uses: <owner>/cicd/.github/workflows/build-and-push.yml@main
    with:
      runner-label: arc-runner-my-go-app
      image-name: my-go-app
      language: go
```

### Go + Node monorepo
```yaml
jobs:
  ci:
    uses: <owner>/cicd/.github/workflows/build-and-push.yml@main
    with:
      runner-label: arc-runner-my-app
      image-name: my-app
      language: go,node
      node-working-directory: web
      dockerfile: deploy/Dockerfile
```

### Python app (uv)
```yaml
jobs:
  ci:
    uses: <owner>/cicd/.github/workflows/build-and-push.yml@main
    with:
      runner-label: arc-runner-my-python-app
      image-name: my-python-app
      language: python
```

See `examples/` for complete workflow files.

## Self-hosted Runner

See `runner/README.md` for deploying GitHub Actions runners on Kubernetes via ARC (Actions Runner Controller).
