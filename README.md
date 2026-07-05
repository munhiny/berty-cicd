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
