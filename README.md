# berty-cicd

Centralized CI/CD pipelines for the berty cluster.

## Overview

Shared GitHub Actions workflows for building, testing, and deploying containers to the berty cluster's local registry (`registry.local:5000`). Multi-language security auditing and quality checks.

## Structure

```
.github/workflows/     Reusable workflows (called by app repos)
workflows/shared/      Source of truth for shared workflows
examples/              Drop-in CI configs for app repos
runner/                Self-hosted GitHub Actions runner setup
```

## Security & Quality Checks

Auto-detects project language or specify explicitly:

| Language | Security | Lint | Format | Tests |
|----------|----------|------|--------|-------|
| Node.js | `npm audit` | — | — | — |
| Go | `govulncheck` | — | — | — |
| Python | `pip-audit` | `ruff check` | `ruff format` | `pytest` |

### Python pipeline (uv-based)

Reads tool config from `pyproject.toml` (`[tool.ruff]`, `[tool.isort]`, `[tool.pytest]`).
Installs `--group dev` dependencies so all dev tools (ruff, isort, pytest, etc.) are available.

Pipeline order:
1. `uv sync --frozen --group dev`
2. `ruff check .` — lint (pycodestyle, pyflakes, bugbear, simplify, etc.)
3. `ruff format --check .` — formatting
4. `isort --check-only .` — import sorting (if in dev deps)
5. `pytest` — tests (if in dev deps)
6. `pip-audit` — vulnerability scan
7. `uv lock --check` — lockfile integrity

## Shared Workflows

### `security-audit.yml`
Language-appropriate vulnerability scanning + quality checks.

### `build-and-push.yml`
Full pipeline: audit → build → push to registry → Flux reconcile.

### `deploy-notify.yml`
Verify image in registry, trigger Flux, report status.

## Usage

In your app repo, create `.github/workflows/ci.yml`:

```yaml
# Node.js app
jobs:
  build:
    uses: munhiny/berty-cicd/.github/workflows/build-and-push.yml@main
    with:
      image-name: scrape-engine
      language: node

# Go app
jobs:
  build:
    uses: munhiny/berty-cicd/.github/workflows/build-and-push.yml@main
    with:
      image-name: task-roulette
      language: go

# Python app (uv + ruff + pytest)
jobs:
  build:
    uses: munhiny/berty-cicd/.github/workflows/build-and-push.yml@main
    with:
      image-name: my-app
      language: python
```

See `examples/` for complete workflow files.

## App repos

| Repo | Language | Image |
|------|----------|-------|
| `scrapEngine2` | Node.js | `scrape-engine` |
| `task-roulette` | Go | `task-roulette` |
| `llm-server` | Python | `llm-server` |

## Self-hosted runner

See `runner/README.md` for deploying the GitHub Actions runner on the cluster via ARC.
