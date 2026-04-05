# GitHub Actions Self-Hosted Runner

Deploy a self-hosted GitHub Actions runner on the berty cluster.

## Prerequisites

1. Create a GitHub Personal Access Token (PAT) with `repo` and `admin:org` scopes
2. Create a Kubernetes secret:

```bash
kubectl create namespace cicd
kubectl create secret generic github-runner-token -n cicd \
  --from-literal=GITHUB_TOKEN=<your-pat>
```

## Deploy

The runner is deployed via the Actions Runner Controller (ARC) Helm chart:

```bash
# Install ARC
helm install arc \
  --namespace cicd \
  --create-namespace \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller

# Install runner scale set for the org
helm install berty-runners \
  --namespace cicd \
  --set githubConfigUrl="https://github.com/munhiny" \
  --set githubConfigSecret.github_token="<your-pat>" \
  --set maxRunners=2 \
  --set minRunners=1 \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set
```

## Runner capabilities

The self-hosted runner has access to:
- `registry.local:5000` (local container registry)
- Docker socket (for image builds)
- `flux` CLI (for reconciliation)
- `kubectl` (for deployment verification)
- `npm` / `node` (for security audits)
