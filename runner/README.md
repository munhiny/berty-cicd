# GitHub Actions Self-Hosted Runner (ARC)

Deploy self-hosted GitHub Actions runners on Kubernetes using Actions Runner Controller.

## Prerequisites

1. Create a GitHub Personal Access Token (PAT) with `repo` and `admin:org` scopes
2. Create a Kubernetes secret:

```bash
kubectl create namespace cicd
kubectl create secret generic github-runner-token -n cicd \
  --from-literal=github_token=<your-pat>
```

## Deploy

### Install ARC controller

```bash
helm install arc \
  --namespace cicd \
  --create-namespace \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller
```

### Install runner scale set (one per repo)

```bash
helm install my-app-runners \
  --namespace cicd \
  --set githubConfigUrl="https://github.com/<owner>/<repo>" \
  --set githubConfigSecret=github-runner-token \
  --set maxRunners=2 \
  --set minRunners=0 \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set
```

### DinD with insecure registry

If pushing to an HTTP registry, define a custom pod template with `--insecure-registry` on the DinD sidecar:

```yaml
template:
  spec:
    containers:
      - name: runner
        image: ghcr.io/actions/actions-runner:latest
        command: ["/home/runner/run.sh"]
        env:
          - name: DOCKER_HOST
            value: unix:///var/run/docker.sock
        volumeMounts:
          - name: dind-sock
            mountPath: /var/run
      - name: dind
        image: docker:dind
        args:
          - dockerd
          - --host=unix:///var/run/docker.sock
          - --group=123
          - --insecure-registry=<registry-ip>:5000
        securityContext:
          privileged: true
        volumeMounts:
          - name: dind-sock
            mountPath: /var/run
```

**Important:** Do not use `containerMode.type: dind` with custom args — the chart overrides your DinD container config. Define the full pod template manually instead.

## Runner capabilities

The self-hosted runner has access to:
- Local container registry (via DinD sidecar)
- Docker (for image builds)
- Any CLI tools installed via `setup-*` actions (Node, Go, Python, etc.)
