# Training container images

How to add a GPU training image that runs as a Kubernetes Job on this cluster,
and the dependencies that are not obvious from any upstream README. Every entry
below cost a failed run to discover, most of them after a full model load with
the desktop scaled down waiting on it.

`diffusion-pipe/` is the worked example. Copy its shape.

## The shape

```dockerfile
FROM nvidia/cuda:12.6.3-cudnn-devel-ubuntu24.04   # devel, not runtime - see below
ARG UPSTREAM_REF=<full commit sha>                 # pin, never a branch
RUN apt-get install -y python3.12 python3.12-venv python3.12-dev ...
RUN python3.12 -m venv /venv
ENV PATH="/venv/bin:${PATH}"
RUN <shallow fetch of UPSTREAM_REF>
RUN pip install torch torchvision torchaudio --index-url .../cu126
RUN pip install -r requirements.txt
RUN <build-time assertions>
```

Build it with the repo's own reusable workflow, path-filtered so unrelated
edits do not trigger a multi-gigabyte build. See
`.github/workflows/build-diffusion-pipe.yml`.

## Dependencies nothing tells you about

### `python3.12-dev` - REQUIRED, and no import test can find it

Triton JIT-compiles its CUDA driver shim **when training starts**: it shells
out to gcc on `driver.c`, which `#include`s `Python.h`. Without the headers the
first training step dies with

```
triton/backends/nvidia/driver.c:9:10: fatal error: Python.h: No such file or directory
```

after the model has loaded and the dataset has been cached, so it costs a full
startup to discover. A runtime *compile* dependency is invisible to
`pip check`, to import tests, and to anything that only exercises Python.
Assert the header file directly.

### `torchaudio` - REQUIRED for diffusion-pipe, and undeclared upstream

`models/base.py` imports it. It is in neither `requirements.txt` nor the
upstream README's install line, which says `pip install torch torchvision`.
Install torch, torchvision AND torchaudio from the CUDA index, together, so
they resolve against the same build.

Assume any project may import something it never declared. `pip check` catches
the class after the fact; installing the obvious trio catches this one up
front.

### The CUDA **devel** base, not runtime

DeepSpeed compiles CUDA ops with `nvcc`, and Triton needs gcc. The runtime
image has neither. This is also where gcc comes from for the Triton compile
above.

### `TORCH_CUDA_ARCH_LIST`

Pin it to the cards you have (`8.6` for the 3090s here). Left unset, nvcc
builds fat binaries for every architecture it knows - most of the build time
and most of the image size, for code that will never run.

## Runtime requirements the image cannot express

These belong in the Job manifest, and each has bitten a run here:

- **A writable dataset directory.** diffusion-pipe writes a metadata cache
  *inside* the dataset folder. The model volume is mounted read-only at
  `/models` on purpose - training should not be able to scribble on shared
  checkpoints - and the same volume is writable at `/shared-models`. Point the
  dataset at the writable path or every run dies on
  `OSError: [Errno 30] Read-only file system`.
- **`/dev/shm`.** DeepSpeed and NCCL use shared memory between ranks. The
  Kubernetes default is 64MB, and overrunning it fails with an NCCL error that
  never mentions shared memory. Mount an `emptyDir` with `medium: Memory`.
- **Do not set `NCCL_P2P_DISABLE`.** Upstream examples set it, which is
  harmless for a single GPU and actively wrong for two: it turns off
  peer-to-peer, which is how NCCL uses the NVLink bridge, pushing every
  gradient all-reduce onto PCIe.
- **One volume entry per PVC.** Declaring the same claim twice to get different
  `readOnly` semantics hangs the pod before it pulls its image - no events, no
  error. Put `readOnly` on the `volumeMount` instead.

## Build-time assertions: what is worth checking, and what cannot be

**The build runner has no GPU.** Model modules that initialise CUDA on import
cannot be imported at build time - they die on "Found no NVIDIA driver". Do not
try; the assertion will fail on a condition the real workload never meets.

What is worth asserting, all GPU-free:

```dockerfile
RUN python -c "import torch, torchvision, torchaudio, deepspeed" \
 && python -c "import transformers, diffusers, peft, safetensors, accelerate" \
 && pip check \
 && test -f /usr/include/python3.12/Python.h \
 && test -d /diffusion-pipe/submodules/ComfyUI/comfy
```

`pip check` is the one that generalises - it verifies every installed
distribution's own dependencies are satisfied, rather than the packages you
happened to think of. The file and directory tests catch the two things imports
cannot see: a runtime compile dependency, and a shallow fetch that silently
dropped a submodule.

The model path stays unverified until run time. That is a real gap; the honest
mitigation is that a baked image fails in the first minute rather than after a
40-minute install.

## Fetching a large upstream repo

Fetch a single commit at depth 1 with shallow submodules. diffusion-pipe is
~16MB but its 9 submodules bring the tree to ~1.2GB.

```dockerfile
RUN git init /src && cd /src \
 && git config http.lowSpeedLimit 1000 && git config http.lowSpeedTime 60 \
 && git remote add origin "${UPSTREAM_REPO}" \
 && git fetch --depth 1 origin "${UPSTREAM_REF}" \
 && git checkout FETCH_HEAD \
 && git submodule update --init --recursive --depth 1
```

Fetching a bare SHA relies on `uploadpack.allowReachableSHA1InWant`, which
GitHub enables, so the pin stays exact without a branch or tag.

The `lowSpeed` settings make a stalled fetch abort with a clear error after 60s
below 1KB/s, instead of hanging until the job's own limit and reporting
nothing.

If a large fetch dies partway with `Connection reset by peer` at a suspiciously
consistent time, that is an MTU problem in the runner's Docker-in-Docker
daemon, not the transfer size - see
`.claude/rules/nested-container-networks-must-match-pod-mtu.md` in the k8s
repo. It is fixed cluster-wide now, but the symptom is worth recognising.

## Tags

CI tags every image with `${{ github.sha }}`, the **full 40-char SHA**. Pin
that in the Job manifest. Short tags do not exist in the registry, and a
manifest referencing one deploys green and then rolls `ImagePullBackOff`.

Note `github.sha` on a `pull_request` is the **merge** commit, which does not
survive a squash. Take the tag from the push-to-main build, and verify it
resolves in the registry before pinning it rather than trusting a printed
value.

## Registry budget

A CUDA + torch + DeepSpeed image is roughly **9GB**, and every rebuild pushes a
new tag. The cluster registry is 70Gi. Garbage collection is currently
**suspended**: `registry garbage-collect --delete-untagged` does not follow OCI
image indexes and destroyed every image in the registry on 2026-09-09. Do not
re-enable it without verifying it against a multi-arch image first.
