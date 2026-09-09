# diffusion-pipe, baked.
#
# The training Job used to build this from scratch on every run: apt, a venv,
# a git clone, torch from the CUDA 12.6 index, then the requirements, then
# DeepSpeed compiling CUDA ops with nvcc. Fifteen to forty minutes before the
# first training step, paid every time, and a run could fail because GitHub,
# PyPI or the PyTorch index was unreachable rather than because of anything to
# do with the training.
#
# Baking moves all of that to build time, where it happens once and is
# reproducible: the trainer version is an image tag, not whatever the branch
# happened to be that morning.
#
# The base is a CUDA devel image, not runtime: DeepSpeed is a hard requirement
# of diffusion-pipe and compiles CUDA ops, which needs nvcc. Ubuntu 24.04 ships
# Python 3.12, which is the version diffusion-pipe asks for.
FROM nvidia/cuda:12.6.3-cudnn-devel-ubuntu24.04

# Pinned rather than a branch. Moving the trainer forward is then a deliberate
# rebuild with a new tag, and a run that worked last week cannot fail this week
# for reasons nobody chose. Override at build time to bump it.
ARG DP_REF=8f83dbf25d03219df705570ec03e62be04bc402f
ARG DP_REPO=https://github.com/tdrussell/diffusion-pipe

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Both cards in this cluster are RTX 3090s, which are Ampere sm_86. Naming the
# one architecture keeps nvcc from building fat binaries for every target it
# knows about, which is most of the compile time and most of the image size.
ENV TORCH_CUDA_ARCH_LIST="8.6"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3.12 python3.12-venv python3-pip git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# A venv rather than the system interpreter, so the image matches what the Job
# used to build at runtime and PATH alone selects it.
RUN python3.12 -m venv /venv
ENV PATH="/venv/bin:${PATH}"
ENV VIRTUAL_ENV=/venv

RUN pip install --no-cache-dir --upgrade pip

RUN git clone --recurse-submodules "${DP_REPO}" /diffusion-pipe \
 && git -C /diffusion-pipe checkout "${DP_REF}" \
 && git -C /diffusion-pipe rev-parse HEAD > /diffusion-pipe/.baked-ref

# torch first and from the CUDA 12.6 index, so the requirements resolve against
# the CUDA build rather than pulling a CPU wheel over the top of it.
RUN pip install --no-cache-dir \
      torch torchvision --index-url https://download.pytorch.org/whl/cu126

RUN pip install --no-cache-dir -r /diffusion-pipe/requirements.txt

# Fail the build here rather than at 3am in a training Job: if the import graph
# is broken, or a CPU-only torch shadowed the CUDA one, this is where it shows.
RUN python -c "import torch, deepspeed; print('torch', torch.__version__); print('deepspeed', deepspeed.__version__)" \
 && test -f /diffusion-pipe/train.py

WORKDIR /diffusion-pipe

# No ENTRYPOINT on purpose. The Job supplies its own command, resolves the
# config path and runs the publish step afterwards; an entrypoint here would
# only be something for it to override.
CMD ["/bin/bash"]
