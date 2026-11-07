# Nightly alignment scan: deterministic code-duplication, dead-code and
# conformance checks over the cluster repository and its associated
# repositories, run as a CronJob. Every tool is pinned by digest or by hash so
# the job needs no package index at run time.
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# uv 0.12.13 (multi-arch index digest).
COPY --from=ghcr.io/astral-sh/uv:0.12.13@sha256:b485bd65cc2cf1c9a93b3554012c9c3778cf7b1b5fd3d3096ce9e1226c97e1e6 /uv /usr/local/bin/uv
# shellcheck v0.10.0.
COPY --from=koalaman/shellcheck@sha256:2097951f02e735b613f4a34de20c40f937a6c8f18ecb170612c88c34517221fb /bin/shellcheck /usr/local/bin/shellcheck
# jscpd 5.4.2.
COPY --from=ghcr.io/kucherenko/jscpd@sha256:112bc771493f25ec412ebf61bef738dc1fbe80d3793090e6a5eeac827ef0ee79 /usr/local/bin/jscpd /usr/local/bin/jscpd

# vulture 2.16, installed from a hash-pinned requirement.
COPY requirements.txt /tmp/requirements.txt
RUN uv pip install --system --require-hashes --no-cache -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin scan \
 && mkdir -p /opt/alignment-scan /work \
 && chown scan:scan /work
COPY scan.py test_scan.py /opt/alignment-scan/

USER 1000
WORKDIR /work
ENTRYPOINT ["python3", "/opt/alignment-scan/scan.py"]
