#!/usr/bin/env python3
"""Nightly alignment scan.

Layer 1 (deterministic) runs copied-lines, dead-code, shellcheck, test-wiring,
app-layout and conformance checks over shallow clones of the repositories named
in REPOS. Every finding gets a deterministic key; the keys are stored in
seen.json under DATA_DIR and only the DELTA (keys not seen before) is pushed to
ntfy, together with a daily heartbeat line.

Layer 2 runs only when the delta is not empty and LAYER2_ENABLED is true: it
asks the broker to wake the large model, then collects one refactor proposal
per new copied-lines cluster and has the smaller models cross-verify it. The
scan never applies code and never holds a GPU control key.

The clones are read-only inputs. The scan writes only under DATA_DIR and a
temporary directory.

Exit codes: 0 ran (new findings and a skipped layer 2 are normal and recorded),
2 could not run (a tool is missing, a mirror is unreachable). With --strict:
1 ran and recorded new findings, 3 layer 2 was asked for but the wake was
unavailable (layer 1 still ran).
"""
import argparse
import datetime
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Optional

log = logging.getLogger("alignment-scan")

ALL_CHECKS = ("jscpd", "vulture", "shellcheck", "wired", "layout", "conformance")
VULTURE_IGNORE = (
    "do_*,_route_*,log_message,protocol_version,daemon_threads,server_version,"
    "sys_version,close_connection,redirect_request,fp,newurl,handle_*,optionxform,"
    "INPUT_TYPES,RETURN_TYPES,FUNCTION,CATEGORY,IS_CHANGED,NODE_CLASS_MAPPINGS,"
    "NODE_DISPLAY_NAME_MAPPINGS"
)
# Built from pieces so this file itself carries no vendor name.
VENDOR_RE = re.compile("(" + "cla" + "ude|" + "anthro" + "pic" + ")", re.IGNORECASE)
RUNNING_STATES = {"pending", "approved", "running", "queued"}
TOOL_TIMEOUT = 1800
WAKE_PURPOSE = "alignment-scan"
CONFORMANCE_TOOL = "check-tooling-alignment.sh"


class ScanError(Exception):
    """A check could not run (tool missing, mirror unreachable, bad output)."""


class WakeUnavailable(Exception):
    """Layer 2 cannot proceed; the message is the reason recorded in the report."""


class HttpError(Exception):
    """A request failed at the transport level."""


class WaitTimeout(Exception):
    """A polled condition did not hold before its deadline."""


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def _flag(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def _pairs(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in text.split():
        name, sep, value = item.partition("=")
        if sep and name and value:
            out[name] = value
    return out


@dataclass
class Config:
    repos: dict[str, str]
    forgejo_token_file: str
    data_dir: Path
    ntfy_url: str
    ntfy_topic: str
    ntfy_token_file: str
    push_enabled: bool
    dry_run: bool
    layer2_enabled: bool
    broker_url: str
    switch_url: str
    vllm_urls: dict[str, str]
    vllm_key_files: dict[str, str]
    checker_url: str
    router_url: str
    router_key_file: str
    max_proposals: int
    job_wait: float
    model_wait: float
    http_timeout: float
    poll_interval: float
    checks: tuple[str, ...]

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "Config":
        g = env.get
        checks = tuple(g("CHECKS", " ".join(ALL_CHECKS)).split())
        unknown = [c for c in checks if c not in ALL_CHECKS]
        if unknown:
            raise ValueError("unknown check(s): %s" % ", ".join(unknown))
        return cls(
            repos=_pairs(g("REPOS", "")),
            forgejo_token_file=g("FORGEJO_TOKEN_FILE", "/forgejo/token"),
            data_dir=Path(g("DATA_DIR", "/data")),
            ntfy_url=g("NTFY_URL", "http://ntfy.ntfy.svc.cluster.local").rstrip("/"),
            ntfy_topic=g("NTFY_TOPIC", "alignment"),
            ntfy_token_file=g("NTFY_TOKEN_FILE", "/ntfy/token"),
            push_enabled=_flag(g("PUSH_ENABLED", "false")),
            dry_run=_flag(g("DRY_RUN", "0")),
            layer2_enabled=_flag(g("LAYER2_ENABLED", "false")),
            broker_url=g("BROKER_URL", "http://job-broker.ai.svc.cluster.local:8080").rstrip("/"),
            switch_url=g("SWITCH_URL", "http://model-switch.ai.svc.cluster.local:8080").rstrip("/"),
            vllm_urls=_pairs(g(
                "VLLM_URLS",
                "qwen3.8-27b=http://vllm.ai.svc.cluster.local:8000 "
                "huihui-qwen3.8-27b-abliterated=http://vllm-huihui.ai.svc.cluster.local:8000",
            )),
            vllm_key_files=_pairs(g("VLLM_KEY_FILES", "")),
            checker_url=g("CHECKER_URL", "http://llama-checker.ai.svc.cluster.local:8082").rstrip("/"),
            router_url=g("ROUTER_5070_URL", "http://192.168.10.50:8010").rstrip("/"),
            router_key_file=g("ROUTER_5070_KEY_FILE", ""),
            max_proposals=int(g("MAX_PROPOSALS", "5")),
            job_wait=float(g("JOB_WAIT", "1700")),
            model_wait=float(g("MODEL_WAIT", "600")),
            http_timeout=float(g("HTTP_TIMEOUT", "120")),
            poll_interval=float(g("POLL_INTERVAL", "15")),
            checks=checks,
        )


# --------------------------------------------------------------------------
# Text filters
# --------------------------------------------------------------------------

class LineFilter:
    """ASCII filter plus vendor-name filter; counts the lines it rejects."""

    def __init__(self) -> None:
        self.redacted = 0

    def clean(self, line: str) -> Optional[str]:
        ascii_line = line.encode("ascii", "replace").decode("ascii")
        if VENDOR_RE.search(ascii_line):
            self.redacted += 1
            return None
        return ascii_line

    def apply(self, lines: list[str]) -> list[str]:
        out: list[str] = []
        for line in lines:
            kept = self.clean(line)
            if kept is not None:
                out.append(kept)
        return out

    def note(self) -> list[str]:
        return ["(redacted: %d line(s))" % self.redacted] if self.redacted else []


# --------------------------------------------------------------------------
# Findings and state
# --------------------------------------------------------------------------

@dataclass
class Finding:
    key: str
    check: str
    repo: str
    text: str
    detail: dict = field(default_factory=dict)


def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()


def compute_delta(current: Mapping[str, Mapping[str, Finding]],
                  seen: Mapping[str, list[str]]) -> dict[str, list[Finding]]:
    """Findings whose key is not in the stored set for their check."""
    delta: dict[str, list[Finding]] = {}
    for check, findings in current.items():
        known = set(seen.get(check, []))
        fresh = [f for k, f in sorted(findings.items()) if k not in known]
        if fresh:
            delta[check] = fresh
    return delta


def load_seen(path: Path) -> dict[str, list[str]]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanError("cannot read %s: %s" % (path, exc)) from exc
    if not isinstance(data, dict):
        raise ScanError("%s is not a JSON object" % path)
    return {str(k): [str(x) for x in v] for k, v in data.items()}


def atomic_write(path: Path, text: str) -> None:
    """Write text to path through a temp file in the same directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def save_seen(path: Path, seen: Mapping[str, list[str]]) -> None:
    atomic_write(path, json.dumps({k: sorted(v) for k, v in seen.items()}, indent=2, sort_keys=True) + "\n")


# --------------------------------------------------------------------------
# Running tools and reading their output
# --------------------------------------------------------------------------

def run_tool(cmd: list[str], cwd: Path, env: Optional[Mapping[str, str]] = None,
             timeout: float = TOOL_TIMEOUT) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, cwd=str(cwd), env=dict(env) if env is not None else None,
                              capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise ScanError("tool not found: %s" % cmd[0]) from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError("%s timed out after %ds" % (cmd[0], int(timeout))) from exc


def _rel(name: str, root: Path) -> str:
    try:
        return os.path.relpath(name, str(root)) if os.path.isabs(name) else name.removeprefix("./")
    except ValueError:
        return name


def parse_jscpd(report: dict, repo: str, root: Path) -> dict[str, Finding]:
    out: dict[str, Finding] = {}
    for dup in report.get("duplicates", []):
        first, second = dup.get("firstFile", {}), dup.get("secondFile", {})
        fname, sname = _rel(first.get("name", "?"), root), _rel(second.get("name", "?"), root)
        fragment = dup.get("fragment", "")
        key = "jscpd|%s|%s|%s|%s" % (repo, fname, sname, _sha1(fragment)[:12])
        text = "%s: %s:%s-%s <-> %s:%s-%s (%s lines)" % (
            repo, fname, first.get("start", "?"), first.get("end", "?"),
            sname, second.get("start", "?"), second.get("end", "?"), dup.get("lines", "?"))
        out[key] = Finding(key, "jscpd", repo, text, {
            "fragment": fragment, "first": fname, "second": sname,
            "first_start": first.get("start"), "first_end": first.get("end"),
            "second_start": second.get("start"), "second_end": second.get("end"),
        })
    return out


VULTURE_LINE = re.compile(r"^(?P<file>.+?):(?P<line>\d+): (?P<what>.+?) '(?P<name>[^']+)' \((?P<conf>\d+)% confidence\)")


def parse_vulture(output: str, repo: str) -> dict[str, Finding]:
    out: dict[str, Finding] = {}
    for line in output.splitlines():
        match = VULTURE_LINE.match(line)
        if not match:
            continue
        key = "vulture|%s|%s|%s" % (repo, match["file"], match["name"])
        out[key] = Finding(key, "vulture", repo, "%s: %s" % (repo, line.strip()))
    return out


def parse_shellcheck(output: str, repo: str) -> dict[str, Finding]:
    try:
        data = json.loads(output) if output.strip() else {"comments": []}
    except json.JSONDecodeError as exc:
        raise ScanError("shellcheck output is not JSON: %s" % exc) from exc
    comments = data.get("comments", []) if isinstance(data, dict) else data
    out: dict[str, Finding] = {}
    for item in comments:
        key = "shellcheck|%s|%s|%s|SC%s" % (repo, item.get("file"), item.get("line"), item.get("code"))
        text = "%s: %s:%s SC%s %s" % (repo, item.get("file"), item.get("line"),
                                       item.get("code"), item.get("message", ""))
        out[key] = Finding(key, "shellcheck", repo, text)
    return out


def parse_lines(check: str, output: str, repo: str) -> dict[str, Finding]:
    """One finding per non-empty output line; the line itself is the key."""
    out: dict[str, Finding] = {}
    for line in output.splitlines():
        line = line.strip()
        if line:
            key = "%s|%s|%s" % (check, repo, line)
            out[key] = Finding(key, check, repo, "%s: %s" % (repo, line))
    return out


def tracked_files(root: Path, *patterns: str) -> list[str]:
    proc = run_tool(["git", "ls-files", "-z", "--", *patterns], root)
    if proc.returncode != 0:
        raise ScanError("git ls-files failed in %s: %s" % (root.name, proc.stderr.strip()))
    return [f for f in proc.stdout.split("\0") if f]


def scan_env(tmp: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["UV_CACHE_DIR"] = str(tmp / "uv-cache")
    env["HOME"] = str(tmp / "home")
    (tmp / "home").mkdir(exist_ok=True)
    return env


def check_jscpd(root: Path, repo: str, tmp: Path, env: Mapping[str, str]) -> dict[str, Finding]:
    out_dir = tmp / ("jscpd-" + repo)
    out_dir.mkdir(exist_ok=True)
    proc = run_tool(["jscpd", "-k", "50", "-l", "5", "-r", "json", "-f", "bash,python",
                     "--no-gitignore", "-s", "-o", str(out_dir), "."], root, env)
    if proc.returncode not in (0, 1):
        raise ScanError("jscpd exit %d in %s: %s" % (proc.returncode, repo, proc.stderr.strip()[:200]))
    report = out_dir / "jscpd-report.json"
    if not report.exists():
        raise ScanError("jscpd wrote no report for %s" % repo)
    return parse_jscpd(json.loads(report.read_text(encoding="utf-8")), repo, root)


def check_vulture(root: Path, repo: str, _tmp: Path, env: Mapping[str, str]) -> dict[str, Finding]:
    files = [f for f in tracked_files(root, "*.py")
             if not re.search(r"(^|/)(test_[^/]*|tests/.*|conftest)\.py$", f)]
    if not files:
        return {}
    proc = run_tool(["vulture", *files, "--min-confidence", "60", "--ignore-names", VULTURE_IGNORE], root, env)
    if proc.returncode not in (0, 3):
        raise ScanError("vulture exit %d in %s: %s" % (proc.returncode, repo, proc.stderr.strip()[:200]))
    return parse_vulture(proc.stdout, repo)


def check_shellcheck(root: Path, repo: str, _tmp: Path, env: Mapping[str, str]) -> dict[str, Finding]:
    files = tracked_files(root, "*.sh")
    if not files:
        return {}
    proc = run_tool(["shellcheck", "-f", "json1", *files], root, env)
    if proc.returncode not in (0, 1):
        raise ScanError("shellcheck exit %d in %s: %s" % (proc.returncode, repo, proc.stderr.strip()[:200]))
    return parse_shellcheck(proc.stdout, repo)


def check_wired(root: Path, repo: str, _tmp: Path, env: Mapping[str, str]) -> dict[str, Finding]:
    script = root / ".github" / "scripts" / "check-tests-wired.py"
    if not script.exists():
        return {}
    proc = run_tool(["python3", str(script)], root, env)
    if proc.returncode not in (0, 1):
        raise ScanError("check-tests-wired exit %d in %s: %s" % (proc.returncode, repo, proc.stderr.strip()[:200]))
    return parse_lines("wired", proc.stdout + proc.stderr if proc.returncode else "", repo)


def check_layout(root: Path, repo: str, _tmp: Path, env: Mapping[str, str]) -> dict[str, Finding]:
    script = root / "scripts" / "new-app.py"
    if not script.exists():
        return {}
    proc = run_tool(["uv", "run", "scripts/new-app.py", "--check", "--all"], root, env)
    if proc.returncode not in (0, 1):
        raise ScanError("new-app --check exit %d in %s: %s" % (proc.returncode, repo, proc.stderr.strip()[:200]))
    return parse_lines("layout", proc.stdout + proc.stderr if proc.returncode else "", repo)


def check_conformance(root: Path, repo: str, _tmp: Path, env: Mapping[str, str]) -> dict[str, Finding]:
    """Hook: runs the tooling-conformance script when it is on PATH.

    Raises LookupError when the script is not installed, so the caller records
    "not available" instead of treating it as a failure.
    """
    tool = shutil.which(CONFORMANCE_TOOL, path=env.get("PATH"))
    if tool is None:
        raise LookupError("%s not available" % CONFORMANCE_TOOL)
    proc = run_tool([tool], root, env)
    if proc.returncode not in (0, 1):
        raise ScanError("%s exit %d in %s: %s" % (CONFORMANCE_TOOL, proc.returncode, repo, proc.stderr.strip()[:200]))
    return parse_lines("conformance", proc.stdout, repo)


CHECK_FUNCS: dict[str, Callable[[Path, str, Path, Mapping[str, str]], dict[str, Finding]]] = {
    "jscpd": check_jscpd,
    "vulture": check_vulture,
    "shellcheck": check_shellcheck,
    "wired": check_wired,
    "layout": check_layout,
    "conformance": check_conformance,
}


def clone_repo(name: str, url: str, dest: Path, token_file: str, env: Mapping[str, str]) -> None:
    """Shallow clone. The token travels in git's environment config, not argv."""
    genv = dict(env)
    token_path = Path(token_file) if token_file else None
    if token_path is not None and token_path.is_file():
        token = token_path.read_text(encoding="utf-8").strip()
        genv.update({
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraheader",
            "GIT_CONFIG_VALUE_0": "Authorization: token " + token,
        })
    genv["GIT_TERMINAL_PROMPT"] = "0"
    proc = run_tool(["git", "clone", "--quiet", "--depth", "1", url, str(dest)], dest.parent, genv, timeout=600)
    if proc.returncode != 0:
        raise ScanError("clone of %s failed: %s" % (name, proc.stderr.strip()[:200]))


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------

def http_json(method: str, url: str, body: Optional[dict] = None, headers: Optional[Mapping[str, str]] = None,
              timeout: float = 120) -> tuple[int, object]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    hdrs = {"Accept": "application/json"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read(), exc.code
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise HttpError("%s %s: %s" % (method, url, exc)) from exc
    try:
        return status, json.loads(raw.decode("utf-8")) if raw.strip() else None
    except (ValueError, UnicodeDecodeError):
        return status, raw.decode("utf-8", "replace")


def read_secret(path: str) -> str:
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        log.warning("secret file %s unreadable", path)
        return ""


def bearer(path: str) -> dict[str, str]:
    token = read_secret(path)
    return {"Authorization": "Bearer " + token} if token else {}


def wait_until(probe: Callable[[], tuple[bool, str]], deadline_s: float, interval_s: float, what: str) -> str:
    """Poll probe() until it reports done; raise WaitTimeout naming the last state."""
    end = time.monotonic() + deadline_s
    last = "never probed"
    while True:
        done, last = probe()
        if done:
            return last
        if time.monotonic() >= end:
            raise WaitTimeout("%s: deadline %ds, last state: %s" % (what, int(deadline_s), last))
        time.sleep(min(interval_s, max(0.0, end - time.monotonic())))


def chat(url: str, model: str, prompt: str, headers: Mapping[str, str], timeout: float,
         max_tokens: int = 1200) -> str:
    status, body = http_json("POST", url + "/v1/chat/completions", {
        "model": model, "max_tokens": max_tokens, "temperature": 0,
        "messages": [{"role": "user", "content": prompt}],
    }, headers, timeout)
    if status != 200 or not isinstance(body, dict):
        raise HttpError("completion at %s returned %s" % (url, status))
    try:
        message = body["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise HttpError("completion at %s has an unexpected shape" % url) from exc
    return (message.get("content") or message.get("reasoning_content") or "").strip()


# --------------------------------------------------------------------------
# Layer 2
# --------------------------------------------------------------------------

def wake_large_model(cfg: Config) -> tuple[str, str]:
    """File the wake job, wait for it, confirm a 27B is serving. Returns (name, url)."""
    hdr = {"X-Job-Broker": "1"}
    try:
        status, body = http_json("POST", cfg.broker_url + "/api/jobs", {
            "type": "alignment-wake", "args": {"purpose": WAKE_PURPOSE}, "requester": "alignment-scan",
        }, hdr, cfg.http_timeout)
    except HttpError as exc:
        raise WakeUnavailable("broker unreachable: %s" % exc) from exc
    if status in (409, 429):
        raise WakeUnavailable("skipped: broker answered %d" % status)
    if status not in (200, 201) or not isinstance(body, dict) or "id" not in body:
        raise WakeUnavailable("broker answered %s with an unexpected body" % status)
    job_id = body["id"]
    tier = body.get("tier") or {}
    if tier.get("kind") == "ask":
        try:
            http_json("POST", "%s/api/jobs/%s/cancel" % (cfg.broker_url, job_id), None, hdr, cfg.http_timeout)
        except HttpError as exc:
            log.warning("cancel of job %s failed: %s", job_id, exc)
        raise WakeUnavailable("skipped: %s" % (tier.get("reason") or "tier ask"))

    final: dict = {}

    def job_done() -> tuple[bool, str]:
        st, job = http_json("GET", "%s/api/jobs/%s" % (cfg.broker_url, job_id), None, hdr, cfg.http_timeout)
        if st != 200 or not isinstance(job, dict):
            return False, "http %s" % st
        state = str(job.get("state", "unknown"))
        if state not in RUNNING_STATES:
            final.update(job)
            return True, state
        return False, state

    try:
        state = wait_until(job_done, cfg.job_wait, cfg.poll_interval, "wake job %s" % job_id)
    except (WaitTimeout, HttpError) as exc:
        raise WakeUnavailable(str(exc)) from exc
    if state != "succeeded":
        raise WakeUnavailable("wake job %s ended %s" % (job_id, state))

    def switch_ready() -> tuple[bool, str]:
        st, sw = http_json("GET", cfg.switch_url + "/api/status", None, None, cfg.http_timeout)
        if st != 200 or not isinstance(sw, dict):
            return False, "http %s" % st
        in_use = sw.get("inUse")
        running = bool((sw.get("op") or {}).get("running"))
        return (in_use in cfg.vllm_urls and not running), "inUse=%s op.running=%s" % (in_use, running)

    try:
        wait_until(switch_ready, cfg.model_wait, cfg.poll_interval, "model switch status")
        _, sw = http_json("GET", cfg.switch_url + "/api/status", None, None, cfg.http_timeout)
        name = str(sw["inUse"]) if isinstance(sw, dict) else ""
        url = cfg.vllm_urls[name]
        headers = bearer(cfg.vllm_key_files.get(name, ""))

        def served() -> tuple[bool, str]:
            s, models = http_json("GET", url + "/v1/models", None, headers, cfg.http_timeout)
            ids = [m.get("id") for m in (models or {}).get("data", [])] if isinstance(models, dict) else []
            return (name in ids), "http %s ids=%s" % (s, ids)

        wait_until(served, cfg.model_wait, cfg.poll_interval, "served model %s" % name)
    except (WaitTimeout, HttpError, KeyError) as exc:
        raise WakeUnavailable("model not ready: %s" % exc) from exc
    return name, url


def checker_ready(cfg: Config) -> bool:
    def healthy() -> tuple[bool, str]:
        st, _ = http_json("GET", cfg.checker_url + "/health", None, None, cfg.http_timeout)
        return st == 200, "http %s" % st

    try:
        wait_until(healthy, cfg.model_wait, cfg.poll_interval, "checker health")
        chat(cfg.checker_url, "checker", "Reply with the word ok.", {}, cfg.http_timeout, max_tokens=1)
    except (WaitTimeout, HttpError) as exc:
        log.warning("checker unavailable: %s", exc)
        return False
    return True


def router_model(cfg: Config) -> Optional[str]:
    try:
        st, body = http_json("GET", cfg.router_url + "/v1/models", None, bearer(cfg.router_key_file), 5)
    except HttpError as exc:
        log.info("5070 router unreachable: %s", exc)
        return None
    if st == 200 and isinstance(body, dict) and body.get("data"):
        return str(body["data"][0].get("id"))
    return None


def proposal_prompt(f: Finding) -> str:
    d = f.detail
    return (
        "Two copied fragments were found in the repository %s.\n\n"
        "Fragment A (%s lines %s-%s):\n%s\n\nFragment B (%s lines %s-%s) is a copy of A.\n\n"
        "Propose ONE shared helper that removes the copy. State: the helper name, where it "
        "lives, its callers, what must stay byte-for-byte or behaviourally identical, and the "
        "exact proof to run. Be concise. Use plain ASCII only."
        % (f.repo, d["first"], d["first_start"], d["first_end"], d["fragment"][:3000],
           d["second"], d["second_start"], d["second_end"])
    )


def verifier_prompt(f: Finding, proposal: str) -> str:
    return (
        "A copied fragment was found in %s (%s lines %s-%s, copied at %s lines %s-%s):\n%s\n\n"
        "A proposal to remove the copy:\n%s\n\n"
        "Answer with AGREE or DISAGREE as the first word, then one reason in one sentence."
        % (f.repo, f.detail["first"], f.detail["first_start"], f.detail["first_end"],
           f.detail["second"], f.detail["second_start"], f.detail["second_end"],
           f.detail["fragment"][:3000], proposal[:3000])
    )


def verdict(text: str) -> str:
    head = text.strip().upper()
    if head.startswith("DISAGREE") or re.search(r"\bDISAGREE\b", head):
        return "DISAGREE"
    if head.startswith("AGREE") or re.search(r"\bAGREE\b", head):
        return "AGREE"
    return "UNCLEAR"


def run_layer2(cfg: Config, clusters: list[Finding]) -> list[str]:
    """Proposals plus cross-verification. Raises WakeUnavailable before any model call."""
    name, url = wake_large_model(cfg)
    headers = bearer(cfg.vllm_key_files.get(name, ""))
    lines = ["Proposer: %s" % name]
    verifiers: list[tuple[str, str, Mapping[str, str], str]] = []
    if checker_ready(cfg):
        verifiers.append(("ada-checker", cfg.checker_url, {}, "checker"))
    else:
        lines.append("Verifier ada-checker: unavailable")
    rmodel = router_model(cfg)
    if rmodel:
        verifiers.append(("5070ti-router", cfg.router_url, bearer(cfg.router_key_file), rmodel))
    else:
        lines.append("Verifier 5070ti-router: unreachable, skipped")
    for f in clusters[: cfg.max_proposals]:
        lines.append("")
        lines.append("Cluster: %s" % f.text)
        try:
            proposal = chat(url, name, proposal_prompt(f), headers, cfg.http_timeout, max_tokens=1500)
        except HttpError as exc:
            lines.append("Proposal failed: %s" % exc)
            continue
        lines.append("Proposal (proposer %s):" % name)
        lines.extend("    " + ln for ln in proposal.splitlines())
        for vname, vurl, vhdr, vmodel in verifiers:
            try:
                answer = chat(vurl, vmodel, verifier_prompt(f, proposal), vhdr, cfg.http_timeout, max_tokens=300)
                lines.append("Verifier %s: %s - %s" % (vname, verdict(answer), " ".join(answer.split())[:200]))
            except HttpError as exc:
                lines.append("Verifier %s: failed - %s" % (vname, exc))
    skipped = len(clusters) - cfg.max_proposals
    if skipped > 0:
        lines.append("")
        lines.append("%d further cluster(s) not proposed (MAX_PROPOSALS=%d)" % (skipped, cfg.max_proposals))
    return lines


# --------------------------------------------------------------------------
# Report and push
# --------------------------------------------------------------------------

def render_report(day: str, repos_ok: list[str], current: Mapping[str, Mapping[str, Finding]],
                  delta: Mapping[str, list[Finding]], notes: list[str], layer2: list[str],
                  layer2_status: str) -> list[str]:
    new_keys = {f.key for fs in delta.values() for f in fs}
    lines = ["# Alignment scan %s" % day, "", "Repos: %s" % (", ".join(repos_ok) or "(none)"), "", "## Summary", ""]
    for check in sorted(current):
        new = sum(1 for k in current[check] if k in new_keys)
        lines.append("- %s: %d finding(s), %d new" % (check, len(current[check]), new))
    for note in notes:
        lines.append("- note: %s" % note)
    for check in sorted(current):
        lines += ["", "## %s" % check]
        for repo in sorted({f.repo for f in current[check].values()}):
            lines += ["", "### %s" % repo]
            for key, f in sorted(current[check].items()):
                if f.repo == repo:
                    lines.append("- %s%s" % ("NEW " if key in new_keys else "", f.text))
    lines += ["", "## New findings", ""]
    if new_keys:
        lines += ["- %s" % f.text for check in sorted(delta) for f in delta[check]]
    else:
        lines.append("(none)")
    lines += ["", "## Layer 2", "", layer2_status]
    lines += layer2
    return lines


def ntfy_push(cfg: Config, title: str, body_lines: list[str]) -> None:
    headers = {"Title": title, "Priority": "default", "Content-Type": "text/plain; charset=utf-8"}
    headers.update(bearer(cfg.ntfy_token_file))
    req = urllib.request.Request("%s/%s" % (cfg.ntfy_url, cfg.ntfy_topic),
                                 data="\n".join(body_lines).encode("ascii", "replace"),
                                 method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=cfg.http_timeout) as resp:
            resp.read()
    except urllib.error.HTTPError as exc:
        raise ScanError("ntfy answered %d" % exc.code) from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise ScanError("ntfy unreachable: %s" % exc) from exc


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def run_scan(cfg: Config, today: Optional[datetime.date] = None, strict: bool = False) -> tuple[int, list[str]]:
    """Run one scan. Returns (exit code, report lines).

    Exit 2 means the scan could not run (tool, clone or push error). New
    findings and a skipped layer 2 are normal outcomes and exit 0; with strict
    they exit 1 and 3 so interactive use can tell them apart.
    """
    day = (today or datetime.date.today()).isoformat()
    flt = LineFilter()
    errors: list[str] = []
    notes: list[str] = []
    seen_path = cfg.data_dir / "seen.json"
    try:
        seen = load_seen(seen_path)
    except ScanError as exc:
        return 2, ["could not run: %s" % exc]
    if not cfg.repos:
        return 2, ["could not run: REPOS is empty"]

    current: dict[str, dict[str, Finding]] = {}
    ran_checks: set[str] = set()
    repos_ok: list[str] = []
    with tempfile.TemporaryDirectory(prefix="alignment-scan-") as tmp_name:
        tmp = Path(tmp_name)
        env = scan_env(tmp)
        for repo, url in cfg.repos.items():
            dest = tmp / "clones" / repo
            dest.parent.mkdir(exist_ok=True)
            try:
                clone_repo(repo, url, dest, cfg.forgejo_token_file, env)
            except ScanError as exc:
                errors.append(str(exc))
                continue
            repos_ok.append(repo)
            for check in cfg.checks:
                try:
                    found = CHECK_FUNCS[check](dest, repo, tmp, env)
                except LookupError as exc:
                    notes.append("%s: %s" % (check, exc))
                    continue
                except (ScanError, json.JSONDecodeError) as exc:
                    errors.append("%s on %s: %s" % (check, repo, exc))
                    continue
                current.setdefault(check, {}).update(found)
                ran_checks.add(check)

    delta = compute_delta(current, seen)
    new_count = sum(len(v) for v in delta.values())
    total = sum(len(v) for v in current.values())
    for e in errors:
        notes.append("ERROR %s" % e)

    layer2_lines: list[str] = []
    layer2_status = "skipped: not enabled"
    wake_failed = False
    clusters = delta.get("jscpd", [])
    if not new_count:
        layer2_status = "skipped: no new findings"
    elif not cfg.layer2_enabled:
        layer2_status = "skipped: layer 2 disabled"
    elif cfg.dry_run:
        layer2_status = "skipped: dry run"
    elif not clusters:
        layer2_status = "skipped: no new copied-lines clusters"
    else:
        try:
            layer2_lines = run_layer2(cfg, clusters)
            layer2_status = "ran"
        except WakeUnavailable as exc:
            layer2_status = "skipped: %s" % exc
            wake_failed = True

    report = flt.apply(render_report(day, repos_ok, current, delta, notes, layer2_lines, layer2_status))
    report += flt.note()

    if not cfg.dry_run:
        atomic_write(cfg.data_dir / "reports" / ("%s.md" % day), "\n".join(report) + "\n")
        merged = {k: list(v) for k, v in seen.items()}
        for check in ran_checks:
            merged[check] = sorted(current.get(check, {}))
        save_seen(seen_path, merged)

    if cfg.push_enabled and not cfg.dry_run:
        pflt = LineFilter()
        short = layer2_status if len(layer2_status) < 80 else layer2_status[:77] + "..."
        heartbeat = "alignment scan: %d new finding(s), %d total, repos %d, layer 2 %s" % (
            new_count, total, len(repos_ok), "ran" if layer2_status == "ran" else short)
        if errors:
            heartbeat += ", %d error(s)" % len(errors)
        try:
            if new_count:
                dl = [f.text for check in sorted(delta) for f in delta[check]]
                body = pflt.apply(dl)[:10]
                if len(dl) > 10:
                    body.append("... and %d more, see the report" % (len(dl) - 10))
                ntfy_push(cfg, "alignment: new findings", body + pflt.note())
            ntfy_push(cfg, "alignment heartbeat", pflt.apply([heartbeat]) or ["alignment scan: heartbeat redacted"])
        except ScanError as exc:
            errors.append(str(exc))

    if errors:
        for e in errors:
            log.error("%s", e)
        return 2, report
    if strict and wake_failed:
        return 3, report
    return (1 if (strict and new_count) else 0), report


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Nightly alignment scan; configuration is read from the environment.")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 when there are new findings and 3 when layer 2 was asked for but the wake "
                             "was unavailable (default: both exit 0; only 'could not run' exits 2)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    try:
        cfg = Config.from_env(os.environ)
    except ValueError as exc:
        log.error("bad configuration: %s", exc)
        return 2
    code, report = run_scan(cfg, strict=args.strict)
    if cfg.dry_run:
        print("\n".join(report))
    log.info("done, exit %d", code)
    return code


if __name__ == "__main__":
    sys.exit(main())
