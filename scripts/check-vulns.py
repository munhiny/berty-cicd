#!/usr/bin/env python3
"""Vulnerability gate for a repository: blocks on high or critical known
vulnerabilities in the dependencies that ship, and reports the rest.

One script for every place the check runs: the vuln-check and build-and-push
workflows in this repository, and the pre-push step of the deploy flow on a
workstation. Each runs this file from this repository's main branch, so the
rules cannot drift between them.

What it scans, found anywhere under the root (node_modules, virtualenvs,
vendor and build output are skipped):

  package-lock.json  npm audit --omit=dev decides; the full audit is reported
  uv.lock            uv export without the dev group, then pip-audit; the dev
                     group is audited and reported
  requirements*.txt  a hashed lock is audited as written, anything else is
                     resolved with uv pip compile first; a file whose name
                     contains "dev" or "test" is report-only
  go.mod             govulncheck; only vulnerabilities reachable from the code
                     count, and those all ship in the binary

Severity: npm reports it. pip-audit and govulncheck do not, so each finding is
looked up in OSV (api.osv.dev) through its GitHub advisory alias, and for an
advisory with only a CVE alias (most Go ones) in GitHub's advisory database by
that CVE (GITHUB_TOKEN or GH_TOKEN raises GitHub's rate limit). A finding
whose severity cannot be found counts as blocking: an unknown is not a pass.

Accepted risks live in .vuln-ignore at the repository root, one per line:

  <advisory id> <expires YYYY-MM-DD> <reason>

The id may be any of a finding's ids (GHSA-..., CVE-..., PYSEC-..., GO-...).
An expired line no longer suppresses anything and is reported.

Usage:
  check-vulns.py [--root DIR] [--all-deps]

  --all-deps   dev and test dependencies block too

Exit codes: 0 nothing blocking, 1 blocking findings, 2 the check could not
run (a scanner or the network failed). 2 is not a pass.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

BLOCKING = {"high", "critical"}
# Worst first when several advisories hit one package; unknown counts as blocking.
RANK = {"critical": 0, "high": 1, "unknown": 2, "moderate": 3, "medium": 3, "low": 4}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "vendor", "dist", "build", "__pycache__",
             ".berty-cicd", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
OSV_URL = "https://api.osv.dev/v1/vulns/"
GH_ADVISORIES_URL = "https://api.github.com/advisories?cve_id="


class CheckError(Exception):
    """The check could not run; the caller exits 2."""


def run(cmd, cwd, ok_codes=(0,)):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=900)
    except FileNotFoundError as exc:
        raise CheckError("%s is not installed" % cmd[0]) from exc
    except subprocess.TimeoutExpired as exc:
        raise CheckError("%s timed out in %s" % (" ".join(cmd[:3]), cwd)) from exc
    if p.returncode not in ok_codes:
        raise CheckError("%s failed in %s (exit %d): %s" % (" ".join(cmd[:3]), cwd, p.returncode,
                                                           (p.stderr or p.stdout).strip()[-600:]))
    return p


# ---- severity --------------------------------------------------------------

_osv_cache = {}


def osv_record(vuln_id):
    if vuln_id in _osv_cache:
        return _osv_cache[vuln_id]
    try:
        with urllib.request.urlopen(OSV_URL + vuln_id, timeout=20) as r:
            rec = json.load(r)
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code != 404:
            raise CheckError("OSV lookup of %s failed: HTTP %d" % (vuln_id, exc.code)) from exc
        rec = None
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise CheckError("OSV lookup of %s failed: %s" % (vuln_id, exc)) from exc
    _osv_cache[vuln_id] = rec
    return rec


def github_severity(cve):
    """GitHub's severity for a CVE, or None (not found, or the API refused)."""
    req = urllib.request.Request(GH_ADVISORIES_URL + cve, headers={"Accept": "application/vnd.github+json"})
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            rows = json.load(r)
    except urllib.error.HTTPError as exc:
        exc.close()
        return None  # left unknown, which blocks
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None
    sevs = [row.get("severity") for row in rows if isinstance(row, dict) and row.get("severity") not in (None, "unknown")]
    return sevs[0] if sevs else None


def severity_of(ids):
    """The GitHub advisory severity of the first id (or alias) that has one,
    lowercased ("moderate" for GitHub's medium), or "unknown"."""
    seen, queue = set(), sorted(ids, key=lambda i: not i.startswith("GHSA-"))
    while queue:
        vid = queue.pop(0)
        if vid in seen:
            continue
        seen.add(vid)
        rec = osv_record(vid)
        if not rec:
            continue
        sev = (rec.get("database_specific") or {}).get("severity")
        if isinstance(sev, str) and sev:
            return sev.lower()
        queue += [a for a in rec.get("aliases", []) if a.startswith("GHSA-") and a not in seen]
    for cve in sorted(i for i in ids if i.startswith("CVE-")):
        sev = github_severity(cve)
        if sev:
            return "moderate" if sev == "medium" else sev.lower()
    return "unknown"


# ---- findings --------------------------------------------------------------

class Group:
    """Every finding for one package version in one project."""

    def __init__(self, items):
        first = items[0]
        self.items = items
        self.project, self.ecosystem, self.package, self.version = first.project, first.ecosystem, first.package, first.version
        self.shipped = first.shipped
        self.severity = min((f.severity for f in items), key=lambda v: RANK.get(v, 2))

    def blocks(self, all_deps):
        return any(f.blocks(all_deps) for f in self.items)

    def line(self):
        where = "shipped" if self.shipped else "dev/test"
        live = [f for f in self.items if not f.ignored]
        ids = [f.ids[0] if not [i for i in f.ids if i.startswith("GHSA-")] else
               [i for i in f.ids if i.startswith("GHSA-")][0] for f in live] or [self.items[0].ids[0]]
        fixes = sorted({f.fix.strip() for f in live if f.fix.strip()},
                       key=lambda v: [int(n) for n in re.findall(r"\d+", v)])
        text = "%s %s %s@%s [%s, %s] %d advisor%s: %s" % (
            self.project, self.ecosystem, self.package, self.version, self.severity, where,
            len(live), "y" if len(live) == 1 else "ies", ", ".join(ids[:4]) + (", ..." if len(ids) > 4 else ""))
        if fixes:
            text += " (fix: %s)" % fixes[-1]
        title = next((f.title for f in live if f.title and not f.title.startswith("#")), "")
        if len(live) == 1 and title:
            text += " - " + title[:110]
        ignored = [f for f in self.items if f.ignored]
        if ignored:
            text += " (%d ignored)" % len(ignored)
        return text


class Finding:
    def __init__(self, project, ecosystem, package, version, ids, severity, shipped, title="", fix=""):
        self.project, self.ecosystem, self.package, self.version = project, ecosystem, package, version
        self.ids, self.severity, self.shipped, self.title, self.fix = ids, severity, shipped, title, fix
        self.ignored = None  # the .vuln-ignore reason when suppressed

    def blocks(self, all_deps):
        if self.ignored:
            return False
        return (self.shipped or all_deps) and (self.severity in BLOCKING or self.severity == "unknown")

    def line(self):
        where = "shipped" if self.shipped else "dev/test"
        text = "%s %s %s@%s [%s, %s] %s" % (self.project, self.ecosystem, self.package, self.version,
                                            self.severity, where, ", ".join(self.ids[:3]))
        if self.fix:
            text += " (fix: %s)" % self.fix.strip()
        if self.title:
            text += " - " + self.title[:120]
        if self.ignored:
            text += " (ignored: %s)" % self.ignored
        return text


def rel(root, path):
    r = os.path.relpath(path, root)
    return "." if r == "." else r


# ---- node ------------------------------------------------------------------

def npm_audit(cwd, omit_dev):
    cmd = ["npm", "audit", "--json"] + (["--omit=dev"] if omit_dev else [])
    p = run(cmd, cwd, ok_codes=(0, 1))
    try:
        data = json.loads(p.stdout or "{}")
    except ValueError as exc:
        raise CheckError("npm audit in %s printed no JSON: %s" % (cwd, p.stderr.strip()[-300:])) from exc
    if "error" in data:
        raise CheckError("npm audit in %s: %s" % (cwd, data["error"].get("summary", data["error"])))
    return data.get("vulnerabilities") or {}


def node_findings(root, d):
    proj = rel(root, d)
    shipped = npm_audit(d, omit_dev=True)
    everything = npm_audit(d, omit_dev=False)
    out = []
    for name, v in everything.items():
        advisories = [x for x in v.get("via", []) if isinstance(x, dict)]
        ids = [a["url"].rsplit("/", 1)[-1] for a in advisories if a.get("url")] or [name]
        title = advisories[0].get("title", "") if advisories else "through " + ", ".join(
            x for x in v.get("via", []) if isinstance(x, str))
        fix = v.get("fixAvailable")
        fix = "%s %s" % (fix.get("name", ""), fix.get("version", "")) if isinstance(fix, dict) else ""
        out.append(Finding(proj, "npm", name, v.get("range", ""), ids, (v.get("severity") or "unknown").lower(),
                           name in shipped, title, fix))
    return out


# ---- python ----------------------------------------------------------------

def pip_audit(req_file, cwd):
    p = run(["uvx", "pip-audit", "-r", str(req_file), "--no-deps", "--disable-pip", "--format", "json",
             "--progress-spinner", "off"], cwd, ok_codes=(0, 1))
    try:
        data = json.loads(p.stdout or "{}")
    except ValueError as exc:
        raise CheckError("pip-audit in %s printed no JSON: %s" % (cwd, p.stderr.strip()[-300:])) from exc
    return [(dep["name"], dep.get("version", ""), v) for dep in data.get("dependencies", []) for v in dep.get("vulns", [])]


def python_findings_from(proj, cwd, req_file, shipped):
    out = []
    for name, version, v in pip_audit(req_file, cwd):
        ids = [v["id"]] + list(v.get("aliases", []))
        out.append(Finding(proj, "pypi", name, version, ids, severity_of(ids), shipped,
                           (v.get("description") or "").split("\n")[0], ", ".join(v.get("fix_versions", []))))
    return out


def uv_findings(root, d, tmp):
    proj = rel(root, d)
    base = ["uv", "export", "--frozen", "--no-hashes", "--no-emit-project", "--format", "requirements-txt"]
    shipped_req = Path(tmp) / ("ship-%d.txt" % abs(hash(proj)))
    all_req = Path(tmp) / ("all-%d.txt" % abs(hash(proj)))
    run(base + ["--no-dev", "-o", str(shipped_req)], d)
    run(base + ["--all-groups", "-o", str(all_req)], d)
    names = {re.split(r"[=<>!~ ;\[]", ln, maxsplit=1)[0].strip().lower().replace("_", "-")
             for ln in shipped_req.read_text().splitlines() if ln and not ln.startswith(("#", " ", "-"))}
    found = python_findings_from(proj, d, all_req, True)
    for f in found:
        f.shipped = f.package.lower().replace("_", "-") in names
    return found


def requirements_findings(root, req, tmp):
    proj = rel(root, req)
    shipped = not re.search(r"dev|test", req.name, re.IGNORECASE)
    pinned = Path(tmp) / ("req-%d.txt" % abs(hash(proj)))
    exact = pinned_lines(req)
    if exact is not None:
        pinned.write_text("\n".join(exact) + "\n")
    else:
        run(["uv", "pip", "compile", "--quiet", "--no-header", str(req), "-o", str(pinned)], req.parent)
    return python_findings_from(proj, req.parent, pinned, shipped)


def pinned_lines(req):
    """name==version for every requirement when the file is a hashed lock (it
    lists every transitive dependency, and an image installs exactly those),
    else None and the file is resolved."""
    text = req.read_text(encoding="utf-8")
    if "--hash=" not in text:
        return None
    out = []
    for raw in text.splitlines():
        ln = raw.split("#", 1)[0].strip().rstrip("\\").strip()
        if not ln or ln.startswith("--"):
            continue
        m = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?==([^\s;]+)(\s*;.*)?(\s+--hash=\S+)*", ln)
        if not m:
            return None
        out.append("%s==%s" % (m.group(1), m.group(3)))
    return out


# ---- go --------------------------------------------------------------------

def go_findings(root, d):
    proj = rel(root, d)
    p = run(["go", "run", "golang.org/x/vuln/cmd/govulncheck@latest", "-format", "json", "./..."], d)
    osv, reachable = {}, {}
    dec = json.JSONDecoder()
    text, i = p.stdout, 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        msg, i = dec.raw_decode(text, i)
        if "osv" in msg:
            osv[msg["osv"]["id"]] = msg["osv"]
        f = msg.get("finding")
        if f and any(fr.get("function") for fr in f.get("trace", [])):
            reachable.setdefault(f["osv"], f)
    out = []
    for vid, f in reachable.items():
        rec = osv.get(vid, {})
        ids = [vid] + list(rec.get("aliases", []))
        frame = (f.get("trace") or [{}])[0]
        out.append(Finding(proj, "go", frame.get("module", ""), frame.get("version", ""), ids, severity_of(ids),
                           True, rec.get("summary", ""), f.get("fixed_version", "")))
    return out


# ---- discovery and the ignore file -----------------------------------------

def discover(root):
    node, uv, reqs, go = [], [], [], []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(n for n in dirnames if n not in SKIP_DIRS and not n.startswith(".venv"))
        here = Path(dirpath)
        if "package-lock.json" in filenames:
            node.append(here)
        if "uv.lock" in filenames:
            uv.append(here)
        else:
            reqs += [here / n for n in sorted(filenames) if re.fullmatch(r"requirements[\w.-]*\.txt", n)]
        if "go.mod" in filenames:
            go.append(here)
    return node, uv, reqs, go


def read_ignores(root, today):
    path = Path(root) / ".vuln-ignore"
    active, problems = {}, []
    if not path.is_file():
        return active, problems
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split(None, 2)
        try:
            expires = datetime.date.fromisoformat(parts[1])
        except (IndexError, ValueError):
            problems.append(".vuln-ignore:%d: expected '<id> <YYYY-MM-DD> <reason>'" % n)
            continue
        if len(parts) < 3:
            problems.append(".vuln-ignore:%d: a reason is required" % n)
        elif expires < today:
            problems.append(".vuln-ignore:%d: %s expired on %s and no longer applies" % (n, parts[0], expires))
        else:
            active[parts[0]] = "%s (until %s)" % (parts[2], expires)
    return active, problems


def main():
    ap = argparse.ArgumentParser(description="Vulnerability gate: blocks on high or critical in shipped dependencies.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--all-deps", action="store_true")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    node, uv, reqs, go = discover(root)
    if not (node or uv or reqs or go):
        print("check-vulns: no package-lock.json, uv.lock, requirements*.txt or go.mod under %s; nothing to scan" % root)
        return 0
    print("check-vulns: scanning %d npm, %d uv, %d requirements and %d go project(s) under %s"
          % (len(node), len(uv), len(reqs), len(go), root))
    findings = []
    try:
        with tempfile.TemporaryDirectory(prefix="check-vulns-") as tmp:
            for d in node:
                findings += node_findings(root, d)
            for d in uv:
                findings += uv_findings(root, d, tmp)
            for r in reqs:
                findings += requirements_findings(root, r, tmp)
            if go and not shutil.which("go"):
                raise CheckError("go.mod found but go is not installed")
            for d in go:
                findings += go_findings(root, d)
    except CheckError as exc:
        print("check-vulns: could not run: %s" % exc, file=sys.stderr)
        return 2
    unique = {}
    for f in findings:
        unique.setdefault((f.project, f.ecosystem, f.package, f.version, frozenset(f.ids)), f)
    findings = list(unique.values())
    ignores, problems = read_ignores(root, datetime.date.today())
    for f in findings:
        hit = next((i for i in f.ids if i in ignores), None)
        if hit:
            f.ignored = ignores[hit]
    by_package = {}
    for f in findings:
        by_package.setdefault((f.project, f.ecosystem, f.package, f.version, f.shipped), []).append(f)
    groups = sorted((Group(v) for v in by_package.values()), key=lambda g: (g.project, RANK.get(g.severity, 2), g.package))
    blocking = [g for g in groups if g.blocks(args.all_deps)]
    reported = [g for g in groups if g not in blocking]
    for p in problems:
        print("WARN  " + p)
    for f in reported:
        print("note  " + f.line())
    for f in blocking:
        print("BLOCK " + f.line())
    if blocking:
        print("check-vulns: %d blocking package(s) (high or critical, or unknown severity, in %s). "
              "Upgrade the package, or record an accepted risk with an expiry in .vuln-ignore."
              % (len(blocking), "any dependency" if args.all_deps else "shipped dependencies"))
        return 1
    print("check-vulns: nothing blocking (%d package(s) with other findings reported above)" % len(reported) if reported
          else "check-vulns: no known vulnerabilities")
    return 0


if __name__ == "__main__":
    sys.exit(main())
