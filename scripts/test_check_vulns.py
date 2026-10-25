"""Offline checks for check-vulns.py: the ignore file, lock detection, and
what blocks. Run: python3 scripts/test_check_vulns.py"""

import datetime
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("check_vulns", Path(__file__).with_name("check-vulns.py"))
cv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cv)


def finding(severity, shipped=True, ids=("GHSA-aaaa-bbbb-cccc",), fix=""):
    return cv.Finding(".", "pypi", "pkg", "1.0", list(ids), severity, shipped, "title", fix)


class Blocking(unittest.TestCase):
    def test_high_critical_and_unknown_block_when_shipped(self):
        for sev in ("high", "critical", "unknown"):
            self.assertTrue(finding(sev).blocks(False), sev)
        for sev in ("moderate", "low"):
            self.assertFalse(finding(sev).blocks(False), sev)

    def test_dev_only_blocks_only_with_all_deps(self):
        f = finding("critical", shipped=False)
        self.assertFalse(f.blocks(False))
        self.assertTrue(f.blocks(True))

    def test_an_ignored_finding_never_blocks(self):
        f = finding("critical")
        f.ignored = "accepted"
        self.assertFalse(f.blocks(True))

    def test_a_group_takes_the_worst_severity_and_the_highest_fix(self):
        g = cv.Group([finding("moderate", fix="2.9.0"), finding("critical", ids=("GHSA-x",), fix="2.10.1")])
        self.assertEqual(g.severity, "critical")
        self.assertTrue(g.blocks(False))
        self.assertIn("fix: 2.10.1", g.line())


class NpmAdvisories(unittest.TestCase):
    VULNS = {
        "expo": {"severity": "high", "via": ["@expo/cli"], "range": "*"},
        "@expo/cli": {"severity": "high", "via": ["node-forge", "zod"], "range": "*"},
        "node-forge": {"severity": "high", "via": [
            {"url": "https://github.com/advisories/GHSA-aaaa", "title": "forge", "severity": "high", "name": "node-forge"}]},
        "zod": {"severity": "high", "via": [
            {"url": "https://github.com/advisories/GHSA-bbbb", "title": "zod", "severity": "high", "name": "zod"},
            {"url": "https://github.com/advisories/GHSA-cccc", "title": "zod2", "severity": "moderate", "name": "zod"}]},
    }

    def test_a_package_flagged_through_others_carries_their_advisories(self):
        urls = sorted(a["url"].rsplit("/", 1)[-1] for a in cv.npm_advisories(self.VULNS, "expo"))
        self.assertEqual(urls, ["GHSA-aaaa", "GHSA-bbbb", "GHSA-cccc"])

    def test_cycles_terminate(self):
        vulns = {"a": {"via": ["b"]}, "b": {"via": ["a"]}}
        self.assertEqual(cv.npm_advisories(vulns, "a"), [])


class IgnoreFile(unittest.TestCase):
    def read(self, text, today=datetime.date(2026, 10, 25)):
        with tempfile.TemporaryDirectory() as d:
            Path(d, ".vuln-ignore").write_text(text)
            return cv.read_ignores(d, today)

    def test_active_entry(self):
        active, problems = self.read("GHSA-1 2026-12-01 not reachable from the server\n")
        self.assertEqual(problems, [])
        self.assertIn("GHSA-1", active)

    def test_expired_entry_is_reported_and_inactive(self):
        active, problems = self.read("GHSA-1 2026-10-01 old reason\n")
        self.assertEqual(active, {})
        self.assertIn("expired", problems[0])

    def test_missing_reason_or_bad_date(self):
        _, p1 = self.read("GHSA-1 2026-12-01\n")
        _, p2 = self.read("GHSA-1 soon because\n")
        self.assertIn("reason is required", p1[0])
        self.assertIn("expected", p2[0])

    def test_comments_and_blank_lines(self):
        active, problems = self.read("# accepted risks\n\nGHSA-1 2026-12-01 reason\n")
        self.assertEqual((len(active), problems), (1, []))


class Locks(unittest.TestCase):
    def write(self, text):
        d = tempfile.mkdtemp()
        p = Path(d, "requirements.txt")
        p.write_text(text)
        return p

    def test_a_hashed_lock_is_used_as_written(self):
        p = self.write("# lock\ntorch==2.8.0+cpu --hash=sha256:aa \\\n    --hash=sha256:bb\nidna==3.20 --hash=sha256:cc\n"
                       "--extra-index-url https://download.pytorch.org/whl/cpu\n")
        self.assertEqual(cv.pinned_lines(p), ["torch==2.8.0+cpu", "idna==3.20"])

    def test_a_file_without_hashes_is_resolved(self):
        self.assertIsNone(cv.pinned_lines(self.write("fastapi==0.115.0\n")))

    def test_discovery_skips_vendored_trees(self):
        with tempfile.TemporaryDirectory() as d:
            for rel in ("package-lock.json", "web/package-lock.json", "node_modules/x/package-lock.json",
                        "svc/uv.lock", "svc/requirements.txt", "tools/requirements-dev.txt", ".venv/lib/go.mod", "go.mod"):
                Path(d, rel).parent.mkdir(parents=True, exist_ok=True)
                Path(d, rel).write_text("")
            node, uv, reqs, go = cv.discover(Path(d))
            names = lambda ps: sorted(str(Path(p).relative_to(d)) for p in ps)
            self.assertEqual(names(node), [".", "web"])
            self.assertEqual(names(uv), ["svc"])
            self.assertEqual(names(reqs), ["tools/requirements-dev.txt"])
            self.assertEqual(names(go), ["."])


if __name__ == "__main__":
    unittest.main()
