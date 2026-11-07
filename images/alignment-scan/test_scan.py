#!/usr/bin/env python3
"""Tests for scan.py: a local HTTP fake stands in for ntfy, the broker, the
model switch and the model endpoints, with the response shapes the real
services return. Run: uv run --no-project --python 3.12 test_scan.py
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scan  # noqa: E402

VENDOR = "cla" + "ude"
FRAGMENT = "def f():\n    return 1\n" * 4


class Fake:
    """Programmable fake of every endpoint the scan talks to."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, object]] = []
        self.job_states = ["running", "succeeded"]
        self.tier = {"kind": "auto", "reason": "free"}
        self.broker_status = 201
        self.in_use = "qwen3.8-27b"
        self.router_up = True
        self._polls = 0
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):  # silence
                pass

            def _send(self, status: int, body: object) -> None:
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _body(self) -> object:
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                if self.path.startswith("/ntfy/"):
                    return raw.decode()
                return json.loads(raw) if raw else None

            def do_GET(self) -> None:
                fake.calls.append(("GET", self.path, None))
                p = self.path
                if p == "/broker/api/jobs/j1":
                    i = min(fake._polls, len(fake.job_states) - 1)
                    fake._polls += 1
                    self._send(200, {"id": "j1", "state": fake.job_states[i],
                                     "results": {"model": fake.in_use}})
                elif p == "/switch/api/status":
                    self._send(200, {"inUse": fake.in_use, "op": {"running": False}})
                elif p == "/vllm/v1/models":
                    self._send(200, {"data": [{"id": fake.in_use}]})
                elif p == "/checker/health":
                    self._send(200, {"status": "ok"})
                elif p == "/router/v1/models" and fake.router_up:
                    self._send(200, {"data": [{"id": "gemma"}]})
                else:
                    self._send(404, {"error": p})

            def do_POST(self) -> None:
                body = self._body()
                fake.calls.append(("POST", self.path, body))
                p = self.path
                if p == "/broker/api/jobs":
                    self._send(fake.broker_status, {"id": "j1", "tier": fake.tier})
                elif p == "/broker/api/jobs/j1/cancel":
                    self._send(200, {"id": "j1", "state": "withdrawn"})
                elif p.endswith("/v1/chat/completions"):
                    who = p.split("/")[1]
                    if who == "vllm":
                        msg = {"content": "", "reasoning_content": "Add helper shared_x in lib."}
                    else:
                        msg = {"content": "AGREE the helper fits"}
                    self._send(200, {"choices": [{"message": msg}]})
                elif p == "/ntfy/alignment":
                    self._send(200, {"ok": True})
                else:
                    self._send(404, {"error": p})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def posts(self, path: str) -> list[object]:
        return [b for m, p, b in self.calls if m == "POST" and p == path]


def make_repo(root: Path, name: str) -> str:
    repo = root / name
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n")
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e")
    for cmd in (["init", "-q", "-b", "main"], ["add", "."], ["commit", "-q", "-m", "init"]):
        subprocess.run(["git", *cmd], cwd=repo, env=env, check=True)
    return str(repo)


def make_fake_tool(bindir: Path, name: str, source: str) -> None:
    path = bindir / name
    path.write_text(source)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


JSCPD_FAKE = '''#!/usr/bin/env python3
import json, sys
out = sys.argv[sys.argv.index("-o") + 1]
dup = {"format": "python", "lines": 8, "fragment": %r,
       "firstFile": {"name": "a.py", "start": 1, "end": 9},
       "secondFile": {"name": "b.py", "start": 3, "end": 11}}
json.dump({"duplicates": [dup]}, open(out + "/jscpd-report.json", "w"))
''' % FRAGMENT


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.data = self.root / "data"
        self.repo = make_repo(self.root, "r1")
        self.fake = Fake()
        make_fake_tool(self.bin, "jscpd", JSCPD_FAKE)
        self._path = os.environ["PATH"]
        os.environ["PATH"] = str(self.bin) + os.pathsep + self._path

    def tearDown(self) -> None:
        os.environ["PATH"] = self._path
        self.fake.close()
        self.tmp.cleanup()

    def twice(self, **env: str) -> tuple[int, int, list[str]]:
        """Run default then strict from a clean state; return both codes and the strict report."""
        d, _ = scan.run_scan(self.cfg(**env))
        (self.data / "seen.json").unlink()
        s, report = scan.run_scan(self.cfg(**env), strict=True)
        return d, s, report

    def cfg(self, **over: str) -> scan.Config:
        b = self.fake.base
        env = {
            "REPOS": "r1=" + self.repo, "DATA_DIR": str(self.data), "CHECKS": "jscpd",
            "FORGEJO_TOKEN_FILE": str(self.root / "none"), "NTFY_URL": b + "/ntfy",
            "NTFY_TOKEN_FILE": "", "BROKER_URL": b + "/broker", "SWITCH_URL": b + "/switch",
            "VLLM_URLS": "qwen3.8-27b=" + b + "/vllm", "CHECKER_URL": b + "/checker",
            "ROUTER_5070_URL": b + "/router", "JOB_WAIT": "5", "MODEL_WAIT": "5",
            "HTTP_TIMEOUT": "5", "POLL_INTERVAL": "0.05",
        }
        env.update(over)
        return scan.Config.from_env(env)


class KeysAndDelta(Base):
    def test_keys_deterministic(self) -> None:
        rep = {"duplicates": [{"lines": 8, "fragment": FRAGMENT,
                               "firstFile": {"name": "a.py", "start": 1, "end": 9},
                               "secondFile": {"name": "b.py", "start": 3, "end": 11}}]}
        k1 = set(scan.parse_jscpd(rep, "r", Path("/x")))
        k2 = set(scan.parse_jscpd(json.loads(json.dumps(rep)), "r", Path("/x")))
        self.assertEqual(k1, k2)
        rep["duplicates"][0]["fragment"] += "z"
        self.assertNotEqual(k1, set(scan.parse_jscpd(rep, "r", Path("/x"))))
        key = next(iter(k1))
        self.assertTrue(key.startswith("jscpd|r|a.py|b.py|"))

    def test_vulture_and_shellcheck_keys(self) -> None:
        v = scan.parse_vulture("apps/x.py:12: unused function 'foo' (60% confidence)\njunk\n", "r")
        self.assertEqual(list(v), ["vulture|r|apps/x.py|foo"])
        s = scan.parse_shellcheck(json.dumps({"comments": [{"file": "a.sh", "line": 3, "code": 2086, "message": "m"}]}), "r")
        self.assertEqual(list(s), ["shellcheck|r|a.sh|3|SC2086"])

    def test_delta(self) -> None:
        f = scan.Finding("k1", "c", "r", "t1")
        g = scan.Finding("k2", "c", "r", "t2")
        d = scan.compute_delta({"c": {"k1": f, "k2": g}}, {"c": ["k1"]})
        self.assertEqual([x.key for x in d["c"]], ["k2"])
        self.assertEqual(scan.compute_delta({"c": {"k1": f}}, {"c": ["k1"]}), {})


class Modes(Base):
    def test_first_run_then_stable(self) -> None:
        code, _ = scan.run_scan(self.cfg())
        self.assertEqual(code, 0)
        self.assertEqual(scan.run_scan(self.cfg(), strict=True)[0], 0)  # already seen
        (self.data / "seen.json").unlink()
        self.assertEqual(scan.run_scan(self.cfg(), strict=True)[0], 1)
        seen = json.loads((self.data / "seen.json").read_text())
        self.assertEqual(len(seen["jscpd"]), 1)
        code, _ = scan.run_scan(self.cfg(), strict=True)
        self.assertEqual(code, 0)

    def test_dry_run_writes_and_pushes_nothing(self) -> None:
        code, report = scan.run_scan(self.cfg(DRY_RUN="1", PUSH_ENABLED="true", LAYER2_ENABLED="true"), strict=True)
        self.assertEqual(code, 1)
        self.assertFalse(self.data.exists())
        self.assertEqual(self.fake.posts("/ntfy/alignment"), [])
        self.assertEqual(self.fake.posts("/broker/api/jobs"), [])
        self.assertTrue(any("dry run" in ln for ln in report))

    def test_push_disabled_pushes_nothing(self) -> None:
        scan.run_scan(self.cfg(PUSH_ENABLED="false"))
        self.assertEqual(self.fake.posts("/ntfy/alignment"), [])
        self.assertTrue((self.data / "seen.json").exists())

    def test_push_enabled_sends_delta_and_heartbeat(self) -> None:
        scan.run_scan(self.cfg(PUSH_ENABLED="true"))
        self.assertEqual(len(self.fake.posts("/ntfy/alignment")), 2)

    def test_missing_conformance_tool_is_a_note(self) -> None:
        _, report = scan.run_scan(self.cfg(CHECKS="conformance"))
        self.assertTrue(any("not available" in ln for ln in report))

    def test_conformance_tool_runs_when_present(self) -> None:
        make_fake_tool(self.bin, scan.CONFORMANCE_TOOL, "#!/bin/sh\necho 'tree x drifted'\n")
        code, report = scan.run_scan(self.cfg(CHECKS="conformance"))
        self.assertEqual(code, 0)
        self.assertTrue(any("tree x drifted" in ln for ln in report))

    def test_unreachable_mirror_exits_2(self) -> None:
        code, _ = scan.run_scan(self.cfg(REPOS="r1=" + str(self.root / "missing")))
        self.assertEqual(code, 2)

    def test_removed_finding_is_new_again_when_it_returns(self) -> None:
        scan.run_scan(self.cfg())
        (self.bin / "jscpd").write_text('#!/usr/bin/env python3\nimport sys, json\nout = sys.argv[sys.argv.index("-o") + 1]\njson.dump({"duplicates": []}, open(out + "/jscpd-report.json", "w"))\n')
        scan.run_scan(self.cfg())
        self.assertEqual(json.loads((self.data / "seen.json").read_text())["jscpd"], [])
        make_fake_tool(self.bin, "jscpd", JSCPD_FAKE)
        code, _ = scan.run_scan(self.cfg())
        self.assertEqual(code, 0)
        self.assertEqual(json.loads((self.data / "seen.json").read_text())["jscpd"] != [], True)


class Layer2(Base):
    def test_happy_path_records_proposal_and_verdicts(self) -> None:
        code, report = scan.run_scan(self.cfg(LAYER2_ENABLED="true"))
        self.assertEqual(code, 0)
        text = "\n".join(report)
        self.assertIn("Proposal (proposer qwen3.8-27b)", text)
        self.assertIn("Add helper shared_x in lib.", text)
        self.assertIn("Verifier ada-checker: AGREE", text)
        self.assertIn("Verifier 5070ti-router: AGREE", text)
        job = self.fake.posts("/broker/api/jobs")[0]
        assert isinstance(job, dict)
        self.assertEqual(job["type"], "alignment-wake")
        self.assertEqual(self.fake.posts("/broker/api/jobs/j1/cancel"), [])

    def test_router_unreachable_is_skipped(self) -> None:
        self.fake.router_up = False
        _, report = scan.run_scan(self.cfg(LAYER2_ENABLED="true"))
        self.assertTrue(any("5070ti-router: unreachable" in ln for ln in report))

    def test_ask_tier_cancels_and_exits_3(self) -> None:
        self.fake.tier = {"kind": "ask", "reason": "needs approval"}
        dflt, code, report = self.twice(LAYER2_ENABLED="true")
        self.assertEqual((dflt, code), (0, 3))
        self.assertEqual(len(self.fake.posts("/broker/api/jobs/j1/cancel")), 2)
        self.assertTrue(any("skipped: needs approval" in ln for ln in report))
        self.assertTrue((self.data / "seen.json").exists())

    def test_busy_broker_is_skipped(self) -> None:
        self.fake.broker_status = 429
        dflt, code, report = self.twice(LAYER2_ENABLED="true")
        self.assertEqual((dflt, code), (0, 3))
        self.assertTrue(any("429" in ln for ln in report))

    def test_deadline_exits_3_with_last_state(self) -> None:
        self.fake.job_states = ["running"]
        dflt, code, report = self.twice(LAYER2_ENABLED="true", JOB_WAIT="0.3")
        self.assertEqual((dflt, code), (0, 3))
        self.assertTrue(any("last state: running" in ln for ln in report))


class Filters(Base):
    def test_ascii_and_vendor(self) -> None:
        flt = scan.LineFilter()
        self.assertEqual(flt.clean("caf\u00e9 \u2014 ok"), "caf? ? ok")
        self.assertIsNone(flt.clean("written by " + VENDOR.upper()))
        self.assertIsNone(flt.clean("see anthro" + "pic docs"))
        self.assertEqual(flt.redacted, 2)
        self.assertEqual(flt.note(), ["(redacted: 2 line(s))"])

    def test_report_is_filtered(self) -> None:
        make_fake_tool(self.bin, scan.CONFORMANCE_TOOL, "#!/bin/sh\necho 'by %s'\necho 'plain'\n" % VENDOR)
        _, report = scan.run_scan(self.cfg(CHECKS="conformance"))
        text = "\n".join(report)
        self.assertNotIn(VENDOR, text.lower())
        self.assertIn("redacted", text)
        self.assertTrue(text.isascii())


class Atomic(Base):
    def test_atomic_write_leaves_no_temp_and_keeps_old_on_failure(self) -> None:
        path = self.root / "d" / "seen.json"
        scan.save_seen(path, {"a": ["2", "1"]})
        self.assertEqual(json.loads(path.read_text()), {"a": ["1", "2"]})
        self.assertEqual([p.name for p in path.parent.iterdir()], ["seen.json"])
        with self.assertRaises(TypeError):
            scan.save_seen(path, {"a": [object()]})  # type: ignore[list-item]
        self.assertEqual(json.loads(path.read_text()), {"a": ["1", "2"]})
        self.assertEqual([p.name for p in path.parent.iterdir()], ["seen.json"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
