#!/usr/bin/env python3
"""
Threat-hunt runner — measurement-error visibility tests (audit #165 / NIST SI-11).

run_hunts.py must distinguish "a hunt's ES query failed" from "a hunt
genuinely found 0 matches", and must exit non-zero if any hunt failed to
query or the final bulk index write failed — it must never silently exit 0.

Run:  python tests/hunts/test_run_hunts.py     (or: pytest tests/hunts)
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# ES_PASS is read at import time; must be truthy or main() exits(1) immediately.
os.environ["ES_PASS"] = "unit_test_pass"

SETUP_DIR = Path(__file__).resolve().parents[2] / "scripts" / "setup"
sys.path.insert(0, str(SETUP_DIR))

import run_hunts  # noqa: E402


HUNT_A = """
id: HUNT-TEST-A
title: Test hunt A
attack: ["T1110"]
index: logstash-security-*
query: "*"
threshold: 1
"""

HUNT_B = """
id: HUNT-TEST-B
title: Test hunt B
attack: ["T1046"]
index: logstash-security-*
query: "*"
threshold: 1
"""


class _FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class EsCountTests(unittest.TestCase):
    def test_raises_on_request_exception(self):
        with mock.patch.object(run_hunts.SESSION, "post", side_effect=ConnectionError("refused")):
            with self.assertRaises(run_hunts.HuntQueryUnavailable):
                run_hunts.es_count("logstash-security-*", "*")

    def test_raises_on_non_200(self):
        with mock.patch.object(run_hunts.SESSION, "post", return_value=_FakeResponse(503)):
            with self.assertRaises(run_hunts.HuntQueryUnavailable):
                run_hunts.es_count("logstash-security-*", "*")

    def test_returns_real_zero_when_es_is_healthy(self):
        with mock.patch.object(run_hunts.SESSION, "post",
                               return_value=_FakeResponse(200, {"count": 0})):
            self.assertEqual(run_hunts.es_count("logstash-security-*", "*"), 0)


class MainExitCodeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        hunts_dir = Path(self._tmp.name)
        (hunts_dir / "HUNT-TEST-A.yml").write_text(HUNT_A, encoding="utf-8")
        (hunts_dir / "HUNT-TEST-B.yml").write_text(HUNT_B, encoding="utf-8")
        self._hunts_patch = mock.patch.object(run_hunts, "HUNTS_DIR", hunts_dir)
        self._hunts_patch.start()

    def tearDown(self):
        self._hunts_patch.stop()
        self._tmp.cleanup()

    def _run_main_capturing_exit(self):
        try:
            run_hunts.main()
        except SystemExit as e:
            return e.code
        return None

    def test_all_hunts_healthy_exits_0(self):
        with mock.patch.object(run_hunts.SESSION, "post") as post:
            post.side_effect = [
                _FakeResponse(200, {"count": 0}),   # HUNT-TEST-A query
                _FakeResponse(200, {"count": 0}),   # HUNT-TEST-B query
                _FakeResponse(200, {}),             # bulk index
            ]
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 0)

    def test_one_hunt_query_failure_exits_2_and_skips_that_hunt(self):
        with mock.patch.object(run_hunts.SESSION, "post") as post:
            post.side_effect = [
                ConnectionError("refused"),         # HUNT-TEST-A query fails
                _FakeResponse(200, {"count": 0}),   # HUNT-TEST-B query succeeds
                _FakeResponse(200, {}),             # bulk index (only B's doc)
            ]
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 2)
        # Only HUNT-TEST-B's doc pair should have been bulk-indexed — a failed
        # hunt must never fabricate a "0 matches" finding.
        bulk_call = post.call_args_list[-1]
        sent = bulk_call.kwargs["data"]
        self.assertIn("HUNT-TEST-B", sent)
        self.assertNotIn("HUNT-TEST-A", sent)

    def test_bulk_index_failure_exits_3(self):
        with mock.patch.object(run_hunts.SESSION, "post") as post:
            post.side_effect = [
                _FakeResponse(200, {"count": 0}),
                _FakeResponse(200, {"count": 0}),
                ConnectionError("refused"),         # bulk index fails
            ]
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
