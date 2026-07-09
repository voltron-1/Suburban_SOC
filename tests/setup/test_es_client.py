#!/usr/bin/env python3
"""
es_client.py — connection reuse + retry-policy tests (audit #170).

Guards the one safety-critical property of the shared Session factory: retry
on connect/status is enabled (transient, always-safe-to-retry failures), but
retry on read-timeout is explicitly disabled (a write may have already landed
server-side; retrying it risks a duplicate write — e.g. run_hunts.py's bulk
index, slo_metrics.py's SLO doc).

Run:  python tests/setup/test_es_client.py     (or: pytest tests/setup)
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "setup" / "lib"))

import es_client  # noqa: E402


class GetSessionTests(unittest.TestCase):
    def test_returns_a_session_with_auth_set(self):
        session = es_client.get_session("elastic", "hunter2")
        self.assertEqual(session.auth, ("elastic", "hunter2"))

    def test_mounts_retrying_adapter_for_both_schemes(self):
        session = es_client.get_session("elastic", "hunter2")
        https_adapter = session.get_adapter("https://elasticsearch:9200/")
        http_adapter = session.get_adapter("http://elasticsearch:9200/")
        self.assertIsNotNone(https_adapter.max_retries)
        self.assertIsNotNone(http_adapter.max_retries)

    def test_read_timeout_retry_is_disabled(self):
        # The safety-critical property: a hung read on a write (e.g. bulk
        # index) must never be retried automatically — it may have already
        # been applied server-side.
        session = es_client.get_session("elastic", "hunter2")
        retry = session.get_adapter("https://elasticsearch:9200/").max_retries
        self.assertEqual(retry.read, 0)

    def test_connect_and_status_retries_are_enabled(self):
        session = es_client.get_session("elastic", "hunter2", retries=3)
        retry = session.get_adapter("https://elasticsearch:9200/").max_retries
        self.assertEqual(retry.connect, 3)
        self.assertEqual(retry.status, 3)
        self.assertEqual(set(retry.status_forcelist), {502, 503, 504})

    def test_allowed_methods_cover_the_verbs_these_scripts_use(self):
        session = es_client.get_session("elastic", "hunter2")
        retry = session.get_adapter("https://elasticsearch:9200/").max_retries
        self.assertTrue({"GET", "POST", "PUT"}.issubset(retry.allowed_methods))

    def test_retries_param_is_configurable(self):
        session = es_client.get_session("elastic", "hunter2", retries=5)
        retry = session.get_adapter("https://elasticsearch:9200/").max_retries
        self.assertEqual(retry.total, 5)
        self.assertEqual(retry.connect, 5)
        self.assertEqual(retry.status, 5)
        self.assertEqual(retry.read, 0)  # never scales with `retries` — always off


if __name__ == "__main__":
    unittest.main(verbosity=2)
