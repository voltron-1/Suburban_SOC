#!/usr/bin/env python3
"""
compact_agent_approval_queue.py — approval-queue compaction tests (issue #176).

Guards the core safety property: an id's FULL history is archived only when
its latest recorded status is a true terminal state (approved/denied) AND
that status is older than the retention window. Pending or claimed-but-not-
resolved ids, and recently-resolved ids, must never be silently dropped.

Run:  pytest tests/ai_agent/test_compact_agent_approval_queue.py
"""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import compact_agent_approval_queue as caq


def _write_queue(path, entries):
    with open(path, "w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")


def _read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


class CompactTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.queue = os.path.join(self._tmp.name, "approval_queue.jsonl")
        self.archive = os.path.join(self._tmp.name, "approval_queue.archive.jsonl")
        mock.patch.object(caq, "APPROVAL_QUEUE", Path(self.queue)).start()
        mock.patch.object(caq, "ARCHIVE_QUEUE", Path(self.archive)).start()
        # _QUEUE_LOCK_PATH is derived from APPROVAL_QUEUE at import time, so
        # patching APPROVAL_QUEUE alone leaves it pointing at the real default.
        mock.patch.object(caq, "_QUEUE_LOCK_PATH", Path(self.queue + ".lock")).start()
        self.addCleanup(mock.patch.stopall)

    def test_missing_queue_file_is_a_no_op(self):
        self.assertEqual(caq.compact(), 0)

    def test_old_resolved_entry_is_archived(self):
        old = time.time() - 40 * 86400
        _write_queue(self.queue, [
            {"id": "a1", "ts": old, "status": "pending"},
            {"id": "a1", "ts": old + 1, "status": "approved"},
        ])
        archived_count = caq.compact(retention_days=30)
        self.assertEqual(archived_count, 1)
        self.assertEqual(_read_lines(self.queue), [])
        archived = _read_lines(self.archive)
        self.assertEqual(len(archived), 2)
        self.assertEqual({e["status"] for e in archived}, {"pending", "approved"})

    def test_recent_resolved_entry_is_not_yet_archived(self):
        recent = time.time() - 2 * 86400
        _write_queue(self.queue, [
            {"id": "a2", "ts": recent, "status": "pending"},
            {"id": "a2", "ts": recent + 1, "status": "denied"},
        ])
        archived_count = caq.compact(retention_days=30)
        self.assertEqual(archived_count, 0)
        self.assertEqual(len(_read_lines(self.queue)), 2)
        self.assertEqual(_read_lines(self.archive), [])

    def test_still_pending_entry_is_never_archived_regardless_of_age(self):
        old = time.time() - 400 * 86400
        _write_queue(self.queue, [{"id": "a3", "ts": old, "status": "pending"}])
        archived_count = caq.compact(retention_days=30)
        self.assertEqual(archived_count, 0)
        self.assertEqual(len(_read_lines(self.queue)), 1)

    def test_claimed_but_never_resolved_is_never_archived(self):
        # A "claimed" latest status means the request started resolving but the
        # process crashed before writing approved/denied — must stay visible
        # for a human to investigate, not be silently swept into the archive.
        old = time.time() - 400 * 86400
        _write_queue(self.queue, [
            {"id": "a4", "ts": old, "status": "pending"},
            {"id": "a4", "ts": old + 1, "status": "claimed"},
        ])
        archived_count = caq.compact(retention_days=30)
        self.assertEqual(archived_count, 0)
        self.assertEqual(len(_read_lines(self.queue)), 2)

    def test_dry_run_reports_but_writes_nothing(self):
        old = time.time() - 40 * 86400
        _write_queue(self.queue, [
            {"id": "a5", "ts": old, "status": "pending"},
            {"id": "a5", "ts": old + 1, "status": "approved"},
        ])
        archived_count = caq.compact(retention_days=30, dry_run=True)
        self.assertEqual(archived_count, 1)
        self.assertEqual(len(_read_lines(self.queue)), 2)   # untouched
        self.assertFalse(os.path.exists(self.archive))       # never created

    def test_malformed_line_is_skipped_not_fatal(self):
        old = time.time() - 40 * 86400
        with open(self.queue, "w", encoding="utf-8") as fh:
            fh.write("not valid json\n")
            fh.write(json.dumps({"id": "a6", "ts": old, "status": "approved"}) + "\n")
        archived_count = caq.compact(retention_days=30)
        self.assertEqual(archived_count, 1)

    def test_mixed_ids_only_archives_the_eligible_ones(self):
        old = time.time() - 40 * 86400
        recent = time.time() - 2 * 86400
        _write_queue(self.queue, [
            {"id": "old-resolved", "ts": old, "status": "approved"},
            {"id": "recent-resolved", "ts": recent, "status": "denied"},
            {"id": "still-pending", "ts": old, "status": "pending"},
        ])
        archived_count = caq.compact(retention_days=30)
        self.assertEqual(archived_count, 1)
        remaining_ids = {e["id"] for e in _read_lines(self.queue)}
        self.assertEqual(remaining_ids, {"recent-resolved", "still-pending"})
        archived_ids = {e["id"] for e in _read_lines(self.archive)}
        self.assertEqual(archived_ids, {"old-resolved"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
