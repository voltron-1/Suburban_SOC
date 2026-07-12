#!/usr/bin/env python3
"""
compact_agent_approval_queue.py — bounds growth of approval_queue.jsonl (#176).

The queue is append-only by design (audit trail — every draft/claim/resolution
is its own line, never edited in place). Left alone it grows forever. This
archives entries whose id's LATEST recorded status is a true terminal state
(approved/denied) and whose most recent line is older than the retention
window; everything else (pending, claimed-but-not-yet-resolved, or resolved
but still within the window) stays in the live file untouched.

Concurrency: flocks _QUEUE_LOCK_PATH, the same stable (never itself replaced)
path agent_app.py's _append_pending_action()/_append_pending_action_locked()
lock — so a compaction run can't race a live append and silently drop it.
Locking the data file directly wouldn't compose safely with the atomic
replace below (see the comment on _QUEUE_LOCK_PATH in agent_app.py).

Run manually or on a schedule (e.g. weekly, alongside refresh_intel.sh).
Usage: python compact_agent_approval_queue.py [--retention-days N] [--dry-run]
"""
import argparse
import fcntl
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
APPROVAL_QUEUE = Path(os.environ.get("APPROVAL_QUEUE", str(HERE / "approval_queue.jsonl")))
ARCHIVE_QUEUE = Path(os.environ.get("APPROVAL_QUEUE_ARCHIVE", str(HERE / "approval_queue.archive.jsonl")))
_QUEUE_LOCK_PATH = Path(str(APPROVAL_QUEUE) + ".lock")
# "claimed" (audit #172) is deliberately excluded — it marks a resolution
# in progress; if it's still the latest status, the request never finished
# and the entry needs a human look, not silent archiving.
TERMINAL_STATUSES = frozenset({"approved", "denied"})
DEFAULT_RETENTION_DAYS = 30


def compact(retention_days: int = DEFAULT_RETENTION_DAYS, dry_run: bool = False) -> int:
    """Archive fully-resolved, aged-out entries. Returns the count of ids archived."""
    if not APPROVAL_QUEUE.exists():
        print(f"No queue file at {APPROVAL_QUEUE} — nothing to do.")
        return 0

    with open(_QUEUE_LOCK_PATH, "a") as lock_fh:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        try:
            entries = []
            for line in APPROVAL_QUEUE.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    print(f"Skipping malformed line: {line[:80]}", file=sys.stderr)

            # Append-only log => the LAST entry for a given id is its current state.
            latest = {}
            for e in entries:
                aid = e.get("id")
                if aid is not None:
                    latest[aid] = e

            cutoff = time.time() - retention_days * 86400
            archivable_ids = {
                aid for aid, e in latest.items()
                if e.get("status") in TERMINAL_STATUSES and e.get("ts", 0) < cutoff
            }

            if not archivable_ids:
                print(f"Nothing to archive (retention={retention_days}d): "
                      f"{len(latest)} distinct id(s), {len(entries)} total line(s).")
                return 0

            keep = [e for e in entries if e.get("id") not in archivable_ids]
            archived = [e for e in entries if e.get("id") in archivable_ids]

            print(f"Archiving {len(archivable_ids)} resolved id(s) "
                  f"({len(archived)} line(s)) older than {retention_days}d; "
                  f"{len(keep)} line(s) remain live.")

            if dry_run:
                print("Dry run — no files written.")
                return len(archivable_ids)

            # Durability order matters: append+fsync the archive copy BEFORE
            # replacing the live file, so a crash in between leaves the
            # archived lines duplicated in the live file (re-compactable next
            # run) rather than lost from both.
            with open(ARCHIVE_QUEUE, "a", encoding="utf-8") as afh:
                for e in archived:
                    afh.write(json.dumps(e) + "\n")
                afh.flush()
                os.fsync(afh.fileno())

            # Atomic replace (temp file + os.replace), not truncate-in-place —
            # a crash mid-rewrite of the live file in place would lose every
            # kept (still-pending) line; os.replace() can only ever leave the
            # old or the new complete content, never a partial one.
            tmp_path = APPROVAL_QUEUE.with_suffix(APPROVAL_QUEUE.suffix + ".tmp")
            with open(tmp_path, "w", encoding="utf-8") as tmp_fh:
                for e in keep:
                    tmp_fh.write(json.dumps(e) + "\n")
                tmp_fh.flush()
                os.fsync(tmp_fh.fileno())
            os.replace(tmp_path, APPROVAL_QUEUE)
            return len(archivable_ids)
        finally:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--retention-days", type=int, default=DEFAULT_RETENTION_DAYS,
                        help=f"Archive terminal entries older than this many days "
                             f"(default {DEFAULT_RETENTION_DAYS})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would be archived without writing anything")
    args = parser.parse_args()
    compact(args.retention_days, args.dry_run)
