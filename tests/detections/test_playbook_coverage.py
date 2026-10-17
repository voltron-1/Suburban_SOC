#!/usr/bin/env python3
"""
#517 follow-up: every deployed Sigma rule must have its own response
procedure in docs/playbooks/IR_Sigma_Playbook.md. #517 backfilled 10
missing entries by hand, but nothing enforced it, and PR #564 then landed
two more rules (system_lnx_*) with no entry — the drift the 2026-08-31
repo audit found, recurring.

An entry counts when the playbook carries both the rule's anchor
(`<a id="<rule stem>"></a>`) and its `**Rule file:** \`rules/sigma/<stem>.yml\``
line, and the Master Detection & Response Matrix links to that anchor.
The inverse is checked too: a `**Rule file:**` line naming a Sigma file that
no longer exists is a stale entry.

Static text assertions against the real files, no live stack needed.

Run:  pytest tests/detections/test_playbook_coverage.py
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIGMA_DIR = ROOT / "rules" / "sigma"
PLAYBOOK = (ROOT / "docs" / "playbooks" / "IR_Sigma_Playbook.md").read_text(encoding="utf-8")

RULE_STEMS = sorted(p.stem for p in SIGMA_DIR.glob("*.yml"))
RULE_FILE_LINE = re.compile(r"^\*\*Rule file:\*\* `rules/sigma/([^`]+)\.yml`", re.MULTILINE)


class PlaybookCoverageTests(unittest.TestCase):
    def test_rule_corpus_is_not_empty(self):
        self.assertTrue(RULE_STEMS, f"no rules found under {SIGMA_DIR}")

    def test_every_sigma_rule_has_a_playbook_entry(self):
        missing = [
            stem for stem in RULE_STEMS
            if f'<a id="{stem}"></a>' not in PLAYBOOK
            or f"**Rule file:** `rules/sigma/{stem}.yml`" not in PLAYBOOK
        ]
        self.assertEqual(
            missing, [],
            f"{len(missing)} of {len(RULE_STEMS)} rules/sigma/*.yml have no "
            "IR_Sigma_Playbook.md entry (anchor + **Rule file:** line); "
            "add one using an existing entry's 5-subsection structure",
        )

    def test_every_sigma_rule_has_a_master_matrix_row(self):
        missing = [stem for stem in RULE_STEMS if f"](#{stem})" not in PLAYBOOK]
        self.assertEqual(
            missing, [],
            "rules with no row in the Master Detection & Response Matrix",
        )

    def test_no_playbook_entry_names_a_missing_rule_file(self):
        stale = sorted(set(RULE_FILE_LINE.findall(PLAYBOOK)) - set(RULE_STEMS))
        self.assertEqual(stale, [], "playbook entries for Sigma rules that no longer exist")


if __name__ == "__main__":
    unittest.main()
