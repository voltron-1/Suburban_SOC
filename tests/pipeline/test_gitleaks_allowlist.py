#!/usr/bin/env python3
"""
.gitleaks.toml allowlist regression guard (#570).

gitleaks is this repo's only secret-scanning layer — there is no
.pre-commit-config.yaml and no .githooks/ — and it is the control
docs/COMPLIANCE_MATRIX.md cites for NIST RA-5. An over-broad entry in
`[allowlist].paths` therefore has no backstop, and its failure mode is silent:
the symptom is *fewer* findings, which nothing alerts on.

Two invariants are enforced here.

1. Every `[allowlist].paths` entry is anchored (`^...$`). gitleaks matches
   these as unanchored regexes against the finding's file path, so a bare
   `AUDIT_REPORT\\.md` also exempts `notes_AUDIT_REPORT.md.bak`, or a copy of
   the file under any other directory. `.gitignore` does not ignore
   `*.bak`/`*.orig`/`*.tmp`, so such a path is committable.

2. `configs/server/suburban_soc_dashboards_bundle_final.ndjson` is NOT
   allowlisted. PR #571 proposed exempting it for an `aws-access-token` hit on
   the `AIDA`-prefixed byte run inside one of its 3 inline
   `data:image/jpeg;base64,...` images. That hit does not reproduce on gitleaks
   8.24.3, whose stock rule carries `AKIA` but not `AIDA` — verified by probe,
   and by scanning the file with and without the entry (identical results).
   A `paths` entry would have excluded the whole 86 KB export from EVERY rule,
   including this config's own `elastic-inline-basic-auth` (audit P0-1), across
   4 hand-authored markdown/HTML panels and a `fieldFormatMap.urlTemplate`
   enrichment link — the two fields most likely to receive a pasted keyed URL.
   See findings/20260914-pr571-{testplan-verification,gitleaks-allowlist}.md.

Requires `tomllib` (Python 3.11+, matches .python-version). Parses the config
only — no gitleaks binary needed.

Run:  python tests/pipeline/test_gitleaks_allowlist.py
      (or: pytest tests/pipeline)
"""

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / ".gitleaks.toml"
DASHBOARD_BUNDLE = "configs/server/suburban_soc_dashboards_bundle_final.ndjson"


class GitleaksAllowlistTests(unittest.TestCase):
    def setUp(self):
        self.config = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        self.paths = self.config["allowlist"]["paths"]

    def test_every_allowlist_path_is_anchored(self):
        """An unanchored entry exempts every path that merely CONTAINS it."""
        for entry in self.paths:
            with self.subTest(entry=entry):
                self.assertTrue(entry.startswith("^") and entry.endswith("$"),
                                f"allowlist path {entry!r} must be anchored as ^...$")

    def test_allowlist_paths_do_not_match_copies_or_backups(self):
        """The concrete over-match shapes anchoring exists to stop: a suffixed
        backup of the file, and the same filename under another directory."""
        for entry in self.paths:
            literal = entry.strip("^$").replace("\\", "")
            for decoy in (f"{literal}.bak", f"{literal}.orig", f"backup/{literal}",
                          f"evidence/2026-09/{literal}", f"notes_{literal}"):
                with self.subTest(entry=entry, decoy=decoy):
                    self.assertIsNone(re.search(entry, decoy),
                                      f"allowlist entry {entry!r} matches {decoy!r}")

    def test_allowlist_paths_still_match_their_real_targets(self):
        """Anchoring must not silently break the suppressions it applies to —
        each entry has to still match the file it was written for."""
        for entry, target in ((r"^AUDIT_REPORT\.md$", "AUDIT_REPORT.md"),
                              (r"^\.gitleaks\.toml$", ".gitleaks.toml")):
            with self.subTest(target=target):
                self.assertIn(entry, self.paths, f"{target} lost its allowlist entry")
                self.assertIsNotNone(re.search(entry, target))

    def test_dashboard_bundle_is_not_allowlisted(self):
        """#571: a whole-file exclusion here blinds every rule across the
        export's markdown panels and urlTemplate field, for a false positive
        that does not fire on the gitleaks version CI runs."""
        matched = [p for p in self.paths if re.search(p, DASHBOARD_BUNDLE)]
        self.assertEqual([], matched,
                         f"{DASHBOARD_BUNDLE} must not be allowlisted; matched by {matched}")

    def test_useDefault_still_extends_the_stock_ruleset(self):
        """Most of the coverage the allowlist narrows comes from the stock
        rules, not from this file. If that ever flips to false, every
        assertion above is guarding a much smaller ruleset than it claims."""
        self.assertTrue(self.config["extend"]["useDefault"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
