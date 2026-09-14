#!/usr/bin/env python3
"""
.gitleaks.toml regression guard.

A full working-tree + full-history gitleaks scan (`gitleaks detect --source .
--config .gitleaks.toml -v --log-opts="--all"`) found exactly one finding in
this repo: the stock `aws-access-token` rule false-positiving on a byte run
inside one of the 3 inline `data:image/jpeg;base64,...` images embedded in
`configs/server/suburban_soc_dashboards_bundle_final.ndjson` (a Kibana saved-
object export) — confirmed by isolating the flagged offset and verifying it
sits inside the base64 URI, not adjacent to it.

This asserts the allowlist entry that suppresses it stays present and
well-formed, and is scoped to exactly the file it's meant for — not
accidentally broadened into a path fragment that would also match something
else, which would silently blind scanning of an unrelated file.

Requires `tomllib` (Python 3.11+, matches .python-version) — no live
gitleaks binary needed; this only parses the config, it doesn't run a scan.

Run:  python tests/pipeline/test_gitleaks_allowlist.py
      (or: pytest tests/pipeline)
"""

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / ".gitleaks.toml"
TARGET_FILE = "configs/server/suburban_soc_dashboards_bundle_final.ndjson"


class GitleaksAllowlistTests(unittest.TestCase):
    def setUp(self):
        self.config = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))

    def test_dashboard_bundle_path_is_allowlisted(self):
        paths = self.config["allowlist"]["paths"]
        matched = [p for p in paths if re.search(p, TARGET_FILE)]
        self.assertTrue(matched, f"{TARGET_FILE} is not covered by any [allowlist].paths entry")

    def test_allowlist_entry_does_not_overmatch_other_files(self):
        """A regex that's broader than intended (e.g. a bare 'dashboards')
        would silently exempt some OTHER file from every rule too — this
        keeps the entry scoped to the one real file it names."""
        paths = self.config["allowlist"]["paths"]
        pattern = next(p for p in paths if "suburban_soc_dashboards_bundle_final" in p)
        decoys = [
            "configs/server/suburban_soc_dashboards_bundle.ndjson",  # the non-"_final" sibling
            "configs/server/executive_dashboard.ndjson",
            "docs/some_dashboards_bundle_final_notes.md",
        ]
        for decoy in decoys:
            with self.subTest(path=decoy):
                self.assertIsNone(re.search(pattern, decoy),
                                  f"allowlist pattern {pattern!r} unexpectedly matches {decoy!r}")

    def test_target_file_still_exists(self):
        """The allowlist entry is meaningless (and a landmine for the next
        person reading this config) if the file it names has been renamed or
        removed."""
        self.assertTrue((ROOT / TARGET_FILE).is_file(), f"expected {TARGET_FILE}")

    def test_dashboard_bundle_still_contains_the_documented_images(self):
        """If the base64 images this allowlist entry exists for are ever
        removed from the file, the exclusion should be reconsidered rather
        than silently carried forward for content that no longer needs it."""
        content = (ROOT / TARGET_FILE).read_text(encoding="utf-8")
        self.assertIn("data:image/jpeg;base64,", content)

    def test_useDefault_still_extends_the_stock_ruleset(self):
        """The aws-access-token rule this allowlist entry suppresses isn't
        defined in this file at all — it only exists because of this. If
        that ever flips to false, the allowlist entry stops meaning what
        this test (and the config's own comment) says it means."""
        self.assertTrue(self.config["extend"]["useDefault"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
