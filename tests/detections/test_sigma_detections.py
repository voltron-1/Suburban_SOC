#!/usr/bin/env python3
"""
test_sigma_detections.py — WS2.1 detection-engineering CI.

For every Sigma rule in rules/sigma/*.yml, evaluate its detection logic against
fixtures (tests/detections/fixtures.json):

  * the true_positive event MUST fire   -> a change that breaks the rule fails CI;
  * every true_negative MUST NOT fire   -> false-positive regression suite;
  * a benign baseline event fires NO rule (cross-rule FP guard);
  * promotion gate: any rule at status `test` or `stable` MUST have fixtures
    (>=1 TP and >=1 TN) and pass — experimental rules may be untested.

Prints a rule -> test coverage report. Requires PyYAML (the Detections CI installs
sigma-cli, which provides it).

Run:  python tests/detections/test_sigma_detections.py   (or: pytest tests/detections)
"""

import json
import sys
import unittest
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from sigma_eval import detection_matches  # noqa: E402

ROOT = HERE.parents[1]
SIGMA_DIR = ROOT / "rules" / "sigma"
FIXTURES = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))

# Tiers that require a passing test before a rule may carry them (promotion gate).
TESTED_STATUSES = {"test", "stable"}
BENIGN = {"Image": "C:\\Windows\\explorer.exe", "CommandLine": "C:\\Windows\\explorer.exe"}


def load_rule(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class SigmaDetectionTests(unittest.TestCase):
    def setUp(self):
        self.rules = sorted(SIGMA_DIR.glob("*.yml"))
        self.assertGreaterEqual(len(self.rules), 10)

    def test_true_positives_fire(self):
        for path in self.rules:
            fx = FIXTURES.get(path.name)
            if not fx:
                continue
            det = load_rule(path)["detection"]
            self.assertTrue(
                detection_matches(det, fx["true_positive"]),
                f"{path.name}: true_positive did NOT fire — rule logic broken")

    def test_true_negatives_do_not_fire(self):
        for path in self.rules:
            fx = FIXTURES.get(path.name)
            if not fx:
                continue
            det = load_rule(path)["detection"]
            for i, neg in enumerate(fx.get("true_negatives", [])):
                self.assertFalse(
                    detection_matches(det, neg),
                    f"{path.name}: true_negative[{i}] fired — false positive")

    def test_benign_event_fires_no_rule(self):
        for path in self.rules:
            det = load_rule(path)["detection"]
            self.assertFalse(detection_matches(det, BENIGN),
                             f"{path.name}: benign baseline event fired (false positive)")

    def test_promotion_gate(self):
        # A rule may only be `test`/`stable` if it has fixtures (>=1 TP, >=1 TN).
        violations = []
        for path in self.rules:
            status = str(load_rule(path).get("status", "experimental")).lower()
            fx = FIXTURES.get(path.name)
            if status in TESTED_STATUSES:
                if not fx:
                    violations.append(f"{path.name}: status={status} but no fixtures")
                elif "true_positive" not in fx or not fx.get("true_negatives"):
                    violations.append(f"{path.name}: status={status} needs >=1 TP and >=1 TN")
        self.assertEqual([], violations, f"promotion-gate violations: {violations}")

    def test_coverage_complete(self):
        # Every rule must have a fixture entry (rule -> test mapping is complete).
        missing = [p.name for p in self.rules if p.name not in FIXTURES]
        self.assertEqual([], missing, f"rules without fixtures: {missing}")


def coverage_report():
    rows = []
    for path in sorted(SIGMA_DIR.glob("*.yml")):
        r = load_rule(path)
        fx = FIXTURES.get(path.name, {})
        rows.append((path.name, str(r.get("status", "experimental")),
                     1 if fx.get("true_positive") else 0, len(fx.get("true_negatives", []))))
    width = max(len(n) for n, *_ in rows)
    print("\nrule -> test coverage:")
    print(f"  {'rule'.ljust(width)}  status      TP  TN")
    for name, status, tp, tn in rows:
        print(f"  {name.ljust(width)}  {status.ljust(10)}  {tp}   {tn}")


if __name__ == "__main__":
    coverage_report()
    unittest.main(verbosity=2)
