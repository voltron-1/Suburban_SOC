#!/usr/bin/env python3
"""
Framework-enrichment consistency tests (MITRE ATT&CK + NIST CSF).

These guard the detection-framework mapping in configs/logstash.conf:

  * every Sigma rule in rules/sigma/*.yml is operationalized in the pipeline —
    its ATT&CK technique is classified into ECS threat.technique.id, and a
    sigma_* tag exists for the Endpoint dashboard's "Sigma Rule Hits" panel;
  * every threat.technique.id mapping carries a tactic and a NIST CSF function
    (so the MITRE heatmap and NIST donut never aggregate half-tagged events);
  * the network detections (port scan T1046, SSH brute force T1110) are mapped.

Pure stdlib (no pyyaml / no running stack) so it runs in any CI.

Run:  python tests/pipeline/test_framework_enrichment.py     (or: pytest tests/pipeline)
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONF = (ROOT / "configs" / "logstash.conf").read_text(encoding="utf-8")
SIGMA_DIR = ROOT / "rules" / "sigma"

# Network detections that must be classified in the pipeline (non-Sigma source).
NETWORK_TECHNIQUES = {"T1046", "T1110"}

_TECH_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_ID_ASSIGN_RE = re.compile(r"\[threat\]\[technique\]\[id\]\"\s*=>\s*\"([^\"]+)\"")
_TACTIC_ASSIGN_RE = re.compile(r"\[threat\]\[tactic\]\[name\]\"\s*=>")
_NIST_ASSIGN_RE = re.compile(r"\[nist\]\[function\]\"\s*=>")
_SIGMA_TAG_RE = re.compile(r"\bsigma_[a-z0-9_]+\b")


def rule_technique(text: str):
    """Return the ATT&CK technique id (e.g. T1003.001) declared in a Sigma rule."""
    m = _TECH_RE.search(text)
    return m.group(1).upper() if m else None


class FrameworkEnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.rules = sorted(SIGMA_DIR.glob("*.yml"))
        self.mapped_ids = set(_ID_ASSIGN_RE.findall(CONF))

    def test_sigma_rules_present(self):
        # Sanity: the rule corpus exists (guards against a moved/empty dir).
        self.assertGreaterEqual(len(self.rules), 10,
                                f"expected >=10 Sigma rules, found {len(self.rules)}")

    def test_every_sigma_technique_is_mapped(self):
        # Completeness: each Sigma rule's ATT&CK technique is classified in the
        # pipeline. This is what keeps rules/ and logstash.conf from drifting.
        missing = []
        for rule in self.rules:
            tech = rule_technique(rule.read_text(encoding="utf-8"))
            self.assertIsNotNone(tech, f"{rule.name}: no attack.tXXXX tag found")
            if tech not in self.mapped_ids:
                missing.append(f"{rule.name} ({tech})")
        self.assertEqual([], missing,
                         f"Sigma techniques not mapped in logstash.conf: {missing}")

    def test_network_detections_mapped(self):
        for tech in NETWORK_TECHNIQUES:
            self.assertIn(tech, self.mapped_ids,
                          f"network technique {tech} not mapped in logstash.conf")

    def test_every_technique_has_tactic_and_nist(self):
        # Each threat.technique.id assignment must be accompanied by a tactic name
        # and a NIST CSF function so dashboards never see half-classified events.
        n_ids = len(_ID_ASSIGN_RE.findall(CONF))
        n_tactic = len(_TACTIC_ASSIGN_RE.findall(CONF))
        n_nist = len(_NIST_ASSIGN_RE.findall(CONF))
        self.assertEqual(n_ids, n_tactic,
                         f"{n_ids} technique ids but {n_tactic} tactic names")
        self.assertEqual(n_ids, n_nist,
                         f"{n_ids} technique ids but {n_nist} nist functions")

    def test_at_least_twelve_mappings(self):
        # 10 Sigma + 2 network detections.
        self.assertGreaterEqual(len(self.mapped_ids), 12,
                                f"only {len(self.mapped_ids)} distinct techniques mapped")

    def test_sigma_tags_defined_for_each_rule(self):
        # Each rule must contribute at least one sigma_* tag in the detection layer.
        tags = set(_SIGMA_TAG_RE.findall(CONF))
        self.assertGreaterEqual(len(tags), len(self.rules),
                                f"{len(tags)} sigma_* tags for {len(self.rules)} rules: {sorted(tags)}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
