#!/usr/bin/env python3
"""
#446: scripts/setup/suricata_threshold_baseline.py — evidence tooling for tuning
the 14 disabled `detection_filter` rules.

These tests prove the tool's own arithmetic and safety properties against
synthetic eve.json and the real rule files. They do NOT prove any threshold is
right for this deployment; that needs a real, attack-free baseline period.
"""
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "setup" / "suricata_threshold_baseline.py"
RULES_DIR = REPO / "rules" / "suricata"
CONFIG = REPO / "configs" / "suricata" / "suricata.yaml"

_spec = importlib.util.spec_from_file_location("suricata_threshold_baseline", SCRIPT)
assert _spec and _spec.loader
tb = importlib.util.module_from_spec(_spec)
sys.modules["suricata_threshold_baseline"] = tb
_spec.loader.exec_module(tb)

EXPECTED_SIDS = [
    9000001, 9000002, 9000005, 9000008, 9000009, 9000010, 9000046,
    9000060, 9000062, 9000073, 9000080, 9000082, 9000083, 9000100,
]


class RealRuleSetTests(unittest.TestCase):
    def test_finds_exactly_the_fourteen_documented_rules(self):
        sids = [c.sid for c in tb.load_candidates(RULES_DIR)]
        self.assertEqual(EXPECTED_SIDS, sids,
                         "docs/detections/suricata-starter-set.md lists these 14; "
                         "if a rule was tuned and enabled, update both")

    def test_every_candidate_parses_track_count_and_seconds(self):
        for c in tb.load_candidates(RULES_DIR):
            with self.subTest(sid=c.sid):
                self.assertIn(c.track, ("by_src", "by_dst"))
                self.assertGreater(c.count, 0)
                self.assertGreater(c.seconds, 0)

    def test_baseline_text_removes_only_the_filter(self):
        cands = tb.load_candidates(RULES_DIR)
        out = tb.baseline_rules_text(cands).splitlines()
        rule_lines = [ln for ln in out if not ln.startswith("#")]
        self.assertEqual(len(cands), len(rule_lines))
        for c, line in zip(cands, rule_lines):
            with self.subTest(sid=c.sid):
                self.assertNotIn("detection_filter", line)
                self.assertTrue(line.startswith("alert "), "must be enabled")
                self.assertIn(f"sid:{c.sid};", line)
                # Everything except the filter option (and its one leading
                # space) is byte-identical to the shipped rule.
                self.assertEqual(
                    c.text.replace(
                        f" detection_filter:track {c.track}, count {c.count}, seconds {c.seconds};", ""),
                    line)

    def test_baseline_rules_parse_with_real_suricata_when_available(self):
        suricata = shutil.which("suricata")
        if suricata is None:
            self.skipTest("no suricata binary (CI's detections job installs one)")
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "baseline.rules"
            rules.write_text(tb.baseline_rules_text(tb.load_candidates(RULES_DIR)))
            logs = Path(tmp) / "log"
            logs.mkdir()
            r = subprocess.run(
                [suricata, "-T", "-c", str(CONFIG), "-l", str(logs),
                 "--af-packet=lo", "-S", str(rules)],
                capture_output=True, text=True, timeout=120, check=False)
            self.assertEqual(0, r.returncode, r.stdout + r.stderr)


class FilterHandlingTests(unittest.TestCase):
    def test_strip_filter_preserves_double_spaces_inside_content(self):
        text = ('alert tcp any any -> any any (msg:"x"; content:"a  b"; '
                'detection_filter:track by_src, count 5, seconds 60; sid:1; rev:1;)')
        out = tb.strip_filter(text)
        self.assertIn('content:"a  b"', out)
        self.assertNotIn("detection_filter", out)
        self.assertEqual(
            'alert tcp any any -> any any (msg:"x"; content:"a  b"; sid:1; rev:1;)', out)

    def test_strip_filter_requires_exactly_one(self):
        with self.assertRaises(ValueError):
            tb.strip_filter('alert tcp any any -> any any (msg:"x"; sid:1; rev:1;)')


class WindowMaxTests(unittest.TestCase):
    def test_empty_and_single(self):
        self.assertEqual(0, tb.window_max([], 10))
        self.assertEqual(1, tb.window_max([5.0], 10))

    def test_window_is_half_open(self):
        # Events at 0 and exactly 10 are NOT in the same 10s window.
        self.assertEqual(1, tb.window_max([0.0, 10.0], 10))
        self.assertEqual(2, tb.window_max([0.0, 9.999], 10))

    def test_finds_densest_window_not_total(self):
        ts = [0, 1, 2, 3, 100, 101, 200]
        self.assertEqual(4, tb.window_max([float(t) for t in ts], 10))

    def test_many_identical_timestamps(self):
        self.assertEqual(50, tb.window_max([7.0] * 50, 10))


def _alert(sid, src, dst, ts):
    return {"timestamp": ts, "event_type": "alert", "src_ip": src, "dest_ip": dst,
            "alert": {"signature_id": sid}}


class AnalyzeTests(unittest.TestCase):
    def cand(self, sid=9000082, track="by_src", count=50, seconds=10):
        return tb.Candidate(sid, "x.rules", "m", track, count, seconds, "")

    def test_parse_ts_handles_suricata_offset_without_colon(self):
        a = tb.parse_ts("2026-10-24T01:52:12.500000+0000")
        b = tb.parse_ts("2026-10-24T01:52:13+0000")
        self.assertAlmostEqual(0.5, b - a, places=3)

    def test_keys_are_tracked_separately(self):
        c = self.cand(count=5, seconds=10)
        ev = [(9000082, "1.1.1.1", "9.9.9.9", float(i)) for i in range(8)]
        ev += [(9000082, "2.2.2.2", "9.9.9.9", float(i)) for i in range(3)]
        (r,), _, _ = tb.analyze_events(ev, [c], 1.25)
        self.assertEqual(2, r.keys)
        self.assertEqual(8, r.observed_max)
        self.assertEqual("1.1.1.1", r.top_key)
        self.assertEqual(1, r.keys_reaching_current)

    def test_by_dst_groups_on_destination(self):
        c = self.cand(sid=9000010, track="by_dst", count=3, seconds=60)
        ev = [(9000010, f"10.0.0.{i}", "8.8.8.8", float(i)) for i in range(5)]
        (r,), _, _ = tb.analyze_events(ev, [c], 1.0)
        self.assertEqual(1, r.keys)
        self.assertEqual("8.8.8.8", r.top_key)
        self.assertEqual(5, r.observed_max)

    def test_suggestion_has_headroom_and_never_drops_below_shipped_count(self):
        c = self.cand(count=50, seconds=10)
        noisy = [(9000082, "1.1.1.1", "d", i * 0.01) for i in range(80)]
        (r,), _, _ = tb.analyze_events(noisy, [c], 1.25)
        self.assertEqual(80, r.observed_max)
        self.assertEqual(101, r.suggested)          # ceil(80*1.25)+1
        self.assertIn("raise", r.note)

        quiet = [(9000082, "1.1.1.1", "d", float(i)) for i in range(4)]
        (r,), _, _ = tb.analyze_events(quiet, [c], 1.25)
        self.assertEqual(50, r.suggested, "must not lower below the shipped count")
        self.assertEqual(0, r.keys_reaching_current)

    def test_no_traffic_means_untested_not_safe(self):
        (r,), first, last = tb.analyze_events([], [self.cand()], 1.25)
        self.assertEqual(0, r.observed_max)
        self.assertEqual(50, r.suggested)
        self.assertIn("untested", r.note)
        self.assertIsNone(first)

    def test_events_for_other_sids_are_ignored(self):
        ev = [(1234, "1.1.1.1", "d", 0.0)]
        (r,), first, _ = tb.analyze_events(ev, [self.cand()], 1.25)
        self.assertEqual(0, r.events)
        self.assertIsNone(first)

    def test_span_reported(self):
        ev = [(9000082, "a", "b", 0.0), (9000082, "a", "b", 86400.0 * 3)]
        _, first, last = tb.analyze_events(ev, [self.cand()], 1.25)
        self.assertEqual(3.0, (last - first) / 86400.0)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True,
                              text=True, timeout=60, check=False)

    def test_prepare_refuses_to_write_inside_the_rules_directory(self):
        before = sorted(p.name for p in RULES_DIR.iterdir())
        r = self.run_cli("prepare", "--out", str(RULES_DIR / "baseline.rules"))
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)
        self.assertEqual(before, sorted(p.name for p in RULES_DIR.iterdir()))

    def test_prepare_writes_baseline_file(self):
        out = self.tmp / "b.rules"
        r = self.run_cli("prepare", "--out", str(out))
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("14 baseline rules", r.stdout)
        self.assertEqual(14, sum(1 for ln in out.read_text().splitlines() if ln.startswith("alert ")))

    def test_analyze_end_to_end_marks_short_baseline_provisional(self):
        eve = self.tmp / "eve.json"
        lines = [json.dumps(_alert(9000082, "1.1.1.1", "10.0.0.5",
                                   f"2026-10-24T01:00:00.{i * 30000:06d}+0000")) for i in range(30)]
        lines += ["not json", json.dumps({"event_type": "flow"}), '{"event_type":"alert"}']
        eve.write_text("\n".join(lines) + "\n")
        r = self.run_cli("analyze", "--eve", str(eve), "--format", "json")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        data = json.loads(r.stdout)
        self.assertTrue(data["provisional"])
        self.assertGreaterEqual(data["skipped_lines"], 1)
        row = next(x for x in data["rules"] if x["sid"] == 9000082)
        self.assertEqual(30, row["observed_max"])
        self.assertEqual(50, row["suggested_count"])

    def test_analyze_table_warns_when_provisional(self):
        eve = self.tmp / "eve.json"
        eve.write_text(json.dumps(_alert(9000082, "1.1.1.1", "d", "2026-10-24T01:00:00.000000+0000")) + "\n")
        r = self.run_cli("analyze", "--eve", str(eve))
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("PROVISIONAL", r.stdout)

    def test_analyze_rejects_margin_below_one(self):
        eve = self.tmp / "eve.json"
        eve.write_text("")
        r = self.run_cli("analyze", "--eve", str(eve), "--margin", "0.5")
        self.assertEqual(2, r.returncode)

    def test_analyze_missing_file_is_an_error(self):
        r = self.run_cli("analyze", "--eve", str(self.tmp / "nope.json"))
        self.assertEqual(1, r.returncode)


if __name__ == "__main__":
    unittest.main()
