#!/usr/bin/env python3
"""
#554 — the SOC self-health lane had no failure-delivery path: no unit carried
`OnFailure=`, so a unit that failed before its own body ever ran (an
ExecStartPre credential or CA-pin check, say) produced a journal line and
nothing else; and `NTFY_TOPIC` was unprovisioned, so even a metric-computed
breach had nowhere to go.

Two kinds of checks, same convention as test_stack_health_unit.py:

  1. Static assertions against the real unit/script files — no live systemd
     needed.
  2. A hermetic run of scripts/setup/soc_alert_on_failure.sh behind a fake
     `curl`, so no real network call can escape the test.

Run:  python tests/pipeline/test_soc_alert_on_failure.py
      (or: pytest tests/pipeline)
"""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SYSTEMD = ROOT / "configs" / "systemd"
DISPATCHER_UNIT = SYSTEMD / "soc-alert-on-failure@.service"
DISPATCHER_SCRIPT = ROOT / "scripts" / "setup" / "soc_alert_on_failure.sh"
SLO_METRICS_SERVICE = SYSTEMD / "slo-metrics.service"
ZEEK_CAPTURE_SERVICE = SYSTEMD / "zeek-host-capture.service"
SLO_METRICS_PY = ROOT / "scripts" / "setup" / "ai_agent" / "slo_metrics.py"
REDEPLOY = ROOT / "scripts" / "setup" / "redeploy_systemd_units.sh"


def _lines(text):
    return text.splitlines()


def _directives(text, key):
    return [ln for ln in _lines(text) if ln.startswith(key + "=")]


class DispatcherUnitExistsTests(unittest.TestCase):
    def test_template_unit_and_script_exist(self):
        self.assertTrue(DISPATCHER_UNIT.is_file(), f"expected {DISPATCHER_UNIT}")
        self.assertTrue(DISPATCHER_SCRIPT.is_file(), f"expected {DISPATCHER_SCRIPT}")

    def test_unit_invokes_the_real_script_with_the_instance_argument(self):
        text = DISPATCHER_UNIT.read_text(encoding="utf-8")
        execs = _directives(text, "ExecStart")
        self.assertEqual(1, len(execs), f"expected exactly one ExecStart=, got {execs}")
        self.assertTrue(execs[0].endswith("soc_alert_on_failure.sh %i"),
                        f"ExecStart must pass %i through as the failed unit name: {execs[0]}")

    def test_dispatcher_carries_no_docker_or_elasticsearch_dependency(self):
        """The whole point: this unit must stay reachable in exactly the
        outage class slo-metrics.service/zeek-host-capture.service report.
        Checks executable directives/code only — the header comments
        legitimately name both while explaining why neither is a dependency."""
        unit_code = [ln for ln in _lines(DISPATCHER_UNIT.read_text(encoding="utf-8"))
                     if not ln.lstrip().startswith("#") and ln.strip()]
        script_code = [ln for ln in _lines(DISPATCHER_SCRIPT.read_text(encoding="utf-8"))
                       if not ln.lstrip().startswith("#") and ln.strip()]
        for name, lines in (("unit", unit_code), ("script", script_code)):
            with self.subTest(source=name):
                joined = "\n".join(lines).lower()
                self.assertNotIn("docker", joined)
                self.assertNotIn("elasticsearch", joined)

    def test_script_is_syntactically_valid_bash(self):
        r = subprocess.run(["bash", "-n", str(DISPATCHER_SCRIPT)],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(0, r.returncode, r.stderr)


class OnFailureWiringTests(unittest.TestCase):
    """The 'at minimum' unit set the issue names."""

    def test_slo_metrics_wires_onfailure_to_the_dispatcher(self):
        text = SLO_METRICS_SERVICE.read_text(encoding="utf-8")
        self.assertIn("OnFailure=soc-alert-on-failure@%n.service", text)

    def test_zeek_host_capture_wires_onfailure_to_the_dispatcher(self):
        text = ZEEK_CAPTURE_SERVICE.read_text(encoding="utf-8")
        self.assertIn("OnFailure=soc-alert-on-failure@%n.service", text)

    def test_onfailure_directive_lives_in_the_unit_section(self):
        """OnFailure= is only meaningful in [Unit] — assert it appears before
        the first [Service] header in both watched units."""
        for path in (SLO_METRICS_SERVICE, ZEEK_CAPTURE_SERVICE):
            with self.subTest(unit=path.name):
                text = path.read_text(encoding="utf-8")
                onfailure_idx = text.index("OnFailure=soc-alert-on-failure@%n.service")
                service_idx = text.index("\n[Service]")
                self.assertLess(onfailure_idx, service_idx,
                                "OnFailure= must precede [Service] to land in [Unit]")


class RedeployScriptInstallsTheDispatcherTests(unittest.TestCase):
    def test_redeploy_script_copies_the_template_unit(self):
        text = REDEPLOY.read_text(encoding="utf-8")
        self.assertIn("soc-alert-on-failure@.service", text)


class SlaMetricsStartupWarningTests(unittest.TestCase):
    """#554: an unprovisioned NTFY_TOPIC must be visible on every run, not
    just discoverable by someone who goes looking at docs or .env.example."""

    def test_main_warns_to_stderr_when_ntfy_topic_is_unset(self):
        text = SLO_METRICS_PY.read_text(encoding="utf-8")
        self.assertIn("NTFY_TOPIC is unset", text)
        self.assertIn("if not NTFY_TOPIC:", text)


class EnvExampleGuidanceTests(unittest.TestCase):
    def test_ntfy_topic_has_selection_guidance(self):
        example = (ROOT / "scripts" / "setup" / ".env.example").read_text(encoding="utf-8")
        lines = example.splitlines()
        idx = next(i for i, ln in enumerate(lines) if ln.startswith("NTFY_TOPIC="))
        preceding = "\n".join(lines[max(0, idx - 3):idx])
        self.assertIn("unguessable", preceding.lower())


class DispatcherFunctionalTests(unittest.TestCase):
    """Runs the real script behind a fake `curl`, so the test cannot open a
    socket no matter what the host's .env happens to contain."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = Path(self.tmp) / "bin"
        self.bin.mkdir()
        self.log = Path(self.tmp) / "curl.log"
        curl = self.bin / "curl"
        curl.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" >> {self.log}\nexit 0\n')
        curl.chmod(curl.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        # scripts/setup/.env is deliberately NOT written here — each test sets
        # NTFY_TOPIC directly via the process environment instead, since the
        # script only reads it FROM .env as a convenience and falls back to
        # whatever is already set (same `${NTFY_TOPIC:-}` pattern as
        # stack_health.sh).

    def _run(self, unit_name="slo-metrics.service", extra_env=None):
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env.get('PATH', '')}"
        env.pop("NTFY_TOPIC", None)
        env.update(extra_env or {})
        return subprocess.run(["bash", str(DISPATCHER_SCRIPT), unit_name],
                              capture_output=True, text=True, timeout=30, env=env)

    def test_requires_a_unit_name_argument(self):
        r = subprocess.run(["bash", str(DISPATCHER_SCRIPT)],
                           capture_output=True, text=True, timeout=30)
        self.assertNotEqual(0, r.returncode)
        self.assertIn("usage:", r.stderr)

    def test_missing_ntfy_topic_warns_but_exits_zero(self):
        """The dispatcher itself must not become a second failure on top of
        the one it is reporting."""
        r = self._run()
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("NTFY_TOPIC is unset", r.stderr)
        self.assertIn("slo-metrics.service", r.stderr)
        self.assertFalse(self.log.exists(), "no ntfy call should be attempted with no topic")

    def test_configured_topic_posts_the_failed_unit_name(self):
        r = self._run(unit_name="zeek-host-capture.service",
                      extra_env={"NTFY_TOPIC": "test-topic-abc"})
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertTrue(self.log.exists(), "expected a curl call to be logged")
        logged = self.log.read_text()
        self.assertIn("ntfy.sh/test-topic-abc", logged)
        self.assertIn("zeek-host-capture.service", logged)

    def test_call_is_time_bounded(self):
        r = self._run(extra_env={"NTFY_TOPIC": "test-topic-abc"})
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("-m", self.log.read_text().split())

    def test_a_curl_failure_does_not_fail_the_dispatcher(self):
        curl = self.bin / "curl"
        curl.write_text("#!/bin/sh\nexit 7\n")
        curl.chmod(curl.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        r = self._run(extra_env={"NTFY_TOPIC": "test-topic-abc"})
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)



class DispatcherRateLimitTests(unittest.TestCase):
    """#567: OnFailure= fires on every restart cycle, so the dispatcher must bound
    its own output instead of relying on a consuming unit's StartLimitBurst."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = Path(self.tmp) / "bin"
        self.bin.mkdir()
        self.state = Path(self.tmp) / "state"
        self.log = Path(self.tmp) / "curl.log"
        self._write_curl(f'printf "%s\\n" "$@" >> {self.log}\nexit 0')

    def _write_curl(self, body):
        curl = self.bin / "curl"
        curl.write_text(f"#!/bin/sh\n{body}\n")
        curl.chmod(curl.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _run(self, unit="slo-metrics.service", cooldown="3600", state=True):
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env.get('PATH', '')}"
        env["NTFY_TOPIC"] = "test-topic-abc"
        env["SOC_ALERT_COOLDOWN_SECONDS"] = cooldown
        env.pop("STATE_DIRECTORY", None)
        env.pop("SOC_ALERT_STATE_DIR", None)
        if state:
            env["STATE_DIRECTORY"] = str(self.state)
        return subprocess.run(
            ["bash", str(DISPATCHER_SCRIPT), unit],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )

    def _pushes(self):
        return (
            self.log.read_text().count("https://ntfy.sh/") if self.log.exists() else 0
        )

    def test_first_failure_delivers(self):
        r = self._run()
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertEqual(1, self._pushes())

    def test_second_failure_inside_cooldown_is_suppressed(self):
        self._run()
        r = self._run()
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertEqual(1, self._pushes())
        self.assertIn("suppressed", r.stderr)

    def test_a_flapping_unit_is_bounded(self):
        for _ in range(50):
            self._run()
        self.assertEqual(1, self._pushes())

    def test_suppressed_count_is_reported_on_the_next_push(self):
        self._run()
        self._run()
        self._run()
        self._run()
        # Expire the cooldown by back-dating the stamp, keeping the suppressed count.
        stamp = self.state / "slo-metrics.service.state"
        last, suppressed = stamp.read_text().split()
        self.assertEqual("3", suppressed)
        stamp.write_text(f"{int(last) - 7200} {suppressed}\n")
        self._run()
        self.assertEqual(2, self._pushes())
        self.assertIn("3 further failure(s) suppressed", self.log.read_text())
        self.assertEqual(
            "0", stamp.read_text().split()[1], "count must reset after delivery"
        )

    def test_two_units_are_throttled_independently(self):
        self._run(unit="slo-metrics.service")
        self._run(unit="zeek-host-capture.service")
        self.assertEqual(2, self._pushes())
        self._run(unit="slo-metrics.service")
        self._run(unit="zeek-host-capture.service")
        self.assertEqual(2, self._pushes())

    def test_zero_cooldown_disables_throttling(self):
        self._run(cooldown="0")
        self._run(cooldown="0")
        self.assertEqual(2, self._pushes())

    def test_unset_topic_still_exits_zero_with_state_dir(self):
        env = dict(
            os.environ,
            PATH=f"{self.bin}:{os.environ.get('PATH', '')}",
            STATE_DIRECTORY=str(self.state),
        )
        env.pop("NTFY_TOPIC", None)
        r = subprocess.run(
            ["bash", str(DISPATCHER_SCRIPT), "slo-metrics.service"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("NTFY_TOPIC is unset", r.stderr)
        self.assertEqual(0, self._pushes())

    def test_unusable_state_dir_fails_open(self):
        blocker = Path(self.tmp) / "not-a-dir"
        blocker.write_text("x")
        self.state = blocker / "sub"  # mkdir -p cannot succeed under a regular file
        r = self._run()
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertEqual(1, self._pushes())
        self.assertIn("without rate limiting", r.stderr)

    def test_failed_push_does_not_start_the_cooldown(self):
        self._write_curl("exit 7")
        self._run()
        self._write_curl(f'printf "%s\\n" "$@" >> {self.log}\nexit 0')
        self._run()
        self.assertEqual(
            1, self._pushes(), "a push that never left the host must be retried"
        )

    def test_curl_is_called_with_fail_so_http_errors_do_not_start_the_cooldown(self):
        self._run()
        self.assertIn("-sf", self.log.read_text().split())

    def test_http_error_response_does_not_start_the_cooldown(self):
        # Fake curl honours -f: exit 22 is what real curl returns for an HTTP 4xx/5xx.
        self._write_curl(f'printf "%s\\n" "$@" >> {self.log}\nexit 22')
        self._run()
        self._run()
        self.assertEqual(2, self._pushes(), "a rejected push must be retried")

    def test_corrupt_stamp_is_treated_as_no_history(self):
        self.state.mkdir()
        (self.state / "slo-metrics.service.state").write_text("garbage\n")
        r = self._run()
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertEqual(1, self._pushes())

    def test_unit_name_cannot_escape_the_state_dir(self):
        self._run(unit="../../etc/evil.service")
        self.assertEqual(
            [],
            [
                p
                for p in Path(self.tmp).rglob("evil.service*")
                if self.state not in p.parents
            ],
        )


class DispatcherUnitStateDirectoryTests(unittest.TestCase):
    def test_template_unit_declares_a_state_directory(self):
        text = DISPATCHER_UNIT.read_text(encoding="utf-8")
        self.assertEqual(
            ["StateDirectory=suburban-soc-alerts"], _directives(text, "StateDirectory")
        )
        self.assertIn(
            "ProtectSystem=strict",
            text,
            "StateDirectory= must stay writable under the strict sandbox",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
