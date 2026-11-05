#!/usr/bin/env python3
"""
Guards for the boot-time compose start (findings/20261104-docker-engine-split.md, Option B).

Failure class: two Docker engines can own /var/run/docker.sock; the stack lives in Docker
Desktop's engine, which WSL does not start, so nothing brought the stack up after a reboot.
suburban-soc-stack.service + start_stack.sh wait for the expected engine and then start it.

The functional tests run the REAL script against a fake `docker` on PATH. They prove the
script's logic (wrong engine never gets the stack; right engine does; missing .env refuses).
They do NOT prove behaviour under real systemd or Docker Desktop (UNVERIFIED on a live host).

Run:  python tests/pipeline/test_stack_start.py  (or: pytest tests/pipeline)
"""

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UNIT = (ROOT / "configs" / "systemd" / "suburban-soc-stack.service").read_text(encoding="utf-8")
SCRIPT_PATH = ROOT / "scripts" / "setup" / "start_stack.sh"
SCRIPT = SCRIPT_PATH.read_text(encoding="utf-8")
REDEPLOY = (ROOT / "scripts" / "setup" / "redeploy_systemd_units.sh").read_text(encoding="utf-8")


def _directive(text: str, key: str) -> list:
    return [
        line.split("=", 1)[1].strip()
        for line in text.splitlines()
        if not line.lstrip().startswith("#") and line.startswith(key + "=")
    ]


class UnitTests(unittest.TestCase):
    def test_runs_the_start_script_as_the_repo_owner(self):
        self.assertEqual(_directive(UNIT, "User"), ["tjlam"])
        self.assertEqual(_directive(UNIT, "Type"), ["oneshot"])
        self.assertEqual(_directive(UNIT, "RemainAfterExit"), ["yes"])
        (exec_start,) = _directive(UNIT, "ExecStart")
        self.assertTrue(exec_start.endswith("scripts/setup/start_stack.sh"), exec_start)

    def test_failure_reaches_the_alert_dispatcher(self):
        self.assertEqual(_directive(UNIT, "OnFailure"), ["soc-alert-on-failure@%n.service"])

    def test_unit_timeout_exceeds_the_scripts_wait(self):
        wait = int(re.search(r'SOC_ENGINE_WAIT_SECONDS:-(\d+)', SCRIPT).group(1))
        (timeout,) = _directive(UNIT, "TimeoutStartSec")
        self.assertGreater(int(timeout), wait, "systemd would kill the wait before it gives up")

    def test_no_dac_capability_or_privilege_escalation(self):
        self.assertEqual(_directive(UNIT, "NoNewPrivileges"), ["true"])
        for value in _directive(UNIT, "CapabilityBoundingSet") + _directive(UNIT, "AmbientCapabilities"):
            self.assertNotIn("CAP_DAC", value)

    def test_redeploy_script_installs_the_unit(self):
        self.assertIn(
            "sudo cp configs/systemd/suburban-soc-stack.service /etc/systemd/system/suburban-soc-stack.service",
            REDEPLOY,
        )


class ScriptTextTests(unittest.TestCase):
    def test_guards_present(self):
        self.assertIn("docker info --format '{{.Name}}'", SCRIPT)
        self.assertIn("SOC_DOCKER_ENGINE_NAME:-docker-desktop", SCRIPT)
        self.assertIn("exit 75", SCRIPT)
        self.assertIn("exit 78", SCRIPT)
        self.assertIn("docker compose up -d --no-recreate", SCRIPT)

    def test_shellcheck_clean_if_available(self):
        if not shutil.which("shellcheck"):
            self.skipTest("shellcheck not installed")
        r = subprocess.run(["shellcheck", "-S", "warning", str(SCRIPT_PATH)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class ScriptFunctionalTests(unittest.TestCase):
    """Run the real script with a fake `docker` first on PATH."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.dir = self.tmp / "setup"
        self.dir.mkdir()
        self.script = self.dir / "start_stack.sh"
        shutil.copy(SCRIPT_PATH, self.script)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.log = self.tmp / "docker.log"

    def _fake_docker(self, engine_name: str):
        fake = self.bin / "docker"
        fake.write_text(
            "#!/usr/bin/env bash\n"
            f'echo "$*" >> "{self.log}"\n'
            f'if [ "$1" = "info" ]; then echo "{engine_name}"; exit 0; fi\n'
            "exit 0\n",
            encoding="utf-8",
        )
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)

    def _run(self, **extra):
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "SOC_ENGINE_WAIT_SECONDS": "2",
            "SOC_ENGINE_POLL_SECONDS": "1",
        }
        env.update(extra)
        return subprocess.run(
            ["bash", str(self.script)], capture_output=True, text=True, env=env, timeout=30
        )

    def _calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_expected_engine_starts_the_stack(self):
        (self.dir / ".env").write_text("X=1\n")
        self._fake_docker("docker-desktop")
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("compose up -d --no-recreate", self._calls())

    def test_wrong_engine_never_gets_the_stack(self):
        (self.dir / ".env").write_text("X=1\n")
        self._fake_docker("Dragon-Zord")  # what the native dockerd would report
        r = self._run()
        self.assertEqual(r.returncode, 75, r.stdout + r.stderr)
        self.assertFalse(any(c.startswith("compose") for c in self._calls()), self._calls())
        self.assertIn("Dragon-Zord", r.stderr)

    def test_missing_env_refuses_before_touching_docker(self):
        self._fake_docker("docker-desktop")
        r = self._run()
        self.assertEqual(r.returncode, 78, r.stdout + r.stderr)
        self.assertEqual(self._calls(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
