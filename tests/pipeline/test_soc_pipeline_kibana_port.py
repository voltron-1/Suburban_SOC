#!/usr/bin/env python3
"""Kibana-facing scripts must follow KIBANA_PORT instead of hardcoding 5601.

docker-compose.yml publishes ${KIBANA_PORT:-5601}. This host runs 5700 (5601
failed with a Docker Desktop /forwards/expose 500), so a hardcoded
https://localhost:5601 reports a healthy Kibana as down.

The script does not source .env (that would export every secret in it); it
reads the one KIBANA_PORT line. These tests pin that, and run the script's own
resolution lines against a temp .env so no real .env is involved.

stack_health.sh, provision_tenant.sh, deploy_soc_presentation.sh,
deploy_detections.sh, deploy_dashboards.sh and erase_tenant.sh DO source .env, so they only need `${KIBANA_PORT:-5601}` in their default, and that
default must come AFTER the .env source line (deploy_soc_presentation.sh set it
before, so a .env KIBANA_PORT was never seen).
"""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "setup" / "soc_pipeline.sh"
TEXT = SCRIPT.read_text(encoding="utf-8")


def _resolution_lines():
    """The script's own KIBANA_PORT/KIBANA_URL lines, so the test cannot drift."""
    lines = [ln for ln in TEXT.splitlines()
             if re.match(r'^(KIBANA_PORT=|\[\[ "\$KIBANA_PORT"|KIBANA_URL=)', ln)]
    return "\n".join(lines)


class KibanaPortWiringTests(unittest.TestCase):
    def test_no_hardcoded_localhost_5601_in_executable_lines(self):
        code = [ln for ln in TEXT.splitlines() if not ln.lstrip().startswith("#")]
        offenders = [ln.strip() for ln in code if "localhost:5601" in ln]
        self.assertEqual([], offenders)

    def test_env_file_is_not_sourced(self):
        self.assertNotRegex(TEXT, r'(?m)^\s*(\.|source)\s+"?\$[{(]?(SCRIPT_DIR|HERE)[^\n]*\.env')


class KibanaPortResolutionTests(unittest.TestCase):
    def _resolve(self, env_text=None, env=None):
        with tempfile.TemporaryDirectory() as d:
            if env_text is not None:
                (Path(d) / ".env").write_text(env_text, encoding="utf-8")
            prog = f'SCRIPT_DIR="{d}"\n{_resolution_lines()}\necho "$KIBANA_URL"'
            r = subprocess.run(["bash", "-c", prog], capture_output=True, text=True,
                               timeout=15, env={"PATH": "/usr/bin:/bin", **(env or {})})
        self.assertEqual(0, r.returncode, r.stderr)
        return r.stdout.strip()

    def test_lines_were_found(self):
        self.assertEqual(3, len(_resolution_lines().splitlines()))

    def test_reads_port_from_env_file(self):
        self.assertEqual("https://localhost:5700",
                         self._resolve("OTHER=1\nKIBANA_PORT=5700\n"))

    def test_environment_wins_over_env_file(self):
        self.assertEqual("https://localhost:6000",
                         self._resolve("KIBANA_PORT=5700\n", {"KIBANA_PORT": "6000"}))

    def test_missing_key_or_file_defaults_to_5601(self):
        self.assertEqual("https://localhost:5601", self._resolve("A=1\n"))
        self.assertEqual("https://localhost:5601", self._resolve(None))

    def test_non_numeric_port_falls_back_to_5601(self):
        self.assertEqual("https://localhost:5601", self._resolve("KIBANA_PORT=5700; id\n"))

    def test_explicit_kibana_url_is_respected(self):
        self.assertEqual("https://kb.example:8443",
                         self._resolve("KIBANA_PORT=5700\n", {"KIBANA_URL": "https://kb.example:8443"}))


SOURCING_SCRIPTS = ["stack_health.sh", "provision_tenant.sh", "deploy_soc_presentation.sh",
                    "deploy_detections.sh", "deploy_dashboards.sh", "erase_tenant.sh"]


class SourcingScriptsKibanaPortTests(unittest.TestCase):
    def _lines(self, name):
        return (ROOT / "scripts" / "setup" / name).read_text(encoding="utf-8").splitlines()

    def test_no_hardcoded_localhost_5601_in_executable_lines(self):
        for name in SOURCING_SCRIPTS:
            with self.subTest(script=name):
                code = [ln for ln in self._lines(name) if not ln.lstrip().startswith("#")]
                self.assertEqual([], [ln for ln in code if "localhost:5601" in ln])

    def test_default_follows_kibana_port_and_is_set_after_env_is_sourced(self):
        for name in SOURCING_SCRIPTS:
            with self.subTest(script=name):
                lines = self._lines(name)
                url = [i for i, ln in enumerate(lines) if ln.startswith("KIBANA_URL=")]
                src = [i for i, ln in enumerate(lines) if '.env"' in ln and ". " in ln and "set -a" in ln]
                self.assertEqual(1, len(url), "exactly one KIBANA_URL assignment")
                self.assertEqual(1, len(src), "exactly one .env source line")
                self.assertIn("${KIBANA_PORT:-5601}", lines[url[0]])
                self.assertGreater(url[0], src[0], "KIBANA_URL must be set after .env is sourced")

    def test_resolved_url_uses_the_env_file_port(self):
        for name in SOURCING_SCRIPTS:
            with self.subTest(script=name):
                lines = self._lines(name)
                url = next(ln for ln in lines if ln.startswith("KIBANA_URL="))
                with tempfile.TemporaryDirectory() as d:
                    (Path(d) / ".env").write_text("KIBANA_PORT=5700\n", encoding="utf-8")
                    prog = f'set -a; . "{d}/.env"; set +a\n{url}\necho "$KIBANA_URL"'
                    r = subprocess.run(["bash", "-c", prog], capture_output=True, text=True,
                                       timeout=15, env={"PATH": "/usr/bin:/bin"})
                self.assertEqual("https://localhost:5700", r.stdout.strip(), r.stderr)


if __name__ == "__main__":
    unittest.main()
