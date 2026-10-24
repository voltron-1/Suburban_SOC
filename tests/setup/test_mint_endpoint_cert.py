#!/usr/bin/env python3
"""
#265: scripts/setup/mint_endpoint_cert.sh mints a CA-signed Beats client
certificate for one endpoint, and the endpoint shipper configs present it.

No Docker daemon is needed: a fake `docker` on PATH records every invocation
and stands in for `inspect`, `exec` and `cp`. What this proves is the script's
own logic — input validation, that the CA private key is never copied out,
that the endpoint name reaches the container as an argument and not as part of
a shell string, that nothing is overwritten, and that scratch state is removed
on failure. It does NOT prove certutil produces the layout the script expects,
or that Logstash accepts the result; that needs a live stack (#265 stays open
until an endpoint ships an event end to end).
"""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "setup" / "mint_endpoint_cert.sh"
WINLOGBEAT = REPO / "configs" / "endpoint" / "winlogbeat.yml"
FILEBEAT = REPO / "configs" / "endpoint" / "filebeat_endpoint.yml"

# Fake docker: logs argv (one invocation per line, args NUL-free, tab-joined),
# answers `inspect`, no-ops `exec`, and materialises files on `cp` the way the
# real command would. FAKE_DOCKER_* env vars switch failure modes.
# Fake openssl: `verify` succeeds unless FAKE_OPENSSL_FAIL=1. The fake docker
# writes placeholder cert text, so the real openssl would (correctly) reject it.
FAKE_OPENSSL = r"""#!/usr/bin/env bash
[[ "${FAKE_OPENSSL_FAIL:-0}" == "1" ]] && exit 2
exit 0
"""

FAKE_DOCKER = r"""#!/usr/bin/env bash
{ printf '%s\x1f' "$@"; printf '\x1e'; } >> "$FAKE_DOCKER_LOG"
case "$1" in
  inspect)
    echo "${FAKE_DOCKER_RUNNING:-true}"
    ;;
  exec)
    if [[ "${FAKE_DOCKER_EXEC_FAIL:-0}" == "1" && "$*" == *"bash -c"* ]]; then exit 1; fi
    ;;
  cp)
    src="$2"; dest="$3"
    if [[ "${FAKE_DOCKER_CP_FAIL:-0}" == "1" ]]; then exit 1; fi
    if [[ "$src" == */out/*/. ]]; then
      mkdir -p "$dest"
      name="$(basename "$(dirname "$src")")"
      echo "CERT" > "$dest/$name.crt"
      echo "KEY"  > "$dest/$name.key"
    else
      echo "CA" > "$dest"
    fi
    ;;
esac
exit 0
"""


class MintEndpointCertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        fake = self.bin / "docker"
        fake.write_text(FAKE_DOCKER)
        fake.chmod(0o755)
        fake_ssl = self.bin / "openssl"
        fake_ssl.write_text(FAKE_OPENSSL)
        fake_ssl.chmod(0o755)
        self.log = self.tmp / "docker.log"
        self.log.write_text("")
        self.out = self.tmp / "out"

    def run_script(self, *args, **env):
        e = {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '')}",
            "FAKE_DOCKER_LOG": str(self.log),
            "HOME": str(self.tmp),
        }
        e.update({k: str(v) for k, v in env.items()})
        return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True,
                              text=True, timeout=30, env=e)

    def calls(self):
        """Each docker invocation as a list of argv strings (after `docker`)."""
        raw = self.log.read_text()
        return [rec.split("\x1f")[:-1] for rec in raw.split("\x1e") if rec]

    @staticmethod
    def _is_mint(call):
        return call[0] == "exec" and "bash" in call and "-c" in call

    # --- input validation: nothing may reach Docker ---------------------------

    def test_invalid_names_are_refused_before_docker_is_touched(self):
        bad = ["", "A", "Win01", "../x", "a/b", "a b", "a;rm -rf /", "$(id)",
               "-x", "x-", "a_b", "a.b", "a" * 64, "ünï"]
        for name in bad:
            with self.subTest(name=name):
                self.log.write_text("")
                r = self.run_script(name, str(self.out))
                self.assertEqual(2, r.returncode, r.stdout + r.stderr)
                self.assertEqual([], self.calls(), "docker must not be invoked")
                self.assertFalse(self.out.exists())

    def test_valid_names_are_accepted(self):
        for name in ["a", "win-lab-01", "host1", "a" * 63, "0abc"]:
            with self.subTest(name=name):
                out = self.tmp / f"o-{name[:10]}"
                r = self.run_script(name, str(out))
                self.assertEqual(0, r.returncode, r.stdout + r.stderr)

    def test_bad_validity_days_refused(self):
        for days in ["0", "-5", "abc", "1.5", "999999"]:
            with self.subTest(days=days):
                r = self.run_script("ok", str(self.out), ENDPOINT_CERT_DAYS=days)
                self.assertEqual(2, r.returncode, r.stdout + r.stderr)

    # --- happy path -----------------------------------------------------------

    def test_happy_path_writes_cert_key_and_ca_with_safe_modes(self):
        r = self.run_script("win-lab-01", str(self.out))
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        for f in ("win-lab-01.crt", "win-lab-01.key", "ca.crt"):
            self.assertTrue((self.out / f).is_file(), f)
        key_mode = stat.S_IMODE((self.out / "win-lab-01.key").stat().st_mode)
        self.assertEqual(0o600, key_mode, f"private key mode is {oct(key_mode)}")
        self.assertIn("WINLOGBEAT_CERT", r.stdout)
        self.assertIn("FILEBEAT_KEY", r.stdout)

    def test_name_is_passed_as_argument_not_spliced_into_the_shell_string(self):
        self.run_script("win-lab-01", str(self.out))
        mint = next(c for c in self.calls() if self._is_mint(c))
        script_text = mint[mint.index("-c") + 1]
        self.assertNotIn("win-lab-01", script_text,
                         "endpoint name must not appear inside the shell script text")
        # `_` is $0; then scratch dir, name, days as separate argv entries.
        tail = mint[mint.index("-c") + 2:]
        self.assertEqual("_", tail[0])
        self.assertEqual("win-lab-01", tail[2])
        self.assertEqual("365", tail[3])

    def test_custom_days_and_container_are_honoured(self):
        self.run_script("host1", str(self.out), ENDPOINT_CERT_DAYS="90",
                        ES_CONTAINER="es-prod")
        mint = next(c for c in self.calls() if self._is_mint(c))
        self.assertIn("es-prod", mint)
        self.assertEqual("90", mint[-1])

    # --- the CA private key must never leave the container -------------------

    def test_ca_private_key_is_never_copied_out(self):
        self.run_script("host1", str(self.out))
        for c in self.calls():
            if c[0] == "cp":
                self.assertFalse(any("ca.key" in a for a in c),
                                 f"docker cp touched the CA key: {c}")
        text = SCRIPT.read_text()
        for ln in text.splitlines():
            if "docker cp" in ln:
                self.assertNotIn("ca.key", ln)
        self.assertFalse((self.out / "ca.key").exists())

    # --- safety: no overwrite, no stack, cleanup ------------------------------

    def test_refuses_to_overwrite_a_non_empty_output_directory(self):
        self.out.mkdir()
        (self.out / "existing.key").write_text("precious")
        r = self.run_script("host1", str(self.out))
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)
        self.assertEqual("precious", (self.out / "existing.key").read_text())
        self.assertEqual([], [c for c in self.calls() if c[0] == "exec"])

    def test_empty_existing_output_directory_is_allowed(self):
        self.out.mkdir()
        r = self.run_script("host1", str(self.out))
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)

    def test_stack_not_running_fails_without_minting(self):
        r = self.run_script("host1", str(self.out), FAKE_DOCKER_RUNNING="false")
        self.assertEqual(1, r.returncode, r.stdout + r.stderr)
        self.assertFalse(any(self._is_mint(c) for c in self.calls()))
        self.assertFalse(self.out.exists())

    def test_scratch_dir_removed_even_when_minting_fails(self):
        r = self.run_script("host1", str(self.out), FAKE_DOCKER_EXEC_FAIL="1")
        self.assertNotEqual(0, r.returncode)
        self.assertTrue(any(c[:1] == ["exec"] and "rm" in c and "-rf" in c
                            for c in self.calls()),
                        "cleanup trap must remove the scratch directory")

    def test_scratch_dir_removed_even_when_copy_fails(self):
        r = self.run_script("host1", str(self.out), FAKE_DOCKER_CP_FAIL="1")
        self.assertNotEqual(0, r.returncode)
        self.assertTrue(any(c[:1] == ["exec"] and "rm" in c and "-rf" in c
                            for c in self.calls()))

    def test_cert_that_does_not_chain_to_the_ca_is_rejected(self):
        r = self.run_script("host1", str(self.out), FAKE_OPENSSL_FAIL="1")
        self.assertEqual(1, r.returncode, r.stdout + r.stderr)
        self.assertIn("do NOT deploy", r.stderr)

    def test_missing_output_file_is_detected(self):
        # A certutil layout change would leave the key missing; the script
        # must fail instead of reporting success with an empty directory.
        broken = self.bin / "docker"
        broken.write_text(FAKE_DOCKER.replace('echo "KEY"  > "$dest/$name.key"', ':'))
        r = self.run_script("host1", str(self.out))
        self.assertNotEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("missing or empty", r.stderr)


class EndpointConfigsPresentAClientCertTests(unittest.TestCase):
    def _output_section(self, path):
        text = path.read_text()
        start = text.index("output.logstash:")
        return text[start:]

    def test_winlogbeat_sets_client_cert_and_key(self):
        s = self._output_section(WINLOGBEAT)
        self.assertIn('ssl.certificate: "${WINLOGBEAT_CERT:', s)
        self.assertIn('ssl.key: "${WINLOGBEAT_KEY:', s)
        self.assertIn("ssl.certificate_authorities", s)
        self.assertIn('ssl.verification_mode: "${WINLOGBEAT_SSL_VERIFY:full}"', s)

    def test_filebeat_endpoint_sets_client_cert_and_key(self):
        s = self._output_section(FILEBEAT)
        self.assertIn('ssl.certificate: "${FILEBEAT_CERT:', s)
        self.assertIn('ssl.key: "${FILEBEAT_KEY:', s)
        self.assertIn("ssl.certificate_authorities", s)
        self.assertIn('ssl.verification_mode: "${FILEBEAT_SSL_VERIFY:full}"', s)

    def test_server_still_requires_client_auth(self):
        # If this ever flips, the configs above stop being load-bearing.
        conf = (REPO / "configs" / "logstash.conf").read_text()
        self.assertIn('ssl_client_authentication => "required"', conf)

    def test_script_is_executable_and_strict(self):
        self.assertTrue(os.access(SCRIPT, os.X_OK), "script must be executable")
        self.assertIn("set -euo pipefail", SCRIPT.read_text())


if __name__ == "__main__":
    unittest.main()
