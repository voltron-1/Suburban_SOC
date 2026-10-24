"""
systemd expands `${NAME}` and `$NAME` in Exec*= command lines BEFORE the command runs
(systemd.service(5), "Command lines"). A name that is not in the unit's environment becomes
the empty string, and the journal says so:

    Referenced but unset environment variable evaluates to an empty string: err

`configs/systemd/zeek-host-capture.service` hit this: its ExecStartPre assigns a bash local
(`err="$(cp ...)"`) and later prints `(${err})`, so systemd blanked it and the warning read
`could not refresh intel.dat from <repo> ()`, discarding the copy error the line exists to show
(seen live on the capture host, 2026-10-24). A literal `$` for the shell must be written `$$`.

This is the Exec*= counterpart of test_systemd_environment_no_expansion.py (which guards
`Environment=` lines). It flags any variable that an Exec*= line assigns itself and then
references with an unescaped `$`, which is the shape of this bug and never intended.
Variables supplied by systemd (EnvironmentFile=, or an `Environment=NAME=` line in the same
unit) are not flagged: those references are meant to be expanded.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SYSTEMD_DIR = ROOT / "configs" / "systemd"
REDEPLOY = ROOT / "scripts" / "setup" / "redeploy_systemd_units.sh"

_ASSIGN_RE = re.compile(r"(?<![\w$])([A-Za-z_]\w*)=")
_REF_RE = re.compile(r"(?<!\$)\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))")
_ENV_DEFINED_RE = re.compile(r"^Environment=(?:\"?)([A-Za-z_]\w*)=", re.M)


def exec_lines(text: str) -> list:
    """Active Exec*= lines, with backslash continuations joined."""
    out, buf = [], ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if not buf and line.lstrip().startswith("#"):
            continue
        buf += line[:-1] + " " if line.endswith("\\") else line
        if not line.endswith("\\"):
            if re.match(r"Exec\w+=", buf.strip()):
                out.append(buf.strip())
            buf = ""
    return out


def unescaped_local_references(text: str) -> list:
    """(line prefix, name) for each Exec*= variable assigned and then referenced unescaped."""
    from_environment = set(_ENV_DEFINED_RE.findall(text))
    hits = []
    for line in exec_lines(text):
        assigned = set(_ASSIGN_RE.findall(line)) - from_environment
        for braced, bare in _REF_RE.findall(line):
            name = braced or bare
            if name in assigned:
                hits.append((line[:60], name))
    return sorted(set(hits))


class ExecLineDollarEscapingTests(unittest.TestCase):
    def test_no_unit_references_its_own_shell_local_unescaped(self):
        files = sorted(SYSTEMD_DIR.glob("*.service"))
        self.assertGreater(len(files), 0)
        offenders = {f.name: unescaped_local_references(f.read_text(encoding="utf-8"))
                     for f in files}
        offenders = {k: v for k, v in offenders.items() if v}
        self.assertEqual({}, offenders,
                         "an Exec*= line assigns a shell variable and then references it with a "
                         "single `$`; systemd expands it first (to nothing). Write `$${name}`.")

    def test_zeek_unit_refresh_warnings_keep_the_copy_error(self):
        text = (SYSTEMD_DIR / "zeek-host-capture.service").read_text(encoding="utf-8")
        line = next(ln for ln in exec_lines(text) if "could not refresh config.zeek" in ln)
        self.assertEqual(2, line.count("$${err}"), "both warnings must print the captured error")
        self.assertEqual(0, len(re.findall(r"(?<!\$)\$\{err\}", line)))

    def test_systemd_supplied_variables_are_still_expanded_by_systemd(self):
        # ${SOC_REPO} comes from the unit's EnvironmentFile, so it must stay a single `$`.
        text = (SYSTEMD_DIR / "zeek-host-capture.service").read_text(encoding="utf-8")
        line = next(ln for ln in exec_lines(text) if "could not refresh config.zeek" in ln)
        self.assertIn("${SOC_REPO}", line)
        self.assertNotIn("$${SOC_REPO}", line)


class DetectorSelfTests(unittest.TestCase):
    def test_flags_the_original_bug_shape(self):
        unit = "ExecStartPre=/bin/bash -c 'err=\"$(cp a b 2>&1)\" || echo \"failed (${err})\"'\n"
        self.assertEqual(["err"], [name for _, name in unescaped_local_references(unit)])

    def test_accepts_the_escaped_form(self):
        unit = "ExecStartPre=/bin/bash -c 'err=\"$(cp a b 2>&1)\" || echo \"failed ($${err})\"'\n"
        self.assertEqual([], unescaped_local_references(unit))

    def test_accepts_a_variable_systemd_defines(self):
        unit = ("Environment=REPO=/x\n"
                "ExecStart=/bin/bash -c 'REPO=\"${REPO}\"; echo $$REPO'\n")
        self.assertEqual([], unescaped_local_references(unit))

    def test_joins_continuation_lines(self):
        unit = "ExecStartPre=/bin/bash -c 'x=1; \\\n  echo $x'\n"
        self.assertEqual(1, len(unescaped_local_references(unit)))


class RedeployInstallsIntelRefreshTests(unittest.TestCase):
    def test_redeploy_script_copies_both_intel_refresh_units(self):
        text = REDEPLOY.read_text(encoding="utf-8")
        for unit in ("intel-refresh.service", "intel-refresh.timer"):
            self.assertRegex(
                text,
                rf"(?m)^sudo cp configs/systemd/{re.escape(unit)} /etc/systemd/system/{re.escape(unit)}$")

    def test_copies_come_before_the_daemon_reload(self):
        text = REDEPLOY.read_text(encoding="utf-8")
        copy_at = text.index("sudo cp configs/systemd/intel-refresh.timer")
        reload_at = text.index("sudo systemctl daemon-reload", copy_at)
        self.assertLess(copy_at, reload_at)
        self.assertNotIn("sudo systemctl daemon-reload", text[text.index("sudo cp configs/systemd/slo-metrics.service"):copy_at])


if __name__ == "__main__":
    unittest.main()
