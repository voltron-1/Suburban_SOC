#!/usr/bin/env python3
"""
2026-10-24 live run: deploy_detections.sh converted 38 rules, then Kibana 9.3.2 answered
HTTP 400 {"message":"Invalid file extension .mgztvfxbpq"} and the script printed
`success=None imported=None errors=0`. The upload was a mktemp path (random suffix) and
Kibana validates the uploaded filename's extension. The script must name the upload
`*.ndjson` explicitly, and must print Kibana's message when the reply is an error body.

Run:  python tests/pipeline/test_deploy_detections_upload.py   (or: pytest tests/pipeline)
"""

import re
import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "setup" / "deploy_detections.sh"


class DeployDetectionsUploadTests(unittest.TestCase):
    def setUp(self):
        self.text = SCRIPT.read_text(encoding="utf-8")

    def test_script_is_syntactically_valid_bash(self):
        r = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(0, r.returncode, r.stderr)

    def test_rules_import_names_the_upload_with_an_ndjson_extension(self):
        forms = re.findall(r'--form "file=@\$\{NDJSON\}[^"]*"', self.text)
        self.assertEqual(1, len(forms), f"expected exactly one rules-import --form, got {forms}")
        self.assertRegex(forms[0], r";filename=[\w.-]+\.ndjson\b")

    def test_error_body_message_is_printed_instead_of_success_none(self):
        self.assertIn("d.get('message')", self.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
