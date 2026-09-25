"""
Tests for the dynamic HTML playbook system (playbooks_blueprint.py), added
by the docs/playbooks/IR_Sigma_Playbook.md migration.

Covers: schema validation of the generated data files, registry/dashboard
rendering, detail routing + 404 handling, filtering, the AI-context JSON
endpoint, and — the build prompt's explicit security requirement — that
rule-derived content can never execute as HTML/JS in the rendered page.
"""
import json
from pathlib import Path

import pytest
from flask import Flask

from playbooks_blueprint import playbooks_bp, build_registry, _load_playbook

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "playbooks" / "data"
SCHEMA_PATH = REPO_ROOT / "playbooks" / "schema" / "playbook.schema.json"


@pytest.fixture
def app():
    app = Flask(__name__)
    app.register_blueprint(playbooks_bp)
    app.testing = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


# ---------------------------------------------------------------------------
# Schema validation — every generated data file must satisfy the schema.
# ---------------------------------------------------------------------------

def test_data_dir_is_not_empty():
    assert DATA_DIR.exists(), "playbooks/data/ must exist — run playbooks/migration/split_ir_sigma_playbook.py"
    files = list(DATA_DIR.glob("*.json"))
    assert len(files) >= 100, f"expected ~120 migrated playbooks, found {len(files)}"


def test_all_playbooks_validate_against_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)

    errors = []
    for path in sorted(DATA_DIR.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        for err in validator.iter_errors(record):
            errors.append(f"{path.name}: {err.message}")

    assert not errors, "schema validation failures:\n" + "\n".join(errors)


def test_every_playbook_id_matches_its_filename():
    for path in sorted(DATA_DIR.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        assert record["id"] == path.stem, f"{path.name}: id field {record['id']!r} != filename stem"


def test_every_playbook_has_all_five_sections():
    expected_ids = {
        "rule-summary-mitre-mapping",
        "automated-extraction-fields",
        "enrichment-criteria",
        "containment-decision-flow",
        "remediation-evidence-preservation",
    }
    for path in sorted(DATA_DIR.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        section_ids = {s["id"] for s in record["sections"]}
        assert section_ids == expected_ids, f"{path.name}: section ids {section_ids} != {expected_ids}"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_build_registry_matches_data_dir_count():
    registry = build_registry()
    assert len(registry) == len(list(DATA_DIR.glob("*.json")))


def test_registry_entries_have_required_fields():
    for entry in build_registry():
        assert entry["id"]
        assert entry["title"]
        assert entry["severity"] in ("low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def test_dashboard_200(client):
    resp = client.get("/playbooks")
    assert resp.status_code == 200
    assert b"SUBURBAN-SOC PLAYBOOKS" in resp.data


def test_known_playbook_detail_200(client):
    any_id = next(iter(build_registry()))["id"]
    resp = client.get(f"/playbooks/{any_id}")
    assert resp.status_code == 200


def test_unknown_playbook_404(client):
    resp = client.get("/playbooks/this-rule-id-does-not-exist")
    assert resp.status_code == 404


def test_path_traversal_id_is_rejected(client):
    # Rule ids are constrained to [a-z0-9_]+; anything else must 404, not
    # resolve outside playbooks/data/.
    resp = client.get("/playbooks/..%2F..%2F..%2Fetc%2Fpasswd")
    assert resp.status_code in (404, 400)


def test_dashboard_filter_by_severity(client):
    resp = client.get("/playbooks?severity=critical")
    assert resp.status_code == 200


def test_ai_context_endpoint_returns_json_not_html(client):
    any_id = next(iter(build_registry()))["id"]
    resp = client.get(f"/playbooks/{any_id}/context.json")
    assert resp.status_code == 200
    assert resp.is_json
    body = resp.get_json()
    assert body["playbook"] == any_id
    # This is the AI-consumable channel — must never expose rendered HTML,
    # per build-prompt Phase 16 ("do not make the AI scrape rendered HTML").
    assert "<html" not in json.dumps(body).lower()


# ---------------------------------------------------------------------------
# Security — XSS / injection (build-prompt Phase 19)
# ---------------------------------------------------------------------------

XSS_PAYLOAD = '<script>alert("XSS")</script>'


def test_xss_payload_in_section_content_is_escaped(app, client, tmp_path, monkeypatch):
    """A playbook whose section content contains a raw <script> tag must
    render as inert escaped text, never as an executable tag, confirming
    Jinja2 autoescaping is in effect end-to-end for playbook data."""
    poisoned = {
        "id": "test_xss_probe",
        "title": "XSS Probe",
        "ruleFile": "rules/sigma/test_xss_probe.yml",
        "status": "experimental",
        "severity": "low",
        "category": "Windows Process Creation",
        "version": "1.0",
        "lastUpdated": "2026-01-01",
        "tags": [],
        "integrations": [],
        "mitre": {"tactics": [], "techniques": []},
        "aiContext": {"playbook": "test_xss_probe", "dataSource": "", "triggerCondition": ""},
        "sections": [
            {
                "id": "rule-summary-mitre-mapping",
                "title": "Rule Summary & Mitre Mapping",
                "type": "reference",
                "blocks": [{"blockType": "markdown", "content": XSS_PAYLOAD}],
            },
            {"id": "automated-extraction-fields", "title": "x", "type": "reference", "blocks": []},
            {"id": "enrichment-criteria", "title": "x", "type": "reference", "blocks": []},
            {
                "id": "containment-decision-flow",
                "title": "Containment Decision Flow",
                "type": "procedure",
                "blocks": [{"blockType": "codeBlock", "content": XSS_PAYLOAD, "language": "bash"}],
            },
            {"id": "remediation-evidence-preservation", "title": "x", "type": "reference", "blocks": []},
        ],
        "evidence": [],
        "unmappedContent": [],
    }

    import playbooks_blueprint as pb_module
    monkeypatch.setattr(pb_module, "DATA_DIR", tmp_path)
    (tmp_path / "test_xss_probe.json").write_text(json.dumps(poisoned), encoding="utf-8")

    resp = client.get("/playbooks/test_xss_probe")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")

    # The literal, unescaped tag must never appear in the response body.
    assert "<script>alert(" not in html
    # It must appear only in its HTML-escaped form.
    assert "&lt;script&gt;" in html


def test_xss_payload_in_evidence_list_is_escaped(app, client, tmp_path, monkeypatch):
    poisoned = {
        "id": "test_xss_probe_evidence",
        "title": "XSS Probe Evidence",
        "ruleFile": "rules/sigma/test_xss_probe_evidence.yml",
        "status": "experimental",
        "severity": "low",
        "category": "Windows Process Creation",
        "version": "1.0",
        "lastUpdated": "2026-01-01",
        "tags": [],
        "integrations": [],
        "mitre": {"tactics": [], "techniques": []},
        "aiContext": {"playbook": "test_xss_probe_evidence", "dataSource": "", "triggerCondition": ""},
        "sections": [
            {"id": "rule-summary-mitre-mapping", "title": "x", "type": "reference", "blocks": []},
            {"id": "automated-extraction-fields", "title": "x", "type": "reference", "blocks": []},
            {"id": "enrichment-criteria", "title": "x", "type": "reference", "blocks": []},
            {"id": "containment-decision-flow", "title": "x", "type": "procedure", "blocks": []},
            {"id": "remediation-evidence-preservation", "title": "x", "type": "reference", "blocks": []},
        ],
        "evidence": [XSS_PAYLOAD],
        "unmappedContent": [],
    }

    import playbooks_blueprint as pb_module
    monkeypatch.setattr(pb_module, "DATA_DIR", tmp_path)
    (tmp_path / "test_xss_probe_evidence.json").write_text(json.dumps(poisoned), encoding="utf-8")

    resp = client.get("/playbooks/test_xss_probe_evidence")
    html = resp.data.decode("utf-8")
    assert "<script>alert(" not in html
    assert "&lt;script&gt;" in html


def test_no_unsafe_jinja_filter_in_playbook_templates():
    """Static guard: none of this feature's templates may use the |safe
    filter (or {% autoescape false %}) on playbook-derived content, which
    would reintroduce the XSS risk the two tests above check at runtime."""
    import re
    # Matches an actual Jinja2 |safe filter application, e.g. {{ x|safe }} or
    # {{ x | safe }} — not the substring "|safe" appearing inside an HTML
    # comment or prose (this file's own templates document *why* they don't
    # use |safe, which would otherwise false-positive a plain substring check).
    unsafe_filter_re = re.compile(r"\{\{.*\|\s*safe\s*\}\}")
    template_dir = REPO_ROOT / "scripts" / "setup" / "ai_agent" / "templates"
    offending = []
    for path in template_dir.glob("playbooks_*.html"):
        text = path.read_text(encoding="utf-8")
        if unsafe_filter_re.search(text) or "autoescape false" in text:
            offending.append(path.name)
    assert not offending, f"unsafe rendering found in: {offending}"
